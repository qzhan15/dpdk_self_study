/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014 John W. Linville <linville@tuxdriver.com>
 * Originally based upon librte_pmd_pcap code:
 * Copyright(c) 2010-2015 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 * All rights reserved.
 */

#include <rte_mbuf.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_kvargs.h>
#include <rte_bus_vdev.h>

#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <poll.h>
#include "xdpsock_queue.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define ETH_AF_XDP_IFACE_ARG		"iface"
#define ETH_AF_XDP_QUEUE_IDX_ARG	"queue"
#define ETH_AF_XDP_RING_SIZE_ARG	"ringsz"

#define ETH_AF_XDP_FRAME_SIZE		2048
#define ETH_AF_XDP_NUM_BUFFERS		131072
#define ETH_AF_XDP_DATA_HEADROOM	192
#define ETH_AF_XDP_DFLT_RING_SIZE	1024
#define ETH_AF_XDP_DFLT_QUEUE_IDX	0

#define ETH_AF_XDP_RX_BATCH_SIZE	32
#define ETH_AF_XDP_TX_BATCH_SIZE	32

struct xdp_umem {
	char *buffer;
	size_t size;
	unsigned int frame_size;
	unsigned int frame_size_log2;
	unsigned int nframes;
	int mr_fd;
	struct rte_mempool *mb_pool;
};

struct pmd_internals {
	int sfd;
	int if_index;
	char if_name[0x100];
	struct ether_addr eth_addr;
	struct xdp_queue rx;
	struct xdp_queue tx;
	struct xdp_umem *umem;
	struct rte_mempool *ext_mb_pool;

	volatile unsigned long rx_pkts;
	volatile unsigned long rx_bytes;
	volatile unsigned long rx_dropped;

	volatile unsigned long tx_pkts;
	volatile unsigned long err_pkts;
	volatile unsigned long tx_bytes;

	uint16_t port_id;
	uint16_t queue_idx;
	int ring_size;

	uint64_t mbuf_alloc_count;
	uint64_t mbuf_free_count;
};

static const char *valid_arguments[] = {
	ETH_AF_XDP_IFACE_ARG,
	ETH_AF_XDP_QUEUE_IDX_ARG,
	ETH_AF_XDP_RING_SIZE_ARG,
	NULL
};

static struct rte_eth_link pmd_link = {
	.link_speed = ETH_SPEED_NUM_10G,
	.link_duplex = ETH_LINK_FULL_DUPLEX,
	.link_status = ETH_LINK_DOWN,
	.link_autoneg = ETH_LINK_AUTONEG
};

static void *get_pkt_data(struct pmd_internals *internals,
			  uint32_t index,
			  uint32_t offset)
{
	return (uint8_t *)(internals->umem->buffer +
			   (index << internals->umem->frame_size_log2) +
			   offset);
}

#if 0
static void hex_dump(void *pkt, size_t length, const char *prefix)
{
	int i = 0;
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;

	printf("length = %zu\n", length);
	printf("%s | ", prefix);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");  /* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", prefix);
		}
	}
	printf("\n");
}
#endif

static uint32_t
mbuf_to_idx(struct pmd_internals *internals, struct rte_mbuf *mbuf)
{
	return (uint32_t)(((uint64_t)mbuf->buf_addr - (uint64_t)internals->umem->buffer)
		>> internals->umem->frame_size_log2);
}

static struct rte_mbuf *
idx_to_mbuf(struct pmd_internals *internals, uint32_t idx)
{
	return (struct rte_mbuf *)(void *)(internals->umem->buffer + (idx
			<< internals->umem->frame_size_log2) + 0x40);
}

static uint16_t
eth_af_xdp_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct pmd_internals *internals = queue;
	struct xdp_queue *rxq = &internals->rx;
	struct rte_mbuf *mbuf;
	unsigned long dropped = 0;
	unsigned long rx_bytes = 0;
	uint16_t count = 0;
	nb_pkts = nb_pkts < ETH_AF_XDP_RX_BATCH_SIZE ?
		  nb_pkts : ETH_AF_XDP_RX_BATCH_SIZE;

	struct xdp_desc descs[ETH_AF_XDP_RX_BATCH_SIZE];
	struct rte_mbuf *mbufs[ETH_AF_XDP_RX_BATCH_SIZE];
	int rcvd, i;
	/* fill rx ring */
	if (rxq->num_free >= ETH_AF_XDP_RX_BATCH_SIZE) {
		int ret = rte_mempool_get_bulk(internals->umem->mb_pool,
					     (void *)mbufs,
					     ETH_AF_XDP_RX_BATCH_SIZE);
		if (!ret) {
			internals->mbuf_alloc_count += ETH_AF_XDP_RX_BATCH_SIZE;
			for (i = 0; i < ETH_AF_XDP_RX_BATCH_SIZE; i++)
				descs[i].idx = mbuf_to_idx(internals, mbufs[i]);
			xq_enq(rxq, descs, ETH_AF_XDP_RX_BATCH_SIZE);
		}
	}

	/* read data */
	rcvd = xq_deq(rxq, descs, nb_pkts);
	if (rcvd == 0)
		return 0;

	for (i = 0; i < rcvd; i++) {
		char *pkt;
		//char buf[32];
		uint32_t idx = descs[i].idx;
		mbuf = rte_pktmbuf_alloc(internals->ext_mb_pool);
		rte_pktmbuf_pkt_len(mbuf) =
			rte_pktmbuf_data_len(mbuf) =
			descs[i].len;
		if (mbuf) {
			pkt = get_pkt_data(internals, idx, descs[i].offset);
			//sprintf(buf, "idx=%d\n", idx);
			//hex_dump(pkt, descs[i].len, buf);
			memcpy(rte_pktmbuf_mtod(mbuf, void *), pkt, descs[i].len);
			rx_bytes += descs[i].len;
			bufs[count++] = mbuf;
		} else {
			dropped++;
		}
		rte_pktmbuf_free(idx_to_mbuf(internals, idx));
		internals->mbuf_free_count++;
	}

	internals->rx_pkts += (rcvd-dropped);
	internals->rx_bytes += rx_bytes;
	internals->rx_dropped += dropped;

	return count;
}

static void kick_tx(int fd)
{
	int ret;

	for (;;) {
		ret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
		if (ret >= 0 || errno == ENOBUFS)
			return;
		if (errno == EAGAIN)
			continue;
	}
}

static uint16_t
eth_af_xdp_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct pmd_internals *internals = queue;
	struct xdp_queue *txq = &internals->tx;
	struct rte_mbuf *mbuf;
	struct xdp_desc descs[ETH_AF_XDP_TX_BATCH_SIZE];
	struct rte_mbuf *mbufs[ETH_AF_XDP_TX_BATCH_SIZE];
	uint16_t i, valid;
	unsigned long tx_bytes = 0;
	int ret;

	nb_pkts = nb_pkts < ETH_AF_XDP_TX_BATCH_SIZE ?
		  nb_pkts : ETH_AF_XDP_TX_BATCH_SIZE;

	if (txq->num_free < ETH_AF_XDP_TX_BATCH_SIZE*4) {
		int n = xq_deq(txq, descs, ETH_AF_XDP_TX_BATCH_SIZE);
		for (i = 0; i < n; i++)
			rte_pktmbuf_free(idx_to_mbuf(internals, descs[i].idx));
		internals->mbuf_free_count+=n;
	}
	
	nb_pkts = nb_pkts > txq->num_free ? txq->num_free : nb_pkts;
	ret = rte_mempool_get_bulk(internals->umem->mb_pool,
				   (void *)mbufs,
				   nb_pkts);
	if (ret)
		return 0;
	internals->mbuf_alloc_count+= nb_pkts;

	valid = 0;
	for (i = 0; i < nb_pkts; i++) {
		char *pkt;
		mbuf = bufs[i];
		if (mbuf->pkt_len <= (internals->umem->frame_size - ETH_AF_XDP_DATA_HEADROOM)) {
			descs[valid].idx = mbuf_to_idx(internals, mbufs[i]);
			descs[valid].offset = ETH_AF_XDP_DATA_HEADROOM;
			descs[valid].flags = 0;
			descs[valid].len = mbuf->pkt_len;
			pkt = get_pkt_data(internals, descs[i].idx, descs[i].offset);
			memcpy(pkt, rte_pktmbuf_mtod(mbuf, void *), descs[i].len);
			valid++;
			tx_bytes += mbuf->pkt_len;
		}
		rte_pktmbuf_free(mbuf);
	}

	xq_enq(txq, descs, valid);
	kick_tx(internals->sfd);

	if (valid < nb_pkts) {
		for (i = valid; i < nb_pkts; i++)
			rte_pktmbuf_free(mbufs[i]);
		internals->mbuf_free_count += (nb_pkts-valid);
	}

	internals->err_pkts += (nb_pkts - valid);
	internals->tx_pkts += valid;
	internals->tx_bytes += tx_bytes;

	return valid;
}

static void
fill_rx_desc(struct pmd_internals *internals)
{
	int num_free = internals->rx.num_free;
	int i;
	for (i = 0; i < num_free; i++ ) {
		struct xdp_desc desc = {};
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(internals->umem->mb_pool);
		internals->mbuf_alloc_count++;
		desc.idx = mbuf_to_idx(internals, mbuf);
		xq_enq(&internals->rx, &desc, 1);
	}
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;
	dev->data->dev_link.link_status = ETH_LINK_UP;
	fill_rx_desc(internals);

	return 0;
}

/*
 * This function gets called when the current port gets stopped.
 */
static void
eth_dev_stop(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = ETH_LINK_DOWN;
}

static int
eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static void
eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *internals = dev->data->dev_private;

	dev_info->if_index = internals->if_index;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)ETH_FRAME_LEN;
	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;
	dev_info->min_rx_bufsize = 0;
}

static int
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	const struct pmd_internals *internals = dev->data->dev_private;

	stats->ipackets = stats->q_ipackets[0] =
		internals->rx_pkts;
	stats->ibytes = stats->q_ibytes[0] =
		internals->rx_bytes;
	stats->imissed =
		internals->rx_dropped;

	stats->opackets = stats->q_opackets[0]
		= internals->tx_pkts;
	stats->oerrors = stats->q_errors[0] =
		internals->err_pkts;
	stats->obytes =stats->q_obytes[0] =
		internals->tx_bytes;

	printf("total alloc = %ld\n", internals->mbuf_alloc_count);
	printf("total freed = %ld\n", internals->mbuf_free_count);
	printf("delta = %ld\n", internals->mbuf_alloc_count - internals->mbuf_free_count);
	return 0;
}

static void
eth_stats_reset(struct rte_eth_dev *dev)
{
	struct pmd_internals *internal = dev->data->dev_private;

	internal->rx_pkts = 0;
	internal->rx_bytes = 0;
	internal->rx_dropped = 0;

	internal->tx_pkts = 0;
	internal->err_pkts = 0;
	internal->tx_bytes = 0;
}

static void
eth_dev_close(struct rte_eth_dev *dev __rte_unused)
{
}

static void
eth_queue_release(void *q __rte_unused)
{
}

static int
eth_link_update(struct rte_eth_dev *dev __rte_unused,
                int wait_to_complete __rte_unused)
{
	return 0;
}

static void *get_base_addr(struct rte_mempool *mb_pool)
{
	struct rte_mempool_memhdr *memhdr;
	STAILQ_FOREACH(memhdr, &mb_pool->mem_list, next) {
		return memhdr->addr;
	}
	return NULL;
}

static void dump_mempool(struct rte_mempool *mb_pool)
{
	struct rte_mempool_memhdr *memhdr;
	struct rte_mbuf *mbuf1, *mbuf2;
	printf("flags = %x\n", mb_pool->flags);
	printf("size = %d\n", mb_pool->size);

	printf("elt_size = %d\n", mb_pool->elt_size);
	printf("header_size = %d\n", mb_pool->header_size);
	printf("trailer_size = %d\n", mb_pool->trailer_size);
	printf("nb_mem_chunk = %d\n", mb_pool->nb_mem_chunks);
	printf("private_data_size = %d\n", mb_pool->private_data_size);
	STAILQ_FOREACH(memhdr, &mb_pool->mem_list, next) {
		printf("base addr = %lx\n", (uint64_t)memhdr->addr);;
	}
	mbuf1 = rte_pktmbuf_alloc(mb_pool);
	printf("mbuf->addr = %lx\n", (uint64_t)mbuf1->buf_addr);
	printf("mbuf1 addr = %lx\n", (uint64_t)mbuf1);
	mbuf2 = rte_pktmbuf_alloc(mb_pool);
	printf("mbuf->addr = %lx\n", (uint64_t)mbuf2->buf_addr);
	printf("mbuf2 addr = %lx\n", (uint64_t)mbuf2);
	rte_pktmbuf_free(mbuf1);
	rte_pktmbuf_free(mbuf2);
}

static struct xdp_umem *xsk_alloc_and_mem_reg_buffers(int sfd,
						      size_t nbuffers,
						      const char *pool_name)
{
	struct xdp_mr_req req = { .frame_size = ETH_AF_XDP_FRAME_SIZE,
				  .data_headroom = ETH_AF_XDP_DATA_HEADROOM };
	struct xdp_umem *umem =calloc(1, sizeof(*umem));
	if (umem == NULL) {
		return NULL;
	}

	umem->mb_pool =
		rte_pktmbuf_pool_create_no_spread(pool_name, nbuffers,
						  250, 0,
						  (ETH_AF_XDP_FRAME_SIZE-192),
						  SOCKET_ID_ANY);
	if (umem->mb_pool == NULL) {
		free(umem);
		return NULL;
	}

	if (umem->mb_pool->nb_mem_chunks > 1) {
		rte_mempool_free(umem->mb_pool);
		free(umem);
		return NULL;
	}

	dump_mempool(umem->mb_pool);

	req.addr = (uint64_t)get_base_addr(umem->mb_pool);
	req.len = nbuffers * req.frame_size;
	setsockopt(sfd, SOL_XDP, XDP_MEM_REG, &req, sizeof(req));

	umem->frame_size = ETH_AF_XDP_FRAME_SIZE;
	umem->frame_size_log2 = 11;
	umem->buffer = (char *)req.addr;
	umem->size = nbuffers * req.frame_size;
	umem->nframes = nbuffers;
	umem->mr_fd = sfd;

	return umem;
}

static int
xdp_configure(struct pmd_internals *internals)
{
	struct sockaddr_xdp sxdp;
	struct xdp_ring_req req;
	char pool_name[0x100];

	int ret = 0;

	snprintf(pool_name, 0x100, "%s_%s_%d", "af_xdp_pool",
		  internals->if_name, internals->queue_idx);
	internals->umem = xsk_alloc_and_mem_reg_buffers(internals->sfd,
							ETH_AF_XDP_NUM_BUFFERS,
							pool_name);
	if (internals->umem == NULL)
		return -1;

	req.mr_fd = internals->umem->mr_fd;
	req.desc_nr = internals->ring_size;

	ret = setsockopt(internals->sfd, SOL_XDP, XDP_RX_RING, &req, sizeof(req));
	RTE_ASSERT(ret == 0);

	ret = setsockopt(internals->sfd, SOL_XDP, XDP_TX_RING, &req, sizeof(req));
	RTE_ASSERT(ret == 0);

	internals->rx.ring = mmap(0, req.desc_nr * sizeof(struct xdp_desc),
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED | MAP_LOCKED | MAP_POPULATE,
				  internals->sfd,
				  XDP_PGOFF_RX_RING);
	RTE_ASSERT(internals->rx.ring != MAP_FAILED);

	internals->rx.num_free = req.desc_nr;
	internals->rx.ring_mask = req.desc_nr - 1;

	internals->tx.ring = mmap(0, req.desc_nr * sizeof(struct xdp_desc),
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED | MAP_LOCKED | MAP_POPULATE,
				  internals->sfd,
				  XDP_PGOFF_TX_RING);
	RTE_ASSERT(internals->tx.ring != MAP_FAILED);

	internals->tx.num_free = req.desc_nr;
	internals->tx.ring_mask = req.desc_nr - 1;

	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_ifindex = internals->if_index;
	sxdp.sxdp_queue_id = internals->queue_idx;

	ret = bind(internals->sfd, (struct sockaddr *)&sxdp, sizeof(sxdp));
	RTE_ASSERT(ret == 0);

	return ret;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev,
                   uint16_t rx_queue_id,
                   uint16_t nb_rx_desc __rte_unused,
                   unsigned int socket_id __rte_unused,
                   const struct rte_eth_rxconf *rx_conf __rte_unused,
                   struct rte_mempool *mb_pool)
{
	struct pmd_internals *internals = dev->data->dev_private;
	unsigned int buf_size, data_size;

	RTE_ASSERT(rx_queue_id == 0);
	internals->ext_mb_pool = mb_pool;
	dump_mempool(mb_pool);
	xdp_configure(internals);

	/* Now get the space available for data in the mbuf */
	buf_size = rte_pktmbuf_data_room_size(internals->ext_mb_pool) -
		RTE_PKTMBUF_HEADROOM;
	data_size = internals->umem->frame_size;

	if (data_size > buf_size) {
		RTE_LOG(ERR, PMD,
			"%s: %d bytes will not fit in mbuf (%d bytes)\n",
			dev->device->name, data_size, buf_size);
		return -ENOMEM;
	}

	dev->data->rx_queues[rx_queue_id] = internals;
	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev,
                   uint16_t tx_queue_id,
                   uint16_t nb_tx_desc __rte_unused,
                   unsigned int socket_id __rte_unused,
                   const struct rte_eth_txconf *tx_conf __rte_unused)
{

	struct pmd_internals *internals = dev->data->dev_private;

	RTE_ASSERT(tx_queue_id == 0);
	dev->data->tx_queues[tx_queue_id] = internals;
	return 0;
}

static int
eth_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct ifreq ifr = { .ifr_mtu = mtu };
	int ret;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -EINVAL;

	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", internals->if_name);
	ret = ioctl(s, SIOCSIFMTU, &ifr);
	close(s);

	if (ret < 0)
		return -EINVAL;

	return 0;
}

static void
eth_dev_change_flags(char *if_name, uint32_t flags, uint32_t mask)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return;

	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", if_name);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		goto out;
	ifr.ifr_flags &= mask;
	ifr.ifr_flags |= flags;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
		goto out;
out:
	close(s);
}

static void
eth_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	eth_dev_change_flags(internals->if_name, IFF_PROMISC, ~0);
}

static void
eth_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;

	eth_dev_change_flags(internals->if_name, 0, ~IFF_PROMISC);
}

static const struct eth_dev_ops ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_close = eth_dev_close,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.mtu_set = eth_dev_mtu_set,
	.promiscuous_enable = eth_dev_promiscuous_enable,
	.promiscuous_disable = eth_dev_promiscuous_disable,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_release = eth_queue_release,
	.tx_queue_release = eth_queue_release,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
};

static struct rte_vdev_driver pmd_af_xdp_drv;

static void
parse_parameters(struct rte_kvargs *kvlist,
		 char **if_name,
		 int *queue_idx,
		 int *ring_size)
{
	struct rte_kvargs_pair *pair = NULL;
	unsigned k_idx;

	for (k_idx = 0; k_idx < kvlist->count; k_idx++) {
		pair = &kvlist->pairs[k_idx];
		if (strstr(pair->key, ETH_AF_XDP_IFACE_ARG) != NULL)
			*if_name = pair->value;
		else if (strstr(pair->key, ETH_AF_XDP_QUEUE_IDX_ARG) != NULL)
			*queue_idx = atoi(pair->value);
		else if (strstr(pair->key, ETH_AF_XDP_RING_SIZE_ARG) != NULL)
			*ring_size = atoi(pair->value);
	}
}

static int
get_iface_info(const char *if_name,
	       struct ether_addr *eth_addr,
	       int *if_index)
{
	struct ifreq ifr;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0)
		return -1;

        strcpy(ifr.ifr_name, if_name);
	if (ioctl(sock, SIOCGIFINDEX, &ifr))
		goto error;
	*if_index = ifr.ifr_ifindex;

	if (ioctl(sock, SIOCGIFHWADDR, &ifr))
		goto error;

	memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, 6);

	close(sock);	
	return 0;
	
error:
	close(sock);
	return -1;
}

static int
init_internals(struct rte_vdev_device* dev,
	       const char* if_name,
	       int queue_idx,
	       int ring_size)
{
	const char *name = rte_vdev_device_name(dev);
	struct rte_eth_dev *eth_dev = NULL;
	struct rte_eth_dev_data *data = NULL;
	const unsigned int numa_node = dev->device.numa_node;
	struct pmd_internals *internals = NULL;
	int ret;

	data = rte_zmalloc_socket(name, sizeof(*internals), 0, numa_node);
	if (data == NULL)
		return -1;

	internals = rte_zmalloc_socket(name, sizeof(*internals), 0, numa_node);
	if (internals == NULL)
		goto error_1;

	internals->queue_idx = queue_idx;
	internals->ring_size = ring_size;;
	strcpy(internals->if_name, if_name);
	internals->sfd = socket(PF_XDP, SOCK_RAW, 0);
	if (internals->sfd <0)
		goto error_2;

	ret = get_iface_info(if_name, &internals->eth_addr, &internals->if_index);
	if (ret)
		goto error_3;

	eth_dev = rte_eth_vdev_allocate(dev, 0);
	if (eth_dev == NULL)
		goto error_3;

	rte_memcpy(data, eth_dev->data, sizeof(*data));
	internals->port_id = eth_dev->data->port_id;
	data->dev_private = internals;
	data->nb_rx_queues = 1;
	data->nb_tx_queues = 1;
	data->dev_link = pmd_link;
	data->mac_addrs = &internals->eth_addr;

	eth_dev->data = data;
	eth_dev->dev_ops = &ops;

	eth_dev->rx_pkt_burst = eth_af_xdp_rx;
	eth_dev->tx_pkt_burst = eth_af_xdp_tx;

	return 0;

error_3:
	close(internals->sfd);

error_2:
	rte_free(internals);
	
error_1:
	rte_free(data);
	return -1;
}

static int
rte_pmd_af_xdp_probe(struct rte_vdev_device *dev)
{
	struct rte_kvargs *kvlist;
	char *if_name = NULL;;
	int ring_size = ETH_AF_XDP_DFLT_RING_SIZE;
	int queue_idx = ETH_AF_XDP_DFLT_QUEUE_IDX;
	int ret;

	RTE_LOG(INFO, PMD, "Initializing pmd_af_packet for %s\n",
		rte_vdev_device_name(dev));

	kvlist = rte_kvargs_parse(rte_vdev_device_args(dev), valid_arguments);
	if (kvlist == NULL) {
		RTE_LOG(ERR, PMD,
			"Invalid kvargs");
		return -1;
	}

	if (dev->device.numa_node == SOCKET_ID_ANY)
		dev->device.numa_node = rte_socket_id();

	parse_parameters(kvlist, &if_name, &queue_idx, &ring_size);

	ret = init_internals(dev, if_name, queue_idx, ring_size);
	rte_kvargs_free(kvlist);

	return ret;
}

static int
rte_pmd_af_xdp_remove(struct rte_vdev_device *dev)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct pmd_internals *internals;

	RTE_LOG(INFO, PMD, "Closing AF_XDP ethdev on numa socket %u\n",
			rte_socket_id());

	if (dev == NULL)
		return -1;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
	if (eth_dev == NULL)
		return -1;

	internals = eth_dev->data->dev_private;
	if (internals->umem) {
		if (internals->umem->mb_pool)
			rte_mempool_free(internals->umem->mb_pool);
		rte_free(internals->umem);
	}
	rte_free(eth_dev->data->dev_private);
	rte_free(eth_dev->data);
	close(internals->sfd);

	rte_eth_dev_release_port(eth_dev);

	return 0;
}

static struct rte_vdev_driver pmd_af_xdp_drv = {
	.probe = rte_pmd_af_xdp_probe,
	.remove = rte_pmd_af_xdp_remove,
};

RTE_PMD_REGISTER_VDEV(net_af_xdp, pmd_af_xdp_drv);
RTE_PMD_REGISTER_ALIAS(net_af_xdp, eth_af_xdp);
RTE_PMD_REGISTER_PARAM_STRING(net_af_xdp,
	"iface=<string> "
	"queue=<int> "
	"ringsz=<int> ");
