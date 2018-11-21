/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _L2FWD_SSE_H_
#define _L2FWD_SSE_H_

#include "macswap_common.h"
static inline void
do_macswap(struct rte_mbuf *pkts[], uint16_t nb,
		struct rte_port *txp)
{
	struct ether_hdr *eth_hdr[4];
	struct rte_mbuf *mb[4];
	uint64_t ol_flags;
	int i;
	int r;
	__m128i addr0, addr1, addr2, addr3;
	__m128i shfl_msk = _mm_set_epi8(15, 14, 13, 12,
					5, 4, 3, 2,
					1, 0, 11, 10,
					9, 8, 7, 6);

	ol_flags = ol_flags_init(txp->dev_conf.txmode.offloads);

	i = 0;
	r = nb;

	while (r >= 4) {
		mb[0] = pkts[i++];
		//rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
		eth_hdr[0] = rte_pktmbuf_mtod(mb[0], struct ether_hdr *);
		addr0 = _mm_loadu_si128((__m128i *)eth_hdr[0]);

		mb[1] = pkts[i++];
		//rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
		eth_hdr[1] = rte_pktmbuf_mtod(mb[1], struct ether_hdr *);
		addr1 = _mm_loadu_si128((__m128i *)eth_hdr[1]);


		mb[2] = pkts[i++];
		//rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
		eth_hdr[2] = rte_pktmbuf_mtod(mb[2], struct ether_hdr *);
		addr2 = _mm_loadu_si128((__m128i *)eth_hdr[2]);

		mb[3] = pkts[i++];
		//rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
		eth_hdr[3] = rte_pktmbuf_mtod(mb[3], struct ether_hdr *);
		addr3 = _mm_loadu_si128((__m128i *)eth_hdr[3]);

		addr0 = _mm_shuffle_epi8(addr0, shfl_msk);
		addr1 = _mm_shuffle_epi8(addr1, shfl_msk);
		addr2 = _mm_shuffle_epi8(addr2, shfl_msk);
		addr3 = _mm_shuffle_epi8(addr3, shfl_msk);

		_mm_storeu_si128((__m128i *)eth_hdr[0], addr0);
		_mm_storeu_si128((__m128i *)eth_hdr[1], addr1);
		_mm_storeu_si128((__m128i *)eth_hdr[2], addr2);
		_mm_storeu_si128((__m128i *)eth_hdr[3], addr3);

		mbuf_field_set(mb[0], ol_flags, txp->tx_vlan_id,
				txp->tx_vlan_id_outer);
		mbuf_field_set(mb[1], ol_flags, txp->tx_vlan_id,
				txp->tx_vlan_id_outer);
		mbuf_field_set(mb[2], ol_flags, txp->tx_vlan_id,
				txp->tx_vlan_id_outer);
		mbuf_field_set(mb[3], ol_flags, txp->tx_vlan_id,
				txp->tx_vlan_id_outer);
		r -= 4;
	}

	for ( ; i < nb; i++) {
		if (i < nb - 1)
			rte_prefetch0(rte_pktmbuf_mtod(pkts[i+1], void *));
		mb[0] = pkts[i];

		eth_hdr[0] = rte_pktmbuf_mtod(mb[0], struct ether_hdr *);

		/* Swap dest and src mac addresses. */
		addr0 = _mm_loadu_si128((__m128i *)eth_hdr);
		addr0 = _mm_shuffle_epi8(addr0, shfl_msk);
		_mm_storeu_si128((__m128i *)eth_hdr[0], addr0);

		mbuf_field_set(mb[0], ol_flags, txp->tx_vlan_id,
				txp->tx_vlan_id_outer);
	}
}

#endif /* _BPF_CMD_H_ */

