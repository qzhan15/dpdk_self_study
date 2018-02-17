#ifndef __XDPSOCK_QUEUE_H
#define __XDPSOCK_QUEUE_H

static inline int xq_enq(struct xdp_queue *q,
			 const struct xdp_desc *descs,
			 unsigned int ndescs)
{
	unsigned int avail_idx = q->avail_idx;
	unsigned int i;
	int j;

	if (q->num_free < ndescs)
		return -ENOSPC;

	q->num_free -= ndescs;

	for (i = 0; i < ndescs; i++) {
		unsigned int idx = avail_idx++ & q->ring_mask;

		q->ring[idx].idx	= descs[i].idx;
		q->ring[idx].len	= descs[i].len;
		q->ring[idx].offset	= descs[i].offset;
		q->ring[idx].error	= 0;
	}
	rte_smp_wmb();

	for (j = ndescs - 1; j >= 0; j--) {
		unsigned int idx = (q->avail_idx + j) & q->ring_mask;

		q->ring[idx].flags = descs[j].flags | XDP_DESC_KERNEL;
	}
	q->avail_idx += ndescs;

	return 0;
}

static inline int xq_deq(struct xdp_queue *q,
			 struct xdp_desc *descs,
			 int ndescs)
{
	unsigned int idx, last_used_idx = q->last_used_idx;
	int i, entries = 0;

	for (i = 0; i < ndescs; i++) {
		idx = (last_used_idx++) & q->ring_mask;
		if (q->ring[idx].flags & XDP_DESC_KERNEL)
			break;
		entries++;
	}
	q->num_free += entries;

	rte_smp_rmb();

	for (i = 0; i < entries; i++) {
		idx = q->last_used_idx++ & q->ring_mask;
		descs[i] = q->ring[idx];
	}

	return entries;
}

#endif /* __XDPSOCK_QUEUE_H */
