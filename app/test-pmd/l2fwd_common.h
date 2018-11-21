/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _L2FWD_COMMON_H_
#define _L2FWD_COMMON_H_

static inline uint64_t
ol_flags_init(uint64_t tx_offload)
{
	uint64_t ol_flags = 0;

	ol_flags |= (tx_offload & DEV_TX_OFFLOAD_VLAN_INSERT) ?
			PKT_TX_VLAN_PKT : 0;
	ol_flags |= (tx_offload & DEV_TX_OFFLOAD_QINQ_INSERT) ?
			PKT_TX_QINQ_PKT : 0;
	ol_flags |= (tx_offload & DEV_TX_OFFLOAD_MACSEC_INSERT) ?
			PKT_TX_MACSEC : 0;

	return ol_flags;
}

static inline void
mbuf_field_set(struct rte_mbuf *mb, uint64_t ol_flags,
		uint16_t vlan, uint16_t vlan_outer)
{
	mb->ol_flags &= IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF;
	mb->ol_flags |= ol_flags;
	mb->l2_len = sizeof(struct ether_hdr);
	mb->l3_len = sizeof(struct ipv4_hdr);
	mb->vlan_tci = vlan;
	mb->vlan_tci_outer = vlan_outer;
}

#endif /* _BPF_CMD_H_ */

