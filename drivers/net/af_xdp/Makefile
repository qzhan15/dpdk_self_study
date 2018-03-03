# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_af_xdp.a

EXPORT_MAP := rte_pmd_af_xdp_version.map

LIBABIVER := 1

LINUX_HEADER_DIR := /opt/af_xdp/linux_headers/include

CFLAGS += -O3 -I$(LINUX_HEADER_DIR) -Wno-error=sign-compare -Wno-error=cast-qual
CFLAGS += $(WERROR_FLAGS)
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_vdev

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_PMD_AF_XDP) += rte_eth_af_xdp.c
SRCS-$(CONFIG_RTE_LIBRTE_PMD_AF_XDP) += bpf_load.c

include $(RTE_SDK)/mk/rte.lib.mk
