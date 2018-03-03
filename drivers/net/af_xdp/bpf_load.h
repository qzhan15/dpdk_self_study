/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */
#ifndef __BPF_LOAD_H
#define __BPF_LOAD_H

#include <bpf/bpf.h>

int load_bpf_file(void);
int set_link_xdp_fd(int ifindex, int fd, __u32 flags);
#endif
