// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_egress")
int xdp_egress_good(struct xdp_md *ctx)
{
	__u32 idx = ctx->egress_ifindex;

	return idx == 1 ? XDP_DROP : XDP_PASS;
}
