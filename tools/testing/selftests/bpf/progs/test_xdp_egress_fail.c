// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_egress")
int xdp_egress_fail(struct xdp_md *ctx)
{
	__u32 rxq = ctx->rx_queue_index;
	__u32 idx = ctx->ingress_ifindex;

	if (idx == 1)
		return XDP_DROP;

	return rxq ? XDP_DROP : XDP_PASS;
}
