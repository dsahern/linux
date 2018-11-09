// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "bpf_helpers.h"

#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)

struct bpf_map_def SEC("maps") tx_devmap = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") tx_idxmap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,
};

#if 1
struct xdp_stats {
	__u64 rx;
	__u64 tx;
	__u64 dropped;
	__u64 skipped;
	__u64 l3_dev;
	__u64 fib_dev;
};

struct bpf_map_def SEC("maps") stats_map = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(u32),
	.value_size     = sizeof(struct xdp_stats),
	.max_entries    = 128,
};

static __always_inline void xdp_stats_rx(int idx)
{
	struct xdp_stats *stats;

	stats = bpf_map_lookup_elem(&stats_map, &idx);
	if (stats)
		stats->rx++;
}

static __always_inline void xdp_stats_tx(int idx)
{
	struct xdp_stats *stats;

	stats = bpf_map_lookup_elem(&stats_map, &idx);
	if (stats)
		stats->tx++;
}

static __always_inline void xdp_stats_l3_dev(int idx)
{
	struct xdp_stats *stats;

	stats = bpf_map_lookup_elem(&stats_map, &idx);
	if (stats)
		stats->l3_dev++;
}

static __always_inline void xdp_stats_fib_dev(int idx)
{
	struct xdp_stats *stats;

	stats = bpf_map_lookup_elem(&stats_map, &idx);
	if (stats)
		stats->fib_dev++;
}

static __always_inline void xdp_stats_drop(int idx)
{
	struct xdp_stats *stats;

	stats = bpf_map_lookup_elem(&stats_map, &idx);
	if (stats)
		stats->dropped++;
}

static __always_inline void xdp_stats_skip(int idx)
{
	struct xdp_stats *stats;

	stats = bpf_map_lookup_elem(&stats_map, &idx);
	if (stats)
		stats->skipped++;
}
#else
struct bpf_map_def SEC("maps") rx_stats = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(u32),
	.value_size     = sizeof(u64),
	.max_entries    = 128,
};
struct bpf_map_def SEC("maps") tx_stats = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(u32),
	.value_size     = sizeof(u64),
	.max_entries    = 128,
};
struct bpf_map_def SEC("maps") l3_dev_stats = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(u32),
	.value_size     = sizeof(u64),
	.max_entries    = 128,
};
struct bpf_map_def SEC("maps") fib_dev_stats = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(u32),
	.value_size     = sizeof(u64),
	.max_entries    = 128,
};
struct bpf_map_def SEC("maps") drop_stats = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(u32),
	.value_size     = sizeof(u64),
	.max_entries    = 128,
};
struct bpf_map_def SEC("maps") skip_stats = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(u32),
	.value_size     = sizeof(u64),
	.max_entries    = 128,
};

static __always_inline void xdp_stats_rx(int idx)
{
	u64 *stat;

	stat = bpf_map_lookup_elem(&rx_stats, &idx);
	if (stat)
		*stat += 1;
}

static __always_inline void xdp_stats_tx(int idx)
{
	u64 *stat;

	stat = bpf_map_lookup_elem(&tx_stats, &idx);
	if (stat)
		*stat += 1;
}

static __always_inline void xdp_stats_l3_dev(int idx)
{
	u64 *stat;

	stat = bpf_map_lookup_elem(&l3_dev_stats, &idx);
	if (stat)
		*stat += 1;
}

static __always_inline void xdp_stats_fib_dev(int idx)
{
	u64 *stat;

	stat = bpf_map_lookup_elem(&fib_dev_stats, &idx);
	if (stat)
		*stat += 1;
}

static __always_inline void xdp_stats_drop(int idx)
{
	u64 *stat;

	stat = bpf_map_lookup_elem(&drop_stats, &idx);
	if (stat)
		*stat += 1;
}

static __always_inline void xdp_stats_skip(int idx)
{
	u64 *stat;

	stat = bpf_map_lookup_elem(&skip_stats, &idx);
	if (stat)
		*stat += 1;
}
#endif

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int xdp_fwd_flags(struct xdp_md *ctx, u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_dev_lookup dev_params;
	struct bpf_fib_lookup fib_params;
	int idx = ctx->ingress_ifindex;
	struct vlan_hdr *vhdr = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct ethhdr *eth = data;
	struct iphdr *iph = NULL;
	u32 *idx_enabled;
	u16 h_proto;
	void *nh;
	int rc;

	nh = data + sizeof(*eth);
	if (nh > data_end) {
		xdp_stats_drop(idx);
		return XDP_DROP;
	}

	__builtin_memset(&dev_params, 0, sizeof(dev_params));

	h_proto = eth->h_proto;
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		vhdr = nh;

		if (vhdr + 1 > data_end) {
			xdp_stats_drop(idx);
			return XDP_DROP;
		}

		nh += sizeof(*vhdr);
		dev_params.proto = h_proto;
		dev_params.vlan_TCI = vhdr->h_vlan_TCI;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto != htons(ETH_P_IP) && h_proto != htons(ETH_P_IPV6)) {
		xdp_stats_skip(idx);
		return XDP_PASS;
	}
	xdp_stats_rx(idx);

	dev_params.ifindex = idx;
	memcpy(&dev_params.dmac, eth->h_dest, ETH_ALEN);
	rc = bpf_dev_lookup(ctx, &dev_params, sizeof(dev_params),
			    BPF_DEV_LOOKUP_L3DEV);
	if (rc != 0) {
		xdp_stats_skip(idx);
		return XDP_PASS;
	}
	idx = dev_params.ifindex;
	xdp_stats_l3_dev(idx);

	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	if (h_proto == htons(ETH_P_IP)) {
		iph = nh;

		if (iph + 1 > data_end) {
			xdp_stats_drop(idx);
			return XDP_DROP;
		}

		if (iph->ttl <= 1) {
			xdp_stats_skip(idx);
			return XDP_PASS;
		}

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = nh;
		if (ip6h + 1 > data_end) {
			xdp_stats_drop(idx);
			return XDP_DROP;
		}

		if (ip6h->hop_limit <= 1) {
			xdp_stats_skip(idx);
			return XDP_PASS;
		}

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else {
		return XDP_PASS;
	}

	fib_params.ifindex = idx;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
	if (rc != 0) {
		xdp_stats_skip(idx);
		return XDP_PASS;
	}

	/* convert FIB nexthop device to egress port */
	idx = fib_params.ifindex;
	xdp_stats_fib_dev(idx);

	dev_params.ifindex = fib_params.ifindex;
	dev_params.proto = 0;
	dev_params.vlan_TCI = 0;
	rc = bpf_dev_lookup(ctx, &dev_params, sizeof(dev_params),
			    BPF_DEV_LOOKUP_EGRESS);
	if (rc != 0) {
		xdp_stats_skip(idx);
		return XDP_PASS;
	}
	idx = dev_params.ifindex;

	/* verify egress index has xdp support */
	idx_enabled = bpf_map_lookup_elem(&tx_idxmap, &dev_params.ifindex);
	if (!idx_enabled || !(*idx_enabled)) {
		xdp_stats_skip(idx);
		return XDP_PASS;
	}

	if (iph)
		ip_decrease_ttl(iph);
	else if (ip6h)
		ip6h->hop_limit--;

	/* add, remove, update vlan header as relevant */
	if (dev_params.vlan_TCI) {
		/* ingress no vlan header; egress does */
		if (!vhdr) {
			int delta = sizeof(*vhdr);

			if (bpf_xdp_adjust_head(ctx, -delta)) {
				xdp_stats_skip(idx);
				return XDP_PASS;
			}

			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			eth = data;
			if (eth + 1 > data_end) {
				xdp_stats_drop(idx);
				return XDP_DROP;
			}
			vhdr = data + sizeof(*eth);
			if (vhdr + 1 > data_end) {
				xdp_stats_drop(idx);
				return XDP_DROP;
			}
		}

		vhdr->h_vlan_TCI = dev_params.vlan_TCI;
		vhdr->h_vlan_encapsulated_proto = h_proto;
		h_proto = dev_params.proto;
	} else if (vhdr) {
		/* ingress has a vlan header; egress does not */
		if (bpf_xdp_adjust_head(ctx, sizeof(*vhdr))) {
			xdp_stats_skip(idx);
			return XDP_PASS;
		}

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		if (eth + 1 > data_end) {
			xdp_stats_drop(idx);
			return XDP_DROP;
		}
	}

	/* update eth header */
	memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	eth->h_proto = h_proto;
	xdp_stats_tx(idx);

	return bpf_redirect_map(&tx_devmap, dev_params.ifindex, 0);
}

SEC("xdp_fwd")
int xdp_fwd_prog(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, 0);
}

SEC("xdp_fwd_direct")
int xdp_fwd_direct_prog(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT);
}

char _license[] SEC("license") = "GPL";
