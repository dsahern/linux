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
	struct vlan_hdr *vhdr = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct ethhdr *eth = data;
	struct iphdr *iph = NULL;
	__u32 *idx_enabled;
	u16 h_proto;
	void *nh;
	int rc;

	nh = data + sizeof(*eth);
	if (nh > data_end)
		return XDP_DROP;

	__builtin_memset(&dev_params, 0, sizeof(dev_params));

	h_proto = eth->h_proto;
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		vhdr = nh;

		if (vhdr + 1 > data_end)
			return XDP_DROP;

		nh += sizeof(*vhdr);
		dev_params.proto = h_proto;
		dev_params.vlan_TCI = vhdr->h_vlan_TCI;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto != htons(ETH_P_IP) && h_proto != htons(ETH_P_IPV6))
		return XDP_PASS;

	dev_params.ifindex = ctx->ingress_ifindex;
	memcpy(&dev_params.dmac, eth->h_dest, ETH_ALEN);
	rc = bpf_dev_lookup(ctx, &dev_params, sizeof(dev_params),
			    BPF_DEV_LOOKUP_L3DEV);
	if (rc != 0)
		return XDP_PASS;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	if (h_proto == htons(ETH_P_IP)) {
		iph = nh;

		if (iph + 1 > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS;

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
		if (ip6h + 1 > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

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

	fib_params.ifindex = dev_params.ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
	if (rc != 0)
		return XDP_PASS;

	/* convert FIB nexthop device to egress port */
	dev_params.ifindex = fib_params.ifindex;
	dev_params.proto = 0;
	dev_params.vlan_TCI = 0;
	rc = bpf_dev_lookup(ctx, &dev_params, sizeof(dev_params),
			    BPF_DEV_LOOKUP_EGRESS);
	if (rc != 0)
		return XDP_PASS;

	/* verify egress index has xdp support */
	idx_enabled = bpf_map_lookup_elem(&tx_idxmap, &dev_params.ifindex);
	if (!idx_enabled || !(*idx_enabled))
		return XDP_PASS;

	if (iph)
		ip_decrease_ttl(iph);
	else if (ip6h)
		ip6h->hop_limit--;

	/* add, remove, update vlan header as relevant */
	if (dev_params.vlan_TCI) {
		/* ingress no vlan header; egress does */
		if (!vhdr) {
			int delta = sizeof(*vhdr);

			if (bpf_xdp_adjust_head(ctx, -delta))
				return XDP_PASS;

			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			eth = data;
			if (eth + 1 > data_end)
				return XDP_DROP;
			vhdr = data + sizeof(*eth);
			if (vhdr + 1 > data_end)
				return XDP_DROP;
		}

		vhdr->h_vlan_TCI = dev_params.vlan_TCI;
		vhdr->h_vlan_encapsulated_proto = h_proto;
		h_proto = dev_params.proto;
	} else if (vhdr) {
		/* ingress has a vlan header; egress does not */
		if (bpf_xdp_adjust_head(ctx, sizeof(*vhdr)))
			return XDP_PASS;

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		if (eth + 1 > data_end)
			return XDP_DROP;
	}

	/* update eth header */
	memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	eth->h_proto = h_proto;

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
