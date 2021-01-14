/* SPDX-License-Identifier: GPL-2.0
 *
 * tcp_ddp.h
 *	Author:	Boris Pismenny <borisp@mellanox.com>
 *	Copyright (C) 2021 Mellanox Technologies.
 */
#ifndef _TCP_DDP_H
#define _TCP_DDP_H

#include <linux/netdevice.h>
#include <net/inet_connection_sock.h>
#include <net/sock.h>

/* limits returned by the offload driver, zero means don't care */
struct tcp_ddp_limits {
	int	 max_ddp_sgl_len;
};

enum tcp_ddp_type {
	TCP_DDP_NVME = 1,
};

/**
 * struct tcp_ddp_config - Generic tcp ddp configuration: tcp ddp IO queue
 * config implementations must use this as the first member.
 * Add new instances of tcp_ddp_config below (nvme-tcp, etc.).
 */
struct tcp_ddp_config {
	enum tcp_ddp_type    type;
	unsigned char        buf[];
};

/**
 * struct nvme_tcp_ddp_config - nvme tcp ddp configuration for an IO queue
 *
 * @pfv:        pdu version (e.g., NVME_TCP_PFV_1_0)
 * @cpda:       controller pdu data alignmend (dwords, 0's based)
 * @dgst:       digest types enabled.
 *              The netdev will offload crc if ddp_crc is supported.
 * @queue_size: number of nvme-tcp IO queue elements
 * @queue_id:   queue identifier
 * @cpu_io:     cpu core running the IO thread for this queue
 */
struct nvme_tcp_ddp_config {
	struct tcp_ddp_config   cfg;

	u16			pfv;
	u8			cpda;
	u8			dgst;
	int			queue_size;
	int			queue_id;
	int			io_cpu;
};

/**
 * struct tcp_ddp_io - tcp ddp configuration for an IO request.
 *
 * @command_id:  identifier on the wire associated with these buffers
 * @nents:       number of entries in the sg_table
 * @sg_table:    describing the buffers for this IO request
 * @first_sgl:   first SGL in sg_table
 */
struct tcp_ddp_io {
	u32			command_id;
	int			nents;
	struct sg_table		sg_table;
	struct scatterlist	first_sgl[SG_CHUNK_SIZE];
};

/* struct tcp_ddp_dev_ops - operations used by an upper layer protocol to configure ddp offload
 *
 * @tcp_ddp_limits:    limit the number of scatter gather entries per IO.
 *                     the device driver can use this to limit the resources allocated per queue.
 * @tcp_ddp_sk_add:    add offload for the queue represennted by the socket+config pair.
 *                     this function is used to configure either copy, crc or both offloads.
 * @tcp_ddp_sk_del:    remove offload from the socket, and release any device related resources.
 * @tcp_ddp_setup:     request copy offload for buffers associated with a command_id in tcp_ddp_io.
 * @tcp_ddp_teardown:  release offload resources association between buffers and command_id in
 *                     tcp_ddp_io.
 * @tcp_ddp_resync:    respond to the driver's resync_request. Called only if resync is successful.
 */
struct tcp_ddp_dev_ops {
	int (*tcp_ddp_limits)(struct net_device *netdev,
			      struct tcp_ddp_limits *limits);
	int (*tcp_ddp_sk_add)(struct net_device *netdev,
			      struct sock *sk,
			      struct tcp_ddp_config *config);
	void (*tcp_ddp_sk_del)(struct net_device *netdev,
			       struct sock *sk);
	int (*tcp_ddp_setup)(struct net_device *netdev,
			     struct sock *sk,
			     struct tcp_ddp_io *io);
	int (*tcp_ddp_teardown)(struct net_device *netdev,
				struct sock *sk,
				struct tcp_ddp_io *io,
				void *ddp_ctx);
	void (*tcp_ddp_resync)(struct net_device *netdev,
			       struct sock *sk, u32 seq);
};

#define TCP_DDP_RESYNC_REQ BIT(0)

/**
 * struct tcp_ddp_ulp_ops - Interface to register uppper layer Direct Data Placement (DDP) TCP offload
 */
struct tcp_ddp_ulp_ops {
	/* NIC requests ulp to indicate if @seq is the start of a message */
	bool (*resync_request)(struct sock *sk, u32 seq, u32 flags);
	/* NIC driver informs the ulp that ddp teardown is done - used for async completions*/
	void (*ddp_teardown_done)(void *ddp_ctx);
};

/**
 * struct tcp_ddp_ctx - Generic tcp ddp context: device driver per queue contexts must
 * use this as the first member.
 */
struct tcp_ddp_ctx {
	enum tcp_ddp_type    type;
	unsigned char        buf[];
};

static inline struct tcp_ddp_ctx *tcp_ddp_get_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	return (__force struct tcp_ddp_ctx *)icsk->icsk_ulp_ddp_data;
}

static inline void tcp_ddp_set_ctx(struct sock *sk, void *ctx)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	rcu_assign_pointer(icsk->icsk_ulp_ddp_data, ctx);
}

#endif //_TCP_DDP_H
