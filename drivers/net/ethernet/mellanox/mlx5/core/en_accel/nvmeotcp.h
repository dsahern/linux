/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */
#ifndef __MLX5E_NVMEOTCP_H__
#define __MLX5E_NVMEOTCP_H__

#ifdef CONFIG_MLX5_EN_NVMEOTCP

#include "net/tcp_ddp.h"
#include "en.h"
#include "en/params.h"

struct nvmeotcp_queue_entry {
	struct mlx5e_nvmeotcp_queue	*queue;
	u32				sgl_length;
	struct mlx5_core_mkey		klm_mkey;
	struct scatterlist		*sgl;
	u32				ccid_gen;
	u64				size;

	/* for the ddp invalidate done callback */
	void				*ddp_ctx;
	struct tcp_ddp_io		*ddp;
};

struct mlx5e_nvmeotcp_sq {
	struct list_head		list;
	struct mlx5e_icosq		icosq;
};

/**
 *	struct mlx5e_nvmeotcp_queue - MLX5 metadata for NVMEoTCP queue
 *	@fh: Flow handle representing the 5-tuple steering for this flow
 *	@tirn: Destination TIR number created for NVMEoTCP offload
 *	@id: Flow tag ID used to identify this queue
 *	@size: NVMEoTCP queue depth
 *	@sq: Send queue used for sending control messages
 *	@ccid_table: Table holding metadata for each CC
 *	@tag_buf_table_id: Tag buffer table for CCIDs
 *	@hash: Hash table of queues mapped by @id
 *	@ref_count: Reference count for this structure
 *	@ccoff: Offset within the current CC
 *	@pda: Padding alignment
 *	@ccid_gen: Generation ID for the CCID, used to avoid conflicts in DDP
 *	@max_klms_per_wqe: Number of KLMs per DDP operation
 *	@channel_ix: Channel IX for this nvmeotcp_queue
 *	@sk: The socket used by the NVMe-TCP queue
 *	@zerocopy: if this queue is used for zerocopy offload.
 *	@crc_rx: if this queue is used for CRC Rx offload.
 *	@ccid: ID of the current CC
 *	@ccsglidx: Index within the scatter-gather list (SGL) of the current CC
 *	@ccoff_inner: Current offset within the @ccsglidx element
 *	@priv: mlx5e netdev priv
 *	@inv_done: invalidate callback of the nvme tcp driver
 *	@after_resync_cqe: indicate if resync occurred
 */
struct mlx5e_nvmeotcp_queue {
	struct tcp_ddp_ctx		tcp_ddp_ctx;
	struct mlx5_flow_handle		*fh;
	int				tirn;
	int				id;
	u32				size;
	struct mlx5e_nvmeotcp_sq	*sq;
	struct nvmeotcp_queue_entry	*ccid_table;
	u32				tag_buf_table_id;
	struct rhash_head		hash;
	refcount_t			ref_count;
	bool				dgst;
	int				pda;
	u32				ccid_gen;
	u32				max_klms_per_wqe;
	u32				channel_ix;
	struct sock			*sk;
	bool				zerocopy;
	bool				crc_rx;

	/* current ccid fields */
	off_t				ccoff;
	int				ccid;
	int				ccsglidx;
	int				ccoff_inner;

	/* for ddp invalidate flow */
	struct mlx5e_priv		*priv;

	/* for flow_steering flow */
	struct completion		done;
	/* for MASK HW resync cqe */
	bool				after_resync_cqe;
};

struct mlx5e_nvmeotcp {
	struct ida			queue_ids;
	struct rhashtable		queue_hash;
	bool				enable;
	bool				crc_rx_enable;
};

void mlx5e_nvmeotcp_build_netdev(struct mlx5e_priv *priv);
int mlx5e_nvmeotcp_init(struct mlx5e_priv *priv);
int set_feature_nvme_tcp(struct net_device *netdev, bool enable);
int set_feature_nvme_tcp_crc(struct net_device *netdev, bool enable);
void mlx5e_nvmeotcp_cleanup(struct mlx5e_priv *priv);
int mlx5e_nvmeotcp_init_rx(struct mlx5e_priv *priv);
void mlx5e_nvmeotcp_cleanup_rx(struct mlx5e_priv *priv);
#else

static inline void mlx5e_nvmeotcp_build_netdev(struct mlx5e_priv *priv) { }
static inline int mlx5e_nvmeotcp_init(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_nvmeotcp_cleanup(struct mlx5e_priv *priv) { }
static inline int set_feature_nvme_tcp(struct net_device *netdev, bool enable) { return 0; }
static inline int set_feature_nvme_tcp_crc(struct net_device *netdev, bool enable) { return 0; }
static inline int mlx5e_nvmeotcp_init_rx(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_nvmeotcp_cleanup_rx(struct mlx5e_priv *priv) { }
#endif
#endif /* __MLX5E_NVMEOTCP_H__ */
