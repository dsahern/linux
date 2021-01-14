// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include <linux/netdevice.h>
#include <linux/idr.h>
#include "en_accel/nvmeotcp.h"
#include "en_accel/nvmeotcp_utils.h"
#include "en_accel/fs_tcp.h"
#include "en/txrx.h"

#define MAX_NVMEOTCP_QUEUES	(512)
#define MIN_NVMEOTCP_QUEUES	(1)

static const struct rhashtable_params rhash_queues = {
	.key_len = sizeof(int),
	.key_offset = offsetof(struct mlx5e_nvmeotcp_queue, id),
	.head_offset = offsetof(struct mlx5e_nvmeotcp_queue, hash),
	.automatic_shrinking = true,
	.min_size = 1,
	.max_size = MAX_NVMEOTCP_QUEUES,
};

static void
fill_nvmeotcp_klm_wqe(struct mlx5e_nvmeotcp_queue *queue,
		      struct mlx5e_umr_wqe *wqe, u16 ccid, u32 klm_entries,
		      u16 klm_offset)
{
	struct scatterlist *sgl_mkey;
	u32 lkey, i;

	lkey = queue->priv->mdev->mlx5e_res.mkey.key;
	for (i = 0; i < klm_entries; i++) {
		sgl_mkey = &queue->ccid_table[ccid].sgl[i + klm_offset];
		wqe->inline_klms[i].bcount = cpu_to_be32(sgl_mkey->length);
		wqe->inline_klms[i].key	   = cpu_to_be32(lkey);
		wqe->inline_klms[i].va	   = cpu_to_be64(sgl_mkey->dma_address);
	}

	for (; i < ALIGN(klm_entries, KLM_ALIGNMENT); i++) {
		wqe->inline_klms[i].bcount = 0;
		wqe->inline_klms[i].key    = 0;
		wqe->inline_klms[i].va     = 0;
	}
}

static void
build_nvmeotcp_klm_umr(struct mlx5e_nvmeotcp_queue *queue,
		       struct mlx5e_umr_wqe *wqe, u16 ccid, int klm_entries,
		       u32 klm_offset, u32 len)
{
	u32 id = queue->ccid_table[ccid].klm_mkey.key;
	struct mlx5_wqe_umr_ctrl_seg *ucseg = &wqe->uctrl;
	struct mlx5_wqe_ctrl_seg      *cseg = &wqe->ctrl;
	struct mlx5_mkey_seg	       *mkc = &wqe->mkc;

	u32 sqn = queue->sq->icosq.sqn;
	u16 pc = queue->sq->icosq.pc;

	cseg->opmod_idx_opcode = cpu_to_be32((pc << MLX5_WQE_CTRL_WQE_INDEX_SHIFT) |
					     MLX5_OPCODE_UMR);
	cseg->qpn_ds = cpu_to_be32((sqn << MLX5_WQE_CTRL_QPN_SHIFT) |
				   MLX5E_KLM_UMR_DS_CNT(ALIGN(klm_entries, KLM_ALIGNMENT)));
	cseg->general_id = cpu_to_be32(id);

	if (!klm_offset) {
		ucseg->mkey_mask |= cpu_to_be64(MLX5_MKEY_MASK_XLT_OCT_SIZE |
						MLX5_MKEY_MASK_LEN | MLX5_MKEY_MASK_FREE);
		mkc->xlt_oct_size = cpu_to_be32(ALIGN(len, KLM_ALIGNMENT));
		mkc->len = cpu_to_be64(queue->ccid_table[ccid].size);
	}

	ucseg->flags = MLX5_UMR_INLINE | MLX5_UMR_TRANSLATION_OFFSET_EN;
	ucseg->xlt_octowords = cpu_to_be16(ALIGN(klm_entries, KLM_ALIGNMENT));
	ucseg->xlt_offset = cpu_to_be16(klm_offset);
	fill_nvmeotcp_klm_wqe(queue, wqe, ccid, klm_entries, klm_offset);
}

static void
mlx5e_nvmeotcp_fill_wi(struct mlx5e_nvmeotcp_queue *nvmeotcp_queue,
		       struct mlx5e_icosq *sq, u32 wqe_bbs, u16 pi)
{
	struct mlx5e_icosq_wqe_info *wi = &sq->db.wqe_info[pi];

	wi->num_wqebbs = wqe_bbs;
	wi->wqe_type = MLX5E_ICOSQ_WQE_UMR_NVME_TCP;
}

static void
post_klm_wqe(struct mlx5e_nvmeotcp_queue *queue,
	     u16 ccid,
	     u32 klm_length,
	     u32 *klm_offset)
{
	struct mlx5e_icosq *sq = &queue->sq->icosq;
	u32 wqe_bbs, cur_klm_entries;
	struct mlx5e_umr_wqe *wqe;
	u16 pi, wqe_sz;

	cur_klm_entries = min_t(int, queue->max_klms_per_wqe,
				klm_length - *klm_offset);
	wqe_sz = MLX5E_KLM_UMR_WQE_SZ(ALIGN(cur_klm_entries, KLM_ALIGNMENT));
	wqe_bbs = DIV_ROUND_UP(wqe_sz, MLX5_SEND_WQE_BB);
	pi = mlx5e_icosq_get_next_pi(sq, wqe_bbs);
	wqe = MLX5E_NVMEOTCP_FETCH_KLM_WQE(sq, pi);
	mlx5e_nvmeotcp_fill_wi(queue, sq, wqe_bbs, pi);
	build_nvmeotcp_klm_umr(queue, wqe, ccid, cur_klm_entries, *klm_offset,
			       klm_length);
	*klm_offset += cur_klm_entries;
	sq->pc += wqe_bbs;
	sq->doorbell_cseg = &wqe->ctrl;
}

static int
mlx5e_nvmeotcp_post_klm_wqe(struct mlx5e_nvmeotcp_queue *queue,
			    u16 ccid,
			    u32 klm_length)
{
	u32 klm_offset = 0, wqes, wqe_sz, max_wqe_bbs, i, room;
	struct mlx5e_icosq *sq = &queue->sq->icosq;

	/* TODO: set stricter wqe_sz; using max for now */
	wqes = DIV_ROUND_UP(klm_length, queue->max_klms_per_wqe);
	wqe_sz = MLX5E_KLM_UMR_WQE_SZ(queue->max_klms_per_wqe);

	max_wqe_bbs = DIV_ROUND_UP(wqe_sz, MLX5_SEND_WQE_BB);

	room = mlx5e_stop_room_for_wqe(max_wqe_bbs) * wqes;
	if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, room)))
		return -ENOSPC;

	for (i = 0; i < wqes; i++)
		post_klm_wqe(queue, ccid, klm_length, &klm_offset);

	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, sq->doorbell_cseg);
	return 0;
}

static int
mlx5e_nvmeotcp_offload_limits(struct net_device *netdev,
			      struct tcp_ddp_limits *limits)
{
	return 0;
}

static int
mlx5e_nvmeotcp_queue_init(struct net_device *netdev,
			  struct sock *sk,
			  struct tcp_ddp_config *tconfig)
{
	return 0;
}

static void
mlx5e_nvmeotcp_queue_teardown(struct net_device *netdev,
			      struct sock *sk)
{
}

static int
mlx5e_nvmeotcp_ddp_setup(struct net_device *netdev,
			 struct sock *sk,
			 struct tcp_ddp_io *ddp)
{
	return 0;
}

static int
mlx5e_nvmeotcp_ddp_teardown(struct net_device *netdev,
			    struct sock *sk,
			    struct tcp_ddp_io *ddp,
			    void *ddp_ctx)
{
	return 0;
}

static void
mlx5e_nvmeotcp_dev_resync(struct net_device *netdev,
			  struct sock *sk, u32 seq)
{
}

static const struct tcp_ddp_dev_ops mlx5e_nvmeotcp_ops = {
	.tcp_ddp_limits = mlx5e_nvmeotcp_offload_limits,
	.tcp_ddp_sk_add = mlx5e_nvmeotcp_queue_init,
	.tcp_ddp_sk_del = mlx5e_nvmeotcp_queue_teardown,
	.tcp_ddp_setup = mlx5e_nvmeotcp_ddp_setup,
	.tcp_ddp_teardown = mlx5e_nvmeotcp_ddp_teardown,
	.tcp_ddp_resync = mlx5e_nvmeotcp_dev_resync,
};

int set_feature_nvme_tcp(struct net_device *netdev, bool enable)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err = 0;

	mutex_lock(&priv->state_lock);
	if (enable)
		err = mlx5e_accel_fs_tcp_create(priv);
	else
		mlx5e_accel_fs_tcp_destroy(priv);
	mutex_unlock(&priv->state_lock);
	if (err)
		return err;

	priv->nvmeotcp->enable = enable;
	err = mlx5e_safe_reopen_channels(priv);
	return err;
}

int set_feature_nvme_tcp_crc(struct net_device *netdev, bool enable)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err = 0;

	mutex_lock(&priv->state_lock);
	if (enable)
		err = mlx5e_accel_fs_tcp_create(priv);
	else
		mlx5e_accel_fs_tcp_destroy(priv);
	mutex_unlock(&priv->state_lock);

	priv->nvmeotcp->crc_rx_enable = enable;
	err = mlx5e_safe_reopen_channels(priv);
	if (err)
		netdev_err(priv->netdev,
			   "%s failed to reopen channels, err(%d).\n",
			   __func__, err);

	return err;
}

void mlx5e_nvmeotcp_build_netdev(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;

	if (!MLX5_CAP_GEN(priv->mdev, nvmeotcp))
		return;

	if (MLX5_CAP_DEV_NVMEOTCP(priv->mdev, zerocopy)) {
		netdev->features |= NETIF_F_HW_TCP_DDP;
		netdev->hw_features |= NETIF_F_HW_TCP_DDP;
	}

	if (MLX5_CAP_DEV_NVMEOTCP(priv->mdev, crc_rx)) {
		netdev->features |= NETIF_F_HW_TCP_DDP_CRC_RX;
		netdev->hw_features |= NETIF_F_HW_TCP_DDP_CRC_RX;
	}

	netdev->tcp_ddp_ops = &mlx5e_nvmeotcp_ops;
	priv->nvmeotcp->enable = true;
}

int mlx5e_nvmeotcp_init_rx(struct mlx5e_priv *priv)
{
	int ret = 0;

	if (priv->netdev->features & NETIF_F_HW_TCP_DDP) {
		ret = mlx5e_accel_fs_tcp_create(priv);
		if (ret)
			return ret;
	}

	if (priv->netdev->features & NETIF_F_HW_TCP_DDP_CRC_RX)
		ret = mlx5e_accel_fs_tcp_create(priv);

	return ret;
}

void mlx5e_nvmeotcp_cleanup_rx(struct mlx5e_priv *priv)
{
	if (priv->netdev->features & NETIF_F_HW_TCP_DDP)
		mlx5e_accel_fs_tcp_destroy(priv);

	if (priv->netdev->features & NETIF_F_HW_TCP_DDP_CRC_RX)
		mlx5e_accel_fs_tcp_destroy(priv);
}

int mlx5e_nvmeotcp_init(struct mlx5e_priv *priv)
{
	struct mlx5e_nvmeotcp *nvmeotcp = kzalloc(sizeof(*nvmeotcp), GFP_KERNEL);
	int ret = 0;

	if (!nvmeotcp)
		return -ENOMEM;

	ida_init(&nvmeotcp->queue_ids);
	ret = rhashtable_init(&nvmeotcp->queue_hash, &rhash_queues);
	if (ret)
		goto err_ida;

	priv->nvmeotcp = nvmeotcp;
	goto out;

err_ida:
	ida_destroy(&nvmeotcp->queue_ids);
	kfree(nvmeotcp);
out:
	return ret;
}

void mlx5e_nvmeotcp_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_nvmeotcp *nvmeotcp = priv->nvmeotcp;

	if (!nvmeotcp)
		return;

	rhashtable_destroy(&nvmeotcp->queue_hash);
	ida_destroy(&nvmeotcp->queue_ids);
	kfree(nvmeotcp);
	priv->nvmeotcp = NULL;
}
