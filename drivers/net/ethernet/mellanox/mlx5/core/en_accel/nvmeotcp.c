// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include <linux/netdevice.h>
#include <linux/idr.h>
#include "en_accel/nvmeotcp.h"
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
