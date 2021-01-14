/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */
#ifndef __MLX5E_NVMEOTCP_RXTX_H__
#define __MLX5E_NVMEOTCP_RXTX_H__

#ifdef CONFIG_MLX5_EN_NVMEOTCP

#include <linux/skbuff.h>
#include "en.h"

struct sk_buff*
mlx5e_nvmeotcp_handle_rx_skb(struct net_device *netdev, struct sk_buff *skb,
			     struct mlx5_cqe64 *cqe, u32 cqe_bcnt, bool linear);

static inline int mlx5_nvmeotcp_get_headlen(struct mlx5_cqe64 *cqe, u32 cqe_bcnt)
{
	struct mlx5e_cqe128 *cqe128;

	if (!cqe_is_nvmeotcp_zc(cqe) || cqe_is_nvmeotcp_resync(cqe))
		return cqe_bcnt;

	cqe128 = container_of(cqe, struct mlx5e_cqe128, cqe64);
	return be16_to_cpu(cqe128->hlen);
}

#else
static inline struct sk_buff*
mlx5e_nvmeotcp_handle_rx_skb(struct net_device *netdev, struct sk_buff *skb,
			     struct mlx5_cqe64 *cqe, u32 cqe_bcnt, bool linear)
{ return skb; }

static inline int mlx5_nvmeotcp_get_headlen(struct mlx5_cqe64 *cqe, u32 cqe_bcnt)
{ return cqe_bcnt; }

#endif /* CONFIG_MLX5_EN_NVMEOTCP */

static inline u16 mlx5e_get_headlen_hint(struct mlx5_cqe64 *cqe, u32 cqe_bcnt)
{
	return min_t(u32, MLX5E_RX_MAX_HEAD, mlx5_nvmeotcp_get_headlen(cqe, cqe_bcnt));
}


#endif /* __MLX5E_NVMEOTCP_RXTX_H__ */
