// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2020 Mellanox Technologies.

#ifndef __MLX5E_NVMEOTCP_RXTX_H__
#define __MLX5E_NVMEOTCP_RXTX_H__

#ifdef CONFIG_MLX5_EN_NVMEOTCP

#include <linux/skbuff.h>
#include "en.h"

struct sk_buff*
mlx5e_nvmeotcp_handle_rx_skb(struct net_device *netdev, struct sk_buff *skb,
			     struct mlx5_cqe64 *cqe, u32 cqe_bcnt, bool linear);

int mlx5_nvmeotcp_get_headlen(struct mlx5_cqe64 *cqe, u32 cqe_bcnt);
#else
int mlx5_nvmeotcp_get_headlen(struct mlx5_cqe64 *cqe, u32 cqe_bcnt) { return cqe_bcnt; }
struct sk_buff*
mlx5e_nvmeotcp_handle_rx_skb(struct net_device *netdev, struct sk_buff *skb,
			     struct mlx5_cqe64 *cqe, u32 cqe_bcnt, bool linear)
{ return skb; }

#endif /* CONFIG_MLX5_EN_NVMEOTCP */

#endif /* __MLX5E_NVMEOTCP_RXTX_H__ */
