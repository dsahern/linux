/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */
#ifndef __MLX5E_NVMEOTCP_UTILS_H__
#define __MLX5E_NVMEOTCP_UTILS_H__

#include "en.h"

#define MLX5E_NVMEOTCP_FETCH_KLM_WQE(sq, pi) \
	((struct mlx5e_umr_wqe *)\
	 mlx5e_fetch_wqe(&(sq)->wq, pi, sizeof(struct mlx5e_umr_wqe)))

#endif /* __MLX5E_NVMEOTCP_UTILS_H__ */
