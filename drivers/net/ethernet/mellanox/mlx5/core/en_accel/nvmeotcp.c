// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include <linux/netdevice.h>
#include <linux/idr.h>
#include <linux/nvme-tcp.h>
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

#define MLX5_NVME_TCP_MAX_SEGMENTS 128

static u32 mlx5e_get_max_sgl(struct mlx5_core_dev *mdev)
{
	return min_t(u32,
		     MLX5_NVME_TCP_MAX_SEGMENTS,
		     1 << MLX5_CAP_GEN(mdev, log_max_klm_list_size));
}

static void mlx5e_nvmeotcp_destroy_tir(struct mlx5e_priv *priv, int tirn)
{
	mlx5_core_destroy_tir(priv->mdev, tirn);
}

static inline u32
mlx5e_get_channel_ix_from_io_cpu(struct mlx5e_priv *priv, u32 io_cpu)
{
	int num_channels = priv->channels.params.num_channels;
	u32 channel_ix = io_cpu;

	if (channel_ix >= num_channels)
		channel_ix = channel_ix % num_channels;

	return channel_ix;
}

static int mlx5e_nvmeotcp_create_tir(struct mlx5e_priv *priv,
				     struct sock *sk,
				     struct nvme_tcp_ddp_config *config,
				     struct mlx5e_nvmeotcp_queue *queue,
				     bool zerocopy, bool crc_rx)
{
	u32 rqtn = priv->direct_tir[queue->channel_ix].rqt.rqtn;
	int err, inlen;
	void *tirc;
	u32 tirn;
	u32 *in;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_INDIRECT);
	MLX5_SET(tirc, tirc, rx_hash_fn, MLX5_RX_HASH_FN_INVERTED_XOR8);
	MLX5_SET(tirc, tirc, indirect_table, rqtn);
	MLX5_SET(tirc, tirc, transport_domain, priv->mdev->mlx5e_res.td.tdn);
	if (zerocopy) {
		MLX5_SET(tirc, tirc, nvmeotcp_zero_copy_en, 1);
		MLX5_SET(tirc, tirc, nvmeotcp_tag_buffer_table_id,
			 queue->tag_buf_table_id);
	}

	if (crc_rx)
		MLX5_SET(tirc, tirc, nvmeotcp_crc_en, 1);

	MLX5_SET(tirc, tirc, self_lb_block,
		 MLX5_TIRC_SELF_LB_BLOCK_BLOCK_UNICAST |
		 MLX5_TIRC_SELF_LB_BLOCK_BLOCK_MULTICAST);
	err = mlx5_core_create_tir(priv->mdev, in, &tirn);

	if (!err)
		queue->tirn = tirn;

	kvfree(in);
	return err;
}

static
int mlx5e_create_nvmeotcp_tag_buf_table(struct mlx5_core_dev *mdev,
					struct mlx5e_nvmeotcp_queue *queue,
					u8 log_table_size)
{
	u32 in[MLX5_ST_SZ_DW(create_nvmeotcp_tag_buf_table_in)] = {};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];
	u64 general_obj_types;
	void *obj;
	int err;

	obj = MLX5_ADDR_OF(create_nvmeotcp_tag_buf_table_in, in,
			   nvmeotcp_tag_buf_table_obj);

	general_obj_types = MLX5_CAP_GEN_64(mdev, general_obj_types);
	if (!(general_obj_types &
	      MLX5_HCA_CAP_GENERAL_OBJECT_TYPES_NVMEOTCP_TAG_BUFFER_TABLE))
		return -EINVAL;

	MLX5_SET(general_obj_in_cmd_hdr, in, opcode,
		 MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_type,
		 MLX5_GENERAL_OBJECT_TYPES_NVMEOTCP_TAG_BUFFER_TABLE);
	MLX5_SET(nvmeotcp_tag_buf_table_obj, obj,
		 log_tag_buffer_table_size, log_table_size);

	err = mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
	if (!err)
		queue->tag_buf_table_id = MLX5_GET(general_obj_out_cmd_hdr,
						   out, obj_id);
	return err;
}

static
void mlx5_destroy_nvmeotcp_tag_buf_table(struct mlx5_core_dev *mdev, u32 uid)
{
	u32 in[MLX5_ST_SZ_DW(general_obj_in_cmd_hdr)] = {};
	u32 out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)];

	MLX5_SET(general_obj_in_cmd_hdr, in, opcode,
		 MLX5_CMD_OP_DESTROY_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_type,
		 MLX5_GENERAL_OBJECT_TYPES_NVMEOTCP_TAG_BUFFER_TABLE);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_id, uid);

	mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
}

#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_TIR_PARAMS 0x2
#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIR_STATIC_PARAMS 0x2
#define MLX5_CTRL_SEGMENT_OPC_MOD_UMR_UMR 0x0

#define STATIC_PARAMS_DS_CNT \
	DIV_ROUND_UP(MLX5E_NVMEOTCP_STATIC_PARAMS_WQE_SZ, MLX5_SEND_WQE_DS)

#define PROGRESS_PARAMS_DS_CNT \
	DIV_ROUND_UP(MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQE_SZ, MLX5_SEND_WQE_DS)

enum wqe_type {
	KLM_UMR = 0,
	BSF_KLM_UMR = 1,
	SET_PSV_UMR = 2,
	BSF_UMR = 3,
	KLM_INV_UMR = 4,
};

static void
fill_nvmeotcp_klm_wqe(struct mlx5e_nvmeotcp_queue *queue,
		      struct mlx5e_umr_wqe *wqe, u16 ccid, u32 klm_entries,
		      u16 klm_offset, enum wqe_type klm_type)
{
	struct scatterlist *sgl_mkey;
	u32 lkey, i;

	if (klm_type == BSF_KLM_UMR) {
		for (i = 0; i < klm_entries; i++) {
			lkey = queue->ccid_table[i + klm_offset].klm_mkey.key;
			wqe->inline_klms[i].bcount = cpu_to_be32(1);
			wqe->inline_klms[i].key	   = cpu_to_be32(lkey);
			wqe->inline_klms[i].va	   = 0;
		}
	} else {
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
}

static void
build_nvmeotcp_klm_umr(struct mlx5e_nvmeotcp_queue *queue,
		       struct mlx5e_umr_wqe *wqe, u16 ccid, int klm_entries,
		       u32 klm_offset, u32 len, enum wqe_type klm_type)
{
	u32 id = (klm_type == KLM_UMR) ? queue->ccid_table[ccid].klm_mkey.key :
		(queue->tirn << MLX5_WQE_CTRL_TIR_TIS_INDEX_SHIFT);
	u8 opc_mod = (klm_type == KLM_UMR) ? MLX5_CTRL_SEGMENT_OPC_MOD_UMR_UMR :
		MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIR_STATIC_PARAMS;
	struct mlx5_wqe_umr_ctrl_seg *ucseg = &wqe->uctrl;
	struct mlx5_wqe_ctrl_seg      *cseg = &wqe->ctrl;
	struct mlx5_mkey_seg	       *mkc = &wqe->mkc;

	u32 sqn = queue->sq->icosq.sqn;
	u16 pc = queue->sq->icosq.pc;

	cseg->opmod_idx_opcode = cpu_to_be32((pc << MLX5_WQE_CTRL_WQE_INDEX_SHIFT) |
					     MLX5_OPCODE_UMR | (opc_mod) << 24);
	cseg->qpn_ds = cpu_to_be32((sqn << MLX5_WQE_CTRL_QPN_SHIFT) |
				   MLX5E_KLM_UMR_DS_CNT(ALIGN(klm_entries, KLM_ALIGNMENT)));
	cseg->general_id = cpu_to_be32(id);

	if (!klm_entries) { /* this is invalidate */
		ucseg->mkey_mask = cpu_to_be64(MLX5_MKEY_MASK_FREE);
		ucseg->flags = MLX5_UMR_INLINE;
		mkc->status = MLX5_MKEY_STATUS_FREE;
		return;
	}

	if (klm_type == KLM_UMR && !klm_offset) {
		ucseg->mkey_mask |= cpu_to_be64(MLX5_MKEY_MASK_XLT_OCT_SIZE |
						MLX5_MKEY_MASK_LEN | MLX5_MKEY_MASK_FREE);
		mkc->xlt_oct_size = cpu_to_be32(ALIGN(len, KLM_ALIGNMENT));
		mkc->len = cpu_to_be64(queue->ccid_table[ccid].size);
	}

	ucseg->flags = MLX5_UMR_INLINE | MLX5_UMR_TRANSLATION_OFFSET_EN;
	ucseg->xlt_octowords = cpu_to_be16(ALIGN(klm_entries, KLM_ALIGNMENT));
	ucseg->xlt_offset = cpu_to_be16(klm_offset);
	fill_nvmeotcp_klm_wqe(queue, wqe, ccid, klm_entries, klm_offset, klm_type);
}

static void
fill_nvmeotcp_progress_params(struct mlx5e_nvmeotcp_queue *queue,
			      struct mlx5_seg_nvmeotcp_progress_params *params,
			      u32 seq)
{
	void *ctx = params->ctx;

	params->tir_num = cpu_to_be32(queue->tirn);

	MLX5_SET(nvmeotcp_progress_params, ctx,
		 next_pdu_tcp_sn, seq);
	MLX5_SET(nvmeotcp_progress_params, ctx, pdu_tracker_state,
		 MLX5E_NVMEOTCP_PROGRESS_PARAMS_PDU_TRACKER_STATE_START);
}

void
build_nvmeotcp_progress_params(struct mlx5e_nvmeotcp_queue *queue,
			       struct mlx5e_set_nvmeotcp_progress_params_wqe *wqe,
			       u32 seq)
{
	struct mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl;
	u32 sqn = queue->sq->icosq.sqn;
	u16 pc = queue->sq->icosq.pc;
	u8 opc_mod;

	memset(wqe, 0, MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQE_SZ);
	opc_mod = MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIR_PROGRESS_PARAMS;
	cseg->opmod_idx_opcode = cpu_to_be32((pc << MLX5_WQE_CTRL_WQE_INDEX_SHIFT) |
					     MLX5_OPCODE_SET_PSV | (opc_mod << 24));
	cseg->qpn_ds = cpu_to_be32((sqn << MLX5_WQE_CTRL_QPN_SHIFT) |
				   PROGRESS_PARAMS_DS_CNT);
	fill_nvmeotcp_progress_params(queue, &wqe->params, seq);
}

static void
fill_nvmeotcp_static_params(struct mlx5e_nvmeotcp_queue *queue,
			    struct mlx5_seg_nvmeotcp_static_params *params,
			    u32 resync_seq, bool zero_copy_en,
			    bool ddgst_offload_en)
{
	void *ctx = params->ctx;

	MLX5_SET(transport_static_params, ctx, const_1, 1);
	MLX5_SET(transport_static_params, ctx, const_2, 2);
	MLX5_SET(transport_static_params, ctx, acc_type,
		 MLX5_TRANSPORT_STATIC_PARAMS_ACC_TYPE_NVMETCP);
	MLX5_SET(transport_static_params, ctx, nvme_resync_tcp_sn, resync_seq);
	MLX5_SET(transport_static_params, ctx, pda, queue->pda);
	MLX5_SET(transport_static_params, ctx, ddgst_en, queue->dgst);
	MLX5_SET(transport_static_params, ctx, ddgst_offload_en, ddgst_offload_en);
	MLX5_SET(transport_static_params, ctx, hddgst_en, 0);
	MLX5_SET(transport_static_params, ctx, hdgst_offload_en, 0);
	MLX5_SET(transport_static_params, ctx, ti,
		 MLX5_TRANSPORT_STATIC_PARAMS_TI_INITIATOR);
	MLX5_SET(transport_static_params, ctx, const1, 1);
	MLX5_SET(transport_static_params, ctx, zero_copy_en, zero_copy_en);
}

void
build_nvmeotcp_static_params(struct mlx5e_nvmeotcp_queue *queue,
			     struct mlx5e_set_nvmeotcp_static_params_wqe *wqe,
			     u32 resync_seq, bool zerocopy, bool crc_rx)
{
	u8 opc_mod = MLX5_CTRL_SEGMENT_OPC_MOD_UMR_NVMEOTCP_TIR_STATIC_PARAMS;
	struct mlx5_wqe_umr_ctrl_seg *ucseg = &wqe->uctrl;
	struct mlx5_wqe_ctrl_seg      *cseg = &wqe->ctrl;
	u32 sqn = queue->sq->icosq.sqn;
	u16 pc = queue->sq->icosq.pc;

	memset(wqe, 0, MLX5E_NVMEOTCP_STATIC_PARAMS_WQE_SZ);

	cseg->opmod_idx_opcode = cpu_to_be32((pc << MLX5_WQE_CTRL_WQE_INDEX_SHIFT) |
					     MLX5_OPCODE_UMR | (opc_mod) << 24);
	cseg->qpn_ds = cpu_to_be32((sqn << MLX5_WQE_CTRL_QPN_SHIFT) |
				   STATIC_PARAMS_DS_CNT);
	cseg->imm = cpu_to_be32(queue->tirn << MLX5_WQE_CTRL_TIR_TIS_INDEX_SHIFT);

	ucseg->flags = MLX5_UMR_INLINE;
	ucseg->bsf_octowords =
		cpu_to_be16(MLX5E_NVMEOTCP_STATIC_PARAMS_OCTWORD_SIZE);
	fill_nvmeotcp_static_params(queue, &wqe->params, resync_seq, zerocopy, crc_rx);
}

static void
mlx5e_nvmeotcp_fill_wi(struct mlx5e_nvmeotcp_queue *nvmeotcp_queue,
		       struct mlx5e_icosq *sq, u32 wqe_bbs,
		       u16 pi, u16 ccid, enum wqe_type type)
{
	struct mlx5e_icosq_wqe_info *wi = &sq->db.wqe_info[pi];

	wi->num_wqebbs = wqe_bbs;
	switch (type) {
	case SET_PSV_UMR:
		wi->wqe_type = MLX5E_ICOSQ_WQE_SET_PSV_NVME_TCP;
		break;
	case KLM_INV_UMR:
		wi->wqe_type = MLX5E_ICOSQ_WQE_UMR_NVME_TCP_INVALIDATE;
		break;
	default:
		wi->wqe_type = MLX5E_ICOSQ_WQE_UMR_NVME_TCP;
		break;
	}

	if (type == KLM_INV_UMR)
		wi->nvmeotcp_qe.entry = &nvmeotcp_queue->ccid_table[ccid];
	else if (type == SET_PSV_UMR)
		wi->nvmeotcp_q.queue = nvmeotcp_queue;
}

static void
mlx5e_nvmeotcp_rx_post_static_params_wqe(struct mlx5e_nvmeotcp_queue *queue,
					 u32 resync_seq)
{
	struct mlx5e_set_nvmeotcp_static_params_wqe *wqe;
	struct mlx5e_icosq *sq = &queue->sq->icosq;
	u16 pi, wqe_bbs;

	wqe_bbs = MLX5E_NVMEOTCP_STATIC_PARAMS_WQEBBS;
	pi = mlx5e_icosq_get_next_pi(sq, wqe_bbs);
	wqe = MLX5E_NVMEOTCP_FETCH_STATIC_PARAMS_WQE(sq, pi);
	mlx5e_nvmeotcp_fill_wi(NULL, sq, wqe_bbs, pi, 0, BSF_UMR);
	build_nvmeotcp_static_params(queue, wqe, resync_seq, queue->zerocopy, queue->crc_rx);
	sq->pc += wqe_bbs;
	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, &wqe->ctrl);
}

static void
mlx5e_nvmeotcp_rx_post_progress_params_wqe(struct mlx5e_nvmeotcp_queue *queue,
					   u32 seq)
{
	struct mlx5e_set_nvmeotcp_progress_params_wqe *wqe;
	struct mlx5e_icosq *sq = &queue->sq->icosq;
	u16 pi, wqe_bbs;

	wqe_bbs = MLX5E_NVMEOTCP_PROGRESS_PARAMS_WQEBBS;
	pi = mlx5e_icosq_get_next_pi(sq, wqe_bbs);
	wqe = MLX5E_NVMEOTCP_FETCH_PROGRESS_PARAMS_WQE(sq, pi);
	mlx5e_nvmeotcp_fill_wi(queue, sq, wqe_bbs, pi, 0, SET_PSV_UMR);
	build_nvmeotcp_progress_params(queue, wqe, seq);
	sq->pc += wqe_bbs;
	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, &wqe->ctrl);
}

static void
post_klm_wqe(struct mlx5e_nvmeotcp_queue *queue,
	     enum wqe_type wqe_type,
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
	mlx5e_nvmeotcp_fill_wi(queue, sq, wqe_bbs, pi, ccid,
			       klm_length ? KLM_UMR : KLM_INV_UMR);
	build_nvmeotcp_klm_umr(queue, wqe, ccid, cur_klm_entries, *klm_offset,
			       klm_length, wqe_type);
	*klm_offset += cur_klm_entries;
	sq->pc += wqe_bbs;
	sq->doorbell_cseg = &wqe->ctrl;
}

static int
mlx5e_nvmeotcp_post_klm_wqe(struct mlx5e_nvmeotcp_queue *queue,
			    enum wqe_type wqe_type,
			    u16 ccid,
			    u32 klm_length)
{
	u32 klm_offset = 0, wqes, wqe_sz, max_wqe_bbs, i, room;
	struct mlx5e_icosq *sq = &queue->sq->icosq;

	/* TODO: set stricter wqe_sz; using max for now */
	if (klm_length == 0) {
		wqes = 1;
		wqe_sz = MLX5E_NVMEOTCP_STATIC_PARAMS_WQEBBS;
	} else {
		wqes = DIV_ROUND_UP(klm_length, queue->max_klms_per_wqe);
		wqe_sz = MLX5E_KLM_UMR_WQE_SZ(queue->max_klms_per_wqe);
	}

	max_wqe_bbs = DIV_ROUND_UP(wqe_sz, MLX5_SEND_WQE_BB);

	room = mlx5e_stop_room_for_wqe(max_wqe_bbs) * wqes;
	if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, room)))
		return -ENOSPC;

	for (i = 0; i < wqes; i++)
		post_klm_wqe(queue, wqe_type, ccid, klm_length, &klm_offset);

	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, sq->doorbell_cseg);
	return 0;
}

static int mlx5e_create_nvmeotcp_mkey(struct mlx5_core_dev *mdev,
				      u8 access_mode,
				      u32 translation_octword_size,
				      struct mlx5_core_mkey *mkey)
{
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	void *mkc;
	u32 *in;
	int err;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, free, 1);
	MLX5_SET(mkc, mkc, translations_octword_size, translation_octword_size);
	MLX5_SET(mkc, mkc, umr_en, 1);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, lr, 1);
	MLX5_SET(mkc, mkc, access_mode_1_0, access_mode);

	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, pd, mdev->mlx5e_res.pdn);

	err = mlx5_core_create_mkey(mdev, mkey, in, inlen);

	kvfree(in);
	return err;
}

static int
mlx5e_nvmeotcp_offload_limits(struct net_device *netdev,
			      struct tcp_ddp_limits *limits)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;

	limits->max_ddp_sgl_len = mlx5e_get_max_sgl(mdev);
	return 0;
}

static void
mlx5e_nvmeotcp_destroy_sq(struct mlx5e_nvmeotcp_sq *nvmeotcpsq)
{
	mlx5e_deactivate_icosq(&nvmeotcpsq->icosq);
	mlx5e_close_icosq(&nvmeotcpsq->icosq);
	mlx5e_close_cq(&nvmeotcpsq->icosq.cq);
	list_del(&nvmeotcpsq->list);
	kfree(nvmeotcpsq);
}

static int
mlx5e_nvmeotcp_build_icosq(struct mlx5e_nvmeotcp_queue *queue,
			   struct mlx5e_priv *priv)
{
	u16 max_sgl, max_klm_per_wqe, max_umr_per_ccid, sgl_rest, wqebbs_rest;
	struct mlx5e_channel *c = priv->channels.c[queue->channel_ix];
	struct mlx5e_sq_param icosq_param = {0};
	struct dim_cq_moder icocq_moder = {0};
	struct mlx5e_nvmeotcp_sq *nvmeotcp_sq;
	struct mlx5e_create_cq_param ccp;
	struct mlx5e_icosq *icosq;
	int err = -ENOMEM;
	u16 log_icosq_sz;
	u32 max_wqebbs;

	nvmeotcp_sq = kzalloc(sizeof(*nvmeotcp_sq), GFP_KERNEL);
	if (!nvmeotcp_sq)
		return err;

	icosq = &nvmeotcp_sq->icosq;
	max_sgl = mlx5e_get_max_sgl(priv->mdev);
	max_klm_per_wqe = queue->max_klms_per_wqe;
	max_umr_per_ccid = max_sgl / max_klm_per_wqe;
	sgl_rest = max_sgl % max_klm_per_wqe;
	wqebbs_rest = sgl_rest ? MLX5E_KLM_UMR_WQEBBS(sgl_rest) : 0;
	max_wqebbs = (MLX5E_KLM_UMR_WQEBBS(max_klm_per_wqe) *
		     max_umr_per_ccid + wqebbs_rest) * queue->size;
	log_icosq_sz = order_base_2(max_wqebbs);

	mlx5e_build_icosq_param(priv, log_icosq_sz, &icosq_param);
	mlx5e_build_create_cq_param(&ccp, c);
	err = mlx5e_open_cq(priv, icocq_moder, &icosq_param.cqp, &ccp, &icosq->cq);
	if (err)
		goto err_nvmeotcp_sq;

	err = mlx5e_open_icosq(c, &priv->channels.params, &icosq_param, icosq);
	if (err)
		goto close_cq;

	INIT_LIST_HEAD(&nvmeotcp_sq->list);
	spin_lock(&c->nvmeotcp_icosq_lock);
	list_add(&nvmeotcp_sq->list, &c->list_nvmeotcpsq);
	spin_unlock(&c->nvmeotcp_icosq_lock);
	queue->sq = nvmeotcp_sq;
	mlx5e_activate_icosq(icosq);
	return 0;

close_cq:
	mlx5e_close_cq(&icosq->cq);
err_nvmeotcp_sq:
	kfree(nvmeotcp_sq);

	return err;
}

static void
mlx5e_nvmeotcp_destroy_rx(struct mlx5e_nvmeotcp_queue *queue,
			  struct mlx5_core_dev *mdev, bool zerocopy)
{
	int i;

	mlx5e_accel_fs_del_sk(queue->fh);
	for (i = 0; i < queue->size && zerocopy; i++)
		mlx5_core_destroy_mkey(mdev, &queue->ccid_table[i].klm_mkey);

	mlx5e_nvmeotcp_destroy_tir(queue->priv, queue->tirn);
	if (zerocopy) {
		kfree(queue->ccid_table);
		mlx5_destroy_nvmeotcp_tag_buf_table(mdev, queue->tag_buf_table_id);
	}

	mlx5e_nvmeotcp_destroy_sq(queue->sq);
}

static int
mlx5e_nvmeotcp_queue_rx_init(struct mlx5e_nvmeotcp_queue *queue,
			     struct nvme_tcp_ddp_config *config,
			     struct net_device *netdev,
			     bool zerocopy, bool crc)
{
	u8 log_queue_size = order_base_2(config->queue_size);
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct sock *sk = queue->sk;
	int err, max_sgls, i;

	if (zerocopy) {
		if (config->queue_size >
		    BIT(MLX5_CAP_DEV_NVMEOTCP(mdev, log_max_nvmeotcp_tag_buffer_size))) {
			return -EINVAL;
		}

		err = mlx5e_create_nvmeotcp_tag_buf_table(mdev, queue, log_queue_size);
		if (err)
			return err;
	}

	err = mlx5e_nvmeotcp_build_icosq(queue, priv);
	if (err)
		goto destroy_tag_buffer_table;

	/* initializes queue->tirn */
	err = mlx5e_nvmeotcp_create_tir(priv, sk, config, queue, zerocopy, crc);
	if (err)
		goto destroy_icosq;

	mlx5e_nvmeotcp_rx_post_static_params_wqe(queue, 0);
	mlx5e_nvmeotcp_rx_post_progress_params_wqe(queue, tcp_sk(sk)->copied_seq);

	if (zerocopy) {
		queue->ccid_table = kcalloc(queue->size,
					    sizeof(struct nvmeotcp_queue_entry),
					    GFP_KERNEL);
		if (!queue->ccid_table) {
			err = -ENOMEM;
			goto destroy_tir;
		}

		max_sgls = mlx5e_get_max_sgl(mdev);
		for (i = 0; i < queue->size; i++) {
			err = mlx5e_create_nvmeotcp_mkey(mdev,
							 MLX5_MKC_ACCESS_MODE_KLMS,
							 max_sgls,
							 &queue->ccid_table[i].klm_mkey);
			if (err)
				goto free_sgl;
		}

		err = mlx5e_nvmeotcp_post_klm_wqe(queue, BSF_KLM_UMR, 0, queue->size);
		if (err)
			goto free_sgl;
	}

	if (!(WARN_ON(!wait_for_completion_timeout(&queue->done, 0))))
		queue->fh = mlx5e_accel_fs_add_sk(priv, sk, queue->tirn, queue->id);

	if (IS_ERR_OR_NULL(queue->fh)) {
		err = -EINVAL;
		goto free_sgl;
	}

	return 0;

free_sgl:
	while ((i--) && zerocopy)
		mlx5_core_destroy_mkey(mdev, &queue->ccid_table[i].klm_mkey);

	if (zerocopy)
		kfree(queue->ccid_table);
destroy_tir:
	mlx5e_nvmeotcp_destroy_tir(priv, queue->tirn);
destroy_icosq:
	mlx5e_nvmeotcp_destroy_sq(queue->sq);
destroy_tag_buffer_table:
	if (zerocopy)
		mlx5_destroy_nvmeotcp_tag_buf_table(mdev, queue->tag_buf_table_id);

	return err;
}

#define OCTWORD_SHIFT 4
#define MAX_DS_VALUE 63
static int
mlx5e_nvmeotcp_queue_init(struct net_device *netdev,
			  struct sock *sk,
			  struct tcp_ddp_config *tconfig)
{
	struct nvme_tcp_ddp_config *config = (struct nvme_tcp_ddp_config *)tconfig;
	bool crc_rx = (netdev->features & NETIF_F_HW_TCP_DDP_CRC_RX);
	bool zerocopy = (netdev->features & NETIF_F_HW_TCP_DDP);
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_nvmeotcp_queue *queue;
	int max_wqe_sz_cap, queue_id, err;
	struct mlx5e_rq_stats *stats;
	u32 channel_ix;

	channel_ix = mlx5e_get_channel_ix_from_io_cpu(priv, config->io_cpu);
	stats = &priv->channel_stats[channel_ix].rq;

	if (tconfig->type != TCP_DDP_NVME) {
		err = -EOPNOTSUPP;
		goto out;
	}

	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue) {
		err = -ENOMEM;
		goto out;
	}

	queue_id = ida_simple_get(&priv->nvmeotcp->queue_ids,
				  MIN_NVMEOTCP_QUEUES, MAX_NVMEOTCP_QUEUES,
				  GFP_KERNEL);
	if (queue_id < 0) {
		err = -ENOSPC;
		goto free_queue;
	}

	queue->crc_rx = crc_rx;
	queue->zerocopy = zerocopy;
	queue->tcp_ddp_ctx.type = TCP_DDP_NVME;
	queue->sk = sk;
	queue->id = queue_id;
	queue->dgst = config->dgst;
	queue->pda = config->cpda;
	queue->channel_ix = channel_ix;
	queue->size = config->queue_size;
	max_wqe_sz_cap  = min_t(int, MAX_DS_VALUE * MLX5_SEND_WQE_DS,
				MLX5_CAP_GEN(mdev, max_wqe_sz_sq) << OCTWORD_SHIFT);
	queue->max_klms_per_wqe = MLX5E_KLM_ENTRIES_PER_WQE(max_wqe_sz_cap);
	queue->priv = priv;
	init_completion(&queue->done);

	if (zerocopy || crc_rx) {
		err = mlx5e_nvmeotcp_queue_rx_init(queue, config, netdev,
						   zerocopy, crc_rx);
		if (err)
			goto remove_queue_id;
	}

	err = rhashtable_insert_fast(&priv->nvmeotcp->queue_hash, &queue->hash,
				     rhash_queues);
	if (err)
		goto destroy_rx;

	stats->nvmeotcp_queue_init++;
	write_lock_bh(&sk->sk_callback_lock);
	tcp_ddp_set_ctx(sk, queue);
	write_unlock_bh(&sk->sk_callback_lock);
	refcount_set(&queue->ref_count, 1);
	return err;

destroy_rx:
	if (zerocopy || crc_rx)
		mlx5e_nvmeotcp_destroy_rx(queue, mdev, zerocopy);
remove_queue_id:
	ida_simple_remove(&priv->nvmeotcp->queue_ids, queue_id);
free_queue:
	kfree(queue);
out:
	stats->nvmeotcp_queue_init_fail++;
	return err;
}

static void
mlx5e_nvmeotcp_queue_teardown(struct net_device *netdev,
			      struct sock *sk)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_nvmeotcp_queue *queue;
	struct mlx5e_rq_stats *stats;

	queue = container_of(tcp_ddp_get_ctx(sk), struct mlx5e_nvmeotcp_queue, tcp_ddp_ctx);

	napi_synchronize(&priv->channels.c[queue->channel_ix]->napi);

	stats = &priv->channel_stats[queue->channel_ix].rq;
	stats->nvmeotcp_queue_teardown++;

	WARN_ON(refcount_read(&queue->ref_count) != 1);
	if (queue->zerocopy | queue->crc_rx)
		mlx5e_nvmeotcp_destroy_rx(queue, mdev, queue->zerocopy);

	rhashtable_remove_fast(&priv->nvmeotcp->queue_hash, &queue->hash,
			       rhash_queues);
	ida_simple_remove(&priv->nvmeotcp->queue_ids, queue->id);
	write_lock_bh(&sk->sk_callback_lock);
	tcp_ddp_set_ctx(sk, NULL);
	write_unlock_bh(&sk->sk_callback_lock);
	mlx5e_nvmeotcp_put_queue(queue);
}

static int
mlx5e_nvmeotcp_ddp_setup(struct net_device *netdev,
			 struct sock *sk,
			 struct tcp_ddp_io *ddp)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct scatterlist *sg = ddp->sg_table.sgl;
	struct mlx5e_nvmeotcp_queue *queue;
	struct mlx5e_rq_stats *stats;
	struct mlx5_core_dev *mdev;
	int i, size = 0, count = 0;

	queue = container_of(tcp_ddp_get_ctx(sk), struct mlx5e_nvmeotcp_queue, tcp_ddp_ctx);

	mdev = queue->priv->mdev;
	count = dma_map_sg(mdev->device, ddp->sg_table.sgl, ddp->nents,
			   DMA_FROM_DEVICE);

	if (WARN_ON(count > mlx5e_get_max_sgl(mdev)))
		return -ENOSPC;

	for (i = 0; i < count; i++)
		size += sg[i].length;

	queue->ccid_table[ddp->command_id].size = size;
	queue->ccid_table[ddp->command_id].ddp = ddp;
	queue->ccid_table[ddp->command_id].sgl = sg;
	queue->ccid_table[ddp->command_id].ccid_gen++;
	queue->ccid_table[ddp->command_id].sgl_length = count;

	stats = &priv->channel_stats[queue->channel_ix].rq;
	stats->nvmeotcp_ddp_setup++;
	if (unlikely(mlx5e_nvmeotcp_post_klm_wqe(queue, KLM_UMR, ddp->command_id, count)))
		stats->nvmeotcp_ddp_setup_fail++;

	return 0;
}

void mlx5e_nvmeotcp_ddp_inv_done(struct mlx5e_icosq_wqe_info *wi)
{
	struct nvmeotcp_queue_entry *q_entry = wi->nvmeotcp_qe.entry;
	struct mlx5e_nvmeotcp_queue *queue = q_entry->queue;
	struct mlx5_core_dev *mdev = queue->priv->mdev;
	struct tcp_ddp_io *ddp = q_entry->ddp;
	const struct tcp_ddp_ulp_ops *ulp_ops;

	dma_unmap_sg(mdev->device, ddp->sg_table.sgl,
		     q_entry->sgl_length, DMA_FROM_DEVICE);

	q_entry->sgl_length = 0;

	ulp_ops = inet_csk(queue->sk)->icsk_ulp_ddp_ops;
	if (ulp_ops && ulp_ops->ddp_teardown_done)
		ulp_ops->ddp_teardown_done(q_entry->ddp_ctx);
}

void mlx5e_nvmeotcp_ctx_comp(struct mlx5e_icosq_wqe_info *wi)
{
	struct mlx5e_nvmeotcp_queue *queue = wi->nvmeotcp_q.queue;

	if (unlikely(!queue))
		return;

	complete(&queue->done);
}

static int
mlx5e_nvmeotcp_ddp_teardown(struct net_device *netdev,
			    struct sock *sk,
			    struct tcp_ddp_io *ddp,
			    void *ddp_ctx)
{
	struct mlx5e_nvmeotcp_queue *queue;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct nvmeotcp_queue_entry *q_entry;
	struct mlx5e_rq_stats *stats;

	queue = container_of(tcp_ddp_get_ctx(sk), struct mlx5e_nvmeotcp_queue, tcp_ddp_ctx);
	q_entry  = &queue->ccid_table[ddp->command_id];
	WARN_ON(q_entry->sgl_length == 0);

	q_entry->ddp_ctx = ddp_ctx;
	q_entry->queue = queue;

	mlx5e_nvmeotcp_post_klm_wqe(queue, KLM_UMR, ddp->command_id, 0);
	stats = &priv->channel_stats[queue->channel_ix].rq;
	stats->nvmeotcp_ddp_teardown++;

	return 0;
}

static void
mlx5e_nvmeotcp_dev_resync(struct net_device *netdev,
			  struct sock *sk, u32 seq)
{
	struct mlx5e_nvmeotcp_queue *queue =
		container_of(tcp_ddp_get_ctx(sk), struct mlx5e_nvmeotcp_queue, tcp_ddp_ctx);

	queue->after_resync_cqe = 1;
	mlx5e_nvmeotcp_rx_post_static_params_wqe(queue, seq);
}

static const struct tcp_ddp_dev_ops mlx5e_nvmeotcp_ops = {
	.tcp_ddp_limits = mlx5e_nvmeotcp_offload_limits,
	.tcp_ddp_sk_add = mlx5e_nvmeotcp_queue_init,
	.tcp_ddp_sk_del = mlx5e_nvmeotcp_queue_teardown,
	.tcp_ddp_setup = mlx5e_nvmeotcp_ddp_setup,
	.tcp_ddp_teardown = mlx5e_nvmeotcp_ddp_teardown,
	.tcp_ddp_resync = mlx5e_nvmeotcp_dev_resync,
};

struct mlx5e_nvmeotcp_queue *
mlx5e_nvmeotcp_get_queue(struct mlx5e_nvmeotcp *nvmeotcp, int id)
{
	struct mlx5e_nvmeotcp_queue *queue;

	rcu_read_lock();
	queue = rhashtable_lookup_fast(&nvmeotcp->queue_hash,
				       &id, rhash_queues);
	if (queue && !IS_ERR(queue))
		if (!refcount_inc_not_zero(&queue->ref_count))
			queue = NULL;
	rcu_read_unlock();
	return queue;
}

void mlx5e_nvmeotcp_put_queue(struct mlx5e_nvmeotcp_queue *queue)
{
	if (refcount_dec_and_test(&queue->ref_count))
		kfree(queue);
}

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
