// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021 Mellanox Technologies. */

#include "en_accel/nvmeotcp_rxtx.h"
#include "en_accel/nvmeotcp.h"
#include <linux/mlx5/mlx5_ifc.h>

#define	MLX5E_TC_FLOW_ID_MASK  0x00ffffff
static void nvmeotcp_update_resync(struct mlx5e_nvmeotcp_queue *queue,
				   struct mlx5e_cqe128 *cqe128)
{
	const struct tcp_ddp_ulp_ops *ulp_ops;
	u32 seq;

	seq = be32_to_cpu(cqe128->resync_tcp_sn);
	ulp_ops = inet_csk(queue->sk)->icsk_ulp_ddp_ops;
	if (ulp_ops && ulp_ops->resync_request)
		ulp_ops->resync_request(queue->sk, seq, TCP_DDP_RESYNC_REQ);
}

static void mlx5e_nvmeotcp_advance_sgl_iter(struct mlx5e_nvmeotcp_queue *queue)
{
	struct nvmeotcp_queue_entry *nqe = &queue->ccid_table[queue->ccid];

	queue->ccoff += nqe->sgl[queue->ccsglidx].length;
	queue->ccoff_inner = 0;
	queue->ccsglidx++;
}

static inline void
mlx5e_nvmeotcp_add_skb_frag(struct net_device *netdev, struct sk_buff *skb,
			    struct mlx5e_nvmeotcp_queue *queue,
			    struct nvmeotcp_queue_entry *nqe, u32 fragsz)
{
	dma_sync_single_for_cpu(&netdev->dev,
				nqe->sgl[queue->ccsglidx].offset + queue->ccoff_inner,
				fragsz, DMA_FROM_DEVICE);
	page_ref_inc(compound_head(sg_page(&nqe->sgl[queue->ccsglidx])));
	// XXX: consider reducing the truesize, as no new memory is consumed
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
			sg_page(&nqe->sgl[queue->ccsglidx]),
			nqe->sgl[queue->ccsglidx].offset + queue->ccoff_inner,
			fragsz,
			fragsz);
}

static struct sk_buff*
mlx5_nvmeotcp_add_tail_nonlinear(struct mlx5e_nvmeotcp_queue *queue,
				 struct sk_buff *skb, skb_frag_t *org_frags,
				 int org_nr_frags, int frag_index)
{
	struct mlx5e_priv *priv = queue->priv;

	while (org_nr_frags != frag_index) {
		if (skb_shinfo(skb)->nr_frags >= MAX_SKB_FRAGS) {
			dev_kfree_skb_any(skb);
			return NULL;
		}
		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
				skb_frag_page(&org_frags[frag_index]),
				skb_frag_off(&org_frags[frag_index]),
				skb_frag_size(&org_frags[frag_index]),
				skb_frag_size(&org_frags[frag_index]));
		page_ref_inc(skb_frag_page(&org_frags[frag_index]));
		frag_index++;
	}
	return skb;
}

static struct sk_buff*
mlx5_nvmeotcp_add_tail(struct mlx5e_nvmeotcp_queue *queue, struct sk_buff *skb,
		       int offset, int len)
{
	struct mlx5e_priv *priv = queue->priv;

	if (skb_shinfo(skb)->nr_frags >= MAX_SKB_FRAGS) {
		dev_kfree_skb_any(skb);
		return NULL;
	}
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
			virt_to_page(skb->data),
			offset,
			len,
			len);
	page_ref_inc(virt_to_page(skb->data));
	return skb;
}

static void mlx5_nvmeotcp_trim_nonlinear(struct sk_buff *skb,
					 skb_frag_t *org_frags,
					 int *frag_index,
					 int remaining)
{
	unsigned int frag_size;
	int nr_frags;

	/* skip @remaining bytes in frags */
	*frag_index = 0;
	while (remaining) {
		frag_size = skb_frag_size(&skb_shinfo(skb)->frags[*frag_index]);
		if (frag_size > remaining) {
			skb_frag_off_add(&skb_shinfo(skb)->frags[*frag_index],
					 remaining);
			skb_frag_size_sub(&skb_shinfo(skb)->frags[*frag_index],
					  remaining);
			remaining = 0;
		} else {
			remaining -= frag_size;
			skb_frag_unref(skb, *frag_index);
			*frag_index += 1;
		}
	}

	/* save original frags for the tail and unref */
	nr_frags = skb_shinfo(skb)->nr_frags;
	memcpy(&org_frags[*frag_index], &skb_shinfo(skb)->frags[*frag_index],
	       (nr_frags - *frag_index) * sizeof(skb_frag_t));
	while (--nr_frags >= *frag_index)
		skb_frag_unref(skb, nr_frags);

	/* remove frags from skb */
	skb_shinfo(skb)->nr_frags = 0;
	skb->len -= skb->data_len;
	skb->truesize -= skb->data_len;
	skb->data_len = 0;
}

struct sk_buff*
mlx5e_nvmeotcp_handle_rx_skb(struct net_device *netdev, struct sk_buff *skb,
			     struct mlx5_cqe64 *cqe, u32 cqe_bcnt,
			     bool linear)
{
	int ccoff, cclen, hlen, ccid, remaining, fragsz, to_copy = 0;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	skb_frag_t org_frags[MAX_SKB_FRAGS];
	struct mlx5e_nvmeotcp_queue *queue;
	struct nvmeotcp_queue_entry *nqe;
	int org_nr_frags, frag_index;
	struct mlx5e_cqe128 *cqe128;
	u32 queue_id;

	queue_id = (be32_to_cpu(cqe->sop_drop_qpn) & MLX5E_TC_FLOW_ID_MASK);
	queue = mlx5e_nvmeotcp_get_queue(priv->nvmeotcp, queue_id);
	if (unlikely(!queue)) {
		dev_kfree_skb_any(skb);
		return NULL;
	}

	cqe128 = container_of(cqe, struct mlx5e_cqe128, cqe64);
	if (cqe_is_nvmeotcp_resync(cqe)) {
		nvmeotcp_update_resync(queue, cqe128);
		mlx5e_nvmeotcp_put_queue(queue);
		return skb;
	}

#ifdef CONFIG_TCP_DDP_CRC
	/* If a resync occurred in the previous cqe,
	 * the current cqe.crcvalid bit may not be valid,
	 * so we will treat it as 0
	 */
	skb->ddp_crc = queue->after_resync_cqe ? 0 :
		cqe_is_nvmeotcp_crcvalid(cqe);
	queue->after_resync_cqe = 0;
#endif
	if (!cqe_is_nvmeotcp_zc(cqe)) {
		mlx5e_nvmeotcp_put_queue(queue);
		return skb;
	}

	/* cc ddp from cqe */
	ccid = be16_to_cpu(cqe128->ccid);
	ccoff = be32_to_cpu(cqe128->ccoff);
	cclen = be16_to_cpu(cqe128->cclen);
	hlen  = be16_to_cpu(cqe128->hlen);

	/* carve a hole in the skb for DDP data */
	if (linear) {
		skb_trim(skb, hlen);
	} else {
		org_nr_frags = skb_shinfo(skb)->nr_frags;
		mlx5_nvmeotcp_trim_nonlinear(skb, org_frags, &frag_index,
					     cclen);
	}

	nqe = &queue->ccid_table[ccid];

	/* packet starts new ccid? */
	if (queue->ccid != ccid || queue->ccid_gen != nqe->ccid_gen) {
		queue->ccid = ccid;
		queue->ccoff = 0;
		queue->ccoff_inner = 0;
		queue->ccsglidx = 0;
		queue->ccid_gen = nqe->ccid_gen;
	}

	/* skip inside cc until the ccoff in the cqe */
	while (queue->ccoff + queue->ccoff_inner < ccoff) {
		remaining = nqe->sgl[queue->ccsglidx].length - queue->ccoff_inner;
		fragsz = min_t(off_t, remaining,
			       ccoff - (queue->ccoff + queue->ccoff_inner));

		if (fragsz == remaining)
			mlx5e_nvmeotcp_advance_sgl_iter(queue);
		else
			queue->ccoff_inner += fragsz;
	}

	/* adjust the skb according to the cqe cc */
	while (to_copy < cclen) {
		if (skb_shinfo(skb)->nr_frags >= MAX_SKB_FRAGS) {
			dev_kfree_skb_any(skb);
			mlx5e_nvmeotcp_put_queue(queue);
			return NULL;
		}

		remaining = nqe->sgl[queue->ccsglidx].length - queue->ccoff_inner;
		fragsz = min_t(int, remaining, cclen - to_copy);

		mlx5e_nvmeotcp_add_skb_frag(netdev, skb, queue, nqe, fragsz);
		to_copy += fragsz;
		if (fragsz == remaining)
			mlx5e_nvmeotcp_advance_sgl_iter(queue);
		else
			queue->ccoff_inner += fragsz;
	}

	if (cqe_bcnt > hlen + cclen) {
		remaining = cqe_bcnt - hlen - cclen;
		if (linear)
			skb = mlx5_nvmeotcp_add_tail(queue, skb,
						     offset_in_page(skb->data) +
								hlen + cclen,
						     remaining);
		else
			skb = mlx5_nvmeotcp_add_tail_nonlinear(queue, skb,
							       org_frags,
							       org_nr_frags,
							       frag_index);
	}

	mlx5e_nvmeotcp_put_queue(queue);
	return skb;
}
