/*
 * drivers/net/ethernet/cumulus/vlan.c
 * Copyright (c) 2018 Cumulus Networks
 * Copyright (c) 2018 David Ahern <dsa@cumulusnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/bitmap.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/ip_fib.h>
#include <net/switchdev.h>
#include <linux/rtnetlink.h>

#include "clsw-private.h"
#include "router.h"
#include "vlan.h"
#include "sdhal_be.h"

// TO-DO: move these caches into some backend struct
// TO-DO: locking other than rtnl needed for these trees?
static struct rb_root vlan_cache = RB_ROOT;
DECLARE_BITMAP(vid_reserved, CLSW_VLAN_RESVD_SLOTS);

static u16 clsw_vlan_find_free_vid(void)
{
	int bit;

	bit = bitmap_find_free_region(vid_reserved, CLSW_VLAN_RESVD_SLOTS, 0);
	if (bit < 0)
		return 0;

	return CLSW_VLAN_RESVD_START + bit;
}

static void clsw_vlan_release_vid(u16 vid)
{
	if (vid >= CLSW_VLAN_RESVD_START && vid <= CLSW_VLAN_RESVD_END)
		bitmap_release_region(vid_reserved, vid, 0);
}

static struct clsw_vlan *clsw_vlan_find_by_vid(const struct rb_root *rb_root,
					       u16 vid)
{
	const struct rb_node *node = rb_root->rb_node;

	while (node) {
		struct clsw_vlan *vlan;

		vlan = rb_entry(node, struct clsw_vlan, rb_node);
		if (vid < vlan->vid)
			node = node->rb_left;
		else if (vid > vlan->vid)
			node = node->rb_right;
		else
			return vlan;
	}
	return NULL;
}

static void clsw_vlan_remove(struct clsw_vlan *vlan)
{
	clsw_vlan_release_vid(vlan->vid);
	rb_erase(&vlan->rb_node, &vlan_cache);
	sdhal_be_ops->vlan_delete(vlan);
	kfree(vlan);
}

static int clsw_vlan_insert(struct clsw_vlan *new_vlan, struct rb_root *root)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*node) {
		struct clsw_vlan *vlan;

		parent = *node;

		vlan = rb_entry(parent, struct clsw_vlan, rb_node);
		if (vlan->vid > new_vlan->vid)
			node = &(*node)->rb_left;
		else if (vlan->vid < new_vlan->vid)
			node = &(*node)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&new_vlan->rb_node, parent, node);
	rb_insert_color(&new_vlan->rb_node, root);

	return 0;
}

struct clsw_vlan *clsw_vlan_get_default(void)
{
	u16 vid = CLSW_PORT_VLAN;
	struct clsw_vlan *vlan;
	int err;

	vlan = clsw_vlan_find_by_vid(&vlan_cache, vid);
	if (vlan)
		goto out;

	vlan = kzalloc(sizeof(*vlan), GFP_KERNEL);
	if (!vlan)
		return NULL;

	vlan->vid = vid;
	vlan->untagged = true;

	/* EEXISTS is the only failure and we checked above */
	err = clsw_vlan_insert(vlan, &vlan_cache);
	if (err) {
		WARN_ON(1);
		goto out_delete;
	}

out:
	refcount_inc(&vlan->refcnt);
	return vlan;

out_delete:
	kfree(vlan);
	return ERR_PTR(err);
}

struct clsw_vlan *clsw_vlan_get(u16 vid, bool untagged)
{
	struct clsw_vlan *vlan;
	int err;

	vlan = clsw_vlan_find_by_vid(&vlan_cache, vid);
	if (vlan)
		goto out;

	vlan = kzalloc(sizeof(*vlan), GFP_KERNEL);
	if (!vlan)
		return ERR_PTR(-ENOMEM);

	vlan->vid = vid;
	vlan->untagged = untagged;
	err = sdhal_be_ops->vlan_create(vlan);
	if (err) {
		pr_warn("vlan_create failed: %d\n", err);
		goto out_err;
	}

	/* EEXISTS is the only failure and we checked above */
	err = clsw_vlan_insert(vlan, &vlan_cache);
	if (err) {
		WARN_ON(1);
		goto out_delete;
	}

out:
	refcount_inc(&vlan->refcnt);
	return vlan;

out_delete:
	sdhal_be_ops->vlan_delete(vlan);
out_err:
	kfree(vlan);
	return ERR_PTR(err);
}

struct clsw_vlan *clsw_vlan_get_unused(bool untagged)
{
	u16 vid = clsw_vlan_find_free_vid();
	struct clsw_vlan *vlan;

	if (!vid)
		return ERR_PTR(-EBUSY);

	vlan = clsw_vlan_get(vid, untagged);
	if (IS_ERR(vlan)) {
		int err = PTR_ERR(vlan);

		clsw_vlan_release_vid(vid);
		vlan = ERR_PTR(err);
	}

	return vlan;
}

void clsw_vlan_put(struct clsw_vlan *vlan)
{
	if (refcount_dec_and_test(&vlan->refcnt))
		clsw_vlan_remove(vlan);
}
