/*
 * drivers/net/ethernet/cumulus/router.c - notifier handlers for routes
 * Copyright (c) 2017-18 Cumulus Networks
 * Copyright (c) 2017-18 David Ahern <dsa@cumulusnetworks.com>
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
 *
 * This code borrows heavily from
 * drivers/net/ethernet/mellanox/mlxsw/spectrum_router.c
 */

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/rhashtable.h>
#include <linux/route.h>
#include <linux/slab.h>
#include <net/addrconf.h>
#include <net/arp.h>
#include <net/ipv6.h>
#include <net/netevent.h>
#include <net/switchdev.h>

#include "clsw-private.h"
#include "router.h"
#include "vlan.h"
#include "sdhal_be.h"

#include "clsw_trace.h"

static struct clsw_vr *clsw_vr_get(struct clsw_router *router, u32 tb_id,
				   struct netlink_ext_ack *extack);
static void clsw_vr_put(struct clsw_router *router, struct clsw_vr *vr);
static struct clsw_rif *clsw_rif_find_by_dev(const struct clsw_router *router,
					     const struct net_device *dev);
static void clsw_fib_node_print(const struct clsw_fib_node *fib_node,
				const char *desc, int err);
static void clsw_fib_node_flush(struct clsw_router *router,
				struct clsw_fib_node *fn);
static void clsw_fib_entry_delete(struct clsw_router *router,
				  struct clsw_fib_entry *fe);
static void clsw_nh_put(struct clsw_router *router, struct clsw_nexthop *nh);

static struct kmem_cache *clsw_fe_cachep __read_mostly;
static struct kmem_cache *clsw_fn_cachep __read_mostly;
static struct kmem_cache *clsw_nh_cachep __read_mostly;

// TO-DO: prefix refcnt for multiple routes with same prefix/length

struct clsw_fib_event_work {
	struct work_struct work;
	struct clsw_router *router;
	unsigned long event;
	union {
		struct fib_entry_notifier_info fen_info;
		struct fib6_entry_notifier_info fen6_info;
	};
};

/*
 * FIB nodes
 */
static const struct rhashtable_params clsw_fib_ht_params = {
	.key_offset = offsetof(struct clsw_fib_node, key),
	.head_offset = offsetof(struct clsw_fib_node, ht_node),
	.key_len = sizeof(struct clsw_fib_key),
	.automatic_shrinking = true,
};

static struct clsw_fib *clsw_fib_create(struct clsw_vr *vr)
{
	struct clsw_fib *fib;
	int err;

	fib = kzalloc(sizeof(*fib), GFP_KERNEL);
	if (!fib)
		return ERR_PTR(-ENOMEM);

	err = rhashtable_init(&fib->ht, &clsw_fib_ht_params);
	if (err)
		goto err_rhashtable_init;

	INIT_LIST_HEAD(&fib->node_list);
	fib->vr = vr;

	return fib;

err_rhashtable_init:
	kfree(fib);
	return ERR_PTR(err);
}

static void clsw_fib_destroy(struct clsw_router *router, struct clsw_fib *fib)
{
	if (!list_empty(&fib->node_list)) {
		struct clsw_fib_node *fn, *tmp;

		list_for_each_entry_safe(fn, tmp, &fib->node_list, list)
			clsw_fib_node_flush(router, fn);

		if (!list_empty(&fib->node_list)) {
			pr_warn("NOT freeing FIB because of FIB entries\n");
			list_for_each_entry(fn, &fib->node_list, list)
				clsw_fib_node_print(fn, "clsw_fib_destroy", 0);
		}
	}

	rhashtable_destroy(&fib->ht);
	kfree(fib);
}

static int clsw_fib_node_insert(struct clsw_fib *fib,
				struct clsw_fib_node *fib_node)
{
	return rhashtable_insert_fast(&fib->ht, &fib_node->ht_node,
				      clsw_fib_ht_params);
}

static void clsw_fib_node_remove(struct clsw_fib *fib,
				 struct clsw_fib_node *fib_node)
{
	rhashtable_remove_fast(&fib->ht, &fib_node->ht_node,
			       clsw_fib_ht_params);
}

static struct clsw_fib_node *
clsw_fib_node_lookup(struct clsw_fib *fib, const void *addr,
		     size_t addr_len, unsigned char prefix_len)
{
	struct clsw_fib_key key = { .plen = prefix_len };

	memcpy(key.addr, addr, addr_len);

	return rhashtable_lookup_fast(&fib->ht, &key, clsw_fib_ht_params);
}

static void clsw_fib_node_print(const struct clsw_fib_node *fib_node,
				const char *desc, int err)
{
	const struct clsw_fib_key *key;
	struct clsw_vr *vr;
	u8 family;

	if (!fib_node)
		return;

	key = &fib_node->key;
	family = fib_node->fib->family;
	vr = fib_node->fib->vr;
	switch (family) {
	case AF_INET:
		pr_err("%s: IPv4 fib node: id %llu prefix %pI4/%d vr %hu table %u err %d\n",
		       desc, fib_node->id, &key->addr, key->plen,
		       vr ? vr->id : 0, vr ? vr->tb_id : 0, err);
		break;
	case AF_INET6:
		pr_err("%s: IPv6 fib node: id %llu prefix %pI6c/%d vr %hu table %u err %d\n",
		       desc, fib_node->id, &key->addr, key->plen,
		       vr ? vr->id : 0, vr ? vr->tb_id : 0, err);
		break;
	default:
		pr_warn("%s: UNKNOWN fib_node: %llu key 0x%02x%02x%02x%02x.../%d vr %hu table %u err %d\n",
			desc, fib_node->id,
			fib_node->key.addr[0], fib_node->key.addr[1],
			fib_node->key.addr[2], fib_node->key.addr[3],
			fib_node->key.plen,
			vr ? vr->id : 0, vr ? vr->tb_id : 0, err);
	}
}

static struct clsw_fib_node *
clsw_fib_node_create(struct clsw_fib *fib, const void *addr,
		     size_t addr_len, unsigned char prefix_len)
{
	struct clsw_fib_node *fib_node;
	static u64 fib_node_id;

	fib_node = kmem_cache_zalloc(clsw_fn_cachep, GFP_KERNEL);
	if (!fib_node)
		return NULL;

	INIT_LIST_HEAD(&fib_node->entry_list);
	list_add(&fib_node->list, &fib->node_list);
	fib_node->fib = fib;

	memcpy(fib_node->key.addr, addr, addr_len);
	fib_node->key.plen = prefix_len;
	fib_node->id = ++fib_node_id;

	trace_fib_node_create(fib_node);

	return fib_node;
}

static void clsw_fib_node_destroy(struct clsw_fib_node *fib_node)
{
	list_del(&fib_node->list);
	WARN_ON(!list_empty(&fib_node->entry_list));
	kmem_cache_free(clsw_fn_cachep, fib_node);
}

static int clsw_fib_node_init(struct clsw_router *router,
			      struct clsw_fib_node *fib_node,
			      struct clsw_fib *fib)
{
	int err;

	err = clsw_fib_node_insert(fib, fib_node);
	if (err)
		return err;

	// TO-DO: lpm tree linking

	//clsw_fib_node_prefix_inc(fib_node);

	return 0;
}

static void clsw_fib_node_fini(struct clsw_router *router,
			       struct clsw_fib_node *fib_node)
{
	struct clsw_fib *fib = fib_node->fib;

	//clsw_fib_node_prefix_dec(fib_node);

	// TO-DO: lpm tree unlinking

	fib_node->fib = NULL;
	clsw_fib_node_remove(fib, fib_node);
}

static struct clsw_fib *clsw_vr_fib(struct clsw_vr *vr, u8 family)
{
	switch(family) {
	case AF_INET:
		return vr->fib4;
	case AF_INET6:
		return vr->fib6;
	default:
		return NULL;
	}
}

static struct clsw_fib_node *
clsw_fib_node_get(struct clsw_router *router, struct clsw_vr *vr,
		  u8 family, const void *addr, size_t addr_len,
		  unsigned char prefix_len, bool create)
{
	struct clsw_fib_node *fib_node;
	struct clsw_fib *fib;
	int err;

	ASSERT_RTNL();

	err = -EINVAL;
	fib = clsw_vr_fib(vr, family);
	if (!fib)
		goto err_out;

	fib_node = clsw_fib_node_lookup(fib, addr, addr_len, prefix_len);
	if (fib_node)
		return fib_node;

	if (!create)
		return ERR_PTR(-ENOENT);

	err = -ENOMEM;
	fib_node = clsw_fib_node_create(fib, addr, addr_len, prefix_len);
	if (!fib_node)
		goto err_out;

	err = clsw_fib_node_init(router, fib_node, fib);
	if (err)
		goto err_fib_node_init;

	return fib_node;

err_fib_node_init:
	clsw_fib_node_destroy(fib_node);
err_out:
	return ERR_PTR(err);
}

static void clsw_fib_node_put(struct clsw_router *router,
			      struct clsw_fib_node *fib_node)
{
	ASSERT_RTNL();

	if (!list_empty(&fib_node->entry_list))
		return;

	trace_fib_node_delete(fib_node);

	clsw_fib_node_fini(router, fib_node);
	clsw_fib_node_destroy(fib_node);
}

static void clsw_fib_node_flush(struct clsw_router *router,
				struct clsw_fib_node *fn)
{
	struct clsw_fib_entry *fe, *tmp;

	clsw_fib_node_print(fn, "clsw_fib_node_flush", 0);

	list_for_each_entry_safe(fe, tmp, &fn->entry_list, node_list) {
		/* expecting any route entries tied to a device to be
		 * flushed based on action of the device
		 */
		if (fe->nh)
			continue;

		clsw_fib_entry_delete(router, fe);
	}
}

/*
 * Virtual routers
 */

static void clsw_vr_fib_flush(struct clsw_router *router, struct clsw_vr *vr)
{
	clsw_fib_destroy(router, vr->fib4);
	clsw_fib_destroy(router, vr->fib6);
}

static void clsw_router_vr_flush(struct clsw_router *router)
{
	u16 i;

	for (i = 0; i < router->max_vrs; i++) {
		struct clsw_vr *vr = &router->vrs[i];

		if (!vr->tb_id)
			continue;

		clsw_vr_fib_flush(router, vr);
		vr->tb_id = 0;
	}
}

static struct clsw_vr *clsw_vr_find_unused(struct clsw_router *router,
					   struct netlink_ext_ack *extack)
{
	u16 i;

	for (i = 0; i < router->max_vrs; i++) {
		struct clsw_vr *vr;

		vr = &router->vrs[i];
		if (!vr->tb_id)
			return vr;
	}

	clsw_set_extack(extack, "Exceeded number of supported virtual routers");

	return NULL;
}

static u32 clsw_fib_tbid_normalize(u32 tb_id)
{
	if (!tb_id || tb_id == RT_TABLE_LOCAL || tb_id == RT_TABLE_DEFAULT)
		tb_id = RT_TABLE_MAIN;

	return tb_id;
}

static struct clsw_vr *clsw_vr_find(struct clsw_router *router, u32 tb_id)
{
	u16 i;

	for (i = 0; i < router->max_vrs; i++) {
		struct clsw_vr *vr;

		vr = &router->vrs[i];
		if (vr->tb_id == tb_id)
			return vr;
	}
	return NULL;
}

static struct clsw_vr *clsw_vr_create(struct clsw_router *router,
				      u32 tb_id,
				      struct netlink_ext_ack *extack)
{
	struct clsw_vr *vr;
	int err;

	vr = clsw_vr_find_unused(router, extack);
	if (!vr)
		return ERR_PTR(-EBUSY);

	vr->fib4 = clsw_fib_create(vr);
	if (IS_ERR(vr->fib4))
		return ERR_CAST(vr->fib4);
	vr->fib4->family = AF_INET;

	vr->fib6 = clsw_fib_create(vr);
	if (IS_ERR(vr->fib6)) {
		err = PTR_ERR(vr->fib6);
		goto err_fib6_create;
	}
	vr->fib6->family = AF_INET6;

	vr->tb_id = tb_id;

	err = sdhal_be_ops->vr_update(vr, true);
	if (err) {
		clsw_set_extack(extack,
				"Backend failed to create virtual router.");
		vr->tb_id = 0;
		goto err_vr_create;
	}

	trace_vr_create(vr);

	return vr;

err_vr_create:
	clsw_fib_destroy(router, vr->fib6);
	vr->fib6 = NULL;
err_fib6_create:
	clsw_fib_destroy(router, vr->fib4);
	vr->fib4 = NULL;
	return ERR_PTR(err);
}

static void clsw_vr_remove(struct clsw_router *router, struct clsw_vr *vr)
{
	trace_vr_delete(vr);

	sdhal_be_ops->vr_update(vr, false);

	clsw_fib_destroy(router, vr->fib4);
	vr->fib4 = NULL;
	clsw_fib_destroy(router, vr->fib6);
	vr->fib6 = NULL;

	vr->tb_id = 0;
}

static struct clsw_vr *clsw_vr_get(struct clsw_router *router, u32 tb_id,
				   struct netlink_ext_ack *extack)
{
	struct clsw_vr *vr;

	vr = clsw_vr_find(router, tb_id);
	if (!vr) {
		vr = clsw_vr_create(router, tb_id, extack);
		if (IS_ERR(vr)) {
			pr_err("Failed to create vr for table %u\n",
			       tb_id);
			return vr;
		}
	}

	refcount_inc(&vr->refcnt);

	return vr;
}

static void clsw_vr_put(struct clsw_router *router, struct clsw_vr *vr)
{
	if (vr && refcount_dec_and_test(&vr->refcnt))
		clsw_vr_remove(router, vr);
}

static int clsw_vrs_init(struct clsw_router *router)
{
	struct clsw_vr *vr;
	u16 i;

	/* should be at least 1 -- default VRF */
	if (router->max_vrs == 0) {
		pr_warn("max vrs is 0\n");
		return -EINVAL;
	}

	router->vrs = kzalloc(router->max_vrs * sizeof(struct clsw_vr),
			      GFP_KERNEL);
	if (!router->vrs)
		return -ENOMEM;

	for (i = 0; i < router->max_vrs; i++)
		router->vrs[i].id = i + 1;

	/* create router for main table */
	vr = clsw_vr_get(router, RT_TABLE_MAIN, NULL);
	if (IS_ERR(vr))
		return PTR_ERR(vr);

	return 0;
}

static void clsw_vrs_fini(struct clsw_router *router)
{
	clsw_flush_owq();
	clsw_router_vr_flush(router);
	kfree(router->vrs);
	router->vrs = NULL;
}

/*
 * neighbor entries
 */
static const struct rhashtable_params clsw_neigh_ht_params = {
	.key_offset = offsetof(struct clsw_neigh_entry, key),
	.head_offset = offsetof(struct clsw_neigh_entry, ht_node),
	.key_len = sizeof(struct clsw_neigh_key),
};

static int clsw_neigh_entry_insert(struct clsw_router *router,
				   struct clsw_neigh_entry *ne)
{
	return rhashtable_insert_fast(&router->neigh_ht,
				      &ne->ht_node,
				      clsw_neigh_ht_params);
}

static void clsw_neigh_entry_remove(struct clsw_router *router,
				    struct clsw_neigh_entry *ne)
{
	rhashtable_remove_fast(&router->neigh_ht, &ne->ht_node,
			       clsw_neigh_ht_params);
}

static struct clsw_neigh_entry *
clsw_neigh_entry_lookup(struct clsw_router *router, struct neighbour *n)
{
	struct clsw_neigh_key key;

	key.n = n;
	return rhashtable_lookup_fast(&router->neigh_ht,
				      &key, clsw_neigh_ht_params);
}

static struct clsw_neigh_entry *clsw_neigh_entry_alloc(struct neighbour *n,
						       struct clsw_rif *rif)
{
	struct clsw_neigh_entry *ne;

	ne = kzalloc(sizeof(*ne), GFP_KERNEL);
	if (!ne)
		return NULL;

	ne->key.n = n;
	neigh_clone(n);
	ne->rif = rif;
	INIT_LIST_HEAD(&ne->nh_list);

	return ne;
}

static void clsw_neigh_entry_free(struct clsw_neigh_entry *ne)
{
	kfree(ne);
}

static void clsw_neigh_entry_print(const struct clsw_neigh_entry *ne,
				   const char *desc, int err)
{
	struct neighbour *n = ne->key.n;

	if (n->tbl->family == AF_INET)
		pr_err("%s neigh_entry %llu: neigh %s %pI4: err %d\n",
		       desc, ne->id, n->dev->name, &n->primary_key, err);
	else if (n->tbl->family == AF_INET6)
		pr_err("%s neigh_entry %llu: neigh %s %pI6c: %d\n",
		       desc, ne->id, n->dev->name, &n->primary_key, err);

}

static struct clsw_neigh_entry *
clsw_neigh_entry_create(struct clsw_router *router, struct neighbour *n)
{
	static u64 neigh_entry_id;
	struct clsw_neigh_entry *ne;
	struct clsw_rif *rif;
	int err;

	rif = clsw_rif_find_by_dev(router, n->dev);
	if (!rif) {
		pr_err("Can not create neigh_entry; no rif for dev %s\n",
		       n->dev->name);
		return ERR_PTR(-EINVAL);
	}

	ne = clsw_neigh_entry_alloc(n, rif);
	if (!ne)
		return ERR_PTR(-ENOMEM);
	ne->id = ++neigh_entry_id;

	err = clsw_neigh_entry_insert(router, ne);
	if (err) {
		pr_err("Failed to insert neigh_entry for dev %s\n",
		       n->dev->name);
		goto err_neigh_entry_insert;
	}

	list_add_tail(&ne->nh_neigh_list_node, &router->nh_neigh_list);

	trace_neigh_create(ne);

	return ne;

err_neigh_entry_insert:
	clsw_neigh_entry_free(ne);
	return ERR_PTR(err);
}

static void clsw_neigh_entry_destroy(struct clsw_router *router,
				     struct clsw_neigh_entry *ne)
{
	trace_neigh_delete(ne);

	/* remove from router list */
	list_del(&ne->nh_neigh_list_node);

	clsw_neigh_entry_remove(router, ne);
	clsw_neigh_entry_free(ne);
}

static int clsw_neigh_entry_update_be(struct clsw_neigh_entry *ne, bool adding)
{
	int err;

	if ((adding && ne->connected) || (!adding && !ne->connected))
		return 0;

	err = sdhal_be_ops->neigh_update(ne, adding);
	if (err) {
		clsw_neigh_entry_print(ne,
				       adding ? "Failed to add to backend" :
				       "Failed to remove from backend", err);
	}
	if (!err || !adding)
		ne->connected = adding;

	trace_neigh_update(ne);

	return err;
}

static int clsw_nh_neigh_entry_init(struct clsw_router *router,
				    struct clsw_nh_info *nh,
				    struct neighbour *n)
{
	struct clsw_neigh_entry *ne;
	u8 nud_state, dead;
	int err;

	ne = clsw_neigh_entry_lookup(router, n);
	if (!ne) {
		ne = clsw_neigh_entry_create(router, n);
		if (IS_ERR(ne))
			return PTR_ERR(ne);
	}
	nh->neigh_entry = ne;

	/* add nexthop to neigh entry's nh list */
	list_add_tail(&nh->neigh_list_node, &ne->nh_list);

	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	dead = n->dead;
	read_unlock_bh(&n->lock);

	err = clsw_neigh_entry_update_be(ne, (nud_state & NUD_VALID) && !dead);
	if (!err && ne->connected)
		nh->has_valid_neigh = 1;

	return err;
}

static void clsw_nh_neigh_entry_fini(struct clsw_router *router,
				     struct clsw_nexthop *nh)
{
	struct clsw_neigh_entry *ne;

	ne = nh->nh_info.neigh_entry;
	if (!ne)
		return;
	nh->nh_info.neigh_entry = NULL;

	/* remove nexthop from neigh entry's nh list */
	list_del(&nh->nh_info.neigh_list_node);

	/* if the neigh entry has no more associated nexthops
	 * then we are done with it
	 */
	if (list_empty(&ne->nh_list)) {
		struct neighbour *n = ne->key.n;
		int err;

		nh->nh_info.has_valid_neigh = 0;

		err = clsw_neigh_entry_update_be(ne, false);
		if (err)
			pr_err("Failed to remove neigh entry %s %pI4 from backend: %d\n",
			       n->dev->name, &n->primary_key, err);
		neigh_release(n);
		clsw_neigh_entry_destroy(router, ne);
	}
}

/* If a neighbor entry has nexthops, make the kernel think it
 * is active regardless of the traffic.
 */
static void clsw_neigh_update_nh(struct clsw_router *router)
{
	struct clsw_neigh_entry *ne;

	/* Take RTNL mutex here to prevent lists from changes */
	rtnl_lock();
// TO-DO: struct router spinlock rather than rtnl?

	list_for_each_entry(ne, &router->nh_neigh_list, nh_neigh_list_node)
		neigh_event_send(ne->key.n, NULL);

	rtnl_unlock();
}

static void clsw_neigh_update_work_schedule(struct clsw_router *router)
{
	unsigned long interval = router->neigh_update.interval;

	clsw_schedule_dw(&router->neigh_update.dw, msecs_to_jiffies(interval));
}

static void clsw_neigh_update_work(struct work_struct *work)
{
	struct clsw_router *router;

	router = container_of(work, struct clsw_router, neigh_update.dw.work);
	clsw_neigh_update_nh(router);
	clsw_neigh_update_work_schedule(router);
}

static void clsw_probe_unresolved_nexthops(struct work_struct *work)
{
	struct clsw_neigh_entry *ne;
	struct clsw_router *router;

	router = container_of(work, struct clsw_router, nh_probe_dw.work);

	/* Iterate over nexthop neighbours, find those who are unresolved and
	 * send arp on them. This solves the chicken-egg problem when
	 * the nexthop wouldn't get offloaded until the neighbor is resolved
	 * but it wouldn't get resolved ever in case traffic is flowing in HW
	 * using different nexthop.
	 *
	 * Take RTNL mutex here to prevent lists from changes.
	 */
	rtnl_lock();
// TO-DO: struct router spinlock rather than rtnl?

	list_for_each_entry(ne, &router->nh_neigh_list, nh_neigh_list_node) {
		if (!ne->connected)
			neigh_event_send(ne->key.n, NULL);
	}

	rtnl_unlock();

	clsw_schedule_dw(&router->nh_probe_dw,
			 CLSW_UNRESOLVED_NH_PROBE_INTERVAL);
}

static void clsw_neigh_update_interval_init(struct clsw_router *router)
{
	unsigned long interval;

#if IS_ENABLED(CONFIG_IPV6)
	interval = min_t(unsigned long,
			 NEIGH_VAR(&arp_tbl.parms, DELAY_PROBE_TIME),
			 NEIGH_VAR(&nd_tbl.parms, DELAY_PROBE_TIME));
#else
	interval = NEIGH_VAR(&arp_tbl.parms, DELAY_PROBE_TIME);
#endif
	router->neigh_update.interval = jiffies_to_msecs(interval);
}

static int clsw_neigh_init(struct clsw_router *router)
{
	int err;

	err = rhashtable_init(&router->neigh_ht, &clsw_neigh_ht_params);
	if (err)
		return err;

	/* Initialize the polling interval according to the default
	 * table.
	 */
	clsw_neigh_update_interval_init(router);

	/* Create the delayed works for the activity_update */
	INIT_DELAYED_WORK(&router->neigh_update.dw,
			  clsw_neigh_update_work);
	INIT_DELAYED_WORK(&router->nh_probe_dw,
			  clsw_probe_unresolved_nexthops);
	clsw_schedule_dw(&router->neigh_update.dw, 0);
	clsw_schedule_dw(&router->nh_probe_dw, 0);

	return 0;
}

static void clsw_neigh_fini(struct clsw_router *router)
{
	cancel_delayed_work_sync(&router->neigh_update.dw);
	cancel_delayed_work_sync(&router->nh_probe_dw);
	rhashtable_destroy(&router->neigh_ht);
}

/*
 *  Nexthops
 */
static void clsw_rt_entry_update_offload(struct clsw_nh_route_entry *rt_entry,
					 bool offload)
{
	unsigned int *flags;

	switch (rt_entry->family) {
	case AF_INET:
		flags = &rt_entry->fib_nh->nh_flags;
		break;
	case AF_INET6:
		flags = &rt_entry->fib6_nh->nh_flags;
		break;
	default:
		return;
	}
	if (offload)
		*flags = *flags | RTNH_F_OFFLOAD;
	else
		*flags = *flags & ~RTNH_F_OFFLOAD;

	trace_rt_entry_update(rt_entry);
}

static void __clsw_nh_update_offload(struct clsw_nexthop *nh, bool offload)
{
	struct clsw_nh_route_entry *rt_entry;

	list_for_each_entry(rt_entry, &nh->nh_info.fnh_list, list)
		clsw_rt_entry_update_offload(rt_entry, offload);
}

static void clsw_nh_update_offload(struct clsw_nexthop *nh, bool offload)
{
	u8 i;

	/* e.g., unreachable default route does not have a nexthop */
	if (!nh)
		return;

	if (!clsw_nh_is_group(nh)) {
		__clsw_nh_update_offload(nh, offload);
		return;
	}

	for (i = 0; i < nh->nh_grp.num_nh; ++i) {
		struct clsw_nh_grp_entry *nh_ge;

		nh_ge = &nh->nh_grp.nh_list[i];
		if (nh_ge->nh)
			__clsw_nh_update_offload(nh_ge->nh, offload);
	}
}

static u32 clsw_nexthop_hash_index(struct clsw_nexthop *nh)
{
	u32 ifindex;

	if (clsw_nh_is_group(nh))
		ifindex = NEXTHOP_GROUP_INDEX;
	else if (nh->nh_info.nh_dev)
		ifindex = (u32) nh->nh_info.nh_dev->ifindex;
	else
		ifindex = 0;

	return ifindex;
}

static void clsw_nexthop_print(const struct clsw_nexthop *nh,
			       const char *desc, int err)
{
	if (!nh) {
		pr_err("%s nexthop: null\n", desc);
	} else if (clsw_nh_is_group(nh)) {
		pr_err("%s nexthop %llu: group\n", desc, nh->id);
	} else if (nh->nh_info.has_gw) {
		if (nh->nh_info.family == AF_INET)
			pr_err("%s nexthop %llu: dev %s gw %pI4 refcnt %d: err %d\n",
			       desc, nh->id, nh->nh_info.nh_dev->name,
			       &nh->nh_info.gw.ipv4,
			       refcount_read(&nh->refcnt), err);

		else if (nh->nh_info.family == AF_INET6)
			pr_err("%s nexthop %llu: dev %s gw %pI6c refcnt %d: %d\n",
			       desc, nh->id, nh->nh_info.nh_dev->name,
			       &nh->nh_info.gw.ipv6,
			       refcount_read(&nh->refcnt), err);
	} else {
		pr_err("%s nexthop %llu: dev %s refcnt %d: %d\n",
		       desc, nh->id, nh->nh_info.nh_dev->name,
			refcount_read(&nh->refcnt), err);
	}
}

static u64 clsw_nh_get_id(void)
{
	static u64 clw_nh_id;

	return ++clw_nh_id;
}

static struct clsw_nexthop *clsw_nh_grp_alloc(struct clsw_router *router,
					      u8 num_nh)
{
	struct clsw_nexthop *nh;

	/* nexthop for group has variable size and can not
	 * use the kmem_cache
	 */
	nh = kzalloc(sizeof(*nh) + sizeof(struct clsw_nh_grp_entry) * num_nh,
		     GFP_KERNEL);
	if (!nh)
		return ERR_PTR(-ENOMEM);

	nh->id = clsw_nh_get_id();
	nh->group = 1;
	INIT_LIST_HEAD(&nh->fe_list);
	nh->nh_grp.num_nh = num_nh;

	return nh;
}

static void clsw_nh_grp_destroy(struct clsw_router *router,
				struct clsw_nexthop *nh)
{
	u8 i;

	for (i = 0; i < nh->nh_grp.num_nh; ++i) {
		struct clsw_nh_grp_entry *nh_ge;

		nh_ge = &nh->nh_grp.nh_list[i];
		if (nh_ge->nh)
			clsw_nh_put(router, nh_ge->nh);
	}

	kfree(nh);
}

static struct clsw_nexthop *clsw_nexthop_alloc(struct clsw_router *router,
					       struct net_device *dev)
{
	struct clsw_nexthop *nh;

	nh = kmem_cache_zalloc(clsw_nh_cachep, GFP_KERNEL);
	if (!nh)
		return ERR_PTR(-ENOMEM);

	nh->id = clsw_nh_get_id();
	INIT_LIST_HEAD(&nh->nh_info.fnh_list);
	INIT_LIST_HEAD(&nh->fe_list);
	nh->nh_info.nh_dev = dev;
	if (!(dev->flags & IFF_UP))
		nh->dead = 1;

	nh->nh_info.rif = clsw_rif_find_by_dev(router, dev);

	return nh;
}

static void clsw_nexthop_destroy(struct clsw_router *router,
				 struct clsw_nexthop *nh)
{
	struct clsw_nh_route_entry *rt_entry, *n;
	struct clsw_nh_info *info;

	/* remove any linked routes */
	if (clsw_nh_is_group(nh)) {
		clsw_nh_grp_destroy(router, nh);
		return;
	}

	info = &nh->nh_info;

	list_for_each_entry_safe(rt_entry, n, &info->fnh_list, list) {
		list_del(&rt_entry->list);
		// TO-DO: reset offload flag here?
		kfree(rt_entry);
	}

	clsw_nh_neigh_entry_fini(router, nh);

	kmem_cache_free(clsw_nh_cachep, nh);
}

static int clsw_nexthop_add_be(struct clsw_nexthop *nh)
{
	int err;

	if (nh->offloaded)
		return 0;

	err = sdhal_be_ops->nh_update(nh, true);
	if (err < 0) {
		clsw_nexthop_print(nh, "Failed to add to backend", err);
		return err;
	}

	/* for a group only mark offloaded if one or more members
	 * is offloaded. nh_update returns > 0 for that case.
	 */
	if (clsw_nh_is_group(nh)) {
		if (err > 0)
			nh->offloaded = 1;
	} else {
		nh->offloaded = 1;
	}

	trace_nh_update(nh);

	return 0;
}

static void clsw_nexthop_remove_be(struct clsw_nexthop *nh)
{
	int err;

	if (!nh->offloaded)
		return;

	err = sdhal_be_ops->nh_update(nh, false);
	if (err)
		clsw_nexthop_print(nh, "Failed to delete in backend", err);

	nh->offloaded = 0;

	trace_nh_update(nh);
}

static int clsw_nexthop_offload(struct clsw_nexthop *nh)
{
	if (nh->ignore || nh->offloaded)
		return 0;

	if (!clsw_nh_is_group(nh)) {
		/* no gateway, no nexthop to create in backend
		 * e.g., connected routes. Mark it offloaded so
		 * fib_entry offload will proceed
		 */
		if (!nh->nh_info.has_gw) {
			nh->offloaded = 1;
			return 0;
		}

		/* gw needs a valid neigh entry */
		if (nh->nh_info.has_gw && !nh->nh_info.has_valid_neigh)
			return 0;
	}

	return clsw_nexthop_add_be(nh);
}

static void clsw_nh_remove_offload(struct clsw_nexthop *nh)
{
	if (nh->ignore || !nh->offloaded)
		return;

	if (!clsw_nh_is_group(nh) && !nh->nh_info.has_gw) {
		nh->offloaded = 0;
		return;
	}

	// walk group_list and remove from group first

	clsw_nexthop_remove_be(nh);
}

static void clsw_nexthop_remove(struct clsw_router *router,
				struct clsw_nexthop *nh)
{
	trace_nh_delete(nh);

	WARN_ON(!list_empty(&nh->fe_list));

	/* drop from the nexthop hash list */
	if (!hlist_unhashed(&nh->hlist))
		hlist_del(&nh->hlist);

	/* remove from backend */
	clsw_nh_remove_offload(nh);

	clsw_nexthop_destroy(router, nh);
}

static void clsw_nh_put(struct clsw_router *router, struct clsw_nexthop *nh)
{
	if (nh && refcount_dec_and_test(&nh->refcnt))
		clsw_nexthop_remove(router, nh);
}

static bool clsw_ignore_dev(struct net_device *dev)
{
	// TO-DO: this needs to be better than check for "eth"
	if (!strncmp(dev->name, "eth", 3))
		return true;

	/* for now only deal with bridges and netdev's baced on
	 * a front panel port (e.g., vlans)
	 */
	if (!clsw_get_port_dev(dev) && !netif_is_bridge_master(dev))
		return true;

	return false;
}

static bool clsw_nh_check_ignore(struct clsw_nexthop *nh)
{
	bool rc;

	if (clsw_nh_is_group(nh)) {
		// TO-DO: for each nh in group call
		// __clsw_nh_check_ignore(nh). if any nh in group has
		// ignore flag set need to FAIL fib insert
		return true;
	}

	if (!nh->nh_info.nh_dev)
		return false;

	rc = clsw_ignore_dev(nh->nh_info.nh_dev);
	if (rc)
		nh->ignore = 1;

	return rc;
}

static int clsw_nexthop_insert(struct clsw_router *router,
			       struct clsw_nexthop *nh)
{
	struct hlist_head *head;
	u32 ifindex;
	int err;

// TO-DO: check if nh has a rif; if not allocate one
	err = clsw_nexthop_offload(nh);
	if (err)
		return err;

	ifindex = clsw_nexthop_hash_index(nh);
	head = &router->nexthop_head[ifindex & (NEXTHOP_HASHENTRIES - 1)];
	hlist_add_head(&nh->hlist, head);

	return 0;
}

static struct clsw_nexthop *
clsw_nexthop_lookup_dev(struct clsw_router *router, struct net_device *dev)
{
	u32 ifindex = dev->ifindex;
	struct hlist_head *head;
	struct clsw_nexthop *nh;

	head = &router->nexthop_head[ifindex & (NEXTHOP_HASHENTRIES - 1)];
	hlist_for_each_entry(nh, head, hlist) {
		if (clsw_nh_is_group(nh))
			continue;
		if (nh->nh_info.nh_dev == dev && !nh->nh_info.has_gw)
			return nh;
	}
	return NULL;
}

static int clsw_nh_neighbor_init(struct clsw_router *router,
				 struct clsw_nh_info *nh_info,
				 void *gw, struct neigh_table *tbl)
{
	struct net_device *dev;
	struct neighbour *n;
	int err;

	if (!nh_info->rif) {
		pr_err("No rif for device as nexthop with gateway\n");
		return -EINVAL;
	}

	dev = nh_info->rif->dev;

	n = neigh_lookup(tbl, gw, dev);
	if (!n) {
		n = neigh_create(tbl, gw, dev);
		if (IS_ERR(n))
			return PTR_ERR(n);
		neigh_event_send(n, NULL);
	}

	err = clsw_nh_neigh_entry_init(router, nh_info, n);
	if (err)
		neigh_release(n);

	return err;
}

static void clsw_nh_unlink_fib6_nh(struct clsw_nexthop *nh,
				   struct fib6_nh *fib6_nh)
{
	struct clsw_nh_info *info = &nh->nh_info;
	struct clsw_nh_route_entry *rt_entry;

	list_for_each_entry(rt_entry, &info->fnh_list, list) {
		if (rt_entry->fib6_nh == fib6_nh) {
			trace_rt_entry_unlink(rt_entry);
			if (refcount_dec_and_test(&rt_entry->refcnt)) {
				struct fib6_info *f6i;

				f6i = container_of(fib6_nh, struct fib6_info,
						   fib6_nh);
				fib6_info_release(f6i);
				list_del(&rt_entry->list);
				kfree(rt_entry);
			}
			return;
		}
	}
}

/* correlate nexthop to fib entries */
static int clsw_nh_link_fib6_nh(struct clsw_nexthop *nh,
				struct fib6_nh *fib6_nh)
{
	struct clsw_nh_info *info = &nh->nh_info;
	struct clsw_nh_route_entry *rt_entry;
	struct fib6_info *f6i;

	list_for_each_entry(rt_entry, &info->fnh_list, list) {
		if (rt_entry->fib6_nh == fib6_nh) {
			refcount_inc(&rt_entry->refcnt);
			trace_rt_entry_update(rt_entry);
			return 0;
		}
	}

	rt_entry = kzalloc(sizeof(*rt_entry), GFP_KERNEL);
	if (!rt_entry)
		return -ENOMEM;

	rt_entry->family = AF_INET6;
	refcount_inc(&rt_entry->refcnt);
	rt_entry->fib6_nh = fib6_nh;

	f6i = container_of(fib6_nh, struct fib6_info, fib6_nh);
	fib6_info_hold(f6i);

	list_add_tail(&rt_entry->list, &nh->nh_info.fnh_list);

	trace_rt_entry_link(rt_entry);

	return 0;
}

static int clsw_nh_ipv6(struct clsw_router *router, struct clsw_nexthop *nh,
			struct in6_addr *gw)
{
	struct clsw_nh_info *nh_info = &nh->nh_info;
	bool skip_create;

	if (gw) {
		nh_info->family = AF_INET6;
		nh_info->gw.ipv6 = *gw;
		nh_info->has_gw = 1;
	}

	skip_create = clsw_nh_check_ignore(nh);
	if (skip_create || !gw)
		return 0;

	return clsw_nh_neighbor_init(router, nh_info, gw, &nd_tbl);
}

static struct clsw_nexthop *clsw_nh_find_v6(struct clsw_router *router,
					    struct net_device *dev,
					    struct in6_addr *gw)
{
	u32 ifindex = dev->ifindex;
	struct hlist_head *head;
	struct clsw_nexthop *nh;

	head = &router->nexthop_head[ifindex & (NEXTHOP_HASHENTRIES - 1)];
	hlist_for_each_entry(nh, head, hlist) {
		if (clsw_nh_is_group(nh))
			continue;
		if (nh->nh_info.nh_dev == dev && nh->nh_info.has_gw &&
		    nh->nh_info.family == AF_INET6 &&
		    ipv6_addr_equal(&nh->nh_info.gw.ipv6, gw))
			return nh;
	}

	return NULL;
}

/* not expecting a lot of unique nexthops via the same dev */
static struct clsw_nexthop *
clsw_nh_get_from_fib6_nh(struct clsw_router *router, struct fib6_nh *fib6_nh,
			 u32 flags, bool noref)
{
	struct net_device *dev = fib6_nh->nh_dev;
	struct clsw_nexthop *nh;
	struct in6_addr *gw;
	int err;

	if (!dev)
		return NULL;

	/* addrconf_dst_alloc sets the gateway for host routes */
	gw = &fib6_nh->nh_gw;
	if ((flags & RTF_NONEXTHOP) || ipv6_addr_any(gw))
		gw = NULL;

	if (gw)
		nh = clsw_nh_find_v6(router, dev, gw);
	else
		nh = clsw_nexthop_lookup_dev(router, dev);

	if (nh)
		goto out;

	if (noref)
		return NULL;

	nh = clsw_nexthop_alloc(router, dev);
	if (IS_ERR(nh))
		return nh;

	err = clsw_nh_ipv6(router, nh, gw);
	if (err)
		goto err_out;

	err = clsw_nexthop_insert(router, nh);
	if (err)
		goto err_out;

	trace_nh_create(nh);
out:
	if (!noref) {
		refcount_inc(&nh->refcnt);
		clsw_nh_link_fib6_nh(nh, fib6_nh);
	}
	return nh;
err_out:
	clsw_nexthop_destroy(router, nh);
	return ERR_PTR(err);
}

/* not expecting a lot of unique nexthops via the same dev */
static int clsw_nh_ipv4(struct clsw_router *router, struct clsw_nexthop *nh,
			__be32 gw)
{
	struct clsw_nh_info *nh_info = &nh->nh_info;
	bool skip_create;

	if (gw) {
		nh_info->family = AF_INET;
		nh_info->gw.ipv4 = gw;
		nh_info->has_gw = 1;
	}

	skip_create = clsw_nh_check_ignore(nh);
	if (skip_create || !gw)
		return 0;

	return clsw_nh_neighbor_init(router, nh_info, &gw, &arp_tbl);
}

static void clsw_nh_unlink_fib_nh(struct clsw_nexthop *nh,
				  struct fib_nh *fib_nh)
{
	struct clsw_nh_info *info = &nh->nh_info;
	struct clsw_nh_route_entry *rt_entry;

	list_for_each_entry(rt_entry, &info->fnh_list, list) {
		if (rt_entry->fib_nh == fib_nh) {
			if (refcount_dec_and_test(&rt_entry->refcnt)) {
				fib_info_put(fib_nh->nh_parent);
				list_del(&rt_entry->list);
				kfree(rt_entry);
			}
			return;
		}
	}
}

/* correlate nexthop to fib_nh in fib_info used in fib entries */
static int clsw_nh_link_fib_nh(struct clsw_nexthop *nh, struct fib_nh *fib_nh)
{
	struct clsw_nh_info *info = &nh->nh_info;
	struct clsw_nh_route_entry *rt_entry;

	list_for_each_entry(rt_entry, &info->fnh_list, list) {
		if (rt_entry->fib_nh == fib_nh) {
			refcount_inc(&rt_entry->refcnt);
			return 0;
		}
	}

	rt_entry = kzalloc(sizeof(*rt_entry), GFP_KERNEL);
	if (!rt_entry)
		return -ENOMEM;

	rt_entry->family = AF_INET;
	refcount_set(&rt_entry->refcnt, 1);
	rt_entry->fib_nh = fib_nh;
	fib_info_hold(fib_nh->nh_parent);
	list_add_tail(&rt_entry->list, &nh->nh_info.fnh_list);

	return 0;
}

static struct clsw_nexthop *clsw_nh_find_v4(struct clsw_router *router,
					    struct net_device *dev,
					    __be32 gw)
{
	u32 ifindex = dev->ifindex;
	struct hlist_head *head;
	struct clsw_nexthop *nh;

	head = &router->nexthop_head[ifindex & (NEXTHOP_HASHENTRIES - 1)];
	hlist_for_each_entry(nh, head, hlist) {
		if (clsw_nh_is_group(nh))
			continue;
		if (nh->nh_info.nh_dev == dev && nh->nh_info.has_gw &&
		    nh->nh_info.family == AF_INET && nh->nh_info.gw.ipv4 == gw)
			return nh;
	}

	return NULL;
}

static struct clsw_nexthop *
clsw_nh_get_from_fib_nh(struct clsw_router *router, struct fib_nh *fib_nh,
			bool noref)
{
	struct net_device *dev = fib_nh->nh_dev;
	__be32 gw = fib_nh->nh_gw;
	struct clsw_nexthop *nh;
	int err;

	if (!dev)
		return NULL;

	if (gw)
		nh = clsw_nh_find_v4(router, dev, gw);
	else
		nh = clsw_nexthop_lookup_dev(router, dev);

	if (nh)
		goto out;

	if (noref)
		return NULL;

	nh = clsw_nexthop_alloc(router, dev);
	if (IS_ERR(nh))
		return nh;

	err = clsw_nh_ipv4(router, nh, gw);
	if (err)
		goto err_out;

	err = clsw_nexthop_insert(router, nh);
	if (err)
		goto err_out;

	trace_nh_create(nh);
out:
	if (!noref) {
		refcount_inc(&nh->refcnt);
		clsw_nh_link_fib_nh(nh, fib_nh);
	}
	return nh;
err_out:
	clsw_nexthop_destroy(router, nh);
	return ERR_PTR(err);
}

static struct clsw_nexthop *
clsw_nh_get_mpath_fi(struct clsw_router *router, struct fib_info *fi,
		     bool noref)
{
	struct clsw_nexthop *nh;
	u8 num_dead = 0, i;
	bool ecmp = true;
	u32 weight = 0;
	int err;

	nh = clsw_nh_grp_alloc(router, fi->fib_nhs);
	if (IS_ERR(nh))
		return nh;

	for (i = 0; i < nh->nh_grp.num_nh; ++i) {
		struct fib_nh *fib_nh = &fi->fib_nh[i];
		struct clsw_nh_grp_entry *nh_ge;
		struct clsw_nexthop *nhm;

		nh_ge = &nh->nh_grp.nh_list[i];

		nhm = clsw_nh_get_from_fib_nh(router, fib_nh, noref);
		if (!nhm) {
			err = -EINVAL;
			goto err_out;
		}
		if (IS_ERR(nhm)) {
			err = PTR_ERR(nhm);
			goto err_out;
		}

		nh_ge->nh = nhm;

		// TO-DO: update these on netdev events
		if (i == 0)
			weight = fib_nh->nh_weight;
		else if (fib_nh->nh_weight != weight)
			ecmp = false;

		nh_ge->nh_weight = fib_nh->nh_weight;
		nh_ge->nh_upper_bound = atomic_read(&fib_nh->nh_upper_bound);

		if (nhm->dead)
			num_dead++;
	}

	nh->nh_grp.ecmp = ecmp;
	if (num_dead == nh->nh_grp.num_nh)
		nh->dead = 1;

	err = clsw_nexthop_insert(router, nh);
	if (err)
		goto err_out;

	if (!noref)
		refcount_inc(&nh->refcnt);

	trace_nh_create(nh);

	return nh;
err_out:
	clsw_nh_grp_destroy(router, nh);

	return ERR_PTR(err);
}

static struct clsw_nexthop *
clsw_nh_get_from_fi(struct clsw_router *router, struct fib_info *fi,
		    bool noref)
{
	if (!fi->fib_nhs)
		return NULL;
	else if (fi->fib_nhs > 1)
		return clsw_nh_get_mpath_fi(router, fi, noref);
	/* e.g., unreachable default route has nhs set to 1 but
	 * does not have a nexthop dev
	 */
	else if (!fi->fib_nh->nh_dev)
		return NULL;

	return clsw_nh_get_from_fib_nh(router, fi->fib_nh, noref);
}

static void clsw_nh_unlink_by_fi(struct clsw_nexthop *nh, struct fib_info *fi)
{
	int i;

	for (i = 0; i < fi->fib_nhs; ++i)
		clsw_nh_unlink_fib_nh(nh, &fi->fib_nh[i]);
}

static int clsw_nexthop_init(struct clsw_router *router)
{
	struct hlist_head *hash;
	int i;

	hash = kmalloc(sizeof(*hash) * NEXTHOP_HASHENTRIES, GFP_KERNEL);
	if (!hash)
		return -ENOMEM;

	for (i = 0; i < NEXTHOP_HASHENTRIES; i++)
		INIT_HLIST_HEAD(&hash[i]);

	router->nexthop_head = hash;

	return 0;
}

static void clsw_nexthop_fini(struct clsw_router *router)
{
	struct hlist_node *p, *n;
	struct hlist_head *head;
	struct clsw_nexthop *nh;
	int i;

	// TO-DO: do groups need to be removed first?
	for (i = 0; i < NEXTHOP_HASHENTRIES; i++) {
		head = &router->nexthop_head[i];
		hlist_for_each_safe(p, n, head) {
			nh = hlist_entry(p, struct clsw_nexthop, hlist);
			clsw_nexthop_remove(router, nh);
		}
	}

	kfree(router->nexthop_head);
	router->nexthop_head = NULL;
}

/*
 * fib entries
 */
static void clsw_fib_entry_print(const struct clsw_fib_entry *fe,
				 const char *desc, int err)
{
	const struct clsw_fib_key *key;
	u8 family;

	key = &fe->fib_node->key;
	family = fe->fib_node->fib->family;
	switch (family) {
	case AF_INET:
		pr_err("%s fib entry: id %llu prefix %pI4/%d type %d prio %u tos %u offload %u err %d\n",
		       desc, fe->id, &key->addr, key->plen, fe->type, fe->prio,
		       fe->tos, fe->offloaded, err);
		break;
	case AF_INET6:
		pr_err("%s fib entry: id %llu prefix %pI6c/%d type %d prio %u offload %u err %d\n",
		       desc, fe->id, &key->addr, key->plen, fe->type, fe->prio,
		       fe->offloaded, err);
		break;
	}
	if (fe->nh)
		clsw_nexthop_print(fe->nh, "fib entry", 0);
}

static struct clsw_fib_entry *
clsw_fib_entry_find(const struct clsw_fib_node *fib_node,
		    const struct clsw_fib_entry *new_fe)
{
	u8 family = fib_node->fib->family;
	struct clsw_fib_entry *fe;

	list_for_each_entry(fe, &fib_node->entry_list, node_list) {
		if (fe->vr->tb_id > new_fe->vr->tb_id)
			continue;
		if (fe->vr->tb_id != new_fe->vr->tb_id)
			break;
		if (family == AF_INET) {
			if (fe->tos > new_fe->tos)
				continue;
			if (fe->tos < new_fe->tos)
				return fe;
		}
		if (fe->prio >= new_fe->prio)
			return fe;
	}

	return NULL;
}

// TO-DO: what does "append" mean for IPv4
//        what needs to happen in the backend??
static int clsw_fib_node_list_append(struct clsw_fib_entry *fe,
				     struct clsw_fib_entry *new_fe)
{
	struct clsw_fib_node *fib_node;
	u8 family;

	if (WARN_ON(!fe))
		return -EINVAL;

	fib_node = fe->fib_node;
	family = fib_node->fib->family;

	list_for_each_entry_from(fe, &fib_node->entry_list, node_list) {
		if (fe->vr->tb_id != new_fe->vr->tb_id)
			break;
		if (fe->prio != new_fe->prio)
			break;
		if (family == AF_INET) {
			if (fe->tos != new_fe->tos)
				break;
		}
	}

	list_add_tail(&new_fe->node_list, &fe->node_list);

	return 0;
}

static int clsw_fib_node_list_insert(struct clsw_fib_entry *new_fe,
				     bool replace, bool append)
{
	struct clsw_fib_node *fib_node = new_fe->fib_node;
	struct clsw_fib_entry *fe, *last;

	fe = clsw_fib_entry_find(fib_node, new_fe);

	if (append && fe)
		return clsw_fib_node_list_append(fe, new_fe);

	/* Insert new entry before replaced one, so that we can later
	 * remove the second.
	 */
	if (fe) {
		list_add_tail(&new_fe->node_list, &fe->node_list);
		return 0;
	}

	list_for_each_entry(last, &fib_node->entry_list, node_list) {
		if (new_fe->vr->tb_id > last->vr->tb_id)
			break;
		fe = last;
	}

	if (fe)
		list_add(&new_fe->node_list, &fe->node_list);
	else
		list_add(&new_fe->node_list, &fib_node->entry_list);

	return 0;
}

static void clsw_fib_node_list_remove(struct clsw_fib_entry *fe)
{
	list_del(&fe->node_list);
}

static bool clsw_fib_entry_is_first(const struct clsw_fib_entry *fe)
{
	struct clsw_fib_node *fib_node = fe->fib_node;

	return list_first_entry(&fib_node->entry_list,
				struct clsw_fib_entry, node_list) == fe;
}

// TO-DO: handle replace and append
static int clsw_fib_entry_add_be(struct clsw_fib_entry *fe)
{
	int err;

	if (fe->offloaded || fe->skip_offload || !clsw_fib_entry_is_first(fe))
		return 0;

	if (fe->nh && fe->nh->ignore)
		return 0;

	err = sdhal_be_ops->route_create(fe);
	if (err < 0) {
		if (err == -EAGAIN)
			return 0;

		clsw_fib_entry_print(fe, "Failed to add to backend", err);
	} else {
		trace_fib_entry_update(fe);
		fe->offloaded = 1;
		clsw_nh_update_offload(fe->nh, true);
	}

	return err;
}

static void clsw_fib_entry_del_be(struct clsw_fib_entry *fe)
{
	int err;

	if (!fe->offloaded)
		return;

	err = sdhal_be_ops->route_delete(fe);
	if (err)
		clsw_fib_entry_print(fe, "Failed to delete from backend", err);

	trace_fib_entry_update(fe);

	/* most likely delete error is no entry found */
	fe->offloaded = 0;
	clsw_nh_update_offload(fe->nh, false);
}

static bool clsw_fib_entry_should_offload(struct clsw_fib_entry *fe)
{
	switch (fe->type) {
	case RTN_BROADCAST:
		fe->skip_offload = 1;
		return false;
	}

	return true;
}

static int clsw_fib_entry_link(struct clsw_router *router,
			       struct clsw_fib_entry *fe,
			       bool replace, bool append)
{
	int err;

	err = clsw_fib_node_list_insert(fe, replace, append);
	if (err) {
		clsw_fib_entry_print(fe, "Failed to insert", err);
		return err;
	}

	if (clsw_fib_entry_should_offload(fe)) {
		err = clsw_fib_entry_add_be(fe);
		if (err)
			goto err_fib_entry_add;
	}

	if (fe->nh)
		list_add_tail(&fe->nh_list, &fe->nh->fe_list);

	return 0;

err_fib_entry_add:
	clsw_fib_node_list_remove(fe);
	return err;
}

static void clsw_fib_entry_unlink(struct clsw_router *router,
				  struct clsw_fib_entry *fe)
{
	if (fe->nh)
		list_del(&fe->nh_list);

	clsw_fib_entry_del_be(fe);
	clsw_fib_node_list_remove(fe);
}

static void clsw_fib_entry_destroy(struct clsw_router *router,
				   struct clsw_fib_entry *fe)
{
	clsw_nh_put(router, fe->nh);
	clsw_vr_put(router, fe->vr);
	kmem_cache_free(clsw_fe_cachep, fe);
}

static void clsw_fib_entry_replace(struct clsw_router *router,
				   struct clsw_fib_entry *fe)
{
	struct clsw_fib_node *fib_node = fe->fib_node;
	struct clsw_fib_entry *replaced;

	/* We inserted the new entry before replaced one */
	replaced = list_next_entry(fe, node_list);

	clsw_fib_entry_unlink(router, replaced);
	clsw_fib_entry_destroy(router, replaced);
	clsw_fib_node_put(router, fib_node);
}

static void clsw_fib_entry_delete(struct clsw_router *router,
				  struct clsw_fib_entry *fe)
{
	struct clsw_fib_node *fib_node = fe->fib_node;

	trace_fib_entry_delete(fe);

	clsw_fib_entry_unlink(router, fe);
	clsw_fib_entry_destroy(router, fe);
	clsw_fib_node_put(router, fib_node);
}

static struct clsw_fib_entry *
clsw_fib_entry_create(struct clsw_vr *vr,
		      struct clsw_fib_node *fib_node,
		      struct clsw_nexthop *nh)
{
	struct clsw_fib_entry *fe;

	fe = kmem_cache_zalloc(clsw_fe_cachep, GFP_KERNEL);
	if (fe) {
		static u64 fib_entry_id;

		fe->id = ++fib_entry_id;
		fe->fib_node = fib_node;
		fe->vr = vr;
		INIT_LIST_HEAD(&fe->node_list);
		INIT_LIST_HEAD(&fe->nh_list);
		fe->nh = nh;
	}

	return fe;
}

static void clsw_router_fib_abort(struct clsw_router *router)
{
#if 1
	pr_warn("Want to abort FIB offload\n");
#else
	// TO-DO: this is really a per-device / backend setting
	//        so make the message per backend.
	pr_warn("FIB abort triggered. FIB entries are no longer being offloaded.\n");
	clsw_router_vr_flush(router);

	router->aborted = true;
#endif
}

/* return NULL or valid fib_entry */
static struct clsw_fib_entry *
clsw_fib6_entry_lookup(struct clsw_router *router, struct fib6_info *f6i)
{
	struct in6_addr *dst = &f6i->fib6_dst.addr;
	int dst_len = f6i->fib6_dst.plen;
	struct clsw_fib_node *fib_node;
	struct clsw_fib_entry *fe;
	struct clsw_nexthop *nh;
	struct clsw_vr *vr;
	u32 tbid;

	nh = clsw_nh_get_from_fib6_nh(router, &f6i->fib6_nh,
				      f6i->fib6_flags, true);
	if (IS_ERR(nh))
		return NULL;

	tbid = clsw_fib_tbid_normalize(f6i->fib6_table->tb6_id);
	vr = clsw_vr_get(router, tbid, NULL);
	if (!vr) {
		pr_err("No virtual router for table %u\n", tbid);
		return NULL;
	}

	fib_node = clsw_fib_node_get(router, vr, AF_INET6, dst, sizeof(*dst),
				     dst_len, false);
	if (IS_ERR(fib_node)) {
		pr_err("Failed to get FIB node for %pI6c/%d: err %ld\n",
		       dst, dst_len, PTR_ERR(fib_node));
		return NULL;
	}

	list_for_each_entry(fe, &fib_node->entry_list, node_list) {
		if (fe->vr == vr && fe->nh == nh &&
		    fe->prio == f6i->fib6_metric) {
			return fe;
		}
	}

	return NULL;
}

static int clsw_fib6_rt_type(const struct fib6_info *f6i)
{
	int rt_type = f6i->fib6_type;

	if (f6i->fib6_flags & RTF_REJECT) {
		switch(f6i->fib6_type) {
		case RTN_UNREACHABLE:
		case RTN_PROHIBIT:
		case RTN_BLACKHOLE:
			break;
		default:
			rt_type = -EOPNOTSUPP;
		}
	}

	return rt_type;
}

static struct clsw_fib_entry *
clsw_fib6_entry_create(struct clsw_vr *vr,
		       struct clsw_fib_node *fib_node,
		       struct clsw_nexthop *nh,
		       struct fib6_info *f6i)
{
	struct clsw_fib_entry *fe;

	fe = clsw_fib_entry_create(vr, fib_node, nh);
	if (!fe)
		return ERR_PTR(-ENOMEM);

	fe->prio = f6i->fib6_metric;
	fe->type = clsw_fib6_rt_type(f6i);

	return fe;
}

static int clsw_router_fib6_add(struct clsw_router *router,
				struct fib6_entry_notifier_info *fen6_info,
				unsigned long event)
{
	bool replace = event == FIB_EVENT_ENTRY_REPLACE;
	bool append = event == FIB_EVENT_ENTRY_APPEND;
	struct fib6_info *f6i = fen6_info->rt;
	struct in6_addr *dst = &f6i->fib6_dst.addr;
	int dst_len = f6i->fib6_dst.plen;
	struct clsw_fib_node *fib_node;
	struct clsw_fib_entry *fe;
	struct clsw_nexthop *nh;
	struct clsw_vr *vr;
	u32 tbid;
	int err;

	if (router->aborted)
		return 0;

	/* nh == NULL means a route without a dev */
	nh = clsw_nh_get_from_fib6_nh(router, &f6i->fib6_nh,
				      f6i->fib6_flags, true);
	if (IS_ERR(nh))
		return PTR_ERR(nh);

	tbid = clsw_fib_tbid_normalize(f6i->fib6_table->tb6_id);

	vr = clsw_vr_get(router, tbid, NULL);
	if (IS_ERR(vr)) {
		err = PTR_ERR(vr);
		goto err_vr;
	}

	fib_node = clsw_fib_node_get(router, vr, AF_INET6, dst, sizeof(*dst),
				     dst_len, true);
	if (IS_ERR(fib_node)) {
		err = PTR_ERR(fib_node);
		pr_err("Failed to get FIB node for %pI6c/%d, err %d. Can not add IPv6 fib entry\n",
		       dst, dst_len, err);
		goto err_fib_node;
	}

	fe = clsw_fib6_entry_create(vr, fib_node, nh, f6i);
	if (IS_ERR(fe)) {
		pr_err("Failed to create FIB entry for %pI6c/%d\n",
		       dst, dst_len);
		err = PTR_ERR(fe);
		goto err_fe_create;
	}
	/* references consumed by fib_entry */
	vr = NULL;
	nh = NULL;

	err = clsw_fib_entry_link(router, fe, replace, append);
	if (err)
		goto err_entry_link;

	trace_fib_entry_create(fe);

	if (replace)
		clsw_fib_entry_replace(router, fe);

	return 0;

err_entry_link:
	clsw_fib_entry_destroy(router, fe);
err_fe_create:
	clsw_fib_node_put(router, fib_node);
err_fib_node:
	clsw_vr_put(router, vr);
err_vr:
	clsw_nh_put(router, nh);
	return err;
}

static void clsw_router_fib6_del(struct clsw_router *router,
				 struct fib6_entry_notifier_info *fen6_info)
{
	struct fib6_info *f6i = fen6_info->rt;
	struct clsw_fib_entry *fe;

	if (router->aborted)
		return;

	fe = clsw_fib6_entry_lookup(router, f6i);
	if (fe) {
		if (fe->nh)
			clsw_nh_unlink_fib6_nh(fe->nh, &f6i->fib6_nh);

		clsw_fib_entry_delete(router, fe);
	}
}

static void clsw_router_fib6_event_work(struct work_struct *work)
{
	struct clsw_fib_event_work *fib_work =
			container_of(work, struct clsw_fib_event_work, work);
	struct clsw_router *router = fib_work->router;
	struct fib6_entry_notifier_info *fen6_info;
	int err;

	fen6_info = &fib_work->fen6_info;

	/* Protect internal structures from changes */
	rtnl_lock();

	switch (fib_work->event) {
	case FIB_EVENT_ENTRY_REPLACE: /* fall through */
	case FIB_EVENT_ENTRY_APPEND: /* fall through */
	case FIB_EVENT_ENTRY_ADD:
		err = clsw_router_fib6_add(router, fen6_info, fib_work->event);
		if (err)
			clsw_router_fib_abort(router);
		fib6_info_release(fen6_info->rt);
		break;
	case FIB_EVENT_ENTRY_DEL:
		clsw_router_fib6_del(router, fen6_info);
		fib6_info_release(fen6_info->rt);
		break;
	}

	rtnl_unlock();

	kfree(fib_work);
}

/* only FIB_EVENT_ENTRY_{ADD,DEL,APPEND,REPLACE} events */
static
int clsw_router_fib6_defer_event(struct clsw_router *router,
				 unsigned long event,
				 struct fib6_entry_notifier_info *fen6_info)
{
	struct clsw_fib_event_work *fib_work;

	fib_work = kzalloc(sizeof(*fib_work), GFP_ATOMIC);
	if (WARN_ON(!fib_work))
		return -ENOMEM;

	INIT_WORK(&fib_work->work, clsw_router_fib6_event_work);
	fib_work->router = router;
	fib_work->event = event;
	fib_work->fen6_info = *fen6_info;

	/* Take reference on route to prevent it from being
	 * freed while work is queued. Release it afterwards.
	 */
	fib6_info_hold(fib_work->fen6_info.rt);

	clsw_schedule_work(&fib_work->work);

	return 0;
}

static int clsw_router_fib6_event(struct clsw_router *router,
				  unsigned long event,
				  struct fib_notifier_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct fib6_entry_notifier_info *fen6_info;
	const struct fib6_info *f6i;
	struct net_device *dev;
	struct clsw_vr *vr;
	u32 tbid;

	fen6_info = container_of(info, struct fib6_entry_notifier_info, info);
	f6i = fen6_info->rt;

	/* skip loopback address, in6addr_loopback */
	if (ipv6_addr_equal(&f6i->fib6_dst.addr, &in6addr_loopback))
		return 0;

	/* Multicast routes aren't supported, so ignore them. */
	if (ipv6_addr_type(&f6i->fib6_dst.addr) & IPV6_ADDR_MULTICAST)
		return 0;

	if (clsw_fib6_rt_type(f6i) < 0) {
		clsw_set_extack(extack, "Route type can not be offloaded.");
		return -EOPNOTSUPP;
	}

	/* ipv6 routes have a single dev which we can check here */
	dev = f6i->fib6_nh.nh_dev;
	if (dev && clsw_ignore_dev(dev))
		return 0;

	/* can not handle source specific routing */
	if (f6i->fib6_src.plen) {
		clsw_set_extack(extack,
				"Source-specific routes not be offloaded.");
		return -EOPNOTSUPP;
	}

	tbid = clsw_fib_tbid_normalize(f6i->fib6_table->tb6_id);
	vr = clsw_vr_find(router, tbid);
	if (!vr && event != FIB_EVENT_ENTRY_DEL &&
	    !clsw_vr_find_unused(router, extack))
		return -ENOENT;

	// TO-DO: for FIB_EVENT_ENTRY_* events, pick apart the
	//	  rt6 into prefix spec and nexthops???
	//	  Any resource checks that can be done here inline?

	return clsw_router_fib6_defer_event(router, event, fen6_info);
}

/* return NULL or valid fib_entry */
static struct clsw_fib_entry *
clsw_fib4_entry_lookup(struct clsw_router *router,
		       const struct fib_entry_notifier_info *fen_info)
{
	__be32 dst = htonl(fen_info->dst);
	struct clsw_fib_node *fib_node;
	struct clsw_fib_entry *fe;
	struct clsw_nexthop *nh;
	struct clsw_vr *vr;

	nh = clsw_nh_get_from_fi(router, fen_info->fi, true);
	if (IS_ERR(nh))
		return NULL;

	vr = clsw_vr_find(router, fen_info->tb_id);
	if (!vr) {
		pr_err("No virtual router for table %u\n", fen_info->tb_id);
		return NULL;
	}

	fib_node = clsw_fib_node_get(router, vr, AF_INET, &dst,
				     sizeof(dst), fen_info->dst_len, false);
	if (IS_ERR(fib_node)) {
		pr_err("Failed to get FIB node for %pI4/%d: err %ld\n",
		       &dst, fen_info->dst_len, PTR_ERR(fib_node));
		return NULL;
	}

	list_for_each_entry(fe, &fib_node->entry_list, node_list) {
		if (fe->vr == vr &&
		    fe->type == fen_info->type &&
		    fe->tos == fen_info->tos &&
		    fe->nh == nh) {
			return fe;
		}
	}

	return NULL;
}

static struct clsw_fib_entry *
clsw_fib4_entry_create(struct clsw_vr *vr,
		       struct clsw_fib_node *fib_node,
		       struct clsw_nexthop *nh,
		       const struct fib_entry_notifier_info *fen_info)
{
	struct clsw_fib_entry *fe;

	// TO-DO: verify this is a route type of interest; ignore if not
	fe = clsw_fib_entry_create(vr, fib_node, nh);
	if (!fe)
		return ERR_PTR(-ENOMEM);

	fe->prio = fen_info->fi->fib_priority;
	fe->type = fen_info->type;
	fe->tos  = fen_info->tos;

	return fe;
}

static int clsw_router_fib4_add(struct clsw_router *router,
				const struct fib_entry_notifier_info *fen_info,
				unsigned long event)
{
	bool replace = event == FIB_EVENT_ENTRY_REPLACE;
	bool append = event == FIB_EVENT_ENTRY_APPEND;
	__be32 dst = htonl(fen_info->dst);
	struct clsw_fib_node *fib_node;
	struct clsw_fib_entry *fe;
	struct clsw_nexthop *nh;
	struct clsw_vr *vr;
	int err;

	if (router->aborted)
		return 0;

	/* nh == NULL means a route without a dev */
	nh = clsw_nh_get_from_fi(router, fen_info->fi, false);
	if (IS_ERR(nh)) {
		err = PTR_ERR(nh);
		return err;
	}

	vr = clsw_vr_get(router, fen_info->tb_id, NULL);
	if (IS_ERR(vr)) {
		err = PTR_ERR(vr);
		goto err_vr;
	}

	fib_node = clsw_fib_node_get(router, vr, AF_INET, &dst,
				     sizeof(dst), fen_info->dst_len, true);
	if (IS_ERR(fib_node)) {
		err = PTR_ERR(fib_node);
		pr_err("Failed to get FIB node for %pI4/%d, err %d. Can not add IPv4 fib entry\n",
		       &dst, fen_info->dst_len, err);
		goto err_fib_node;
	}

	fe = clsw_fib4_entry_create(vr, fib_node, nh, fen_info);
	if (IS_ERR(fe)) {
		pr_err("Failed to create FIB entry for %pI4/%d\n",
		       &dst, fen_info->dst_len);
		err = PTR_ERR(fe);
		goto err_fe_create;
	}

	/* references consumed by fib_entry */
	vr = NULL;
	nh = NULL;

	err = clsw_fib_entry_link(router, fe, replace, append);
	if (err)
		goto err_entry_link;

	trace_fib_entry_create(fe);

	if (replace)
		clsw_fib_entry_replace(router, fe);

	return 0;

err_entry_link:
	clsw_fib_entry_destroy(router, fe);
err_fe_create:
	clsw_fib_node_put(router, fib_node);
err_fib_node:
	clsw_vr_put(router, vr);
err_vr:
	clsw_nh_put(router, nh);
	return err;
}

static void clsw_router_fib4_del(struct clsw_router *router,
				 struct fib_entry_notifier_info *fen_info)
{
	struct clsw_fib_entry *fe;

	if (router->aborted)
		return;

	fe = clsw_fib4_entry_lookup(router, fen_info);
	if (fe) {
		if (fe->nh)
			clsw_nh_unlink_by_fi(fe->nh, fen_info->fi);

		clsw_fib_entry_delete(router, fe);
	}
}

static void clsw_router_fib4_event_work(struct work_struct *work)
{
	struct clsw_fib_event_work *fib_work =
			container_of(work, struct clsw_fib_event_work, work);
	struct clsw_router *router = fib_work->router;
	struct fib_entry_notifier_info *fen_info;
	int err;

	fen_info = &fib_work->fen_info;
	fen_info->tb_id = clsw_fib_tbid_normalize(fen_info->tb_id);

	/* Protect internal structures from changes */
	rtnl_lock();

	switch (fib_work->event) {
	case FIB_EVENT_ENTRY_REPLACE: /* fall through */
	case FIB_EVENT_ENTRY_APPEND: /* fall through */
	case FIB_EVENT_ENTRY_ADD:
		err = clsw_router_fib4_add(router, fen_info, fib_work->event);
		if (err)
			clsw_router_fib_abort(router);
		fib_info_put(fen_info->fi);
		break;
	case FIB_EVENT_ENTRY_DEL:
		clsw_router_fib4_del(router, fen_info);
		fib_info_put(fen_info->fi);
		break;
	}

	rtnl_unlock();

	kfree(fib_work);
}

/* only FIB_EVENT_ENTRY_{ADD,DEL,APPEND,REPLACE} events */
static
int clsw_router_fib4_defer_event(struct clsw_router *router,
				 unsigned long event,
				 struct fib_entry_notifier_info *fen_info)
{
	struct clsw_fib_event_work *fib_work;

	fib_work = kzalloc(sizeof(*fib_work), GFP_ATOMIC);
	if (WARN_ON(!fib_work))
		return -ENOMEM;

	INIT_WORK(&fib_work->work, clsw_router_fib4_event_work);
	fib_work->router = router;
	fib_work->event = event;
	fib_work->fen_info = *fen_info;

	/* Take reference on fib_info to prevent it from being
	 * freed while work is queued. Release it afterwards.
	 */
	fib_info_hold(fib_work->fen_info.fi);

	clsw_schedule_work(&fib_work->work);

	return 0;
}

static int clsw_router_fib4_event(struct clsw_router *router,
				  unsigned long event,
				  struct fib_notifier_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct fib_entry_notifier_info *fen_info;
	struct clsw_vr *vr;

	fen_info = container_of(info, struct fib_entry_notifier_info, info);

	/* skip loopback address */
	if (IN_LOOPBACK(fen_info->dst))
		return 0;

// TO-DO: scan fi and fib_nh to see if this is a skipped route?

	// TO-DO: Limit the following 3 checks to just front panel
	//	  ports or not management interface
	if (fen_info->tos) {
		clsw_set_extack(extack,
				"Routes based on tos can not be offloaded.");
		return -EOPNOTSUPP;
	}

	vr = clsw_vr_find(router, clsw_fib_tbid_normalize(fen_info->tb_id));
	if (!vr && event != FIB_EVENT_ENTRY_DEL &&
	    !clsw_vr_find_unused(router, extack))
		return -ENOENT;

	// TO-DO: check RTN_ route type? If not expected one tell user
	//        offload not supported

	// TO-DO: for FIB_EVENT_ENTRY_* events, pick apart the
	//	  fib_info into prefix spec and nexthops???
	//	  Any resource checks that can be done here inline?

	return clsw_router_fib4_defer_event(router, event, fen_info);
}

static int clsw_router_fib_rule_event(unsigned long event,
				      struct fib_notifier_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct fib_rule_notifier_info *fr_info;
	struct fib_rule *rule;
	int err = 0;

	/* nothing to do at the moment */
	if (event == FIB_EVENT_RULE_DEL)
		return 0;

	fr_info = container_of(info, struct fib_rule_notifier_info, info);
	rule = fr_info->rule;

	/* TO-DO: handle DNS fib rules (lookup points to mgmt vrf) */
	switch (info->family) {
	case AF_INET:
		if (!fib4_rule_default(rule) && !rule->l3mdev)
			err = -EOPNOTSUPP;
		break;
	case AF_INET6:
		if (!fib6_rule_default(rule) && !rule->l3mdev)
			err = -EOPNOTSUPP;
		break;
	}

	if (err < 0)
		clsw_set_extack(extack, "FIB rules not supported.");

	return err;
}

static int clsw_router_fib_event(struct notifier_block *nb,
				 unsigned long event, void *ptr)
{
	struct fib_notifier_info *info = ptr;
	struct clsw_router *router;
	int err = 0;

	/* at the moment we only handle init namespace and
	 * only handling ipv4 and ipv6 families
	 */
	if (!net_eq(info->net, &init_net) ||
	    (info->family != AF_INET && info->family != AF_INET6))
		return NOTIFY_DONE;

	// TO-DO: on abort, can the notifier be unregistered?
	router = container_of(nb, struct clsw_router, fib_nb);
	if (router->aborted)
		return NOTIFY_DONE;

	switch(event) {
	case FIB_EVENT_RULE_ADD: /* fall through */
	case FIB_EVENT_RULE_DEL:
		err = clsw_router_fib_rule_event(event, info);
		break;

	case FIB_EVENT_ENTRY_REPLACE: /* fall through */
	case FIB_EVENT_ENTRY_APPEND:  /* fall through */
	case FIB_EVENT_ENTRY_ADD:
	case FIB_EVENT_ENTRY_DEL:
		switch (info->family) {
		case AF_INET:
			err = clsw_router_fib4_event(router, event, info);
			break;
		case AF_INET6:
			err = clsw_router_fib6_event(router, event, info);
			break;
		}
		break;
	}

	return notifier_from_errno(err);
}

static void clsw_router_fib_dump_flush(struct notifier_block *nb)
{
	struct clsw_router *router;

	/* Flush pending FIB notifications and then flush the device's
	 * table before requesting another dump. The FIB notification
	 * block is unregistered, so no need to take RTNL.
	 */
	clsw_flush_owq();

	router = container_of(nb, struct clsw_router, fib_nb);
	clsw_router_vr_flush(router);
}

static int clsw_rif_index_alloc(struct clsw_router *router, u16 *index)
{
	u16 i;

	for (i = 0; i < router->max_rifs; i++) {
		if (!router->rifs[i]) {
			*index = i;
			return 0;
		}
	}

	return -ENOBUFS;
}

static struct clsw_rif *clsw_rif_create(struct clsw_router *router,
					struct clsw_rif_params *params,
					struct netlink_ext_ack *extack)
{
	struct net_device *dev = params->dev;
	u32 tb_id = clsw_fib_tbid_normalize(l3mdev_fib_table(dev));
	struct clsw_rif *rif;
	struct clsw_vr *vr;
	u16 rif_index;
	int err;

	vr = clsw_vr_get(router, tb_id, extack);
	if (IS_ERR(vr)) {
		err = PTR_ERR(vr);
		goto err_out;
	}

	err = clsw_rif_index_alloc(router, &rif_index);
	if (err) {
		clsw_set_extack(extack,
			      "Exceeded number of supported router interfaces.");
		goto err_put_vr;
	}

	err = -ENOMEM;
	rif = kzalloc(sizeof(*rif), GFP_KERNEL);
	if (!rif)
		goto err_put_vr;

	ether_addr_copy(rif->addr, dev->dev_addr);
	rif->dev = dev;
	rif->vr = vr;
	rif->rif_index = rif_index;
	rif->rif_type  = params->rif_type;

	err = sdhal_be_ops->rif_create(rif, params->priv);
	if (err) {
		pr_err("rif_create failed for dev %s: %d\n", dev->name, err);
		clsw_set_extack(extack,
				"Failed to create router interface in backend");
		kfree(rif);
		goto err_put_vr;
	}

	router->rifs[rif_index] = rif;

	trace_rif_create(rif);

	return rif;

err_put_vr:
	clsw_vr_put(router, vr);
err_out:
	return ERR_PTR(err);
}

static void clsw_rif_delete(struct clsw_router *router, struct clsw_rif *rif)
{
	int err;

	router->rifs[rif->rif_index] = NULL;

	trace_rif_delete(rif);

	err = sdhal_be_ops->rif_delete(rif);
	if (err)
		pr_err("Failed to delete rif for dev %s\n",
		       rif->dev->name);

	// TO-DO: walk nexthops for netdev verifying / evicting references

	clsw_vr_put(router, rif->vr);
	kfree(rif);
}

static bool clsw_rif_should_config(struct clsw_rif *rif,
				   struct net_device *dev,
				   unsigned long event)
{
	struct inet6_dev *inet6_dev;
	bool addr_list_empty = true;
	struct in_device *idev;

	switch (event) {
	case NETDEV_UP:
		return rif == NULL;
	case NETDEV_DOWN:
		idev = __in_dev_get_rtnl(dev);
		if (idev && idev->ifa_list)
			addr_list_empty = false;

		inet6_dev = __in6_dev_get(dev);
		if (addr_list_empty && inet6_dev &&
		    !list_empty(&inet6_dev->addr_list))
			addr_list_empty = false;

		if (rif && addr_list_empty && !netif_is_l3_slave(rif->dev))
			return true;
		return false;
	}

	return false;
}

static struct clsw_rif *clsw_rif_find_by_dev(const struct clsw_router *router,
					     const struct net_device *dev)
{
	struct clsw_rif **rifs = router->rifs;
	u16 i;

	for (i = 0; i < router->max_rifs; i++) {
		if (rifs[i] && rifs[i]->dev == dev)
			return rifs[i];
	}
	return NULL;
}

static int clsw_rif_set_addr(const struct clsw_router *router,
			     const struct net_device *dev,
			     struct netlink_ext_ack *extack)
{
	struct clsw_rif *rif;
	int err;

	rif = clsw_rif_find_by_dev(router, dev);
	if (!rif)
		return 0;

	ether_addr_copy(rif->addr, dev->dev_addr);
	err = sdhal_be_ops->rif_set_addr(rif);
	if (err)
		clsw_set_extack(extack,
		       "Failed to update hardware address on router interface");
	return err;
}

static int clsw_rifs_init(struct clsw_router *router)
{
	// TO-DO: need a backend op to read this
	router->max_rifs = 1000;

	if (router->max_rifs == 0) {
		pr_warn("max rifs is 0\n");
		return -EINVAL;
	}

	router->rifs = kzalloc(router->max_rifs * sizeof(struct clsw_rif *),
			       GFP_KERNEL);
	return router->rifs ? 0 : -ENOMEM;
}

static void clsw_rifs_fini(struct clsw_router *router)
{
	u16 i;

	for (i = 0; i < router->max_rifs; i++)
		WARN_ON_ONCE(router->rifs[i]);

	kfree(router->rifs);
	router->rifs = NULL;
}

/*
 * ipv4/ipv6 address events
 */

static int clsw_inetaddr_bridge_event(struct clsw_router *router,
				      struct net_device *dev,
				      unsigned long event,
				      struct netlink_ext_ack *extack)
{
	struct clsw_rif *rif;
	int err = 0;

	switch (event) {
	case NETDEV_UP:
		rif = clsw_rif_find_by_dev(router, dev);
		if (!rif) {
			struct clsw_rif_params params = {
				.dev = dev,
				.rif_type = CLSW_RIF_TYPE_BRIDGE,
			};

			rif = clsw_rif_create(router, &params, extack);
			if (IS_ERR(rif))
				err = PTR_ERR(rif);
		}
		if (!err)
			err = clsw_rif_bridge_join(rif, dev, extack);
		break;

	case NETDEV_DOWN:
		rif = clsw_rif_find_by_dev(router, dev);
		if (rif) {
			clsw_rif_bridge_leave(rif, dev);
			clsw_rif_delete(router, rif);
		}
		break;
	}

	return err;
}

static int clsw_port_vlan_router_join(struct clsw_port_vlan *pv,
				      struct net_device *dev,
				      struct netlink_ext_ack *extack)
{
	struct clsw_port *port = pv->port;
	struct clsw_router *router = port->router;
	struct clsw_rif *rif;
	u16 vid = pv->vlan->vid;

	rif = clsw_rif_find_by_dev(router, dev);
	if (!rif) {
		struct clsw_rif_params params = {
			.dev = dev,
			.vid = vid,
		};

		if (is_vlan_dev(dev)) {
			params.rif_type = CLSW_RIF_TYPE_PORT_VLAN;
			params.priv = pv;
		} else {
			params.rif_type = CLSW_RIF_TYPE_PORT;
			params.priv = port;
		}

		rif = clsw_rif_create(router, &params, extack);
		if (IS_ERR(rif))
			return PTR_ERR(rif);
	}

	return 0;
}

void clsw_port_vlan_router_leave(struct clsw_port_vlan *pv)
{
// TO-DO: what else????
	//u16 vid = pv->vlan->vid;

	//clsw_port_vid_stp_set(clsw_port, vid, BR_STATE_BLOCKING);
	//clsw_port_vid_learning_set(clsw_port, vid, true);
}

static int clsw_inetaddr_port_vlan_event(struct clsw_port_vlan *pv,
					 struct net_device *dev,
					 unsigned long event,
					 struct netlink_ext_ack *extack)
{
	switch (event) {
	case NETDEV_UP:
		return clsw_port_vlan_router_join(pv, dev, extack);
	case NETDEV_DOWN:
		clsw_port_vlan_router_leave(pv);
		break;
	}

	return 0;
}

static int clsw_inetaddr_vlan_event(struct clsw_port *port,
				    struct net_device *vlan_dev,
				    unsigned long event,
				    struct netlink_ext_ack *extack)
{
	struct net_device *real_dev = vlan_dev_real_dev(vlan_dev);
	u16 vid = vlan_dev_vlan_id(vlan_dev);
	int err = 0;

	if (netif_is_bridge_port(vlan_dev))
		return 0;

	if (clsw_port_dev_check(real_dev)) {
		struct clsw_port_vlan *pv;

		pv = clsw_port_vlan_get(port, vid, false, extack);
		if (!pv)
			return -ENOENT;

		err = clsw_inetaddr_port_vlan_event(pv, vlan_dev, event,
						    extack);
	} else if (netif_is_bridge_master(real_dev) &&
		   br_vlan_enabled(real_dev)) {
		pr_info("TO-DO: inetaddr_vlan_event: add support for bridges\n");
	}
	return 0;
}

static int clsw_inetaddr_port_event(struct clsw_port *port,
				    struct net_device *dev,
				    unsigned long event,
				    struct netlink_ext_ack *extack)
{
	struct clsw_port_vlan *pv;

	// why not return an error here? a device enslaved to a bridge
	// should not have an address on it
	if (netif_is_bridge_port(dev) ||
	    netif_is_lag_port(dev) ||
	    netif_is_ovs_port(dev))
		return 0;

	pv = clsw_port_vlan_find_pvid(port);
	if (!pv) {
		clsw_set_extack(extack, "No PVID on port");
		return -ENOENT;
	}
	return clsw_inetaddr_port_vlan_event(pv, dev, event, extack);
}

static int __clsw_inetaddr_event(struct clsw_router *router,
				 struct net_device *dev,
				 unsigned long event,
				 struct netlink_ext_ack *extack)
{
	struct clsw_port *port;
	struct clsw_rif *rif;
	int err = 0;

	port = clsw_get_port_dev(dev);
	/* e.g., device is not ultimately backed by a port netdev */
	if (!port)
		goto out;

	rif = clsw_rif_find_by_dev(router, dev);
	if (!clsw_rif_should_config(rif, dev, event))
		goto out;

	if (clsw_port_dev_check(dev))
		err = clsw_inetaddr_port_event(port, dev, event, extack);
	else if (is_vlan_dev(dev))
		err = clsw_inetaddr_vlan_event(port, dev, event, extack);
	else if (netif_is_bridge_master(dev))
		err = clsw_inetaddr_bridge_event(router, dev, event, extack);
	else
		pr_info("__clsw_inetaddr_event: nothing to do for dev %s event %lx\n",
			dev->name, event);
out:
	return err;
}

static int clsw_inet6addr_valid_event(struct notifier_block *nb,
				      unsigned long event, void *ptr)
{
	struct in6_validator_info *i6vi = ptr;
	struct net_device *dev = i6vi->i6vi_dev->dev;
	struct clsw_router *router;

	router = container_of(nb, struct clsw_router, in6addr_valid_nb);
	return notifier_from_errno(__clsw_inetaddr_event(router, dev, event,
							 i6vi->extack));
}

struct clsw_inet6addr_event_work {
	struct work_struct work;
	struct clsw_router *router;
	struct net_device *dev;
	unsigned long event;
};

static void clsw_inet6addr_event_work(struct work_struct *work)
{
	struct clsw_inet6addr_event_work *in6addr_work =
		     container_of(work, struct clsw_inet6addr_event_work, work);
	struct clsw_router *router = in6addr_work->router;
	struct net_device *dev = in6addr_work->dev;
	unsigned long event = in6addr_work->event;

	rtnl_lock();

	__clsw_inetaddr_event(router, dev, event, NULL);

	rtnl_unlock();

	dev_put(dev);
	kfree(in6addr_work);
}

/* Called with rcu_read_lock() */
static int clsw_inet6addr_event(struct notifier_block *nb,
				unsigned long event, void *ptr)
{
	struct clsw_inet6addr_event_work *in6addr_work;
	struct inet6_ifaddr *if6 = ptr;
	struct net_device *dev = if6->idev->dev;

	/* NETDEV_UP event is handled by clsw_in6addr_valid_event */
	if (event == NETDEV_UP)
		return NOTIFY_DONE;

	in6addr_work = kzalloc(sizeof(*in6addr_work), GFP_ATOMIC);
	if (!in6addr_work)
		return NOTIFY_BAD;

	INIT_WORK(&in6addr_work->work, clsw_inet6addr_event_work);
	in6addr_work->router = container_of(nb, struct clsw_router, in6addr_nb);
	in6addr_work->event = event;
	in6addr_work->dev = dev;
	dev_hold(dev);

	clsw_schedule_work(&in6addr_work->work);

	return NOTIFY_DONE;
}

static int clsw_inetaddr_valid_event(struct notifier_block *nb,
				     unsigned long event, void *ptr)
{
	struct in_validator_info *ivi = ptr;
	struct net_device *dev = ivi->ivi_dev->dev;
	struct clsw_router *router;

	router = container_of(nb, struct clsw_router, inetaddr_valid_nb);
	return notifier_from_errno(__clsw_inetaddr_event(router, dev, event,
							 ivi->extack));
}

static int clsw_inetaddr_event(struct notifier_block *nb,
			       unsigned long event, void *ptr)
{
	int err = 0;

	/* NETDEV_UP event is handled by clsw_inetaddr_valid_event */
	if (event != NETDEV_UP) {
		struct in_ifaddr *ifa = ptr;
		struct net_device *dev = ifa->ifa_dev->dev;
		struct clsw_router *router;

		router = container_of(nb, struct clsw_router, inetaddr_nb);
		err = __clsw_inetaddr_event(router, dev, event, NULL);
	}

	return notifier_from_errno(err);
}

static int clsw_nh_walk_fe(struct clsw_nexthop *nh,
			   bool skip_ipv4, bool skip_ipv6, bool add)
{
	struct clsw_fib_entry *fe;
	int err = 0;

	nh->dead = add ? 0 : 1;

	list_for_each_entry(fe, &nh->fe_list, nh_list) {
		u8 family;

		if (fe->nh != nh) {
			clsw_fib_entry_print(fe, "Nexthop mismatch on add", 0);
			continue;
		}

		family = fe->fib_node->fib->family;
		if ((family == AF_INET && skip_ipv4) ||
		    (family == AF_INET6 && skip_ipv6))
			continue;

		/* remove from backend and reinstall */
		clsw_fib_entry_del_be(fe);

		err = clsw_fib_entry_add_be(fe);
		if (err)
			break;
	}

	return err;
}

static int clsw_nh_netdev_up(struct clsw_router *router,
			     struct net_device *dev,
			     struct netlink_ext_ack *extack)
{
	u32 ifindex = dev->ifindex;
	struct hlist_head *head;
	struct clsw_nexthop *nh;
	bool skip_ipv4 = false;
	bool skip_ipv6 = false;
	int err = 0;

	if (!netif_carrier_ok(dev)) {
		struct inet6_dev *in6_dev;
		struct in_device *in_dev;

		rcu_read_lock();

		in_dev = __in_dev_get_rcu(dev);
		if (in_dev && IN_DEV_IGNORE_ROUTES_WITH_LINKDOWN(in_dev))
			skip_ipv4 = true;

		in6_dev = __in6_dev_get(dev);
		if (in6_dev && in6_dev->cnf.ignore_routes_with_linkdown)
			skip_ipv6 = true;

		rcu_read_unlock();
	}

	/* if carrier is down and sysctl is set for both protocols,
	 * nothing to do here
	 */
	if (skip_ipv4 && skip_ipv6)
		return 0;

	/* restore routes */
	head = &router->nexthop_head[ifindex & (NEXTHOP_HASHENTRIES - 1)];
	hlist_for_each_entry(nh, head, hlist) {
		// TO-DO: update nh group
		if (clsw_nh_is_group(nh) || nh->nh_info.nh_dev != dev)
			continue;

		err = clsw_nh_walk_fe(nh, skip_ipv4, skip_ipv6, true);
		if (err) {
			clsw_set_extack(extack,
					"Failed to update fib entry in backend.");
			clsw_router_fib_abort(router);
			break;
		}
	}

	// TO-DO: handle impact of this nexthop in a group

	return err;
}

/* assumes routes are removed from backend based on fib
 * delete notifier
 */
static int clsw_nh_netdev_down(struct clsw_router *router,
			       struct net_device *dev)
{
	u32 ifindex = dev->ifindex;
	struct hlist_head *head;
	struct clsw_nexthop *nh;
	int err = 0;

	head = &router->nexthop_head[ifindex & (NEXTHOP_HASHENTRIES - 1)];
	hlist_for_each_entry(nh, head, hlist) {
		if (clsw_nh_is_group(nh) || nh->nh_info.nh_dev != dev)
			continue;

		nh->dead = 1;
		// TO-DO: check any nexthop groups referencing this nh
		//        set its dead flag if all nexthops are dead
	}

	return err;
}

static int clsw_nh_netdev_change(struct clsw_router *router,
				 struct net_device *dev,
				 struct netlink_ext_ack *extack)
{
	u32 ifindex = dev->ifindex;
	struct inet6_dev *in6_dev;
	struct in_device *in_dev;
	struct hlist_head *head;
	struct clsw_nexthop *nh;
	bool skip_ipv4 = false;
	bool skip_ipv6 = false;
	int err = 0;

	if (netif_carrier_ok(dev))
		return clsw_nh_netdev_up(router, dev, extack);

	rcu_read_lock();

	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev || !IN_DEV_IGNORE_ROUTES_WITH_LINKDOWN(in_dev))
		skip_ipv4 = true;

	in6_dev = __in6_dev_get(dev);
	if (!in6_dev || !in6_dev->cnf.ignore_routes_with_linkdown)
		skip_ipv6 = true;

	rcu_read_unlock();

	/* if carrier is down and sysctl is set for both protocols,
	 * nothing to do here
	 */
	if (skip_ipv4 && skip_ipv6)
		return 0;

	head = &router->nexthop_head[ifindex & (NEXTHOP_HASHENTRIES - 1)];
	hlist_for_each_entry(nh, head, hlist) {
		// TO-DO: walk nexthop group
		if (clsw_nh_is_group(nh) || nh->nh_info.nh_dev != dev)
			continue;

		err = clsw_nh_walk_fe(nh, skip_ipv4, skip_ipv6, false);
		if (err) {
			clsw_set_extack(extack,
					"Failed to update fib entry in backend.");
			clsw_router_fib_abort(router);
			break;
		}
	}

	return err;
}

static int clsw_router_dev_event(struct notifier_block *nb,
				 unsigned long event, void *ptr)
{
	struct netdev_notifier_info *info = ptr;
	struct netlink_ext_ack *extack = info->extack;
	struct net_device *dev = info->dev;
	struct clsw_router *router;
	int err = 0;

	router = container_of(nb, struct clsw_router, dev_nb);

	switch (event) {
	case NETDEV_UP:
		err = clsw_nh_netdev_up(router, dev, extack);
		break;
	case NETDEV_DOWN:
		err = clsw_nh_netdev_down(router, dev);
		break;
	case NETDEV_CHANGE:
		err = clsw_nh_netdev_change(router, dev, extack);
		break;
	case NETDEV_CHANGEADDR:
		err = clsw_rif_set_addr(router, dev, extack);
		break;
	}

	return notifier_from_errno(err);
}

static int clsw_router_netevent_delay_probe(struct clsw_router *router,
					    void *ptr)
{
	struct neigh_parms *p = ptr;
	unsigned long interval;

	if (!p->dev ||
	    (p->tbl->family != AF_INET && p->tbl->family != AF_INET6))
		return 0;

	interval = jiffies_to_msecs(NEIGH_VAR(p, DELAY_PROBE_TIME));
	router->neigh_update.interval = interval;

	return 0;
}

struct clsw_netevent_work {
	struct work_struct work;
	struct clsw_router *router;
	struct neighbour *n;
};

static int clsw_nh_neigh_add(struct clsw_router *router,
			     struct clsw_nexthop *nh)
{
	int err;

	nh->nh_info.has_valid_neigh = 1;

	err = clsw_nexthop_offload(nh);
	if (err) {
		pr_err("Failed to offload nexthop for connected neighbor: %d\n", err);
		return err;
	}

	err = clsw_nh_walk_fe(nh, false, false, true);
	if (err) {
		pr_err("Failed to add fib entry to backend for newly connected neighbor. aborting offload");
		clsw_router_fib_abort(router);
	}

	return err;
}

/* neigh is no longer valid; remove fib_entries
 * associated with nexthop and nexthop
 */
static void clsw_nh_neigh_remove(struct clsw_nexthop *nh)
{
	nh->nh_info.has_valid_neigh = 0;

	clsw_nh_walk_fe(nh, false, false, false);
	clsw_nh_remove_offload(nh);
}

static void clsw_nh_neigh_update(struct clsw_router *router,
				 struct clsw_neigh_entry *ne,
				 bool adding)
{
	struct clsw_nh_info *nh_info;

	list_for_each_entry(nh_info, &ne->nh_list, neigh_list_node) {
		struct clsw_nexthop *nh;

		if (!nh_info->has_gw) {
			pr_err("neigh_entry nexthop_list has an invalid nexthop\n");
			continue;
		}

		nh = container_of(nh_info, struct clsw_nexthop, nh_info);
		if (adding) {
			if (clsw_nh_neigh_add(router, nh))
				return;
		} else {
			clsw_nh_neigh_remove(nh);
		}
	}
}

static void clsw_router_neigh_event_work(struct work_struct *work)
{
	struct clsw_netevent_work *ne_work =
			container_of(work, struct clsw_netevent_work, work);
	struct clsw_router *router = ne_work->router;
	struct neighbour *n = ne_work->n;
	struct clsw_neigh_entry *ne;
	u8 nud_state, dead;
	bool connected;
	int err;

	/* If these parameters are changed after we release the lock,
	 * then we are guaranteed to receive another event letting us
	 * know about it.
	 */
	read_lock_bh(&n->lock);
	nud_state = n->nud_state;
	dead = n->dead;
	read_unlock_bh(&n->lock);

	rtnl_lock();

	connected = nud_state & NUD_VALID && !dead;
	ne = clsw_neigh_entry_lookup(router, n);
	if (!connected && !ne)
		goto out;

	/* if no entry exists, create one */
	if (!ne) {
		ne = clsw_neigh_entry_create(router, n);
		if (IS_ERR(ne))
			goto out;
	}

	if (connected) {
		err = clsw_neigh_entry_update_be(ne, true);
		if (!err)
			clsw_nh_neigh_update(router, ne, true);
	} else {
		clsw_nh_neigh_update(router, ne, false);
		clsw_neigh_entry_update_be(ne, false);
	}

	if (!ne->connected && list_empty(&ne->nh_list))
		clsw_neigh_entry_destroy(router, ne);

out:
	rtnl_unlock();

	neigh_release(n);
	kfree(ne_work);
}

static int clsw_router_netevent_neigh(struct clsw_router *router, void *ptr)
{
	struct clsw_netevent_work *ne_work;
	struct neighbour *n = ptr;

	if (n->tbl->family != AF_INET && n->tbl->family != AF_INET6)
		return 0;

	if (clsw_ignore_dev(n->dev))
		return 0;

	ne_work = kzalloc(sizeof(*ne_work), GFP_ATOMIC);
	if (!ne_work)
		return -ENOMEM;

	INIT_WORK(&ne_work->work, clsw_router_neigh_event_work);
	ne_work->router = router;
	ne_work->n = n;

	/* Take a reference to ensure the neighbour won't be
	 * destructed until we drop the reference in delayed work.
	 */
	neigh_clone(n);
	clsw_schedule_work(&ne_work->work);

	return 0;
}

static int clsw_router_netevent_event(struct notifier_block *nb,
				      unsigned long event, void *ptr)
{
	struct clsw_router *router;
	int err;

	router = container_of(nb, struct clsw_router, netevent_nb);

	switch (event) {
	case NETEVENT_DELAY_PROBE_TIME_UPDATE:
		err = clsw_router_netevent_delay_probe(router, ptr);
		break;
	case NETEVENT_NEIGH_UPDATE:
		err = clsw_router_netevent_neigh(router, ptr);
		break;
	case NETEVENT_IPV4_MPATH_HASH_UPDATE:
	case NETEVENT_IPV6_MPATH_HASH_UPDATE:
		pr_err("Add support for NETEVENT_MULTIPATH_HASH_UPDATE\n");
		/* fallthrough */
	default:
		return NOTIFY_DONE;
	}

	return notifier_from_errno(err);
}

static void clsw_unregister_router_notifiers(struct clsw_router *router)
{
	unregister_fib_notifier(&router->fib_nb);
	unregister_netevent_notifier(&router->netevent_nb);
	unregister_netdevice_notifier(&router->dev_nb);
	unregister_inet6addr_validator_notifier(&router->in6addr_valid_nb);
	unregister_inet6addr_notifier(&router->in6addr_nb);
	unregister_inetaddr_validator_notifier(&router->inetaddr_valid_nb);
	unregister_inetaddr_notifier(&router->inetaddr_nb);
}

int clsw_register_router_notifiers(struct clsw_router *router)
{
	int err;

	err = register_inetaddr_notifier(&router->inetaddr_nb);
	if (err < 0) {
		pr_err("router: Failed to register inetaddr notifier\n");
		return err;
	}

	err = register_inetaddr_validator_notifier(&router->inetaddr_valid_nb);
	if (err < 0) {
		pr_err("router: Failed to register inetaddr_validator notifier\n");
		goto err_inet_valid;
	}

	err = register_inet6addr_notifier(&router->in6addr_nb);
	if (err < 0) {
		pr_err("router: Failed to register inet6addr notifier\n");
		goto err_inet6;
	}

	err = register_inet6addr_validator_notifier(&router->in6addr_valid_nb);
	if (err < 0) {
		pr_err("router: Failed to register inet6addr_validator notifier\n");
		goto err_inet6_valid;
	}

	err = register_netdevice_notifier(&router->dev_nb);
	if (err < 0) {
		pr_err("router: Failed to register netdevice notifier\n");
		goto err_dev;
	}

	err = register_netevent_notifier(&router->netevent_nb);
	if (err < 0) {
		pr_err("router: Failed to register netdevice notifier\n");
		goto err_netevent;
	}

	err = register_fib_notifier(&router->fib_nb,
				    clsw_router_fib_dump_flush);
	if (err < 0) {
		pr_err("router: Failed to register fib notifier\n");
		goto err_fib;
	}

	return 0;
err_fib:
	unregister_netevent_notifier(&router->netevent_nb);
err_netevent:
	unregister_netdevice_notifier(&router->dev_nb);
err_dev:
	unregister_inet6addr_validator_notifier(&router->in6addr_valid_nb);
err_inet6_valid:
	unregister_inet6addr_notifier(&router->in6addr_nb);
err_inet6:
	unregister_inetaddr_validator_notifier(&router->inetaddr_valid_nb);
err_inet_valid:
	unregister_inetaddr_notifier(&router->inetaddr_nb);
	return err;
}

int clsw_router_init(struct clsw_router *router)
{
	int err;

	/* dev handler needs to be called before inetaddr and fib
	 * notifier handler are invoked
	 */
	router->dev_nb.notifier_call = clsw_router_dev_event;
	router->dev_nb.priority = 10;
	router->inetaddr_nb.notifier_call = clsw_inetaddr_event;
	router->inetaddr_valid_nb.notifier_call = clsw_inetaddr_valid_event;
	router->in6addr_nb.notifier_call = clsw_inet6addr_event;
	router->in6addr_valid_nb.notifier_call = clsw_inet6addr_valid_event;
	router->fib_nb.notifier_call = clsw_router_fib_event;
	router->netevent_nb.notifier_call = clsw_router_netevent_event;

	err = clsw_rifs_init(router);
	if (err)
		return err;

	err = clsw_vrs_init(router);
	if (err)
		goto err_vrs_init;

	err = clsw_nexthop_init(router);
	if (err)
		goto err_nh_init;

	INIT_LIST_HEAD(&router->nh_neigh_list);
	err = clsw_neigh_init(router);
	if (err)
		goto err_neigh_init;

	return 0;

err_neigh_init:
	clsw_nexthop_fini(router);
err_nh_init:
	clsw_vrs_fini(router);
err_vrs_init:
	clsw_rifs_fini(router);
	return err;
}

void clsw_router_exit(struct clsw_router *router)
{
	clsw_unregister_router_notifiers(router);
	clsw_neigh_fini(router);
	clsw_nexthop_fini(router);
	clsw_vrs_fini(router);
	clsw_rifs_fini(router);
}

// TO-DO: remove this
static void clswslab_ctor(void *addr)
{
	/* to force cache's to be separate entries in slabinfo
	 * (kmem_cache code will consolidate if params match an existing one)
	 */
}

int clsw_router_mod_init(void)
{
	clsw_fe_cachep = kmem_cache_create("clsw_fe_cache",
					   sizeof(struct clsw_fib_entry),
					   0, SLAB_PANIC, clswslab_ctor);
	if (!clsw_fe_cachep) {
		pr_err("Failed to create fib_entry slab cache\n");
		return -ENOMEM;
	}

	clsw_fn_cachep = kmem_cache_create("clsw_fn_cache",
					   sizeof(struct clsw_fib_node),
					   0, SLAB_PANIC, clswslab_ctor);
	if (!clsw_fn_cachep) {
		pr_err("Failed to create fib_node slab cache\n");
		return -ENOMEM;
	}

	clsw_nh_cachep = kmem_cache_create("clsw_nh_cache",
					   sizeof(struct clsw_nexthop),
					   0, SLAB_PANIC, clswslab_ctor);
	if (!clsw_nh_cachep) {
		pr_err("Failed to create nexthop slab cache\n");
		return -ENOMEM;
	}

	return 0;
}

void clsw_router_mod_exit(void)
{
	kmem_cache_destroy(clsw_fe_cachep);
	kmem_cache_destroy(clsw_fn_cachep);
	kmem_cache_destroy(clsw_nh_cachep);
}
