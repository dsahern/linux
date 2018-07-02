/*
 * switchdev hal backend ops for kernel space driver
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
 */

#include <linux/clsw-sai.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include <net/ipv6.h>

#include "router.h"
#include "clsw-private.h"
#include "clsw-priv-sai.h"
#include "router.h"
#include "vlan.h"
#include "sdhal_be.h"

struct sdhal_sai_info {
	struct sai_data		sai_data;
#define switch_api_cb sai_data.switch_api
#define hostif_api_cb sai_data.hostif_api
#define port_api_cb   sai_data.port_api
#define vlan_api_cb   sai_data.vlan_api
#define br_api_cb     sai_data.br_api
#define rif_api_cb    sai_data.rif_api
#define vr_api_cb     sai_data.vr_api
#define route_api_cb  sai_data.route_api
#define nh_api_cb     sai_data.nh_api
#define nh_grp_api_cb sai_data.nh_grp_api
#define neigh_api_cb  sai_data.neigh_api
	struct clsw_router	router;

        struct clsw_sai_ops     *registered_ops;
} sai_info;

static void inet6_make_mask(int plen, struct in6_addr *mask)
{
	struct in6_addr a;

	a.s6_addr32[0] = 0xffffffff;
	a.s6_addr32[1] = 0xffffffff;
	a.s6_addr32[2] = 0xffffffff;
	a.s6_addr32[3] = 0xffffffff;

	ipv6_addr_prefix(mask, &a, plen);
}

static int sdhal_sai_route_set_dest_ip6(sai_route_entry_t *rt_entry,
					struct clsw_fib_key *key)
{
	struct in6_addr *a, *b;

	if (key->plen > 128)
		return -ERANGE;

	rt_entry->destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
	a = (struct in6_addr *)&rt_entry->destination.addr.ip6;
	b = (struct in6_addr *)key->addr;
	*a = *b;

	a = (struct in6_addr *)&rt_entry->destination.mask.ip6;
	inet6_make_mask(key->plen, a);

	return 0;
}

static int sdhal_sai_route_set_dest_ip4(sai_route_entry_t *rt_entry,
					struct clsw_fib_key *key)
{
	if (key->plen > 32)
		return -ERANGE;

	rt_entry->destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
	rt_entry->destination.addr.ip4 = *((u32 *)key->addr);
	rt_entry->destination.mask.ip4 = inet_make_mask(key->plen);

	return 0;
}

static int sdhal_sai_rt_set_nh_id_unicast(struct clsw_fib_entry *fe)
{
	struct clsw_nexthop *nh = fe->nh;

	if (!nh) {
		pr_err("Unicast route without a nexthop\n");
		return -ENOENT;
	}

	/* if nexthop device(s) down ... */
	if (clsw_nh_is_dead(nh))
		return -EAGAIN;

	if (clsw_nh_is_group(nh) || nh->nh_info.has_gw) {
		if (clsw_nh_is_offloaded(nh))
			fe->nh_obj_id = nh->nh_obj_id;
		else
			/*  punt to CPU until nh is offloaded */
			fe->nh_obj_id = sai_info.sai_data.cpu_port_id;
	} else {
		if (!nh->nh_info.rif) {
			pr_err("No rif for nexthop device %s\n",
			       nh->nh_info.nh_dev->name);
			return -EINVAL;
		}
		fe->nh_obj_id = nh->nh_info.rif->rif_obj_id;
	}

	return 0;
}

static int sdhal_sai_rt_set_nh_id(struct clsw_fib_entry *fe)
{
	int err = 0;

	switch (fe->type) {
	case RTN_LOCAL:      /* fall through */
	case RTN_ANYCAST:    /* fall through */
	case RTN_BROADCAST:
		/* kernel should see to it this never happens */
		if (!fe->nh || clsw_nh_is_group(fe->nh))
			return -EINVAL;
		/* if device is not up, do not offload */
		if (clsw_nh_is_dead(fe->nh))
			return -EAGAIN;
		/* fall through */
	case RTN_PROHIBIT:   /* fall through */
	case RTN_UNREACHABLE:
		fe->nh_obj_id = sai_info.sai_data.cpu_port_id;
		break;
	/* should unreachable be punted to cpu or dropped? */
	case RTN_BLACKHOLE:
		fe->nh_obj_id = SAI_NULL_OBJECT_ID;
		break;
	case RTN_UNICAST:
		err = sdhal_sai_rt_set_nh_id_unicast(fe);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

static int sdhal_sai_route_update(struct clsw_fib_entry *fe)
{
	sai_object_id_t orig_obj_id = fe->nh_obj_id;
	int err;

	err = sdhal_sai_rt_set_nh_id(fe);
	if (err < 0)
		return err;

	if (fe->nh_obj_id == orig_obj_id)
		return 0;

	return clsw_sai_route_update(sai_info.route_api_cb, &fe->route_entry,
				     fe->nh_obj_id);
}

static int sdhal_sai_route_create(struct clsw_fib_entry *fe)
{
	sai_route_entry_t *rt_entry = &fe->route_entry;
	u8 family = fe->fib_node->fib->family;
	struct clsw_fib_key *key;
	int err;

	rt_entry->switch_id = sai_info.sai_data.switch_id;
	rt_entry->vr_id = fe->vr->vr_obj_id;

	err = sdhal_sai_rt_set_nh_id(fe);
	if (err < 0)
		return err;

	key = &fe->fib_node->key;
	switch (family) {
	case AF_INET:
		err = sdhal_sai_route_set_dest_ip4(rt_entry, key);
		break;
	case AF_INET6:
		err = sdhal_sai_route_set_dest_ip6(rt_entry, key);
		break;
	default:
		pr_err("route create backend does not support address family %u\n",
		       family);
		err = -EOPNOTSUPP;
	}

	if (err)
		return err;

	return clsw_sai_route_create(sai_info.route_api_cb, rt_entry,
				     fe->nh_obj_id);
}

static int sdhal_sai_route_delete(struct clsw_fib_entry *fe)
{
	sai_route_entry_t *rt_entry = &fe->route_entry;

	return clsw_sai_route_delete(sai_info.route_api_cb, rt_entry);
}

/*******************************************************************************
 * neighbor maintenance
 */

static int sdhal_sai_neigh_delete(sai_neighbor_entry_t *sai_ne)
{
	int err;

	if (!sai_ne->switch_id)
		return 0;

	err = clsw_sai_neigh_delete(sai_info.neigh_api_cb, sai_ne);
	sai_ne->switch_id = 0;

	return err;
}

static int sdhal_sai_neigh_create(struct clsw_neigh_entry *ne)
{
	struct neighbour *n = ne->key.n;
	sai_ip_address_t *addr;
	int err;

	if (!ne->rif || !ne->rif->rif_obj_id) {
		pr_err("Attempting to create a neigh entry with an invalid rif\n");
		return -EINVAL;
	}

	addr = &ne->sai_neigh_entry.ip_address;
	switch (n->tbl->family) {
	case AF_INET:
		addr->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
		break;
	case AF_INET6:
		addr->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
		break;
	default:
		pr_err("neighbor create backend does not support address family %u\n",
		       n->tbl->family);
		return -EOPNOTSUPP;
	}

	memcpy(&ne->sai_neigh_entry.ip_address.addr,
	       n->primary_key, n->tbl->key_len);

	ne->sai_neigh_entry.switch_id = sai_info.sai_data.switch_id;
	ne->sai_neigh_entry.rif_id = ne->rif->rif_obj_id;

	err = clsw_sai_neigh_create(sai_info.neigh_api_cb,
				    &ne->sai_neigh_entry, n->ha, false);
	if (err)
		ne->sai_neigh_entry.switch_id = 0;

	return err;
}

static int sdhal_sai_neigh_update(struct clsw_neigh_entry *ne, bool add)
{
	if (!add)
		return sdhal_sai_neigh_delete(&ne->sai_neigh_entry);

	return sdhal_sai_neigh_create(ne);
}

/*******************************************************************************
 * nexthops maintenance
 */

static int sdhal_sai_create_ipv6_nh(struct clsw_nexthop *nh)
{
	struct clsw_nh_info *nh_info = &nh->nh_info;
	sai_ip_address_t addr;
	struct in6_addr *in6;

	if (!nh_info->has_gw)
		return 0;

	if (!nh_info->rif) {
		pr_err("Attempting to create a nexthop without a rif\n");
		return -EINVAL;
	}

	addr.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
	in6 = (struct in6_addr *)&addr.addr.ip6;
	*in6 = nh_info->gw.ipv6;

	return clsw_sai_nexthop_ip_create(sai_info.nh_api_cb,
				       sai_info.sai_data.switch_id,
				       &nh->nh_obj_id, &addr,
				       nh_info->rif->rif_obj_id);
}

static int sdhal_sai_create_ipv4_nh(struct clsw_nexthop *nh)
{
	struct clsw_nh_info *nh_info = &nh->nh_info;
	sai_ip_address_t addr;

	if (!nh_info->has_gw)
		return 0;

	if (!nh_info->rif) {
		pr_err("Attempting to create a nexthop without a rif\n");
		return -EINVAL;
	}

	addr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
	addr.addr.ip4 = nh_info->gw.ipv4;

	return clsw_sai_nexthop_ip_create(sai_info.nh_api_cb,
				       sai_info.sai_data.switch_id,
				       &nh->nh_obj_id, &addr,
				       nh_info->rif->rif_obj_id);
}

static int sdhal_sai_nh_grp_add_member(struct clsw_nh_grp_entry *nhge,
				       sai_object_id_t nh_grp_id)
{
	int err;

	if (nhge->nh_mbr_obj_id)
		return 0;

	err = clsw_sai_nh_grp_add_member(sai_info.nh_grp_api_cb,
					 sai_info.sai_data.switch_id,
					 nh_grp_id, nhge->nh->nh_obj_id,
					 &nhge->nh_mbr_obj_id);
	if (err)
		pr_err("Failed to add member to nexthop group: err %x\n", err);

	return err;
}

static void sdhal_sai_nh_grp_rem_member(struct clsw_nh_grp_entry *nhge)
{
	int err;

	if (!nhge->nh_mbr_obj_id)
		return;

	err = clsw_sai_nh_grp_rem_member(sai_info.nh_grp_api_cb,
					 nhge->nh_mbr_obj_id);
	if (err)
		pr_err("Failed to remove member from nexthop group: %x\n", err);

	nhge->nh_mbr_obj_id = 0;
}

/* update group members */
static int sdhal_sai_nh_grp_members(struct clsw_nexthop *nh)
{
	int num_offload = 0;
	int err;
	u8 i;

	for (i = 0; i < nh->nh_grp.num_nh; ++i) {
		struct clsw_nh_grp_entry *nhge = &nh->nh_grp.nh_list[i];

		if (clsw_nh_is_dead(nh)) {
			sdhal_sai_nh_grp_rem_member(nhge);
			/* don't include in num_offload count */
			continue;
		}

		/* if member nexthop is not offloaded, can't add to group;
		 * assumes nexthop is removed from groups prior to being
		 * removed from backend
		 */
		if (!clsw_nh_is_offloaded(nhge->nh))
			continue;

		err = sdhal_sai_nh_grp_add_member(nhge, nh->nh_obj_id);
		if (err)
			return err;

		num_offload++;
	}

	return num_offload;
}

/* invoked to update nexthop groups as well */
static int sdhal_sai_nh_grp_create(struct clsw_nexthop *nh)
{
	int err;

	if (!nh->nh_grp.ecmp) {
		pr_err("nh_grp_create does not support weighted multipath\n");

		/* if it went from ecmp to weighted then nh should be removed
		 * from backend but that means fib entries are removed first
		 */
		return -EOPNOTSUPP;
	}

	if (!nh->nh_obj_id) {
		err = clsw_sai_nh_grp_create(sai_info.nh_grp_api_cb,
					     sai_info.sai_data.switch_id,
					     &nh->nh_obj_id);
		if (err)
			return err;
	}

	/* update members in group */
	err = sdhal_sai_nh_grp_members(nh);
	if (err < 0) {
		clsw_sai_nh_grp_delete(sai_info.nh_grp_api_cb, nh->nh_obj_id);
		nh->nh_obj_id = 0;
	}

	return err;
}

static int sdhal_sai_nh_create(struct clsw_nexthop *nh)
{
	if (clsw_nh_is_group(nh))
		return sdhal_sai_nh_grp_create(nh);

	switch (nh->nh_info.family) {
	case AF_INET:
		return sdhal_sai_create_ipv4_nh(nh);
	case AF_INET6:
		return sdhal_sai_create_ipv6_nh(nh);
	}

	pr_err("sdhal_sai_nh_create does not support address family %u\n",
	       nh->nh_info.family);
	return -EOPNOTSUPP;
}

static int sdhal_sai_nh_delete(struct clsw_nexthop *nh)
{
	int err;

	if (!nh->nh_obj_id)
		return 0;

	if (clsw_nh_is_group(nh))
		err = clsw_sai_nh_grp_delete(sai_info.nh_grp_api_cb,
					     nh->nh_obj_id);
	else
		err = clsw_sai_nexthop_delete(sai_info.nh_api_cb,
					      nh->nh_obj_id);
	nh->nh_obj_id = 0;

	return err;
}

static int sdhal_sai_nh_update(struct clsw_nexthop *nh, bool add)
{
	if (!add)
		return sdhal_sai_nh_delete(nh);

	return sdhal_sai_nh_create(nh);
}

/*******************************************************************************
 * virtual routers
 */

static int sdhal_sai_vr_create(struct clsw_vr *vr)
{
	return clsw_sai_vr_create(sai_info.vr_api_cb,
				  sai_info.sai_data.switch_id,
				  &vr->vr_obj_id);
}

static int sdhal_sai_vr_delete(struct clsw_vr *vr)
{
	return clsw_sai_vr_delete(sai_info.vr_api_cb, vr->vr_obj_id);
}

static int sdhal_sai_vr_update(struct clsw_vr *vr, bool add)
{
	if (!add)
		return sdhal_sai_vr_delete(vr);

	return sdhal_sai_vr_create(vr);
}

/*******************************************************************************
 * router interfaces
 */

static int sdhal_sai_rif_set_addr(struct clsw_rif *rif)
{
	return clsw_sai_rif_set_addr(sai_info.rif_api_cb,
				     rif->rif_obj_id,
				     rif->addr);
}

static int sdhal_sai_rif_create(struct clsw_rif *rif, void *priv)
{
	struct clsw_port_vlan *pv;
	struct clsw_port *port;
	struct clsw_vlan *vlan;
	int err;

	switch(rif->rif_type) {
	case CLSW_RIF_TYPE_PORT:
		port = priv;

		err = clsw_sai_rif_create_port(sai_info.rif_api_cb,
					       sai_info.sai_data.switch_id,
					       &rif->rif_obj_id,
					       rif->vr->vr_obj_id,
					       port->port_obj_id);
		if (!err)
			rif->port_obj_id = port->port_obj_id;
		else
			pr_err("Failed RIF create for port device %s: err %d\n",
				rif->dev->name, err);
		break;
	case CLSW_RIF_TYPE_PORT_VLAN:
		pv = priv;

		err = clsw_sai_rif_create_port_vlan(sai_info.rif_api_cb,
						    sai_info.sai_data.switch_id,
						    &rif->rif_obj_id,
						    rif->vr->vr_obj_id,
						    pv->port->port_obj_id,
						    pv->vlan->vlan_obj_id);
		if (!err)
			rif->vlan_obj_id = pv->vlan->vlan_obj_id;

		else
			pr_err("Failed RIF create for port vlan device %s: err %d\n",
			       rif->dev->name, err);
		break;
	case CLSW_RIF_TYPE_VLAN:
		vlan = priv;
		err = clsw_sai_rif_create_vlan(sai_info.rif_api_cb,
					       sai_info.sai_data.switch_id,
					       &rif->rif_obj_id,
					       rif->vr->vr_obj_id,
					       vlan->vlan_obj_id);
		if (!err)
			rif->vlan_obj_id = vlan->vlan_obj_id;
		else
			pr_err("Failed RIF create for vlan device %s: err %d\n",
			       rif->dev->name, err);
		break;
	case CLSW_RIF_TYPE_BRIDGE:
		err = clsw_sai_rif_create_bridge(sai_info.rif_api_cb,
						 sai_info.sai_data.switch_id,
						 &rif->rif_obj_id,
						 rif->vr->vr_obj_id);
		if (err)
			pr_err("Failed RIF create for bridge device %s: err %d\n",
			       rif->dev->name, err);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	if (!err) {
		err = sdhal_sai_rif_set_addr(rif);
		if (err)
			pr_err("Failed to set mac addr\n");
	}

	return err;
}

static int sdhal_sai_rif_delete(struct clsw_rif *rif)
{
	int err;

	err = clsw_sai_rif_delete(sai_info.rif_api_cb, rif->rif_obj_id);

	rif->rif_obj_id = 0;
	rif->port_obj_id = 0;
	rif->vlan_obj_id = 0;

	return err;
}

/*******************************************************************************
 * bridges
 */

static int sdhal_sai_bridge_create(struct clsw_bridge *br)
{
	return clsw_sai_bridge_create(sai_info.br_api_cb,
				      sai_info.sai_data.switch_id,
				      &br->br_obj_id,
				      !!br->vlan_enabled);
}

static int sdhal_sai_bridge_delete(struct clsw_bridge *br)
{
	int err;

	err = clsw_sai_bridge_delete(sai_info.br_api_cb, br->br_obj_id);

	br->br_obj_id = 0;

	return err;
}

static const int sai_br_port_types[CLSW_BRIDGE_PORT_TYPE_MAX + 1] = {
	0,
	SAI_BRIDGE_PORT_TYPE_PORT,
	SAI_BRIDGE_PORT_TYPE_SUB_PORT,
	SAI_BRIDGE_PORT_TYPE_1Q_ROUTER,
	SAI_BRIDGE_PORT_TYPE_1D_ROUTER,
	SAI_BRIDGE_PORT_TYPE_TUNNEL
};

static int sdhal_sai_bridge_port_admin_state(struct clsw_bridge_port *br_port,
					     bool up)
{
	return clsw_sai_bridge_port_admin_state(sai_info.br_api_cb,
						br_port->br_port_obj_id, up);
}

static int sdhal_sai_bridge_port_create(struct clsw_bridge_port *br_port,
					const void *priv)
{
	struct sai_br_port_args args = {
		.br_obj_id = br_port->br->br_obj_id,
	};

	if (br_port->port_type == 0 ||
	    br_port->port_type > CLSW_BRIDGE_PORT_TYPE_MAX)
		return -EINVAL;

	if (!br_port->br->br_obj_id)
		return -EINVAL;

	args.port_type = sai_br_port_types[br_port->port_type];

	if (br_port->port_type == CLSW_BRIDGE_PORT_TYPE_PORT) {
		const struct clsw_port *port = priv;

		args.port_obj_id = port->port_obj_id;
	} else if (br_port->port_type == CLSW_BRIDGE_PORT_TYPE_VLAN) {
		const struct clsw_port_vlan *pv = priv;

		args.port_obj_id = pv->port->port_obj_id;
		args.vid = pv->vlan->vid;
		if (!br_port->br->vlan_enabled)
			args.untagged = true;
	} else if (br_port->port_type == CLSW_BRIDGE_PORT_TYPE_1D_ROUTER) {
		const struct clsw_rif *rif = priv;

		args.rif_obj_id = rif->rif_obj_id;
	} else {
		return -EOPNOTSUPP;
	}

	return clsw_sai_bridge_port_create(sai_info.br_api_cb,
					   sai_info.sai_data.switch_id,
					   &br_port->br_port_obj_id, &args);
}

static int sdhal_sai_bridge_port_delete(struct clsw_bridge_port *br_port)
{
	int err;

	err = clsw_sai_bridge_port_delete(sai_info.br_api_cb,
					  br_port->br_port_obj_id);

	br_port->br_port_obj_id = 0;

	return err;
}

/*******************************************************************************
 * VLANs
 */

static int sdhal_sai_vlan_create(struct clsw_vlan *vlan)
{
	return clsw_sai_vlan_create(sai_info.vlan_api_cb,
				    sai_info.sai_data.switch_id,
				    &vlan->vlan_obj_id, vlan->vid);
}

static int sdhal_sai_vlan_delete(struct clsw_vlan *vlan)
{
	int err;

	err = clsw_sai_vlan_remove(sai_info.vlan_api_cb,
				   vlan->vlan_obj_id);
	vlan->vlan_obj_id = 0;

	return err;
}

/*******************************************************************************
 * front panel ports
 */
static int sdhal_sai_port_set_pvid(struct clsw_port_vlan *pv)
{
	int err;

	if (!pv->vlan->untagged)
		return -EINVAL;

	err = clsw_sai_port_set_pvid(sai_info.port_api_cb,
				     pv->port->port_obj_id,
				     pv->vlan->vid);

	if (err) {
		pr_err("Failed to set pvid on dev %s: %d\n",
		       pv->port->dev->name, err);
		return err;
	}

	return err;
}

static int sdhal_sai_port_set_mtu(struct clsw_port *port)
{
	return clsw_sai_port_set_mtu(sai_info.port_api_cb,
				     port->port_obj_id,
				     port->dev->mtu);
}

static int sdhal_sai_port_get_stats(struct clsw_port *port,
				    const sai_port_stat_t *ids,
				    u32 num_counters, u64 *counters)
{
	return clsw_sai_port_get_stats(sai_info.port_api_cb,
				       port->port_obj_id, ids,
				       num_counters, counters);
}

static int sdhal_sai_port_get_speed(struct clsw_port *port, u32 *speed,
				    u8 *autoneg, u8 *duplex)
{
	return clsw_sai_port_get_speed(sai_info.port_api_cb,
				       port->port_obj_id, speed,
				       autoneg, duplex);
}

static int sdhal_sai_port_set_speed(struct clsw_port *port, u32 speed,
				    u8 autoneg, u8 duplex)
{
	return clsw_sai_port_set_speed(sai_info.port_api_cb,
				       port->port_obj_id, speed,
				       autoneg, duplex);
}

static int sdhal_sai_port_admin_state(struct clsw_port *port, bool up)
{
	return clsw_sai_port_set_admin_state(sai_info.port_api_cb,
					     port->port_obj_id, up);
}

/*******************************************************************************
 * the rest
 */

static struct clsw_sdhal_be_ops sai_be_ops = {
	.priv = &sai_info,

	.port_admin_state	= sdhal_sai_port_admin_state,
	.port_get_stats		= sdhal_sai_port_get_stats,
	.port_set_mtu		= sdhal_sai_port_set_mtu,
	.port_get_speed		= sdhal_sai_port_get_speed,
	.port_set_speed		= sdhal_sai_port_set_speed,
	.port_set_pvid		= sdhal_sai_port_set_pvid,

	.vlan_create		= sdhal_sai_vlan_create,
	.vlan_delete		= sdhal_sai_vlan_delete,

	.bridge_create		= sdhal_sai_bridge_create,
	.bridge_delete		= sdhal_sai_bridge_delete,
	.bridge_port_create	= sdhal_sai_bridge_port_create,
	.bridge_port_delete	= sdhal_sai_bridge_port_delete,
	.bridge_port_admin_state = sdhal_sai_bridge_port_admin_state,

	.rif_create		= sdhal_sai_rif_create,
	.rif_delete		= sdhal_sai_rif_delete,
	.rif_set_addr		= sdhal_sai_rif_set_addr,

	.neigh_update		= sdhal_sai_neigh_update,
	.nh_update		= sdhal_sai_nh_update,

	.vr_update		= sdhal_sai_vr_update,

	.route_create		= sdhal_sai_route_create,
	.route_update		= sdhal_sai_route_update,
	.route_delete		= sdhal_sai_route_delete,
};

/* callback pass to SAI infra; invoked on carrier changes */
void clsw_sai_port_state_cb(uint32_t count,
                            sai_port_oper_status_notification_t *data)
{
	struct clsw_port *port;

	rtnl_lock();

	port = clsw_port_find_by_portid(data->port_id);
	if (!port) {
		pr_err("unknown port id %Lx; ignoring state change\n",
		       data->port_id);
		goto out;
	}

	switch (data->port_state) {
	case SAI_PORT_OPER_STATUS_UP:
		pr_warn("Carrier up for %s\n", port->dev->name);
		netif_carrier_on(port->dev);
		break;
	case SAI_PORT_OPER_STATUS_DOWN:
		pr_warn("Carrier down for %s\n", port->dev->name);
		netif_carrier_off(port->dev);
		break;
	default:
		/* other oper states */
		break;
	}

out:
	rtnl_unlock();
}

/* serdes to front panel port mapping */
// TO-DO: needs to come from APD
static char *porttab[] = {
    "swp2", "swp19", "swp18", "swp17", "swp3", "swp21",
    "swp1", "swp20", "swp23", "swp7", "swp22", "swp5",
    "swp25", "swp10", "swp24", "swp9", "swp14", "swp13",
    "swp12", "swp11", "swp8", "swp6", "swp4", "swp16",
    "swp15", "swp28", "swp27", "swp26", "swp35", "swp31",
    "swp30", "swp29", "swp32", "swp38", "swp37", "swp36",
    "swp53", "swp51", "swp49", "swp40", "swp47", "swp34",
    "swp33", "swp54", "swp52", "swp50", "swp41", "swp43",
    "swp44", "swp48", "swp39", "swp45", "swp46", "swp42"
};

/* create kernel netdevs for ports */
static int sdhal_sai_create_port_netdev(void)
{
	sai_hostif_api_t *hostif_api = sai_info.hostif_api_cb;
	sai_object_id_t switch_id = sai_info.sai_data.switch_id;
	sai_object_id_t *port_obj_id, hif_id;
	u16 nports, i;
	int err;

	err = clsw_sai_hostif_config_traps(hostif_api, switch_id);
	if (err)
		return err;

	err = clsw_sai_get_port_info(sai_info.switch_api_cb, switch_id,
				     &port_obj_id, &nports);
	if (err)
		return err;

	rtnl_lock();
	creating_host_if = true;

	for (i = 0; i < nports; ++i) {
		struct clsw_port *port;
		struct clsw_port_vlan *pv;
		struct net_device *dev;
		char name[IFNAMSIZ];

		if (i < ARRAY_SIZE(porttab))
			snprintf(name, sizeof(name), "%s", porttab[i]);
		else
			snprintf(name, sizeof(name), "swp%d", i + 1);

		err = clsw_sai_hostif_create(hostif_api, switch_id,
					     port_obj_id[i], &hif_id,
					     name);
		if (err) {
			pr_err("Failed to create netdev for port %u\n", i);
			goto out;
		}

		err = -ENOENT;
		dev = __dev_get_by_name(&init_net, name);
		if (!dev) {
			pr_err("Failed to find netdev for port %u\n", i);
			goto out;
		}

		port = clsw_port_find_by_dev(dev);
		if (!port) {
			pr_err("Failed to find cache entry for dev %s\n",
			       name);
			goto out;
		}
		port->port_obj_id = port_obj_id[i];
		port->hif_id = hif_id;
		port->router = &sai_info.router;
		port->port_index = i;

		err = clsw_port_ethtool_init(port);
		if (err) {
			pr_err("ethtool init failed\n");
			goto out;
		}

		pv = clsw_port_vlan_get(port, CLSW_PORT_VLAN, true, NULL);
		if (IS_ERR(pv)) {
			pr_err("Failed to create PVID\n");
			err = PTR_ERR(pv);
			goto out;
		}

		sdhal_sai_port_admin_state(port, false);
		dev->operstate = IF_OPER_DOWN;
		netif_carrier_off(dev);
        }

	err = 0;
out:
	creating_host_if = false;
	rtnl_unlock();

	kfree(port_obj_id);
	return err;
}

static int clsw_default_port_vlan(void)
{
	sai_object_id_t switch_id = sai_info.sai_data.switch_id;
	sai_object_id_t vlan_obj_id;
	int err;

	err = clsw_sai_get_default_vlan(sai_info.switch_api_cb, switch_id,
					&vlan_obj_id);
	if (err) {
		pr_info("Failed to get object id for default VLAN: %d\n",
			err);
		/* fallback to letting link code create it */
		err = 0;
	} else {
		struct clsw_vlan *vlan;

		rtnl_lock();

		vlan = clsw_vlan_get_default();
		if (IS_ERR(vlan))
			err = PTR_ERR(vlan);
		else
			vlan->vlan_obj_id = vlan_obj_id;

		rtnl_unlock();
	}

	return err;
}

int clsw_sdhal_unregister(struct clsw_sai_ops *sai_ops)
{
	struct sai_data *sai_data = &sai_info.sai_data;
	struct clsw_router *router = &sai_info.router;

	if (sai_info.registered_ops != sai_ops)
		return -EBUSY;

	clsw_router_exit(router);

	clsw_unregister_netdevice_notifier();

	sdhal_be_ops = NULL;

	clsw_port_flush_all();

	clsw_sai_switch_cleanup(sai_data->switch_api, sai_data->switch_id);

	memset(&sai_info, 0, sizeof(sai_info));

	return 0;
}
EXPORT_SYMBOL(clsw_sdhal_unregister);

// TO-DO: locking, allow multiple asics
/* used for sai backend */
int clsw_sdhal_register(struct clsw_sai_ops *sai_ops)
{
	struct sai_data *sai_data = &sai_info.sai_data;
	struct clsw_router *router = &sai_info.router;
	int err;

	/* only support 1 driver ATM */
	if (sai_data->switch_id)
		return -EBUSY;

	if (sdhal_be_ops)
		return -EBUSY;

	sai_info.registered_ops = sai_ops;
	sdhal_be_ops = &sai_be_ops;

	err = clsw_sai_switch_init(sai_ops->sai_api_query, sai_ops->hw_info,
				   sai_data);
	if (err)
		goto reset_info;

	if (clsw_sai_max_vrs(sai_data->switch_api, sai_data->switch_id,
			     &router->max_vrs)) {
		pr_err("Failed to retrieve max number of virtual routers\n");
		goto switch_cleanup;
	}

	err = clsw_router_init(router);
	if (err)
		goto switch_cleanup;

	err = clsw_default_port_vlan();
	if (err < 0) {
		pr_err("Failed to setup default port vlan\n");
		goto router_exit;
	}

	err = clsw_register_netdevice_notifier();
	if (err < 0) {
		pr_err("Failed to register netdevice notifier\n");
		goto router_exit;
	}

	err = sdhal_sai_create_port_netdev();
	if (err)
		goto unreg_netdev;

	err = clsw_register_router_notifiers(router);
	if (err) {
		pr_err("Failed to register router notifiers\n");
		goto remove_hostif;
	}

	return 0;

remove_hostif:
	clsw_port_flush_all();
unreg_netdev:
	clsw_unregister_netdevice_notifier();
router_exit:
	clsw_router_exit(router);
switch_cleanup:
	clsw_sai_switch_cleanup(sai_data->switch_api, sai_data->switch_id);
reset_info:
	memset(&sai_info, 0, sizeof(sai_info));
	sdhal_be_ops = NULL;

	return err;
}
EXPORT_SYMBOL(clsw_sdhal_register);
