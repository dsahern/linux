/*
 * drivers/net/ethernet/cumulus/bridge.c - Bridge handling code for clsw
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

#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include "clsw-private.h"
#include "router.h"
#include "vlan.h"
#include "sdhal_be.h"

// TO-DO: move these caches into some backend struct
// TO-DO: locking/refcnt other than rtnl needed for these trees?
static struct rb_root bridge_cache = RB_ROOT;

static struct clsw_bridge *clsw_bridge_find(const struct net_device *dev)
{
	struct rb_node *node = bridge_cache.rb_node;
	int ifindex = dev->ifindex;

	ASSERT_RTNL();

	while (node) {
		struct clsw_bridge *br;

		br = rb_entry(node, struct clsw_bridge, rb_node);

		if (ifindex < br->ifindex)
			node = node->rb_left;
		else if (ifindex > br->ifindex)
			node = node->rb_right;
		else
			return br;
	}
	return NULL;
}

static void clsw_bridge_remove(struct clsw_bridge *br)
{
	if (br->br_obj_id && sdhal_be_ops->bridge_delete(br))
		pr_err("Failed to delete bridge from backend\n");

	if (br->vlan)
		clsw_vlan_put(br->vlan);

	rb_erase(&br->rb_node, &bridge_cache);
	kfree(br);
}

void clsw_bridge_flush_all(struct rb_root *root)
{
	struct rb_node *node;

	node = rb_first(root);
	while (node) {
		struct clsw_bridge *br;

		br = rb_entry(node, struct clsw_bridge, rb_node);
		node = rb_next(node);

		clsw_bridge_remove(br);
	}
}

static int clsw_bridge_insert(struct clsw_bridge *new_br,
			      struct netlink_ext_ack *extack)
{
	struct rb_root *root = &bridge_cache;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*node) {
		struct clsw_bridge *br;

		parent = *node;

		br = rb_entry(parent, struct clsw_bridge, rb_node);
		if (br->ifindex > new_br->ifindex) {
			node = &(*node)->rb_left;
		} else if (br->ifindex < new_br->ifindex) {
			node = &(*node)->rb_right;
		} else {
			clsw_set_extack(extack,
					"Bridge already exists in cache");
			return -EEXIST;
		}
	}

	rb_link_node(&new_br->rb_node, parent, node);
	rb_insert_color(&new_br->rb_node, root);

	return 0;
}

static struct clsw_bridge *clsw_bridge_add(const struct net_device *dev,
					   struct netlink_ext_ack *extack)
{
	struct clsw_bridge *br;
	int err;

	br = kzalloc(sizeof(*br), GFP_KERNEL);
	if (!br)
		return ERR_PTR(-ENOMEM);

	br->ifindex = dev->ifindex;
	br->vlan_enabled = br_vlan_enabled(dev);
	if (!br->vlan_enabled) {
		br->vlan = clsw_vlan_get_unused(true);
		if (IS_ERR(br->vlan)) {
			clsw_set_extack(extack,
					"Failed to assign vlan for bridge");
			err = PTR_ERR(br->vlan);
			goto out;
		}
	}

	br->multicast_enabled = br_multicast_enabled(dev);
	INIT_LIST_HEAD(&br->port_list);

	err = clsw_bridge_insert(br, extack);
	if (err)
		goto out;

	err = sdhal_be_ops->bridge_create(br);
	if (err) {
		clsw_set_extack(extack,
				"Failed to create bridge in backend");
		clsw_bridge_remove(br);
	}

out:
	if (err) {
		kfree(br);
		br = ERR_PTR(err);
	}

	return br;
}

static void clsw_bridge_destroy(struct clsw_bridge *br)
{
	WARN_ON(!list_empty(&br->port_list));
	clsw_bridge_remove(br);
}

static struct clsw_bridge *clsw_bridge_get(const struct net_device *dev,
					   struct netlink_ext_ack *extack)
{
	struct clsw_bridge *br;

	br = clsw_bridge_find(dev);
	if (br)
		return br;

	return clsw_bridge_add(dev, extack);
}

static void clsw_bridge_put(struct clsw_bridge *br)
{
	if (list_empty(&br->port_list))
		clsw_bridge_destroy(br);
}

bool clsw_bridge_is_offloaded(const struct net_device *br_dev)
{
	struct clsw_bridge *br;

	br = clsw_bridge_find(br_dev);
	if (br && br->br_obj_id)
		return true;

	return false;
}

static struct clsw_bridge_port *
clsw_bridge_port_find(const struct clsw_bridge *br,
		      const struct net_device *port_dev)
{
	struct clsw_bridge_port *br_port;
	int ifindex = port_dev->ifindex;

	list_for_each_entry(br_port, &br->port_list, br_list) {
		if (br_port->ifindex == ifindex)
			return br_port;
	}

	return NULL;
}

static struct clsw_bridge_port *
clsw_bridge_port_create(struct clsw_bridge *br,
			const struct net_device *brport_dev,
			enum clsw_bridge_port_type port_type,
			const void *priv)
{
	struct clsw_bridge_port *br_port;
	int err;

	br_port = kzalloc(sizeof(*br_port), GFP_KERNEL);
	if (!br_port)
		return ERR_PTR(-ENOMEM);

	br_port->ifindex = brport_dev->ifindex;
	br_port->br = br;
	br_port->stp_state = BR_STATE_DISABLED;
	br_port->flags = BR_LEARNING | BR_FLOOD | BR_LEARNING_SYNC |
			 BR_MCAST_FLOOD;
	INIT_LIST_HEAD(&br_port->vlan_list);
	br_port->ref_count = 1;
	br_port->port_type = port_type;

	err = sdhal_be_ops->bridge_port_create(br_port, priv);
	if (err) {
		kfree(br_port);
		br_port = ERR_PTR(err);
		goto out;
	}

	list_add(&br_port->br_list, &br->port_list);
out:
	return br_port;
}

static void
clsw_bridge_port_destroy(struct clsw_bridge_port *br_port)
{
	list_del(&br_port->br_list);
	WARN_ON(!list_empty(&br_port->vlan_list));
	kfree(br_port);
}

static struct clsw_bridge_port *
clsw_bridge_port_get(struct clsw_bridge *br, const struct net_device *dev,
		     enum clsw_bridge_port_type port_type, const void *priv)
{
	struct clsw_bridge_port *br_port;

	br_port = clsw_bridge_port_find(br, dev);
	if (br_port) {
		WARN_ON(br_port->port_type != port_type);
		br_port->ref_count++;
		return br_port;
	}
	return clsw_bridge_port_create(br, dev, port_type, priv);
}

static void clsw_bridge_port_put(struct clsw_bridge_port *br_port)
{
	struct clsw_bridge *br = br_port->br;

	br_port->ref_count--;
	if (br_port->ref_count)
		return;

	clsw_bridge_port_destroy(br_port);
	clsw_bridge_put(br);
}

/* join a front panel port to a bridge */
int clsw_port_bridge_join(struct clsw_port *port,
			  const struct net_device *br_dev,
			  struct netlink_ext_ack *extack)
{
	struct clsw_bridge_port *br_port;
	struct clsw_port_vlan *pv = NULL;
	struct clsw_bridge *br;
	int err;

	br = clsw_bridge_get(br_dev, extack);
	if (!br) {
		clsw_set_extack(extack, "Failed to create bridge");
		return -ENOENT;
	}

	if (!br->vlan_enabled) {
		/* port is joining a vlan unaware bridge;
		 * change the pvid for the port
		 */
		pv = clsw_port_vlan_change_pvid(port, br->vlan->vid);
		if (IS_ERR(pv)) {
			clsw_set_extack(extack,
					"Failed to change pvid for port");
			err = PTR_ERR(pv);
			goto out;
		}
	} else {
		clsw_set_extack(extack, "Add support for port into vlan aware bridge");
		return -EOPNOTSUPP;
	}

	br_port = clsw_bridge_port_get(br, port->dev,
				       CLSW_BRIDGE_PORT_TYPE_VLAN, pv);
	if (IS_ERR(br_port)) {
		clsw_set_extack(extack, "Failed to create bridge port");
		err = PTR_ERR(br_port);
		goto out;
	}
	port->br_port = br_port;

	if (clsw_port_bridge_set_state(port)) {
		clsw_set_extack(extack,
				"Failed to set bridge port state in backend");
	}
	err = 0;
out:
	return err;
}

int clsw_port_bridge_leave(struct clsw_port *port,
			   struct netlink_ext_ack *extack)
{
	struct clsw_bridge_port *br_port = port->br_port;

	if (!br_port)
		return 0;

	port->br_port = NULL;
	if (sdhal_be_ops->bridge_port_delete(br_port)) {
		clsw_set_extack(extack,
			        "Failed to remove bridge port from backend");
	}

	/* port is leaving a vlan unaware bridge; reset
	 * the pvid for the port
	 */
	if (!br_port->br->vlan_enabled)
		clsw_port_vlan_change_pvid(port, 0);

	clsw_bridge_port_put(br_port);

	return 0;
}

int clsw_port_bridge_set_state(const struct clsw_port *port)
{
	struct clsw_bridge_port *br_port = port->br_port;
	bool up = netif_running(port->dev) ? true : false;
	int err = 0;

	if (br_port)
		err = sdhal_be_ops->bridge_port_admin_state(br_port, up);

	return err;
}

int clsw_rif_bridge_join(struct clsw_rif *rif, const struct net_device *br_dev,
			 struct netlink_ext_ack *extack)
{
	struct clsw_bridge_port *br_port;
	struct clsw_bridge *br;
	int err = 0;

	br = clsw_bridge_get(br_dev, extack);
	if (!br) {
		clsw_set_extack(extack, "Failed to create bridge");
		return -ENOENT;
	}

	br_port = clsw_bridge_port_get(br, rif->dev,
				       CLSW_BRIDGE_PORT_TYPE_1D_ROUTER, rif);
	if (IS_ERR(br_port)) {
		clsw_set_extack(extack, "Failed to create bridge port");
		err = PTR_ERR(br_port);
		goto out;
	}

	if (sdhal_be_ops->bridge_port_admin_state(br_port, true))
		clsw_set_extack(extack, "Failed to set bridge port up in backend");

out:
	return err;
}

int clsw_rif_bridge_leave(struct clsw_rif *rif,
			  const struct net_device *br_dev)
{
	pr_warn("clsw_rif_bridge_leave: implement me\n");
	return 0;
}

// - if bridge has forwarding enabled, create L3 interface and set
//   router mac
int clsw_bridge_event(const struct net_device *br_dev, unsigned long event,
		      struct netdev_notifier_info *info)
{
	return 0;
}
