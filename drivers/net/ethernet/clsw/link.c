/*
 * drivers/net/ethernet/cumulus/link.c - notifier handlers for netdev
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

#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/ip_fib.h>
#include <net/switchdev.h>
#include <linux/rtnetlink.h>

#include "clsw-private.h"
#include "router.h"
#include "bridge.h"
#include "vlan.h"
#include "sdhal_be.h"

// TO-DO: move these caches into some backend struct
// TO-DO: locking other than rtnl needed for these trees?
static struct rb_root port_cache = RB_ROOT;

bool creating_host_if;

static int clsw_port_set_pvid(struct clsw_port_vlan *pv, bool add,
			      struct netlink_ext_ack *extack)
{
	int err;

	err = sdhal_be_ops->port_set_pvid(pv);
	if (err)
		clsw_set_extack(extack, "Failed to set PVID for port");

	return err;
}

static struct clsw_port_vlan *
clsw_port_vlan_create(struct clsw_port *port, u16 vid, bool untagged,
		      struct netlink_ext_ack *extack)
{
	struct clsw_vlan *vlan;
	struct clsw_port_vlan *pv;
	int err = -ENOMEM;

	vlan = clsw_vlan_get(vid, untagged);
	if (IS_ERR(vlan)) {
		clsw_set_extack(extack, "Failed to create vlan");
		return ERR_PTR(PTR_ERR(vlan));
	}

	pv = kzalloc(sizeof(*pv), GFP_KERNEL);
	if (!pv)
		goto out_err;

	pv->port = port;
	pv->vlan = vlan;

	if (untagged) {
		err = clsw_port_set_pvid(pv, true, NULL);
		if (err)
			goto out_free;
	}

	list_add(&pv->list, &port->vlan_list);

	return pv;

out_free:
	kfree(pv);
out_err:
	clsw_vlan_put(vlan);
	return ERR_PTR(err);
}

struct clsw_port_vlan *clsw_port_vlan_find_pvid(const struct clsw_port *port)
{
	struct clsw_port_vlan *pv;

	list_for_each_entry(pv, &port->vlan_list, list) {
		if (pv->vlan->untagged)
			return pv;
	}

	return NULL;
}

static struct clsw_port_vlan *
clsw_port_vlan_find_by_vid(const struct clsw_port *port, u16 vid)
{
	struct clsw_port_vlan *pv;

	list_for_each_entry(pv, &port->vlan_list, list) {
		if (pv->vlan->vid == vid)
			return pv;
	}

	return NULL;
}

struct clsw_port_vlan *clsw_port_vlan_get(struct clsw_port *port,
					  u16 vid, bool untagged,
					  struct netlink_ext_ack *extack)
{
	struct clsw_port_vlan *pv;

	pv = clsw_port_vlan_find_by_vid(port, vid);
	if (pv)
		return pv;

	return clsw_port_vlan_create(port, vid, untagged, extack);
}

static void clsw_port_vlan_put(struct clsw_port_vlan *pv)
{
	list_del(&pv->list);
	clsw_vlan_put(pv->vlan);
	kfree(pv);
}

struct clsw_port_vlan *clsw_port_vlan_change_pvid(struct clsw_port *port,
						  u16 vid)
{
	struct clsw_port_vlan *pv, *pv_new;

	vid = vid ? : CLSW_PORT_VLAN;

	/* get reference to old pvid */
	pv = clsw_port_vlan_find_pvid(port);
	if (pv && pv->vlan->vid == vid)
		return pv;

	pv_new = clsw_port_vlan_get(port, vid, true, NULL);
	if (!IS_ERR(pv_new) && pv)
		clsw_port_vlan_put(pv);

	return pv_new;
}

static void clsw_port_vlan_flush(struct clsw_port *port)
{
	struct clsw_port_vlan *pv, *tmp;

	list_for_each_entry_safe(pv, tmp, &port->vlan_list, list)
		clsw_port_vlan_put(pv);
}

// TO-DO: a second tree with clsw_port sorted by port_id
/* used by backend when port state changes */
struct clsw_port *clsw_port_find_by_portid(sai_object_id_t port_id)
{
	struct rb_node *node;

	for (node = rb_first(&port_cache); node; node = rb_next(node)) {
		struct clsw_port *port;

		port = rb_entry(node, struct clsw_port, rb_node);

		if (port->port_obj_id == port_id)
			return port;
	}
	return NULL;
}

// TO-DO: rbtree changes made only under rtnl, but we should not
//        have to take the rtnl to do lookups. need either rcu or
//        refcnt'ed entries
struct clsw_port *clsw_port_find_by_dev(struct net_device *dev)
{
	struct rb_node *node = port_cache.rb_node;

	while (node) {
		struct clsw_port *port;

		port = rb_entry(node, struct clsw_port, rb_node);

		if (dev->ifindex < port->dev->ifindex)
			node = node->rb_left;
		else if (dev->ifindex > port->dev->ifindex)
			node = node->rb_right;
		else
			return port;
	}
	return NULL;
}

static void clsw_port_remove(struct clsw_port *port)
{
	rb_erase(&port->rb_node, &port_cache);
	clsw_port_vlan_flush(port);
	clsw_port_ethtool_fini(port);
	kfree(port);
}

void clsw_port_flush_all(void)
{
	struct rb_node *node;

	rtnl_lock();

	node = rb_first(&port_cache);
	while (node) {
		struct clsw_port *port;

		port = rb_entry(node, struct clsw_port, rb_node);
		node = rb_next(node);

		clsw_port_remove(port);
	}

	rtnl_unlock();
}

static int clsw_port_insert(struct clsw_port *new_port,
			    struct netlink_ext_ack *extack)
{
	struct rb_root *root = &port_cache;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*node) {
		struct clsw_port *port;

		parent = *node;

		port = rb_entry(parent, struct clsw_port, rb_node);
		if (port->dev->ifindex > new_port->dev->ifindex) {
			node = &(*node)->rb_left;
		} else if (port->dev->ifindex < new_port->dev->ifindex) {
			node = &(*node)->rb_right;
		} else {
			clsw_set_extack(extack,
					"port already exists for device");
			return -EEXIST;
		}
	}

	rb_link_node(&new_port->rb_node, parent, node);
	rb_insert_color(&new_port->rb_node, root);

	return 0;
}

static int clsw_port_add(struct net_device *dev, struct netlink_ext_ack *extack)
{
	struct clsw_port *port;
	int err;

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	port->dev = dev;
	INIT_LIST_HEAD(&port->vlan_list);

	err = clsw_port_insert(port, extack);
	if (err)
		kfree(port);

	return err;
}

static int clsw_lower_dev_walk(struct net_device *lower_dev, void *data)
{
	struct net_device **dev = data;
	int ret = 0;

	if (clsw_port_dev_check(lower_dev)) {
		*dev = lower_dev;
		ret = 1;
	}

	return ret;
}

struct net_device *clsw_port_dev_lower_find(struct net_device *dev)
{
	struct net_device *port_dev;

	if (clsw_port_dev_check(dev))
		return dev;

	port_dev = NULL;
	netdev_walk_all_lower_dev(dev, clsw_lower_dev_walk, &port_dev);

	return port_dev;
}

/* returns port struct if device is a known port (e.g., front
 * panel port) or dev is an upper device based layered on a port
 */
struct clsw_port *clsw_get_port_dev(struct net_device *dev)
{
	if (!clsw_port_dev_check(dev))
		dev = clsw_port_dev_lower_find(dev);

	if (!dev)
		return NULL;

	return clsw_port_find_by_dev(dev);
}

/*******************************************************************************
 * netdev events
 */

static int clsw_port_chg_upper_event(struct clsw_port *port,
				     struct netdev_notifier_info *info)
{
	struct netdev_notifier_changeupper_info *chup_info;
	struct netlink_ext_ack *extack = info->extack;
	struct net_device *upper_dev;
	int err = 0;

	chup_info = container_of(info, struct netdev_notifier_changeupper_info,
				 info);
	upper_dev = chup_info->upper_dev;

	if (netif_is_bridge_master(upper_dev)) {
		if (chup_info->linking)
			err = clsw_port_bridge_join(port, upper_dev, extack);
		else
			err = clsw_port_bridge_leave(port, extack);
	}
	return err;
}

static int clsw_port_prechg_upper_event(struct net_device *port_dev,
					struct netdev_notifier_info *info)
{
	struct netdev_notifier_changeupper_info *chup_info;
	struct netlink_ext_ack *extack = info->extack;
	struct net_device *upper_dev;

	chup_info = container_of(info, struct netdev_notifier_changeupper_info,
				 info);
	upper_dev = chup_info->upper_dev;

	if (!is_vlan_dev(upper_dev) &&
	    !netif_is_bridge_master(upper_dev) &&
	    !netif_is_l3_master(upper_dev)) {
		clsw_set_extack(extack, "Unknown upper device type");
		pr_err("port %s enslaved to master %s - unknown type\n",
		       port_dev->name, upper_dev->name);
		return -EINVAL;
	}

	if (!chup_info->linking)
		return 0;

	if (netdev_has_any_upper_dev(upper_dev) &&
	    (!netif_is_bridge_master(upper_dev) ||
	     !clsw_bridge_is_offloaded(upper_dev))) {
		clsw_set_extack(extack,
				"Enslaving a port to a device that already has an upper device is not supported");
		return -EINVAL;
	}

	return 0;
}

static int clsw_port_event(struct net_device *port_dev, unsigned long event,
			   struct netdev_notifier_info *info)
{
	struct netlink_ext_ack *extack = info->extack;
	struct clsw_port *port;
	int err = 0;

	port = clsw_port_find_by_dev(port_dev);

	/* port is required for most events */
	if (!port && event != NETDEV_REGISTER && event != NETDEV_UNREGISTER) {
		pr_info("device %s is missing port struct\n", port_dev->name);
		goto out;
	}

	switch (event) {
	case NETDEV_REGISTER:
		if (port)
			clsw_port_remove(port);

		err = clsw_port_add(port_dev, extack);
		break;
	case NETDEV_UNREGISTER:
		port_dev->switchdev_ops = NULL;
		if (port)
			clsw_port_remove(port);
		break;
	case NETDEV_UP:
		err = sdhal_be_ops->port_admin_state(port, true);
		if (err) {
			clsw_set_extack(extack, "Failed to set admin up state");
		} else if (netif_is_bridge_port(port_dev) &&
			   clsw_port_bridge_set_state(port)) {
			clsw_set_extack(extack,
					"Failed to set admin up state on bridge port");
		}
		break;
	case NETDEV_DOWN:
		err = sdhal_be_ops->port_admin_state(port, false);
		if (err) {
			clsw_set_extack(extack,
					"Failed to set admin down state");
		} else if (netif_is_bridge_port(port_dev) &&
			   clsw_port_bridge_set_state(port)) {
			clsw_set_extack(extack,
					"Failed to set admin down state on bridge port");
		}
		break;
	case NETDEV_CHANGEMTU:
		err = sdhal_be_ops->port_set_mtu(port);
		if (err)
			clsw_set_extack(extack,
					"Failed to update MTU on port");
		break;
	case NETDEV_PRECHANGEUPPER:
		err = clsw_port_prechg_upper_event(port_dev, info);
		break;
	case NETDEV_CHANGEUPPER:
		err = clsw_port_chg_upper_event(port, info);
		break;
	}
out:
	return err;
}

/* substitute for ndo_vlan_rx_add_vid and ndo_vlan_rx_kill_vid */
static int clsw_port_vlan_dev_event(struct net_device *vlan_dev,
				    struct net_device *real_dev,
				    unsigned long event,
				    struct netdev_notifier_info *info)
{
	struct clsw_port *port = clsw_get_port_dev(real_dev);
	struct netlink_ext_ack *extack = info->extack;
	u16 vid = vlan_dev_vlan_id(vlan_dev);
	struct clsw_port_vlan *pv;
	int err = 0;

	if (!vid)
		return 0;

	if (!port) {
		clsw_set_extack(extack, "Port device does not have a port struct");
		pr_err("Port device %s does not have a port struct\n",
		       real_dev->name);
		return -ENOENT;
	}

	switch (event) {
	case NETDEV_REGISTER:
		pv = clsw_port_vlan_get(port, vid, false, extack);
		if (IS_ERR(pv))
			err = PTR_ERR(pv);
		break;
	case NETDEV_UNREGISTER:
		pv = clsw_port_vlan_find_by_vid(port, vid);
		if (pv)
			clsw_port_vlan_put(pv);
		break;
	}

	return err;
}

static int netdevice_event(struct notifier_block *self,
			   unsigned long event, void *ptr)
{
	struct netdev_notifier_info *info = ptr;
	struct netlink_ext_ack _extack = {};
	struct net_device *dev = info->dev;
	int err = 0;

	if (!info->extack)
		info->extack = &_extack;

	if (creating_host_if && event == NETDEV_REGISTER)
		dev->switchdev_ops = &clsw_swdev_ops;

	if (clsw_port_dev_check(dev)) {
		err = clsw_port_event(dev, event, info);
	} else if (is_vlan_dev(dev)) {
		struct net_device *real_dev = vlan_dev_real_dev(dev);

		if (clsw_port_dev_check(real_dev))
			err = clsw_port_vlan_dev_event(dev, real_dev,
						       event, info);
	} else if (netif_is_bridge_master(dev)) {
		err = clsw_bridge_event(dev, event, info);
	}

	return notifier_from_errno(err);
}

static struct notifier_block netdevice_nb = {
	.notifier_call = netdevice_event,
};

int clsw_register_netdevice_notifier(void)
{
	int err;

	err = register_netdevice_notifier(&netdevice_nb);
	if (err < 0)
		pr_err("Failed to register netdevice notifier\n");
	else
		pr_info("Registered netdevice notifier\n");

	return err;
}

void clsw_unregister_netdevice_notifier(void)
{
	unregister_netdevice_notifier(&netdevice_nb);
	pr_info("unregistered netdevice notifier\n");
}
