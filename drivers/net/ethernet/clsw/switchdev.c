/*
 * drivers/net/ethernet/cumulus/switchdev.c - notifier handlers for switchdev
 * Copyright (c) 2017-18 Cumulus Networks
 * Copyright (c) 2017-18 Andy Roulin <aroulin@cumulusnetworks.com>
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

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/switchdev.h>

#include "clsw-private.h"

struct switchdev_ops clsw_swdev_ops;

static int switchdev_event(struct notifier_block *self,
			   unsigned long event, void *ptr)
{
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	struct switchdev_notifier_fdb_info *fdb_info = ptr;

	pr_info("fdb notification: entry %pM vlan %d device %s event 0x%lx",
		fdb_info->addr, fdb_info->vid, dev->name, event);

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
		pr_info("Event %lx is FDB_ADD\n", event);
		/* call bridge api */
		break;
	/* case ... */
	default:
		break;
	}

	return 0;
}

static struct notifier_block switchdev_nb = {
	.notifier_call = switchdev_event,
};

int clsw_register_switchdev_notifier(void)
{
	int err;

	err = register_switchdev_notifier(&switchdev_nb);
	if (err)
		return err;

	return 0;
}

void clsw_unregister_switchdev_notifier(void)
{
	unregister_switchdev_notifier(&switchdev_nb);
}
