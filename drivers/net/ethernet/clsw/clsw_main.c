/*
 * drivers/net/ethernet/cumulus/clsw_main.c - entry for generic switchdev driver
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "clsw-private.h"
#include "router.h"

#define CREATE_TRACE_POINTS
#include "clsw_trace.h"

struct clsw_sdhal_be_ops *sdhal_be_ops;

static struct workqueue_struct *clsw_wq;
static struct workqueue_struct *clsw_owq;

bool clsw_schedule_dw(struct delayed_work *dwork, unsigned long delay)
{
	return queue_delayed_work(clsw_wq, dwork, delay);
}

bool clsw_schedule_work(struct work_struct *work)
{
	return queue_work(clsw_owq, work);
}

void clsw_flush_owq(void)
{
	flush_workqueue(clsw_owq);
}

static int __init clsw_module_init(void)
{
	int err = -ENOMEM;

	clsw_wq = alloc_workqueue("clsw", WQ_MEM_RECLAIM, 0);
	if (!clsw_wq)
		return err;

	clsw_owq = alloc_ordered_workqueue("clsw_ordered", WQ_MEM_RECLAIM);
	if (!clsw_owq)
		goto free_wq;

	err = clsw_router_mod_init();
	if (err)
		goto free_owq;

	return 0;

free_owq:
	destroy_workqueue(clsw_owq);
free_wq:
	destroy_workqueue(clsw_wq);
	return err;
}

// TO-DO: need to make sure all clsw core/router allocations
//        have been freed
static void __exit clsw_module_exit(void)
{
	destroy_workqueue(clsw_owq);
	destroy_workqueue(clsw_wq);

	clsw_unregister_netdevice_notifier();
	clsw_unregister_switchdev_notifier();

	clsw_router_mod_exit();
}

module_init(clsw_module_init);
module_exit(clsw_module_exit);

MODULE_AUTHOR("David Ahern");
MODULE_DESCRIPTION("Common Layer for Switchdev");
MODULE_LICENSE("GPL");
