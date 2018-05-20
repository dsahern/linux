// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 David Ahern <dsahern@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/netdevice.h>
#include <net/stubs.h>

static struct net_device *
no_support_bond_egress_slave(struct net_device *dev, __be16 protocol)
{
	return NULL;
}

static struct bond_stub no_support_bond_stub = {
	.egress_slave = no_support_bond_egress_slave,
};

struct bond_stub __rcu *bond_stub __read_mostly = &no_support_bond_stub;

void register_bond_stubs(struct bond_stub *stubs)
{
	rcu_read_lock();
	bond_stub = stubs;
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(register_bond_stubs);

void unregister_bond_stubs(void)
{
	rcu_read_lock();
	bond_stub = &no_support_bond_stub;
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(unregister_bond_stubs);
