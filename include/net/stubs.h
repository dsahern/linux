/* SPDX-License-Identifier: GPL-2.0 */

struct bond_stub {
	struct net_device *(*egress_slave)(struct net_device *dev,
					   __be16 protocol);
};

extern struct bond_stub __rcu *bond_stub;

void register_bond_stubs(struct bond_stub *stubs);
void unregister_bond_stubs(void);
