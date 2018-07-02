/* declarations local to driver */

#ifndef __CLSW_PRIVATE_H_
#define __CLSW_PRIVATE_H_

#include <linux/if_bridge.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>
#include <saitypes.h>

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define clsw_set_extack(extack, errstr) \
	do { \
		NL_SET_ERR_MSG_MOD((extack), errstr); \
		pr_err("%s\n", errstr); \
	} while (0)

struct clsw_port {
	struct rb_node		rb_node;   /* location in port cache tree by dev */

	struct net_device	*dev;
	struct clsw_router	*router;
	struct clsw_bridge_port	*br_port;

	sai_object_id_t		port_obj_id;
	sai_object_id_t		hif_id;   /* host interface id; kernel netdev */
	u16			port_index;

	struct list_head	vlan_list;
};

struct clsw_port_vlan {
	struct clsw_vlan	*vlan;

	struct clsw_port	*port;
	struct list_head list;   /* tracking in clsw_port */

	sai_object_id_t vlan_member_id;
};

struct clsw_port *clsw_get_port_dev(struct net_device *dev);
struct clsw_port *clsw_port_find_by_dev(struct net_device *dev);
struct clsw_port *clsw_port_find_by_portid(sai_object_id_t port_id);
void clsw_port_flush_all(void);
int clsw_port_ethtool_init(struct clsw_port *port);
void clsw_port_ethtool_fini(struct clsw_port *port);

struct clsw_port_vlan *clsw_port_vlan_find_pvid(const struct clsw_port *port);
struct clsw_port_vlan *clsw_port_vlan_get(struct clsw_port *port,
					  u16 vid, bool untagged,
					  struct netlink_ext_ack *extack);
struct clsw_port_vlan *
clsw_port_vlan_change_pvid(struct clsw_port *port, u16 vid);

extern bool creating_host_if;

int clsw_router_mod_init(void);
void clsw_router_mod_exit(void);

struct clsw_router;
int clsw_router_init(struct clsw_router *router);
void clsw_router_exit(struct clsw_router *router);
int clsw_register_router_notifiers(struct clsw_router *router);
struct clsw_router *clsw_get_router(struct net_device *dev);

extern struct switchdev_ops clsw_swdev_ops;
int clsw_register_switchdev_notifier(void);
void clsw_unregister_switchdev_notifier(void);

int clsw_register_netdevice_notifier(void);
void clsw_unregister_netdevice_notifier(void);

/* does this netdev correlate to front panel port? */
static inline bool clsw_port_dev_check(struct net_device *dev)
{
	return dev->switchdev_ops == &clsw_swdev_ops;
}
struct net_device *clsw_port_dev_lower_find(struct net_device *dev);

bool clsw_schedule_dw(struct delayed_work *dwork, unsigned long delay);
bool clsw_schedule_work(struct work_struct *work);
void clsw_flush_owq(void);
#endif
