#ifndef __CLSW_BRIDGE_H_
#define __CLSW_BRIDGE_H_

struct clsw_bridge {
	struct rb_node          rb_node;   /* location in bridge cache by dev */
	struct list_head        port_list;
	struct clsw_vlan	*vlan;
	int                     ifindex;
	u8			vlan_enabled:1,
				multicast_enabled:1;

	sai_object_id_t         br_obj_id;
};

enum clsw_bridge_port_type {
	CLSW_BRIDGE_PORT_TYPE_UNSPEC,
	CLSW_BRIDGE_PORT_TYPE_PORT,
	CLSW_BRIDGE_PORT_TYPE_VLAN,
	CLSW_BRIDGE_PORT_TYPE_1Q_ROUTER,
	CLSW_BRIDGE_PORT_TYPE_1D_ROUTER,
	CLSW_BRIDGE_PORT_TYPE_TUNNEL,
	__CLSW_BRIDGE_PORT_TYPE_MAX,
#define CLSW_BRIDGE_PORT_TYPE_MAX (__CLSW_BRIDGE_PORT_TYPE_MAX - 1)
};

struct clsw_bridge_port {
	int                     ifindex;
	unsigned int		ref_count;
	struct clsw_bridge	*br;
	struct list_head	br_list;   /* place on bridge port_list */
	struct list_head	vlan_list;
	unsigned long		flags;
	u8			stp_state;

	enum clsw_bridge_port_type port_type;

	sai_object_id_t         br_port_obj_id;
};

int clsw_bridge_event(const struct net_device *br_dev, unsigned long event,
		      struct netdev_notifier_info *info);

bool clsw_bridge_is_offloaded(const struct net_device *br_dev);

int clsw_port_bridge_join(struct clsw_port *port,
			  const struct net_device *br_dev,
			  struct netlink_ext_ack *extack);
int clsw_port_bridge_leave(struct clsw_port *port,
			   struct netlink_ext_ack *extack);
int clsw_port_bridge_set_state(const struct clsw_port *port);
int clsw_rif_bridge_join(struct clsw_rif *rif, const struct net_device *br_dev,
			 struct netlink_ext_ack *extack);
int clsw_rif_bridge_leave(struct clsw_rif *rif,
			  const struct net_device *br_dev);
#endif
