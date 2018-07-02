/* sdhal backend operations */

#ifndef __SDHAL_BE_H_
#define __SDHAL_BE_H_

#include <linux/netdevice.h>
#include <saiport.h>

#include "bridge.h"
#include "router.h"
#include "vlan.h"

struct clsw_sdhal_be_ops {
	void *priv;

	/* port maintenance */
	int (*port_admin_state)(struct clsw_port *port, bool up);
	int (*port_get_stats)(struct clsw_port *port,
			      const sai_port_stat_t *ids,
			      u32 num_counters, u64 *counters);
	int (*port_set_mtu)(struct clsw_port *port);
	int (*port_get_speed)(struct clsw_port *port, u32 *speed,
			      u8 *autoneg, u8 *duplex);
	int (*port_set_speed)(struct clsw_port *port, u32 speed,
			      u8 autoneg, u8 duplex);
	int (*port_set_pvid)(struct clsw_port_vlan *pv);

	/* VLANs */
	int (*vlan_create)(struct clsw_vlan *vlan);
	int (*vlan_delete)(struct clsw_vlan *vlan);

	/* bridge interfaces */
	int (*bridge_create)(struct clsw_bridge *br);
	int (*bridge_delete)(struct clsw_bridge *br);
	int (*bridge_port_create)(struct clsw_bridge_port *br_port,
				  const void *priv);
	int (*bridge_port_delete)(struct clsw_bridge_port *br_port);
	int (*bridge_port_admin_state)(struct clsw_bridge_port *br_port,
				       bool up);

	/* L3 (router) interfaces */
	int (*rif_create)(struct clsw_rif *rif, void *priv);
	int (*rif_delete)(struct clsw_rif *rif);
	int (*rif_set_addr)(struct clsw_rif *rif);

	/* nexthops */
	int (*nh_update)(struct clsw_nexthop *nh, bool add);

	/* neighbors */
	int (*neigh_update)(struct clsw_neigh_entry *ne, bool add);

	/* virtual routers */
	int (*vr_update)(struct clsw_vr *vr, bool add);

	/* routes */
	int (*route_create)(struct clsw_fib_entry *fe);
	int (*route_update)(struct clsw_fib_entry *fe);
	int (*route_delete)(struct clsw_fib_entry *fe);
};

extern struct clsw_sdhal_be_ops *sdhal_be_ops;

#endif
