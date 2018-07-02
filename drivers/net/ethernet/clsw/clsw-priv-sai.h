#ifndef __CLSW_SAI_H
#define __CLSW_SAI_H

#include <linux/clsw-sai.h>

struct sai_data {
	sai_object_id_t		switch_id;
	sai_object_id_t		cpu_port_id;

	sai_switch_api_t	*switch_api;
	sai_hostif_api_t	*hostif_api;
	sai_port_api_t		*port_api;
	sai_bridge_api_t	*br_api;
	sai_vlan_api_t		*vlan_api;
	sai_router_interface_api_t *rif_api;
	sai_virtual_router_api_t *vr_api;
	sai_route_api_t		*route_api;
	sai_next_hop_api_t	*nh_api;
	sai_next_hop_group_api_t *nh_grp_api;
	sai_neighbor_api_t	*neigh_api;
};

int clsw_sai_switch_init(sai_status_t (*sai_api_query)(sai_api_t sai_api_id,
						       void **api_method_table),
			 char *hw_info, struct sai_data *data);

/* switch API */
void clsw_sai_switch_cleanup(sai_switch_api_t *switch_api,
			     sai_object_id_t switch_id);
int clsw_sai_get_port_info(sai_switch_api_t *switch_api,
			   sai_object_id_t switch_id,
			   sai_object_id_t **port_obj_id, u16 *nports);
int clsw_sai_get_default_vlan(sai_switch_api_t *switch_api,
			      sai_object_id_t switch_id,
			      sai_object_id_t *vlan_obj_id);

/* switch ports */
int clsw_sai_port_set_admin_state(sai_port_api_t *port_api,
				  sai_object_id_t port_id, bool up);
int clsw_sai_port_get_oper_state(sai_port_api_t *port_api,
				 sai_object_id_t port_id, bool *state);
int clsw_sai_port_set_pvid(sai_port_api_t *port_api, sai_object_id_t port_id,
			   u16 vid);
int clsw_sai_port_get_stats(sai_port_api_t *port_api,
			    sai_object_id_t port_id,
			    const sai_port_stat_t *ids,
			    u32 num_counters, u64 *counters);
int clsw_sai_port_set_mtu(sai_port_api_t *port_api, sai_object_id_t port_id,
			  unsigned int mtu);
int clsw_sai_port_get_speed(sai_port_api_t *port_api, sai_object_id_t port_id,
			    u32 *speed, u8 *autoneg, u8 *duplex);
int clsw_sai_port_set_speed(sai_port_api_t *port_api, sai_object_id_t port_id,
			    u32 speed, u8 autoneg, u8 duplex);
void clsw_sai_port_state_cb(uint32_t count,
			    sai_port_oper_status_notification_t *data);

/* kernel netdevs for ports */
int clsw_sai_hostif_config_traps(sai_hostif_api_t *hostif_api,
				 sai_object_id_t switch_id);
int clsw_sai_hostif_create(sai_hostif_api_t *hostif_api, sai_object_id_t swid,
			   sai_object_id_t port_id, sai_object_id_t *hif_id,
			   const char *name);
void clsw_sai_hostif_remove(sai_hostif_api_t *hostif_api,
			    sai_object_id_t hif_id);

/* Virtual Routers / VRF */
int clsw_sai_max_vrs(sai_switch_api_t *switch_api, sai_object_id_t swid,
		     u16 *nvrs);

int clsw_sai_vr_create(sai_virtual_router_api_t *vr_api,
		       sai_object_id_t switch_id, sai_object_id_t *vr_id);
int clsw_sai_vr_delete(sai_virtual_router_api_t *vr_api, sai_object_id_t vr_id);

/* VLANs */
int clsw_sai_vlan_create(sai_vlan_api_t *vlan_api, sai_object_id_t switch_id,
			 sai_object_id_t *vlan_obj_id, u16 vid);
int clsw_sai_vlan_remove(sai_vlan_api_t *vlan_api, sai_object_id_t vlan_obj_id);
int clsw_sai_vlan_add_membership(sai_vlan_api_t *vlan_api,
				 sai_object_id_t switch_id,
				 sai_object_id_t *member_obj_id,
				 sai_object_id_t br_port_obj_id,
				 sai_object_id_t vlan_obj_id,
				 bool untagged);
int clsw_sai_vlan_rem_membership(sai_vlan_api_t *vlan_api,
				 sai_object_id_t member_obj_id);

/* bridge interfaces */
struct sai_br_port_args {
	unsigned int		port_type;   /* SAI_BRIDGE_PORT_TYPE_* */
	u16			vid;	     /* SAI_BRIDGE_PORT_TYPE_SUB_PORT */
	bool			untagged;

	/* object id for port, vlan, rif, tunnel - based on port type */
	union {
		sai_object_id_t port_obj_id;
		sai_object_id_t rif_obj_id;
		sai_object_id_t tunnel_obj_id;
	};

	sai_object_id_t		br_obj_id; /* bridge object id */
};

int clsw_sai_bridge_create(sai_bridge_api_t *br_api, sai_object_id_t switch_id,
			   sai_object_id_t *br_obj_id, bool vlan_aware);
int clsw_sai_bridge_delete(sai_bridge_api_t *br_api, sai_object_id_t br_obj_id);

int clsw_sai_bridge_port_create(sai_bridge_api_t *br_api,
				sai_object_id_t switch_id,
				sai_object_id_t *br_port_obj_id,
				struct sai_br_port_args *args);
int clsw_sai_bridge_port_delete(sai_bridge_api_t *br_api,
				sai_object_id_t br_port_obj_id);
int clsw_sai_bridge_port_admin_state(sai_bridge_api_t *br_api,
				     sai_object_id_t br_port_obj_id,
				     bool up);

/* router interfaces */
int clsw_sai_rif_create_port(sai_router_interface_api_t *rif_api,
			     sai_object_id_t switch_id, sai_object_id_t *rif_id,
			     sai_object_id_t vr_id, sai_object_id_t port_id);
int clsw_sai_rif_create_port_vlan(sai_router_interface_api_t *rif_api,
				  sai_object_id_t switch_id,
				  sai_object_id_t *rif_id,
				  sai_object_id_t vr_id,
				  sai_object_id_t port_id,
				  sai_object_id_t vlan_obj_id);
int clsw_sai_rif_create_vlan(sai_router_interface_api_t *rif_api,
			     sai_object_id_t switch_id, sai_object_id_t *rif_id,
			     sai_object_id_t vr_id, sai_object_id_t vlan_id);
int clsw_sai_rif_create_bridge(sai_router_interface_api_t *rif_api,
			       sai_object_id_t switch_id,
			       sai_object_id_t *rif_id,
			       sai_object_id_t vr_id);
int clsw_sai_rif_delete(sai_router_interface_api_t *rif_api,
			sai_object_id_t rif_id);
int clsw_sai_rif_set_addr(sai_router_interface_api_t *rif_api,
                          sai_object_id_t rif_id,
                          unsigned char *addr);

/* nexthops */
int clsw_sai_nexthop_ip_create(sai_next_hop_api_t *nexthop_api,
			       sai_object_id_t switch_id,
			       sai_object_id_t *nh_obj_id,
			       sai_ip_address_t *addr,
			       sai_object_id_t rif_obj_id);
int clsw_sai_nexthop_delete(sai_next_hop_api_t *nexthop_api,
			    sai_object_id_t nh_obj_id);
int clsw_sai_nh_grp_create(sai_next_hop_group_api_t *nh_grp_api,
			   sai_object_id_t switch_id,
			   sai_object_id_t *nh_obj_id);
int clsw_sai_nh_grp_delete(sai_next_hop_group_api_t *nh_grp_api,
			   sai_object_id_t nh_obj_id);
int clsw_sai_nh_grp_add_member(sai_next_hop_group_api_t *nh_grp_api,
			       sai_object_id_t switch_id,
			       sai_object_id_t nh_grp_obj_id,
			       sai_object_id_t nh_obj_id,
			       sai_object_id_t *nh_mbr_obj_id);
int clsw_sai_nh_grp_rem_member(sai_next_hop_group_api_t *nh_grp_api,
			       sai_object_id_t nh_mbr_obj_id);

/* neighbors */
int clsw_sai_neigh_create(sai_neighbor_api_t *neigh_api,
			  sai_neighbor_entry_t *sai_ne,
			  u8 *mac, bool no_host_rt);
int clsw_sai_neigh_delete(sai_neighbor_api_t *neigh_api,
			  sai_neighbor_entry_t *sai_ne);

/* route maintenance */
int clsw_sai_route_create(sai_route_api_t *route_api,
			  sai_route_entry_t *route_entry,
			  sai_object_id_t nh_obj_id);
int clsw_sai_route_delete(sai_route_api_t *route_api,
			  sai_route_entry_t *route_entry);
int clsw_sai_route_update(sai_route_api_t *route_api,
			  sai_route_entry_t *route_entry,
			  sai_object_id_t nh_obj_id);
#endif
