/*
 * SAI interface for CLSW driver
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

#include <linux/ethtool.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <sai.h>
#include <saitypes.h>
#include <saihostif.h>
#include <sainexthop.h>
#include <sainexthopgroup.h>
#include <saiport.h>
#include <sairoute.h>
#include <sairouterinterface.h>
#include <saiswitch.h>
#include <asm/errno.h>

#include "clsw-priv-sai.h"

/* rest of the kernel code uses ERR_PTR and PTR_ERR which assume
 * errno is < MAX_ERRNO = 4095. Hence sai status can not be returned
 * directly
 */
static int sai_status_to_errno(sai_status_t status)
{
	int err;

	/* hope for the best; overhead on error */
	if (likely(status == SAI_STATUS_SUCCESS))
		return 0;

	switch (status) {
	case SAI_STATUS_FAILURE:
		err = -1;
		break;
	case SAI_STATUS_NOT_SUPPORTED:
	case SAI_STATUS_NOT_IMPLEMENTED:
		err = -EOPNOTSUPP;
		break;
	case SAI_STATUS_NO_MEMORY:
		err = -ENOMEM;
		break;
	case SAI_STATUS_INSUFFICIENT_RESOURCES:
	case SAI_STATUS_TABLE_FULL:
		err = -ENOSPC;
		break;
	case SAI_STATUS_INVALID_PARAMETER:
	case SAI_STATUS_INVALID_PORT_NUMBER:
	case SAI_STATUS_INVALID_PORT_MEMBER:
	case SAI_STATUS_INVALID_VLAN_ID:
	case SAI_STATUS_UNINITIALIZED:
	case SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING:
	case SAI_STATUS_INVALID_OBJECT_TYPE:
	case SAI_STATUS_INVALID_OBJECT_ID:
		err = -EINVAL;
		break;
	case SAI_STATUS_ITEM_ALREADY_EXISTS:
		err = -EEXIST;
		break;
	case SAI_STATUS_ITEM_NOT_FOUND:
	case SAI_STATUS_ADDR_NOT_FOUND:
		err = -ENOENT;
		break;
	case SAI_STATUS_BUFFER_OVERFLOW:
		err = -ENOBUFS;
		break;
	case SAI_STATUS_OBJECT_IN_USE:
		err = -EBUSY;
		break;
	default:
		err = -1;
	}
	pr_err("clsw: sai status %d converted to error %d\n", status, err);

	return err;
}

int clsw_sai_neigh_create(sai_neighbor_api_t *neigh_api,
			  sai_neighbor_entry_t *sai_ne,
			  u8 *mac, bool no_host_rt)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 1;

	if (no_host_rt)
		count++;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
	memcpy(&attr[0].value.mac, mac, ETH_ALEN);

	if (no_host_rt) {
		attr[1].id = SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE;
		attr[1].value.booldata = true;
	}

	status = neigh_api->create_neighbor_entry(sai_ne, count, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_neigh_delete(sai_neighbor_api_t *neigh_api,
			  sai_neighbor_entry_t *sai_ne)
{
	sai_status_t status;

	status = neigh_api->remove_neighbor_entry(sai_ne);

	return sai_status_to_errno(status);
}

int clsw_sai_nexthop_ip_create(sai_next_hop_api_t *nexthop_api,
			       sai_object_id_t switch_id,
			       sai_object_id_t *nh_obj_id,
			       sai_ip_address_t *addr,
			       sai_object_id_t rif_obj_id)
{
	sai_attribute_t *attr;
	sai_status_t status;

	attr = kzalloc(sizeof(*attr) * 3, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_NEXT_HOP_ATTR_TYPE;
	attr[0].value.s32 = SAI_NEXT_HOP_TYPE_IP;

	attr[1].id = SAI_NEXT_HOP_ATTR_IP;
	attr[1].value.ipaddr = *addr;

	attr[2].id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
	attr[2].value.oid = rif_obj_id;

	status = nexthop_api->create_next_hop(nh_obj_id, switch_id, 3, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_nexthop_delete(sai_next_hop_api_t *nexthop_api,
			    sai_object_id_t nh_obj_id)
{
	sai_status_t status;

	status = nexthop_api->remove_next_hop(nh_obj_id);

	return sai_status_to_errno(status);
}

int clsw_sai_nh_grp_add_member(sai_next_hop_group_api_t *nh_grp_api,
			       sai_object_id_t switch_id,
			       sai_object_id_t nh_grp_obj_id,
			       sai_object_id_t nh_obj_id,
			       sai_object_id_t *nh_mbr_obj_id)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 2;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
	attr[0].value.oid = nh_grp_obj_id;

	attr[1].id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
	attr[1].value.oid = nh_obj_id;

	status = nh_grp_api->create_next_hop_group_member(nh_mbr_obj_id,
							  switch_id,
							  count, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_nh_grp_rem_member(sai_next_hop_group_api_t *nh_grp_api,
			       sai_object_id_t nh_mbr_obj_id)
{
	sai_status_t status;

	status = nh_grp_api->remove_next_hop_group_member(nh_mbr_obj_id);
	return sai_status_to_errno(status);
}

int clsw_sai_nh_grp_create(sai_next_hop_group_api_t *nh_grp_api,
			   sai_object_id_t switch_id,
			   sai_object_id_t *nh_obj_id)
{
	sai_attribute_t attr = {
		.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE,
		.value.u32 = SAI_NEXT_HOP_GROUP_TYPE_ECMP
	};
	sai_status_t status;

	status = nh_grp_api->create_next_hop_group(nh_obj_id, switch_id,
						   1, &attr);
	return sai_status_to_errno(status);
}

int clsw_sai_nh_grp_delete(sai_next_hop_group_api_t *nh_grp_api,
			   sai_object_id_t nh_obj_id)
{
	sai_status_t status;

	status = nh_grp_api->remove_next_hop_group(nh_obj_id);

	return sai_status_to_errno(status);
}

int clsw_sai_route_update(sai_route_api_t *route_api,
			  sai_route_entry_t *route_entry,
			  sai_object_id_t nh_obj_id)
{
	sai_attribute_t attr = {
		.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
		.value.oid = nh_obj_id
	};
	sai_status_t status;

	status = route_api->set_route_entry_attribute(route_entry, &attr);
	return sai_status_to_errno(status);
}

/* nh_obj_id is a nexthop object, nexthop group object, router interface
 * (directly attached routes), or port object (e.g., cpu port for local
 * host routes)
 */
int clsw_sai_route_create(sai_route_api_t *route_api,
			  sai_route_entry_t *route_entry,
			  sai_object_id_t nh_obj_id)
{
	sai_attribute_t attr = {
		.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
		.value.oid = nh_obj_id
	};
	sai_status_t status;

	status = route_api->create_route_entry(route_entry, 1, &attr);
	if (status == SAI_STATUS_ITEM_ALREADY_EXISTS)
		status = 0;

	return sai_status_to_errno(status);
}

int clsw_sai_route_delete(sai_route_api_t *route_api,
			  sai_route_entry_t *route_entry)
{
	sai_status_t status;

	status = route_api->remove_route_entry(route_entry);
	if (status == SAI_STATUS_ITEM_NOT_FOUND)
		status = 0;

	return sai_status_to_errno(status);
}

// TO-DO: set router mac, admin state
int clsw_sai_vr_create(sai_virtual_router_api_t *vr_api,
		       sai_object_id_t switch_id,
		       sai_object_id_t *vr_id)
{
	sai_status_t status;

	status = vr_api->create_virtual_router(vr_id, switch_id, 0, NULL);

	return sai_status_to_errno(status);
}

int clsw_sai_vr_delete(sai_virtual_router_api_t *vr_api,
		       sai_object_id_t vr_id)
{
	sai_status_t status;

	status = vr_api->remove_virtual_router(vr_id);

	return sai_status_to_errno(status);
}

int clsw_sai_rif_set_addr(sai_router_interface_api_t *rif_api,
			  sai_object_id_t rif_id,
			  unsigned char *addr)
{
	sai_attribute_t attr = {
		.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS
	};
	sai_status_t status;

	memcpy(attr.value.mac, addr, sizeof(sai_mac_t));

	status = rif_api->set_router_interface_attribute(rif_id, &attr);

	return sai_status_to_errno(status);
}

int clsw_sai_rif_create_vlan(sai_router_interface_api_t *rif_api,
			     sai_object_id_t switch_id,
			     sai_object_id_t *rif_id,
			     sai_object_id_t vr_id,
			     sai_object_id_t vlan_obj_id)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 5;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
	attr[0].value.oid = vr_id;

	attr[1].id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
	attr[1].value.s32 = SAI_ROUTER_INTERFACE_TYPE_VLAN;

	attr[2].id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
	attr[2].value.oid = vlan_obj_id;

	attr[3].id = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE;
	attr[3].value.booldata = true;

	attr[4].id = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE;
	attr[4].value.booldata = true;

	status = rif_api->create_router_interface(rif_id, switch_id,
						  count, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_rif_create_bridge(sai_router_interface_api_t *rif_api,
			       sai_object_id_t switch_id,
			       sai_object_id_t *rif_id,
			       sai_object_id_t vr_id)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 2;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
	attr[0].value.oid = vr_id;

	attr[1].id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
	attr[1].value.s32 = SAI_ROUTER_INTERFACE_TYPE_BRIDGE;

	status = rif_api->create_router_interface(rif_id, switch_id,
						  count, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_rif_create_port_vlan(sai_router_interface_api_t *rif_api,
				  sai_object_id_t switch_id,
				  sai_object_id_t *rif_id,
				  sai_object_id_t vr_id,
				  sai_object_id_t port_id,
				  sai_object_id_t vlan_obj_id)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 6;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
	attr[0].value.oid = vr_id;

	attr[1].id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
	attr[1].value.s32 = SAI_ROUTER_INTERFACE_TYPE_SUB_PORT;

	attr[2].id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
	attr[2].value.oid = port_id;

	attr[3].id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
	attr[3].value.oid = vlan_obj_id;

	attr[4].id = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE;
	attr[4].value.booldata = true;

	attr[5].id = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE;
	attr[5].value.booldata = true;

	status = rif_api->create_router_interface(rif_id, switch_id,
						  count, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_rif_create_port(sai_router_interface_api_t *rif_api,
			     sai_object_id_t switch_id,
			     sai_object_id_t *rif_id,
			     sai_object_id_t vr_id,
			     sai_object_id_t port_id)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 3;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
	attr[0].value.oid = vr_id;

	attr[1].id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
	attr[1].value.s32 = SAI_ROUTER_INTERFACE_TYPE_PORT;

	attr[2].id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
	attr[2].value.oid = port_id;

	status = rif_api->create_router_interface(rif_id, switch_id,
						  count, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_rif_delete(sai_router_interface_api_t *rif_api,
			sai_object_id_t rif_id)
{
	sai_status_t status;

	status = rif_api->remove_router_interface(rif_id);

	return sai_status_to_errno(status);
}

/*******************************************************************************
 * Bridge and bridge ports
 */
int clsw_sai_bridge_create(sai_bridge_api_t *br_api, sai_object_id_t switch_id,
			   sai_object_id_t *br_obj_id, bool vlan_aware)
{
	sai_attribute_t attr = {
		.id = SAI_BRIDGE_ATTR_TYPE,
	};
	sai_status_t status;

	attr.value.s32 = vlan_aware ? SAI_BRIDGE_TYPE_1Q : SAI_BRIDGE_TYPE_1D;

	status = br_api->create_bridge(br_obj_id, switch_id, 1, &attr);

	return sai_status_to_errno(status);
}

int clsw_sai_bridge_delete(sai_bridge_api_t *br_api, sai_object_id_t br_obj_id)
{
	sai_status_t status;

	status = br_api->remove_bridge(br_obj_id);

	return sai_status_to_errno(status);
}

int clsw_sai_bridge_port_create(sai_bridge_api_t *br_api,
				sai_object_id_t switch_id,
				sai_object_id_t *br_port_obj_id,
				struct sai_br_port_args *args)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 7; /* max count based on paths below */

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_BRIDGE_PORT_ATTR_TYPE;
	attr[0].value.s32 = args->port_type;

	/* what happens on mac learning */
	attr[1].id = SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE;
	attr[1].value.s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW;

	/* drop packets with unknown vlan */
	attr[2].id = SAI_BRIDGE_PORT_ATTR_INGRESS_FILTERING;
	attr[2].value.booldata = true;
	count = 3;

	if (args->port_type != SAI_BRIDGE_PORT_TYPE_PORT) {
		attr[count].id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
		attr[count].value.oid = args->br_obj_id;
		count++;
	}

	switch (args->port_type) {
	case SAI_BRIDGE_PORT_TYPE_PORT:
		attr[count].id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
		attr[count].value.oid = args->port_obj_id;
		count++;
		break;
	case SAI_BRIDGE_PORT_TYPE_SUB_PORT:
		attr[count].id = SAI_BRIDGE_PORT_ATTR_TAGGING_MODE;
		attr[count].value.u16 = args->untagged ?
				SAI_BRIDGE_PORT_TAGGING_MODE_UNTAGGED :
				SAI_BRIDGE_PORT_TAGGING_MODE_TAGGED;
		count++;
		attr[count].id = SAI_BRIDGE_PORT_ATTR_VLAN_ID;
		attr[count].value.u16 = args->vid;
		count++;
		attr[count].id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
		attr[count].value.oid = args->port_obj_id;
		count++;
		break;
	case SAI_BRIDGE_PORT_TYPE_1D_ROUTER:
		attr[count].id = SAI_BRIDGE_PORT_ATTR_RIF_ID;
		attr[count].value.oid = args->rif_obj_id;
		count++;
		break;
	case SAI_BRIDGE_PORT_TYPE_TUNNEL:
		attr[count].id = SAI_BRIDGE_PORT_ATTR_TUNNEL_ID;
		attr[count].value.oid = args->tunnel_obj_id;
		count++;
		break;
	}

	status = br_api->create_bridge_port(br_port_obj_id, switch_id,
					    count, attr);
	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_bridge_port_delete(sai_bridge_api_t *br_api,
				sai_object_id_t br_port_obj_id)
{
	sai_status_t status;
	int err;

	/* make sure port is admin down */
	err = clsw_sai_bridge_port_admin_state(br_api, br_port_obj_id, false);
	if (err)
		pr_err("Failed to set port admin down: %d\n", err);

	// TO-DO: flush fdb entries

	status = br_api->remove_bridge_port(br_port_obj_id);

	return sai_status_to_errno(status);
}

int clsw_sai_bridge_port_admin_state(sai_bridge_api_t *br_api,
				     sai_object_id_t br_port_obj_id,
				     bool up)
{
	sai_attribute_t attr = {
		.id = SAI_BRIDGE_PORT_ATTR_ADMIN_STATE,
		.value.booldata = up,
	};
	sai_status_t status;

	status = br_api->set_bridge_port_attribute(br_port_obj_id, &attr);

	return sai_status_to_errno(status);
}

/*******************************************************************************
 * VLANs
 */

int clsw_sai_vlan_create(sai_vlan_api_t *vlan_api, sai_object_id_t switch_id,
			 sai_object_id_t *vlan_obj_id, u16 vid)
{
	sai_attribute_t attr = {
		.id = SAI_VLAN_ATTR_VLAN_ID,
		.value.u16 = vid,
	};
	sai_status_t status;

	status = vlan_api->create_vlan(vlan_obj_id, switch_id, 1, &attr);

	return sai_status_to_errno(status);
}

int clsw_sai_vlan_remove(sai_vlan_api_t *vlan_api, sai_object_id_t vlan_obj_id)
{
	sai_status_t status;

	status = vlan_api->remove_vlan(vlan_obj_id);

	return sai_status_to_errno(status);
}

int clsw_sai_vlan_add_membership(sai_vlan_api_t *vlan_api,
				 sai_object_id_t switch_id,
				 sai_object_id_t *member_obj_id,
				 sai_object_id_t br_port_obj_id,
				 sai_object_id_t vlan_obj_id,
				 bool untagged)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 3;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
	attr[0].value.oid = vlan_obj_id;

	attr[1].id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
	attr[1].value.oid = br_port_obj_id;

	attr[2].id = SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE;
	attr[2].value.s32 = untagged ?
		  SAI_VLAN_TAGGING_MODE_UNTAGGED : SAI_VLAN_TAGGING_MODE_TAGGED;

	status = vlan_api->create_vlan_member(member_obj_id, switch_id,
					      count, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

int clsw_sai_vlan_rem_membership(sai_vlan_api_t *vlan_api,
				 sai_object_id_t member_obj_id)
{
	return vlan_api->remove_vlan_member(member_obj_id);
}

int clsw_sai_max_vrs(sai_switch_api_t *switch_api, sai_object_id_t switch_id,
		     u16 *nvrs)
{
	sai_attribute_t attr = {
		.id = SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS,
	};
	sai_status_t status;
	sai_uint32_t count;

	status = switch_api->get_switch_attribute(switch_id, 1, &attr);
	if (status != SAI_STATUS_SUCCESS)
		return sai_status_to_errno(status);

	count = attr.value.u32;

	/* we need at a minimum 1 VR for the default VRF / main table */
	if (count == 0)
		count = 1;
	else if (count > 0xffff)
		count = 0xffff;

	*nvrs = (u16) count;

	return 0;
}

/* ports default to full duplex (SAI_PORT_ATTR_FULL_DUPLEX_MODE) */
int clsw_sai_port_set_speed(sai_port_api_t *port_api, sai_object_id_t port_id,
			    u32 speed, u8 autoneg, u8 duplex)
{
	sai_attribute_t attr;
	sai_status_t status;

	attr.id = SAI_PORT_ATTR_SPEED;
	attr.value.u32 = speed;
	status = port_api->set_port_attribute(port_id, &attr);
	if (status != SAI_STATUS_SUCCESS)
		return sai_status_to_errno(status);

	attr.id = SAI_PORT_ATTR_AUTO_NEG_MODE;
	attr.value.booldata = (autoneg == AUTONEG_ENABLE) ? true : false;
	status = port_api->set_port_attribute(port_id, &attr);

	return sai_status_to_errno(status);
}

int clsw_sai_port_get_speed(sai_port_api_t *port_api, sai_object_id_t port_id,
			    u32 *speed, u8 *autoneg, u8 *duplex)
{
	sai_attribute_t attr[] = {
		{ .id = SAI_PORT_ATTR_SPEED },
		{ .id = SAI_PORT_ATTR_AUTO_NEG_MODE },
	};
	sai_status_t status;

	status = port_api->get_port_attribute(port_id, ARRAY_SIZE(attr), attr);
	if (status != SAI_STATUS_SUCCESS)
		return sai_status_to_errno(status);

	*speed = attr[0].value.u32;
	*autoneg = attr[1].value.booldata ? AUTONEG_ENABLE : AUTONEG_DISABLE;
	*duplex = DUPLEX_FULL;

	return 0;
}

int clsw_sai_port_set_mtu(sai_port_api_t *port_api,
			  sai_object_id_t port_id,
			  unsigned int mtu)
{
	sai_attribute_t attr = {
		.id = SAI_PORT_ATTR_MTU,
		.value.u32 = mtu,
	};
	sai_status_t status;

	status = port_api->set_port_attribute(port_id, &attr);

	return sai_status_to_errno(status);
}

int clsw_sai_port_get_stats(sai_port_api_t *port_api,
			    sai_object_id_t port_id,
			    const sai_port_stat_t *counter_ids,
			    u32 number_of_counters,
			    u64 *counters)
{
	sai_status_t status;

	status = port_api->get_port_stats(port_id, number_of_counters,
					  counter_ids, counters);

	return sai_status_to_errno(status);
}

int clsw_sai_port_get_oper_state(sai_port_api_t *port_api,
				 sai_object_id_t port_id,
				 bool *state)
{
	sai_attribute_t attr[] = {
		{ .id = SAI_PORT_ATTR_OPER_STATUS },
	};
	sai_status_t status;

	status = port_api->get_port_attribute(port_id,
					      ARRAY_SIZE(attr), attr);
	if (status != SAI_STATUS_SUCCESS)
		return sai_status_to_errno(status);

	*state = attr[0].value.booldata;

	return 0;
}

int clsw_sai_port_set_admin_state(sai_port_api_t *port_api,
				  sai_object_id_t port_id,
				  bool state)
{
	sai_attribute_t attr = {
		.id = SAI_PORT_ATTR_ADMIN_STATE,
		.value.booldata = state
	};
	sai_status_t status;

	status = port_api->set_port_attribute(port_id, &attr);

	return sai_status_to_errno(status);
}

int clsw_sai_port_set_pvid(sai_port_api_t *port_api, sai_object_id_t port_id,
			   u16 vid)
{
	sai_attribute_t attr = {
		.id = SAI_PORT_ATTR_PORT_VLAN_ID,
		.value.u16 = vid,
	};
	sai_status_t status;

	status = port_api->set_port_attribute(port_id, &attr);

	return sai_status_to_errno(status);
}

static int hostif_trap_table_entry(sai_hostif_api_t *hostif_api,
				   sai_object_id_t switch_id,
				   sai_object_id_t trap_id)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 3;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE;
	attr[0].value.s32 = SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID;

	attr[1].id = SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID;
	attr[1].value.oid = trap_id;

	attr[2].id = SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE;
	attr[2].value.s32 =
		       SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT;

	status = hostif_api->create_hostif_table_entry(&trap_id, switch_id,
						       count, attr);

	kfree(attr);

	return sai_status_to_errno(status);
}

static int hostif_config_trap(sai_hostif_api_t *hostif_api,
			      sai_object_id_t switch_id,
			      s32 trap_type)
{
	sai_object_id_t trap_id;
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 2;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE;
	attr[0].value.s32 = trap_type;

	attr[1].id = SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION;
	attr[1].value.s32 = SAI_PACKET_ACTION_TRAP;


	status = hostif_api->create_hostif_trap(&trap_id, switch_id,
						count, attr);

	kfree(attr);

	if (status != SAI_STATUS_SUCCESS) {
		pr_err("Failed to create trap for type %d: %d\n",
			trap_type, status);
		return sai_status_to_errno(status);
	}

	status = hostif_trap_table_entry(hostif_api, switch_id, trap_id);
	if (status != SAI_STATUS_SUCCESS) {
		pr_err("Failed to add trap type 0x%x to table: %d\n",
			trap_type, status);
		return sai_status_to_errno(status);
	}

	return 0;
}

int clsw_sai_hostif_config_traps(sai_hostif_api_t *hostif_api,
				 sai_object_id_t switch_id)
{
	u32 trap_types[] = {
		SAI_HOSTIF_TRAP_TYPE_LLDP,
		SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST,
		SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE,
		SAI_HOSTIF_TRAP_TYPE_IP2ME
	};
	int err;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(trap_types); ++i) {
		err = hostif_config_trap(hostif_api, switch_id, trap_types[i]);
		if (err) {
			pr_err("Failed to configure host trap, i %d type %u\n",
			       i, trap_types[i]);
			break;
		}
	}

	return err;
}

void clsw_sai_hostif_remove(sai_hostif_api_t *hostif_api,
			    sai_object_id_t hif_id)
{
	sai_status_t status;

	status = hostif_api->remove_hostif(hif_id);
	if (status != SAI_STATUS_SUCCESS) {
		pr_err("Failed to remove netdev for port %Lx: %d\n",
			hif_id, status);
	}
}

int clsw_sai_hostif_create(sai_hostif_api_t *hostif_api, sai_object_id_t swid,
			   sai_object_id_t port_id, sai_object_id_t *hif_id,
			   const char *name)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 3;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_HOSTIF_ATTR_OBJ_ID;
	attr[0].value.oid = port_id;

	attr[1].id = SAI_HOSTIF_ATTR_TYPE;
	attr[1].value.s32 = SAI_HOSTIF_TYPE_NETDEV;

	attr[2].id = SAI_HOSTIF_ATTR_NAME;
	strncpy(attr[2].value.chardata, name, SAI_HOSTIF_NAME_SIZE);

	status = hostif_api->create_hostif(hif_id, swid, count, attr);

	kfree(attr);

	if (status != SAI_STATUS_SUCCESS) {
		pr_err("Failed to create netdev for port %Lx: %d\n",
			port_id, status);
		return sai_status_to_errno(status);
	}

	return 0;
}

static int get_num_ports(sai_switch_api_t *switch_api,
			 sai_object_id_t switch_id, u16 *nports)
{
	sai_attribute_t attr = {
		.id = SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS,
	};
	sai_status_t status;
	sai_uint32_t count;

	status = switch_api->get_switch_attribute(switch_id, 1, &attr);
	if (status != SAI_STATUS_SUCCESS) {
		pr_err("get_switch_attribute(PORT_NUMBER) failed: %d",
			status);
		return sai_status_to_errno(status);
	}

	count = attr.value.u32;
	*nports = (u16) count;

	return 0;
}

int clsw_sai_get_port_info(sai_switch_api_t *switch_api,
			   sai_object_id_t switch_id,
			   sai_object_id_t **port_obj_id,
			   u16 *nports)
{
	sai_attribute_t attr = { .id = SAI_SWITCH_ATTR_PORT_LIST };
	sai_status_t status;
	int err;

	err = get_num_ports(switch_api, switch_id, nports);
	if (err)
		return err;

	*port_obj_id = kzalloc(sizeof(sai_object_id_t) * (*nports), GFP_KERNEL);
	if (!*port_obj_id) {
		pr_err("Failed to allocate memory for port object ids\n");
		return -ENOMEM;
	}

	attr.value.objlist.count = *nports;
	attr.value.objlist.list = *port_obj_id;
	status = switch_api->get_switch_attribute(switch_id, 1, &attr);
	if (status != SAI_STATUS_SUCCESS) {
		pr_err("get_switch_attribute(PORT_LIST) failed: %d\n",
			status);
		return sai_status_to_errno(status);
	}

	return 0;
}

static int sai_get_cpu_port(sai_switch_api_t *switch_api,
			    sai_object_id_t switch_id,
			    sai_object_id_t *cpu_port_id)
{
	sai_attribute_t attr = { .id = SAI_SWITCH_ATTR_CPU_PORT };
	sai_status_t status;

	status = switch_api->get_switch_attribute(switch_id, 1, &attr);
	if (status != SAI_STATUS_SUCCESS) {
		pr_err("get_switch_attribute(CPU_PORT) failed: %d\n",
		       status);
		return sai_status_to_errno(status);
	}

	*cpu_port_id = attr.value.oid;

	return 0;
}

static void sai_fdb_event_cb(uint32_t count,
			     sai_fdb_event_notification_data_t *data)
{
	switch (data->event_type) {
	case SAI_FDB_EVENT_LEARNED:
		pr_err("FDB learned event \n");
		break;
	case SAI_FDB_EVENT_AGED:
		pr_err("FDB aged event \n");
		break;
	case SAI_FDB_EVENT_MOVE:
		pr_err("FDB move event \n");
		break;
	case SAI_FDB_EVENT_FLUSHED:
		pr_err("FDB flushed event \n");
		break;
	default:
		pr_err("SAI: FDB event %x\n", data->event_type);
	}
}

int clsw_sai_get_default_vlan(sai_switch_api_t *switch_api,
			      sai_object_id_t switch_id,
			      sai_object_id_t *vlan_obj_id)
{
	sai_attribute_t attr = {
		.id = SAI_SWITCH_ATTR_DEFAULT_VLAN_ID,
	};
	sai_status_t status;

	status = switch_api->get_switch_attribute(switch_id, 1, &attr);
	if (status != SAI_STATUS_SUCCESS)
		return sai_status_to_errno(status);

	*vlan_obj_id = attr.value.oid;

	return 0;
}

static void sai_switch_state_change_cb(sai_object_id_t switch_id,
				       sai_switch_oper_status_t oper_status)
{
	const char *status_str[] = { "unknown", "up", "down", "failed" };
	const char *str = "invalid";

	if (oper_status < ARRAY_SIZE(status_str))
		str = status_str[oper_status];

	pr_warn("switch operational status changed to '%s'\n", str);
}

static int sai_create_switch(sai_switch_api_t *switch_api, char *hw_info,
			     sai_object_id_t *switch_id)
{
	sai_attribute_t *attr;
	sai_status_t status;
	int count = 6;

	attr = kzalloc(sizeof(*attr) * count, GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

	attr[0].id = SAI_SWITCH_ATTR_INIT_SWITCH;
	attr[0].value.booldata = true;

	attr[1].id = SAI_SWITCH_ATTR_SWITCH_PROFILE_ID;
	attr[1].value.u32 = 0;  // TO-DO: specify profile

	attr[2].id = SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO;
	attr[2].value.s8list.list = hw_info;

	attr[3].id = SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY;
	attr[3].value.ptr = (void *)&clsw_sai_port_state_cb;

	attr[4].id = SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY;
	attr[4].value.ptr = (void *)&sai_fdb_event_cb;

	attr[5].id = SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY;
	attr[5].value.ptr = (void *)&sai_switch_state_change_cb;

	status = switch_api->create_switch(switch_id, count, attr);

	kfree(attr);

	if (status != SAI_STATUS_SUCCESS)
		pr_err("create_switch failed: err %d\n", status);

	return sai_status_to_errno(status);
}

void clsw_sai_switch_cleanup(sai_switch_api_t *switch_api,
			     sai_object_id_t switch_id)
{
	if (switch_api && switch_id)
		switch_api->remove_switch(switch_id);
}

#define SAI_API_QUERY(n, p) { SAI_API_##n, (p), __stringify(n) }

int clsw_sai_switch_init(sai_status_t (*sai_api_query)(sai_api_t sai_api_id,
						       void **api_method_table),
			 char *hw_info, struct sai_data *data)
{
	struct sai_api_query {
		sai_api_t type;
		void **hndlr;
		const char *desc;
	} qdata[] = {
		SAI_API_QUERY(SWITCH,		(void **) &data->switch_api),
		SAI_API_QUERY(HOSTIF,		(void **) &data->hostif_api),
		SAI_API_QUERY(PORT,		(void **) &data->port_api),
		SAI_API_QUERY(VLAN,		(void **) &data->vlan_api),
		SAI_API_QUERY(BRIDGE,		(void **) &data->br_api),
		SAI_API_QUERY(ROUTER_INTERFACE,	(void **) &data->rif_api),
		SAI_API_QUERY(VIRTUAL_ROUTER,	(void **) &data->vr_api),
		SAI_API_QUERY(ROUTE,		(void **) &data->route_api),
		SAI_API_QUERY(NEXT_HOP,		(void **) &data->nh_api),
		SAI_API_QUERY(NEXT_HOP_GROUP,	(void **) &data->nh_grp_api),
		SAI_API_QUERY(NEIGHBOR,		(void **) &data->neigh_api),
	};
	sai_status_t status;
	unsigned int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(qdata); ++i) {
		status = sai_api_query(qdata[i].type, qdata[i].hndlr);
		if (status != SAI_STATUS_SUCCESS) {
			pr_err("Failed to get handler for %s API\n",
			       qdata[i].desc);
			return sai_status_to_errno(status);
		}
		if (!(*qdata[i].hndlr)) {
			pr_err("no %s api\n", qdata[i].desc);
			return -EOPNOTSUPP;
		}
	}

	err = sai_create_switch(data->switch_api, hw_info, &data->switch_id);
	if (err)
		return err;

	err = sai_get_cpu_port(data->switch_api, data->switch_id,
			       &data->cpu_port_id);
	if (err) {
		clsw_sai_switch_cleanup(data->switch_api, data->switch_id);
		return err;
	}

	return 0;
}
