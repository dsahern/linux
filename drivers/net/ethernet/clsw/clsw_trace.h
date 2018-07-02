/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM clsw

#if !defined(_CLSW_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _CLSW_TRACE_H_

#include <linux/tracepoint.h>
#include <linux/netdevice.h>
#include "router.h"

DECLARE_EVENT_CLASS(clsw_rif_event,
	TP_PROTO(struct clsw_rif *rif),

	TP_ARGS(rif),

	TP_STRUCT__entry(
		__string(	name,	rif->dev->name	)
		__field(	u16,	rif_index	)
		__field(	u32,	vr_id		)
		__field(	u64,	rif_obj_id	)
		__field(	u64,	port_obj_id	)
		__field(	u64,	vlan_obj_id	)
	),

	TP_fast_assign(
		__assign_str(name, rif->dev ? rif->dev->name : "<none>");
		__entry->rif_index = rif->rif_index;
		__entry->vr_id = rif->vr->id;
		__entry->rif_obj_id = rif->rif_obj_id;
		__entry->port_obj_id = rif->port_obj_id;
		__entry->vlan_obj_id = rif->vlan_obj_id;
	),

	TP_printk("rif %u dev %s vr %u rif_oid %Lx port_oid %Lx vlan_oid %Lx",
		  __entry->rif_index, __get_str(name), __entry->vr_id,
		  __entry->rif_obj_id, __entry->port_obj_id,
		  __entry->vlan_obj_id)
);

DEFINE_EVENT(clsw_rif_event, rif_create,
	TP_PROTO(struct clsw_rif *rif),
	TP_ARGS(rif)
);
DEFINE_EVENT(clsw_rif_event, rif_delete,
	TP_PROTO(struct clsw_rif *rif),
	TP_ARGS(rif)
);

DECLARE_EVENT_CLASS(clsw_vr_event,
	TP_PROTO(struct clsw_vr *vr),

	TP_ARGS(vr),

	TP_STRUCT__entry(
		__field(	u16,	id		)
		__field(	u32,	tb_id		)
		__field(	u64,	vr_obj_id	)
	),

	TP_fast_assign(
		__entry->id = vr->id;
		__entry->tb_id = vr->tb_id;
		__entry->vr_obj_id = vr->vr_obj_id;
	),

	TP_printk("id %u table %u vr_oid %Lx",
		  __entry->id, __entry->tb_id, __entry->vr_obj_id)
);

DEFINE_EVENT(clsw_vr_event, vr_create,
	TP_PROTO(struct clsw_vr *vr),
	TP_ARGS(vr)
);
DEFINE_EVENT(clsw_vr_event, vr_delete,
	TP_PROTO(struct clsw_vr *vr),
	TP_ARGS(vr)
);

DECLARE_EVENT_CLASS(clsw_nh_event,
	TP_PROTO(struct clsw_nexthop *nh),

	TP_ARGS(nh),

	TP_STRUCT__entry(
		__dynamic_array( char,	name,	IFNAMSIZ )
		__field(	u64,	nh_obj_id	 )
		__field(	u16,	rif_id		 )
		__field(	u32,	gw4		 )
		__array(	u8,	gw6,		16)
		__field(	bool,	group		 )
		__field(	bool,	ignore		 )
		__field(	bool,	offload		 )
		__field(	u32,	refcnt		 )
	),

	TP_fast_assign(
		__entry->refcnt    = refcount_read(&nh->refcnt);
		__entry->nh_obj_id = nh->nh_obj_id;
		__entry->ignore    = nh->ignore;
		__entry->offload   = nh->offloaded;

		if (clsw_nh_is_group(nh)) {
			__entry->group = 1;
			__assign_str(name, "<grp>");
			__entry->gw4 = 0;
			memset(__entry->gw6, 0, 16);
			__entry->rif_id = 0;
		} else {
			struct clsw_nh_info *info = &nh->nh_info;
			struct net_device *dev = info->nh_dev;
			struct clsw_rif *rif = info->rif;

			__entry->group = 0;
			__entry->rif_id = rif ? rif->rif_index: 0;
			__assign_str(name, dev ? dev->name : "<none>");

			if (info->family == AF_INET) {
				__entry->gw4 = info->gw.ipv4;
				memset(__entry->gw6, 0, 16);
			} else {
				struct in6_addr *in6;

				__entry->gw4 = 0;
				in6 = (struct in6_addr *)__entry->gw6;
				*in6 = info->gw.ipv6;
			}
		}
	),

	TP_printk("nh_oid %Lx rif %u dev %s gw %pI4 / %pI6c group %u ignore %u offload %u refcnt %u",
		  __entry->nh_obj_id, __entry->rif_id, __get_str(name),
		  &__entry->gw4, &__entry->gw6, __entry->group,
		  __entry->ignore, __entry->offload, __entry->refcnt)
);

DEFINE_EVENT(clsw_nh_event, nh_create,
	TP_PROTO(struct clsw_nexthop *nh),
	TP_ARGS(nh)
);
DEFINE_EVENT(clsw_nh_event, nh_delete,
	TP_PROTO(struct clsw_nexthop *nh),
	TP_ARGS(nh)
);
DEFINE_EVENT(clsw_nh_event, nh_update,
	TP_PROTO(struct clsw_nexthop *nh),
	TP_ARGS(nh)
);

DECLARE_EVENT_CLASS(clsw_rt_entry_event,
	TP_PROTO(struct clsw_nh_route_entry *rt_entry),

	TP_ARGS(rt_entry),

	TP_STRUCT__entry(
		__dynamic_array( char,	name,	IFNAMSIZ )
		__field(	u32,	gw4		 )
		__array(	u8,	gw6,		16)
		__field(	u32,	refcnt		 )
		__field(	bool,	offloaded	 )
	),

	TP_fast_assign(
		struct net_device *dev = NULL;
		unsigned int flags = 0;

		__entry->refcnt = refcount_read(&rt_entry->refcnt);
		if (rt_entry->family == AF_INET) {
			__entry->gw4 = rt_entry->fib_nh->nh_gw;
			memset(__entry->gw6, 0, 16);

			dev = rt_entry->fib_nh->nh_dev;
			flags = rt_entry->fib_nh->nh_flags;
		} else {
			struct in6_addr *in6;

			__entry->gw4 = 0;
			in6 = (struct in6_addr *)__entry->gw6;
			*in6 = rt_entry->fib6_nh->nh_gw;

			dev = rt_entry->fib6_nh->nh_dev;
			flags = rt_entry->fib6_nh->nh_flags;
		}

		__assign_str(name, dev ? dev->name : "<none>");
		__entry->offloaded = !!(flags & RTNH_F_OFFLOAD);
	),

	TP_printk("dev %s gw %pI4 / %pI6c offloaded %u refcnt %u",
		  __get_str(name), &__entry->gw4, &__entry->gw6,
		  __entry->offloaded, __entry->refcnt)
);

DEFINE_EVENT(clsw_rt_entry_event, rt_entry_link,
	TP_PROTO(struct clsw_nh_route_entry *rt_entry),
	TP_ARGS(rt_entry)
);
DEFINE_EVENT(clsw_rt_entry_event, rt_entry_unlink,
	TP_PROTO(struct clsw_nh_route_entry *rt_entry),
	TP_ARGS(rt_entry)
);
DEFINE_EVENT(clsw_rt_entry_event, rt_entry_update,
	TP_PROTO(struct clsw_nh_route_entry *rt_entry),
	TP_ARGS(rt_entry)
);

DECLARE_EVENT_CLASS(clsw_fib_node_event,
	TP_PROTO(struct clsw_fib_node *node),

	TP_ARGS(node),

	TP_STRUCT__entry(
		__field(	u64,	id		 )
		__field(	u32,	tbid		 )
		__field(	u32,	vrid		 )
		__field(	u32,	pfx4		 )
		__array(	u8,	pfx6,		16)
		__field(	u8,	plen		 )
	),

	TP_fast_assign(
		struct clsw_fib_key *key = &node->key;
		u8 family = node->fib->family;

		__entry->id = node->id;
		__entry->plen = key->plen;
		__entry->tbid = node->fib->vr->tb_id;
		__entry->vrid = node->fib->vr->id;

		if (family == AF_INET) {
			__entry->pfx4 = *((u32 *)key->addr);
			memset(__entry->pfx6, 0, 16);
		} else if (family == AF_INET6) {
			__entry->pfx4 = 0;
			memcpy(__entry->pfx6, key->addr, 16);
		} else {
			__entry->pfx4 = 0;
			memset(__entry->pfx6, 0, 16);
		}
	),

	TP_printk("id %Lu vr %u table %u prefix %pI4 / %pI6c plen %u",
		  __entry->id, __entry->vrid, __entry->tbid,
		  &__entry->pfx4, &__entry->pfx6, __entry->plen)
);

DEFINE_EVENT(clsw_fib_node_event, fib_node_create,
	TP_PROTO(struct clsw_fib_node *node),
	TP_ARGS(node)
);

DEFINE_EVENT(clsw_fib_node_event, fib_node_delete,
	TP_PROTO(struct clsw_fib_node *node),
	TP_ARGS(node)
);

DECLARE_EVENT_CLASS(clsw_fib_entry_event,
	TP_PROTO(struct clsw_fib_entry *fe),

	TP_ARGS(fe),

	TP_STRUCT__entry(
		__field(	u64,	id		 )
		__field(	u32,	vr_id		 )
		__field(	u32,	tbid		 )
		__field(	u32,	node_id		 )
		__field(	u64,	nh_obj_id	 )
	),

	TP_fast_assign(
		__entry->id = fe->id;
		__entry->vr_id = fe->fib_node->fib->vr->id;
		__entry->tbid = fe->fib_node->fib->vr->tb_id;
		__entry->node_id = fe->fib_node->id;
		__entry->nh_obj_id = fe->nh_obj_id;
	),

	TP_printk("id %Lu vr %u table %u fib_node %u nh_oid %Lx",
		  __entry->id, __entry->vr_id, __entry->tbid,
		  __entry->node_id, __entry->nh_obj_id)
);

DEFINE_EVENT(clsw_fib_entry_event, fib_entry_create,
	TP_PROTO(struct clsw_fib_entry *fe),
	TP_ARGS(fe)
);
DEFINE_EVENT(clsw_fib_entry_event, fib_entry_delete,
	TP_PROTO(struct clsw_fib_entry *fe),
	TP_ARGS(fe)
);
DEFINE_EVENT(clsw_fib_entry_event, fib_entry_update,
	TP_PROTO(struct clsw_fib_entry *fe),
	TP_ARGS(fe)
);

DECLARE_EVENT_CLASS(clsw_neigh_event,
	TP_PROTO(struct clsw_neigh_entry *ne),

	TP_ARGS(ne),

	TP_STRUCT__entry(
		__string(	name,	ne->key.n->dev->name	)
		__field(	u32,	key4	 )
		__array(	u8,	key6,	16)
		__array(	u8,	mac,	6)
		__field(	u16,	rif	 )
		__field(	u8,	connected )
	),

	TP_fast_assign(
		struct neighbour *n = ne->key.n;
		u8 family = n->tbl->family;

		__assign_str(name, n->dev->name);

		if (family == AF_INET) {
			__entry->key4 = *((u32 *)n->primary_key);
			memset(__entry->key6, 0, 16);
		} else if (family == AF_INET6) {
			__entry->key4 = 0;
			memcpy(__entry->key6, n->primary_key, 16);
		}
		memcpy(__entry->mac, n->ha, 6);

		__entry->rif = ne->rif ? ne->rif->rif_index : 0;
		__entry->connected = ne->connected;
	),

	TP_printk("%pI4 / %pI6c dev %s rif %u %pM connected %u",
		  &__entry->key4, &__entry->key6, __get_str(name),
		  __entry->rif, __entry->mac,
		  __entry->connected)
);

DEFINE_EVENT(clsw_neigh_event, neigh_create,
	TP_PROTO(struct clsw_neigh_entry *ne),
	TP_ARGS(ne)
);
DEFINE_EVENT(clsw_neigh_event, neigh_delete,
	TP_PROTO(struct clsw_neigh_entry *ne),
	TP_ARGS(ne)
);
DEFINE_EVENT(clsw_neigh_event, neigh_update,
	TP_PROTO(struct clsw_neigh_entry *ne),
	TP_ARGS(ne)
);
#endif /* _CLSW_TRACE_H_ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE clsw_trace
#include <trace/define_trace.h>
