#ifndef __CLSW_ROUTER_H_
#define __CLSW_ROUTER_H_

#include <linux/refcount.h>
#include <net/ip_fib.h>
#include <net/ip6_fib.h>
#include <net/neighbour.h>
#include <saineighbor.h>
#include <sairoute.h>

#define NEXTHOP_HASHBITS    8
#define NEXTHOP_HASHENTRIES (1 << NEXTHOP_HASHBITS)

struct clsw_rif;

struct clsw_neigh_key {
	struct neighbour *n;
};

struct clsw_neigh_entry {
	struct rhash_head	ht_node;
	struct list_head	nh_list; /* nexthops using this neigh entry */
	struct list_head	nh_neigh_list_node; /* node on router list */

	struct clsw_neigh_key	key;
	u64			id;
	struct clsw_rif		*rif;
	sai_neighbor_entry_t	sai_neigh_entry;
	bool			connected;
};

struct clsw_nexthop;

struct clsw_nh_grp_entry {
	struct clsw_nexthop	*nh;
	sai_object_id_t		nh_mbr_obj_id;
	u32			nh_weight;
	int			nh_upper_bound;
};

struct clsw_nh_grp {
	u8			 num_nh;
	u8			 ecmp:1,
				 unused:7;
	struct clsw_nh_grp_entry nh_list[0];
};

/* route_entry list is used to set/reset OFFLOAD in nh_flags
 * for specific route nexthops
 */
struct clsw_nh_route_entry {
	struct list_head	list;   /* link entry to nh */

	refcount_t		refcnt;
	u8			family;
	union {
		struct fib_nh	*fib_nh;
		struct fib6_nh	*fib6_nh;
	};
};

struct clsw_nh_info {
	struct list_head	fnh_list;  /* fib_nh using this nexthop */
	struct net_device	*nh_dev;
	struct clsw_rif		*rif;

	struct clsw_neigh_entry	*neigh_entry;
	struct list_head	neigh_list_node; /* links nh to neigh_entry */

	u8                      family;
	u8			has_gw:1,
				has_valid_neigh:1,
				unused:6;
	union {
		__be32		ipv4;
		struct in6_addr ipv6;
	} gw;
};

struct clsw_nexthop {
	u64			id;
	struct hlist_node       hlist;    /* node for nexthop hash */
	struct list_head	fe_list;  /* list of fib_entries using nh */
	refcount_t		refcnt;

	u32			group:1,
				dead:1,
				ignore:1,
				offloaded:1,
				rem_offload:1,
				unused:27;

	sai_object_id_t		nh_obj_id;

	union {
		struct clsw_nh_info nh_info;
		struct clsw_nh_grp  nh_grp;
	};
};

/* used for hash index. dev index is an int; can never be 0xFFFFFFFF */
#define NEXTHOP_GROUP_INDEX	0xFFFFFFFF

static inline bool clsw_nh_is_group(const struct clsw_nexthop *nh)
{
	return nh->group;
}

static inline bool clsw_nh_is_dead(const struct clsw_nexthop *nh)
{
	return nh->dead;
}

static inline bool clsw_nh_is_offloaded(const struct clsw_nexthop *nh)
{
	return nh->offloaded;
}

static inline bool clsw_nh_rem_offload(const struct clsw_nexthop *nh)
{
	return nh->rem_offload;
}

struct clsw_fib_key {
	unsigned char	addr[sizeof(struct in6_addr)];
	unsigned char	plen;
};

struct clsw_vr;

struct clsw_fib {
	struct rhashtable ht;
	struct list_head  node_list;
	struct clsw_vr	  *vr;
	u8		  family;
};

struct clsw_fib_node {
	u64			id;
	struct rhash_head	ht_node;
	struct list_head	entry_list; /* fib_entry */
	struct list_head	list;       /* linking to fib node_list */
	struct clsw_fib		*fib;       /* fib this node is in */
	struct clsw_fib_key	key;
};

struct clsw_fib_entry {
	struct list_head node_list;	/* fib_node entry_list */
	struct list_head nh_list;	/* linked to nh fe_list */

	u64	id;
	u32	prio;
	u8	tos;
	u8	type;
	u8	offloaded:1,
		skip_offload:1,
		unused:6;

	struct clsw_fib_node	*fib_node;
	struct clsw_vr		*vr;
	struct clsw_nexthop	*nh;

	/* nh_obj_id is a nexthop object, nexthop group object, router
	 * interface (directly attached routes), or port object (e.g., cpu
	 * port for local host routes)
	 */
	sai_object_id_t		nh_obj_id;
	sai_route_entry_t	route_entry;
};

struct clsw_vr {
	u16 id;		/* virtual router ID */
	u32 tb_id;	/* kernel FIB table id */

	struct clsw_fib	*fib4;  /* ipv4 fib_nodes and entries for this table */
	struct clsw_fib	*fib6;  /* ipv6 fib nodes and fib entries */

	refcount_t refcnt;    /* number of rifs referencing it */
	sai_object_id_t vr_obj_id;
};

enum clsw_rif_type {
	CLSW_RIF_TYPE_NONE,
	CLSW_RIF_TYPE_PORT,
	CLSW_RIF_TYPE_PORT_VLAN,
	CLSW_RIF_TYPE_VLAN,
	CLSW_RIF_TYPE_BRIDGE,
	CLSW_RIF_TYPE_MAX,
};

struct clsw_router;

struct clsw_rif {
	struct net_device	*dev;
	struct clsw_router	*router;
	struct clsw_vr		*vr;

	enum clsw_rif_type	rif_type;
	u16			rif_index;
	unsigned char		addr[ETH_ALEN];

	sai_object_id_t		rif_obj_id;
	// TO-DO: do these references need to be saved?
	sai_object_id_t		port_obj_id;
	sai_object_id_t		vlan_obj_id;
};

struct clsw_rif_params {
	struct net_device	*dev;
	u16			vid;
	enum clsw_rif_type	rif_type;
	void			*priv;    /* depends on rif_type */
};

struct clsw_router {
	struct rhashtable	neigh_ht;
	struct list_head	nh_neigh_list;  /* used to keep neigh active */
	struct {
		struct delayed_work dw;
		unsigned long	interval; /* ms */
	} neigh_update;
	struct delayed_work	nh_probe_dw;
#define CLSW_UNRESOLVED_NH_PROBE_INTERVAL 5000 /* ms */

	u16 max_rifs;
	u16 max_vrs;

	bool aborted;

	/* rifs and vrs as an array since some drivers (mlxsw) use
	 * the index for hardware commands
	 */
	struct clsw_rif		**rifs;
	struct clsw_vr		*vrs;

	struct hlist_head	*nexthop_head;

	struct notifier_block dev_nb;
	struct notifier_block fib_nb;
	struct notifier_block netevent_nb;
	struct notifier_block inetaddr_nb;
	struct notifier_block inetaddr_valid_nb;
	struct notifier_block in6addr_nb;
	struct notifier_block in6addr_valid_nb;
};

void clsw_nh_update_state(struct clsw_router *router,
			  struct net_device *dev, bool up);
#endif
