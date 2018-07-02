#ifndef __CLSW_VLAN_H_
#define __CLSW_VLAN_H_

/* default vlan for ports */
#define CLSW_PORT_VLAN  1

#define CLSW_VLAN_RESVD_START 3001
#define CLSW_VLAN_RESVD_END   3500
#define CLSW_VLAN_RESVD_SLOTS (CLSW_VLAN_RESVD_END - CLSW_VLAN_RESVD_START + 1)

struct clsw_vlan {
	struct rb_node rb_node;
	refcount_t refcnt;

	u16 vid;
	bool untagged;

	sai_object_id_t vlan_obj_id;
};

struct clsw_vlan *clsw_vlan_get_default(void);
struct clsw_vlan *clsw_vlan_get(u16 vid, bool untagged);
struct clsw_vlan *clsw_vlan_get_unused(bool untagged);
void clsw_vlan_put(struct clsw_vlan *vlan);
#endif
