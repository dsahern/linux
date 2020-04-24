// SPDX-License-Identifier: GPL-2.0
#include <linux/if_link.h>
#include <test_progs.h>

#define IFINDEX_LO 1

void test_xdp_egress_attach(void)
{
	struct bpf_prog_load_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.expected_attach_type = BPF_XDP_EGRESS,
	};
	struct bpf_prog_info info = {};
	__u32 id, len = sizeof(info);
	struct bpf_object *obj;
	__u32 duration = 0;
	int err, fd = -1;

	/* should fail - accesses rx queue info */
	attr.file = "./test_xdp_egress_fail.o",
	err = bpf_prog_load_xattr(&attr, &obj, &fd);
	if (CHECK(err == 0 && fd >= 0, "xdp_egress with rx failed to load",
		 "load of xdp_egress with rx succeeded instead of failed"))
		return;

	attr.file = "./test_xdp_egress.o",
	err = bpf_prog_load_xattr(&attr, &obj, &fd);
	if (CHECK_FAIL(err))
		return;

	err = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (CHECK_FAIL(err))
		goto out_close;

	err = bpf_set_link_xdp_fd(IFINDEX_LO, fd, XDP_FLAGS_EGRESS_MODE);
	if (CHECK(err, "xdp attach", "xdp attach failed"))
		goto out_close;

	err = bpf_get_link_xdp_id(IFINDEX_LO, &id, XDP_FLAGS_EGRESS_MODE);
	if (CHECK(err || id != info.id, "id_check",
		  "loaded prog id %u != id %u, err %d", info.id, id, err))
		goto out;

out:
	err = bpf_set_link_xdp_fd(IFINDEX_LO, -1, XDP_FLAGS_EGRESS_MODE);
	if (CHECK(err, "xdp detach", "xdp detach failed"))
		goto out_close;

	err = bpf_get_link_xdp_id(IFINDEX_LO, &id, XDP_FLAGS_EGRESS_MODE);
	if (CHECK(err || id, "id_check",
		  "failed to detach program %u", id))
		goto out;

out_close:
	bpf_object__close(obj);
}
