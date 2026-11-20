// SPDX-License-Identifier: GPL-2.0
/* Keep the workload's VAs alive across firmware SAVE/LOAD and replay uverbs. */
#include <errno.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "../../../../include/uapi/rdma/ib_user_verbs.h"
#include "../../../../include/uapi/rdma/ib_user_ioctl_cmds.h"
#include "../../../../include/uapi/rdma/ib_user_ioctl_verbs.h"
#include "../../../../include/uapi/rdma/mlx5-abi.h"
#include "../../../../include/uapi/rdma/mlx5_user_ioctl_cmds.h"
#include "../../../../include/uapi/rdma/rdma_user_ioctl_cmds.h"

struct group {
	uint32_t pd, cq, mr;
	struct mlx5_ib_restore_pd_req pd_blob;
	struct mlx5_ib_restore_cq_req cq_blob;
	uint32_t cqe, vector, cq_flags, lkey, rkey, access;
	uint64_t addr, length, iova;
};

struct qp {
	uint32_t handle, qpn, state, flags;
	uint64_t user_handle;
	struct mlx5_ib_restore_qp_req blob;
	struct ib_uverbs_qp_cap cap;
};

struct context_snapshot {
	struct mlx5_ib_vfmig_ucontext_meta meta;
	uint32_t *uars;
};

static void fail(const char *what)
{
	perror(what);
	exit(EXIT_FAILURE);
}

static void invalid(const char *what)
{
	fprintf(stderr, "%s\n", what);
	exit(EXIT_FAILURE);
}

static uint32_t count(const char *value, uint32_t max)
{
	char *end;
	unsigned long num;

	errno = 0;
	num = strtoul(value, &end, 10);
	if (errno || *value < '0' || *value > '9' || *end || !num || num > max)
		invalid("Invalid count or port");
	return num;
}

static uint64_t now_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		fail("clock_gettime");
	return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

static void write_cmd(int fd, void *buf, size_t len, uint32_t op,
		      size_t response_size, const char *name)
{
	struct ib_uverbs_cmd_hdr *hdr = buf;
	ssize_t ret;

	hdr->command = op;
	hdr->in_words = len / 4;
	hdr->out_words = response_size / 4;
	ret = write(fd, buf, len);
	if (ret < 0)
		fail(name);
	if ((size_t)ret != len)
		invalid("Short uverbs command write");
}

#define WRITE_CMD(fd, op, cmd, resp) \
	write_cmd(fd, &(cmd), sizeof(cmd), IB_USER_VERBS_CMD_##op, sizeof(resp), #op)

#define VALUE(id, value) \
	{ .attr_id = (id), .flags = UVERBS_ATTR_F_MANDATORY, .data = (value) }
#define POINTER(id, address, size) \
	{ .attr_id = (id), .flags = UVERBS_ATTR_F_MANDATORY, \
	  .data = (uintptr_t)(address), .len = (size) }
#define PTR(id, value) POINTER(id, &(value), sizeof(value))

/* Small PTR_IN attributes are inline, including FLAGS and CONST. */
static struct ib_uverbs_attr input_attr(uint16_t id, const void *value, size_t len)
{
	struct ib_uverbs_attr attr = {
		.attr_id = id, .flags = UVERBS_ATTR_F_MANDATORY, .len = len,
	};

	if (len <= sizeof(attr.data))
		memcpy(&attr.data, value, len);
	else
		attr.data = (uintptr_t)value;
	return attr;
}

#define INPUT(id, value) input_attr(id, &(value), sizeof(value))

static void ioctl_cmd(int fd, uint16_t object, uint16_t method,
		      const struct ib_uverbs_attr *attrs, size_t num, const char *name)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[12];
	} cmd = {};

	if (num > sizeof(cmd.attrs) / sizeof(cmd.attrs[0]))
		invalid("Too many uverbs attributes");
	cmd.hdr.length = sizeof(cmd.hdr) + num * sizeof(*attrs);
	cmd.hdr.num_attrs = num;
	cmd.hdr.object_id = object;
	cmd.hdr.method_id = method;
	cmd.hdr.driver_id = RDMA_DRIVER_MLX5;
	memcpy(cmd.attrs, attrs, num * sizeof(*attrs));
	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		fail(name);
}

#define EXEC(fd, object, method, ...) \
	ioctl_cmd(fd, object, method, (struct ib_uverbs_attr[]){ __VA_ARGS__ }, \
		  sizeof((struct ib_uverbs_attr[]){ __VA_ARGS__ }) / \
		  sizeof(struct ib_uverbs_attr), #method)

static int open_context(const char *path, const struct mlx5_ib_vfmig_ucontext_meta *meta)
{
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_get_context core;
		struct mlx5_ib_alloc_ucontext_req_v2 mlx5;
	} cmd = {};
	struct {
		struct ib_uverbs_get_context_resp core;
		struct mlx5_ib_alloc_ucontext_resp mlx5;
	} resp = {};
	int fd;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		fail(path);

	cmd.core.response = (uintptr_t)&resp;
	cmd.mlx5.total_num_bfregs = 2;
	/* Use CQE v0, which does not require a userspace QP index table. */
	cmd.mlx5.lib_caps = MLX5_LIB_CAP_4K_UAR;
	if (meta) {
		/* Match the source request, before mlx5 adds dynamic BFREGs. */
		cmd.mlx5.flags = MLX5_IB_ALLOC_UCTX_VFMIG_RESTORE;
		if (meta->flags & MLX5_IB_VFMIG_UCTX_META_F_TDN) {
			cmd.mlx5.flags |= MLX5_IB_ALLOC_UCTX_VFMIG_ADOPT_TD;
			cmd.mlx5.vfmig_tdn = meta->tdn;
			cmd.mlx5.vfmig_td_uid = meta->td_uid;
		}
	}
	WRITE_CMD(fd, GET_CONTEXT, cmd, resp);
	close(resp.core.async_fd);
	return fd;
}

static void create_group(int fd, struct group *g, char *cq_buf, char *cq_db,
			 char *mr_buf, size_t page)
{
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_alloc_pd core;
	} pd = {};
	struct {
		struct ib_uverbs_alloc_pd_resp core;
		struct mlx5_ib_alloc_pd_resp mlx5;
	} pd_resp = {};
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_create_cq core;
		struct mlx5_ib_create_cq mlx5;
	} cq = {};
	struct {
		struct ib_uverbs_create_cq_resp core;
		struct mlx5_ib_create_cq_resp mlx5;
	} cq_resp = {};
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_reg_mr core;
	} mr = {};
	struct ib_uverbs_reg_mr_resp mr_resp = {};

	pd.core.response = (uintptr_t)&pd_resp;
	WRITE_CMD(fd, ALLOC_PD, pd, pd_resp);
	g->pd = pd_resp.core.pd_handle;

	cq.core.response = (uintptr_t)&cq_resp;
	cq.core.cqe = 16;
	cq.core.comp_channel = -1;
	cq.mlx5.buf_addr = (uintptr_t)cq_buf;
	cq.mlx5.db_addr = (uintptr_t)cq_db;
	cq.mlx5.cqe_size = 64;
	WRITE_CMD(fd, CREATE_CQ, cq, cq_resp);
	g->cq = cq_resp.core.cq_handle;

	mr.core.response = (uintptr_t)&mr_resp;
	mr.core.start = (uintptr_t)mr_buf;
	mr.core.hca_va = mr.core.start;
	mr.core.length = page;
	mr.core.pd_handle = g->pd;
	mr.core.access_flags = IB_UVERBS_ACCESS_LOCAL_WRITE;
	WRITE_CMD(fd, REG_MR, mr, mr_resp);
	g->mr = mr_resp.mr_handle;
}

static void create_qp(int fd, struct qp *qp, const struct group *g,
		      char *buf, char *db, uint8_t port)
{
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_create_qp core;
		struct mlx5_ib_create_qp mlx5;
	} cmd = {};
	struct {
		struct ib_uverbs_create_qp_resp core;
		struct mlx5_ib_create_qp_resp mlx5;
	} resp = {};
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_modify_qp core;
	} modify = {};

	cmd.core.response = (uintptr_t)&resp;
	cmd.core.pd_handle = g->pd;
	cmd.core.send_cq_handle = g->cq;
	cmd.core.recv_cq_handle = g->cq;
	cmd.core.qp_type = IB_UVERBS_QPT_RC;
	cmd.core.max_send_wr = 16;
	cmd.core.max_recv_wr = 16;
	cmd.core.max_send_sge = 1;
	cmd.core.max_recv_sge = 1;
	cmd.mlx5.buf_addr = (uintptr_t)buf;
	cmd.mlx5.db_addr = (uintptr_t)db;
	/* 16 receive WQEs and enough 64-byte send blocks for 16 RC WRs. */
	cmd.mlx5.rq_wqe_count = 16;
	cmd.mlx5.rq_wqe_shift = 4;
	cmd.mlx5.sq_wqe_count = 32;
	cmd.mlx5.uidx = 0xffffff;
	WRITE_CMD(fd, CREATE_QP, cmd, resp);

	qp->handle = resp.core.qp_handle;
	qp->qpn = resp.core.qpn;
	qp->cap = (struct ib_uverbs_qp_cap) {
		resp.core.max_send_wr, resp.core.max_recv_wr,
		resp.core.max_send_sge, resp.core.max_recv_sge, resp.core.max_inline_data,
	};
	modify.core.qp_handle = qp->handle;
	modify.core.qp_state = IBV_QPS_INIT;
	modify.core.port_num = port;
	modify.core.attr_mask = IBV_QP_STATE | IBV_QP_PORT |
				IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS;
	write_cmd(fd, &modify, sizeof(modify), IB_USER_VERBS_CMD_MODIFY_QP, 0, "MODIFY_QP");
}

static uint32_t query_state(int fd, uint32_t handle)
{
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_query_qp core;
	} cmd = {};
	struct ib_uverbs_query_qp_resp resp = {};

	cmd.core.response = (uintptr_t)&resp;
	cmd.core.qp_handle = handle;
	cmd.core.attr_mask = IBV_QP_STATE;
	WRITE_CMD(fd, QUERY_QP, cmd, resp);
	return resp.qp_state;
}

static void capture_context(int fd, struct context_snapshot *snapshot)
{
	size_t len;

	EXEC(fd, MLX5_IB_OBJECT_VFMIG, MLX5_IB_METHOD_VFMIG_QUERY_UCONTEXT,
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_META, snapshot->meta));
	if (!snapshot->meta.num_sys_pages ||
	    snapshot->meta.num_sys_pages > UINT16_MAX / sizeof(*snapshot->uars))
		invalid("Invalid static UAR table size");
	len = snapshot->meta.num_sys_pages * sizeof(*snapshot->uars);
	snapshot->uars = malloc(len);
	if (!snapshot->uars)
		fail("UAR table allocation");
	EXEC(fd, MLX5_IB_OBJECT_VFMIG, MLX5_IB_METHOD_VFMIG_QUERY_UCONTEXT,
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_META, snapshot->meta),
	     POINTER(MLX5_IB_ATTR_VFMIG_QUERY_UCONTEXT_UAR_TABLE, snapshot->uars, len));
}

static void capture_group(int fd, struct group *g)
{
	uint32_t uid;

	EXEC(fd, MLX5_IB_OBJECT_VFMIG, MLX5_IB_METHOD_VFMIG_QUERY_PD,
	     VALUE(MLX5_IB_ATTR_VFMIG_QUERY_PD_HANDLE, g->pd),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_PD_RESP_BLOB, g->pd_blob),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_PD_RESP_UID, uid));
	if (uid)
		invalid("Unexpected DEVX-owned PD");
	EXEC(fd, MLX5_IB_OBJECT_VFMIG, MLX5_IB_METHOD_VFMIG_QUERY_CQ,
	     VALUE(MLX5_IB_ATTR_VFMIG_QUERY_CQ_HANDLE, g->cq),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_BLOB, g->cq_blob),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_CQE, g->cqe),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_COMP_VECTOR, g->vector),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_CQ_RESP_FLAGS, g->cq_flags));
	EXEC(fd, UVERBS_OBJECT_MR, UVERBS_METHOD_QUERY_MR,
	     VALUE(UVERBS_ATTR_QUERY_MR_HANDLE, g->mr),
	     PTR(UVERBS_ATTR_QUERY_MR_RESP_LKEY, g->lkey),
	     PTR(UVERBS_ATTR_QUERY_MR_RESP_RKEY, g->rkey),
	     PTR(UVERBS_ATTR_QUERY_MR_RESP_LENGTH, g->length),
	     PTR(UVERBS_ATTR_QUERY_MR_RESP_IOVA, g->iova),
	     PTR(UVERBS_ATTR_QUERY_MR_RESP_USER_ADDR, g->addr),
	     PTR(UVERBS_ATTR_QUERY_MR_RESP_ACCESS_FLAGS, g->access));
}

static void capture_qp(int fd, struct qp *qp)
{
	EXEC(fd, MLX5_IB_OBJECT_VFMIG, MLX5_IB_METHOD_VFMIG_QUERY_QP,
	     VALUE(MLX5_IB_ATTR_VFMIG_QUERY_QP_HANDLE, qp->handle),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_BLOB, qp->blob),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_USER_HANDLE, qp->user_handle),
	     PTR(MLX5_IB_ATTR_VFMIG_QUERY_QP_RESP_CREATE_FLAGS, qp->flags));
	qp->state = query_state(fd, qp->handle);
	if (qp->state != IBV_QPS_INIT || qp->blob.qpn != qp->qpn)
		invalid("Unexpected source QP state or QPN");
}

static void restore_pd(int fd, const struct group *g)
{
	EXEC(fd, UVERBS_OBJECT_RESTORE, UVERBS_METHOD_RESTORE_PD,
	     INPUT(UVERBS_ATTR_RESTORE_PD_HANDLE, g->pd),
	     PTR(UVERBS_ATTR_UHW_IN, g->pd_blob));
}

static void restore_cq(int fd, const struct group *g)
{
	uint64_t user_handle = 0;
	uint32_t cqe = 0;

	EXEC(fd, UVERBS_OBJECT_RESTORE, UVERBS_METHOD_RESTORE_CQ,
	     INPUT(UVERBS_ATTR_RESTORE_CQ_HANDLE, g->cq),
	     INPUT(UVERBS_ATTR_RESTORE_CQ_CQE, g->cqe),
	     INPUT(UVERBS_ATTR_RESTORE_CQ_USER_HANDLE, user_handle),
	     INPUT(UVERBS_ATTR_RESTORE_CQ_COMP_VECTOR, g->vector),
	     INPUT(UVERBS_ATTR_RESTORE_CQ_FLAGS, g->cq_flags),
	     PTR(UVERBS_ATTR_RESTORE_CQ_RESP_CQE, cqe),
	     PTR(UVERBS_ATTR_UHW_IN, g->cq_blob));
	if (cqe != g->cqe)
		invalid("Restored CQ capacity does not match source");
}

static void restore_mr(int fd, const struct group *g)
{
	struct mlx5_ib_restore_mr_req blob = { .mkey_index = g->lkey >> 8 };
	uint32_t lkey = 0, rkey = 0;

	EXEC(fd, UVERBS_OBJECT_RESTORE, UVERBS_METHOD_RESTORE_MR,
	     INPUT(UVERBS_ATTR_RESTORE_MR_HANDLE, g->mr),
	     VALUE(UVERBS_ATTR_RESTORE_MR_PD_HANDLE, g->pd),
	     INPUT(UVERBS_ATTR_RESTORE_MR_ADDR, g->addr),
	     INPUT(UVERBS_ATTR_RESTORE_MR_LENGTH, g->length),
	     INPUT(UVERBS_ATTR_RESTORE_MR_IOVA, g->iova),
	     INPUT(UVERBS_ATTR_RESTORE_MR_ACCESS_FLAGS, g->access),
	     INPUT(UVERBS_ATTR_RESTORE_MR_LKEY_HINT, g->lkey),
	     INPUT(UVERBS_ATTR_RESTORE_MR_RKEY_HINT, g->rkey),
	     PTR(UVERBS_ATTR_RESTORE_MR_RESP_LKEY, lkey),
	     PTR(UVERBS_ATTR_RESTORE_MR_RESP_RKEY, rkey),
	     PTR(UVERBS_ATTR_UHW_IN, blob));
	if (lkey != g->lkey || rkey != g->rkey)
		invalid("Restored MR keys do not match source");
}

static void restore_qp(int fd, const struct qp *qp, const struct group *g)
{
	uint64_t type = IB_UVERBS_QPT_RC, state = qp->state;
	uint32_t qpn = 0;

	EXEC(fd, UVERBS_OBJECT_RESTORE, UVERBS_METHOD_RESTORE_QP,
	     INPUT(UVERBS_ATTR_RESTORE_QP_HANDLE, qp->handle),
	     VALUE(UVERBS_ATTR_RESTORE_QP_PD_HANDLE, g->pd),
	     VALUE(UVERBS_ATTR_RESTORE_QP_SEND_CQ_HANDLE, g->cq),
	     VALUE(UVERBS_ATTR_RESTORE_QP_RECV_CQ_HANDLE, g->cq),
	     INPUT(UVERBS_ATTR_RESTORE_QP_TYPE, type),
	     INPUT(UVERBS_ATTR_RESTORE_QP_STATE, state),
	     INPUT(UVERBS_ATTR_RESTORE_QP_USER_HANDLE, qp->user_handle),
	     PTR(UVERBS_ATTR_RESTORE_QP_CAP, qp->cap),
	     INPUT(UVERBS_ATTR_RESTORE_QP_CREATE_FLAGS, qp->flags),
	     PTR(UVERBS_ATTR_RESTORE_QP_RESP_QPN, qpn),
	     PTR(UVERBS_ATTR_UHW_IN, qp->blob));
	if (qpn != qp->qpn)
		invalid("Restored QPN does not match source");
}

int main(int argc, char **argv)
{
	struct context_snapshot snapshot = {};
	uint64_t t0, t1, t2, t3, t4;
	uint32_t nqp, ngroup, i;
	struct group *groups;
	char dest[PATH_MAX];
	size_t page, pages;
	struct qp *qps;
	char *arena;
	long size;
	int src, dst;
	uint8_t port;

	if (argc != 5)
		invalid("Usage: ib_objects_direct SOURCE_CDEV QPS GROUPS PORT");
	nqp = count(argv[2], UINT32_MAX);
	ngroup = count(argv[3], nqp);
	port = count(argv[4], UINT8_MAX);
	size = sysconf(_SC_PAGESIZE);
	if (size < 4096)
		invalid("Unsupported page size");
	page = size;
	/* One CQ/DB/MR page per group and one work queue/DB page per QP. */
	if (3ULL * ngroup + 2ULL * nqp > SIZE_MAX / page)
		invalid("Object buffers are too large");
	pages = 3 * (size_t)ngroup + 2 * (size_t)nqp;
	arena = mmap(NULL, pages * page, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (arena == MAP_FAILED)
		fail("mmap object buffers");
	groups = calloc(ngroup, sizeof(*groups));
	qps = calloc(nqp, sizeof(*qps));
	if (!groups || !qps)
		fail("allocate object metadata");

	src = open_context(argv[1], NULL);
	for (i = 0; i < ngroup; i++) {
		char *buf = arena + 3 * (size_t)i * page;

		create_group(src, &groups[i], buf, buf + page, buf + 2 * page, page);
	}
	for (i = 0; i < nqp; i++) {
		char *buf = arena + (3 * (size_t)ngroup + 2 * (size_t)i) * page;

		create_qp(src, &qps[i], &groups[i % ngroup], buf, buf + page, port);
	}

	capture_context(src, &snapshot);
	t0 = now_ns();
	for (i = 0; i < ngroup; i++)
		capture_group(src, &groups[i]);
	for (i = 0; i < nqp; i++)
		capture_qp(src, &qps[i]);
	printf("READY %" PRIu64 "\n", now_ns() - t0);
	if (fflush(stdout))
		fail("write capture result");

	/* Close source objects after SAVE while retaining their backing VAs. */
	if (!fgets(dest, sizeof(dest), stdin) || strcmp(dest, "CLOSE\n"))
		invalid("Missing source close request");
	if (close(src))
		fail("close source uverbs");
	puts("CLOSED");
	if (fflush(stdout))
		fail("write source close result");
	/* The caller recycles, loads, and binds the VF before sending its cdev. */
	if (!fgets(dest, sizeof(dest), stdin) || !strchr(dest, '\n'))
		invalid("Missing destination uverbs device");
	*strchr(dest, '\n') = '\0';
	dst = open_context(dest, &snapshot.meta);
	EXEC(dst, MLX5_IB_OBJECT_VFMIG, MLX5_IB_METHOD_VFMIG_RESTORE_UCONTEXT,
	     INPUT(MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_META, snapshot.meta),
	     input_attr(MLX5_IB_ATTR_VFMIG_RESTORE_UCONTEXT_UAR_TABLE, snapshot.uars,
		     snapshot.meta.num_sys_pages * sizeof(*snapshot.uars)));

	t0 = now_ns();
	for (i = 0; i < ngroup; i++)
		restore_pd(dst, &groups[i]);
	t1 = now_ns();
	for (i = 0; i < ngroup; i++)
		restore_cq(dst, &groups[i]);
	t2 = now_ns();
	for (i = 0; i < ngroup; i++)
		restore_mr(dst, &groups[i]);
	t3 = now_ns();
	for (i = 0; i < nqp; i++)
		restore_qp(dst, &qps[i], &groups[i % ngroup]);
	t4 = now_ns();
	for (i = 0; i < nqp; i++)
		if (query_state(dst, qps[i].handle) != qps[i].state)
			invalid("Restored QP state does not match source");

	if (close(dst))
		fail("close destination uverbs");
	printf("OK %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
	       t4 - t0, t1 - t0, t2 - t1, t3 - t2, t4 - t3);
	return EXIT_SUCCESS;
}
