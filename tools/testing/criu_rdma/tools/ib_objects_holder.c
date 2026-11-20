// SPDX-License-Identifier: GPL-2.0
/* Workload for ib_objects_bench.py. */
#include <errno.h>
#include <infiniband/verbs.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct object_group {
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_mr *mr;
};

static unsigned int parse_count(const char *value, unsigned int max)
{
	char *end;
	unsigned long num;

	errno = 0;
	num = strtoul(value, &end, 10);
	if (errno || *value < '0' || *value > '9' || *end || !num || num > max) {
		fprintf(stderr, "Invalid count: %s\n", value);
		exit(EXIT_FAILURE);
	}
	return num;
}

static void fail(const char *what)
{
	perror(what);
	exit(EXIT_FAILURE);
}

static void report(const char *path, const char *status)
{
	FILE *file = fopen(path, "w");
	int written;

	if (!file)
		fail(path);
	written = fputs(status, file);
	if (fclose(file) || written == EOF)
		fail(path);
}

int main(int argc, char **argv)
{
	struct ibv_context *ctx = NULL;
	struct ibv_device **devices;
	unsigned int nqps, ngroups, port, i;
	struct object_group *groups;
	struct ibv_qp **qps;
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned char *memory;
	sigset_t signals;
	size_t page;
	int sig;

	if (argc != 6) {
		fprintf(stderr, "Usage: %s IBDEV STATUS QPS GROUPS PORT\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (page_size <= 0)
		fail("sysconf(_SC_PAGESIZE)");
	page = page_size;
	nqps = parse_count(argv[3], UINT_MAX);
	ngroups = parse_count(argv[4], nqps);
	port = parse_count(argv[5], UINT8_MAX);
	sigemptyset(&signals);
	sigaddset(&signals, SIGUSR1);
	sigaddset(&signals, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &signals, NULL))
		fail("sigprocmask");

	devices = ibv_get_device_list(NULL);
	if (!devices)
		fail("ibv_get_device_list");
	for (i = 0; devices[i]; i++) {
		if (!strcmp(ibv_get_device_name(devices[i]), argv[1])) {
			ctx = ibv_open_device(devices[i]);
			if (!ctx)
				fail("ibv_open_device");
			break;
		}
	}
	ibv_free_device_list(devices);
	if (!ctx) {
		fprintf(stderr, "No verbs device %s\n", argv[1]);
		return EXIT_FAILURE;
	}
	groups = calloc(ngroups, sizeof(*groups));
	qps = calloc(nqps, sizeof(*qps));
	if (!groups || !qps)
		fail("calloc");
	if (ngroups > SIZE_MAX / page) {
		fprintf(stderr, "Too many MR pages\n");
		return EXIT_FAILURE;
	}
	memory = mmap(NULL, page * ngroups, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED)
		fail("mmap MR pages");
	for (i = 0; i < ngroups; i++) {
		struct object_group *group = &groups[i];

		group->pd = ibv_alloc_pd(ctx);
		if (!group->pd)
			fail("ibv_alloc_pd");
		group->cq = ibv_create_cq(ctx, 16, NULL, NULL, 0);
		if (!group->cq)
			fail("ibv_create_cq");
		memory[i * page] = 1;
		group->mr = ibv_reg_mr(group->pd, memory + i * page, page,
				       IBV_ACCESS_LOCAL_WRITE);
		if (!group->mr)
			fail("ibv_reg_mr");
	}
	for (i = 0; i < nqps; i++) {
		struct object_group *group = &groups[i % ngroups];
		struct ibv_qp_init_attr init = {
			.send_cq = group->cq,
			.recv_cq = group->cq,
			.qp_type = IBV_QPT_RC,
			.cap = {
				.max_send_wr = 16, .max_recv_wr = 16,
				.max_send_sge = 1, .max_recv_sge = 1,
			},
		};
		struct ibv_qp_attr attr = {
			.qp_state = IBV_QPS_INIT,
			.port_num = port,
		};

		qps[i] = ibv_create_qp(group->pd, &init);
		if (!qps[i])
			fail("ibv_create_qp");
		errno = ibv_modify_qp(qps[i], &attr, IBV_QP_STATE | IBV_QP_PORT |
				      IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS);
		if (errno)
			fail("ibv_modify_qp");
	}

	report(argv[2], "READY\n");
	for (;;) {
		errno = sigwait(&signals, &sig);
		if (errno)
			fail("sigwait");
		if (sig == SIGTERM)
			break;
		for (i = 0; i < nqps; i++) {
			struct ibv_qp_init_attr init = {};
			struct ibv_qp_attr attr = {};

			errno = ibv_query_qp(qps[i], &attr, IBV_QP_STATE, &init);
			if (errno || attr.qp_state != IBV_QPS_INIT) {
				fprintf(stderr, "Restored QP %u (QPN %u): state=%u error=%d\n",
					i, qps[i]->qp_num, attr.qp_state, errno);
				report(argv[2], "FAILED\n");
				return EXIT_FAILURE;
			}
		}
		report(argv[2], "OK\n");
	}
	/* Closing the process's uverbs fds releases its objects. */
	return EXIT_SUCCESS;
}
