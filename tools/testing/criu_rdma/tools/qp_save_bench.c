// SPDX-License-Identifier: GPL-2.0
/* Time whole-VF SAVE with 1000 idle RC QPs; see ../README.md. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <infiniband/verbs.h>

#include "../../../../include/uapi/linux/mlx5_vfmig.h"

#define NUM_QPS 10000
#define READ_SIZE (128 * 1024 * 1024)
#define MLX5_PCI_DRIVER "/sys/bus/pci/drivers/mlx5_core"

static int parse_uint(const char *s, unsigned int *value)
{
	char *end;
	unsigned long n;

	errno = 0;
	n = strtoul(s, &end, 10);
	if (errno || *s < '0' || *s > '9' || *end || n > UINT_MAX)
		return -1;
	*value = n;
	return 0;
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int resolve_vf(const char *pf, unsigned int vf, char *vf_path)
{
	char path[PATH_MAX];

	if (strchr(pf, '/'))
		return -1;
	if (snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/virtfn%u",
		     pf, vf) >= (int)sizeof(path) || !realpath(path, vf_path))
		return -1;
	return 0;
}

/* Refuse to time a different VF from the one owning our QPs. */
static int check_vf(const char *vf_path, const char *ibdev)
{
	char path[PATH_MAX], ib_path[PATH_MAX];

	if (strchr(ibdev, '/'))
		return -1;
	if (snprintf(path, sizeof(path), "/sys/class/infiniband/%s/device",
		     ibdev) >= (int)sizeof(path) || !realpath(path, ib_path))
		return -1;
	return strcmp(vf_path, ib_path) ? -1 : 0;
}

static int write_bdf(const char *path, const char *bdf)
{
	size_t len = strlen(bdf);
	ssize_t n;
	int fd;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		return -1;
	}
	do {
		n = write(fd, bdf, len);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		perror(path);
	else if ((size_t)n != len)
		fprintf(stderr, "%s: short write for %s\n", path, bdf);
	close(fd);
	return n >= 0 && (size_t)n == len ? 0 : -1;
}

/* Return 1 if the VF was rebound and its verbs name may have changed. */
static int enable_migration(int fd, unsigned int vf, const char *vf_path)
{
	struct mlx5_vfmig_enable_migratable arg = { .vf_id = vf };
	char path[PATH_MAX + sizeof("/driver")], driver[PATH_MAX];
	const char *bdf = strrchr(vf_path, '/') + 1;
	int err;

	/* An already-enabled VF succeeds even while bound. */
	if (!ioctl(fd, MLX5_VFMIG_IOC_ENABLE_MIGRATABLE, &arg))
		return 0;
	/* Firmware reports bad resource state as EINVAL on a probed VF. */
	if (errno != EINVAL) {
		perror("ENABLE_MIGRATABLE");
		return -1;
	}
	snprintf(path, sizeof(path), "%s/driver", vf_path);
	if (!realpath(path, driver) || strcmp(driver, MLX5_PCI_DRIVER)) {
		fprintf(stderr, "ENABLE_MIGRATABLE: %s is not bound to mlx5_core\n",
			bdf);
		return -1;
	}
	fprintf(stderr, "Rebinding VF %s to enable migration\n", bdf);
	if (write_bdf(MLX5_PCI_DRIVER "/unbind", bdf))
		return -1;

	err = ioctl(fd, MLX5_VFMIG_IOC_ENABLE_MIGRATABLE, &arg);
	if (err)
		perror("ENABLE_MIGRATABLE on unbound VF");
	/* Restore the original driver even if firmware rejected the retry. */
	if (write_bdf(MLX5_PCI_DRIVER "/bind", bdf)) {
		fprintf(stderr, "Failed to rebind VF %s to mlx5_core\n", bdf);
		return -1;
	}
	return err ? -1 : 1;
}

static int sample(int fd, unsigned int vf, unsigned int round, void *buf,
		  uint64_t *elapsed)
{
	struct mlx5_vfmig_save_state arg = { .vf_id = vf };
	uint64_t start, saved, drained, end, bytes = 0;
	ssize_t n;
	int err = 0;

	start = now_ns();
	if (ioctl(fd, MLX5_VFMIG_IOC_SAVE_VHCA_STATE, &arg)) {
		perror("SAVE_VHCA_STATE");
		return -1;
	}
	saved = now_ns();
	for (;;) {
		n = read(arg.save_fd, buf, READ_SIZE);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		bytes += n;
	}
	drained = now_ns();
	if (n < 0) {
		perror("read(save_fd)");
		err = -1;
	}
	/* flags=0: closing also unwinds SAVE's temporary suspension. */
	if (close(arg.save_fd)) {
		perror("close(save_fd)");
		err = -1;
	}
	end = now_ns();
	if (err)
		return err;
	if (bytes <= 16) {
		fprintf(stderr, "SAVE returned an empty/truncated image\n");
		return -1;
	}
	*elapsed = end - start;
	printf("%u,%u,%llu,%.3f,%.3f,%.3f,%.3f\n", round, NUM_QPS,
	       (unsigned long long)bytes, (saved - start) / 1e6,
	       (drained - saved) / 1e6, (end - drained) / 1e6,
	       *elapsed / 1e6);
	return 0;
}

int main(int argc, char **argv)
{
	struct ibv_qp *qps[NUM_QPS] = {};
	struct ibv_context *ctx = NULL;
	struct ibv_device **list = NULL;
	struct ibv_device *dev = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	unsigned int vf, iters = 10, port = 1, created = 0, i;
	uint64_t elapsed, total = 0, min = UINT64_MAX, max = 0;
	char path[PATH_MAX], vf_path[PATH_MAX];
	void *buf = NULL;
	int fd = -1, ret = EXIT_FAILURE, rebound, matches = 0;

	if (argc < 4 || argc > 6 || parse_uint(argv[2], &vf) ||
	    (argc > 4 && (parse_uint(argv[4], &iters) || !iters)) ||
	    (argc > 5 && (parse_uint(argv[5], &port) || !port || port > 255))) {
		fprintf(stderr, "usage: %s <pf-bdf> <vf-id> <vf-ibdev> [iterations=10] [port=1]\n",
			argv[0]);
		return 2;
	}
	if (resolve_vf(argv[1], vf, vf_path) || check_vf(vf_path, argv[3])) {
		fprintf(stderr, "%s is not VF %u of %s (check sysfs/device names)\n",
			argv[3], vf, argv[1]);
		return EXIT_FAILURE;
	}
	snprintf(path, sizeof(path), "/dev/mlx5_vfmig/%s", argv[1]);
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		goto out;
	}
	rebound = enable_migration(fd, vf, vf_path);
	if (rebound < 0)
		goto out;

	list = ibv_get_device_list(NULL);
	for (i = 0; list && list[i]; i++) {
		const char *name = ibv_get_device_name(list[i]);

		if (check_vf(vf_path, name))
			continue;
		if (!strcmp(name, argv[3])) {
			dev = list[i];
			matches = 1;
			break;
		}
		if (rebound) {
			dev = list[i];
			matches++;
		}
	}
	if (matches > 1) {
		fprintf(stderr, "Multiple verbs devices found on VF %u after rebind\n", vf);
		goto out;
	}
	if (!dev) {
		fprintf(stderr, "Cannot find verbs device for VF %u of %s\n", vf, argv[1]);
		goto out;
	}
	ctx = ibv_open_device(dev);
	if (!ctx) {
		fprintf(stderr, "cannot open verbs device %s\n", ibv_get_device_name(dev));
		goto out;
	}
	pd = ibv_alloc_pd(ctx);
	cq = ibv_create_cq(ctx, 16, NULL, NULL, 0);
	buf = malloc(READ_SIZE);
	if (!pd || !cq || !buf) {
		perror("allocate PD/CQ/read buffer");
		goto out;
	}
	/* Prefault the drain buffer outside the timed interval. */
	memset(buf, 0, READ_SIZE);
	while (created < NUM_QPS) {
		struct ibv_qp_init_attr init = {
			.send_cq = cq,
			.recv_cq = cq,
			.qp_type = IBV_QPT_RC,
			.cap = {
				.max_send_wr = 16, .max_recv_wr = 16,
				.max_send_sge = 1, .max_recv_sge = 1,
			},
		};
		struct ibv_qp_attr attr = {
			.qp_state = IBV_QPS_INIT,
			.port_num = port,
			.pkey_index = 0,
			.qp_access_flags = IBV_ACCESS_REMOTE_READ |
					   IBV_ACCESS_REMOTE_WRITE,
		};
		int err;

		qps[created] = ibv_create_qp(pd, &init);
		if (!qps[created]) {
			fprintf(stderr, "create QP %u/%u: %s\n", created + 1,
				NUM_QPS, strerror(errno));
			goto out;
		}
		created++;
		err = ibv_modify_qp(qps[created - 1], &attr, IBV_QP_STATE |
				    IBV_QP_PORT | IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS);
		if (err) {
			fprintf(stderr, "modify QP to INIT: %s\n", strerror(err));
			goto out;
		}
	}
	printf("# %u idle RC QPs in INIT, 16 send/recv WRs, shared CQ, one PD\n", NUM_QPS);
	printf("# Whole-VF snapshot; includes existing VF objects. No disk writes.\n");
	printf("iteration,qps,bytes,save_ms,read_ms,close_ms,total_ms\n");
	for (i = 0; i < iters; i++) {
		if (sample(fd, vf, i + 1, buf, &elapsed))
			goto out;
		total += elapsed;
		if (elapsed < min)
			min = elapsed;
		if (elapsed > max)
			max = elapsed;
	}
	printf("# total_ms: mean=%.3f min=%.3f max=%.3f samples=%u (no warmup)\n",
	       total / 1e6 / iters, min / 1e6, max / 1e6, iters);
	ret = EXIT_SUCCESS;
out:
	while (created) {
		if (ibv_destroy_qp(qps[--created])) {
			fprintf(stderr, "destroy QP failed\n");
			ret = EXIT_FAILURE;
		}
	}
	if (cq && ibv_destroy_cq(cq))
		ret = EXIT_FAILURE;
	if (pd && ibv_dealloc_pd(pd))
		ret = EXIT_FAILURE;
	if (ctx && ibv_close_device(ctx))
		ret = EXIT_FAILURE;
	if (list)
		ibv_free_device_list(list);
	if (fd >= 0)
		close(fd);
	free(buf);
	return ret;
}
