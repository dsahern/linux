// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include "bpf/libbpf.h"
#include <bpf/bpf.h>

struct xdp_stats {
	__u64 rx;
	__u64 tx;
	__u64 dropped;
	__u64 skipped;
	__u64 l3_dev;
	__u64 fib_dev;
};

static unsigned int ncpus;

static unsigned int get_possible_cpus(void)
{
	static unsigned int result;
	char buf[128];
	long n;
	char *ptr;
	int fd;

	if (result)
		return result;

	fd = open("/sys/devices/system/cpu/possible", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "can't open sysfs possible cpus");
		exit(-1);
	}

	n = read(fd, buf, sizeof(buf));
	if (n < 2) {
		fprintf(stderr, "can't read sysfs possible cpus");
		exit(-1);
	}
	close(fd);

	if (n == sizeof(buf)) {
		fprintf(stderr, "read sysfs possible cpus overflow");
		exit(-1);
	}

	ptr = buf;
	n = 0;
	while (*ptr && *ptr != '\n') {
		unsigned int a, b;

		if (sscanf(ptr, "%u-%u", &a, &b) == 2) {
			n += b - a + 1;

			ptr = strchr(ptr, '-') + 1;
		} else if (sscanf(ptr, "%u", &a) == 1) {
			n++;
		} else {
			exit(1);
		}

		while (isdigit(*ptr))
			ptr++;
		if (*ptr == ',')
			ptr++;
	}

	result = n;

	return result;
}

static char *timestamp(void)
{
	static char timebuf[64];
	time_t now;

	now = time(NULL);
	if (strftime(timebuf, 64, "%T", localtime(&now)) == 0) {
		memset(timebuf, 0, 64);
		strncpy(timebuf, "00:00:00", 63);
	}

	return timebuf;
}

static void show_stats_entry(__u32 idx, void *value)
{
	struct xdp_stats sum = {}, *entry = value, none = {};
	unsigned int i;

	for (i = 0; i < ncpus; ++i) {
		sum.rx += entry->rx;
		sum.tx += entry->tx;
		sum.dropped += entry->dropped;
		sum.skipped += entry->skipped;
		sum.l3_dev += entry->l3_dev;
		sum.fib_dev += entry->fib_dev;

		entry += 1;
	}

	if (!memcmp(&none, &sum, sizeof(none)))
		return;

	printf("index %2u: %8llu   %8llu   %8llu   %8llu   %8llu   %8llu\n",
	       idx, sum.rx, sum.tx, sum.dropped, sum.skipped,
	       sum.l3_dev, sum.fib_dev);
}

static void *value;

static void show_stats(int fd)
{
	__u32 key, prev_key = 0;

	if (!value)
		value = malloc(sizeof(struct xdp_stats) * ncpus);
	if (!value)
		exit(1);

	printf("\n%s: %8s   %8s   %8s   %8s   %8s   %8s\n",
	       timestamp(), "rx", "tx", "dropped", "skipped",
	       "l3_dev", "fib_dev");
	while (1) {
		int err;

		err = bpf_map_get_next_key(fd, &prev_key, &key);
		if (err)
			return;

		if (!bpf_map_lookup_elem(fd, &key, value))
			show_stats_entry(key, value);

		prev_key = key;
	}
}

static int do_attach(int idx, int fd, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, fd, 0);
	if (err < 0)
		printf("ERROR: failed to attach program to %s\n", name);

	return err;
}

static int do_detach(int idx, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, -1, 0);
	if (err < 0)
		printf("ERROR: failed to detach program from %s\n", name);

	return err;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] interface-list\n"
		"\nOPTS:\n"
		"    -d           detach program\n"
		"    -D           direct table lookups (skip fib rules)\n"
		"    -t interval  stats interval\n",
		prog);
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	int prog_fd, devmap_fd = -1, idxmap_fd = -1, map_fd;
	const char *prog_name = "xdp_fwd";
	struct bpf_program *prog;
	char filename[PATH_MAX];
	struct bpf_object *obj;
	int stats_interval = 0;
	int opt, i, idx, err;
	struct bpf_map *map;
	int attach = 1;
	int ret = 0;

	while ((opt = getopt(argc, argv, ":dDt:")) != -1) {
		switch (opt) {
		case 'd':
			attach = 0;
			break;
		case 'D':
			prog_name = "xdp_fwd_direct";
			break;
		case 't':
			stats_interval = atoi(optarg);
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	if (attach) {
		snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
		prog_load_attr.file = filename;

		if (access(filename, O_RDONLY) < 0) {
			printf("error accessing file %s: %s\n",
				filename, strerror(errno));
			return 1;
		}

		if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
			return 1;

		prog = bpf_object__find_program_by_title(obj, prog_name);
		prog_fd = bpf_program__fd(prog);
		if (prog_fd < 0) {
			printf("program not found: %s\n", strerror(prog_fd));
			return 1;
		}

		map = bpf_object__find_map_by_name(obj, "tx_devmap");
		if (map)
			devmap_fd = bpf_map__fd(map);
		if (devmap_fd < 0) {
			printf("device map not found: %s\n", strerror(devmap_fd));
			return 1;
		}
		map = bpf_object__find_map_by_name(obj, "tx_idxmap");
		if (map)
			idxmap_fd = bpf_map__fd(map);
		if (idxmap_fd < 0) {
			printf("device map not found: %s\n", strerror(idxmap_fd));
			return 1;
		}
	}

	for (i = optind; i < argc; ++i) {
		idx = if_nametoindex(argv[i]);
		if (!idx)
			idx = strtoul(argv[i], NULL, 0);

		if (!idx) {
			fprintf(stderr, "Invalid arg\n");
			return 1;
		}
		if (!attach) {
			err = do_detach(idx, argv[i]);
			if (err)
				ret = err;
		} else {
			int one = 1;

			err = do_attach(idx, prog_fd, argv[i]);
			if (err)
				ret = err;
			bpf_map_update_elem(devmap_fd, &idx, &idx, 0);
			bpf_map_update_elem(idxmap_fd, &idx, &one, 0);
		}
	}

	if (ret || !stats_interval)
		return ret;

	map = bpf_object__find_map_by_name(obj, "stats_map");
	if (!map) {
		fprintf(stderr, "stats_map does not exist\n");
		return 0;
	}
#if 0
	if (map->def.key_size != sizeof(int)) {
		fprintf(stderr, "stats_map uses unexpected key length\n");
		return 0;
	}
	if (map->def.value_size != sizeof(struct xdp_stats)) {
		fprintf(stderr, "stats_map does not contain expected stats struct\n");
		return 0;
	}
#endif
	map_fd = bpf_map__fd(map);
	ncpus = get_possible_cpus();
	while (1) {
		show_stats(map_fd);
		sleep(stats_interval);
	}

	return 0;
}
