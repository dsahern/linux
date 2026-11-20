# SPDX-License-Identifier: GPL-2.0
#
# Out-of-band validators for mlx5 vfmig. Build with:
#   make -C tools/testing/criu_rdma
#   make -C tools/testing/criu_rdma probes	# also the libibverbs probes

CC	?= gcc
CFLAGS	?= -O2 -g
CFLAGS	+= -Wall -Wextra

UAPI	:= ../../../include/uapi/linux/mlx5_vfmig.h

PROGS	:= tools/mlx5_vfmig probes/vfmig_fence
VERBS_PROGS := probes/rc_pair probes/umr_release_probe probes/q_counter_room
BENCH_PROGS := tools/qp_save_bench tools/ib_objects_holder tools/ib_objects_direct
RDMA_UAPI := $(addprefix ../../../include/uapi/rdma/,ib_user_verbs.h \
	ib_user_ioctl_cmds.h ib_user_ioctl_verbs.h mlx5-abi.h \
	mlx5_user_ioctl_cmds.h rdma_user_ioctl_cmds.h)

all: $(PROGS)

probes: $(PROGS) $(VERBS_PROGS)

bench: $(BENCH_PROGS) tools/mlx5_vfmig

tools/qp_save_bench: tools/qp_save_bench.c $(UAPI)
	$(CC) $(CFLAGS) -o $@ $< -libverbs

tools/ib_objects_holder: tools/ib_objects_holder.c
	$(CC) $(CFLAGS) -o $@ $< -libverbs

tools/ib_objects_direct: tools/ib_objects_direct.c $(RDMA_UAPI)
	$(CC) $(CFLAGS) -o $@ $<

tools/mlx5_vfmig: tools/mlx5_vfmig.c $(UAPI)
	$(CC) $(CFLAGS) -o $@ $<

probes/vfmig_fence: probes/vfmig_fence.c $(UAPI)
	$(CC) $(CFLAGS) -o $@ $<

probes/rc_pair: probes/rc_pair.c
	$(CC) $(CFLAGS) -o $@ $< -libverbs

probes/umr_release_probe: probes/umr_release_probe.c $(UAPI)
	$(CC) $(CFLAGS) -o $@ $< -libverbs

probes/q_counter_room: probes/q_counter_room.c
	$(CC) $(CFLAGS) -o $@ $< -lmlx5 -libverbs

clean:
	rm -f $(PROGS) $(VERBS_PROGS) $(BENCH_PROGS)

.PHONY: all probes bench clean
