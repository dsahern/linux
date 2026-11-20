# tools/testing/criu_rdma -- out-of-band vfmig validators

Kernel-level harnesses for mlx5 vfmig that drive `/dev/mlx5_vfmig/<pf-bdf>`
directly, without CRIU. They isolate kernel and firmware behaviour from
the CRIU plugin and process restore.

## Build

```
make -C tools/testing/criu_rdma
```

Builds `tools/mlx5_vfmig`, a small CLI over the vfmig ioctls (see its
header comment for the verbs).

## SAVE benchmark

`tools/qp_save_bench` creates exactly 1,000 idle RC QPs in INIT on an
existing VF, sharing one PD and one CQ. Each QP has 16 send and receive
WRs and one SGE per WR. It times a whole-VF `SAVE_VHCA_STATE`, drains the
image to a reusable memory buffer, and closes the save fd. QP creation
and destruction are outside the measured interval; no image is written
to disk. Requires libibverbs headers and library to build.

```
make -C tools/testing/criu_rdma bench
```

Use an idle, dedicated VF on a PF whose firmware advertises `migration`
and `vhca_resource_manager`. Pass the VF's current verbs device name.

```sh
sudo tools/testing/criu_rdma/tools/qp_save_bench 0000:08:00.0 0 mlx5_2 10
```

Arguments are `<pf-bdf> <vf-id> <vf-ibdev> [iterations=10] [port=1]`.
The benchmark verifies the VF and calls `ENABLE_MIGRATABLE` before opening
the verbs device. An already-enabled VF can stay bound. If firmware returns
`EINVAL` on a VF bound to `mlx5_core`, the benchmark unbinds it, retries the
ioctl, and rebinds it. This interrupts the VF's network and RDMA services.
The benchmark locates the verbs device by PCI address after rebind, so it
can use the new name. Migration setup is outside the measured interval.

SAVE temporarily suspends the entire VF, including any other users' QPs.
Leave it running normally before starting; SAVE restores the suspension
steps it issued when the save fd closes.

If `ENABLE_MIGRATABLE` or SAVE fails, check the mlx5 `vfmig` messages in
the kernel log for details such as missing PF firmware capabilities.

Output has one CSV row per iteration, including image bytes and elapsed
milliseconds for the synchronous save ioctl (`save_ms`), image reads
(`read_ms`), close/resource release/resume (`close_ms`), and all three
(`total_ms`). A final line reports mean/min/max total time. All iterations
are measured, including the first; there is no warmup. The ioctl time
includes suspend, snapshot sizing, image allocation, firmware SAVE and
host-page capture. This measures all objects on the VF with 1,000 added
QPs, rather than isolated per-QP serialization or CRIU process checkpoint
time. The QPs carry no traffic and are not connected.

## IB object save and restore benchmark

`tools/ib_objects_bench.py` runs the CRIU mlx5 migration path on one host.
It holds idle RC QPs in INIT, dumps them with CRIU, recycles the VF,
loads the firmware image with `mlx5_vfmig_restore_vf`, and restores the
process with CRIU. After restore it queries every QP through its restored
verbs handle and checks that each is still in INIT.

```sh
make -C tools/testing/criu_rdma bench
sudo tools/testing/criu_rdma/tools/ib_objects_bench.py 0000:08:00.0 0 \
    --qps 1000 --groups 10 --iterations 10
```

Use an existing, idle, dedicated mlx5 Ethernet VF in a DMA IOMMU domain
with no UUID or tracked state. If the VF starts bound to `mlx5_core`,
the benchmark unbinds it before the first trial and rebinds it during
final cleanup. Each trial binds and recycles the VF in place. Rebinding
recreates the network interface and verbs device. Run as root with
bpftrace, iproute2, and matching RDMA-enabled CRIU, mlx5 plugin and
firmware prerestore helper. `--criu`, `--plugin`, and `--prerestore`
select alternate builds. The CRIU binary must retain the uobject function
symbols for uprobes, and the running kernel must expose the uverbs
RESTORE handlers to kprobes.

`--qps` defaults to 1000 and `--groups` to 1. Each group has one PD, one
CQ and one page-sized registered MR. The QPs are spread across the groups
and have 16 send and receive WRs each. Increase the group count to stress
PD, CQ and MR replay as well as QP replay. The benchmark verifies the
number of successful restore calls for each object type.

The CSV reports summed elapsed time in the instrumented functions, in
milliseconds. `save_ms` combines CRIU uobject capture and image emission.
`restore_ms` combines image collection, uobject DAG replay, preparation for
the in-process restorer, and the kernel CQ, MR and QP handlers. The PD handler
time is also reported separately and is included once via `dag_ms`.
Firmware SAVE and LOAD, VF reconfiguration, and other process checkpoint
and restore work are outside these timings. Each iteration uses fresh
images. Logs, traces, and images from a failed run are retained at the
printed path under `/tmp`.

### Direct uverbs mode

```sh
make -C tools/testing/criu_rdma bench
sudo tools/testing/criu_rdma/tools/ib_objects_bench.py 0000:08:00.0 0 \
    --direct --qps 1000 --groups 10 --iterations 10
```

`--direct` runs without CRIU, the mlx5 CRIU plugin, or bpftrace. A single
worker creates idle RC QPs in INIT, captures their PD, CQ, MR and QP state
through uverbs, and keeps their backing memory mapped across VF recycle.
After `mlx5_vfmig` saves and loads the firmware image, the worker opens
a restore-mode ucontext and uses `RESTORE_PD`, `RESTORE_CQ`, `RESTORE_MR`
and `RESTORE_QP` to adopt the loaded objects at their original handles.
It checks the restored CQ sizes, MR keys, QPNs and QP states.

In this mode `save_ms` covers the object queries and `restore_ms` covers
the four restore batches. The per-type columns report those batches
individually. The worker's monotonic clock measures elapsed time around
the batches. Ucontext setup, firmware SAVE/LOAD, and post-restore QP
queries are outside the measurements. The same dedicated VF and IOMMU
requirements apply.

## Harnesses

- `save_load/test_xvf_save_load.sh` -- SAVE on one VF, recreate the VF
  set, LOAD onto another VF of the same PF, and bind it. Reports four
  stages separately: `arena` (every VF reserves the same IOVA window),
  `replay` (HOST_PAGE records replay into the destination), `fw_load`
  (LOAD_VHCA_STATE lands on the destination vHCA) and `probe` (the
  restored VF binds without allocator drift and brings up its ib
  device). `SRC_VF=DST_VF` runs the same-slot case.

  ```
  sudo PF=0000:08:00.0 SRC_VF=0 DST_VF=1 \
      tools/testing/criu_rdma/save_load/test_xvf_save_load.sh
  ```

  The image holds only the driver's kernel buffers; user verbs objects
  and RDMA traffic are out of scope. The harness resets every VF on the
  PF, so keep any traffic peer on another PF or host.

- `save_load/test_vf_recycle.sh` -- reuses VF 0 and VF 1 for SAVE/LOAD
  for `ITERS` rounds (default 10) without SR-IOV teardown, checking each
  round that `sriov_numvfs` and the virtfn links are unchanged and, with
  `trace/reset_trace.sh`, that the vacated VF is reset exactly once and
  nothing resets either VF between LOAD and the end of the restored
  probe. Cycles: 1 sysfs FLR then LOAD into a used VF, 2 the same via
  RECYCLE_VF, 3 recycle and reload a restored VF, 4 save from the VF
  restored in the previous round, 5 as 4 with a UUID handed off every
  round. Cycle 3 fails while restored-VF teardown logs a fatal health
  event (`design/teardown_reclaim_hang.md`).

  ```
  sudo PF=0000:08:00.0 tools/testing/criu_rdma/save_load/test_vf_recycle.sh
  sudo CYCLES="2 5" ITERS=20 tools/testing/criu_rdma/save_load/test_vf_recycle.sh
  ```

## Tracing

- `trace/reset_trace.sh` -- records PCI resets (`pcie_flr` and the
  `pci_reset_*` entry points) and mlx5 HCA lifecycle commands
  (ENABLE/DISABLE/INIT/TEARDOWN_HCA), with SAVE/LOAD_VHCA_STATE as window
  markers, and fails if any hit a watched VF other than as allowed.

  ```
  sudo tools/testing/criu_rdma/trace/reset_trace.sh arm
  sudo tools/testing/criu_rdma/trace/reset_trace.sh mark flr
  ...
  sudo tools/testing/criu_rdma/trace/reset_trace.sh report \
      --pf 0000:08:00.0 --vf 0000:08:00.2 --vf 0000:08:00.3 \
      --from flr --to load --allow flr@0000:08:00.2=1 \
      --allow reset@0000:08:00.2=1
  sudo tools/testing/criu_rdma/trace/reset_trace.sh disarm
  ```

  It reads struct offsets from the tree's `vmlinux` and `mlx5_core.ko`
  with gdb, so run it from the tree the running kernel was built from.

## Probes

One-off experiments behind `design/restored_state_growth.md`, kept so the
findings there can be reproduced. They are functional only, with no timing.
They reset SR-IOV on `$PF`, so keep traffic off it. `make ... probes` also
builds the helpers that need libibverbs.

- `probes/test_ib_release.sh` -- checks `MLX5_VFMIG_RX_FENCE_F_IB_RELEASE`
  on VF 0 with `umr_release_probe`: the first MR creates mlx5_ib's UMR CQ,
  the fence raise with the flag removes it, the next MR creates it again,
  and a LIFT with the flag is refused.
- `probes/run_criu_gates.sh` -- runs the CRIU tree's hardware vfmig gates
  (`CRIU_TREE=...`, `GATES="..."`) and summarizes each one's exit code and
  kernel warnings.
- `probes/growth_split_probe.sh` -- chains SAVE/LOAD over restored
  generations with only some of the VF's auxiliary drivers bound, or with
  mlx5e unbound, suspended or down before SAVE. It prints the image growth
  per generation.
- `probes/eq_gen_probe.sh` -- records the EQs, CQs and QPs on a normal VF
  and on restored generations, to show leaked source EQs.
- `probes/eth_unbind_questions.sh` -- RC traffic between VF 0 and VF 1,
  with VF 1 in its own namespace, across an mlx5e unbind or suspend, the
  RX fence, and RECYCLE_VF.
- `probes/qp1_orphan_probe.sh` -- sends RDMA CM connects to a restored
  VF, which land on the source's QP1, and reports IOMMU faults, "bogus
  CQ" completion events and mlx5 errors in dmesg, with a control run
  against the source first. Needs `rping`.
- `probes/criu_dropeth_gate.sh` -- a CRIU dump and restore of a
  self-loop RC QP, with the source's mlx5e unbound or suspended
  (`CRIU_REPO=...`). It has since been ported to the CRIU tree as
  `run_vfmig_qp_traffic_cr.sh`.

Helpers: `probes/vfmig_fence` raises and lifts the RX fence, optionally
with `eth`. `probes/rc_pair` drives RC QP pairs between two ib devices
from stdin. `probes/q_counter_room <ibdev>` prints how many more queue
counters the device can allocate (as root, through DEVX); run on each
restored VF of a chain, it drops by one per hop while a counter leaks.

```
make -C tools/testing/criu_rdma probes
sudo PF=0000:08:00.0 tools/testing/criu_rdma/probes/test_ib_release.sh
```
