#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import argparse
from contextlib import contextmanager
import csv
import fcntl
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


HERE = Path(__file__).resolve().parent
PCI = Path('/sys/bus/pci')
DRIVER = PCI / 'drivers/mlx5_core'
OBJECTS = ('pd', 'cq', 'mr', 'qp')
SAVE_PROBES = ('rdma_capture_uobj_dag', 'rdma_emit_uobj_dag')
RESTORE_PROBES = ('rdma_collect_uobj_dag', 'rdma_restore_uobj_dag_for_ufile') + tuple(
    f'rdma_prepare_rdma_{kind}s' for kind in ('cq', 'mr', 'qp')
)
MS = 1_000_000


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def executable(name):
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f'Executable not found: {name}')
    return Path(path).resolve()


def wait_for(check, description, alive=lambda: True):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        if not alive():
            raise RuntimeError(f'Workload exited while waiting for {description}')
        time.sleep(0.05)
    raise RuntimeError(f'Timed out waiting for {description}')


def read_status(path):
    try:
        return path.read_text().strip()
    except FileNotFoundError:
        return ''


class VF:
    def __init__(self, pf, index, path):
        self.path = path
        self.base = [HERE / 'mlx5_vfmig', pf]
        self.index = str(index)
        self.driver = path / 'driver'
        self.override = path / 'driver_override'
        self.original_override = self.override.read_text().strip()
        if self.original_override not in ('', '(null)', 'mlx5_core'):
            raise RuntimeError(f'{path.name} has driver_override={self.original_override}')
        self.was_bound = self.driver.is_symlink()
        if self.was_bound and self.driver.resolve() != DRIVER:
            raise RuntimeError(f'{path.name} is bound to an unexpected driver')
        domain = (path / 'iommu_group/type').read_text().strip()
        if domain not in ('DMA', 'DMA-FQ'):
            raise RuntimeError(f'{path.name} needs a DMA IOMMU domain, found {domain}')
        state = self.ioctl('query_vf', capture_output=True).stdout.split()
        expected = {'vf_uuid=<unset>', 'restored=0', 'tracked=0', f'bound={int(self.was_bound)}'}
        if not expected <= set(state):
            raise RuntimeError(f'{path.name} has unexpected migration state: {" ".join(state)}')

    def ioctl(self, verb, *args, **kwargs):
        return command([*self.base, verb, self.index, *args], **kwargs)

    def prepare(self, identity):
        self.ioctl('set_tracked', '1', stdout=subprocess.DEVNULL)
        self.ioctl('enable_migratable', stdout=subprocess.DEVNULL)
        self.ioctl('set_vf_uuid', identity, stdout=subprocess.DEVNULL)

    def bind(self):
        self.override.write_text('mlx5_core\n')
        (DRIVER / 'bind').write_text(self.path.name + '\n')

    def unbind(self):
        if self.driver.is_symlink():
            if self.driver.resolve() != DRIVER:
                raise RuntimeError(f'{self.path.name} is bound to an unexpected driver')
            (DRIVER / 'unbind').write_text(self.path.name + '\n')

    def restore_override(self):
        value = '' if self.original_override == '(null)' else self.original_override
        self.override.write_text(value + '\n')

    @contextmanager
    def detached(self):
        try:
            if self.was_bound:
                self.unbind()
            yield
        finally:
            if self.was_bound and not self.driver.is_symlink():
                try:
                    self.bind()
                finally:
                    self.restore_override()

    def up(self):
        netdev, = wait_for(lambda: list((self.path / 'net').glob('*')), 'VF netdev')
        command(['ip', 'link', 'set', 'dev', netdev.name, 'up'])

    def recycle(self, identity):
        state = self.ioctl('query_vf', capture_output=True).stdout.split()
        uuid_owned = f'vf_uuid={identity}' in state
        if not uuid_owned and 'vf_uuid=<unset>' not in state:
            raise RuntimeError(f'{self.path.name} has an unexpected UUID')
        try:
            self.unbind()
            if uuid_owned:
                self.ioctl('clear_vf_uuid', identity, stdout=subprocess.DEVNULL)
            self.ioctl('recycle_vf', stdout=subprocess.DEVNULL)
        finally:
            self.restore_override()


def trace_source(criu, restore):
    probes = [f'uprobe:{criu}:{name}' for name in (RESTORE_PROBES if restore else SAVE_PROBES)]
    if restore:
        probes += [f'kprobe:ib_uverbs_handler_UVERBS_METHOD_RESTORE_{kind.upper()}'
                   for kind in OBJECTS]
    # bpftrace's child is the launcher. CRIU restore does the ioctls
    # from its descendants, including after the PIE restorer takes over.
    program = ['''
tracepoint:sched:sched_process_fork /pid == cpid || @child[pid]/ {
    @child[args->child_pid] = 1;
}
tracepoint:sched:sched_process_exit /pid == tid && @child[pid]/ {
    delete(@child[pid]);
}
END { clear(@child); }
''']
    for index, probe in enumerate(probes):
        retprobe = probe.replace('probe:', 'retprobe:', 1)
        program.append(f'''
{probe} /pid == cpid || @child[pid]/ {{
    @start[{index}, tid] = nsecs;
}}
{retprobe} /@start[{index}, tid]/ {{
    @ns[{index}] = sum(nsecs - @start[{index}, tid]);
    @calls[{index}] = count();
    if (retval != 0) {{ @errors[{index}] = count(); }}
    delete(@start[{index}, tid]);
}}
''')
    return ''.join(program)


def read_trace(path, expected):
    values = dict(((name, int(index)), int(value)) for name, index, value in re.findall(
        r'^@(ns|calls|errors)\[(\d+)\]: (\d+)$', path.read_text(), re.MULTILINE))
    for index, count in enumerate(expected):
        calls = values.get(('calls', index), 0)
        errors = values.get(('errors', index), 0)
        if calls != count or errors or ('ns', index) not in values:
            raise RuntimeError(f'{path.name}: probe {index} recorded {calls}/{count} '
                               f'calls and {errors} failed returns')
    return [values['ns', index] for index in range(len(expected))]


def trace_criu(criu, args, work, phase, expected):
    launcher = work / f'{phase}.sh'
    result = work / f'{phase}.rc'
    trace = work / f'{phase}.trace'
    launcher.write_text('#!/bin/sh\n' + shlex.join([str(criu), *map(str, args)]) +
                        ' </dev/null\n' + f'echo "$?" > {shlex.quote(str(result))}\n')
    launcher.chmod(0o700)
    with trace.open('w') as output:
        command(['bpftrace', '-q', '-e', trace_source(criu, phase == 'restore'),
                 '-c', str(launcher)], stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.STDOUT)
    if read_status(result) != '0':
        raise RuntimeError(f'CRIU {phase} failed, exit status: {read_status(result) or "missing"}')
    return read_trace(trace, expected)


def restored_pidfd(pidfile, holder):
    pid = read_status(pidfile)
    if not pid:
        return
    try:
        fd = os.pidfd_open(int(pid))
    except ProcessLookupError:
        return
    try:
        exe = Path(f'/proc/{pid}/exe').readlink()
        if exe == holder:
            return fd
    except FileNotFoundError:
        os.close(fd)
        return
    except OSError:
        os.close(fd)
        raise
    os.close(fd)
    raise RuntimeError(f'Restored PID {pid} does not match the benchmark workload')


def stop_restored(pidfile, holder):
    fd = restored_pidfd(pidfile, holder)
    if fd is None:
        return
    try:
        poll = select.poll()
        poll.register(fd, select.POLLIN)
        signal.pidfd_send_signal(fd, signal.SIGTERM)
        if not poll.poll(5000):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            if not poll.poll(5000):
                raise RuntimeError('Restored workload did not exit')
    except ProcessLookupError:
        pass
    finally:
        os.close(fd)


def trial(args, vf, work, plugins):
    identity = str(uuid.uuid4())
    status = work / 'status'
    pidfile = work / 'restored.pid'
    holder = (HERE / 'ib_objects_holder').resolve()
    workload = None
    try:
        vf.prepare(identity)
        vf.bind()
        vf.up()
        ibdev, = wait_for(lambda: list((vf.path / 'infiniband').glob('*')), 'VF verbs device')
        with (work / 'holder.log').open('w') as log:
            workload = subprocess.Popen([holder, ibdev.name, status, str(args.qps),
                                         str(args.groups), str(args.port)],
                                        stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=subprocess.STDOUT, start_new_session=True)
        wait_for(lambda: read_status(status) == 'READY', 'READY', lambda: workload.poll() is None)
        common = ['-D', work, '-L', plugins, '--shell-job', '-v3', '--no-default-config']
        capture, emit = trace_criu(args.criu, ['dump', '-t', workload.pid, '-o', 'dump.log', *common],
                                   work, 'dump', [1, 1])
        workload.wait(timeout=30)

        vf.recycle(identity)
        vf.prepare(identity)
        with (work / 'firmware.log').open('w') as log:
            command([args.prerestore, '-D', work, '-p', args.plugin], stdout=log,
                    stderr=subprocess.STDOUT)
        vf.up()
        expected = [1] * len(RESTORE_PROBES) + [args.groups] * 3 + [args.qps]
        restore = trace_criu(args.criu, ['restore', '-d', '--pidfile', pidfile,
                                       '-o', 'restore.log', *common], work, 'restore', expected)
        fd = restored_pidfd(pidfile, holder)
        if fd is None:
            raise RuntimeError('CRIU did not leave a running restored workload')
        try:
            signal.pidfd_send_signal(fd, signal.SIGUSR1)
            poll = select.poll()
            poll.register(fd, select.POLLIN)

            def validation_status():
                value = read_status(status)
                return value if value in ('OK', 'FAILED') else None

            result = wait_for(validation_status, 'restored QP query', lambda: not poll.poll(0))
        finally:
            os.close(fd)
        if result != 'OK':
            raise RuntimeError('Restored QP validation failed')
        collect, dag, cq_prep, mr_prep, qp_prep, pd, cq, mr, qp = restore
        prep = cq_prep + mr_prep + qp_prep
        # Phase A includes RESTORE_PD. Count it only once in the total.
        return [capture + emit, capture, emit, collect + dag + prep + cq + mr + qp,
                collect, dag, prep, pd, cq, mr, qp]
    finally:
        try:
            if workload is not None and workload.poll() is None:
                workload.kill()
                workload.wait(timeout=30)
            stop_restored(pidfile, holder)
        finally:
            vf.recycle(identity)


def uverbs_node(vf):
    nodes = [Path('/dev/infiniband') / entry.name
             for entry in (vf.path / 'infiniband_verbs').glob('uverbs*')]
    if len(nodes) > 1:
        raise RuntimeError(f'Multiple uverbs devices on {vf.path.name}')
    return next((node for node in nodes if node.exists()), None)


def worker_result(worker, state, count):
    if not select.select([worker.stdout], [], [], 120)[0]:
        raise RuntimeError(f'Timed out waiting for direct verbs worker ({state})')
    return parse_worker_result(worker.stdout.readline(), state, count)


def parse_worker_result(line, state, count):
    fields = line.split()
    if len(fields) != count + 1 or fields[0] != state:
        raise RuntimeError(f'Direct verbs worker did not report {state}, see holder.log')
    return [int(value) for value in fields[1:]]


def direct_trial(args, vf, work):
    identity = str(uuid.uuid4())
    blob = work / 'vf.blob'
    worker = None
    try:
        vf.prepare(identity)
        vf.bind()
        source = wait_for(lambda: uverbs_node(vf), 'source uverbs device')
        with (work / 'holder.log').open('w') as log:
            worker = subprocess.Popen([HERE / 'ib_objects_direct', source, str(args.qps),
                                       str(args.groups), str(args.port)], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=log, text=True)
        save = worker_result(worker, 'READY', 1)
        with (work / 'firmware.log').open('w') as log:
            vf.ioctl('save_vhca_state', blob, stdout=log, stderr=subprocess.STDOUT)
            worker.stdin.write('CLOSE\n')
            worker.stdin.flush()
            worker_result(worker, 'CLOSED', 0)
            vf.recycle(identity)
            vf.prepare(identity)
            vf.ioctl('load_vhca_state', blob, stdout=log, stderr=subprocess.STDOUT)
        vf.bind()
        dest = wait_for(lambda: uverbs_node(vf), 'destination uverbs device')
        output, _ = worker.communicate(f'{dest}\n', timeout=120)
        if worker.returncode:
            raise RuntimeError(f'Direct verbs worker exited with {worker.returncode}, see holder.log')
        return save + parse_worker_result(output, 'OK', 5)
    finally:
        try:
            if worker is not None:
                if worker.poll() is None:
                    worker.kill()
                worker.wait(timeout=30)
                worker.stdin.close()
                worker.stdout.close()
        finally:
            vf.recycle(identity)


def main():
    parser = argparse.ArgumentParser(description='Stress mlx5 IB object save and restore on one VF')
    parser.add_argument('pf', help='PCI BDF of the PF')
    parser.add_argument('vf', type=int, help='index of an existing dedicated mlx5 VF')
    parser.add_argument('--qps', type=int, default=1000)
    parser.add_argument('--groups', type=int, default=1, help='number of PD/CQ/MR sets')
    parser.add_argument('--iterations', type=int, default=10)
    parser.add_argument('--port', type=int, default=1)
    parser.add_argument('--direct', action='store_true', help='issue the uverbs commands directly')
    parser.add_argument('--criu', default='criu')
    parser.add_argument('--prerestore', default='mlx5_vfmig_restore_vf')
    parser.add_argument('--plugin', type=Path, default=Path('/usr/local/lib/criu/rdma_mlx5_vfmig_plugin.so'))
    args = parser.parse_args()
    if (not re.fullmatch(r'[\da-fA-F]{4}:[\da-fA-F]{2}:[\da-fA-F]{2}\.[0-7]', args.pf)
            or not 0 <= args.vf <= 65535 or not 1 <= args.groups <= args.qps <= 2**32 - 1
            or args.iterations < 1 or not 1 <= args.port <= 255):
        parser.error('Invalid PF BDF, VF index, count, or port')
    if os.geteuid() != 0:
        parser.error('Run as root for VF management')
    executable(HERE / 'mlx5_vfmig')
    if args.direct:
        executable(HERE / 'ib_objects_direct')
    else:
        args.criu = executable(args.criu)
        args.prerestore = executable(args.prerestore)
        for name in ('bpftrace', 'ip', HERE / 'ib_objects_holder'):
            executable(name)
        args.plugin = args.plugin.resolve(strict=True)
    vf_path = (PCI / 'devices' / args.pf / f'virtfn{args.vf}').resolve(strict=True)
    if not (Path('/dev/mlx5_vfmig') / args.pf).exists():
        raise RuntimeError(f'No mlx5_vfmig device node for {args.pf}')

    with open(f'/run/lock/ib_objects_bench-{vf_path.name}', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        vf = VF(args.pf, args.vf, vf_path)
        work = Path(tempfile.mkdtemp(prefix='ib-objects-bench-', dir='/tmp'))
        out = csv.writer(sys.stdout, lineterminator='\n')
        columns = ['iteration', 'qps', 'groups', 'save_ms']
        object_columns = ['pd_ms', 'cq_ms', 'mr_ms', 'qp_ms']
        if args.direct:
            out.writerow(columns + ['restore_ms'] + object_columns)
        else:
            plugins = work / 'plugins'
            plugins.mkdir()
            (plugins / 'rdma_mlx5_vfmig_plugin.so').symlink_to(args.plugin)
            out.writerow(columns + ['capture_ms', 'emit_ms', 'restore_ms', 'collect_ms',
                                    'dag_ms', 'prep_ms'] + object_columns)
        try:
            with vf.detached():
                for iteration in range(1, args.iterations + 1):
                    sample = work / str(iteration)
                    sample.mkdir()
                    if args.direct:
                        timings = direct_trial(args, vf, sample)
                    else:
                        timings = trial(args, vf, sample, plugins)
                    out.writerow([iteration, args.qps, args.groups,
                                  *[f'{ns / MS:.3f}' for ns in timings]])
                    sys.stdout.flush()
                    shutil.rmtree(sample)
        except BaseException:
            print(f'Failed run artifacts: {work}', file=sys.stderr)
            raise
        shutil.rmtree(work)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f'ib_objects_bench: {error}')
    except KeyboardInterrupt:
        sys.exit(130)
