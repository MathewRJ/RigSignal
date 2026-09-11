#!/usr/bin/env python3
"""Diagnostic only: measure cgroup v2 containment, never configure delegation."""

# KNOWN LIMITS (accepted):
# NO_DELEGATION means no mkdir via own / parent / root; other writable delegated
# ancestors are not tried. Carriage returns in cgroup names mis-parse.
# The first successful mkdir is not reconsidered after placement fails (PROBE_ERROR).
# Interrupts between mkdir and registration can leak the unregistered cgroup.

import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


ROOT = Path('/sys/fs/cgroup')
FIELDS = ('pid', 'ppid', 'pgid', 'sid', 'starttime', 'state')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def snapshot(pid):
    """Return field-22 anchored identity; only explicit proc absence means gone."""
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
    except OSError:
        # Neither PermissionError nor FileNotFoundError alone proves absence.
        if str(pid) not in os.listdir('/proc'):
            return None
        raise
    # comm may contain spaces and closing parentheses.
    fields = raw[raw.rindex(')') + 2:].split()
    return dict(pid=pid, ppid=int(fields[1]), pgid=int(fields[2]),
                sid=int(fields[3]), starttime=int(fields[19]), state=fields[0])


def evidence(phase, name, current, original=None):
    values = current or dict.fromkeys(FIELDS, '-')
    if current is None:
        values['pid'] = original['pid']
        values['state'] = 'ABSENT'
    identity = ''
    if original is not None:
        same = same_identity(current, original)
        identity = (' identity=SURVIVED' if same else ' identity=GONE')
        identity += f" anchor_starttime={original['starttime']}"
    print(f"{phase}: {name} " + ' '.join(f'{k}={values[k]}' for k in FIELDS)
          + identity, flush=True)


def same_identity(current, original):
    return (current is not None and current['starttime'] == original['starttime']
            and current['state'] != 'Z')


def timeout_handler(signum, frame):
    raise RuntimeError(f'probe interrupted by signal {signum}')


class Probe:
    def __init__(self):
        self.cgroup = None
        self.children = {}

    def run(self):
        print(f'UNAME-R: {os.uname().release}', flush=True)
        mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
        if not any(row[2] == 'cgroup2' for row in mounts):
            return 'NO_CGROUP2'
        require(any(row[1] == str(ROOT) and row[2] == 'cgroup2' for row in mounts),
                'unified mount is not at /sys/fs/cgroup')
        own_entries = [line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                       if line.startswith('0::')]
        require(len(own_entries) == 1, 'expected one unified self cgroup')
        own = (ROOT / own_entries[0].lstrip('/')).resolve()
        require(own == ROOT or ROOT in own.parents, 'own cgroup escapes mount')
        print(f'OWN-CGROUP: {own}', flush=True)
        # Exactly the specified candidates; do not acquire or repair delegation.
        parent = own.parent if own != ROOT else ROOT
        for candidate in (own, parent, ROOT):
            child = candidate / f'rsprobe-{os.getpid()}'
            try:
                child.mkdir()
            except OSError as exc:
                print(f'MKDIR-ATTEMPT: {child} errno={errno.errorcode[exc.errno]}',
                      flush=True)
                # Unexpected failures are probe errors, not evidence of permissions.
                if exc.errno not in (errno.EACCES, errno.EPERM, errno.EROFS,
                                     errno.ENOENT, errno.EBUSY, errno.EOPNOTSUPP):
                    raise
            else:
                self.cgroup = child
                print(f'MKDIR-ATTEMPT: {child} errno=0', flush=True)
                break
        if self.cgroup is None:
            print('CGROUP-PATH: NONE', flush=True)
            return 'NO_DELEGATION'
        print(f'CGROUP-PATH: {self.cgroup}', flush=True)
        if 'cgroup.kill' not in os.listdir(self.cgroup):
            return 'NO_CGROUP_KILL'

        for name in ('setsid', 'setpgid', 'control', 'pgroup-control'):
            options = ({'preexec_fn': os.setpgrp} if name == 'setpgid'
                       else {'start_new_session': True})
            if name == 'pgroup-control':
                target_pgid = os.getpgid(self.children['setpgid'].pid)
                options = {'preexec_fn': lambda: os.setpgid(0, target_pgid)}
            proc = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(60)', f'rsprobe-{name}'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, **options)
            self.children[name] = proc
            if name in ('setsid', 'setpgid'):
                (self.cgroup / 'cgroup.procs').write_text(str(proc.pid))

        before = {name: snapshot(proc.pid) for name, proc in self.children.items()}
        for name, row in before.items():
            require(row is not None, f'clause 1: {name} absent before kill')
            evidence('BEFORE', name, row)
            require(row['state'] != 'Z', f'clause 1: {name} is a zombie')
            require(row['ppid'] == os.getpid(), f'{name} is not a direct child')
        print(f'PROBE-IDENTITY: pid={os.getpid()} pgid={os.getpgrp()} sid={os.getsid(0)}',
              flush=True)
        require(before['setsid']['sid'] != os.getsid(0), 'clause 1: setsid not detached')
        require(before['setpgid']['pgid'] != os.getpgrp(), 'clause 1: setpgid not detached')
        require(before['control']['sid'] != os.getsid(0), 'clause 4: control not detached')
        require(before['pgroup-control']['pgid'] == before['setpgid']['pgid'],
                'clause 4: pgroup-control does not share setpgid target process group')
        members_text = (self.cgroup / 'cgroup.procs').read_text()
        print(f'CGROUP-PROCS-BEFORE: {members_text.split()}', flush=True)
        members = {int(pid) for pid in members_text.split()}
        for name in ('setsid', 'setpgid'):
            require(before[name]['pid'] in members, f'clause 2: {name} missing from cgroup.procs')
        require(os.getpid() not in members, 'probe is inside kill cgroup')
        for name in ('control', 'pgroup-control'):
            require(before[name]['pid'] not in members, f'clause 4: {name} inside cgroup')

        # No signals or process-group kills until all post-kill evidence is captured.
        for name in ('setsid', 'setpgid'):
            current = snapshot(self.children[name].pid)
            require(same_identity(current, before[name]),
                    f'clause 1b: {name} died before the kill')
            evidence('CLAUSE-1B', name, current, before[name])
        try:
            written = (self.cgroup / 'cgroup.kill').write_bytes(b'1')
        except OSError as exc:
            raise RuntimeError(f'cgroup.kill write failed errno='
                               f'{errno.errorcode.get(exc.errno, exc.errno)}') from exc
        require(written == 1, f'cgroup.kill short write: {written} bytes')
        print('KILL-WRITE: cgroup.kill bytes=1 errno=0 success=True', flush=True)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            # Reap direct children so zombies do not masquerade as survivors.
            for proc in self.children.values():
                proc.poll()
            if all(self.children[name].returncode is not None
                   for name in ('setsid', 'setpgid')):
                break
            time.sleep(0.02)
        # Poll once more after the deadline before taking fresh final snapshots.
        for proc in self.children.values():
            proc.poll()
        after = {name: snapshot(proc.pid) for name, proc in self.children.items()}
        for name, row in after.items():
            evidence('AFTER', name, row, before[name])
        for name in ('control', 'pgroup-control'):
            require(same_identity(after[name], before[name]),
                    f'clause 4: out-of-cgroup {name} did not survive')
        if any(same_identity(after[name], before[name]) for name in ('setsid', 'setpgid')):
            return 'KILL_INEFFECTIVE'
        return 'AVAILABLE'

    def cleanup(self):
        errors = []
        # Popen owns unreaped direct children: poll before kill avoids recycled pids.
        for name, proc in self.children.items():
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=1)
                print(f'CLEANUP-REAP: {name} pid={proc.pid} rc={proc.returncode}', flush=True)
            except Exception as exc:
                errors.append(f'{name}: {exc!r}')
        if self.cgroup is not None:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    self.cgroup.rmdir()
                    print(f'CLEANUP-RMDIR: {self.cgroup}', flush=True)
                    break
                except OSError as exc:
                    if exc.errno != errno.EBUSY:
                        errors.append(f'rmdir: {exc!r}')
                        break
                    time.sleep(0.02)
            else:
                errors.append('rmdir: still busy after bounded cleanup')
        require(not errors, '; '.join(errors))


def main():
    probe = Probe()
    verdict = 'PROBE_ERROR'
    try:
        for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, 20)
        verdict = probe.run()
    except BaseException as exc:
        print(f'PROBE-ERROR: {type(exc).__name__}: {exc}', flush=True)
        verdict = 'PROBE_ERROR'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        try:
            probe.cleanup()
        except BaseException as exc:
            print(f'CLEANUP-ERROR: {type(exc).__name__}: {exc}', flush=True)
            verdict = 'PROBE_ERROR'
        print(f'PROBE-VERDICT: {verdict}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
