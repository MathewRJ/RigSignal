#!/usr/bin/env python3
"""Signal harness with owned-subtree diagnostics and deadline-bound cleanup."""
import ctypes
import errno
import fcntl
import io
import hashlib
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

PR_SET_CHILD_SUBREAPER = 36
# pidfd_send_signal(2). The group flag needs Linux 6.9; preflight PROBES it
# rather than reading a version, because inferring a kernel behaviour instead of
# constructing it is what put a wrong-group SIGKILL in this file once already.
SYS_PIDFD_SEND_SIGNAL = 424
PIDFD_SIGNAL_PROCESS_GROUP = 4


def libc_handle():
    handle = ctypes.CDLL(None, use_errno=True)
    handle.syscall.restype = ctypes.c_long
    return handle


def pidfd_group_signal(anchor, number):
    """Signal the group led by the process this descriptor holds. Returns errno."""
    ctypes.set_errno(0)
    if libc_handle().syscall(SYS_PIDFD_SEND_SIGNAL, ctypes.c_int(anchor), ctypes.c_int(number),
                      None, ctypes.c_uint(PIDFD_SIGNAL_PROCESS_GROUP)) == 0:
        return 0
    return ctypes.get_errno()


def report(message):
    """Best effort only: a blocked diagnostic consumer must not delay cleanup."""
    if isinstance(sys.stderr, io.StringIO):
        sys.stderr.write(message + '\n')
        return
    try:
        fd = sys.stderr.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        try:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            os.write(fd, (message + '\n').encode()[:4096])
        finally:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
    except (OSError, ValueError):
        pass


def open_output(path, deadline):
    check_deadline(deadline)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK, 0o666)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise DiagnosticIncomplete()
        check_deadline(deadline)
        os.ftruncate(fd, 0)
        return os.fdopen(fd, 'wb', buffering=0)
    except BaseException:
        os.close(fd)
        raise


def preflight():
    """Required Linux coverage: unavailable containment is a setup failure."""
    prerequisite = 'platform'
    try:
        if sys.platform != 'linux':
            raise OSError(errno.ENOSYS, 'Linux required')
        prerequisite = 'prctl'
        libc = ctypes.CDLL(None, use_errno=True)
        if not hasattr(libc, 'prctl'):
            raise OSError(errno.ENOSYS, 'prctl unavailable')
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        libc.prctl.restype = ctypes.c_int
        prerequisite = 'subreaper'
        if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
        # The identity anchor is a prerequisite, not an optimisation: without it
        # terminate_group() targets a bare number that becomes recyclable the
        # moment the launcher is reaped. Refuse, never fall back silently.
        prerequisite = 'pidfd'
        if not hasattr(os, 'pidfd_open'):
            raise OSError(errno.ENOSYS, 'pidfd_open unavailable')
        prerequisite = 'pidfd-group-flag'
        probe = os.pidfd_open(os.getpid())
        try:
            # Signal 0 carries no signal, so this asks the kernel whether it
            # ACCEPTS the group flag -- a constructed answer, not a version
            # string. Two readings are needed because one is not decisive:
            #
            #   ESRCH is a PASS. The kernel validated the flag, then looked for
            #   a group led by this process and found none, because this process
            #   need not be a group leader. An earlier revision of this probe
            #   treated ESRCH as failure and so refused every host where the
            #   harness was not the group leader -- which is most of them.
            #
            #   EINVAL is the real failure: the flag word was rejected.
            #
            # The undefined-bit call is the probe's own negative control: if it
            # did NOT return EINVAL, this kernel ignores unknown flags and the
            # first reading would prove nothing at all.
            if pidfd_group_signal(probe, 0) not in (0, errno.ESRCH):
                raise OSError(errno.EINVAL, 'PIDFD_SIGNAL_PROCESS_GROUP')
            ctypes.set_errno(0)
            if libc_handle().syscall(SYS_PIDFD_SEND_SIGNAL, ctypes.c_int(probe), ctypes.c_int(0),
                              None, ctypes.c_uint(1 << 30)) == 0:
                raise OSError(errno.ENOSYS, 'flag validation absent')
        finally:
            os.close(probe)
    except OSError as error:
        report(f'HARNESS SETUP: {prerequisite} prerequisite errno={error.errno}')
        return False
    return True


class DiagnosticIncomplete(Exception):
    """Existing deadline or fixed diagnostic work limit exhausted."""


def check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise DiagnosticIncomplete()


def bounded_read(path, deadline, limit=65536):
    # O_NONBLOCK prevents FIFO open from waiting, including a replacement race.
    # fstat rejects devices, sockets and FIFOs before any read.
    check_deadline(deadline)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise DiagnosticIncomplete()
        data = bytearray()
        while len(data) <= limit:
            check_deadline(deadline)
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise DiagnosticIncomplete()
    finally:
        os.close(fd)


def owned_pids(deadline, known=None):
    # Include adopted descendants, even if they have created another session.
    # An incomplete scan must never be interpreted as an empty subtree.
    pending = [os.getpid()]
    owned = set() if known is None else known
    visited = set()
    scanned = 0
    while pending:
        check_deadline(deadline)
        scanned += 1
        if scanned > 1024:
            raise DiagnosticIncomplete()
        pid = pending.pop()
        try:
            children = bounded_read(Path(f'/proc/{pid}/task/{pid}/children'), deadline).split()
        except FileNotFoundError:
            continue
        for value in children:
            check_deadline(deadline)
            child = int(value)
            if child not in visited:
                visited.add(child)
                if len(owned) >= 1024:
                    raise DiagnosticIncomplete()
                owned.add(child)
                pending.append(child)
    return owned


def capture(child, deadline, known=None):
    # No argv, ancestor data, arbitrary acknowledgement contents, or paths.
    report(f'TIMEOUT launcher={child.pid}')
    for label, path in (
        ('driver', Path(__file__)),
        ('test', Path(os.environ['RIGSIGNAL_ASSETS_TEST_SCRIPT'])),
        ('launcher', Path(os.environ['RIGSIGNAL_ASSETS_LAUNCHER'])),
        ('fixture', Path(os.environ['RIGSIGNAL_ASSETS_FIXTURE'])),
    ):
        digest = hashlib.sha256(bounded_read(path, deadline, 4 * 1024 * 1024)).hexdigest()
        report(f'sha256 {digest} {label}')
    check_deadline(deadline)
    report(f"ack present={Path(os.environ['RIGSIGNAL_ASSETS_SIGNAL_SEEN']).exists()}")
    fields = {'Pid', 'PPid', 'State', 'SigPnd', 'ShdPnd', 'SigBlk', 'SigIgn', 'SigCgt'}
    # At most 64 process records, each with eight allowlisted bounded fields.
    discovered = set()
    try:
        pids = sorted(owned_pids(deadline, discovered))
    finally:
        if known is not None:
            known.update(discovered)
    for pid in pids[:64]:
        try:
            lines = bounded_read(Path(f'/proc/{pid}/status'), deadline).decode().splitlines()
            record = ' '.join(line[:80] for line in lines if line.split(':', 1)[0] in fields)
            report(f'process {pid} {record}')
        except FileNotFoundError:
            continue
    report(f'process records omitted={max(0, len(pids) - 64)}')
    if os.environ.get('RIGSIGNAL_ASSETS_HARNESS_FAILURE') == 'capture':
        raise RuntimeError('injected capture failure')


def terminate_group(anchor):
    """Terminate the process group led by the process this descriptor holds.

    run() spawns the launcher with start_new_session=True, so it leads a group
    whose id is its own pid and ordinary descendants inherit that group. One
    syscall, no /proc traversal and no deadline check, so this is still reachable
    when the final deadline is exhausted and every scan below has failed.

    IDENTITY, NOT A NUMBER. The signal is addressed to the pidfd, via
    PIDFD_SIGNAL_PROCESS_GROUP, never to `child.pid`. An earlier revision held a
    pidfd and then called killpg() on the number, on the stated belief that
    holding the descriptor kept the number reserved. THAT BELIEF IS FALSE and was
    falsified by construction, not by argument: free_pid() removes the allocator
    entry before the later reference release, so the object and the number are
    independent. A round-6 review forced real reuse -- 4,194,004 serial children
    in 184 s -- watched pid 323 be reassigned while its original pidfd was open,
    and watched this function SIGKILL the replacement group. pidfd_send_signal
    returned ESRCH on that same descriptor at that same moment, which is exactly
    the distinction: the descriptor knew its target was gone, the number did not.

    preflight() refuses a host whose kernel does not accept the group flag, so
    there is no silent fallback to a numeric signal.

    REFUTED alternative, recorded so it is not re-proposed: "skip the group kill
    once the leader is reaped and nothing is known" looks equivalent and is not.
    A round-5 probe ran a real launcher that exited 17 and was reaped while an
    ordinary child legitimately retained the killable group; at an exhausted
    deadline `known` is empty there, so that guard would drop a kill that works.

    NAMED RESIDUAL (accepted, not fixed): this cannot reach a descendant that
    called setsid() or setpgid() -- it has left the group, and at an exhausted
    deadline there is no discovery budget to find it. owned_pids() attempts that
    class whenever time remains, within its own deadline and its 1024-record
    limit, which is why both paths exist; a scan that stops at either bound has
    not cleared the subtree. When neither path reaches it, cleanup() returns
    False and reports HARNESS CLEANUP FAILURE, so the leak is loud rather than
    silent, and the `detached-expiry` regression holds that behaviour. Closing it
    needs a containment primitive the harness creates before launch -- a per-case
    cgroup with a group-kill -- not another deadline check, reserve or delayed
    observation, none of which can supply ownership.
    """
    if anchor is None:
        return
    # ESRCH once the group is empty; nothing else here is actionable.
    pidfd_group_signal(anchor, signal.SIGKILL)


def cleanup(child, deadline, known=None, anchor=None):
    reaped = []
    known = set() if known is None else known
    if child.returncode is None:
        known.add(child.pid)
    incomplete = False
    while True:
        # Containment must not depend on remaining time: an exhausted deadline
        # fails every scan below, leaving known = {launcher} and its child alive.
        terminate_group(anchor)
        # Killing known ownership must precede (and survive) a failed scan.
        for pid in known:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        discovered = set()
        try:
            discovered.update(owned_pids(deadline, discovered))
        except Exception:
            incomplete = True
        finally:
            # owned_pids retains partial results even when its bound fires.
            for pid in discovered:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        known.update(discovered)
        child.poll()
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                pid = 0
            if not pid:
                break
            reaped.append(pid)
            known.discard(pid)
            if time.monotonic() >= deadline:
                break
        if child.returncode is not None:
            known.discard(child.pid)
        if not discovered and not known and not incomplete:
            report(f'FINALLY reaped launcher={child.pid} descendants={reaped[:64]} omitted={max(0, len(reaped) - 64)}')
            report('FINALLY process group absent')
            return True
        if time.monotonic() >= deadline:
            report('HARNESS CLEANUP FAILURE: incomplete owned-subtree cleanup at deadline')
            return False
        time.sleep(min(0.001, max(0, deadline - time.monotonic())))


def run():
    if not preflight():
        return 1
    signal_name = sys.argv[1]
    ready = os.environ['RIGSIGNAL_ASSETS_SIGNAL_READY']
    budget = float(os.environ.get('RIGSIGNAL_LAUNCHER_WAIT_SECS', '60'))
    command = [os.environ['RIGSIGNAL_ASSETS_LAUNCHER'], 'assets', 'install', '--bundle', os.environ['RIGSIGNAL_ASSETS_BUNDLE'], '--endpoint', 'http://127.0.0.1:9200', '--ca-file', os.environ['RIGSIGNAL_ASSETS_CA'], '--kibana-endpoint', 'https://kibana.example.invalid', '--admin-credentials-file', os.environ['RIGSIGNAL_ASSETS_CREDENTIALS'], '--non-interactive']
    failed = False
    status = None
    deadline = time.monotonic() + budget
    # Reserve cleanup/publication time inside each existing allowance.
    work_deadline = deadline - budget * 0.2
    with open_output(os.environ['RIGSIGNAL_ASSETS_SIGNAL_OUT'], work_deadline) as output:
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        known = set()
        anchor = None
        try:
            try:
                # Hold the launcher's identity before anything can reap it; see
                # the caller contract on terminate_group().
                anchor = os.pidfd_open(child.pid)
            except OSError as error:
                # No anchor means NO containment, because terminate_group() is a
                # no-op without one. Fail loudly and reap what was just spawned,
                # rather than continue down a path that cannot contain anything.
                report(f'HARNESS SETUP: anchor prerequisite errno={error.errno}')
                try:
                    os.kill(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
                return 1
            while not os.path.exists(ready) and time.monotonic() < work_deadline:
                time.sleep(min(0.01, max(0, work_deadline - time.monotonic())))
            if not os.path.exists(ready):
                raise subprocess.TimeoutExpired('launcher', budget)
            if os.environ.get('RIGSIGNAL_ASSETS_HARNESS_FAILURE'):
                child.wait(timeout=0)
            deadline = time.monotonic() + budget
            work_deadline = deadline - budget * 0.2
            os.kill(child.pid, getattr(signal, 'SIG' + signal_name))
            if os.environ.get('RIGSIGNAL_ASSETS_REPEAT_SIGNAL'):
                # Second delivery consumes the same post-signal allowance.
                time.sleep(min(0.2, max(0, work_deadline - time.monotonic())))
                if child.poll() is None and time.monotonic() < work_deadline:
                    os.kill(child.pid, getattr(signal, 'SIG' + signal_name))
            status = child.wait(timeout=max(0, work_deadline - time.monotonic()))
            if owned_pids(work_deadline, known):
                raise AssertionError('launcher returned with surviving owned descendants (including detached descendants)')
        except subprocess.TimeoutExpired:
            failed = True
            report('TimeoutExpired: launcher exceeded harness wait')
            try:
                capture(child, work_deadline, known)
            except Exception as error:
                # Exception values may contain paths or fixture data.
                detail = 'injected capture failure' if os.environ.get('RIGSIGNAL_ASSETS_HARNESS_FAILURE') == 'capture' else type(error).__name__
                report(f'capture failed: {detail}')
        except AssertionError:
            failed = True
            report('HARNESS FAILURE: launcher returned with surviving owned descendants (including detached descendants)')
        except Exception as error:
            failed = True
            report(f'HARNESS FAILURE: {type(error).__name__}')
        finally:
            # The descriptor is released in a finally that encloses everything
            # able to raise after acquisition -- including BaseException, which
            # the inner `except Exception` does not catch. A real SIGINT landing
            # at cleanup's return boundary used to escape past the close.
            try:
                try:
                    if not cleanup(child, deadline, known, anchor):
                        failed = True
                except Exception as error:
                    report(f'HARNESS CLEANUP FAILURE: {type(error).__name__}')
                    failed = True
                if failed and status is not None:
                    report(f'HARNESS FAILURE: launcher_status={status}')
            finally:
                if anchor is not None:
                    # Released only after the last group signal.
                    os.close(anchor)
    if failed:
        return 1
    try:
        with open_output(os.environ['RIGSIGNAL_ASSETS_SIGNAL_RESULT'], deadline) as result:
            check_deadline(deadline)
            result.write(f'status={status}\n'.encode())
    except Exception as error:
        report(f'HARNESS FAILURE: launcher_status={status} result_write={type(error).__name__}')
        return 1
    return 0


def main():
    try:
        return run()
    except Exception as error:
        # Never emit exception values, argv, filenames or traceback paths.
        report(f'HARNESS FAILURE: {type(error).__name__}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
