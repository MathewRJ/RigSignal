#!/usr/bin/env python3
"""Isolated probes of blocked diagnostics and retained/redacted failure evidence."""
import contextlib
import importlib.util
import io
import inspect
import signal
import time
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch


def alive(pid):
    """Liveness from /proc/<pid>/stat, never from an exception class.

    comm is the only field that may contain spaces or parens, so the state
    character is the first field after the final ') '. A zombie has been
    killed and is awaiting a reap: it is not a surviving process.
    """
    try:
        record = Path(f'/proc/{pid}/stat').read_text()
    except (FileNotFoundError, ProcessLookupError):
        return False
    return record.rsplit(') ', 1)[1].split(' ', 1)[0] != 'Z'


def worker(driver, case):
    spec = importlib.util.spec_from_file_location('driver', driver)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if case in ('expired-cleanup', 'partial-cleanup'):
        descendants = []
        with tempfile.TemporaryDirectory() as directory:
            if case == 'expired-cleanup':
                # A launcher in its own session with its own child, because the
                # single-sleep shape admitted termination of the known PID while
                # an undiscovered descendant survived. start_new_session mirrors
                # run(), so the launcher leads the group the harness created.
                marker = Path(directory) / 'descendant'
                children = [subprocess.Popen(
                    ['sh', '-c', 'sleep 100 & echo "$!" > "$1"; wait', 'sh', str(marker)],
                    start_new_session=True)]
                limit = time.monotonic() + 0.1
                while not marker.exists() and time.monotonic() < limit:
                    time.sleep(0.001)
                assert marker.exists(), 'fixture did not start its descendant'
                descendants.append(int(marker.read_text()))
            else:
                children = [subprocess.Popen(['sleep', '100']) for _ in range(2)]
            try:
                deadline = time.monotonic() + 0.05
                with contextlib.ExitStack() as stack:
                    if case == 'expired-cleanup':
                        # Exhaust real time, rather than injecting TimeoutExpired.
                        while time.monotonic() < deadline:
                            time.sleep(min(0.001, max(0, deadline - time.monotonic())))
                    else:
                        read = module.bounded_read
                        calls = 0
                        def incomplete(path, bound, *args):
                            nonlocal calls
                            calls += 1
                            if calls > 1:
                                raise module.DiagnosticIncomplete()
                            return read(path, bound, *args)
                        stack.enter_context(patch.object(module, 'bounded_read', side_effect=incomplete))
                    try:
                        module.cleanup(children[0], deadline)
                    except module.DiagnosticIncomplete:
                        pass
                # Allow the kernel to deliver kills; the assertion is liveness.
                for child in children:
                    try:
                        child.wait(timeout=0.05)
                    except subprocess.TimeoutExpired:
                        pass
                # A descendant is not ours to wait() on, so settle on a bound.
                # This cannot mask the defect it guards: an unsignalled child of
                # this fixture sleeps 100s, so it is alive at any bound.
                limit = time.monotonic() + 0.05
                while any(map(alive, descendants)) and time.monotonic() < limit:
                    time.sleep(0.001)
                survivors = [pid for pid in [child.pid for child in children] + descendants
                             if alive(pid)]
                assert not survivors, f'SURVIVING PROCESSES: {survivors}'
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait()
                for pid in descendants:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        return
    if case == 'traversal':
        class GrowingTree:
            next_pid = 200000
            def __init__(self, *args):
                pass
            def read_text(self):
                GrowingTree.next_pid += 1
                return str(GrowingTree.next_pid)
        with patch.object(module, 'Path', GrowingTree), patch.object(
                module, 'bounded_read', side_effect=lambda path, deadline: path.read_text().encode(),
                create=True):
            # Adapt the pre-remediation API so the negative control exercises
            # its actual recursive scan, rather than failing on an argument.
            args = [time.monotonic() + 0.05] if inspect.signature(module.owned_pids).parameters else []
            try:
                module.owned_pids(*args)
            except Exception as error:
                assert type(error).__name__ == 'DiagnosticIncomplete', type(error).__name__
            else:
                raise AssertionError('growing scan incorrectly completed')
        return
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for key in ('LAUNCHER', 'TEST_SCRIPT', 'FIXTURE', 'SIGNAL_READY', 'SIGNAL_SEEN',
                    'SIGNAL_RESULT', 'SIGNAL_OUT', 'BUNDLE', 'CA', 'CREDENTIALS'):
            os.environ['RIGSIGNAL_ASSETS_' + key] = str(root / key)
        for key in ('LAUNCHER', 'TEST_SCRIPT', 'FIXTURE', 'SIGNAL_READY'):
            Path(os.environ['RIGSIGNAL_ASSETS_' + key]).touch()
        os.environ['RIGSIGNAL_LAUNCHER_WAIT_SECS'] = '0.05'
        os.environ.pop('RIGSIGNAL_ASSETS_HARNESS_FAILURE', None)
        os.environ.pop('RIGSIGNAL_ASSETS_REPEAT_SIGNAL', None)
        canary = 'PRIVATE_PATH_CANARY'
        if case == 'fifo':
            fixture = Path(os.environ['RIGSIGNAL_ASSETS_FIXTURE'])
            fixture.unlink()
            os.mkfifo(fixture)
        if case in ('output-fifo', 'result-fifo'):
            os.mkfifo(os.environ['RIGSIGNAL_ASSETS_' + ('SIGNAL_OUT' if case == 'output-fifo' else 'SIGNAL_RESULT')])
        if case == 'stderr-full':
            read_fd, write_fd = os.pipe()
            os.set_blocking(write_fd, False)
            try:
                while True:
                    os.write(write_fd, b'x' * 4096)
            except BlockingIOError:
                pass
            os.set_blocking(write_fd, True)
            os.dup2(write_fd, 2)
            os.close(write_fd)
        if case == 'real-expiry':
            Path(os.environ['RIGSIGNAL_ASSETS_SIGNAL_READY']).unlink()
            launcher = Path(os.environ['RIGSIGNAL_ASSETS_LAUNCHER'])
            launcher.write_text('#!/bin/sh\ntrap "" INT\nsleep 100 &\necho "$!" > "' + str(root / 'descendant') + '"\ntouch "$RIGSIGNAL_ASSETS_SIGNAL_READY"\nwait\n')
            launcher.chmod(0o700)
            children = []
            waits = []
            popen = module.subprocess.Popen
            def launch(*args, **kwargs):
                child = popen(*args, **kwargs)
                children.append(child)
                wait = child.wait
                def real_wait(timeout=None):
                    started = time.monotonic()
                    try:
                        return wait(timeout=timeout)
                    finally:
                        waits.append((timeout, time.monotonic() - started))
                child.wait = real_wait
                return child
            try:
                with patch.object(module.subprocess, 'Popen', side_effect=launch), patch.object(module.sys, 'argv', ['driver', 'INT']):
                    code = module.main()
                pids = [child.pid for child in children]
                if (root / 'descendant').exists():
                    pids.append(int((root / 'descendant').read_text()))
                survivors = [pid for pid in pids if Path(f'/proc/{pid}').exists()]
                assert not survivors, f'SURVIVING PROCESSES: {survivors}'
                assert code == 1, code
                assert len(pids) == 2, 'fixture did not start its descendant'
                assert any(timeout is not None and timeout > 0 and elapsed >= timeout
                           for timeout, elapsed in waits), 'no real wait exhaustion'
            finally:
                for child in children:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait()
                while True:
                    try: os.waitpid(-1, 0)
                    except ChildProcessError: break
            return
        if case in ('output', 'result'):
            key = 'SIGNAL_OUT' if case == 'output' else 'SIGNAL_RESULT'
            os.environ['RIGSIGNAL_ASSETS_' + key] = str(root / canary / 'missing')

        class Child:
            pid = 123456789
            returncode = 17
            def wait(self, timeout):
                if case in ('fifo', 'stderr-full'):
                    raise subprocess.TimeoutExpired('launcher', timeout)
                return 17
            def poll(self):
                return self.returncode

        output = io.StringIO()
        # No real child or signal: exercise real main/capture/cleanup branches.
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(module, 'preflight', return_value=True))
            stack.enter_context(patch.object(module.subprocess, 'Popen', return_value=Child()))
            stack.enter_context(patch.object(module.os, 'kill'))
            # Mocked pid: the group fallback must signal nothing real here,
            # rather than relying on pid_max to keep the id unallocatable.
            stack.enter_context(patch.object(module.os, 'killpg'))
            stack.enter_context(patch.object(module.os, 'waitpid', side_effect=ChildProcessError))
            stack.enter_context(patch.object(module, 'owned_pids', return_value={123456789} if case == 'status' else set()))
            stack.enter_context(patch.object(module.sys, 'argv', ['driver', 'INT']))
            if case != 'stderr-full':
                stack.enter_context(contextlib.redirect_stderr(output))
            code = module.main()
        report = output.getvalue()
        assert code == 1, (code, report)
        if case == 'stderr-full':
            os.close(read_fd)
            return
        if case == 'fifo':
            assert 'TimeoutExpired' in report and 'FINALLY' in report, report
        elif case == 'status':
            assert 'HARNESS CLEANUP FAILURE' in report, report
            assert 'HARNESS FAILURE: launcher_status=17' in report, report
            assert not Path(os.environ['RIGSIGNAL_ASSETS_SIGNAL_RESULT']).exists()
        else:
            assert canary not in report and 'Traceback' not in report, report
            assert 'HARNESS FAILURE:' in report, report
        print(report, end='')


if __name__ == '__main__':
    if sys.argv[1] == '--worker':
        worker(sys.argv[2], sys.argv[3])
    else:
        for case in sys.argv[2:] or ['fifo', 'status', 'output', 'result', 'traversal', 'output-fifo', 'result-fifo', 'stderr-full', 'real-expiry', 'expired-cleanup', 'partial-cleanup']:
            result = subprocess.run([sys.executable, __file__, '--worker', sys.argv[1], case],
                                    capture_output=True, text=True, timeout=0.3)
            assert result.returncode == 0, result.stdout + result.stderr
            print(f'PASS: {case} reporting regression worker exit=0')
