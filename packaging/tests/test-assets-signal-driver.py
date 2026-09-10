#!/usr/bin/env python3
"""Harness regressions, including a harmless secret-disclosure canary."""
import contextlib
import ctypes
import errno
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch


def run(driver, case, escape_fixture=None):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        fixture = root / 'launcher.py'
        fixture.write_text('''#!/usr/bin/env python3
import os, signal, time
from pathlib import Path
signal.signal(signal.SIGINT, lambda *_: os._exit(42))
if os.environ.get('ESCAPE'):
    if os.fork() == 0:
        os.setsid()
        Path(os.environ['ESCAPED_PID_FILE']).write_text(str(os.getpid()))
        while True: time.sleep(1)
    while not Path(os.environ['ESCAPED_PID_FILE']).exists(): time.sleep(0.001)
Path(os.environ['RIGSIGNAL_ASSETS_SIGNAL_READY']).touch()
while True: time.sleep(1)
''')
        fixture.chmod(0o700)
        env = dict(os.environ)
        for key in ('RIGSIGNAL_ASSETS_HARNESS_FAILURE', 'RIGSIGNAL_ASSETS_REPEAT_SIGNAL'):
            env.pop(key, None)
        for key, value in {
            'LAUNCHER': escape_fixture or fixture, 'TEST_SCRIPT': __file__, 'FIXTURE': fixture,
            'SIGNAL_READY': root / 'ready', 'SIGNAL_SEEN': root / 'seen',
            'SIGNAL_RESULT': root / 'result', 'SIGNAL_OUT': root / 'out',
            'BUNDLE': root / 'bundle', 'CA': root / 'ca', 'CREDENTIALS': root / 'credentials',
        }.items():
            env['RIGSIGNAL_ASSETS_' + key] = str(value)
        env['RIGSIGNAL_LAUNCHER_WAIT_SECS'] = '0.3'
        env['ESCAPED_PID_FILE'] = str(root / 'escaped.pid')
        if case == 'escape':
            env['ESCAPE'] = '1'
        else:
            env['RIGSIGNAL_ASSETS_HARNESS_FAILURE'] = case
        # Keep this shell alive as the driver's ancestor, with the canary in argv.
        canary = 'RS8_HARMLESS_ANCESTOR_CANARY_7f421'
        start = time.monotonic()
        result = subprocess.run(['sh', '-c', '"$@"; code=$?; exit "$code"', canary,
                                 sys.executable, str(driver), 'INT'], env=env,
                                capture_output=True, text=True, timeout=1)
        elapsed = time.monotonic() - start
        output = result.stdout + result.stderr
        assert canary not in output, f'{case}: ancestor canary disclosed'
        assert result.returncode == 1, (case, result.returncode, output)
        if case == 'escape':
            assert 'detached descendants' in output, output
            assert elapsed < 0.3, f'escape exceeded existing 0.3s budget: {elapsed}'
            pid = int((root / 'escaped.pid').read_text())
            assert not Path(f'/proc/{pid}').exists(), 'escaped descendant survives'
            assert 'HARNESS FAILURE: launcher_status=42' in output, output
            assert not (root / 'result').exists(), 'failure published as success'
        else:
            assert 'TimeoutExpired' in output, output
            if case == 'capture':
                assert 'capture failed:' in output, output
        print(f'PASS: {case} driver exit={result.returncode} elapsed={elapsed:.3f}s; canary absent')


def setup_failure(driver):
    spec = importlib.util.spec_from_file_location('signal_driver', driver)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class Prctl:
        def __call__(self, *args):
            assert args == (36, 1, 0, 0, 0)
            ctypes.set_errno(errno.ENOSYS)
            return -1

    class Libc:
        prctl = Prctl()

    output = io.StringIO()
    with patch.object(module.ctypes, 'CDLL', return_value=Libc()), contextlib.redirect_stderr(output):
        assert module.main() == 1
    assert 'HARNESS SETUP' in output.getvalue() and 'errno=38' in output.getvalue()
    assert Libc.prctl.argtypes == [ctypes.c_int] + [ctypes.c_ulong] * 4
    print('PASS: prerequisite injected ENOSYS exit=1 HARNESS SETUP errno=38')


if __name__ == '__main__':
    driver = Path(sys.argv[1])
    cases = sys.argv[2:] or ['timeout', 'capture', 'escape', 'setup']
    for case in cases:
        if case == 'setup':
            setup_failure(driver)
        else:
            run(driver, case, os.environ.get('RS8_ESCAPE_FIXTURE') if case == 'escape' else None)
