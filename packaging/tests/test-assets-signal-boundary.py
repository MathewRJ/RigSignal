#!/usr/bin/env python3
"""Force dash's completed-wait transition using the launcher's real handler."""
from pathlib import Path
import subprocess
import sys

launcher = Path(sys.argv[1]).read_text()
functions = launcher[launcher.index('assets_restore_terminal() {'):launcher.index('assets_snapshot_ca() {')]
failed = False
for captured in (False, True):
    probe = functions + '''
ASSETS_CLEANING=0
trap assets_cleanup EXIT
trap 'assets_interrupted INT' INT
(exit 42) &
ASSETS_ENGINE_PID=$!
wait "$ASSETS_ENGINE_PID"
''' + ('ASSETS_ENGINE_STATUS=$?\n' if captured else '') + '''
kill -INT $$
ASSETS_ENGINE_STATUS=$?
ASSETS_ENGINE_PID=""
exit "$ASSETS_ENGINE_STATUS"
'''
    result = subprocess.run(['dash'], input=probe, text=True, capture_output=True, timeout=5)
    print(f'post-wait captured={captured}: exit={result.returncode}, expected=42')
    failed |= result.returncode != 42
sys.exit(int(failed))
