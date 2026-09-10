# RigSignal gpu_sched-port paired deploy — FINAL state (2026-07-17 late, build off main c7288e5)

**DEPLOYED AND LIVE-VALIDATED on both boxes** (three install rounds: port → loss fix →
TSDS-collision fix; A9.2-R distribution comparison PASSED 21:01Z). Artifacts here match
what is installed (hashes in `SHA256SUMS`); staged copies at `/tmp/rigsignal-gpusched/`.

| file | state | installs to | who installs |
|---|---|---|---|
| `rigsignal-agent` | UNCHANGED 0.2.3 (`65b6bc20…`) — not part of this deploy | — | — |
| `rigsignal-ebpf` | INSTALLED (`9e5f3bec…`; crate still 0.2.3 — bump gated on item 5) | `/usr/local/bin/rigsignal-ebpf` | **user** (sudo) — done |
| `rigsignal-ebpf-probes` | INSTALLED (`ddf8199e…` — `GPU_SCHED_KEY_OFFSET` + scoped-LRU contract) | `/usr/local/lib/rigsignal/rigsignal-ebpf-probes` | **user** (sudo) — done |

Post-validation live signature: 9/9 probes; `variant=legacy key_field=id key_offset=32
scope_field=entity scope_offset=8`; seven probes at 60 docs/min. On-box `.bak-*` files
from the first round remain the rollback point (pair-restore together).

Targets: the two paired producer hosts, `<user>@<box-a>` AND `<user>@<box-b>`.
Unlike the 0.2.3 deploy, BOTH pair files changed — never install one without the other.

> **This section is stale.** It named two hosts by address, hostname and login user. Those addresses
> stopped resolving when the LAN was renumbered in August 2026, so the line was misleading as well as
> over-specific; the placeholders match the `deck@<box>` idiom already used below. Removing them here
> **unpublishes nothing** — the values remain in this file's git history and in every existing clone.

## What this deploy changes at runtime

gpu_sched probe attaches on valve 6.16 kernels via the legacy tracepoint pair
(`drm_sched_job`/`drm_run_job`), keyed on `id` at an attach-time-parsed offset; the
renamed pair's offset is also parsed at attach now (no hardcoded offsets remain).
Expected on both boxes: **9/9 probes loaded** and one info log line with
`variant=legacy key_field=id key_offset=32`. Emitted ES fields are unchanged.

## Install (USER-run, sudo, both boxes)

```sh
ssh deck@<box>
cd /tmp/rigsignal-gpusched && sha256sum -c --ignore-missing SHA256SUMS
sudo steamos-readonly disable
sudo cp -a /usr/local/bin/rigsignal-ebpf /usr/local/bin/rigsignal-ebpf.bak-$(date +%Y%m%d-%H%M)
sudo cp -a /usr/local/lib/rigsignal/rigsignal-ebpf-probes /usr/local/lib/rigsignal/rigsignal-ebpf-probes.bak-$(date +%Y%m%d-%H%M)
sudo install -m 755 rigsignal-ebpf /usr/local/bin/rigsignal-ebpf
sudo install -m 644 rigsignal-ebpf-probes /usr/local/lib/rigsignal/rigsignal-ebpf-probes
sudo steamos-readonly enable
sudo systemctl restart rigsignal-ebpf
sudo journalctl -u rigsignal-ebpf --since -2min --no-pager | grep -Ei 'gpu_sched|probes|variant'
```

## Live acceptance (A9.2-R — orchestrator-coordinated after install)

1. Journal shows `variant=legacy key_field=id key_offset=32` + 9/9 probes (both boxes).
2. Orchestrator launches a game remotely on the gaming host; `gpu_sched` docs appear in
   `metrics-rigsignal.ebpf-default`.
3. Reference comparison (the gaming host, mid-game, USER-run):
   `sudo /tmp/rigsignal-gpusched/gpu-sched-ftrace-reference.sh 60 /tmp/gpu-sched-ref.txt`
   — orchestrator fetches the capture, runs `gpu-sched-reference-parse.py`, and compares
   count + latency distribution against the daemon's docs for the same window within
   tolerances. "9/9 loaded" alone is NOT validity.

Keep backups until acceptance passes; roll back both pair files together if needed.
