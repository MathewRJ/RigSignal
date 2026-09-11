# RigSignal — Parity QA Matrix (Milestone F)

This document is the pass/fail oracle for cross-platform parity verification.
Every cell in the platform matrix must reach ✅ or 🟡(known limitation documented)
before the elastic/integrations PR (Milestone G) can be opened.

---

## How to run a parity check

```bash
# 1. Build release binary (skip if already built)
cargo build --release --manifest-path src/Cargo.toml

# 2. Run one tick in dry-run mode, capture log
RIGSIGNAL_LOG=debug target/release/rigsignal-agent \
  --dry-run --once --log-level debug 2>&1 | tee /tmp/gp-parity-<platform>.log

# 3. Check each collector section in the log for the required fields below
# 4. Fill in the results table in docs/STATUS.md
```

For Docker-based runs (F.2 Ubuntu, F.3 Fedora, F.4 Arch):
```bash
# Run inside the container (binary + /proc/sys bind-mounted from host)
docker run --rm \
  -v $(pwd)/target/release/rigsignal-agent:/usr/bin/rigsignal-agent:ro \
  --pid=host --network=host \
  -e RIGSIGNAL_LOG=debug \
  <image> rigsignal-agent --dry-run --once --log-level debug
```

`--pid=host` is required so the container sees the host's `/proc` and can read
per-process metrics. Without it, only aggregated metrics are visible.

---

## Build provenance (G4)

Both binaries expose a no-privilege, machine-readable build record:

```bash
cargo run --manifest-path src/Cargo.toml -- --build-info-json
cargo run --manifest-path ebpf/rigsignal-ebpf/Cargo.toml -- --build-info-json
```

Each command prints one JSON line containing `name`, `version`, and `commit`.
The commit is a 40-character SHA when Git metadata or `GITHUB_SHA` is available,
otherwise `unknown` for source-tarball builds. The build scripts watch Git's real
`HEAD`, current branch-ref, and `packed-refs` paths, so building again after a
new commit re-stamps the binary without `cargo clean`. In CI, a `GITHUB_SHA`
that differs from local `HEAD` fails the build rather than producing stale
provenance.

---

## Pass criteria per stream

A stream is ✅ when:
- Binary does not crash or panic on this platform
- All **required** fields below are present and non-null in the log output
- Field types match the schema (no dynamic type conflict)

A stream is 🟡(known limitation) when:
- At least one collector field is emitted
- Missing fields have a documented reason (hardware absent, privilege needed, etc.)

A stream is 🔲 when not yet tested.

---

## Stream field requirements

### cpu
| Field | Required | Notes |
|---|---|---|
| `rigsignal.cpu.total_utilisation_pct` | ✅ Required | Reads `/proc/stat` |
| `rigsignal.cpu.per_core` | ✅ Required | Array of per-core % |
| `rigsignal.cpu.clock_mhz_avg` | ✅ Required | `/proc/cpuinfo` |
| `rigsignal.cpu.temperature_c` | 🟡 Optional | Missing on VMs / containers without hwmon |
| `rigsignal.cpu.governor` | 🟡 Optional | Missing if cpufreq not exposed |
| `rigsignal.cpu.boost_state` | 🟡 Optional | Missing if boost sysfs absent |
| `rigsignal.cpu.power_w` | 🟡 Optional | RAPL — missing in containers/VMs |

### gpu
| Field | Required | Notes |
|---|---|---|
| `rigsignal.gpu.utilisation_pct` | ✅ Required on bare-metal | Empty in Docker (no /sys/class/drm passthrough) |
| `rigsignal.gpu.memory_used_mb` | ✅ Required on bare-metal | Same |
| `rigsignal.gpu.temperature_c` | 🟡 Optional | hwmon; bare-metal AMD/NVIDIA only |
| `rigsignal.gpu.temp_source` | 🟡 Optional | Present iff temperature_c present |
| `rigsignal.gpu.clock_mhz` | 🟡 Optional | AMD bare-metal |
| `rigsignal.gpu.power_w` | 🟡 Optional | AMD bare-metal |

Docker containers: gpu stream expected to emit nothing (no hardware passthrough) — mark 🟡 with note.

### memory
| Field | Required | Notes |
|---|---|---|
| `rigsignal.memory.system_used_mb` | ✅ Required | `/proc/meminfo` |
| `rigsignal.memory.page_cache_mb` | ✅ Required | `/proc/meminfo` |
| `rigsignal.memory.swap_used_mb` | ✅ Required | `/proc/meminfo` (may be 0) |
| `rigsignal.memory.game_rss_mb` | 🟡 Optional | Only when game PID is set |
| `rigsignal.memory.page_faults_major` | 🟡 Optional | `/proc/<pid>/stat` |

### storage
| Field | Required | Notes |
|---|---|---|
| `rigsignal.storage.read_mbps` | ✅ Required | `/proc/diskstats` |
| `rigsignal.storage.write_mbps` | ✅ Required | `/proc/diskstats` |
| `rigsignal.storage.read_iops` | ✅ Required | `/proc/diskstats` |
| `rigsignal.storage.write_iops` | ✅ Required | `/proc/diskstats` |
| `rigsignal.storage.io_wait_pct` | 🟡 Optional | `/proc/stat` cpu_iowait |
| `rigsignal.storage.game_process_read_mb` | 🟡 Optional | Only when game PID set |
| `rigsignal.storage.drive_temperature_c` | 🟡 Optional | NVMe hwmon; bare-metal only |

### network
| Field | Required | Notes |
|---|---|---|
| `rigsignal.network.tx_packets_per_sec` | ✅ Required | `/proc/net/dev` — per-second tx packet rate |
| `rigsignal.network.rx_packets_per_sec` | ✅ Required | `/proc/net/dev` — per-second rx packet rate |
| `rigsignal.network.bandwidth_utilisation_mbps` | ✅ Required | Derived from byte counters |
| `rigsignal.network.tx_mbps` | 🟡 Optional | Transmit throughput |
| `rigsignal.network.rx_mbps` | 🟡 Optional | Receive throughput |
| `rigsignal.network.interface` | 🟡 Optional | Active NIC name |
| `rigsignal.network.connection_type` | 🟡 Optional | `ethernet`, `wifi`, etc. |
| `rigsignal.network.tcp_retransmits_per_sec` | 🟡 Optional | TCP reliability signal |
| `rigsignal.network.packet_loss_pct` | 🟡 Optional | Requires ICMP ping target |
| `rigsignal.network.rtt_ms` | 🟡 Optional | Requires ICMP ping target |

### audio
| Field | Required | Notes |
|---|---|---|
| `rigsignal.audio.backend` | ✅ Required on bare-metal | `pipewire`, `pulseaudio`, `alsa`, or `wasapi` |
| `rigsignal.audio.quantum` | 🟡 Optional | Effective PipeWire scheduling quantum from `pw-metadata` |
| `rigsignal.audio.sample_rate_hz` | 🟡 Optional | Effective PipeWire clock rate from `pw-metadata`, or PulseAudio server rate |
| `rigsignal.audio.latency_ms` | 🟡 Optional | Configured PipeWire scheduling latency derived from effective quantum and rate |

Docker containers: audio stream expected to emit nothing or `backend` only — acceptable as 🟡.

### power
| Field | Required | Notes |
|---|---|---|
| `rigsignal.power.ac_connected` | 🟡 Optional | `/sys/class/power_supply` — absent on desktop (no AC/BAT entries) |
| `rigsignal.power.battery_pct` | 🟡 Optional | Battery devices only |
| `rigsignal.power.battery_rate_w` | 🟡 Optional | Battery + RAPL |
| `rigsignal.power.profile` | 🟡 Optional | power-profiles-daemon |
| `rigsignal.power.tdp_current_w` | 🟡 Optional | AMD TDP sysfs |

Desktop: `ac_connected` absent (no AC/BAT in /sys/class/power_supply on desktop).
Docker: `ac_connected` may be absent (no /sys/class/power_supply passthrough) — acceptable as 🟡.

### frame
| Field | Required | Notes |
|---|---|---|
| `rigsignal.fps.current` | ✅ Required when MangoHud present | Empty without MangoHud/PresentMon |
| `rigsignal.fps.frametime_ms` | ✅ Required when MangoHud present | |

Docker/non-gaming sessions: frame stream expected empty — mark 🟡 with note.

### ebpf
| Field | Required | Notes |
|---|---|---|
| `rigsignal.ebpf.drm_gpu_submit_latency_us` | ✅ Required on Linux bare-metal | Needs CAP_BPF or root |
| `rigsignal.ebpf.syscall_latency_us` | ✅ Required on Linux bare-metal | |

Docker: eBPF probe loading typically fails without `--privileged` — acceptable as 🟡.

### session
| Field | Required | Notes |
|---|---|---|
| `rigsignal.session.id` | ✅ Required | UUID generated at startup |
| `rigsignal.session.agent_version` | ✅ Required | Semver string |
| `host.name` | ✅ Required | Hostname |
| `host.os.type` | ✅ Required | `linux` or `windows` |

---

## Platform results

| Stream | Ubuntu 24.04 | Fedora 40 | Arch (clean) | SteamOS 3.9¹ | Windows 11 |
|---|---|---|---|---|---|
| cpu | ✅ | ✅ | ✅ | 🟡 (temp_c absent; APU thermal path differs) | 🟡 (PDH; no game_util) |
| gpu | ✅ | ✅ | ✅ | ✅ (VanGogh APU; no hotspot/fan — expected) | 🟡 (DXGI+PDH; wmi_acpi temp) |
| memory | ✅ | ✅ | ✅ | ✅ | ✅ |
| storage | ✅ | ✅ | ✅ | ✅ | 🟡 (aggregate only) |
| network | ✅ | ✅ | ✅ | ✅ (wifi; connection_type=wifi) | 🟡 (aggregate only) |
| audio | 🟡 (no server in Docker) | 🟡 (no server in Docker) | 🟡 (no server in Docker) | ✅ (pipewire) | 🟡 (wasapi) |
| power | 🟡 (tdp_current_w only; desktop=no AC/BAT) | 🟡 (tdp_current_w only) | 🟡 (tdp_current_w only) | ✅ (ac_connected+battery_pct+battery_rate_w+tdp) | 🟡 (AC+battery%; no rate_w) |
| frame | 🟡 (no MangoHud) | 🟡 (no MangoHud) | 🟡 (no MangoHud) | 🟡 (SSH session; no game running) | 🟡 (PresentMon required) |
| ebpf | 🟡 (no --privileged) | 🟡 (no --privileged) | 🟡 (no --privileged) | 🟡 (needs CAP_BPF/root) | n/a |
| session | ✅ (os.type+platform in host snapshot) | ✅ | ✅ | ✅ (platform=steamos; device=laptop; model=Jupiter) | 🟡 (label counter not wired) |

¹ QA matrix targeted SteamOS 3.6; actual device runs 3.9 (Valve rolling release). Results apply to both.

*Table updated as parity runs complete. F.2/F.3/F.4 Docker runs 2026-04-29 with --pid=host. F.5 SteamOS run 2026-04-29 via SSH to Steam Deck (Jupiter, kernel 6.18.22-valve1). Windows column pre-filled from live ES verification (2026-04-29 Windows run).*

---

## Known permanent limitations

| Platform | Stream | Limitation | Reason |
|---|---|---|---|
| Windows | cpu | No `game_utilisation_pct` | ETW/job objects required |
| Windows | session | `rigsignal.hardware.{cpu,gpu,ram}` empty in host snapshot | `host.rs` cpu_info/gpu_info/ram_info still read `/proc`; Windows port pending |
| Windows | gpu | `temp_source = "wmi_acpi"` (not precise) | No WinRing0 / ADLX in v0.1 |
| Windows | storage | Aggregate only; no game-process IO | No ETW disk I/O tracking |
| Windows | network | Aggregate only; tunnels filtered | No per-process network tracking |
| Windows | audio | No PipeWire clock settings | WASAPI does not expose PipeWire's `pw-metadata` settings |
| Windows | power | No `battery_rate_w` | WMI BatteryStatus rate unreliable |
| Windows | frame | Requires `PresentMon.exe` on PATH | External binary dependency |
| Windows | session | Session label counter not wired | `$LOCALAPPDATA` counter path TBD |
| SteamOS | cpu | No `temperature_c` | APU thermal sensors not in `/sys/class/hwmon` path probed by CPU collector |
| SteamOS | gpu | No `hotspot_c`, `fan_speed_rpm`, `fan_pct` | VanGogh APU shares thermals with CPU; no discrete fan hwmon |
| SteamOS | gpu | AMD only | Hardware constraint |
| Docker | gpu | No output | No /sys/class/drm passthrough |
| Docker | ebpf | No output | Requires --privileged |
| Docker | audio | No backend | No audio server in container |
| Docker | power | ac_connected may be absent | No /sys/class/power_supply |

---

## Clean-stack matrix (G4)

### How to run

```bash
bash scripts/clean-stack/matrix.sh fresh 9.4.4          # fresh install proof
bash scripts/clean-stack/matrix.sh upgrade 9.4.3        # previous-state -> current bundle
bash scripts/clean-stack/matrix.sh stackupgrade 9.4.3 9.4.4  # in-place stack upgrade
bash scripts/clean-stack/matrix.sh --keep fresh 9.4.4   # keep containers + run dir
bash scripts/clean-stack/matrix.sh --dry-run fresh 9.4.4     # command plan only
```


Fresh installs current assets and proves fixture data, assets, saved objects, and
a lifted CPU panel query. Upgrade installs the previous state, records sentinels,
installs current, and proves source hashes and counts are unchanged. Stackupgrade
reuses run-scoped named volumes with target images and reruns all asserts.
Dry-run makes no Docker or network calls; keep retains resources.

The previous state is **the 0.3.0-era production asset state, minimally adapted
to boot on a Fleet-free clean stack**. This is the honest previous version until
0.3.1 ships a real bundle (Amendment 1 / Sol F5: never install-current-twice).
Fixtures keep production structure, use lowercase host.name
fixture-host.example, and receive timestamp at ingest. CPU marker
rigsignal.cpu.total_utilisation_pct=42.25 and the connected events value are
exact asserts. Browser-visual verification is a known limitation deferred to the
app/kiosk design task. TK-4 publishes a range only after every mode passes both
endpoints.
