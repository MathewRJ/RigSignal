# Changelog

All notable changes to RigSignal will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.5] — 2026-09-09

#### Security

- **Stream-client peer identities are pseudonymised before collection.** Peer
  SteamID64s and hostnames never leave the host in the clear; they are replaced
  with per-install, keyed pseudonyms, and peer fields are omitted if the key
  cannot be safely used.
- **Asset publication resists unsafe local filesystem inputs.** Optional FIFO
  sources cannot block installation, publication files retain owner-only
  permissions despite a restrictive umask, and publication-anchor failures
  follow the documented safe failure path.

#### Fixed

- **Post-SteamOS-OTA eBPF units skip cleanly when their binary was wiped.** The
  units no longer enter a crash loop when the OTA removes the binary.
- **Setup refuses an Elasticsearch version it cannot determine by default.**
  Operators behind a proxy or hardened cluster can proceed deliberately with
  `setup --allow-unknown-version`; known versions below the supported floor
  remain refused.
- **Enrollment publication works reliably on btrfs and preserves recovery
  evidence.** Stage membership is read through fresh, fd-anchored directory
  descriptions, avoiding btrfs's readdir cutoff after files are written; an
  identity mismatch before exchange keeps the private stage for safe recovery,
  while unsupported filesystem refusals identify the filesystem when possible.

#### Changed

- **Elasticsearch support is now an enforced 9.4.3 floor, not an exact-patch
  pin.** Newer versions are allowed, while versions below 9.4.3 are refused.
- **Installation guidance now accurately describes Elastic Cloud and the
  self-hosted example.** It distinguishes the 14-day Cloud trial from a free
  tier and uses a compatible Elasticsearch image.

## [0.3.4] — 2026-08-26

#### Fixed

- **Frame telemetry no longer dies silently.** The gamescope frame source is
  resolved at collect time (symlink-preferred, FIFO-validated) instead of once
  at startup in arbitrary directory order; the reader survives writer-less
  FIFOs (non-blocking open both paths) and recovers from EOF via bounded
  demotion/rotation instead of dying permanently. Root cause of the
  Jul-21→Aug-25 fleet-wide frame outage (a decoy pipe or gamescope restart
  could wedge or kill the one-shot reader forever). Attach/detach transitions
  are logged at INFO (`Gamescope frame source attached`).
- Frame-source discovery is containment-hardened: dirfd walk with
  `O_NOFOLLOW` at every component, `fstat` on the opened fd, and uid checks
  (security-audit notes N3/N5–N8).
- GPU discovery retries at collect time for both the drm card and hwmon paths,
  so losing the boot race no longer silences GPU metrics until restart.
- Installer fish PATH-guard matches populated `config.fish` correctly
  (previous fixed-string guard could append a duplicate PATH block).

#### Changed

- Release and publish workflows validate `workflow_dispatch` version inputs
  through the repository's single SemVer contract and pass all values to
  shell steps via environment indirection; the Arch packaging step runs under
  a static `runuser` command string. The dead pre-split `integration-audit`
  workflow was removed.
- The `rigsignal_viewer` Kibana role is now source-pinned (JCS-SHA256) beside
  the existing shipper-role pin; a mutated viewer role refuses installation.
- Full-suite test discovery is isolated and order-independent
  (`tools/tests/run_shuffled.py`); suite currently 350 tests.

#### Removed

- **The eBPF daemon, probes, and systemd unit are no longer built, shipped,
  or installed** (owner ruling 2026-08-26). The shipped unit's capability
  grants contradicted SCOPE, `/usr/local` does not survive SteamOS OTAs, and
  the daemon is disabled fleet-wide. Existing installed units are left
  untouched; `restore-after-steamos-update.sh` still restores legacy
  installs that retain the unit file and cleanly reports the shelved state
  otherwise. Re-enablement is pre-registered as a design stub with hard
  preconditions (capability proof on SteamOS, persistent-path install).

## [0.3.3] — 2026-08-06

#### Added

- Assets installation now keeps a protected transaction record and re-observes
  uncertain work.  A durable `possible_mutation` record can produce exit 4 in a
  later zero-write invocation; detected pipeline/role overwrites halt with
  evidence and no automatic restoration.  See
  [asset installation recovery](docs/RECOVERY.md).
- DL2 final publication pads undersized NDJSON finals to the 1024-byte
  filestream fingerprint floor, and the shipper no longer deletes finals.

#### Residual risks accepted for this release

The eight-entry residual register is retained here for release sign-off:

1. A same-UID or root actor can create a schema-valid transaction record; the
   record does not thereby authorize divergent targets, but provenance is not
   detected.
2. **Owner-ratified:** friendly invocations using different canonical
   `XDG_STATE_HOME` domains are not serialized by the narrowed lock.
3. **Owner-ratified:** after an absent GET, pipeline/role APIs retain an
   approximately-millisecond foreign-create/PUT overwrite window.  The control
   is detect-and-halt with durable evidence, exit 4, no further writes, and no
   auto-restore—not a conditional-write claim.
4. **Owner-ratified:** the pipeline timestamp detector is ambiguous when the
   foreign create and installer PUT occur in the same millisecond; the
   ambiguity is surfaced as such and is not silently reclassified as clean
   evidence.
5. **Owner-ratified:** a foreign write followed by restoration of the identical
   canonical descriptor before the verifier GET is unobservable.
6. **Owner-ratified:** a remote replacement between ownership GET and qualified
   Elasticsearch reconciliation update can still be overwritten; pipeline
   updates use `if_version` when present and are post-update reverified.
7. With no local record, a remote Elasticsearch ownership stamp can enable
   no-flag reconciliation; deleting or selecting a different state domain is
   not an authority-preserving no-op.
8. **Owner-ratified support scope:** the mechanisms are evidenced only on
   Elasticsearch/Kibana 9.4.3 and 9.4.4.  Other versions must fail the
   capability/version gate or be separately probed.

#### DL2 roadmap and contract pair

- In 9.5+, the growing-fingerprint roadmap (`beats#50566`) removes the
  `<1kB` filestream stranding condition.  It is a roadmap residual, not a
  substitute for the current producer-side floor.
- Padding and the integration fingerprint pin are a **contract pair**.  Pin
  `df8371d` makes the 1024-byte floor explicit; a future producer that stops
  padding while the pin remains in place would silently strand small finals
  again.  Conversely, if the Integration pin regresses (removed, or its
  offset/length changed) while producers still pad to 1024, a future Beats
  default change could alter file-identity semantics — re-fingerprinting
  already-harvested finals or re-ingesting them as new files.  Neither side
  may change without the other.
- **F-D, document-only residual:** canonical origin encoding currently uses
  Python's legacy IDNA-2003 codec rather than UTS-46.  For example, `faß.de`
  canonicalizes to `fass.de` instead of `xn--fa-hia.de`; distinct origins can
  therefore merge in transaction record bindings.  This is not changed by the
  0.3.3 release work.

#### Retention caveat

A `rigsignal-*.ndjson` final is pruned only if all conditions hold: the
discovered elastic-agent reports HEALTHY, its filestream registry is readable,
the registry cursor for that final has an offset at least the file size, and
the final is older than 48 hours. Since R1 (`4ff058c`), discovery is
`RIGSIGNAL_ELASTIC_AGENT` → `PATH` → `/opt/Elastic/Agent` →
`~/elastic/elastic-agent-*/`, and the registry glob is overridable via
`RIGSIGNAL_FILESTREAM_REGISTRY_GLOB`. Any unavailable or malformed condition
skips fail-closed; finding or installing an agent alone does not enable pruning.

## [0.3.2] — 2026-08-04

### Fixed

- `rigsignal assets install` now secures its ownership-marker directory in
  preflight with a dedicated `0700` subdirectory, so it no longer fails after
  cluster assets are applied when the shared state directory is `0755` (for
  example, after the agent or a prior enrollment ran). Marker-directory faults
  now refuse cleanly before mutation and surface their real cause. Full
  partial-apply idempotency remains a documented limitation; see the
  [assets-install exit contract](docs/assets-install-exit-contract.md).

## [0.3.1] — 2026-08-01

### Added

- `rigsignal assets install` now installs the bundled asset engine across supported
  release channels, verifies matching release bundles, and can safely use an
  offline bundle when needed.
- Agent and eBPF binaries expose build identity (version and source commit) for
  provenance checks and support diagnostics.

### Changed

- `rigsignal setup` now establishes verified TLS trust with an operator-supplied
  CA certificate and keeps the user and eBPF configuration in sync.
- Linux installer releases are x86_64-only and can optionally install the
  pre-built eBPF service; Windows remains an agent-only installation.
- Packaged units and configuration transitions now consistently preserve the
  user-scoped agent configuration across distro package upgrades.

### Fixed

- Release bundle installation now rejects version or source-commit mismatches
  before changing assets, and reports actionable assets-install exit codes.
- Release checksum consumption now validates the exact requested sidecar record
  and artifact name.

## [0.3.0] — 2026-07-21

### Added

- **D6 display mode-override detector**: `rigsignal-agent diagnose display` compares
  Gamescope `modes.cfg` overrides with DRM display state, supports live collection and
  offline replay, and reports rule version `d6.1`, evidence, confidence basis,
  falsifier, and reversible suggested fixes. Its stable exit contract is 0 for `ok` or
  `not-applicable`, 1 for a real invalid/degraded override finding, and 2 for incomplete
  or invalid input/collection.
- Hardened manual post-SteamOS-OTA eBPF restore script with a self-test: validates
  connection identity and privileges before mutation, verifies attested artifacts and
  secure paths, installs atomically, preserves the unit disabled, checks the effective
  unit and acceptance state, and proves the read-only filesystem transition.

### Changed

- `host.name` is now trimmed and canonical lowercase at every userspace and eBPF
  emission boundary, avoiding case-split metrics, sessions, events, and correlations.
  In-repository dashboard grouping keys and the host selector normalize host names too.
- eBPF release builds are pinned to `nightly-2026-07-18`, `bpf-linker` 0.10.4, and a
  commit-pinned toolchain action; `xtask` now respects the workspace toolchain pin.
- AUR and WinGet package metadata now correctly identifies RigSignal as Apache-2.0
  licensed.

## [0.2.5] — 2026-07-19

### Added

- Spool durability (S2): the NDJSON spool now finalizes active batches on graceful
  shutdown, eagerly recovers stranded batches at startup (quarantining malformed input),
  prunes the old delivered/quarantined tail under a rolling retention bound, and rejects
  concurrent writers for the same spool directory via a single-writer lock.
- eBPF probe identity as a TSDS dimension (S1): each probe carries its name as a
  time-series dimension, so same-millisecond per-probe documents no longer collide on
  `_tsid` (previously dropped as version conflicts); slot-table offset encoding retired and
  unknown probes fail closed.
- Streaming-lab dashboard rows for `stream_client` telemetry.

### Changed

- Spool hardening (S2): startup recovery streams input with a 1 MiB line bound instead of
  buffering whole files; malformed sources are disposed by rename rather than full-copy
  quarantine (eliminates the OOM / 2×-disk crash-loop); and retention scans a bounded batch
  per cycle via a persistent directory cursor — no full-directory sort on the tick, and
  newly-eligible files are pruned within one cycle.

## [0.2.4] — 2026-07-18

0.2.4 arc: gpu_sched legacy port + fleet TSDS fix (shipped 2026-07-17), then item 5
(client stream telemetry) + P4 (PipeWire re-source), live-validated on a streaming-client host
(spec: `RIGSIGNAL-024-ITEM5-SPEC.md` in the Workflow repo, incl. Addendum 2026-07-18).

### Added
- `gpu_sched` legacy-tracepoint port: attach-time format parsing for both
  `drm_sched_job`/`drm_run_job` name variants (valve 6.16 era kernels), scoped-LRU
  pairing map + per-CPU loss counters; A9.2-R validated against root-ftrace ground
  truth (max latency identical, 198.0μs).
- Linux `stream_client` collector (`metrics-rigsignal.stream_client`, TSDS): Steam
  Remote Play client GPU video/gfx engine utilization from DRM fdinfo — bounded /proc
  discovery with PID-reuse guards, FD dedup by `(drm-pdev, drm-client-id)`,
  monotonic-interval deltas, `video_engine` = dec|enc|dec+enc. Client-only docs omit
  session/game groups entirely (no idle association).
- Remote Play connection events (`logs-rigsignal.events`, first producer): durable
  `remote_connections.txt` tailer with atomic XDG checkpoint, sha256 source-line
  identity as bulk `_id`, 409-as-success idempotent delivery, nack/replay on failure,
  rotation/truncation handling, local→UTC (DST-earlier) timestamps. Events always ship
  direct-ES (scoped `create_doc` key); metrics stay on the configured output mode.
- Shipper: routes by `data_stream.type` (`metrics`/`logs`), optional keyed `_id`,
  CA-trust support for self-signed Elasticsearch (`elasticsearch.ca_cert` /
  `ES_CA_CERT`, mirroring the eBPF daemon convention).
- Audio: `rigsignal.audio.quantum` + effective `sample_rate_hz` + configured
  scheduling `latency_ms` from `pw-metadata -n settings 0` (force-key precedence).

### Fixed
- Fleet-wide TSDS identity collision: same-millisecond per-probe eBPF docs shared one
  TSDB identity and were silently dropped as version conflicts; per-probe millisecond
  timestamp slots recovered ~6x eBPF telemetry (seven probes at exactly 60 docs/min).
- fdinfo engine counters parse the kernel's `<value> ns` format (live-validation catch).
- Remote Play disconnect lines with Steam's colon-reason suffix
  (`disconnected: disconnecting all`) parse correctly (live-validation catch).

### Removed
- PipeWire xrun telemetry (`rigsignal.audio.xruns`, `pw-top` path): structurally dead
  under the systemd user manager — removal is truthful, not a zero-valued replacement.

## [0.2.3] — 2026-07-17

Collector/daemon fix pack from the 2026-07-14 HFW live-monitored session (evidence-linked
backlog in `tasks/rigsignal-0.2.3-collector-fixes.md`). eBPF daemon crates align on 0.2.3.

### Fixed

- **Sparse-stream spool rotation** (item 1): rotation timer so sparse datasets flush on
  time, not only on write.
- **eBPF session watch survives file replacement** (item 2): Remove-event race on
  session.json re-arm fixed (watcher was already dir-based; diagnosis corrected).
- **eBPF coverage for games already running at daemon start** (seed fix): games running
  before the daemon/probes started produced zero `ebpf`/`ebpf_thread` docs for the whole
  session (live-pinned: FC6, 7 h). GAME_PIDS seeding now unions recorded PIDs with a
  bounded `/proc` SteamGameId/SteamAppId environ scan, walks children of every thread
  (Wine/Proton spawn from worker threads), collects up to 1024 TIDs (was 256), and
  refreshes the TID set every 30 s while a session is active.
- **frame_gen emitter unification** (item 7): all emitters use the object form; scalar
  docs from ≤0.2.2 need reindex (see docs note).

### Added

- **Gamescope frametime/stutter** (item 3): `fps.frametime_ms` + `fps.stutter_count`
  (sample-derived approximations) on the gamescope path.
- **PipeWire audio enrichment** (item 4): `sink_name`, `card_profile`, `channels`,
  `sample_format`, `sample_rate_hz`, `quantum`, `driver_latency_ms` — makes A/V-lag
  card-profile diagnosis a dashboard read.
- **Per-tick memory total** (item 6): `rigsignal.memory.total_mb`.
- **Honest session totals** (item 8): `fps_coverage_s` + documented `total_frames`
  semantics.

### Known issues

- **gpu_sched probe does not attach on SteamOS 6.16** (item 9): the valve kernel exposes
  pre-rename tracepoints (`drm_sched_job`/`drm_run_job`); probe targets the post-6.16
  names. Loader warn-skips cleanly (8/9 probes). Legacy-variant port with attach-time
  format-file offset verification is designed and scheduled for 0.2.4.
- **Client-side stream stats** (item 5): design accepted (remote_connections.txt tail +
  DRM fdinfo decode saturation); implementation in 0.2.4.

## [0.2.1] — 2026-06-11

### Fixed

- **Steam library VDF path unescaping** (`src/collectors/windows/game_detect.rs`): library paths containing backslashes (e.g. drives other than C:) were stored in `libraryfolders.vdf` with escape sequences (`\\`) that were not unescaped before filesystem lookups, causing game detection to silently fail for Steam libraries on non-default drives. Found in live Windows e2e.

- **Native D3D11/D3D12 graphics API labels** (`src/dllscan.rs`): the native Direct3D 11 and Direct3D 12 matchers were reporting translation-layer values (`dx11_via_dxvk`, `dx12_via_vkd3d`) instead of `dx11` and `dx12`, meaning games using native D3D without any compatibility layer were misclassified. Found in live Windows e2e.

- **Primary game PID chosen by working set** (`src/collectors/windows/launchers.rs`): when PresentMon was asked to attach to a game, it could latch onto a helper process (crash reporter, DRM service) that shares the same image name but has a smaller working set than the actual game. The primary PID is now selected by largest working set among all matching processes, ensuring PresentMon attaches to the render process. Found in live Windows e2e.

## [0.2.0] — 2026-06-10

### Changed

- **Renamed the project from GamePulse to RigSignal** across crates, binaries, packaging, documentation, install paths (`/etc/rigsignal/`, `~/.config/rigsignal/`), environment variables (`RIGSIGNAL_*`), and release metadata. Elasticsearch data streams move from `metrics-gamepulse.*` to `metrics-rigsignal.*` (old data ages out via ILM; no reindex). The Windows MSI carries a new product identity — GamePulse ≤ 0.1.7 must be uninstalled separately. Earlier entries in this changelog have had names updated to the current paths; the releases they describe shipped under the GamePulse name.

---

### Fixed

- **Performance / collection rate** (`src/main.rs`): per-tick Elasticsearch bulk shipping was `await`-ed synchronously inside the 1-second collection loop. Network latency or intermittent bulk errors caused each tick to take 5–7 seconds, producing choppy frame data and noticeable game performance degradation on the Steam Deck. Shipping is now spawned as a `tokio::spawn` fire-and-forget task — the collection timer runs independently of ES response times.

- **Audio collector blocking tick loop** (`src/collectors/linux/audio.rs`): `pw-top -b` (PipeWire stats) was spawned every tick and blocked ~2 seconds waiting for a PipeWire refresh cycle, reducing the collection rate from 1/sec to ~0.33/sec. PipeWire stats are now cached for 5 seconds so `pw-top` runs at most once every 5 ticks; all other ticks return the cached value instantly.

- **Launcher: env vars in wrong position crash** (`packaging/rigsignal-launcher.sh`): placing an env var after `run` (e.g. `rigsignal run RIGSIGNAL_LOG=debug %command%`) was treated as the first positional arg of the exec command and caused an immediate crash. The launcher now strips and exports leading `KEY=VALUE` args before exec, making both forms equivalent.

- **Launcher: agent stop blocked exit** (`packaging/rigsignal-launcher.sh`): the background watcher called `systemctl stop` synchronously, holding the watcher process open until the agent fully flushed and shut down. Changed to `--no-block` so the stop signal is sent and the watcher exits immediately.

- **MangoHud CSV not written with Steam Linux Runtime games** (`packaging/rigsignal-launcher.sh`): wrapping the game command with the host `mangohud` binary prevented frame timing CSV output because pressure-vessel (Steam Linux Runtime) uses its own bundled MangoHud layer which ignored the host binary's configuration. The launcher now exports `MANGOHUD=1` instead, which pressure-vessel intercepts to inject its own MangoHud — then honours `~/.config/MangoHud/MangoHud.conf` and `MANGOHUD_CONFIG` normally.

### Added

- **Windows PresentMon bundle**: the MSI now includes Intel GameTechDev PresentMon
  v2.4.1 plus MIT and third-party license texts; set `RIGSIGNAL_PRESENTMON` to
  override it with a custom copy.

- **MangoHud `autostart_log`** (`packaging/install.sh`, `packaging/rigsignal-launcher.sh`): installer now writes `autostart_log=1` to `~/.config/MangoHud/MangoHud.conf` so MangoHud writes frame timing CSVs immediately on game start without requiring an F2 keypress. Previously `output_folder` alone was insufficient — MangoHud required explicit log-start to write data. Set `RIGSIGNAL_MANGOHUD=0` to disable MangoHud integration entirely.

- **MangoHud `output_folder`**: installer now ensures `~/.config/MangoHud/MangoHud.conf` contains `output_folder=$HOME/.local/share/MangoHud` so the agent can read frame timing CSV data.

---

## [0.1.7] — 2026-05-09

### Fixed

- **eBPF nightly CI** (`ebpf/rigsignal-ebpf/src/`): five dead-code stubs (`LatencyHistogram::is_empty`, `SessionInfo::steam_app_id`, `EsShipper::batch_size`, `EsShipper::queue`, `EbpfConfig::enabled_probes`) now suppressed with per-item `#[allow(dead_code)]` — nightly's `-D warnings` was treating them as errors.
- **Smoke test**: `cpu.clock_mhz_avg` demoted to optional check — the field is absent on GitHub-hosted runners where cpufreq is not exposed.
- **Formatting**: `cargo fmt` pass on `src/diagnose.rs`, `src/profiles.rs`, `src/session.rs`, `src/shipper.rs`, `src/main.rs`.

### Added

- **Uninstaller** (`packaging/uninstall.sh`): mirrors `install.sh` in reverse — stops and disables both systemd services, removes user-space binaries, then removes system eBPF files with privilege escalation. `--user-only` skips the privileged step.
- **`--no-ebpf` flag** (`packaging/install.sh`): skip eBPF daemon install explicitly (useful on VMs or older kernels without BTF).
- **Install inventory**: `install.sh` now prints a full `Installed:` / `Not installed:` summary after completion so it's always clear what was placed on the system.

### Documentation

- `docs/README.md` retitled `# RigSignal — Elastic Integration` with a callout pointing to the project README — clarifies that this file is the Fleet integration guide bundled into the Elastic Package Registry.
- Root `README.md` documentation section rewritten as a labelled table with one row per guide and an audience column.

---

### Added (2026-05-08)

- **Launcher debug log** (`~/.local/share/rigsignal/launcher.log`): the launcher now writes timestamped entries for every key decision in `cmd_run` (agent binary resolved, systemctl outcome, PID captured, exec path taken). The log file persists across sessions and is readable in Desktop Mode after a Gaming Mode run — eliminating the "invisible crash" debugging problem. Set `RIGSIGNAL_DEBUG=1` in Steam launch options (`RIGSIGNAL_DEBUG=1 rigsignal run %command%`) to additionally capture a full shell trace (`set -x`) in the same file. Log rotates at 1 MB to `.old`.

- **Unified installer with eBPF** (`install.sh`): the Linux release tarball now includes the `rigsignal-ebpf` daemon and `rigsignal-ebpf-probes` BPF blob built in CI (nightly Rust + `bpf-linker`). `install.sh` automatically installs the eBPF daemon to `/usr/local/bin/` and its system service when `sudo` is available — no separate AUR/yay step required. On SteamOS, the installer temporarily disables the read-only filesystem (`steamos-readonly disable`) and re-enables it after. If `sudo` is unavailable or the install fails, the script degrades gracefully and reports agent-only mode.

- **eBPF build in CI** (`release.yml`): new `build-ebpf` job builds `rigsignal-ebpf-probes` (BPF target) and `rigsignal-ebpf` daemon using nightly Rust from the workspace `rust-toolchain.toml`. The eBPF binaries and a `/usr/local/`-based service file are bundled into the Linux tarball alongside the agent.

### Milestone D — Linux portable packaging (2026-04-27)

- `/proc/<pid>/maps` DLL scan for Tier 2 settings auto-detection: detects graphics API
  (VKD3D > DXVK D3D9/D3D11 > Vulkan > OpenGL), upscaler (DLSS/XeSS/FSR), and frame
  generation technology from loaded shared libraries (`src/dllscan.rs`)
- Game profile loader and three starter profiles — Starfield, Cyberpunk 2077, Baldur's
  Gate 3 — for Tier 3 settings capture (`src/profiles.rs`, `profiles/`)
- GitHub Actions release workflow: `.deb` (cargo-deb), `.rpm` (cargo-generate-rpm), and
  Arch `.pkg.tar.zst` (makepkg) attached to GitHub Releases on `v*` tag pushes
- `rigsignal-agent diagnose` subcommand: single-file bug-report dump covering kernel,
  GPU, Elasticsearch reachability, and resolved config path
- Unified logging flags: `--verbose` / `--log-level LEVEL` / `--print-config` (redacted)

### Milestone C — Windows collectors (2026-04-26)

- Full 8-stream Windows support: CPU (PDH), memory (Win32), storage (PDH), network (PDH),
  power (GetSystemPowerStatus), audio (WASAPI), GPU (DXGI VRAM + PDH util + WMI temperature),
  frame timing (PresentMon subprocess with auto-discovery)
- PDH infrastructure (`src/collectors/windows/pdh.rs`) wrapping Windows Performance Counters
- `rigsignal.gpu.temp_source` field distinguishing `hwmon` (Linux) from `wmi_acpi` (Windows)
- Platform parity gaps documented: `cpu.game_utilisation_pct`, `gpu.power_w`, `audio.xruns`,
  `storage.game_io` require ETW/vendor SDK and are deferred to later milestones

### Milestone B2 — Launcher-agnostic game detection (2026-04-25)

- Multi-launcher game detection: Lutris (YAML game configs + WINEPREFIX scan), Heroic
  (Epic and GOG via installed.json), Bottles (bottle.yml + WINEPREFIX), plus manual
  `--target-pid` / `--target-name` override flags
- `rigsignal.game.source` and `rigsignal.game.launcher` fields on all session and metric docs
- Proton/Wine env var enrichment (`PROTON_VERSION`, `DXVK_CONFIG_FILE`) wired to all launchers
- `steam_app_id` made conditional (present only when `source == steam`)

### Milestone B — Cross-platform refactor (2026-04-24)

- Unified `Collector` trait (`Send + 'static`) with platform-gated `linux::*` / `windows::*`
  implementations; `build_collectors()` dispatch replaces per-platform main.rs branches
- Linux collectors relocated to `src/collectors/linux/`; Windows stubs added in
  `src/collectors/windows/` (replaced with real implementations in Milestone C)
- GitHub Actions CI matrix: `cargo check` + `cargo clippy -- -D warnings` on
  `ubuntu-latest` and `windows-latest` for every push to `main` and every PR
- eBPF feature flag (`--features ebpf`) with compile-time Linux guard
- Session label counter: format changed from `<slug>-YYYYMMDD-HHMMSS` to `<slug>-YYYYMMDD-N`;
  counter persisted atomically to `$XDG_STATE_HOME/rigsignal/session-counters.json`
- Tier 1 settings capture: `[session.settings]` TOML section and CLI flags `--preset`,
  `--upscaler`, `--frame-gen`, `--features`, `--resolution`, `--vsync`, `--notes`
- Signal handling ported to cross-platform (`tokio::signal::ctrl_c` on Windows)

---

## [0.1.6] — 2026-05-08

### Fixed

- **Gamescope / Gaming Mode — wrong process tree (launcher)**: `cmd_run` was running the game as a *subprocess* of the launcher shell (`"$@"`), making it a grandchild of Steam. Gamescope requires the game to be the *direct* child of Steam to assign the correct cgroup and display priority; running it one level deeper caused the session to crash or be killed. Fixed by replacing the trap + subprocess + exit pattern with a background PID watcher + `exec "$@"` so the launcher shell is replaced by the game process in-place. The watcher monitors `/proc/<launcher_pid>` (which after exec is the game pid) and stops the agent service when the game exits.

---

## [0.1.5] — 2026-05-08

### Fixed

- **Gamescope / Gaming Mode crash (launcher)**: `systemctl --user reset-failed` is now called before `start` in `cmd_run` so a FAILED unit (from a prior crash loop hitting the restart rate limit) is properly reset instead of silently failing to start. The `wait_agent_active` poll that previously blocked game launch for up to 10 seconds is removed — the agent detects already-running games by scanning `/proc`, so the game launches immediately regardless of agent initialisation state. This prevents Gamescope session-launch timeouts from killing the game before it renders.

---

## [0.1.4] — 2026-05-08

### Fixed

- **Gamescope / Gaming Mode (launcher)**: `cmd_run` now falls back to running `rigsignal-agent` directly in the background when `systemctl --user` fails (DBUS absent in Gamescope). Previously the launcher exited, preventing the game from launching. The agent binary is resolved relative to the launcher's own directory so `~/.local/bin` does not need to be on PATH in the gamescope session.

---

## [0.1.3] — 2026-05-08

### Fixed

- **Elasticsearch 403 on startup**: Ping endpoint changed from `GET /` (requires `cluster:monitor/main`) to `GET /_cluster/health` (requires `cluster:monitor/health`). HTTP 4xx responses from the ping are now non-fatal — the agent continues and ships data even if the health check returns 401/403/410.

---

## [0.1.0] — 2026-03-30

### Added

**Core Agent**
- Rust-based telemetry agent with 1-second collection interval
- TOML configuration with CLI overrides
- Graceful shutdown via Ctrl+C / SIGTERM
- Debug mode (`--debug`) for stdout output without Elasticsearch
- Single-pass mode (`--once`) for testing

**GPU Metrics**
- AMD GPU support via sysfs/hwmon (utilisation, clocks, VRAM, temps, power, fan, voltage, PCIe)
- NVIDIA GPU support via dynamic NVML loading (cross-platform, no compile-time SDK dependency)
- Auto-detection of GPU vendor on startup
- Thermal throttle detection

**CPU Metrics**
- Per-core utilisation, clock speeds, temperature (k10temp/coretemp)
- Package power via RAPL
- CPU governor and boost state detection

**Memory Metrics**
- System RAM and swap usage
- Memory pressure via Linux PSI
- Dirty pages and buffer/cache breakdown

**Storage Metrics**
- Drive type classification: NVMe, SATA SSD, HDD, SD card, USB, eMMC
- Filesystem detection with mount options (btrfs compression, TRIM, scheduler)
- Per-second I/O: throughput, IOPS, latency, queue depth, merged operations
- Drive temperature monitoring
- SD card speed class detection (UHS, A1/A2, V30)
- Encryption detection (LUKS)

**Network Metrics**
- Interface throughput (bytes/packets per second)
- TCP retransmit tracking
- Active connection count
- Auto-detection of primary interface and connection type (ethernet/wifi)

**Game Detection**
- Automatic Steam game detection via `/proc` environment scanning
- Steam App ID resolution from appmanifest files
- Multi-library support (standard, Flatpak, Snap Steam installations)
- Graphics API detection (Vulkan, DX11 via DXVK, DX12 via VKD3D-Proton)
- Wine/Proton helper process filtering

**Compatibility Detection**
- Proton version (from env vars, tool paths, Steam config, version files)
- Wine version (from Proton bundle)
- DXVK version (from Proton directory, DXVK logs)
- VKD3D-Proton version
- Mesa version (via vulkaninfo or glxinfo)
- Gamescope version

**Frame Timing**
- MangoHud CSV log parsing (incremental, low overhead)
- Gamescope stats integration
- FPS percentiles: average, 1% low, 0.1% low
- Frame time statistics: avg, min, max, standard deviation
- Stutter detection (frames exceeding 33ms)

**Per-Process Game Metrics**
- Game process RSS/VMS/shared memory
- Major/minor page fault rates
- Context switch rates (voluntary + involuntary)
- Per-process I/O read/write bytes
- CPU user/kernel time
- Open file descriptor count

**eBPF Deep Telemetry (Linux, requires CAP_BPF)**
- Block I/O latency histograms (biolatency)
- Scheduler run-queue latency (schedlatency)
- VFS read/write latency per game process
- Syscall count and latency profiling
- Page fault latency
- Futex contention (thread sync bottlenecks)
- TCP retransmit tracing
- GPU command submission latency (amdgpu_cs_ioctl)
- GPU fence wait time (dma_fence_wait — CPU stalled on GPU)
- Automatic stutter cause correlation

**Device Detection**
- Steam Deck LCD/OLED identification
- ROG Ally, Legion Go detection
- Laptop vs desktop classification (DMI chassis type)
- Power source detection (AC/battery)

**Analytics**
- Hardware tier classification (Enthusiast/High/Mid/Low/Integrated)
- Per-session summary with avg/median FPS, stutter rate, thermal stats
- Comparison query builders: driver impact, Proton impact, OS comparison, kernel impact, storage impact

**Elasticsearch Integration**
- Bulk API shipping with configurable batching
- Index lifecycle management (hot → warm → cold → delete)
- Index templates for sessions, metrics, eBPF, and events
- Ingest pipeline: hardware tier classification, FPS bracket tagging, throttle detection, stutter tagging
- Continuous transform for community aggregation
- FPS regression watcher (6-hour schedule)
- API key and basic auth support

**Distribution**
- Systemd services (system-level and user-level)
- Debian package (.deb) with postinst
- RPM spec file
- AUR PKGBUILD (Arch Linux / Steam Deck)
- Elastic Agent Fleet integration manifest
- Interactive install script with hardware auto-detection
- Makefile with build, test, install, and package targets
- GitHub Actions CI/CD (build, lint, test, release)

**Kibana**
- Pre-built dashboard with 7 panels (FPS, GPU, CPU, memory, storage, frame time, sessions)
- NDJSON export for easy import
