# RigSignal — Project Status

Last updated: 2026-09-09 (0.3.5 release)
Active streams: main (local ElasticHome deployment) + offline (air-gapped, not yet forked)

## Publication hygiene — 2026-09-10

Captured host references in prose now use synthetic `.example` names and documentation
addresses. Producer link-local IPv6 addresses in journal tails now use a documentation
address; public DNS/NTP endpoints remain. Boot IDs are omitted from capture-note tables. Assertion-bearing test data and
boot-pairing fixture IDs are retained; dashboard selectors are reserved for a separate PR.

**Removal at HEAD does NOT unpublish.** These identifiers are already inside released
archives, and AUR clones the full repository at every version. Only history rewriting would
unpublish them from repository history, and that breaks every clone and AUR's `pkgver()`;
it cannot recall archives or clones already distributed. This is a hygiene change for what
ships next, not retrospective remediation. Historical command examples use placeholders
and must be adapted before use.

## Decision record — supported stack floor (supersedes TK-4, 2026-08-27)

Supported Elasticsearch/Kibana: **9.4.3 or newer**, Kibana at the same version — a **floor with no
upper bound**, enforced in the launcher as `ES_SUPPORTED_FLOOR_VERSION`. Versions above 9.4.4 are
not matrix-tested but are expected to work. An **undeterminable** ES version is **refused** by
default; `setup --allow-unknown-version` is the explicit operator opt-out, and it gates *only* the
undeterminable branch — a version that is determinable and below the floor stays refused either
way (`b5e68f7`, PR #15).

This **supersedes the TK-4 exact-patch range (9.4.3 – 9.4.4, 2026-07-22)**, which is retained only
as history. The matrix evidence is unchanged and still bounds what is *tested*: the G4 clean-stack
matrix (5 legs, 162 asserts) proved fresh install + previous-state→bundle upgrade at both
endpoints + in-place 9.4.3→9.4.4 stack upgrade; image digests in Workflow
`projects/Workflow/evidence/pilot-readiness-2026-07-22/`. The distinction that changed: *tested
range* and *supported range* are no longer the same thing — "newest" was never an acceptance
criterion, and the floor now moves independently of the test endpoints.

Per STRATEGY-2026H2.md Amendment 1: G3 pilot deferred; the floor serves the turnkey bar (the
bundled local stack pins to a tested version).

## For AI agents reading this file

- This file is the single source of truth for project state.
- claude.ai (planning) reads at session start, writes at session end.
- Claude Code (implementation) reads at session start, writes after each WP completion.
- Other agents (Codex, etc.) follow the same contract.
- Update the "Last updated" line on every edit.
- Move completed work packages to "Completed work" — never delete.
- Historical narrative lives in `docs/HANDOFF.md`; do not duplicate it here.
- See `CLAUDE.md` for workflow rules, protected files, and validation commands.

## At a glance — main branch

| Milestone | Status | Progress |
|---|---|---|
| A  Docs reorganisation | 🟢 Done | ▓▓▓▓▓▓▓▓▓▓ |
| B  Cross-platform refactor | 🟢 Done | ▓▓▓▓▓▓▓▓▓▓ |
| B2 Launcher-agnostic game detection | 🟢 Done | ▓▓▓▓▓▓▓▓▓▓ |
| B3 Automatic game detection | 🟡 In progress (B3.0 ✅ cfg-gate; B3.1+ design TBD) | ▓░░░░░░░░░ |
| C  Windows collectors | 🟢 Done (C.0–C.8) | ▓▓▓▓▓▓▓▓▓▓ |
| D  Linux portable packaging | 🟢 Done | ▓▓▓▓▓▓▓▓▓▓ |
| E  Windows packaging | 🟢 Done | ▓▓▓▓▓▓▓▓▓▓ |
| F  Cross-platform parity verification (M2) | 🟢 Done | ▓▓▓▓▓▓▓▓▓▓ |
| G  elastic/integrations PR (M4) | 🟡 Deferred (maintainer architecture rework + `fields.yml` gating) | ▓░░░░░░░░░ |
| 0.2.4 release | 🟢 Released 2026-07-18 | ▓▓▓▓▓▓▓▓▓▓ |
| 0.2.5 release | 🟢 Released + deployed 2026-07-19 (both hosts) | ▓▓▓▓▓▓▓▓▓▓ |
| 0.3.2 release — packaging and asset-install hardening | 🟢 Published 2026-08-04 | ▓▓▓▓▓▓▓▓▓▓ |
| 0.3.3 release — idempotency and DL2 recovery carries | 🟢 Published 2026-08-06 | ▓▓▓▓▓▓▓▓▓▓ |
| 0.3.4 release — frame-source fix, input hardening, eBPF unship | 🟢 Published 2026-08-26 | ▓▓▓▓▓▓▓▓▓▓ |
| 0.3.5 release — security hardening, packaging guards, fd-anchored publication | 🟢 Published 2026-09-09 | ▓▓▓▓▓▓▓▓▓▓ |

## At a glance — offline branch (not yet forked)

| Milestone | Status |
|---|---|
| H1  Branch + docs-sync automation | ⚪ Not started |
| H2  Bundled stack | ⚪ Not started |
| H3  Offline install flow | ⚪ Not started |
| H4  Export tooling | ⚪ Not started |

## Feature capability matrix

| Feature | Linux | Windows | Offline |
|---|---|---|---|
| Core metrics (8 streams) | ✅ | 🟡 (8/8 implemented; gaps documented) | ✅ (inherited) |
| eBPF deep probes | ✅ | n/a | ✅ (inherited) |
| Settings Tier 1 — manual CLI/config | ✅ | 🔲 | ✅ (inherited) |
| Settings Tier 2 — auto-detect (DLL/ETW) | ✅ (/proc/maps) | ✅ (EnumProcessModules) | ✅ (inherited) |
| Settings Tier 3 — per-game config profiles | ✅ | 🔲 | ✅ (inherited) |
| Session label (per-game-per-day counter) | ✅ | 🔲 | ✅ (inherited) |

## Platform parity matrix (populated during M2)

| Stream | Ubuntu 24.04 | Fedora 40 | Arch/CachyOS | SteamOS 3.6 | Windows 11 |
|---|---|---|---|---|---|
| cpu | ✅ | 🔲 | ✅ | 🔲 | 🟡 (PDH; no game_util) |
| gpu | ✅ (AMD) | 🔲 | ✅ (AMD) | 🔲 | 🟡 (DXGI VRAM + PDH util; temp wmi_acpi) |
| memory | ✅ | 🔲 | ✅ | 🔲 | ✅ |
| storage | ✅ | 🔲 | ✅ | 🔲 | 🟡 (aggregate only; no per-disk/game IO) |
| network | ✅ | 🔲 | ✅ | 🔲 | 🟡 (aggregate only; tunnels filtered) |
| audio | ✅ | 🔲 | ✅ | 🔲 | 🟡 (backend=wasapi) |
| power | ✅ | 🔲 | ✅ | 🔲 | 🟡 (AC + battery%; no rate_w) |
| frame | ✅ (MangoHud) | 🔲 | ✅ (MangoHud) | 🔲 | 🟡 (PresentMon subprocess; external binary required) |
| ebpf | ✅ | 🔲 | ✅ | 🔲 | n/a |
| session | ✅ | 🔲 | ✅ | 🔲 | 🟡 Partial[^windows-session-parity] |

[^windows-session-parity]: Expected absent on Windows: `rigsignal.compatibility.proton_version` and `rigsignal.compatibility.dxvk_version` are Wine concepts; `rigsignal.hardware.*` remains pending Windows support in `host.rs`. Launcher detection (Steam/Epic/GOG), manual attach, and PresentMon bundling landed 2026-06-10.

## Active work package

**0.3.5 is published** (tag `v0.3.5`, 2026-09-09). It includes peer-identity
pseudonymisation, safe asset-publication hardening, the eBPF post-OTA unit
guard, and fd-anchored publication/idempotency coverage.
Historical: 0.3.4 (2026-08-26) shipped the frame-source lifecycle fix,
containment hardening, GPU collect-time retry, workflow-input validation, the
viewer-role source pin, and the eBPF daemon/unit unship.

**Retention caveat (R1).** A final is pruned only when the discovered
elastic-agent is HEALTHY, its registry is readable, the matching
`rigsignal-*.ndjson` file has a harvested cursor with offset at least its size,
and it is older than 48 hours. R1 is merged (`4ff058c`): agent discovery is
`RIGSIGNAL_ELASTIC_AGENT` → `PATH` → `/opt/Elastic/Agent` →
`~/elastic/elastic-agent-*/`, with the registry glob overridable via
`RIGSIGNAL_FILESTREAM_REGISTRY_GLOB`. Any unavailable or malformed input skips
fail-closed; pruning is a per-host outcome, not a portable guarantee.

**0.2.4 released 2026-07-18.** It delivers the legacy `gpu_sched` port, fleet TSDS fix, client stream telemetry, and PipeWire re-source.

**0.2.5 released + deployed 2026-07-19** (tag `v0.2.5`, RigSignal `34882fe`). Delivers S2 spool
durability + hardening and S1 probe-as-TSDS-dimension. The A6-24h retention gate PASSED at
2026-07-19T18:43:24Z and was sealed before release; the 0.2.5 agent (`dca30eae`) is live on both
the streaming-client and gaming hosts with zero-gap continuity. eBPF daemons deferred
(version-string-only rebuild).

**0.3.0 released 2026-07-21** (tag `v0.3.0`). Ships D6, RigSignal's first diagnostic-evidence-engine
detector: `rigsignal-agent diagnose display` compares a Gamescope `modes.cfg` override against
DRM display state and reports a verdict, cited evidence, confidence, and a falsifier (exit
contract 0/1/2). D6 shipped end-to-end through a 5-stage QC chain (Codex-sparred spec, reviewer
approval, adversarial hardening, and a live gaming-host replay that caught 2 live-path bugs invisible
to tests/review). Also in this release: `host.name` canonical-lowercase normalization at every
emission boundary, and pinned/hardened eBPF release-build toolchain. See `CHANGELOG.md` and
`.github/RELEASE_NOTES.md` for the full release notes.

**Deployment.** The local ElasticHome Elasticsearch stack is active (cloud migrated 2026-07-09). Agents run on the gaming host and the streaming client in spool-file output mode.

**Distribution.** `rigsignal-git` is live on AUR and `install.sh` is live (now installing pre-built
eBPF from the Linux tarball as of 0.3.0). `.deb`/`.rpm`/`.pkg.tar.zst` packages are agent-only (no
eBPF). There is no winget package — it remains unavailable/closed pending the elastic/integrations
architecture rework. elastic/integrations PR #18878 remains deferred for the maintainer
architecture rework and `fields.yml` gating.

**D3 GPU-boot detector.** `rigsignal-agent diagnose gpu-boot` is implemented with explicit-slot
baselines, authoritative PCI sysfs collection, bounded boot-ID-addressed journald collection,
offline replay, and stateful one-time recovery reporting. It remains pending the orchestration
gate; see `docs/diagnose-gpu-boot.md`.

## Completed work

### Release 0.3.0 (released, 2026-07-21, tag `v0.3.0`)

- **D6 display mode-override detector**: `rigsignal-agent diagnose display` compares Gamescope
  `modes.cfg` overrides against DRM display state (from a live Gamescope session, or offline via
  `--modes-cfg` + `--drm-state` replay). Reports `detector_id`, `rule_version` (`d6.2`), a
  `verdict` (`ok` | `mode-override-invalid` | `mode-override-degraded` | `not-applicable`),
  `confidence`, `confidence_basis`, cited `evidence`, `plain_language` summary, reversible
  `suggested_fix`(es), a `falsifier`, `supported_scope`, `missing_evidence`, and a
  `nearest_alternative`. Exit contract: `0` for `ok`/`not-applicable`, `1` for a real finding,
  `2` for incomplete/invalid invocation. `--json` and `--host` flags supported.
  Shipped through a 5-stage QC chain (Codex-sparred spec, reviewer approval, adversarial
  hardening, and a live gaming-host replay that caught 2 live-path bugs invisible to tests/review); see
  `docs/diagnose-display.md` for the full field reference and a real replay transcript.
- **`host.name` normalization**: all emission boundaries (agent, eBPF daemon, events tailer) now
  trim and lowercase `host.name` consistently, fixing dashboards that were splitting one physical
  host into multiple case-variant buckets.
- **Hardened SteamOS post-OTA eBPF restore script**: self-tests connection identity and
  privileges before mutation, verifies attested artifacts and secure paths, installs atomically,
  and scopes its acceptance check to the current boot's journal cursor (previously a fixed line
  count, which false-aborted on multi-boot machines).
- **Toolchain pinning**: eBPF release builds pin `nightly-2026-07-18` + `bpf-linker` 0.10.4 with a
  commit-pinned toolchain action, so release eBPF artefacts are reproducible.
- **Distribution**: the Linux tarball (`rigsignal-0.3.0-linux-x86_64.tar.gz`) now ships the
  pre-built eBPF daemon and probes alongside the agent; `install.sh` installs and starts eBPF
  automatically (one sudo prompt, `--no-ebpf` to skip). `.deb`/`.rpm`/`.pkg.tar.zst` packages
  remain agent-only. AUR/WinGet package metadata corrected to Apache-2.0 licensing; winget itself
  remains unavailable.

### Release 0.2.4 (released, 2026-07-18)

- Legacy GPU scheduler support now parses tracepoint formats at attach time and accepts the `drm_sched_job`/`drm_run_job` name variants used by Valve 6.16-era kernels.
- Fleet TSDS fix, client stream telemetry, and PipeWire re-source shipped with the release.

### Milestone E — Windows packaging (complete, 2026-04-29)

- **E.1 — WiX 3 installer source** (`.github/packaging/main.wxs`, hand-authored): single `Product` with `MajorUpgrade` (afterInstallInitialize, blocks downgrade), `perMachine` `InstallScope`, `ProgramFiles64Folder` rooted at `APPLICATIONFOLDER` named `RigSignal`. Three sibling subdirs — `bin\` (component `AgentBinary` with `rigsignal-agent.exe`), `config\` (`ConfigExample` with `rigsignal.toml.example`), `profiles\` (`Profiles` with three TOML files). System PATH `bin\` entry via separate `PathEntry` component (`Environment` element, `Part='last'`, `System='yes'`). Stable GUIDs: UpgradeCode `862FBC47-5257-4EC9-9854-0D10D2B8FD29`, AgentBinary `335B8F3D-…`, PathEntry `CC21BF89-…`, ConfigExample `95548900-…`, Profiles `17D6C34F-…` (changing any of these breaks upgrade detection or orphans uninstall; all five were issued fresh at the RigSignal rename so the retired GamePulse MSI shares no component identity). `ARPINSTALLLOCATION` + `ARPHELPLINK` + `ARPURLINFOABOUT` set so Add/Remove Programs shows the install path and links to the GitHub repo.

- **E.2 — cargo-wix metadata in `src/Cargo.toml`**: `[package.metadata.wix]` block with `upgrade-guid` + `path-guid` matching the wxs source, `license = false`, `eula = false`. Build invocation in CI: `cargo wix --no-build --nocapture --include .github/packaging/main.wxs src/Cargo.toml` — `--no-build` because the Rust binary is built in a separate CI job and downloaded as an artifact, `--include` so cargo-wix uses our hand-authored wxs instead of generating one.

- **E.3 — Release workflow Windows job rewired**: `package-windows` job in `.github/workflows/release.yml` switched from the zip placeholder to MSI: installs Rust toolchain (Swatinem rust-cache for incremental cargo-wix builds), `actions/download-artifact@v4` lands the agent binary at `target/release/`, `cargo-bins/cargo-binstall@main` provides the cargo-binstall extension, `cargo binstall cargo-wix --no-confirm --locked` installs the cargo-wix subcommand pre-built (no source compile), `cargo wix` builds the MSI, artifact is `target/wix/*.msi` named `windows-package`. Final release job picks up the artifact via the existing `softprops/action-gh-release` glob.

- **E.4 — Windows config fallback chain**: `src/config.rs::Config::load()` now branches on `cfg(windows)`: Windows fallback chain is `%APPDATA%\RigSignal\rigsignal.toml` (per-user) then `%PROGRAMDATA%\RigSignal\rigsignal.toml` (system-wide); Linux unchanged (`~/.config/rigsignal/rigsignal.toml` then `/etc/rigsignal/rigsignal.toml`). CLI `--config` and `$RIGSIGNAL_CONFIG` env var precedence unchanged across both platforms. Doc-comment on `Config::load` lists both chains.

- **E.5 — `RELEASE_NOTES.md` Windows section**: Added install via `msiexec /i ... /qb!` and uninstall via `msiexec /x` or *Settings → Apps*. Documents: PATH integration (`rigsignal-agent` from any new shell), absent `rigsignal setup` launcher (Windows-side TODO), `notepad` walkthrough for hand-authoring `%APPDATA%\RigSignal\rigsignal.toml`, env-var alternative (`ES_URL` + `ES_API_KEY`), Windows-specific PowerShell start/stop snippets (no systemd analogue yet), and a "Windows caveats" block enumerating the four fields that don't populate on Windows in this release (`cpu.game_utilisation_pct`, `storage.game_io`, `audio.quantum`, `power.battery_rate_w`) plus the PresentMon optional-dep note.

- **E.6 — CLI help strings de-Linux-ified**: `src/main.rs` clap `about` changed from "RigSignal Linux telemetry agent" to "RigSignal cross-platform gaming telemetry agent". `--config` doc-comment now enumerates Linux and Windows fallback chains (clap's default-value display string was the only place that lied about Windows behaviour after E.4).

- **E.7 — Local install/uninstall round-trip on Windows 11**: `cargo wix` produced `target/wix/rigsignal-agent-0.1.0-x86_64.msi` (2.7 MB, contains 5 files at expected names + sizes). Elevated `msiexec /i` (UAC `/qb!`) exit 0, files at `C:\Program Files\RigSignal\{bin,config,profiles}\` with correct sizes (6.7 MB exe, 225 B config example, 3 profile TOMLs), system PATH gained `C:\Program Files\RigSignal\bin\`, `rigsignal-agent.exe --help` runs cleanly via PATH. Elevated `msiexec /x` exit 0, install dir removed cleanly, PATH entry removed cleanly. `cargo check` + `cargo clippy -- -D warnings` green; `cargo fmt --check` shows pre-existing drift in 5 files unrelated to this milestone (`config.rs` and `main.rs` changes within this milestone are correctly formatted). `cargo test` blocked by Windows Application Control policy (`os error 4551`) on this machine — not a code issue, tests gate on Linux.

### Milestone D — Linux portable packaging (complete, 2026-04-29 — D.1/D.2 smoke tests done)

- **D.2 — Fedora 40 `.rpm` smoke test**: Built `rigsignal-agent-0.1.0-1.x86_64.rpm` via `cargo generate-rpm`. Ran `rpm -ivh` in a clean `fedora:40` container. Install PASS. All assets verified: `/usr/bin/rigsignal-agent` (755), `/usr/bin/rigsignal` launcher (755), `/etc/rigsignal/rigsignal.toml` (644, config=true), `/usr/lib/systemd/user/rigsignal-agent.service` (644), three profile files under `/usr/share/rigsignal/profiles/`. Binary runs (`--help` prints usage). Container: Docker 29.4.1 on kernel 7.0.2.

- **D.1 — Ubuntu 24.04 `.deb` smoke test**: Built `rigsignal-agent_0.1.0-1_amd64.deb` via `cargo deb --no-build --no-strip`. Ran `dpkg -i` in a clean `ubuntu:24.04` container. Install PASS. All assets verified: `/usr/bin/rigsignal-agent` (755, 8.5 MB), `/usr/bin/rigsignal` launcher (755), `/etc/rigsignal/rigsignal.toml` (644), `/usr/lib/systemd/user/rigsignal-agent.service` (644), three profile files under `/usr/share/rigsignal/profiles/`. Binary runs (`--help` prints usage). Note: `dpkg-shlibdeps` unavailable on build host (CachyOS) so `$auto` deps resolved to none — acceptable for initial smoke test; CI build on `ubuntu-latest` will resolve correctly. Container: Docker 29.4.1 on kernel 7.0.2.

- **D.8 — `/proc/<pid>/maps` DLL scan — Tier 2 settings auto-detection**: New `src/dllscan.rs` module. `read_mapped_paths(pid)` parses `/proc/<pid>/maps`, extracts file-backed paths (those starting with '/'), lowercases them for case-insensitive matching, and returns an empty Vec gracefully on any read error (cross-platform safe). Three detection functions (all `pub(crate)`, tested with mock path slices): `detect_graphics_api_from_paths` — priority chain VKD3D > DXVK D3D9 > DXVK D3D11 > Vulkan > OpenGL (all fragments lowercase to match lowercased paths); `detect_upscaler_from_paths` — DLSS (nvngx_dlss) > XeSS (xess) > FSR (ffx_fsr/libffx_fsr/amd_fidelityfx_vk/openfsr); `detect_frame_gen_from_paths` — DLSS3 (nvngx_dlssg/dlss_fg/dlssg.dll) > FSR3 (ffx_framegeneration/ffx_fsr3framegen) > AFMF. Two public functions: `graphics_api_from_maps(pid)` and `settings_overlay_from_maps(pid)` (builds `{ rigsignal.settings.* }` with `source="auto_detected"`, `confidence="medium"`, returns Null when nothing detected). Wired in `session.rs`: new `graphics_api_with_maps_fallback(env, pid)` helper calls `detect_graphics_api(env)` first; falls back to `graphics_api_from_maps(pid)` when env returns None. Replaces all 5 `detect_graphics_api` call sites (Lutris, Heroic, Bottles, Steam, UserSpecified). Wired in `main.rs` `GameStarted` arm: `settings_overlay_from_maps(target.pid)` merged after the D.7 profile block with existing overlay winning (maps is lowest precedence). 13 dllscan unit tests + bug fix (libGL.so/libGLX.so fragments lowercased). 26/26 tests green.

- **D.7 — Game profile loader + three starter profiles (Tier 3 settings)**: New `src/profiles.rs` module: `GameProfile`/`GameMeta`/`ProfileSettings` structs (TOML Deserialize); `find_profile(target)` — searches profile dirs with Steam AppID exact-match taking precedence over case-insensitive name/alias substring match; `to_overlay(profile)` — builds `{ rigsignal.settings.* }` JSON with `source="profile"` `confidence="medium"`, returns Null when no fields set; `profile_dirs()` — ordered search: `$RIGSIGNAL_PROFILES_DIR` → `~/.config/rigsignal/profiles/` → `/etc/rigsignal/profiles/` → `/usr/share/rigsignal/profiles/` → `{exe}/../../profiles/` (dev fallback). `main.rs` integration: `base_settings_overlay` snapshot taken after session creation; `GameStarted` calls `find_profile()` and if matched, `deep_merge(profile_ov, base)` (CLI/config wins), updates `session.settings_overlay` before `build_game_detected_doc()`; `GameEnded` restores base overlay after summary ships so next game starts clean. Three starter profiles at `profiles/`: Starfield (app 1716740, FSR 2, ray tracing, ultra), Cyberpunk 2077 (app 1091500, DLSS 3.5/FSR 3/XeSS, path tracing, dlss3 frame-gen), Baldur's Gate 3 (app 1086940, Vulkan, no native upscaler). Packaging: profiles added to cargo-deb, cargo-generate-rpm, and CI PKGBUILD (installs to `/usr/share/rigsignal/profiles/`). `cargo check` + `cargo clippy -- -D warnings` + `cargo test` (12/12) green.

- **D.6 — GitHub Actions release workflow**: On `git push` of a `v*` tag: (1) `build` job compiles the agent release binary on `ubuntu-latest`; (2) `package-deb` uses `cargo-deb` (via cargo-binstall) to produce a `.deb` with binary + rigsignal launcher + systemd user unit + example config — files in `/etc/` auto-marked conffiles; (3) `package-rpm` uses `cargo-generate-rpm` for `.rpm` with `config=true` on the TOML; (4) `package-arch` runs `makepkg` in `archlinux/archlinux:latest` using a CI-only PKGBUILD at `.github/packaging/PKGBUILD` (agent-only, no eBPF, pre-built binary, unprivileged builder user, PKGVER injected via sed); (5) `release` uses `softprops/action-gh-release` to create the GitHub Release and attach all three artifacts with auto-generated release notes. `[package.metadata.deb]` and `[package.metadata.generate-rpm]` added to `src/Cargo.toml`; asset paths relative to `src/` (manifest dir). eBPF excluded from CI packages (nightly + bpf-linker toolchain not available); AUR PKGBUILD unchanged. `cargo check` + `cargo test` (8/8) green.

- **D.5 — `rigsignal diagnose` subcommand**: Added `rigsignal-agent diagnose [--output <PATH>]` — a single-file bug-report snapshot covering kernel version, OS, CPU, RAM, GPU (vendor/model/VRAM/driver/Mesa/Vulkan), Elasticsearch reachability (endpoint + auth kind + ping status; api_key redacted), resolved config file path, and a trailing log of every probe step taken during the run. Converted flat `Cli` struct to a `Commands` subcommand enum; dispatch order is `--print-config` → `diagnose` → `--dry-run` → main loop (fully backward-compatible). New `src/diagnose.rs` module (~160 lines); no new crate deps. `cargo check`, `cargo clippy -- -D warnings`, `cargo test` (8/8) all green. Live smoke test: ES REACHABLE, full report emitted cleanly to stdout.

- **D.3 — Unified CLI logging flags + --print-config**: Added `-v`/`--verbose` (sets debug level), `--log-level <LEVEL>` (error|warn|info|debug|trace; validated by clap, overrides --verbose and RIGSIGNAL_LOG), and `--print-config` (prints resolved config as TOML with api_key/username/password redacted, exits 0). Precedence: --log-level > --verbose > RIGSIGNAL_LOG > "info". `resolve_log_filter()` helper is a pure function — unit tested (`test_log_level_from_cli`, 8/8 total tests pass). `Config` and all sub-structs now derive `Clone + Serialize`; `redacted_for_display()` method masks sensitive fields. No new crate deps (uses existing `toml` + `tracing-subscriber`). `cargo check`, `cargo clippy -- -D warnings`, `cargo test` all green. Smoke tests: invalid `--log-level banana` gives clean clap error; `--print-config` on live config outputs valid TOML with `api_key = "<redacted>"`. Unblocks D.5 (diagnose subcommand needs --log-level to control verbosity).

### Milestone C — Windows collectors (complete, 2026-04-26 session 4 — C.8 PresentMon)

- **C.8 — Frame timing collector**: Replaced `src/collectors/windows/frame.rs` stub. Defines a `pub(crate) FrameSource` trait (`next_sample`, `attach`, `detach`) so the backend can swap (e.g., to ETW-direct via the Microsoft PresentMon SDK) without touching `FrameCollector` or `main.rs`. `PresentMonSource` spawns `PresentMon.exe --process_id <pid> --output_stdout --stop_existing_session`, parses the CSV header to discover the `MsBetweenPresents` column index by name (resilient to PresentMon 1.x→2.x column renames), and runs a background `std::thread` reader that pushes raw frametime `f64` values onto a bounded `mpsc::sync_channel` (cap 256). `next_sample()` drains the channel non-blocking, maintains a 120-sample ring (`VecDeque<f64>`, ~2 s @ 60 FPS), and returns a `FrameSample` with avg-FPS-over-ring, mean/variance frametime over this tick, current FPS, low_1pct/low_01pct from sorted ring, and per-tick stutter count (frames > 2× tick mean). Discovery order: `RIGSIGNAL_PRESENTMON` env var → agent binary directory → PATH via `where`. One-time warn if not found; reader thread exits silently if `MsBetweenPresents` column absent. `Drop` impl on `PresentMonSource` kills child + drops rx (reader thread exits on next send failure). No new crates; pure `std::process` / `std::sync::mpsc` / `std::thread`. Field path emitted under `rigsignal.fps.*` (not `rigsignal.frame.*`) to match Linux MangoHud collector and `SessionAccumulators` in `main.rs:359-368`. Dataset name remains `rigsignal.frame`. `cargo check` + `cargo clippy -- -D warnings` + `cargo test` (7/7) all green. Dry-run verified (no game pid attached) — collector reports "no data this tick" without panic; PresentMon "not found" warning path verified by code review (Windows game-pid resolution is gated on `/proc` and not exercisable in dry-run on Windows; live verification deferred to Phase E packaging).

### Milestone C — Windows collectors (complete, 2026-04-25 session 3)

- **C.5 — GPU collector**: Replaced `src/collectors/windows/gpu.rs` stub. Three data sources: (1) DXGI — `CoInitializeEx(COINIT_MULTITHREADED)` + `CreateDXGIFactory2(DXGI_CREATE_FACTORY_FLAGS(0))` + `EnumAdapterByGpuPreference(DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE)` → `IDXGIAdapter3::QueryVideoMemoryInfo(DXGI_MEMORY_SEGMENT_GROUP_LOCAL)` → `memory_used_mb` + `memory_total_mb`. COM init returns raw `HRESULT` in windows 0.58 (not `Result`) — matched on `.0` field (0=S_OK, 1=S_FALSE own it, `0x80010106`=RPC_E_CHANGED_MODE skip uninit). (2) PDH — `\GPU Engine(*engtype_3D*)\Utilization Percentage` wildcard counter, `counter_values_array()` filtered for `engtype_3D`, max taken across instances → `utilisation_pct`. (3) WMI — `wmi::query_thermal_zones()` with GPU zone name selection (prefers "GPU"/"VRAM"/"diode"/"VGA", falls back to hottest zone) → `temperature_c` + `temp_source: "wmi_acpi"`. Added `wmi.rs` shared helper factored from cpu.rs (cpu.rs refactored to use it). Added `Win32_System_Com` feature. Dry-run verified: 15428 MB VRAM total, 0.1% util at idle, no temperature (WMI returned no GPU zone on this system — correct graceful behavior).

- **C.7 — Audio collector**: Replaced `src/collectors/windows/audio.rs` stub. Always emits `backend: "wasapi"`. GlitchListener scaffold included verbatim per spec with `TODO(C.7-xruns)` ETW upgrade path documented.

- **`temp_source` field**: Added to `data_stream/gpu/fields/fields.yml` — keyword, describes provenance of `temperature_c` (`hwmon` on Linux, `wmi_acpi` on Windows).

- **Full dry-run verification (all 8 collectors)**: cpu ✅, memory ✅, storage ✅, network ✅, power ✅, audio ✅ (`backend: wasapi`), gpu ✅ (VRAM + util), frame (stub, expected). No panics, no ERROR logs.

### Phase C parity gap summary

| Field | Linux | Windows | Upgrade path |
|---|---|---|---|
| `cpu.power_w` | RAPL sysfs | None | Vendor SDK |
| `cpu.governor` | cpufreq | None | Windows power plan mapping |
| `cpu.game_utilisation_pct` | /proc cgroup | None | ETW / Job Object |
| `gpu.temperature_c` | hwmon exact | wmi_acpi approx | ADLX / NvAPI |
| `gpu.power_w` | hwmon | None | ADLX / NvAPI |
| `storage.game_io` | procfs | None | ETW kernel IO |
| `audio.quantum` | pw-metadata | None | Platform-specific audio configuration API |
| `power.battery_rate_w` | sysfs | None | WMI Win32_Battery |

### Milestone C — Windows collectors (partial, 2026-04-25 session 2)

- **C.3 — Storage collector**: Replaced `src/collectors/windows/storage.rs` stub. Two PDH scalar counters: `\PhysicalDisk(_Total)\Disk Read Bytes/sec` and `\PhysicalDisk(_Total)\Disk Write Bytes/sec`. Baseline collect in `new()`; `initialized` guard for graceful degradation. Emits `read_bytes_per_sec` + `write_bytes_per_sec` (u64, f64→u64 cast). Parity gap: per-disk breakdown and game-scoped IO omitted (ETW required). Dry-run verified: read 65 KB/s, write 260 KB/s on an active system.

- **C.4 — Network collector**: Replaced `src/collectors/windows/network.rs` stub. Two PDH wildcard counters: `\Network Interface(*)\Bytes Sent/sec` and `\Network Interface(*)\Bytes Received/sec`. `counter_values_array()` result filtered (case-insensitive exclusion of isatap*, teredo*, loopback* tunnel/loopback adapters), then summed to aggregate. Emits `bytes_sent_per_sec` + `bytes_recv_per_sec` (u64). Dry-run verified: 398 B/s recv on idle desktop.

- **C.6 — Power collector**: Replaced `src/collectors/windows/power.rs` stub. Pure Win32 — `GetSystemPowerStatus` (SYSTEM_POWER_STATUS). `ACLineStatus` 0/1/255 → `ac_connected` Some(bool)/None. `BatteryLifePercent` 0–100/255 → `battery_pct` Some(f64)/None. Returns `Ok(None)` when both fields are absent (desktop with no battery + unknown AC). Added `Win32_System_Power` feature to windows dep. Dry-run verified: `ac_connected: true`, no `battery_pct` (desktop, correct).

- **Dry-run verification (C.0–C.4 + C.6)**: All five implemented collectors emit real data. `rigsignal.cpu` — 16 cores, 5.9% total, 4700 MHz. `rigsignal.memory` — 63 GB total, 18.4% used. `rigsignal.storage` — non-zero. `rigsignal.network` — non-zero recv. `rigsignal.power` — `ac_connected: true`. No panics, no ERROR logs.

### Milestone C — Windows collectors (partial, 2026-04-25 session 1)

- **C.0 — PDH infrastructure**: Created `src/collectors/windows/pdh.rs` with `PdhQuery` / `PdhCounter` newtypes wrapping raw `isize` PDH handles (windows crate 0.58 exposes these as raw `isize`, not named type aliases). `PdhQuery::new()` calls `PdhOpenQueryW`; `add_counter()` calls `PdhAddCounterW`; `collect()` calls `PdhCollectQueryData`; `counter_value_f64()` calls `PdhGetFormattedCounterValue` with `PDH_FMT_DOUBLE`; `counter_values_array()` calls `PdhGetFormattedCounterArrayW` with a two-pass buffer (size probe → fill). Drop impl calls `PdhCloseQuery`. Module-level doc explains why counters must be long-lived (rate-counter baseline semantics) and the ETW upgrade path. Added `Win32_System_Threading` + `Win32_Foundation` features to the `[target.'cfg(windows)'.dependencies]` block (needed by C.2 memory collector). Declared `mod pdh;` (private) in `windows/mod.rs`.

- **C.1 — CPU collector**: Replaced `src/collectors/windows/cpu.rs` stub with a real PDH-backed implementation. Fields emitted under `rigsignal.cpu.*`: `total_utilisation_pct` (f64, PDH `\Processor(_Total)\% Processor Time`), `per_core` ([f64], `\Processor(*)\% Processor Time` wildcard — `_Total` instance filtered out, remaining sorted by numeric core index), `clock_mhz_avg` (u64, optional, `\Processor Information(_Total)\Processor Frequency`), `temperature_c` (f64, optional, WMI `MSAcpi_ThermalZoneTemperature` via PowerShell subprocess cached 5 s, plausibility-checked 10–105 °C), `boost_state` (bool, hardcoded `true` — no cross-vendor API without vendor SDK). PDH query opened + baseline collect in `new()`; if init fails, `initialized = false` and `collect()` returns `Ok(None)` gracefully. Parity gap: `game_utilisation_pct` omitted — requires ETW or Job Object, documented as `TODO(C.1-game-util)`. `governor` field omitted (Windows has no equivalent).

- **C.2 — Memory collector**: Replaced `src/collectors/windows/memory.rs` stub. Uses `GlobalMemoryStatusEx` (MEMORYSTATUSEX) for system-wide stats; `OpenProcess` + `GetProcessMemoryInfo` (PROCESS_MEMORY_COUNTERS.WorkingSetSize) for `game_rss_mb`. Fields: `total_mb`, `used_mb`, `available_mb` (all from `ullTotalPhys`/`ullAvailPhys`), `used_pct` (f64, 1 decimal), `game_rss_mb` (optional). `set_game_pid` wired. Process handle closed via `CloseHandle` on all paths. `cargo check` + `cargo clippy -- -D warnings` both clean. Linux unaffected (windows crate dep is cfg-gated).

### Milestone B2 — Launcher-agnostic game detection (partial, 2026-04-25)

- **B2.8 — Dashboard source/launcher filters**: Added `ctrl-source` and `ctrl-launcher` options-list filter controls to Game Library dashboard (`game-library-dashboard.json`). Added `launcher-breakdown` horizontal bar panel: x=`rigsignal.game.source` (terms), breakdown by `rigsignal.game.launcher`, count metric, KQL filter `data_stream.dataset : "rigsignal.session"`. Deploy path: component template `rigsignal-session-context.json` PUT to ES (fields were mapped in repo since B2.2 but not deployed to live index); PUT `/_mapping` on `metrics-rigsignal.session-default` to add `source`/`launcher` to existing backing index; saved-objects `_import` with updated NDJSON. `scripts/verify-dashboard.sh` PASS: 11 panels, all Lens invariants OK, internal loader OK. ES|QL validation: fields mapped (0 rows — no sessions indexed since B2.2, expected). Deployed NDJSON saved as `dashboards/game-library-dashboard-deployed.ndjson`. `rigsignal-session-performance.ndjson` unchanged (no `source`/`launcher` filters to break). B2 milestone complete.

- **B2.7 — User-specified target override**: Added `--target-pid <PID>` and `--target-name <NAME>` CLI flags to `src/main.rs` Cli struct, and `target_pid`/`target_name` fields to `SessionConfig` in `src/config.rs` (config-file equivalents under `[session]`). Added `resolve_user_target(pid_override, name_override) -> Option<Target>` to `src/session.rs`: PID mode validates `/proc/<pid>` exists, reads comm/exe for display name, runs enrichment helpers; name mode scans `/proc/*/comm` and `/proc/*/exe` basename (case-insensitive, first match). Added `poll_pinned_target()` helper in `src/main.rs` that synthesises `GameStarted`/`GameEnded`/`NoChange` events by checking `/proc/<pid>` liveness — replaces `session.poll()` in the tick loop when a pinned target is active. CLI takes precedence over config; `--target-pid` over `--target-name` if both given. Fallback to auto-detection if process not found. Updated dispatcher comment in `scan_for_game()` explaining why UserSpecified bypasses the chain. 7/7 tests (added `test_resolve_user_target_invalid_pid` + `test_resolve_user_target_no_args`). Smoke test: `--dry-run --target-pid $SHELL_PID` and `--target-name fish` both parse without panic.

- **B2.6 — Proton/Wine env var enrichment**: Called `read_environ(pid).unwrap_or_default()` + `detect_graphics_api` + `proton_version_from_env` + `dxvk_version_from_env` at the `Target` construction site in `scan_for_lutris_game`, `scan_for_heroic_game`, and `scan_for_bottles_game`. All three previously returned `None` for these fields. No new crates, no schema changes, no helper modifications — pure mechanical wiring. Added unit test `test_enrich_from_proton_env` confirming `PROTON_VERSION` + `DXVK_CONFIG_FILE` env produces `graphics_api = "dx11_via_dxvk"` and `proton_version = "GE-Proton9-20"`. Known limitation not fixed: Lutris umu-backed GOG games still show `launcher = "Lutris — Native"` (requires runner detection via process environ, deferred post-B2). Verification: `cargo check`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo test` (5/5) green.

- **B2.5 — Bottles detection**: Added `scan_for_bottles_game() -> Option<Target>` in `src/session.rs`. Enumerates `bottle.yml` files across two roots (native + Flatpak), parses each with serde_yaml into `BottleConfig` / `BottleProgram` structs, then scans `/proc/*/environ` for `WINEPREFIX` matching the bottle directory (which IS the WINEPREFIX). `BottleProgram::is_active()` filters removed entries (handles null/bool/string variants). Display name resolved by matching `/proc/<pid>/exe` basename against `Programs` entries (case-insensitive); falls back to the bottle `Name` field if no program matches. Both roots absent → immediate `None` (Bottles not installed). Wired into `scan_for_game()` dispatcher. Smoke test: Bottles absent on both paths (not installed); detector returns None immediately. Verification: `cargo check`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo test` (4/4) green. Commit: see feat commit below.

- **B2.4 — Heroic detection**: Added `scan_for_heroic_game() -> Option<Target>` in `src/session.rs`. Probes four `installed.json` paths (native + Flatpak × Epic/GOG) via `heroic_installed_games()` which returns `Vec<(app_name, title, HeroicStore)>`. Detects running games by scanning `/proc/*/environ` for `SteamGameId=heroic-<app_name>` — the env var Heroic sets on all child processes. `HeroicStore` enum (Epic/Gog) drives `launcher` label: "Heroic — Epic" or "Heroic — GOG". Handles object format (Legendary/newer GOG) and array format (older GOG) defensively; skips DLC entries; deduplicates by app_name across all four paths; empty or malformed JSON files are silently skipped. Wired into `scan_for_game()` dispatcher. Smoke test: Heroic installed (non-Flatpak); one Epic game found (`911 Operator`, app_name UUID `a7594e61a4f24e6d9495ea959749598e`); GOG `installed.json` exists but empty (no GOG games installed). `gogdlConfig/heroic_gogdl/installed.json` also empty — not in spec paths, documented in HANDOFF. Verification: `cargo check`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo test` (4/4) green. Commit: see feat commit below.

- **B2.3 — Lutris detection**: Added `scan_for_lutris_game() -> Option<Target>` in `src/session.rs`. Scans `~/.local/share/lutris/games/*.yml`, deserialises each file into a minimal `LutrisGameConfig` struct (serde_yaml 0.9), derives display name from filename slug via `lutris_slug_to_title()` (strips 10+-digit Unix timestamp suffix, title-cases words), detects Wine vs native runner from presence of top-level `wine:` YAML key, cross-references `/proc/<pid>/exe` symlinks (native games) and `/proc/<pid>/environ` WINEPREFIX entries (Wine games). Wired into `scan_for_game()` dispatcher replacing the placeholder comment. Added `serde_yaml = "0.9"` to `src/Cargo.toml`. Unit test `test_lutris_slug_to_title` confirms 4 slug examples including numeric version segments and multi-word titles. Smoke test: one real Lutris game found (`thronebreaker-the-witcher-tal-gog-1777116393.yml`, GOG/umu Wine game) — YAML parses cleanly, Wine prefix would be matched via WINEPREFIX scan when game is running. Note: real Lutris YAML uses no top-level `wine:` key for umu-backed games, so all GOG games will show "Lutris — Native" label until B2.6 improves runner detection. Verification: `cargo check`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo test` (4/4) green. Commit: see feat commit below.

- **B2.2 — Schema generalisation**: Added `rigsignal.game.source` (keyword enum: steam|lutris|heroic|bottles|user_specified|auto_detected) and `rigsignal.game.launcher` (free-form keyword) to session and events streams (Path 2: per-tick metric streams receive description-only update, no new fields). Made `rigsignal.game.steam_app_id` conditionally emitted — only present when `source == steam`. New helpers `target_source_str()` + `target_to_game_doc()` in `src/session.rs` centralise emission logic; both `base_doc()` and `build_summary_doc()` in `src/main.rs` use the helper. Session.json on-disk format gains `target_source` field; `steam_app_id` now optional. `Target::from_steam()` sets `launcher: Some("Steam")`. Component template `rigsignal-session-context.json` updated with source + launcher properties. Lutris pipeline test fixture added (`test-session-pipeline-lutris.json` + expected) to prove schema accepts non-Steam targets without `steam_app_id`. Daemon compatibility confirmed: `SessionInfo` uses `serde(default)` + no `deny_unknown_fields` — new field silently ignored. Verification: `cargo check`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo test` (3/3) green. Live gaming-PC verification deferred (see follow-ups). Commit: aec9c24.

- **B2.1 — Target type + detection abstraction**: Renamed `DetectedGame` struct to `Target` and introduced a `TargetSource` enum (`Steam` | `Lutris` | `Heroic` | `Bottles` | `UserSpecified` | `AutoDetected`) in `src/session.rs`. Only `Steam` is constructed today via `Target::from_steam()`; the other variants are reserved for B2.3-B2.7 + B3 and rely on the per-crate `dead_code = "allow"` lint to stay quiet until their detectors land. `SessionEvent` variants kept their `Game{Started,Ended}` names but now carry `Target` instead of `DetectedGame`. `SessionManager::current_game` retyped to `Option<Target>`. `scan_for_game` is now a public dispatcher that calls `scan_for_steam_game` (the renamed Steam-specific helper); its body has commented-out `.or_else(scan_for_…)` lines documenting the slot for each future detector. Field accesses migrated: `game.name` → `target.display_name`, `game.steam_app_id: u32` → `target.steam_app_id: Option<u32>` with `.expect("Steam target without steam_app_id — invariant violation")` at the two emission sites (`write_session_json` and `base_doc`/summary `game_doc`). Behaviour-neutral: session.json on-disk format byte-for-byte unchanged (eBPF daemon reader untouched), and the ES schema is unchanged — `rigsignal.game.{source,launcher}` are deferred to B2.2 alongside making `steam_app_id` optional. Verification on Windows: `cargo check`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo test` (3/3) all green. Live game-session verification on the Linux gaming PC deferred (see follow-ups). Single migration commit + docs commit.

### Milestone B — Cross-platform refactor (complete, 2026-04-24 session 2)

- **B.5 — GitHub Actions CI matrix**: Added `.github/workflows/ci.yml`. `check` job matrix runs `cargo check --locked` and `cargo clippy --locked -- -D warnings` on `ubuntu-latest` and `windows-latest` for every push to `main` and every PR. A Linux-only conditional step also exercises `cargo check --features ebpf` and `cargo clippy --features ebpf -- -D warnings` to verify B.6's feature plumbing. Separate `fmt` job runs `cargo fmt --check` on Linux only. Caching via `Swatinem/rust-cache@v2` with per-OS keys; toolchain via `dtolnay/rust-toolchain@stable`; fail-fast disabled; concurrency group cancels in-progress runs on same ref. eBPF workspace (`ebpf/`) intentionally excluded from CI — separate workspace requiring bpf-linker. A `style: cargo fmt` commit (c556589) preceded B.5 to ensure the fmt gate is green on first CI run. Commits: c556589 (fmt prep), 93ad4e6 (ci.yml).
- **B.6 — eBPF feature flag (Linux-only)**: Added `[features]` block to `src/Cargo.toml` with `default = []` and `ebpf = []`. Added `compile_error!` gated on `cfg(all(feature = "ebpf", not(target_os = "linux")))` at the top of `src/main.rs`. Today the agent crate has zero eBPF deps and no in-agent eBPF integration (the daemon is an out-of-process sibling workspace), so the feature is a scaffold — it reserves the name, enforces the Linux constraint the moment someone enables it on Windows, and makes the pattern obvious for future in-agent eBPF work. CI exercises both feature modes on Linux. Verified on Windows: default build OK, `--all-features` fails with the compile_error as designed. Commit: ad1aa93.

### Milestone B — Cross-platform refactor (partial, 2026-04-24)

- **B.1 — Collector trait + uniform constructor**: `Collector` trait now requires `Send + 'static` and includes a default-no-op `set_game_pid(&mut self, _pid: Option<u32>)`. All 8 collectors now implement the trait (previously only some did). Every collector's `new()` signature is uniform: `pub fn new(game_pid: Option<u32>) -> Self` — collectors that don't use the pid prefix with `_`. AudioCollector's previously-expensive `detect_backend()` call in `new()` moved into lazy init at first `collect()` via an `Option<String>` field. Collectors with process-scoped state (cpu, memory, mangohud, gpu_amd) keep both an inherent `set_game_pid` method and a delegating trait impl. Commit: ce29210.
- **B.2 — Linux collectors moved to `src/collectors/linux/`**: 8 collectors (cpu, memory, storage, network, power, audio, mangohud, gpu_amd) relocated via `git mv` into a platform submodule. New `src/collectors/linux/mod.rs` declares and re-exports each collector; `GpuAmdCollector` re-exported as `GpuCollector` for platform symmetry. Imports in moved files: `use super::Collector` → `use crate::collectors::Collector`. `src/collectors/mod.rs` now cfg-gates the linux module behind `#[cfg(target_os = "linux")]` and re-exports via `pub use linux::*`.
- **B.3 — Windows collector stubs + `Vec<Box<dyn Collector>>` dispatch**: 8 Windows stub files in `src/collectors/windows/` (cpu, memory, storage, network, power, audio, frame, gpu). Each stub implements the trait with the same `dataset()` string as its Linux counterpart but returns `Ok(None)` from `collect()` — Phase C will replace with real collection. The MangoHud↔frame split follows platform-symmetric naming: `frame.rs` defines `FrameCollector`, re-exported in `windows/mod.rs` as `MangoHudCollector` so main.rs uses a single type name across both platforms. main.rs collector instantiation replaced with `build_collectors(game_pid) -> Vec<Box<dyn Collector>>`; per-tick collect and game-pid propagation are now Vec iterations using the trait's `dataset()` method. `cargo check` passes on Windows. Commit: 40d1612.
- B.1–B.3 shipped as two commits rather than three: B.2 and B.3 were combined because B.2's intermediate state leaves Windows `cargo check` broken, and this session was Windows-only (no Linux host to verify a standalone B.2). Splitting post-hoc via hunk-staging was rejected as higher-risk than combining.

### Milestone B — Cross-platform refactor (partial, 2026-04-21)

- **B.4 — Windows signal-handler gate**: Unix-only `tokio::signal::unix` import and signal setup moved behind `#[cfg(unix)]`. On non-Unix hosts the agent spawns a task waiting on `tokio::signal::ctrl_c()` instead; both paths send on a `tokio::sync::oneshot` channel so the `select!` loop arm is platform-neutral. `cargo check` and `cargo clippy -- -D warnings` both pass on Windows.

### Milestone B — Cross-platform refactor (partial, 2026-04-18)

- **B.7 — Settings schema + Tier 1 manual support**: Added `rigsignal.settings` group to `data_stream/session/fields/fields.yml` (17 new fields covering preset, upscaler, frame-gen, features, render mode, source/confidence, notes). Config support via `[session.settings]` TOML section; CLI flags `--preset`, `--upscaler`, `--frame-gen`, `--features`, `--resolution`, `--vsync`, `--notes`. CLI overrides config. Settings block emitted on session-start and summary docs only (omitted entirely when nothing configured). Added `fs2` dep for file locking in B.8.
- **B.8 — Session label counter format**: Label format changed from `<slug>-YYYYMMDD-HHMMSS` to `<slug>-YYYYMMDD-N`. Counter persisted to `$XDG_STATE_HOME/rigsignal/session-counters.json` with atomic write (rename) and `fs2::FileExt::lock_exclusive`. Prunes entries >30 days on first call each day. Windows path stubbed (`%LOCALAPPDATA%\RigSignal\session-counters.json`). New `session.label_source` ("auto"|"manual") and `session.sequence_number` (integer, auto-only) fields in all session docs. 3 unit tests added (increment, prune, slug). Migration note: existing ES docs with `HHMMSS` labels unchanged; new sessions use `N` counter format.
- Added `[lints]` to `src/Cargo.toml` to suppress pre-existing dead_code/clippy warnings in collector files so `cargo clippy -- -D warnings` passes cleanly.

Commit: 561dc78

### Pre-reorg (Phases 0, 0.5, 1, 2, 3, 6)

- **Phase 0–0.5** — Elasticsearch foundation + integration package scaffold. 12 component templates, 11 index templates, 11 ingest pipelines deployed to Elastic Cloud Serverless. All `elastic-package check` + `test static` 11/11 passing.
- **Phase 1** — Python collector validated end-to-end with live Cyberpunk 2077 session.
- **Phase 2** — eBPF daemon complete. Sprints 1–3 ES-confirmed (schedlatency, bio, gpu_sched, mem, stutter, gpu_fence, gpu_submit, futex, irq, vfs). Sprint 4 (sample_event.json updates) outstanding but low-priority for beta.
- **Phase 3** — Seven Kibana dashboards built: baseline, config comparison, session deep-dive, storage I/O, system health, game library, scheduler analysis, home. File-by-value, `data_stream.dataset` filters applied.
- **Phase 6 — Rust production agent: COMPLETE AND ES-VERIFIED.** Live Starfield session 2026-04-11 (40 min, Proton, avg 286.9 FPS) confirmed all 8 metric streams shipping. Rust is production-primary; Python collector is reference/fallback.
- **Phase 4 distribution infrastructure** — `elastic-package stack up` local registry working; zip upload to Kibana Fleet API verified on local 8.13.0 (44 assets) and Serverless (47 assets). `docs/BETA-INSTALL.md` written.
- **Packaging** — AUR PKGBUILD complete; systemd user + system units (`rigsignal-agent.service`, `rigsignal-ebpf.service`) smoke-tested active. `rigsignal-launcher.sh` POSIX shell CLI with `setup / start / stop / status / run %command%` subcommands. Steam integration verified: `rigsignal run %command%` as launch option.
- **Full `elastic-package test` suite** — static 11/11, pipeline 11/11, asset 12/12 pass. Policy + system return "No test results" (acceptable per elastic/integrations guidelines for hardware-dependent integrations).

### Milestone A — Docs reorganisation (2026-04-18)

- Created `docs/STATUS.md` as single source of truth for project state
- Created `architecture/` subdirectory at repo root (ebpf.md moved, data-model.md + agent.md stubs added) — note: lives at repo root, **not** `docs/architecture/`, because `elastic-package check` rejects subdirectories inside `docs/`. Do not re-nest.
- Created `docs/install.md` (unified installation guide, absorbs elasticsearch-setup.md content)
- Created `docs/dashboards.md` (merged dashboard-guide.md + kibana-lens-ndjson-reference.md)
- Renamed `docs/RigSignal-Scope-v3_2.md` → `docs/SCOPE.md`
- Stripped `docs/ROADMAP.md` to structure-only; all status content moved to STATUS.md
- Stripped `CLAUDE.md` to rules-only; all state content moved to STATUS.md
- Rewrote `README.md` to lead with Rust agent as primary
- Deleted: `docs/project-scope.md`, `docs/scope-v2.md`, `docs/claude-chat-context.md`,
  `docs/elasticsearch-setup.md`, `docs/dashboard-guide.md`, `docs/kibana-lens-ndjson-reference.md`

### Infrastructure session — 2026-04-21 (Windows MCP wiring)

- **Windows machine MCP wiring (2026-04-21)**: elastic-agent-builder registered and connected via npx mcp-remote against the Kibana MCP endpoint. `RIGSIGNAL_MCP_API_KEY` set as persistent user env var; `.mcp.json` uses variable substitution (`${RIGSIGNAL_MCP_API_KEY}`) rather than baked-in key — no API key material on disk. New MCP key was created with explicit `feature_agentBuilder.read` + `feature_actions.read` application privileges via Kibana Dev Console (superuser session). Previous attempt with derived inherits-parent key failed because parent `ES_API_KEY` lacks `feature_agentBuilder.read`; documented here to save future time. Tools (`recall_memory`, `recall_recent`) activate on next session restart per the MCP protocol.

### Infrastructure session — 2026-04-21 (Python hooks — cross-platform guard)

- **Claude Code hooks ported to Python**: Three hooks (pre-edit-check, pre-command-check, post-edit-check) rewritten as Python 3 replacements; bash scripts retained as fallback. Windows machine now has functional protected-file guard, blocked-command guard, and auto cargo check on .rs edits — all three were silently dead on Windows before this change (bash does not execute). Linux behaviour preserved; when Linux switches to Python hooks, fixes propagate automatically.
- **Absolute-path bug fixed in pre-edit-check**: exact-match (manifest.yml) and prefix checks (_dev/, packaging/) never fired against absolute paths on either OS. Fixed in the Python port by stripping the cwd prefix (available in hook JSON) before applying checks.
- **Self-test harness**: `python3 .claude/hooks/pre-edit-check.py --test` — 10 cases covering Windows absolute paths, Linux relative paths, backslash normalization, outside-cwd safety, and sibling-directory guard. All pass.
- Commits: 6c05cdf (Python files + absolute-path fix), e49d7db (settings.json switched to python3)

### Infrastructure session — 2026-04-20 (token optimisation + security + Windows prep)

- **CLAUDE.md progressive disclosure refactor** — slimmed from 208 → 84 lines. Reference content (file locations, hardware, skills, Kibana conventions, test suite status, package build) moved to `docs/claude-reference.md`. Agent routing table and grep-first rule added as enforced rules. Estimated 60–70% reduction in per-turn system prompt overhead.
- **ES_API_KEY security consolidation** — single canonical key name across all scripts. `scripts/kibana-lib.sh` ELASTIC_API_KEY fallback removed. `~/.elastic/claude-memory-credentials.json` scrubbed of plaintext key fields. `~/.config/rigsignal/rigsignal.toml` hardcoded expired key cleared. `/etc/rigsignal/rigsignal.toml` still needs `sudo` clear (user action).
- **Rust agent (`src/config.rs`) env var override** — `ES_API_KEY` and `ES_URL` env vars override TOML values at load time. Enables keyless TOML on Windows.
- **eBPF daemon (`ebpf/.../config.rs`) env var override** — same pattern applied; `api_key` made optional with env var fallback and clear error if neither TOML nor env var provides the key.
- **ES memory migration** — all 6 prior file-based memories migrated to `agent-memory` ES index. `recall_memory` / `recall_recent` verified working. MEMORY.md reduced to 3-line pointer. Cross-platform: Windows clone needs only `ES_API_KEY` env var set + `wire-mcp.sh` run.
- **`settings.local.json` cleanup** — removed ~40 stale entries (old stale paths, specific PIDs, one-off diagnostic commands); consolidated overlapping wildcards; fixed broken hook path to current repo location.

### Developer tooling

- **T.1 Elastic Agent Builder MCP server** — `.mcp.json.example` + `.agents/skills/elastic-mcp-setup/SKILL.md` committed. Wires Claude Code and claude.ai to ES for live ES|QL field validation during dashboard builds. API key creation and wiring steps documented in the skill. Not a runtime dependency.
- **T.2 Dashboard verification script (2026-04-19)** — `scripts/verify-dashboard.sh` + `scripts/kibana-lib.sh`. Runs four checks against a deployed dashboard: saved-objects export round-trip, Lens datasource-layer invariants (catches "import-valid but UI-blank" foot-gun), internal dashboard loader (`/internal/dashboards/app/<id>`) renderability, and opt-in `--require-dataset-filter` for integration-submission compliance. Also supports `--expected-panel-types` for regression pinning. Smoke-tested live against both deployed dashboards; documented in the `kibana-dashboards` skill.

## Blockers & decisions pending

- **0.2.5 S2 gate** ✅ RESOLVED 2026-07-19 — A6-24h retention check PASSED, sealed before the 0.2.5 release.
- **Distribution follow-up** — winget is unavailable/closed; do not resubmit until the elastic/integrations architecture rework lands. PR #18878 is deferred pending maintainer architecture work and `fields.yml` gating.
- **D3 detector scoping** — next diagnostic-evidence-engine vertical after D6 (0.3.0), per the ratified H2 strategy. Not yet started.

- **Security hardening follow-up — MCP key exposure via `claude mcp list`**: During initial MCP setup attempt, the first `rigsignal-mcp` API key was printed verbatim in `claude mcp list` output and exposed to a conversation transcript. That key has been invalidated. A separate properly-scoped key now lives in env var only. `claude mcp list` displaying raw API key values in its output is a design-level issue — future setup flows should either redact or be executed in non-logged contexts. Worth surfacing to Anthropic as a product feedback item.

- **Infrastructure follow-up — pre-command-check allowlist non-functional** ✅ RESOLVED 2026-04-29: removed the dead `allowed_prefixes` list (it had no blocking effect) and added `_scan_target()` which strips `-m`/`--message` content before scanning, so commit messages mentioning blocked words no longer false-positive block. Also handles compound `&&` commands correctly.
- **Infrastructure fix — pre-edit-check absolute-path bug (resolved in Python port)**: exact-match (manifest.yml) and prefix checks (_dev/, packaging/) never fired against absolute paths on either OS in the bash version. Fixed in Python port by stripping cwd prefix before applying checks. Bash scripts still carry the unfixed logic; when Linux migrates to Python hooks, the fix propagates automatically.
- **Hook observability — PostToolUse stdout not surfaced to Claude Code**: post-edit-check cargo check output flows to the Claude Code terminal, not back into conversation context. Claude Code cannot directly observe the hook result; it must re-run cargo check manually to verify. Not blocking; worth revisiting if hook output becomes debugging-relevant.

## Environment

- Primary dev host: CachyOS Linux (AMD Ryzen 7 9800X3D / Radeon RX 9070 XT)
- Agent hosts: the gaming host and the streaming client, both using spool-file output mode
- ES endpoint: local ElasticHome Elasticsearch stack (migrated from cloud 2026-07-09)
- Repo: github.com/MathewRJ/RigSignal

## Follow-ups and migration notes

- **0.2.5 S2 spool durability**: ✅ complete — A6-24h retention check passed, sealed before the 0.2.5 release.
- **Backlog (not yet scheduled)**: S3 `read_loss_counters` hardening, S4, and idle-doc suppression remain open items but were not part of 0.3.0, which shipped D6 instead per the ratified H2 strategy.

- **Linux `cargo check` verification for B.1–B.3 + B.6 (`--features ebpf`) pending**: 2026-04-24 sessions were Windows-only (gaming PC offline). Windows `cargo check`, `cargo clippy -- -D warnings`, `cargo fmt --check`, and `cargo check --all-features` (expected-fail via compile_error) all green. The B.5 CI workflow exercises both Linux and Windows on push, so this is self-healing as soon as CI runs on main — but a gaming-PC session to run `cargo check --manifest-path src/Cargo.toml --features ebpf` and confirm the cfg gate doesn't accidentally exclude required modules on Linux is still worth doing.
- **B2.1 live verification on gaming PC**: the Windows session can only smoke-test the migration via `cargo check`/`clippy`/`test`. The behaviour claim (session-start, in-tick, and session-summary docs are byte-for-byte identical to pre-B2.1, modulo timestamps) needs a live Linux session — boot a real game, capture a session-start doc and a session-summary doc, diff field-by-field against a known-good pre-B2.1 sample from ES Discover. Same trip should also confirm the eBPF daemon still parses `/tmp/rigsignal/session.json` cleanly (format wasn't supposed to change, but verify).
- **Hook scope redesign — PostToolUse cargo check noise during structural refactors**: deferred from the 2026-04-24 sessions. The `post-edit-check.py` hook runs `cargo check` after every `.rs` edit, which is helpful for single-file fixes but creates N-times-expected-failure noise during multi-file structural refactors (see 2026-04-24 B.2+B.3 session for the python-via-bash workaround). Options: scope the hook to only fire on the final edit in a batch, add a way to suppress it during planned structural refactors, or move the cargo check to a manual command. Infrastructure session, defer until Phase C scheduling.
- **B.8 label format migration**: ES docs indexed before B.8 carry `<slug>-YYYYMMDD-HHMMSS` labels. New sessions use `<slug>-YYYYMMDD-N`. Dashboard filters on `session.label` should use `*` wildcards or filter on `session.label_source` instead. No backfill needed.

## Follow-ups to investigate

- S3 `read_loss_counters` hardening, S4, and idle-doc suppression remain open backlog items (not scheduled into a release yet).
- Revisit elastic/integrations PR #18878 once the maintainer architecture rework and `fields.yml` gate are resolved.
- D3 detector scoping is the next diagnostic-evidence-engine vertical per the ratified H2 strategy.

- **Dashboard integration-compliance gap (Milestone G blocker)**: ✅ RESOLVED 2026-04-29 — `data_stream.dataset: rigsignal.*` wildcard filter added at dashboard level to all 6 new-suite dashboards via `scripts/add-dataset-filter.py`. `verify-dashboard.sh --require-dataset-filter` PASS 6/6 (API + UI gate). Deployed NJDSONs saved to `dashboards/*-dashboard-deployed.ndjson`. `verify-dashboard.sh` updated to accept dashboard-level filter as satisfying the integration-compliance requirement.
- **Dev install: systemd unit ExecStart path drop-in override** ✅ DOCUMENTED 2026-04-29: `docs/install.md` now has a callout block showing the exact `~/.config/systemd/user/rigsignal-agent.service.d/override.conf` snippet for dev builds installed to `/usr/local/bin`. PKGBUILD installs to `/usr/bin/` and is unaffected.
- `bottleneck_dominant` null in April-12 session summaries — historical: those sessions predate the accumulator code; new sessions populate it correctly when both GPU and CPU collectors are active
- HOME env fallback fixed: `home_dir()` helper in session.rs now checks HOME → SUDO_USER → None instead of falling back to `/root`; `game_name_from_appid()` and `counter_file_path()` both updated
- Startup ES credential validation: already implemented (`shipper::ping` called at startup in main.rs)
- No-game system metrics dashboard panel (system health without game filter)
- `docs/BETA-INSTALL.md` merged into `docs/install.md` and deleted (D.1/D.2 smoke tests still pending)
