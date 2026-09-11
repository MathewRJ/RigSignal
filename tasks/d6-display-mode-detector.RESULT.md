# D6 display mode-override detector result

## Implementation

- Added the pure Rust D6 detector and Linux-only live collector in
  `src/detectors/d6.rs`, plus the detector module root.
- Added `rigsignal-agent diagnose display` before `Config::load()`. Offline replay
  requires both fixture paths; incomplete conditions return stderr/exit 2, findings
  exit 1, and `ok`/typed `not-applicable` exit 0.
- Copied the specified D6 captures and synthetic discriminator fixtures to
  `fixtures/d6/`. The read-only Workflow reference directory was not modified.
- Preserved the existing `rigsignal-agent diagnose --output` dispatch. A manual
  regression invocation wrote the usual `=== RigSignal Diagnostic Report ===` and
  exited 0.

Fixture replay/manual CLI checks covered degraded (0.9, exit 1), healthy `ok`
(exit 0), invalid (exit 1), one offline flag (exit 2), explicitly missing fixture
(exit 2), and JSON `not-applicable` (exit 0). Nine dependency-free CLI integration
tests now cover Clap nesting, every required exit-code class, one-line diagnosis
and typed-not-applicable JSON, human contract fields, and legacy `diagnose --output`
behavior. The Rust suite has 119 passing tests, including hardening regressions
for malformed DRM with an empty modes file, oversized fixtures, and non-regular
fixture paths.

## Live-replay verification (orchestrator-run, 2026-07-21, PASS)

Performed on the gaming host `deck@192.0.2.254` via
`Workflow projects/RigSignal/scripts/d6-live-replay.sh` (EXIT-trap, existence-aware
restore). Full transcript:
`Workflow projects/RigSignal/evidence/d6-live-replay-2026-07-21/d6-live-replay-20260721T170204.log`.

- Candidate: commit `018f65f` build, binary sha256 `3ededae8...9bf7a48e`,
  shipped to `~/rigsignal-test/rigsignal-agent-3ededae8`, remote hash verified equal.
- Preflight: `card0-DP-2` connected (AOC AG352UCG6), sysfs modes still advertise
  `1280x800`; original `modes.cfg` = `AOC AG352UCG6:3440x1440@120`,
  sha256 `23ec0055...caa3010`.
- Baseline run: verdict `ok`, confidence 0.75, exit 0 ("pinned mode matches preferred").
- Seeded `AOC AG352UCG6:1280x800@60`: verdict `mode-override-degraded`,
  confidence 0.85, exit 1; evidence includes degraded branch
  `area ratio 0.207 < 0.5, aspect delta 0.789 > 0.05 vs preferred 3440x1440` and
  refresh divergence vs `valid_refresh_rates=[120.0]`; plain language names the
  stale-override cause and that a reboot won't help; two actionable suggested fixes.
- Restore: `modes.cfg` sha256 identical before/after (`23ec0055...caa3010`),
  healthy re-run verdict `ok` exit 0, backup removed.
- First replay attempt (candidate `fdaf2885`) FAILED and exposed two live-path bugs
  (selection predicate never matching; sysfs edid stat-size 0) — fixed with unit
  tests before this passing run. The EXIT trap restored the box cleanly on failure.

An earlier candidate note: this run exercised the exit-code contract 0/1 in both
directions on real hardware, per spec Work step 4.

## Gates

- `cargo fmt --check`: PASS
- `cargo clippy --locked --all-targets -- -D warnings`: PASS
- `cargo check --locked`: PASS
- `cargo test --locked`: PASS (119 passed, 0 failed)
- Linux CI feature gates (`cargo check` and clippy with `--features ebpf`): PASS
- `bash scripts/smoke-test.sh ./target/debug/rigsignal-agent`: FAIL in this sandbox:
  the pre-existing smoke check could not observe the three required live network
  metrics. All other smoke checks passed. The Windows CI job cannot run locally
  because only the Linux Rust target is installed; it remains for CI.
- STM recall/save: skipped because `stm.sh` cannot open its network socket in this
  sandbox.
- Commit: `b76ad2e` (`feat(d6): display mode-override detector — Rust port +
  diagnose display CLI`) was created by the orchestrator.

## Threat model / accepted risk

The D6 CLI runs with the invoking user's privileges and intentionally trusts that
user's session environment (`PATH` and `HOME`). A hostile inherited environment is
out of scope for this user-invoked diagnostic.

## Changed files

- `src/detectors/mod.rs`
- `src/detectors/d6.rs`
- `src/main.rs`
- `fixtures/d6/**`
- `src/tests/d6_display_cli.rs`
- `tasks/d6-display-mode-detector.RESULT.md`
