# Task: D6 display mode-override detector — Rust port + CLI surface (rigsignal-agent diagnose display)

CHRONO_SESSION=2026-07-21c-d6-rust-port

## STM contract (do this first and last)
- First: `bash ~/coding/Workflow/scripts/stm.sh recall --all-sessions --last 15 --grep "D6"` — catch up on prior D6/D3 diagnostic-detector work.
- Last: save learnings/failures/status via `bash ~/coding/Workflow/scripts/stm.sh save "<title>" "<content>" --kind <learning|failure|status> --project RigSignal --session <SID>`.
- Return only a condensed summary; detail goes in the RESULT file + STM.

## Context
- RigSignal 0.3.0 = D6 (display mode-override detector), per the ratified H2 strategy
  (`STRATEGY-2026H2.md` owner decision #4) and `D6-RUNWAY-2026-07-21.md`.
- The reference implementation is a validated, stdlib-only Python 3 prototype at
  `~/coding/Workflow/projects/RigSignal/scenario-testing/diagnostics/` (`detect_d6_display_mode.py`
  + `diagnosis.py` contract), 17/17 tests passing as of 2026-07-21. It has NEVER touched RigSignal
  and never will ship — Python is the executable spec, this task is a from-scratch Rust port.
- RigSignal's existing `rigsignal-agent diagnose` (`src/diagnose.rs`) is an unrelated plain-text
  env/connectivity bug-report dump — do not change its behavior or flags.
- Owner decision #2 (STRATEGY-2026H2.md): verdict/evidence/confidence/next-action must print from
  RigSignal's OWN CLI — `rigsignal-agent diagnose display` — not a sidecar script. Kibana is
  deep-dive only, not required for this task.
- Tiered detection logic (do not relitigate, port as-is): T1 `mode-override-invalid` (pinned or
  active resolution absent from the connector's sysfs `modes` list) and T2
  `mode-override-degraded` (pinned mode's orientation-normalized resolution equals the internal
  eDP panel's native resolution, OR pinned area is <50% of the connector's preferred/first-listed
  mode's area AND aspect delta >0.05 vs preferred). Same-aspect performance downscales resolve
  `ok`. See `detect_d6_display_mode.py` for the exact reference logic (`AREA_RATIO_MAX=0.5`,
  `ASPECT_TOLERANCE=0.05`).
- **Fixture provenance matrix (do not alter):** `fixtures/d6/deck-real/drm-state.json` is the real
  fixture-deck.example good-state capture and has `active_mode: 3840x2160@120`; `real-254/drm-state.json` is real
  and lacks `active_mode`; `deck-incident-bad/drm-state.json` is the real fixture-deck.example base with only
  `active_mode` synthetically mutated to `1280x800@60`. Missing `active_mode` is therefore normal
  and must be treated as unknown, skipping the active-resolution check; do not invent EDID DTD
  parsing or another active-mode source in this task.
- **Does not port cleanly — resolve, don't reproduce:** the Python prototype's `_live_collect()`
  invokes `gamescopectl` but discards stdout and returns no DRM state. The Rust live path must
  actually parse captured-format `gamescopectl` stdout (`- Connector Name: <x>`, `- Display Make:
  <x>`, `- Display Model: <x>`, `- ValidRefreshRates: <n>`) and collect per-connector state from
  `/sys/class/drm/card*-*/{status,enabled,dpms,edid,modes}`. Read raw resolution-only `modes`
  lines; Hz is not recoverable there. Use manual string parsing (as in
  `src/collectors/linux/gamescope.rs`), no `regex` dependency, and call `gamescopectl` with no
  arguments only. This read-only detector must never write `modes.cfg`, DRM state, or invoke a
  mutating/debug gamescopectl command.

## Preparation
1. Amend and commit this specification alone on `main` before creating the implementation
   worktree; it is currently untracked and must not be mixed into the implementation diff.
2. Create `git worktree add worktrees/codex-d6-detector -b codex-d6-detector` from that `main`.

## Work (repo `~/coding/RigSignal`, implementation worktree above)

1. **New module** `src/detectors/mod.rs` + `src/detectors/d6.rs`:
   - Port `ModeOverride`, `_parse_modes_cfg`, `_parse_resolution`, `_orientation_normalize`,
     `_area`, `_aspect`, `_connector_short_name`, `_find_gamescope_connector`,
     `_is_connected_external`, `_internal_native_resolutions`, `_mode_set`,
     `_preferred_resolution`, `_invalid_mode`, `_degraded_mode`, `_plain_bad`, and the top-level
     dispatch from `detect_d6_display_mode.py` into idiomatic Rust (plain structs,
     `Option`/`Result`, no new crate dependencies).
   - Keep the logic pure: `diagnose_inputs(&str, &str) -> Result<Diagnosis>` consumes modes.cfg
     and DRM-state JSON text. Thin path wrappers read explicitly supplied files and then call that
     core; the live wrapper collects the same two in-memory texts and calls it. A path wrapper
     accepting `diagnose(None, …)` represents no modes.cfg override and returns `ok`; it is not an
     attempt to open a missing explicit path. Unit tests must embed fixtures with `include_str!`,
     not depend on runtime fixture paths.
   - Define a fallible Rust `Diagnosis` contract: `detector_id` (`"D6"`), `rule_version`
     (`"d6.1"`), `verdict`, `confidence: f64`, `confidence_basis: String`, `evidence: Vec<String>`,
     `plain_language`, `suggested_fixes: Vec<String>`, `falsifier: String`, `host: Option<String>`,
     and timestamp. `confidence_basis` must state which D6 branch/evidence warrants the numeric
     confidence (including the no-override/validation case), not merely repeat the verdict.
     Enforce confidence in [0,1], non-empty evidence/plain language/falsifier/confidence basis,
     and non-empty suggested fixes for real findings. `not-applicable` is an explicit typed
     outcome, not a `Diagnosis`: it has an explanation/evidence and serializes as a clean JSON
     outcome under `--json`; it exits 0 and is exempt from the non-`ok` suggested-fixes invariant.
   - `serde::Serialize` must emit the Python-style fields where practical, including `@timestamp`,
     plus `rule_version`, `confidence_basis`, and `falsifier`; serialize typed `not-applicable`
     with a stable outcome/verdict of `not-applicable`, its explanation/evidence, and no fake
     diagnosis. Human output must print `detector_id`, `rule_version`, verdict, confidence,
     confidence basis, evidence (one per line), plain-language summary, suggested fixes, and
     falsifier.
   - Parse modes.cfg deliberately: an absent optional source (`diagnose(None, …)`) and an empty
     file mean no override and `ok`; an explicitly supplied path that is absent or unreadable is
     an incomplete detector error. If every nonblank line is unparsable, report an incomplete
     detector error rather than `ok`. If parsed overrides exist but none maps to a connected,
     usable external connector, return `not-applicable` (nothing validatable), not silent `ok`.
   - Implement Linux live collection. A successful `gamescopectl` invocation must yield all four
     required fields before a live diagnosis. A missing executable, a documented/no-session
     absence result, or no connected display is `not-applicable`; any other non-zero command
     status, unreadable/malformed required output, or no usable collection fallback is incomplete
     (exit 2). Enumerate `card*-*` directories.
     `status` is mandatory for every considered connector; `enabled` and `dpms` are best-effort
     metadata (record absent/unreadable values as evidence); for the selected connected external
     connector, non-empty `edid` (using file length) and readable `modes` are mandatory. Select by
     the gamescopectl connector short name and `status=connected`; if it resolves to zero usable
     connectors, return `not-applicable`, and if multiple GPU/card candidates match it, return an
     incomplete ambiguity error (exit 2). On non-Linux, do not compile the live collector; the CLI
     returns `not-applicable`.

2. **CLI wiring** in `src/main.rs`:
   - Add `mod detectors;` and add `rigsignal-agent diagnose display` as a nested subcommand of the
     existing `Diagnose` command (for example `action: Option<DiagnoseAction>`). With no nested
     action, preserve the existing plain-text `rigsignal-agent diagnose [--output PATH]` behavior
     and flags exactly. `display` accepts `--modes-cfg PATH`, `--drm-state PATH`, `--json`, and
     `--host NAME`.
   - Offline/reproducible mode requires **both** `--modes-cfg` and `--drm-state`; either flag by
     itself is a usage/detector-completion error, printed to stderr with exit 2. With neither flag,
     use live collection only. Do not combine one supplied fixture with live collection.
   - Dispatch `diagnose display` immediately after Clap parsing and before `Config::load()`;
     display must not require a RigSignal config. Its runner returns an explicit `ExitCode` and
     `main` propagates it, rather than letting an `anyhow` error become exit 1. Keep config loading
     and the legacy diagnose dispatch unchanged for every other command.
   - Exit codes: 0 = diagnosis verdict `ok` or typed `not-applicable`; 1 = a real
     `mode-override-invalid` or `mode-override-degraded` finding; 2 = detector incomplete or
     invalid invocation (including explicitly missing/unreadable fixture paths, one offline flag,
     all-nonblank-unparsable modes.cfg, gamescopectl/sysfs/read/parse failures without the defined
     not-applicable condition, connector ambiguity, or diagnosis-contract failure). Incomplete
     errors go to stderr; `--json` never converts them into a fake success document.

3. **Fixtures and tests:** copy (not move) the D6 fixture data, including captured
   `gamescopectl.txt`, from
   `~/coding/Workflow/projects/RigSignal/scenario-testing/diagnostics/fixtures/d6/` and
   `tests/data/{legit-downscale-modes.cfg,synthetic-4k-drm-state.json,invalid-mode-modes.cfg}` to
   a new root `fixtures/d6/` directory. Do not modify/delete anything in Workflow. Port the six
   D6 cases as Rust tests in `src/detectors/d6.rs` using `include_str!`:
   - `deck-incident-bad` → `mode-override-degraded`, confidence 0.9, evidence contains the
     Samsung QCQ95S 1280x800@60 line and `active_mode ... agrees`, and plain language says a
     reboot will not help.
   - `deck-real` → `ok`, with unmappable LG connector skipped as "display not currently connected".
   - `real-254` → `ok`, with "pinned mode matches preferred" evidence.
   - `legit-downscale` (synthetic) → `ok`, with "below preferred 3840x2160" evidence.
   - `invalid-mode` (synthetic) → `mode-override-invalid`, evidence includes `2000x2000` and
     "not present in resolution-only sysfs modes".
   - `diagnose(None, …)` → `ok`, with "no override present" evidence; separately prove an explicit
     missing modes.cfg path exits 2.
   - Add contract tests for every real finding: confidence bounds, non-empty evidence/plain
     language/suggested fixes/falsifier/confidence basis, and `rule_version == "d6.1"`; add
     all-unparsable and nothing-validatable outcome tests.
   - Add parser unit tests using the captured real `fixture-peer.example` and Deck `gamescopectl.txt` stdout,
     asserting connector, make, model, and refresh-rate parsing without regex.
   - Add CLI integration tests for Clap nesting, every exit-code class (including explicit bad
     fixture, incomplete error, and not-applicable/no-op), one-line JSON shape for diagnosis and
     not-applicable, and human output fields. Include a regression test that runs legacy
     `rigsignal-agent diagnose --output <path>` with no `display` subcommand and proves its report
     text/flag behavior remains unchanged.

4. **Live-replay verification (manual, required before merge; document in the RESULT file):**
   after review and CI pass but before merge, run the exact candidate binary on Gaming PC
   (`deck@192.0.2.254`) uninstalled. First preflight the current connector and its sysfs
   `modes`; only if `1280x800` remains advertised, seed the known bad line adapted from
   `deck-incident-bad` to the gaming host's live connector: `AOC AG352UCG6:1280x800@60` (preserve any required
   line format/flags). It must yield `mode-override-degraded`, confidence `0.85`, and exit 1 — do
   not accept merely any non-`ok` result. Run the restored healthy configuration and require `ok`,
   exit 0. Use a bash `EXIT` trap with existence-aware restoration (remove the test file only when
   it did not previously exist; otherwise restore the exact backup), and record before/after
   `sha256sum` equality. Capture the preflight, exact commands, candidate hash, both outputs/exit
   codes, restore proof, and a transcript review in `tasks/d6-display-mode-detector.RESULT.md`.
   The RigSignal binary itself never writes `modes.cfg`; only the manual tester seeds/restores it.

5. **Minimal diff and gates:** no `src/diagnose.rs` behavior change, dashboard change, D3/D7 work,
   or Cargo dependency addition. Before review/merge pass `cargo fmt --check`,
   `cargo clippy --locked --all-targets -- -D warnings`, `cargo check --locked`, and
   `cargo test --locked`, plus the existing CI matrix (including its Windows PR job). The
   implementation diff allowlist is `src/detectors/mod.rs` (new), `src/detectors/d6.rs` (new),
   `src/main.rs`, `fixtures/d6/**` (new), relevant new CLI/integration test files, and
   `tasks/d6-display-mode-detector.RESULT.md`; the separately prepared task-spec commit is allowed.

## Acceptance criteria
- `rigsignal-agent diagnose display --modes-cfg <fixture> --drm-state <fixture>` reproduces all
  six ported D6 verdict/confidence/evidence-substring cases above; missing `active_mode` remains
  tolerated and the fixture provenance matrix above remains accurate.
- Offline mode rejects either lone fixture flag with exit 2; explicitly absent/unreadable fixture
  paths exit 2; `diagnose(None, …)`/an empty no-override source is `ok`; all-nonblank-unparsable
  modes.cfg exits 2; and parsed-but-unmappable overrides are typed `not-applicable`, exit 0.
- `rigsignal-agent diagnose --output <path>` with no `display` subcommand behaves identically to
  before this change — same text report, same flags, no configuration/dispatch regression.
- Every emitted diagnosis carries `rule_version: "d6.1"`, a non-empty verdict-specific
  `falsifier`, and a non-empty `confidence_basis`; both JSON and human output expose all contract
  fields. `--json` is a single-line valid document for diagnoses and typed not-applicable outcomes.
- Clap nesting and explicit display `ExitCode` dispatch are tested; display dispatch occurs before
  `Config::load()`, so it works without a RigSignal configuration. All incomplete errors are stderr
  + exit 2, and no-op/not-applicable is exit 0.
- Live collection observes the mandatory/best-effort sysfs rules, uses connected connector
  selection, treats multi-GPU/card ambiguity as exit 2, parses real gamescopectl output, performs
  zero writes to `modes.cfg` or `/sys/class/drm`, and invokes `gamescopectl` with no arguments.
- The required live replay on the gaming host is performed before merge, seeds the stated known line only after
  preflight, observes degraded/0.85/exit-1 then restored ok/exit-0, and records an EXIT-trap and
  before/after SHA-256 restoration proof in the RESULT file.
- `cargo fmt --check`, locked clippy with `-D warnings`, locked `cargo check`, locked `cargo test`,
  and the existing CI matrix pass. The RESULT file lists changed files, tests, the live-replay
  transcript, and confirms the Workflow reference directory was untouched.
- The implementation diff stays within the explicit allowlist in Work step 5.

## Explicitly deferred (not this task)
- G2 gap 3 — provenance note for the two synthetic discriminator fixtures (`legit-downscale`,
  `invalid-mode`) in a ported `fixtures/d6/README.md`.
- G2 gap 6 — one-paragraph baseline-absence note (why MangoHud/FrameView/CapFrameX cannot see a
  `modes.cfg`/DRM-state mismatch).
- G2 gap 7 — RigSignal `docs/` operator-facing writeup of `rigsignal-agent diagnose display` and
  D6 as the 0.3.0 wedge.
- A future `d6.2` rule-pack revision that attempts genuine active-mode/EDID-preferred-timing
  detection (would need EDID parsing, a real new dependency, and real hardware-format risk).
- Any update to the Python reference implementation itself (adding rule version/falsifier there)
  — optional, non-blocking, since Python never ships.
