# Task: D3 GPU-boot detector — Rust port + CLI surface (rigsignal-agent diagnose gpu-boot)

**Status: SPEC v3 — DISPATCH-READY.** v1 drafted 2026-07-21 (session 2026-07-21e-d3-spec,
owner-ratified as the next bet — explicit deviation from the STRATEGY-2026H2 D6→0.3.1 pilot
sequence; the pilot remains mainline). Codex-Sol-xhigh QC chain: v1 → REWORK (12 MAJOR /
6 MINOR); v2 applied all 18 → AMEND-THEN-DISPATCH (16/18 OK, 9 new findings N1–N9, 4 MAJOR);
v3 applies N1–N9 (bridge-at-BDF routes to bus-absent; frozen d3.1 precursor constants;
pending-finding transition table; ambiguity sub-case; boot-ID hex normalization; preflight
stage before precedence; learn/reset observable contract; missing_evidence-may-be-empty;
replay-helper-reuse allowed). Spar logs archived:
`Workflow projects/RigSignal/evidence/d3-spec-2026-07-21/`.

## STM contract (do this first and last)

Before starting: `CHRONO_SESSION=<SID> bash /home/dev/coding/Workflow/scripts/stm.sh recall`.
On completion and on any non-obvious discovery: `stm.sh save … --kind
learning|failure|decision|status` (set `STM_AGENT=<worker>@<host>`). Return only a condensed
summary — detail goes in STM. (stm.sh is network-blocked in the Codex sandbox — if saves fail,
list the learnings in the summary and the orchestrator saves them.)

## Context

D3 diagnoses the "GPU absent on boot / power-state latch" failure (real incident 2026-07-01,
ES mem-1782915538): an in-use SMU hang latches the GPU's power state; on the next boot the
GPU's slot (`0000:03:00.0` on the incident box) enumerates a bridge `[1022:43f5]` instead of
the GPU `[1002:7550]`, downstream buses renumber, and only a full PSU power-drain recovers it.
The detector reads journald boot history + current PCI sysfs state and issues a plain-language
verdict. Python ref impl `~/coding/Workflow/projects/RigSignal/scenario-testing/diagnostics/
detect_d3_gpu_boot.py` is prototype-grade and known-flawed — port its intent, not its bugs
(gap list in §4).

v1-scope boundaries (Codex finding 18): explicit-slot baselines only (no automatic dGPU
discovery), state schema v1 with unknown-version refusal (no migration machinery), one pending
recovery transition (no audit ring), generic PCI presence/identity detection for any
explicitly-selected GPU, precursor analysis AMD/amdgpu-only.

## Work

### 0. PREREQUISITE A — shared diagnose contract extraction (separate commit, D6 regressions green)

`Diagnosis`, `Outcome`, `NotApplicable`, validation, printing, and exit mapping are private to
`src/detectors/d6.rs`, and `Diagnosis::new` hard-codes `D6`/`d6.1`; `run_cli` maps every
non-`ok` verdict to exit 1 — a literal extraction gives D3 wrong exits (`recovered`,
`baseline-required` are non-`ok` but exit 0). Required shape:

- Extract into `src/detectors/mod.rs` (or `contract` submodule), **parameterizing detector ID,
  rule version, and error prefix**. Add a non-serialized disposition enum
  (`NonFinding | Finding`) carried alongside the verdict; exit mapping = disposition 0/1,
  `Err` = 2. D6 assigns dispositions preserving its exact current exits.
- Replace the pre-config `if let` dispatch in `src/main.rs` (~line 700) with an exhaustive
  `match` over `DiagnoseAction`.
- Contract stays **serialization-only** (`Serialize`; no `Deserialize` on output types —
  `NotApplicable` holds `&'static str`). D3's state structs get their own
  `Serialize + Deserialize`.
- New always-present diagnosis fields: `supported_scope: Vec<String>`,
  `missing_evidence: Vec<String>`, `nearest_alternative: String`. D6 becomes `d6.2`.
- D6 compatibility acceptance: one-line unwrapped diagnosis JSON on stdout; untagged smaller
  `not-applicable` shape; error-only stderr on exit 2; existing field types; existing exit
  codes. Add an explicit D6 JSON compatibility test; update `docs/diagnose-display.md`,
  README, STATUS for `d6.2` + the three new fields.

### 0b. PREREQUISITE B — fixture normalization gate (before any detector code)

`fixtures/d3/` does not exist in RigSignal yet. Freeze and normalize:

- Copy the Workflow captures (`scenario-testing/diagnostics/fixtures/d3/`, including
  `captures-2026-07-21/{fixture-peer.example,fixture-client.example}/` with `pci-topology.txt` — parent
  chains + boot IDs, both boxes, captured 2026-07-21) into repo `fixtures/d3/` under
  **normalized stable names**; record `fixtures/d3/MANIFEST.md` with sha256 + provenance
  (real-capture vs SYNTHETIC clearly separated). Decompress the old
  `good-boot-kernel.log.gz` (or replace with the fresh capture) — `include_str!` cannot read
  gzip. Everything normalized UTF-8. Tests and the replay script depend ONLY on the
  normalized names, never on provisional Workflow filenames.
- Create the missing logical fixtures (all synthetic ones labeled): full PCI snapshot with
  the expected GPU genuinely absent; prior full-journal tail + matching boot inventory for
  the synthetic precursor; current/prior boot identities supporting a real fault→later-boot
  recovery transition; different-device-at-BDF, unique-relocation, duplicate-ID-ambiguity,
  and multi-GPU learning snapshots; precursor threshold-minus-one, cross-slot,
  outside-window, clean-tail, and truncated-tail journals.

### 1. Detector module `src/detectors/d3.rs`

**PCI snapshot schema v1 (versioned, one schema for live + fixtures):** boot ID; per device:
BDF, vendor, device, class, canonical sysfs parent path (bridge chain), upstream bridge BDF.
Live source: `/sys/bus/pci/devices/*` + `readlink` parent chain (deck-user readable, proven
by the 2026-07-21 captures). Sysfs is the **authoritative** presence/identity source.

**Journald collection** (all bounded, all failures typed):
- Boot inventory via `journalctl --list-boots` → select boots by **explicit boot ID**, never
  bare `-b -1` offsets internally (multi-boot: the gaming host runs Windows/CachyOS between Linux boots).
- All queries: `--no-pager -o short-iso-precise`, `LC_ALL=C`, explicit timeout, exit
  status + stderr checked, bounded output. Prior-boot kernel evidence collected as an
  **end-oriented window** (tail of that boot) so a byte cap can never truncate the end.
- Prior full-boot tail (NOT `-k`; shutdown markers are userspace — verified live on the gaming host)
  for shutdown evidence. **Validate the tail actually reaches the boot's last entry per the
  boot inventory before interpreting missing markers.** Shutdown patterns anchor near the
  terminal tail — the real fixture-peer.example capture contains an early `steam: Shutdown` line that a
  naive grep misreads as a clean OS shutdown.
- Any journal collection failure → `missing_evidence` entry; it never erases a sysfs-proven
  finding and never becomes exit 2 on its own (exit-2 causes listed under the table).

**PREFLIGHT (before any verdict logic; failures → incomplete, exit 2, stderr):** invocation
validity (flag combinations, offline trio), state-file readability/parseability/schema
version, authoritative-PCI-input readability/well-formedness, boot-identity pairing validity,
and fixture consistency (e.g. a healthy snapshot matching baseline paired with an absent-GPU
journal is rejected as inconsistent input, NOT mislabeled `hardware-changed`). No verdict —
including `baseline-required` — can mask a preflight failure.

**Verdict precedence (after preflight; evaluate strictly in this order, first match wins):**
1. State operation requested (`--learn-baseline` / `--reset-baseline`) → perform it (see
   observable contract in §3).
2. No baseline → `baseline-required` (exit 0).
3. Expected identity present elsewhere or replaced by another endpoint →
   `hardware-changed` (exit 1; no power-drain advice; advise re-learn if intentional).
   Sub-cases, each with distinct evidence wording: (a) unique relocation — expected identity
   at exactly one DIFFERENT BDF; (b) replacement — a different NON-bridge device (e.g.
   another display controller) at the expected BDF with expected identity globally absent;
   (c) ambiguity — expected identity matched at multiple BDFs / duplicate-ID → include
   explicit ambiguity evidence.
4. Expected identity absent from the ENTIRE snapshot, and the expected BDF is empty OR
   occupied by a bridge-class device → `bus-absent` (exit 1). **The real 2026-07-01
   incident is this row: bridge `[1022:43f5]` enumerated at `0000:03:00.0` with the GPU
   gone — bridge-at-BDF must NOT route to `hardware-changed`.** With same-boot journal
   corroboration (upstream link-down/empty-slot along the baseline's bridge chain, e.g. the
   synthetic evidence at upstream `0000:00:03.1`): high confidence + power-drain guidance as
   "most consistent with". Without journal evidence: reduced confidence, cause explicitly
   undetermined, latch one listed alternative — absence itself is observed.
5. GPU present + current-relevant precursor on the paired prior boot → `precursor-warning`
   (exit 1).
6. GPU present + pending recorded fault from an EARLIER boot ID → `recovered` (exit 0),
   consuming the pending finding (next run → `ok`).
7. GPU present, prior-boot history unavailable (rotated/no prior Linux boot) →
   `history-unavailable` typed non-finding (exit 0) — never a bare `ok` claim.
8. Otherwise → `ok` (exit 0).
Non-Linux → typed `not-applicable` (exit 0). Every finding carries confidence basis,
falsifier, `supported_scope`, `missing_evidence`, `nearest_alternative` — all fields
present, `missing_evidence` may legitimately be empty; wording is "most consistent with" —
no absolute causal language anywhere.
**Boot-ID normalization:** journald `--list-boots` IDs are compact 32-hex;
`/proc/sys/kernel/random/boot_id` and the topology captures are hyphenated UUIDs — all boot
IDs are normalized to canonical lowercase 32-hex (hyphens stripped) before any pairing or
state comparison.

**Precursor rule v1 (AMD/amdgpu-only, same-BDF, evidence-calibrated):** requires a compound
sequence on the baseline BDF within the trailing window of the prior boot. Frozen provisional
`d3.1` constants (calibration caveat: no real positive capture exists yet, only the
deliberately-dense synthetic one — revisit when a real capture lands):
- `SMU_UNRESPONSIVE_MIN = 3` — lines matching exactly `SMU: response:0xFFFFFFFF`.
- `RESET_ATTEMPT_MIN = 2` — lines matching `GPU reset begin`.
- `PRECURSOR_WINDOW_S = 900` — sequence must fall within the final 900 s of the prior boot
  (end derived per the collection rules above).
- Terminal-failure requirement (at least one): a reset attempt with NO subsequent
  `recovered through reset`/`GPU recovered` line in the remaining window, OR the boot's
  journal ending within the window after the last SMU-unresponsive line (mid-flood cutoff).
All three counted/evaluated separately; the rule fires only when SMU count AND reset count
meet minimums AND a terminal-failure condition holds. Acceptance boundary tests use exactly
these constants (threshold-minus-one, outside-window, cross-slot, clean-tail,
truncated-tail). "Failed to export SMU metrics" patterns DEFERRED until a captured example
exists. Shutdown-tail evidence grades confidence: tail present + no terminal shutdown
markers strengthens; tail missing/truncated lowers confidence and can never support a latch
claim on its own.

**Evidence output & PII:** emit normalized evidence facts (parsed fields) rather than raw
journal lines wherever possible; any retained excerpt passes a defined redactor (usernames,
non-target hostnames, MACs, serials, UUID-bearing command lines, control characters) with
redaction unit tests. D6's strip-and-truncate helper is insufficient — extend or replace.

### 2. CLI surface

- `GpuBoot` variant in the nested `DiagnoseAction` → `diagnose gpu-boot`; dispatch after Clap
  parsing, before `Config::load()`, explicit `ExitCode`. Legacy plain `diagnose` unchanged.
- Flags: `--offline`, `--journal-current PATH`, `--journal-prior-kernel PATH`,
  `--journal-prior-tail PATH`, `--pci-snapshot PATH`, `--boot-list PATH`,
  `--current-boot-id ID`, `--state-file PATH` (mode-neutral: usable live to point at a
  non-default state), `--slot BDF`, `--json`, `--host NAME`, `--learn-baseline`,
  `--reset-baseline`.
- **Offline mode** = `--offline` (explicit; fixture flags without `--offline` = usage error,
  exit 2). Requires: `--pci-snapshot`, a NON-DEFAULT `--state-file`, and trustworthy current
  boot identity (`--boot-list` or `--current-boot-id`). Journal inputs optional — absence is
  typed `missing_evidence` (models real rotation). Offline NEVER fills an omitted input from
  live collection. Unpairable current/prior fixtures → exit 2.
- **Learning:** requires explicit `--slot` (multi-GPU is real: the gaming host has dGPU `03:00.0` AND
  iGPU `7b:00.0`, both class `0x030000` — heuristics cannot pick); refuses to overwrite an
  existing baseline; live or offline (offline learn = replay seeding path).
  `--reset-baseline` is idempotent and mutually exclusive with learn/diagnose.

### 3. Persistent baseline state

- Default `$XDG_STATE_HOME/rigsignal/detectors/d3-gpu-boot.json`, fallback
  `~/.local/state/…`; directory created with restrictive permissions.
- Schema v1: `schema_version`, learned boot ID + timestamp, slot BDF, vendor/device/class,
  parent bridge chain + upstream bridge (from snapshot schema v1), plus at most ONE pending
  finding record (verdict + observation boot ID + timestamp). Unknown `schema_version` →
  typed refusal, exit 2 (no migration machinery; test unknown-version rejection).
- **Pending-finding transition table** (only these verdicts touch `pending`):
  `bus-absent` → creates/replaces the pending record; `recovered` → consumes it;
  `hardware-changed` → clears it (the baseline no longer describes the machine — a later
  healthy run must NOT emit `recovered` for a fault recorded against replaced hardware);
  all other verdicts (`precursor-warning` included) preserve `pending` unchanged and never
  create one — a warning has no confirmed fault to recover from.
- `recovered` semantics: emitted only when the current (normalized) boot ID differs from the
  pending finding's observation boot ID and no current finding exists; emitting consumes the
  pending record — `recovered` fires exactly once per fault.
- **Learn/reset observable contract:** learn success → one-line JSON (`--json`) / plain
  confirmation with learned slot+identity+boot ID, exit 0; learn refusal (existing baseline,
  missing `--slot`, slot not in snapshot, ambiguity) → stderr, exit 2; reset success → 
  confirmation, exit 0, idempotent (resetting absent state is still exit 0).
- Concurrency/durability: **stable sidecar lock file** (`d3-gpu-boot.lock`, `fs2` — already
  in Cargo.toml; never lock the state file itself, the lock dies with the replaced inode on
  atomic rename); nonblocking acquire with timeout → exit 2 on contention; bounded
  regular-file reads; symlink refusal; atomic same-directory tempfile+rename; **state
  committed before success output is printed**.

### 4. Tests

Port the Python cases via `include_str!` on normalized fixtures, EXTENDING them. Ref-impl
bugs that must each have a regression test: burst not time-bounded/slot-scoped; SMU+reset
pooled into one threshold; missing/rotated journal degraded to `ok` (now
`history-unavailable`); journalctl status/stderr ignored; findings always exit 0; no
rule_version/confidence-basis/falsifier/scope/missing-evidence/alternative; omitted
known-good made recovery tautological (now impossible: pending-finding + boot-ID pairing);
temp-dir leak; **the old bus-absent test's healthy-snapshot-plus-absent-journal
contradiction → now rejected as inconsistent input (exit 2)**.

Full matrix: every precedence row; every exit-code class via CLI integration tests (Clap
nesting included); mismatch-at-BDF vs relocation vs bridge-at-BDF; precursor threshold-minus-
one / cross-slot / outside-window / clean-tail / truncated-tail; multi-GPU learn refusal
without `--slot`; learn-refuses-overwrite; reset idempotency; state lifecycle (create,
unchanged rerun, corrupt file, unknown schema version, lock contention — contention tested
in Rust, not via remote process races); redaction cases; non-Linux `not-applicable`
(keeps Windows CI green — offline tests are cross-platform, live collection Linux-gated).

### 5. CI (`.github/workflows/ci.yml` — currently: check, clippy, fmt, Linux telemetry
smoke; NO cargo test; clippy without `--all-targets`)

- Add `cargo test --manifest-path src/Cargo.toml --locked` to the Linux AND Windows matrix.
- Add `--all-targets` to BOTH clippy invocations (normal and Linux `--features ebpf`).

### 6. Docs

`docs/diagnose-gpu-boot.md` (mirror diagnose-display.md): usage, precedence/verdict table,
learn/reset workflow (explicit `--slot`), **SSH note — black-screen users run this over SSH;
enabling sshd beforehand is part of setup**, multi-boot caveat, journal-retention caveat
(real evidence: the gaming host lost boot-time enumeration to an RTC-jump rotation even on persistent
journald — capture provenance 2026-07-21), redaction statement. Plus `fixtures/d3/README.md`
provenance and the §0 doc updates (`d6.2`).

## Acceptance criteria

- §0 refactor lands first, all D6 tests + JSON compat test green before D3 code.
- Full suite + clippy `--all-targets` green on Linux and Windows CI.
- NEW `Workflow projects/RigSignal/scripts/d3-live-replay.sh` — reuse of any tested
  d6-live-replay.sh helpers is fine; what matters is the assertion set below, and that no
  D6-specific logic (connector preflight, modes.cfg seed/restore) is blindly carried over.
  All remote runs as `deck`, no sudo,
  temp `--state-file`, remote temp/state/lock cleanup asserted. **Deterministic stateful
  sequence:** offline healthy learn with explicit `--slot` → absent-snapshot fixture →
  `bus-absent` → simulated later boot (different `--current-boot-id`, healthy snapshot) →
  exactly one `recovered` → immediate rerun → `ok`. Plus: synthetic precursor → `precursor-
  warning`; real clean 2026-07-21 capture → `ok`; omitted prior journal → typed missing-
  evidence with correct verdict class; edited different-ID snapshot → `hardware-changed`
  with no power-drain advice; live healthy run on the gaming host (real journalctl + sysfs) →
  `ok`/`baseline-required`.
- Verdict-language audit: no absolute causal claims; all five contract fields present on
  every finding (`missing_evidence` may legitimately be empty).

## Explicitly deferred (not this task)

- Elastic Agent journald log-shipping auto-capture (design-doc phase 2).
- Split-lock journal-spam detector (real hazard on the gaming host; separate candidate).
- "Failed to export SMU metrics" precursor patterns (no captured example yet).
- Automatic dGPU discovery; state schema migration; multi-finding history ring.
- gpu_fence/present-interval probes, NIC counters (telemetry freeze).
- Dashboard D3 journal/PCI surface (behind the system-health trim).
- Any tagged release/deploy (re-triggers the 0.2.5-vintage eBPF pin rebuild+re-attest
  obligation — separate gated session).
