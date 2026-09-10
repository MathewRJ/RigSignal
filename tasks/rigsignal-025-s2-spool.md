# Task: rigsignal-025-s2-spool — Spool shutdown finalization + startup recovery + retention (0.2.5 S2)

Session: 2026-07-18-s2-spool. Workspace: the git worktree you are launched in
(branch `codex/rigsignal-025-s2-spool` of `/home/dev/coding/RigSignal`, cut from main
`4bf8145`). Do NOT commit — leave all changes in the working tree; the orchestrator
commits after review. Do NOT bump any version field — Cargo stays 0.2.4; the release
version change lands later, after S1+S2 live validation.

## Contract — S2 section of RIGSIGNAL-025-SPEC.md, VERBATIM (authoritative)

Where this task file's notes and the contract below conflict, the contract wins; report
the conflict in your summary.

---

## S2 — Spool shutdown finalization + startup recovery + retention  (RELEASE BLOCKER)

### Negative control (run live 2026-07-18, the streaming client — evidence banked)

Pre-stop: 24 buffered records across 7 dataset `.tmp` files (cpu 6; audio/gpu/memory/
network/power/storage 3 each). Graceful `systemctl --user stop rigsignal-agent`: `.tmp`
files unchanged (no shutdown rotation of buffered batches). Restart: `.tmp` truncated and
refilled with fresh ticks. ES confirms permanent loss: cpu bucket 10:59:50–59 has 3/10
docs; the 6 buffered docs (10:59:50–55) never arrived. Evidence:
`projects/RigSignal/evidence/025-s2-negative-control/` (raw `.tmp` copies + log).
**Nuance:** one session-dataset doc written during shutdown DID reach a final — the
stale-age rotation fired coincidentally at write time (`shipper.rs:81`, rotation check
runs per write). Escape by timing luck, not design.

**Related debt folded in (found 2026-07-18):** shipped finals are never deleted — live:
the streaming client = 406 MB / 39,966 files (since 07-14), the gaming host = 406 MB / 3,190 files (since 07-16).
Unbounded growth; 40k files in one directory also taxes filestream scans.

### Decisions (spec-time; spar verdicts applied)

- **D1 — Durability: user-space flush only.** Finalization = flush + close before rename;
  no `fsync` of file or directory. **Contract covers graceful exit and SIGKILL while the
  OS remains running** — OS/power/filesystem crash is explicitly out of scope (a short or
  absent final after power loss is accepted; excluded from A2). (Verdict 7.)
- **D2 — Delivery contract (gate's record-identity decision, resolved):** the spool layer
  guarantees **atomic publication: every complete record appears in exactly one final
  file, exactly once**. End-to-end Fleet delivery remains **at-least-once** (filestream
  identity/rescan semantics can re-read a renamed file); no per-record idempotency key is
  adopted. Consequence accepted: rare duplicates at the reader layer are possible on
  agent-reader restarts — and on TSDS metrics streams they are naturally suppressed
  (same timestamp+dimensions → create conflict). This narrowed claim, not
  "exactly-once end-to-end", is the testable contract. (Verdicts 2, 12.)
- **D2a — Collision-proof final names.** `next_seq` resets per process (`shipper.rs:47`),
  so `<millis>-<seq>` can collide on rapid restart. Final-name publication MUST use
  exclusive creation (rename only onto a name proven free via `create_new`-style
  reservation, else bump seq and retry). Never replace an existing final. (Verdict 1.)
- **D2b — Recovery staging.** Recovery output is written to a NON-matching staging name,
  flushed, closed, then atomically renamed into the glob. On any failure (disk full,
  quarantine write error) the source `.tmp` is retained untouched — recovery is
  all-or-nothing per file, retried next startup. (Verdict 4.)

### Behavior

1. **Graceful shutdown:** shutdown owner attempts the summary write, then calls
   `finalize_all()` — **unconditionally, even if summary generation/write failed** — which
   for every dataset spool with a non-empty active file: flush, close, publish to a final
   name per D2a. Empty actives are removed. If the summary write itself triggered a stale
   rotation (observed live), the subsequent finalize is a harmless no-op for that dataset.
   (Verdict 5; forced-stale-at-summary test required.)
2. **Startup recovery — eager, all datasets:** recovery scans the whole spool directory at
   `SpoolWriter::new` (NOT lazily per-dataset — a stranded dataset that never emits again
   would otherwise never recover; scoping §2 requires first-startup recovery). For each
   stranded `.tmp`: **JSON-parse every complete line** (not just the last); valid lines →
   staging file → publish per D2b; any malformed line and any partial trailing bytes →
   `rigsignal-<dataset>-<millis>-<seq>.quarantine` (unique name, never matches the Fleet
   glob), one warning per recovery naming the quarantine file. Empty `.tmp` → reuse.
   (Verdicts 3, 6.)
3. **Retention (new):** at rotation time, delete final AND quarantine files older than
   `spool_retention_hours` (config, default 72). 72h is far beyond observed Fleet lag
   (~seconds); prevents the unbounded-growth debt above. Deletion is age-by-mtime,
   oldest-first, rate-limited per tick.
4. **Single-writer contract:** the spool directory is guarded by an advisory lock
   (flock on a lockfile) taken at `SpoolWriter::new`; a second agent instance fails fast
   with a clear error instead of racing the active `.tmp`. (Spar missed-item.)
5. **Reader contract:** finals keep the existing name scheme and glob; `.tmp`,
   `.quarantine`, staging names, and the lockfile are excluded. The deployed filestream
   configuration (native path identity, default scanner) is pinned in the A-tests — S2
   correctness claims are validated against the ACTUAL deployed Agent version, not
   assumed. (Verdict 2 + missed-item.)

### Acceptance criteria (reworked per verdict 11)

- A1 Graceful shutdown (unit/integration): write uniquely-markered records into ≥3
  datasets, shut down; assert every marker appears exactly once across final files, no
  non-empty `.tmp` remains, all names match the Fleet glob.
- A2 Crash/restart (SIGKILL, OS running): markered records + a deliberately truncated
  trailing line + a deliberately malformed interior line; restart; assert valid markers
  exactly once in finals, malformed + partial content in `.quarantine`, warning logged,
  source `.tmp` gone only on full success. Disk-full simulation: recovery fails, `.tmp`
  retained, no partial final published.
- A3 Name collision: force same-millis publication with a pre-existing final of the same
  name; assert exclusive-create bumps seq, never overwrites.
- A4 Rotation regression: existing stale-age test passes unchanged; ADD a size-rotation
  test (none exists today — `shipper.rs:623-650` covers stale only); forced-stale-at-
  summary shutdown test.
- A5 End-to-end Fleet (live, the streaming client): repeat the negative-control choreography post-deploy —
  assert a ZERO-gap ES timeline across the restart AND no duplicate docs (logs datasets
  checked by count, TSDS by absence of conflict storms); pin the deployed Agent version in
  the attestation. Fleet re-read of a recovered file is tolerated per D2 (at-least-once)
  but must be OBSERVED and recorded if it occurs.
- A6 Retention: finals + quarantine older than the configured window are pruned at
  rotation; newer files untouched; live disk usage on the streaming client drops from ~406 MB and stays
  bounded over 24h.
- A7 Lock: second agent instance against the same spool dir fails fast with the
  documented error.

---

(End of verbatim contract. A5/A6-live are run by the orchestrator post-merge, not by
you — your deliverables are the code plus tests A1–A4 and A7.)

## Hazard warnings — from the live code, address ALL of these

1. **`DatasetSpool::new` truncates the active `.tmp`** (`shipper.rs:196`+). Startup
   recovery MUST complete for the whole directory BEFORE any `DatasetSpool` is created,
   or recovery input is destroyed. Order inside `SpoolWriter::new`: flock first, then
   recovery scan, then normal operation.
2. **Rotation renames while the `BufWriter<File>` is still open** (`rotate()`,
   `shipper.rs:153`+). D1 requires flush + close BEFORE the rename in every publication
   path (rotation, finalize, recovery staging).
3. **The `main.rs` shutdown path can skip finalization when the summary write fails.**
   `finalize_all()` must run unconditionally on the shutdown path (Behavior 1) — use a
   structure that survives an early `?`/error from the summary step.
4. **Retention pruning runs inside the synchronous tick/rotation path.** It must never
   stall collection: bounded work per tick, no unbounded directory sorts on every tick
   (cache or cap the scan).

## Retention drain contract (sharpens Behavior 3; execution-spar verdict 4)

- Deletion batch floor: at least **1000 eligible files per rotation tick** (a rotation
  tick = each `rotate_stale_files` invocation), oldest-first by mtime.
- Stated deadline: a 40k-file backlog must fully drain in well under a day of uptime —
  at the current ~30s stale-rotation cadence, 1000/tick clears 40k in ~20 min. Document
  the chosen batch size as a constant with this rationale.
- Config: `spool_retention_hours` (u64, default 72) in `config.rs` beside the existing
  spool settings, plus the example TOML (`packaging/config/rigsignal.toml.example`).

## Files in scope

- `src/shipper.rs` — finalize_all, recovery, retention, flock, D2a naming (+ tests)
- `src/main.rs` — shutdown ordering (unconditional finalize), SpoolWriter::new call site
- `src/config.rs` — `spool_retention_hours`
- `packaging/config/rigsignal.toml.example` — new setting, commented, default 72
- `CHANGELOG.md` — Unreleased entry (no version header)

Protected: everything else. No dependency additions beyond what flock needs — prefer
`nix`/`rustix` if already in the tree, else `std`-only via `libc` if already present;
report if a new crate is unavoidable BEFORE adding it.

## Acceptance criteria (your deliverables)

- `cargo check` clean; `cargo test` green including NEW tests covering A1, A2 (incl.
  truncated + malformed + disk-full-retain cases), A3, A4 (stale regression unchanged +
  new size-rotation test + forced-stale-at-summary test), A7.
- Existing test suite untouched except where the contract requires additions.
- Summary must list: each Behavior item → where implemented; each hazard → how addressed;
  any contract conflicts found.

## STM contract

Before starting: `CHRONO_SESSION=2026-07-18-s2-spool bash /home/dev/coding/Workflow/scripts/stm.sh recall`.
On completion and on any non-obvious discovery: `stm.sh save "<title>" "<content>"
--kind learning|failure|decision|status` (set `STM_AGENT=codex@nuc`). Return only a
condensed summary — detail goes in STM. If STM is unreachable from your sandbox
(network is blocked), note that once in your summary and proceed — do not retry.
