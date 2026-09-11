# Task: host.name lowercase normalization (canonical contract, all emitters)

CHRONO_SESSION=2026-07-21-deploy-valve-d6

## STM contract (do this first and last)
- First: `bash ~/coding/Workflow/scripts/stm.sh recall --all-sessions --last 15 --grep "host.name"` — catch up.
- Last: save learnings/failures/status via `bash ~/coding/Workflow/scripts/stm.sh save "<title>" "<content>" --kind <learning|failure|status> --project RigSignal --session 2026-07-21-deploy-valve-d6`.
- Return only a condensed summary; detail goes in the RESULT file + STM.

## Context
- Known data bug: `host.name` case split in ES — the eBPF daemon emits `Fixture-PEER.EXAMPLE` (reads
  `/etc/hostname` raw at `ebpf/rigsignal-ebpf/src/main.rs:96`, hostinfo in
  `ebpf/rigsignal-ebpf/src/es_model.rs`), while the userspace agent emits lowercase
  (`src/host.rs::hostname()` reading `/proc/sys/kernel/hostname`; Windows path reads
  `COMPUTERNAME`, which is typically UPPERCASE — also a latent split source).
- `host.name` is a TSDS dimension; historic docs keep the split (queries use TO_LOWER) —
  do NOT attempt any data migration. This task is emission-side only.
- Contract decision (ratified): canonical `host.name` is ASCII-lowercased at the emission
  boundary in EVERY emitter, so no code path can regress: userspace metrics, sessions,
  direct events, remote_connections/stream docs, eBPF and ebpf_thread and correlation docs.

## Work (repo ~/coding/RigSignal, worktree: `git worktree add worktrees/codex-hostname-fix -b codex-hostname-fix` off main 4134524)
1. Userspace: normalize in ONE place — `src/host.rs::hostname()` returns the lowercased,
   trimmed value (unix + windows branches). Audit all callers (main.rs base_doc paths,
   remote_connections.rs, diagnose.rs) to confirm nothing re-reads the hostname elsewhere;
   the diagnose bug-report dump may print the raw OS value additionally if it wants, but any
   emitted/structured `host.name` must be the canonical lowercase.
2. eBPF daemon: normalize the `/etc/hostname` read (trim + ASCII-lowercase) at
   `ebpf/rigsignal-ebpf/src/main.rs:96` (and any other host field population in es_model.rs).
3. Lowercasing = `str::to_lowercase()` (Unicode-safe) or explicit ASCII lowercase — pick one,
   use it in both crates, note the choice in the RESULT file.
4. Tests (the CI workflows do NOT adequately cover this — ci.yml never enters ebpf/):
   a. Unit test in userspace: hostname normalization incl. a mixed-case and an
      UPPERCASE (Windows-style) input — test the normalization function directly with
      injected input, not the live /proc read.
   b. Raw-document tests: for each doc family that carries `host.name` (metrics, session
      start/end, direct events, stream_client, ebpf, ebpf_thread, correlation), assert the
      emitted JSON's `host.name` is lowercase given a mixed-case host input. Reuse the
      existing raw-payload test patterns where present; add minimal ones where absent.
   c. eBPF crate: `cargo test` for the es_model/hostinfo normalization (host-side unit test,
      no kernel needed).
5. Verify: `cargo check` + `cargo test` in BOTH crates (agent workspace and ebpf/), plus the
   pinned `cargo xtask build-all --release` if that xtask exists (check; otherwise the
   documented pinned-nightly ebpf build per CI/feedback_ebpf_ci_build pattern — build must
   succeed, artifacts land where the build normally puts them).
6. MINIMAL diff. No opportunistic refactors, no data migration, no dashboard/query changes.

## Acceptance criteria
- All emitters produce lowercase `host.name` under mixed-case host input, proven by tests.
- `cargo check` + `cargo test` green in both crates; release build of both artifacts succeeds.
- Diff touches only hostname read/normalization sites + tests.
- RESULT file: tasks/host-name-normalization.RESULT.md with changed files, test list,
  build artifact paths + sha256s of the built agent binary and eBPF daemon (candidate
  hashes — NOT to be written to milestone-attestations.md; that promotion happens later).
