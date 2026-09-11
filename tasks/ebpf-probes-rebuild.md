# Task: eBPF probes rebuild + GAME_PIDS resize + non-aborting seed loop

CHRONO_SESSION=2026-07-16-elastic-agentic

## STM contract (do this first and last)
- First: `bash ~/coding/Workflow/scripts/stm.sh recall --all-sessions --last 15 --grep ebpf` — catch up.
- Last: save learnings/failures/status via `bash ~/coding/Workflow/scripts/stm.sh save "<title>" "<content>" --kind <learning|failure|status> --project RigSignal --session 2026-07-16-elastic-agentic`.
- Return only a condensed summary; detail goes in the RESULT file + STM.

## Context (validated live 2026-07-16)
- eBPF SHIPPING is fixed (CA port merged 0f4658c, userspace deployed on the gaming host, zero flush
  errors) but DOC PRODUCTION is zero. Prime suspect: probes ELF at
  `/usr/local/lib/rigsignal/rigsignal-ebpf-probes` on the box is the ORIGINAL bootstrap build —
  userspace/bytecode map-contract drift.
- Known additional bugs to fix while in there: GAME_PIDS map max_entries=256 (FC6 hit 276 TIDs)
  and the PID seed loop ABORTS mid-loop on map-full (userspace main.rs ~line 135 warn) —
  must become non-aborting (warn per entry, continue).
- Build pattern that works (see memory feedback_ebpf_ci_build + repo CI files): pinned nightly
  toolchain + `cargo install bpf-linker --locked`; `allow(unused_unsafe)` + `unsafe{}` wrapper
  pattern already in the source.

## Work (repo ~/coding/RigSignal, use a worktree: `git worktree add worktrees/codex-ebpf-rebuild -b codex-ebpf-rebuild`)
1. Locate the probes crate + userspace collector. Confirm from git history what rev the box's
   deployed probes ELF was built from vs current main (explains the drift).
2. Code changes (MINIMAL, no opportunistic refactors):
   a. GAME_PIDS (and any sibling per-TID map with the same 256 cap) max_entries 256 → 1024.
   b. Seed loop: on insert failure warn-and-continue instead of aborting the loop.
3. Rebuild BOTH artifacts from the same rev (paired deploy is mandatory — map contract):
   a. probes ELF (pinned nightly + bpf-linker per CI pattern; install toolchain if missing —
      rustup + cargo install are allowed).
   b. userspace release binary (the rigsignal agent) — same source tree.
4. Validate: `cargo check` (workspace) + existing tests. Do NOT touch manifest/pipeline/packaging
   files. Do NOT deploy anything to any box. Do NOT commit to main — commit on the worktree branch.
5. Stage artifacts + sha256sums in the worktree under `deploy-staging/` and write a
   deploy runbook `deploy-staging/DEPLOY.md`: exact scp/install commands for the gaming host
   deck@192.0.2.254 (SteamOS: needs `sudo steamos-readonly disable` window, user-run;
   agent restart procedure as used for the 0.2.3 install; paired install of BOTH files;
   post-install check commands: journal grep for probe-load lines, GAME_PIDS seed warns gone).
6. Write `tasks/ebpf-probes-rebuild.RESULT.md` (condensed: what changed, build versions used,
   artifact shas, drift confirmation, anything surprising).

## Acceptance
- Both artifacts build clean from one rev; cargo check + tests pass; diff limited to map size +
  seed loop (+ Cargo.lock if unavoidable); RESULT + DEPLOY.md written; STM saved.
