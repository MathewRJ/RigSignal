# eBPF probes rebuild result

Date: 2026-07-16

## Changes

- Raised the shared per-TID `GAME_PIDS` BPF hash map from 256 to 1024 entries.
  No other 256-entry per-TID map exists in the probes crate.
- Changed `SchedProbe::update_pids` so a failed TID insertion logs the TID and
  continues seeding the remaining TIDs instead of returning early.

## Build and validation

- Built together from the same worktree source snapshot:
  - `rigsignal-ebpf-probes` (BPF ELF)
  - `rigsignal-ebpf` (userspace eBPF daemon)
- Build command: `cd ebpf && cargo xtask build-all --release`.
- Toolchain: `rustc 1.98.0-nightly (f428d123a 2026-06-19)`;
  `cargo 1.98.0-nightly (598ab48ec 2026-06-17)`; `bpf-linker 0.10.4`
  (installed with `cargo install bpf-linker --locked`).
- `cargo check` passed in the root and `ebpf/` workspaces.
- Tests passed: root workspace 55/55; eBPF workspace 2/2.
- The two changed Rust files pass `rustfmt --check`. A workspace-wide eBPF
  formatting check remains blocked by a pre-existing formatting difference in
  `ebpf/xtask/src/main.rs`; it was not changed.

## Staged artifacts

| File | SHA-256 |
| --- | --- |
| `deploy-staging/rigsignal-ebpf` | `b724f9675c8aab6ad5c9fcffadd88640a55356f29850b7442871b03ef549aa80` |
| `deploy-staging/rigsignal-ebpf-probes` | `4a25554f2fff451660b47e8b8a13dcc4e797b7dae79e097e46cbde3a21fb7fa7` |

`deploy-staging/DEPLOY.md` contains the user-run, paired SteamOS install and
post-install checks. No remote action was performed.

## Drift confirmation

The task's live handoff/STM records that the gaming host has the original bootstrap
probe ELF at `/usr/local/lib/rigsignal/rigsignal-ebpf-probes`, while the
userspace daemon was later rebuilt and deployed; that is the expected
bytecode/userspace map-contract drift. Per the amendment, all Git operations
were skipped, so no additional Git-history comparison was performed here.
