# Task: rigsignal-0.2.4-gpu-sched-loss — diagnose + fix gpu_sched event loss (A9.2-R comparison FAILED)

Session: `CHRONO_SESSION=2026-07-17-024-kickoff`. You are `codex-impl@dev` in worktree
`worktrees/codex-024-gpu-sched` (branch fast-forwarded to main ad4da7d, which contains
your legacy-port merge). Git is read-only for you — no commits; orchestrator commits.
Write `tasks/rigsignal-0.2.4-gpu-sched-loss.RESULT.md` in the worktree.

> Before starting: `CHRONO_SESSION=2026-07-17-024-kickoff bash /home/dev/coding/Workflow/scripts/stm.sh recall --all-sessions --last 30`. Save findings via stm.sh (STM_AGENT=codex-impl@dev); if curl is blocked, put them in the RESULT. Return a condensed summary.

## Live evidence (the gaming host running valve 6.16, HFW session 00000000-0000-4000-8000-000000000002, 2026-07-17 19:50–20:01Z)

1. Port deployed; journal shows `variant="legacy" key_field="id" key_offset=32`, 9/9 probes.
2. **Kernel ground truth** (root ftrace capture 19:53:42–19:54:42, parsed by
   `scripts/gpu-sched-reference-parse.py`): **61,213 paired events in 60s (~1020/s
   sustained)**, min/mean/max = 1.0/7.68/199 μs, log2 buckets
   `counts=0,168,31891,20329,3449,1766,3106,450,54,0…` — continuous full-rate stream.
3. **Daemon output** (metrics-rigsignal.ebpf-default): gpu_sched snapshots appear only
   **3–5 per minute** with multi-minute dead zones (19:51: 3 docs, 19:52: 3, 19:53–19:56:
   ZERO — includes the whole capture window, 19:57: 3, 19:58: 5, 19:59: 1, 20:00: 5).
   Each emitted snapshot holds ~1020–1028 events, i.e. exactly ONE second of full-rate
   data. Loss is >90% of seconds. Other probes' docs flow normally (~100 docs/min).
4. **Zero warnings**: journal since install has no ring/drop/full/lost/overflow lines.
   The loss is silent.
5. First check right after session start also showed only 6 snapshots over the first
   ~2.5 min — sparse from the beginning, not a fill-up-then-die decay.

## Facts to weigh

- `GPU_SCHED_TS: HashMap<u64,u64> max_entries=4096`; `GPU_SCHED_EVENTS: RingBuf`
  (`RING_BUF_BYTES` — check the constant). Legacy `id` is a per-scheduler MONOTONIC
  atomic counter: keys never repeat, so any queue-entry whose run-event is missed leaks
  FOREVER (no overwrite-by-reuse); ids also collide across schedulers/rings (same
  counter value on different rings) — a cross-ring collision overwrites an in-flight
  timestamp and the eventual two run-events produce one wrong-pairing and one miss.
  The renamed variant's fence_seqno has similar-but-not-identical semantics.
- The userspace drain cadence/batching for the RingBuf and the aggregator's per-second
  window attribution (aggregator.rs ~line 483 emits the snapshot; find where events are
  consumed and bucketed) are as your port left them — the port did not touch drain code,
  so a pre-existing drain/aggregation defect may only now be VISIBLE because the legacy
  kernel actually produces events at 1020/s on this box.

## Mandate

1. Root-cause the sparseness with code evidence. Classify the loss point: (a) BPF-side
   insert failure (TS map full from monotonic-key leakage), (b) RingBuf overflow vs
   drain cadence, (c) userspace drain starvation/batch cap, (d) aggregator window
   attribution (events collected but attributed to one second, rest discarded), or a
   combination. Explain the observed shape (~exactly-one-full-second bursts, then dead
   zones) — the fix must explain THIS pattern, not a generic possibility. Explain why it
   is silent (missing drop counters) and whether the pattern is timing-consistent with
   the evidence timeline above.
2. Implement the fix in the worktree. Constraints: emitted ES field schema unchanged;
   probes+daemon may both change (they deploy as a pair); TS-map hygiene for monotonic
   keys (stale-entry eviction or LRU map) is in scope; ADD drop/loss counters logged at
   warn (rate-limited) so this class of loss is never silent again — a counter log line
   does not violate the schema constraint.
3. Tests: unit tests for the fixed logic; if the root cause is drain/aggregation, a test
   that replays a synthetic 1000-events/s stream across multiple seconds and asserts
   per-second snapshots emerge for every second.
4. Validation: `cargo check` + full `cargo test` (workspace + `-p rigsignal-ebpf`),
   `cargo xtask build-all --release`, `rustfmt --check` on changed files.

Do not touch files outside the gpu_sched/drain/aggregator code paths, their tests, and
your RESULT file. No opportunistic refactors.
