# Task: shared collector regression — memory.* / storage.* / power fields dead

**Class:** 0.3.x maintenance (telemetry-freeze-compatible — restores existing fields, adds none)
**Status:** BACKLOG — do NOT dispatch while the D3 implementation arc is active (shared
collector/common-file overlap; spar finding F10, 2026-07-21f). If dispatched, branch from the
merged post-D3 SHA.
**Origin:** system-health dashboard trim audit 2026-07-21e (evidence:
`Workflow projects/RigSignal/evidence/system-health-trim-2026-07-21/PROPOSAL.md`,
ES mem-1784657518-9228, STM j0jNhZ8BTyUckH-jLMDO).

## Symptom

Fields with zero non-null ingest, confirmed against `metrics-rigsignal.*` on the local cluster:

| Field | Dead since | Notes |
|---|---|---|
| `rigsignal.memory.used_mb` | 2026-06-11 | |
| `rigsignal.memory.available_mb` | 2026-06-11 | |
| `rigsignal.memory.used_pct` | 2026-06-11 | was one series in the Proton game-RSS panel |
| `rigsignal.storage.read_bytes_per_sec` | 2026-06-11 | |
| `rigsignal.storage.write_bytes_per_sec` | 2026-06-11 | |
| `rigsignal.power.ac_connected` | ~2026-07-13 | last value 2026-07-13 — may be a separate/later break |

`rigsignal.memory.game_rss_mb` is ALIVE (16.7k docs/24h) — the memory collector is not wholly
dead; only these series stopped.

## Hypothesis

memory.* and storage.* dying on the SAME date points to ONE shared regression (likely a change
merged 2026-06-11 in the agent's collector plumbing, not two coincident breaks). power.* may be
the same bug surfacing later or an independent break — verify separately.

## Investigation steps

1. `git log --oneline --since 2026-06-09 --until 2026-06-13` on RigSignal — identify the
   candidate commit(s); diff collector/common paths (`src/collectors/`, spool serialization).
2. Reproduce locally: run the agent, check whether the fields are absent at emission (spool
   NDJSON) or dropped at ingest (pipeline). Field-name drift vs `fields.yml` is a known failure
   class (see feedback_field_audit_before_deploy).
3. Check live spool files on the gaming host and the streaming client for the fields to split agent-side vs pipeline-side.
4. For `power.ac_connected`: correlate the ~2026-07-13 death with deploys/changes around 0.2.x.

## Acceptance

- Root cause identified and stated for each field group (memory/storage vs power).
- Fix merged; fields ingesting again with sane values on BOTH boxes (fresh docs in ES).
- Restore the 3 dropped system-health panels (Power State Over Time, System Memory Usage Over
  Time, Storage Throughput Over Time) and the `used_pct` series in the game-RSS panel —
  pre-trim panel JSON preserved in the trim evidence dir (`pre-edit/`).
- `cargo check` + full test suite green; `elastic-package check` if any pipeline/manifest touched.
