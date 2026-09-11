# Task: rigsignal-024-item5-round-a-delivery — shipper routing + remote_connections tailer

Session: 2026-07-18-024-item5. Workspace: the RigSignal git worktree you are launched in.
Do NOT commit — the orchestrator commits after review. Structure your changes so the two
review units are separable: (1) tailer/state-machine, (2) shipper/ack wiring + main-loop
integration.

## Contract (read first, follow exactly)

`/home/dev/coding/Workflow/projects/RigSignal/RIGSIGNAL-024-ITEM5-SPEC.md` — sections
"Event document and parser contract", "No-local-game correlation rule", "Durable
event-tail and idempotent delivery contract", "Identity, acknowledgement, and shipper
change", and **"Addendum 2026-07-18 — events delivery routing"** (overseer-gated routing
decision; it modifies the base sections where they conflict). Where this task file and
the spec conflict, the spec+addendum win; report the conflict.

## Scope

### 1. Shipper extension (`src/shipper.rs`)
- Route each document to `{data_stream.type}-{data_stream.dataset}-default`; validate
  type is `metrics` or `logs` (reject otherwise with an error, not a panic).
- Extend the bulk action builder (the `{"create":{"_index":index}}` construction around
  `src/shipper.rs:337`) to accept an optional internal `_id`.
- Treat HTTP 201 AND keyed-create 409 (`version_conflict_engine_exception`) as delivery
  success for keyed documents. Unkeyed metrics keep existing behavior bit-for-bit;
  existing shipper tests must stay green.
- Never pass `?pipeline=` or `pipeline=_none` (addendum point 2).

### 2. remote_connections tailer (new module, main-loop-owned — NOT a Collector impl)
- Tail `$HOME/.local/share/Steam/logs/remote_connections.txt` per the parser contract:
  bracketed local-time timestamp → UTC (DST-ambiguous → earlier instant + warn;
  nonexistent local time or malformed line → consumed without a document, debug/warn),
  accept ONLY `connected`/`disconnected`, transport mapping direct/relay/unknown, omit
  `transport` when no `via` phrase, emit no nulls, no `message` field.
- Document shape exactly per the spec JSON examples: `event.kind` scalar,
  `event.category`/`event.type` JSON ARRAYS. No-local-game rule: merge
  `rigsignal.session.{id,label,agent_version}` + `rigsignal.game.*` only when
  `SessionManager.current_game` is present at that tick; otherwise omit both groups
  entirely — never attach `idle-*` labels or the idle session UUID.
- State at `$XDG_STATE_HOME/rigsignal/stream-client-tail.json` (fallbacks per spec), dir
  0700 / file 0600, atomic write (same-dir tmp + fsync + rename + fsync parent).
- Checkpoint semantics per spec: offset = byte after last committed complete line for the
  `(dev, ino)` generation; first-ever run commits current EOF (no backfill); truncation →
  reset to zero + log; replacement while running → drain old handle to EOF then new
  generation at zero; after restart → search only the log directory's
  `remote_connections.txt.*` regular files for the saved dev/ino, drain if found, else
  rotation-gap warning and current path from zero. Incomplete trailing line stays at its
  offset. 64 KiB complete-line cap: log once, consume as unparseable, advance checkpoint.
- Identity: `sha256(host.name || dev || ino || byte_start_offset || raw_line_bytes)` hex,
  used as bulk `_id`, never stored as a document field.
- Batching: ≤100 lines or 256 KiB per batch; envelopes carry a contiguous byte-range
  token; `ack_success(token)` performs the atomic checkpoint only when every envelope
  through that token succeeded (201 or 409); no later token acknowledged ahead of an
  earlier one; on transport error / non-409 item error / shutdown / crash, retain the
  token and replay from the old checkpoint.

### 3. Main-loop wiring + routing (addendum)
- The tailer's event envelopes ALWAYS ship via the direct-ES bulk shipper to
  `logs-rigsignal.events-default`, regardless of the configured output mode (metrics
  stay on the configured spool path unchanged).
- Config surface: reuse the existing Elasticsearch endpoint/credentials config section.
  In spool mode, if no ES endpoint/credentials are configured, the tailer stays disabled
  with a single startup warning (no crash, no spooled events). Tailer runs only on Linux.

### 4. Tests (unit, no network — mock/inject the bulk result)
201 acknowledgement; 409 acknowledgement; bulk failure → no checkpoint advance;
crash/replay → identical `_id` (byte-identical identity input); truncation reset;
replacement/new-generation; rotated-file drain; partial-line hold + reread; DST-ambiguous
earlier choice; oversize-line consume+advance; parser fixture for the spec's example line
(`[2026-07-17 09:09:44] Client 1000000000000000001 (fixture-peer.example) connected via direct
connection`) and a disconnect variant; transport mapping incl. missing `via`; no-local-game
document omits session/game groups. Existing shipper tests unchanged and green.

## Gates you run (report honestly)

`cargo check` and `cargo test` from the worktree root. Report exact pass/fail counts. If
sandboxing blocks anything, say so — do not fake results.

## STM contract

Before starting: `CHRONO_SESSION=2026-07-18-024-item5 bash /home/dev/coding/Workflow/scripts/stm.sh recall`.
On completion and on any non-obvious discovery:
`stm.sh save "<title>" "<content>" --kind learning|failure|decision|status` with
`STM_AGENT=codex@nuc`. Return only a condensed summary — detail goes in STM.
