# TK-3 — Clean-stack fresh + upgrade matrix (turnkey-readiness slice)

Context: Amendment 1 sequence; TK-1 harness (`scripts/clean-stack/{lib.sh,spike.sh}`) and
TK-2 bundle tooling (`elastic/`, `tools/build_asset_bundle.py`, `tools/install_assets.py`)
are merged and live-proven (51/51 fresh + idempotent on 9.4.4). TK-3 turns those pieces
into the repeatable G4 matrix. You have NO network/docker access: author scripts +
fixtures + tests; the orchestrator executes live. Inputs staged for you (input-only, do
NOT commit the raw exports): `tools/asset-export-2026-07-22/` now also contains
`sample-doc-cpu.json` and `sample-doc-events.json` — real production docs to derive
fixtures from.

## Deliverables

1. **`scripts/clean-stack/matrix.sh`** — reuses `lib.sh`. Modes:
   - `matrix.sh fresh <ES_VERSION>`: boot clean stack → `install_assets.py --bundle` (built
     on the fly via `build_asset_bundle.py` unless `--bundle PATH` given) → ingest fixtures
     → exact-value asserts → teardown. Exit 0 only if every assert passes.
   - `matrix.sh upgrade <ES_VERSION>`: boot clean stack → install the PREVIOUS-STATE assets
     (deliverable 3) → ingest fixtures (sentinel docs) → record doc _ids + counts → install
     the CURRENT bundle over it → assert: sentinel docs survive byte-identical (_source
     hash), counts unchanged, bundle marker `rigsignal-bundle-meta` present with current
     version, saved-object import produced no duplicates (dashboard count by title equals
     canonical count), exact-value asserts still pass → teardown.
   - `matrix.sh stackupgrade <FROM_ES> <TO_ES>`: boot FROM stack → current bundle → ingest
     → stop containers, restart SAME data volumes with TO images (this mode needs named
     volumes — create run-scoped named volumes, remove them in teardown) → wait healthy →
     re-run asserts. (This is the in-place stack upgrade leg.)
   - `--keep` and `--dry-run` behave as in spike.sh.
2. **Fixtures `fixtures/clean-stack/{cpu-doc.json,events-doc.json}`** derived from the
   samples: keep real structure/dimensions, normalize `host.name` to lowercase
   `fixture-host.example` (both docs), set an obvious marker value in one numeric field
   you then assert exactly (document which). `@timestamp` must be set AT INGEST TIME by
   the script (TSDS accept window — a stale timestamp will be rejected); script injects
   `"@timestamp"` via jq before POST.
3. **Previous-state assets `scripts/clean-stack/previous-state/`**: generated from the raw
   export (committed here, since they ARE the documented baseline): the raw production
   index/component templates + pipelines, minimally adapted — `.fleet_*` entries stripped
   from composed_of (they cannot exist on a clean stack), volatile fields stripped, and
   cluster-local ILM policy references replaced the same way TK-2 did. Include a README
   stating exactly what this simulates: "the 0.3.0-era production asset state, minimally
   adapted to boot on a Fleet-free clean stack" — and that this is the honest 'previous
   asset version' until 0.3.1 ships a real bundle (per Amendment 1 / Sol F5: never
   install-current-twice). Install it with a small `install-previous-state.sh` (plain curl
   loop is fine here — failures must abort, no silent skips).
4. **Asserts** (in matrix.sh, via ES|QL `/_query`):
   - cpu doc: `FROM metrics-rigsignal.cpu-default | WHERE host.name == "fixture-host.example"`
     returns exactly 1 row with the exact marker value.
   - events doc: analogous.
   - dashboards: saved-objects find by type=dashboard returns exactly the canonical count
     (7); each canonical title present exactly once.
   - templates: `_index_template/metrics-rigsignal.cpu` exists; `_ingest/pipeline` for its
     default_pipeline exists.
   - render-proof (data level): execute one representative ES|QL query lifted from a
     canonical dashboard panel against the ingested fixture and assert non-empty result.
     Browser-visual verification is explicitly OUT of scope (documented in QA-MATRIX
     addition as a known limitation, deferred to the app/kiosk design task).
5. **`pytest` regression tests `tools/tests/test_asset_tools.py`** (closes
   `tasks/tk2-followup-asset-tool-tests.md`): (a) missing referenced pipeline fails build,
   (b) missing composed_of component fails build, (c) non-conforming filename fails build,
   (d) installer failure-table + nonzero exit on asset error (mock urllib), (e) transform
   update path strips pivot. Stdlib + pytest only; must pass with `python3 -m pytest tools/tests/ -q`.
6. **`docs/QA-MATRIX.md`** — add a "Clean-stack matrix (G4)" section: what each mode
   proves, how to run, the previous-state definition, the browser-visual limitation, and
   that TK-4 publishes the supported range only after all modes pass at both endpoints.

## Acceptance criteria (binary)

- AC1: `bash -n` + shellcheck clean on new scripts; `python3 -m pytest tools/tests/ -q` green.
- AC2: `matrix.sh --dry-run fresh 9.4.4` prints the full command plan with zero network/docker calls.
- AC3: fixtures are valid JSON, lowercase host.name, marker values documented in QA-MATRIX.
- AC4: previous-state dir contains only adapted assets + README; raw export NOT committed.
- AC5: every assert failure path exits nonzero with a named assert in the output
  (`ASSERT FAIL <name>`), never a silent pass. Grep-provable: no assert helper can return
  success without comparing against an expected value.
- AC6: your final summary lists each matrix mode with its exact assert inventory.

## Constraints

- New/changed files: `scripts/clean-stack/matrix.sh`, `scripts/clean-stack/previous-state/**`,
  `scripts/clean-stack/install-previous-state.sh`, `fixtures/clean-stack/**`,
  `tools/tests/**`, `docs/QA-MATRIX.md` section append, and (only if needed) minor
  additions to `scripts/clean-stack/lib.sh` that stay backward-compatible with spike.sh.
- Commit on this branch (codex/tk3-matrix). Final message: condensed summary only.
