# Owner-bundle apply/rollback design — v3

Session: `2026-07-24d-owner-bundle`. Target: owner cluster `192.0.2.174`
(ES `https://…:9200`, Kibana currently `http://…:5601` — see STOP #1 below).
Gate: overseer + Codex-Sol double gate before any implementation or live use.
Principal: `dev@192.0.2.144` (NUC), per the ratified session plan.

This is a **design document**, not executable code. Phase pseudocode below is
concrete enough for a Codex implementation task to build a script in the style
of `projects/Workflow/evidence/legacy-migration-2026-07-24b/live-migration-m1.sh`,
but nothing in this session writes to the owner cluster.

## Gate round 1 disposition

Both reviewers issued this document REWORK/APPROVE-WITH-NOTES on 2026-07-24d.
Union of required edits below; where the two conflict, Sol's binding rulings
win (evidence-grounded, later pass). "Adopted" = folded into this v2.

| # | Source | Edit required | Disposition |
|---|---|---|---|
| 1 | Overseer #1 | Data-stream count wrong (12→16); make loops dynamic | Adopted — §Preservation invariants, break-glass phase now enumerate `GET /_data_stream/*rigsignal*` dynamically; 16 streams/18 backing indices confirmed ground truth (`raw/data-streams.json`) |
| 2 | Overseer #2 | No TLS-proxy teardown capsule | Adopted — new capsule row, §Capsules |
| 3 | Overseer #3 | "100 rows" is 98 | Adopted — §Inputs |
| 4 | Overseer #4 | Transform `_meta`-restore fidelity unconfirmed | Adopted — folded into Sol #2's transform gate requirement below (superset of the same concern) |
| 5 | Overseer blocker 5 | Confirm native-user admin credential exists | **Cleared, not just adopted**: `PREFLIGHT-REPORT.md` addendum confirms `elastic`/reserved-realm native user via `GET /_security/_authenticate`. No longer an open item. |
| 6 | Overseer alignment note (ii) | Row-9 pipeline PUT vs. rollback design's BLOCKED stance | **Superseded by Sol #1** — the underlying DIFF-REPORT quiescence requirement for the pipeline was an evidence artifact (server timestamps compared as payload); corrected, the pipeline's operational body equals the bundle. This design adopts Sol's ruling: pipeline unblocked, standard adapter, no quiescence gate. See §4. |
| 7 | Sol #1 | Pipeline classification correction; class-specific compatibility projections | Adopted — §1 rewritten around `compatibility_projection()` per class; §4 pipeline unblocked |
| 8 | Sol #2 | `projection()` rejects pipelines/transforms; need public version-pinned adapter module with per-class `get_projection`/`request_body_from_preimage`/`compatibility_projection`/`verify` | Adopted — §1 intro + table restructured around this module; transform `_meta`-absent restoration gate added |
| 9 | Sol #3 | Phase-only state insufficient for partial rollback; need crash-safe per-object journal | Adopted — new §5 Transaction journal, replaces `state.env` as mutation authority; rollback order corrected |
| 10 | Sol #4 | Proof deletion conflicts with ratified A4 §5.4; proof capture not crash-safe | Adopted — proof-intent persistence pattern (§2); A4 exception drafted as a short A5 sub-clause (see `FLEET-COEXISTENCE-AMENDMENT-DRAFT.md` §8), flagged for owner ratification, not asserted here as already-ratified |
| 11 | Sol #5 | Marker granularity: 55 manifest assets, 16 owned/39 external, not 65 expanded live objects | Adopted — §Capsules and journal text now cite the manifest-level split; expanded per-object counts (this doc's dashboard/saved-object rows) are kept only as illustrative detail, never as the marker's authority |
| 12 | Sol #6 | Stream counts / rollover semantics | Adopted — 16/18 everywhere; three-way rollover handling (in-transaction / between-invocation / external Fleet upgrade) added to STOP conditions and §5 |
| 13 | Sol #7 | Transport security claims overstated | Not this document's scope (A5 §5 territory) — cross-referenced only via the proxy teardown capsule (#2 above) |
| — | (evidence) | Wire gate PASS 109/109 | `BINARY-PROVENANCE.md` final section: standalone handshake wire gate now PASS 109/109 against the pinned installed binary. Sol's "Release/live STOP" on the wire gate is cleared. |

### Round 2 (Sol confirmation pass)

Overseer's confirmation pass CONFIRMED both v2 docs unchanged. Sol's confirmation pass returned
**NOT CONFIRMED** on both, with six exact remaining edits (three land in this document; the
other three, plus one shared change, land in `FLEET-COEXISTENCE-AMENDMENT-DRAFT.md`). This is v3.

| # | Edit required | Disposition |
|---|---|---|
| R2-1 | Rename `installed_assets` → `applied_owned_assets` everywhere; define explicit `noop` action so all 16 owned manifest assets always appear, making 16+39=55 hold unconditionally | Adopted — §1.2's apply-phase pseudocode and marker text renamed; `noop` action specified in `FLEET-COEXISTENCE-AMENDMENT-DRAFT.md` §2.5 and referenced here at §6 `apply` |
| R2-2 | Dashboard/saved-object adapters bypassed the module contract — specify all four functions incl. absent-preimage case | Adopted — new §1.3, dashboard row in §1.2's table now points at it instead of describing the mechanism inline |
| R2-3 | Journal after-pin: `write_intent` must atomically persist `intended_after_sha256` + a durable request-body reference before the mutation; ambiguous-crash rule compares against the persisted after-pin; dashboard intents carry per-object hashes | Adopted — §5 rewritten |
| R2-4 | Component-template adapter row scoping: state explicitly that Fleet-owned components route through §3 verify-only *before* adapter selection, and the generic row applies to bundle-owned members only | Adopted — new routing-order note before §1.2's table |
| R2-5 | Transport: (a) label the accepted-risk `:5601` option as a new deviation needing its own fresh gate; (b) fix key-location statement — CA key stays on `192.0.2.144`, deployed leaf key/cert live on `192.0.2.174` at a protected path, with staging-shred + rollback removal | Lands in `FLEET-COEXISTENCE-AMENDMENT-DRAFT.md` §5; this document's TLS-proxy teardown capsule (§Capsules) is extended to name the owner-host artifacts explicitly, per (b) |
| R2-6 | `DIFF-REPORT.md`'s stale "pipeline comparison is exact body equality; pipeline GET is denied" normalization bullet; correct "four server timestamps" prose to match what the capture actually shows (two `_millis` fields observed; all four still stripped defensively by the projection) | Lands in `DIFF-REPORT.md`; this document's §1.1/§4 pipeline-timestamp prose corrected to match (projection still strips all four defensively) |

## Inputs

- `INVENTORY.tsv` — 26 equal / 42 different / 30 absent, 98 rows (corrected
  gate round 1: `logs-rigsignal.stream@pipeline` reclassified `different`→
  `equal`; see `DIFF-REPORT.md` "Correction (gate round 1)").
- `DIFF-REPORT.md` — STOP findings, Fleet-managed-template drift, writer
  exposure table (corrected), all 18 backing indices across 16 data streams,
  M1 anchors, normalization notes.
- `PREFLIGHT-REPORT.md` — STOP #1 (plaintext Kibana), STOP credential hygiene
  (0664 secret file, two-write whitelist exhausted), pinned bundle
  `sha256=aa57aade…` at commit `0d427d37`, cargo `0.3.0`; addendum confirms
  native-user (`elastic`, reserved realm) admin credential is available.
- `tls-proxy/ROLLBACK.md` — no deployment made; nothing to remove yet.
- Pinned installer `tools/install_assets.py` (same SHA) — read for its own
  canonicalization, ordering, and key-lifecycle functions; this design reuses
  them where they apply and adds a parallel adapter module where they do not
  (pipelines, transforms — see §1).

`uninstall.sh --purge` is explicitly **disqualified** as the rollback engine
(ES 9.4.x empty-id-array bug already caught in this session's STM trail).

## Design axioms (ratified, not relitigated here)

1. Class adapters, not per-asset bespoke blocks.
2. Rollback scope extends past ES/Kibana objects: local enrollment state,
   the minted shipper key, any provisioning proof, the install marker.
3. Transform rollback restores config **and** run state.
4. Snapshot/export is break-glass only; routine rollback is per-object
   inverse ops.
5. Data-stream/backing-index identity (16 streams / 18 backing indices,
   enumerated dynamically, never hardcoded), the 2 M1 doc IDs + JCS hashes,
   and the (currently empty) set of provisioning proofs must survive
   apply+rollback.
6. Separate capsules for TLS proxy, credentials, enrollment generation,
   Kibana saved objects, transform state, marker.
7. Fleet-managed templates/pipelines (13+13+13, verify-only per Sol's
   binding ruling) and final marker semantics are amendment-dependent —
   verify-only here, not designed. Writer-quiescence procedure is **not**
   needed for this milestone's asset set per the gate-round-1 pipeline
   correction (§4) — if a future manifest asset lands on an active write
   path with a genuine operational-body diff, quiescence remains undesigned
   and must be designed before that asset's apply.
8. Phase-gated, journal-resumable (§5), idempotent, explicit STOP conditions.
9. **New (Sol #2):** canonicalization/rollback logic for every class lives in
   a public, version-pinned adapter module with named `get_projection()`,
   `request_body_from_preimage()`, `compatibility_projection()`, and
   `verify()` functions — reusing the pinned installer's own private helpers
   where they already produce the correct behavior for a class, and
   supplying new functions where they do not (pipelines, transforms).
10. **New (Sol #3):** mutation authority is a crash-safe per-object
    transaction journal, not a coarse phase flag (§5).

---

## 1. Class adapters and the compatibility-projection module

**Adapter module architecture (Sol #2).** The pinned installer's `projection()`
explicitly rejects `pipelines` and `transforms` (`install_assets.py:855`); its
verify path (`verify_asset()`, `install_assets.py:946`) only compares
templates and roles — pipelines receive no comparison at all today. This
design therefore specifies a public, version-pinned adapter module
(same-SHA-pinned as the installer, imported by both apply and rollback) that
provides four named functions **per class**:

- `get_projection(class, live_body)` — strip server-injected fields not
  present in the bundle.
- `request_body_from_preimage(class, preimage)` — reconstruct the exact PUT
  body rollback must send to restore a preimage.
- `compatibility_projection(class, live_body)` — the class-specific equality
  oracle used for external/verify-only assets (never used to justify a
  write).
- `verify(class, live_body, pinned_hash)` — canonicalize + JCS + sha256,
  compare against the recorded pin.

For `component_templates`, `index_templates` (non-Fleet), `security_roles`,
`kibana_spaces`, `kibana_roles`, and `install_marker`, these four functions
are thin wrappers around the installer's own `projection()`,
`_strip_server_metadata()`, `_normalize_settings_scalars()`, and
`es_path()`/`kibana_path()` — so apply-time and rollback-time equality can
never diverge from what the installer itself considers "equal". For
`pipelines` and `transforms`, the module supplies new functions (below)
because the installer's own helpers do not cover them.

### 1.1 Compatibility projections, by class (Sol #1, binding)

- **Component templates:** strip only server timestamps
  (`created_date`/`created_date_millis`/`modified_date`/`modified_date_millis`,
  mirroring the pipeline fields below where present) and the ratified
  `_meta.managed_by` difference; require everything else equal.
- **Fleet index templates (external only):** additionally permit exactly the
  two Fleet `composed_of` members (`.fleet_globals-1`,
  `.fleet_agent_id_verification-1`) and corresponding managed-by fields;
  require every other field equal, then check effective owned
  mappings/settings/default-pipeline/lifecycle via `_simulate_index`
  outcome-equivalence (§3.2 of the amendment).
- **Pipelines:** extract `response[name]` (GET returns `{name: body}`, not
  the bare body); strip the four server timestamps
  (`created_date`, `created_date_millis`, `modified_date`,
  `modified_date_millis`); permit only the ratified ownership-metadata
  difference (`_meta.managed_by`); require `processors`, `on_failure`, and
  all other operational content equal. (Observed-vs-defensive note, gate
  round 2: this cluster's pipeline captures only ever carry `created_date_millis`/
  `modified_date_millis` — the human-readable `created_date`/`modified_date`
  pair is stripped defensively, in case a differently-configured stack
  emits it, not because it was seen here.) This is the projection whose
  absence produced the gate-round-1 evidence artifact — see `DIFF-REPORT.md`
  "Correction (gate round 1)". It is now used both for the (already-run)
  inventory classification and for the live verify-only re-checks of the 13
  Fleet pipelines at preimage-capture/apply/verify.

### 1.2 Class adapter table

**Routing order for `component_templates` and `index_templates` (Sol round 2, explicit):**
ownership resolution (amendment §1/§2.2) runs **before** class-adapter selection, not after. For
both classes, every asset's `(kind, name)` is first looked up in the ownership table; the 13
Fleet-owned component templates and the 13 Fleet-owned index templates (amendment §1 rows 6, 8)
are routed to the **external verify-only path** (§3 below, `compatibility_projection()`) and
never reach the class adapter row in this table at all — they get no `write_intent`, no
`get_projection()`/`request_body_from_preimage()` call, nothing. The `component_templates` and
`index_templates` rows below therefore apply **only to bundle-owned members of each class**: the
1 diagnosis component template + 1 diagnosis index template (row 1), plus (for index templates)
`logs-rigsignal.stream` and `metrics-rigsignal.profiles` (rows 9–10). This scoping was implicit
in v1/v2 and is stated explicitly here per Sol's round-2 confirmation-pass finding.

| Class | Preimage capture | Verdict: equal | Verdict: different (existing) | Verdict: absent | Rollback inverse |
|---|---|---|---|---|---|
| `component_templates` (**bundle-owned only** — see routing note above) | `GET /_component_template/{name}`, `get_projection()` | no HTTP write; journaled as `write_intent`/`write_verified` with `action:"noop"`, `request_body_sha256` = bundle body hash (§5, §2.5 of the amendment) | apply `PUT` bundle body (`action:"update"`); rollback `PUT` `request_body_from_preimage()` | apply `PUT` (create, `action:"create"`); rollback `DELETE /_component_template/{name}` | `verify()` vs. pin |
| `index_templates` (**bundle-owned only** — see routing note above; non-Fleet — see §3) | `GET /_index_template/{name}`, `get_projection()` | no HTTP write; journaled `action:"noop"` (same as component templates) | apply `PUT` bundle body (`action:"update"`); rollback `PUT` `request_body_from_preimage()` | apply `PUT` (`action:"create"`); rollback `DELETE /_index_template/{name}` | `verify()` vs. pin |
| `security_roles` (`rigsignal_shipper`) | `GET /_security/role/{name}`, role-specific stripping (`_ROLE_SERVER_KEYS`, `_ROLE_EMPTY_DEFAULT_KEYS`) | n/a (live is absent) | n/a | apply `PUT /_security/role/rigsignal_shipper` (`action:"create"`); rollback `DELETE /_security/role/rigsignal_shipper` | `verify()`; absent-on-rollback confirmed by 404 |
| `pipelines` (non-Fleet only — see §3, §4) | `GET /_ingest/pipeline/{name}`, `get_projection()` extracts `response[name]` then strips the four server timestamps | `logs-rigsignal.stream@pipeline` post-correction: no HTTP write; journaled `action:"noop"` | apply `PUT` bundle body (`action:"update"`); rollback `PUT` `request_body_from_preimage()` | apply `PUT` (`action:"create"`); rollback `DELETE /_ingest/pipeline/{name}`; on ES's specific default-pipeline in-use guard, retain and journal the retained state (§5) | `verify()` on the operational-content projection (§1.1), not raw-body equality |
| `transforms` (`rigsignal-game-timeline`) | `GET /_transform/{name}` **and** `GET /_transform/{name}/_stats` (state); `get_projection()` strips `id`, `version`, `create_time`, `authorization`, stats/state/checkpointing | n/a (live differs only in `_meta` visibility; `pivot` exactly equal) | apply `POST /_transform/{name}/_update` with bundle body minus `pivot` (installer's own update-hazard guard, matched here; `action:"update"`); rollback `POST …/_update` with preimage body minus `pivot` | n/a (live already exists) | config `verify()` **and** `_stats.state` unchanged, **gated on the transform `_meta`-absent-restore proof below** |
| `kibana_spaces` (`rigsignal`) | `GET /api/spaces/space/{id}` | n/a | n/a | apply `POST /api/spaces/space` (create, per installer's 404-branch; `action:"create"`); rollback `DELETE /api/spaces/space/rigsignal` | `verify()`; absent-on-rollback confirmed by 404 |
| `kibana_roles` (`rigsignal_viewer`) | `GET /api/security/role/{name}` | n/a | n/a | apply `PUT /api/security/role/rigsignal_viewer` (`action:"create"`); rollback `DELETE /api/security/role/rigsignal_viewer` | `verify()`; absent-on-rollback confirmed by 404 |
| `dashboard`/saved-object bundles (7 manifest bundles, 18 saved objects: 15 in space `rigsignal`, 3 in `default`) — **routed through the adapter module (§1.3), not bypassed** | see §1.3 | n/a (all absent live today) | n/a | see §1.3 (`action:"import"`) | see §1.3 |
| `install_marker` (`rigsignal-bundle-meta`) | `GET /_component_template/rigsignal-bundle-meta` | n/a (absent live today) | n/a | apply `PUT` last (installer step 11; `action:"create"`); rollback `DELETE /_component_template/rigsignal-bundle-meta`, restoring the preexisting absent state | 404 post-rollback |

### 1.3 Dashboard/saved-object class adapter (Sol round 2 — was bypassed in v2, now specified)

The dashboard/saved-object class gets the same four adapter-module functions as every other
class, not a hand-waved "apply via installer's own import path" bypass:

- **`get_projection(class, live_body)`:** for each manifest saved-object ID (enumerated from the
  bundle's own `dashboard_objects()`, not the ndjson blob as a whole), `GET /s/{space}/api/saved_objects/{type}/{id}`
  (or `/api/saved_objects/{type}/{id}` for the `default` space); a 404 projects to the sentinel
  value `ABSENT` — there is no live body to strip fields from when the object does not exist,
  which is the case for all 18 objects today.
- **`request_body_from_preimage(class, preimage)`:** if the preimage is `ABSENT` (today's case
  for every object), there is no PUT/import body to reconstruct — the rollback inverse for an
  `ABSENT` preimage is deletion, not a restore-PUT (see inverse, below). If a future preimage is
  a real object body (an object that already existed pre-apply, e.g. a second invocation
  overwriting the first's dashboards), this function reconstructs the exact `attributes`/
  `references` payload the installer's multipart importer would need to restore it.
- **`compatibility_projection(class, live_body)`:** not applicable — dashboard/saved-object
  assets are always bundle-owned (amendment §1 row 3), never external/verify-only, so this
  function is never called for this class; it exists only for interface uniformity with the
  other classes.
- **`verify(class, live_body, pinned_hash)`:** for an `ABSENT` preimage post-apply, verify means
  confirming the object now exists and its canonicalized `attributes`/`references` hash matches
  the bundle's recorded pin. For an `ABSENT` state post-rollback, verify means confirming the
  object is `ABSENT` again (404) — the same absence check used everywhere else in this design
  for "rollback restored the pre-apply absent state" (matches the `install_marker`,
  `kibana_spaces`, and `kibana_roles` rows' rollback oracle).

**Apply:** the installer's own `dashboard_import_path`/multipart import, but only after
**enumerating every saved-object ID as a journaled `write_intent`** (§5) — each intent carries
its own `intended_after_sha256` (the per-object canonicalized hash the import is expected to
produce) — before the import call runs.

**Rollback inverse:** delete each `(object_type, object_id)` pair from that enumeration — never
a wildcard space wipe — via `DELETE /s/rigsignal/api/saved_objects/{type}/{id}` (product
dashboards) or `DELETE /api/saved_objects/{type}/{id}` (streaming-lab, default space). Because
today's preimage is `ABSENT` for all 18 objects, this is always a delete-back-to-absent, never a
restore-a-prior-body operation — but the adapter functions above are written generally so a
future non-absent preimage (a rerun over an already-dashboarded cluster) is handled by the same
module rather than a special case.

**Oracle:** `verify()` above; post-rollback, 404 on each object id, matching the pre-apply
baseline exactly as it does for `kibana_spaces`/`kibana_roles`/`install_marker`.

**Ratification (owner-ratified 2026-07-28, dashboard-origin v8 §5):** §1.2's routing note and
§1.3's dashboard/saved-object adapter — including the clean-stack/first-install qualification that
today's preimage is `ABSENT` for all 18 objects — stand **verbatim, unchanged**; v8 §5 names both as
"kept verbatim from v3 (no round-3 findings against these)". This adapter's `get_projection`/
`request_body_from_preimage`/`verify` triad is unaffected by the dashboard-origin fix: the fix's
fail-closed topology preflight (v8 §2 W-B, `run_topology_preflight`) runs **before** this adapter's
own apply path is ever reached, refusing pre-mutation rather than changing what the adapter does
once apply proceeds; the Kibana `_import`-response-based regeneration check that guards the actual
multipart import call (v8 §2, inside `install_asset`'s dashboard branch) likewise runs on the same
absent-preimage, 18-object topology this section already describes. `ERRATA-v8.md` E2/E5 (alias
cascade-delete and `createNewCopies` origin-reset) are fixture-level findings about the *gate leg
harness* that exercises this adapter's rollback inverse, not amendments to the adapter's own
`get_projection`/`request_body_from_preimage`/`verify` contract stated above.

### Transform `_meta`-absent-restore gate (Sol #2 / Overseer #4)

Live transform GET omits the bundle `_meta`; apply *adds* it via
`_update`. Because `_update` is a partial merge, it is not proven that a
rollback `_update` whose preimage lacks `_meta` can reproduce the *absence*
of `_meta` (as opposed to leaving the applied value in place). This design
requires a standalone gate — starting from absent `_meta`, applying, then
rolling back to absent again, on both supported stack versions (9.4.3,
9.4.4), while `pivot` and `_stats.state=started` are preserved throughout —
to be run and evidenced (Phase 3 history-shaped rehearsal is the natural
home for it) before Phase 4 relies on transform rollback. **If that proof
does not hold on either version, the transform falls back to verify-only**
(same treatment as the 13 Fleet-managed classes): apply is skipped, and the
cosmetic `_meta`-only diff is left as a documented, accepted drift.

### 2. Rollback scope beyond ES/Kibana objects (axiom 2)

| Item | Preimage | Inverse op | Oracle |
|---|---|---|---|
| Enrollment local state (`~/.local/state/rigsignal/enrollment/{state.json,credentials.toml,handshake.toml,shipping-policy-v1.toml}` + transient `candidate/`) | today: root absent (clean, per Phase 0 P0.1) | remove exactly the root apply's `atomic_publication()` created, reusing the installer's own path-ownership/symlink guards (`_reject_symlinked_path`, `secure_root`) rather than a bare `rm -rf`; never touch a root that fails those guards | root absent again, or retained completed journal/body audit files only; `enrollment_condition(root) == "clean" or "rolled-back"` (owner-ratified 2026-07-25) |
| Shipper API key | none — key does not exist before apply | apply mints via `mint_key()` with `role_descriptors={"rigsignal_shipper": role_body(bundle)}` **using the native-user admin credential** (confirmed available, `PREFLIGHT-REPORT.md` addendum; `mint_key()` at `install_assets.py:1362-1367` refuses the API-key-auth branch at non-dry-run), immediately persists the exact ID as a journaled intent (§5); rollback revokes **only that exact ID** via `DELETE /_security/api_key {"ids":[id]}`, with a name-based recovery fallback (`GET /_security/api_key?name=…&active_only=true`, exactly `invalidate_mint_name()`'s logic) if the ID was lost mid-crash | per ES 9.4.x semantics already validated in Phase 0.5: `invalidated`/`previously_invalidated_api_keys` both empty + `error_count:0` on a response to a valid request **is** confirmed-inactive, not a failure — rollback must accept that as PASS, not retry-loop on it |
| Provisioning proof (`event.id` prefix `provision-`) | none exist today (Phase 0.5 confirmed, `INVENTORY.tsv` row 97) | apply's own live-write verification (`verify_stream_behavior`/`candidate_document`, `install_assets.py:1477`, which returns no identifier from the call itself) creates exactly the docs it writes; **crash-safe intent pattern (Sol #4): persist the exact `event.id` as an intent before `_create`; record the returned `_index` afterward, once available.** Rollback deletes **by the exact backing index + `_id`** recovered this way — crash recovery may search the diagnosis stream for that one exact ID, require zero or one hit, then delete by exact backing index and ID; no wildcard search or delete-by-query, ever. | post-rollback `event.id: provision-*` search returns 0 hits for this transaction's proofs, matching the pre-apply baseline. **Deleting an accepted proof at all requires the explicit owner-ratified A4 exception** drafted as a short A5 sub-clause (`FLEET-COEXISTENCE-AMENDMENT-DRAFT.md` §8) — ratified A4 §5.4 otherwise retains accepted proofs permanently; this design does not assume that exception is already ratified. |
| Install marker | absent (§1 table) | see §1 | see §1 |

### 3. Deferred (amendment-dependent, verify-only — axiom 7)

Per Sol's binding ruling (gate round 1), the external verify-only scope is
exactly **13 component templates + 13 index templates + 13 pipelines** — 39
manifest assets, scoped by **ownership** (live `_meta` identifies Fleet),
not by body equality. This design does **not** specify an apply or rollback
write for them. Apply phase treats them as **verify-only**: GET, run the
class's `compatibility_projection()` (§1.1), assert it still holds against
the Phase-1 baseline; any unexpected drift is a STOP (§5), not a write
trigger. A future Fleet-coexistence amendment (`FLEET-COEXISTENCE-AMENDMENT-DRAFT.md`)
defines this class's ownership table normatively; this design only
implements the mechanics.

Final marker semantics (whether the marker encodes partial Fleet-scope
completion) follow the amendment's manifest-level accounting: 55 manifest
assets, split 16 bundle-owned / 39 external, disjoint sets, per Sol's
binding ruling. See §5.

### 4. `logs-rigsignal.stream` template and pipeline (row 9) — corrected, gate round 1

Both `logs-rigsignal.stream` (index template) and `logs-rigsignal.stream@pipeline`
are **not** Fleet-managed and are **bundle-owned** (Sol's binding ruling).
Gate round 1 corrects this design's original stance, which had blocked
both pending an undesigned writer-quiescence procedure:

- **`logs-rigsignal.stream@pipeline` is unblocked.** DIFF-REPORT's original
  "semantic active-write-path diff" verdict was an evidence artifact —
  server-injected `created_date_millis`/`modified_date_millis` (the pair
  actually present in this cluster's pipeline captures; the projection
  strips the human-readable `created_date`/`modified_date` variants too,
  defensively, though neither appears here) were compared as payload. After the corrected
  `compatibility_projection()` (§1.1), the operational body equals the
  bundle. This is a metadata-only diff, the same category as a cosmetic
  `_meta.managed_by`-only component-template diff. It gets the standard §1
  adapter, unconditionally — no quiescence gate.
- **`logs-rigsignal.stream` (template) is unblocked for a different reason.**
  Its diff is a genuine lifecycle policy-identity change
  (`logs-rigsignal-stream-30d` → `logs@lifecycle`). But a composable index
  template PUT only affects *future* rollovers/index creation, not the
  current backing index or in-flight writes — so its exposure is
  next-rollover-deferred, not immediate (`DIFF-REPORT.md`, corrected writer
  exposure table). It therefore does not need writer quiescence either. It
  **does** still require: (a) owner ratification of the policy-identity
  change (amendment §1.2/open question 3), and (b) the same-day
  delete-phase-free re-read of both policies immediately pre-PUT (amendment
  §3 item 4 — this design's preflight phase re-checks it every run, per
  §5's pseudocode).
- **Writer-quiescence procedure remains undesigned** (axiom 7) — nothing in
  this milestone's asset set needs it. If a future manifest asset lands on
  an active write path with a genuine operational-body diff, that procedure
  must be designed before that asset's apply.

`metrics-rigsignal.profiles` (also `index_templates`, also "different") is
cosmetic `_meta.managed_by` only, unconditionally on the standard adapter,
unaffected by this section.

### Preservation invariants checked at every phase boundary

- All 16 data streams / 18 backing index (name, UUID) pairs unchanged —
  enumerated **dynamically** via `GET /_data_stream/*rigsignal*` before and
  after both apply and rollback (never a hardcoded count; ground truth:
  `raw/data-streams.json`, 3 `logs-*` + 13 `metrics-*` streams, audio and
  ebpf each with 2 backing indices).
- The 2 M1 doc IDs (`13610797-…`, `76e28921-…`) and their JCS SHA-256 hashes
  (`e86e538f…`, `03cff192…`) unchanged — same `fetch_by_id`/`hash_source`
  technique as `live-migration-m1.sh`.
- Provisioning-proof count returns to the pre-transaction baseline after
  rollback (§2) — not necessarily 0, if a prior transaction's proofs are
  retained per ratified A4 §5.4.
- `ownership_profile` and `ownership_table_version` (persisted in both
  protected transaction/enrollment state and the marker) match on every
  boundary; a mismatch fences the invocation (Sol #5).
  - **Owner ratification (2026-07-27, v3 gate ruling 5):** the profile limb of this
    invariant is DIRECTIONAL by design: a remote marker carrying `fleet-coexist` fences
    any non-coexist invocation, while remote `default`/absent → requested `fleet-coexist`
    is A5's own migration direction and is intentionally not fenced (it fails closed
    downstream at the Fleet-composition check if the remote is not genuinely
    Fleet-composed). The `ownership_table_version` limb is unconditional: any remote
    marker version differing from the invoker's `OWNERSHIP_TABLE_VERSION` refuses; a
    `fleet-coexist` marker lacking the version refuses (every coexist writer stamps
    it); a pre-A5 `default` marker lacking it is legacy input on the accepted
    migration direction. This stamp corrects the v2 closure record, which wrongly marked the version limb
    implemented (v3 findings F1-v3/S3-v3).

### Capsules (axiom 6)

| Capsule | Status this session | Notes |
|---|---|---|
| TLS proxy listener + CA on `192.0.2.174` | No deployment made — `tls-proxy/ROLLBACK.md` confirms nothing to remove today | **New (Overseer #2), owner-host artifacts named explicitly (Sol round 2):** once A5 §5's transport path is deployed, its teardown capsule must cover the `:5643` listener, its systemd unit, any firewall rule, and — split by host, per A5 §5's corrected key-location statement — (a) on `192.0.2.174` (owner host): the deployed leaf key/cert pair at `/etc/nginx/rigsignal-tls/` (`root:root`, dir `0750`, key `0600`, cert `0644`) and any un-shredded staging copy; teardown removes the deployed leaf key/cert from `192.0.2.174` and confirms the listener is gone; (b) on `192.0.2.144` (NUC): the proxy CA's own private key is the durable signing authority and is **not** removed by a single deployment's rollback (it survives to sign a future re-deployment) — only a full A5 decommission would retire it. This design does not yet specify the removal script because nothing is deployed; it must land before the proxy is ever used for a live invocation, not retrofitted after. STOP #1 (plaintext Kibana `:5601`) resolution and the §5.5 remote-`:5601`-block open ratification item are A5 §5's track, not this design's. |
| Temporary credentials | Not yet exercised in this draft | Must fix the Phase 0.5 credential-hygiene STOP (0664 secret file) before implementation: mirror `live-migration-m1.sh`'s `CRED_FILE="$(mktemp)"; trap 'rm -f "$CRED_FILE"' EXIT` pattern and explicitly `chmod 0600`/verify the mode, not just remove-on-exit |
| Local enrollment generation | §2 | reuse installer's own guarded removal, not `rm -rf` |
| Kibana saved objects | §1 | enumerated deletes only, journaled as pre-import intents (§5) |
| Transform state | §1 | config + run-state both restored, gated on the `_meta`-absent-restore proof |
| Provisioning proof | §2 | exact `event.id` intent persisted before `_create`; deletion requires the A4 exception |
| Install marker | §1, §3 | absent today; step-11-equivalent ordering both directions; carries `ownership_profile`/`ownership_table_version` |

---

## 5. Transaction journal (replaces phase-only mutation authority — Sol #3)

The original draft permitted rollback with only a coarse `PREIMAGE_OK` phase
flag and then reversed every asset unconditionally. If apply crashes
midway, that can overwrite assets the transaction never touched, or delete a
marker created later by another actor. This design replaces `state.env` as
the **mutation authority** (it remains useful for phase sequencing) with an
atomic, protected **per-object journal**:

- `write_intent` is persisted **atomically, before** every remote mutation
  (one entry per `(kind, name, action)`), and — **extended, Sol round 2** —
  carries two additional fields written in the same atomic persist, not a
  follow-up write: `intended_after_sha256` (the canonical hash the mutation
  is expected to produce — for `action:"noop"` this equals the preimage
  hash, since no change is expected) and a **durable request-body
  reference**: `{path, sha256}` pointing at the exact on-disk body the
  mutation is about to send (the same file `preimage-capture`/apply staged
  under `preimage/<class>/<name>.json` or the bundle's own asset path — this
  design never re-derives the body from memory at recovery time, it re-reads
  the referenced file and re-checks its hash against the persisted
  `sha256`). This is what makes the after-pin durable across a crash: the
  journal alone (without re-running any canonicalization logic) tells
  recovery exactly what was about to happen and exactly which bytes were
  about to be sent.
- `write_verified` plus the after-hash is persisted **immediately after**
  verification succeeds.
- Rollback acts **only** on journaled intents — never on the full asset set
  inferred from the manifest.
- **Ambiguous-crash three-way rule (Sol round 2: compare against the
  intent's persisted after-pin, not an abstractly-implied one):** for any
  intent without a matching `write_verified`, re-GET the live object and
  compare its hash against the **persisted `intended_after_sha256`** on
  that exact intent record. If live == `intended_after_sha256`, treat it as
  applied and restore from preimage. If live == the preimage hash, treat it
  as a no-op (never mutated, or a `noop`-action intent that behaved exactly
  as expected) and do nothing further. If live matches neither, **STOP** as
  concurrent drift — do not guess, and do not fall back to re-deriving an
  expected hash from the manifest at recovery time (the durable
  request-body reference exists precisely so recovery never has to).
- Dashboard-import intents enumerate **every saved-object ID** before the
  multipart import call, **each carrying its own per-object
  `intended_after_sha256`** (not one hash for the whole bundle import), so a
  partial import is recoverable object-by-object rather than
  all-or-nothing, and the three-way rule above applies per object, not per
  import call.
- **External assets never receive a rollback inverse** — they are
  verify-only by construction (§3); no intent is ever journaled for them.
- `ownership_profile` and `ownership_table_version` are persisted in this
  protected journal/enrollment state, mirroring the marker (§Capsules);
  a supplied profile that differs from persisted state refuses before any
  mutation.
- **Pipeline retained in use (owner-ratified 2026-07-25):** when deletion of a
  pipeline created by this transaction receives ES's 400
  `illegal_argument_exception` stating it cannot be deleted because it is the
  default pipeline for an index, rollback retains that pipeline, persists
  `pipeline_retained_in_use` with the parsed referencing index names on its
  journal intent, reports it to the operator, and still completes with
  `rollback_ok`. Any other 400 remains a failure.
- **Topology preflight and recovery-sweep exemption (owner-ratified 2026-07-28, dashboard-origin
  v8 §5):** the fail-closed saved-object topology preflight (`run_topology_preflight`, v8 §2 W-B),
  its rollback-time recovery sweep for lost-response id-regeneration orphans (`_recovery_sweep`,
  v8 §2 W-B (a)(iii) degradation marker), and the `test_pause` test hook are all **outside
  `write_intent` scope, by the same reasoning as the preflight itself** — none of the three is a
  journaled mutation of a bundle-owned asset. The preflight is proof-of-activity read traffic only
  (every verdict traces to a validated `200`, never an unqualified `404`); the recovery sweep's own
  deletes act only on forensically-logged, hash-verified regenerated-id orphans identified by
  `asset_adapters.sha256(asset_adapters.get_projection("dashboard", row))` (v8 §9 D-1/D-5), never on
  a journaled dashboard-import intent from §1.3 above; `test_pause` is inert unless test-enabled and
  never issues a remote call. A degradation-sweep DELETE that fails leaves a named orphan and
  refuses `saved_object_id_regenerated_cleanup_failed` (§6 STOP list below) rather than silently
  retrying or rolling forward.

**Rollback order (corrected, Sol #3):**

1. Delete the transaction-owned marker.
2. Fence any consumer (the shipper key's role/descriptor scope).
3. Revoke and confirm the exact minted key ID.
4. Remove the protected enrollment publication.
5. Remove exact transaction proofs (only under the A4 exception, §2).
6. Restore owned assets, in reverse dependency order.

This never leaves a live credential able to write while its role/templates
are mid-restore — the credential is revoked (steps 2–3) before any owned
asset is touched (step 6).

**Rollover handling, three cases (Sol #6):**

- **In-transaction rollover** (a rollover fires between preimage-capture and
  verify): fail-closed **before publication**, and exercise the journaled
  rollback/recovery path above — do not attempt to detect "legitimate" vs.
  installer-caused rollover mid-transaction; treat any rollover observed
  inside the transaction window as a STOP.
- **Between-invocation rollover** (rollover happens after one successful
  invocation completes, before the next runs): this is a separate, later
  successful rerun leg — rebaseline the new backing set (`(name, UUID)`
  pairs) and preserve the earlier invocation's anchors; it is not a defect
  in the prior run.
- **External Fleet upgrades:** may change external asset hashes at any
  time. Rollback verifies **current** compatibility against the live Fleet
  state; it never requires restoring an obsolete external preimage — Fleet
  assets have no rollback inverse (§3).

---

## 6. Phase-gated runbook spec

Same shape as `live-migration-m1.sh`: `usage: <script> preflight|preimage-capture|break-glass|apply|verify|rollback`,
a `state.env` of `mark`/`need`/`get_state` for phase sequencing plus the
per-object journal (§5) for mutation authority, a `verdict-rows.tsv` of
`row()`/`pass_or_die()`, admin creds loaded from `~/.elastic/kibana-local.env`
(native-user `elastic`/reserved-realm — confirmed available, `PREFLIGHT-REPORT.md`
addendum) into a trapped 0600 temp file, never on a command line.

```text
PHASE=preflight
  - id/HOME/enrollment-root check (Phase 0 P0.1 pattern); STOP if root is not
    "clean" or fails ownership/symlink guards.
  - GET / and GET /_cluster/health; STOP if status == red, or yellow with any
    unassigned primary or any pending task (cluster-health explanation gate).
  - GET the actual Kibana endpoint; STOP if scheme != https (STOP #1 gate —
    this phase re-checks it every run, it does not assume it was fixed).
  - GET /_security/api_key?name=rigsignal-provision-*&active_only=true;
    STOP if any active key already matches the shipper mint-name pattern
    (baseline must be clean, mirrors Phase 0.5's own clean-baseline finding).
  - Confirm admin credential is native-user (username/password), not an API
    key — refuse before Step 5 otherwise (mint_key() would refuse anyway).
  - Same-day delete-phase-free re-read of `logs-rigsignal-stream-30d` and
    `logs@lifecycle` (amendment §3 item 4) if the template PUT is in scope.
  - Pin: bundle sha256, source commit, manifest asset list (55 assets, split
    16 bundle-owned / 39 external per §3), cluster_uuid.
  - mark PREFLIGHT_OK

PHASE=preimage-capture
  need PREFLIGHT_OK
  - For every bundle-owned manifest asset (§1, §4) + marker: run the class's
    `get_projection()`, `verify()` sha256, write preimage/<class>/<name>.json,
    persist as a `write_intent`-eligible candidate (not yet journaled — that
    happens at apply).
  - For the 39 external assets (§3): capture a verify-only baseline hash via
    `compatibility_projection()`, tag DEFERRED.
  - Idempotency rule: if a preimage file already exists, re-capture and
    compare; a mismatch means the live object moved between runs — STOP,
    do not silently overwrite the recorded preimage.
  - mark PREIMAGE_OK

PHASE=break-glass   # optional insurance, never auto-invoked by rollback
  need PREIMAGE_OK
  - PUT /_snapshot/{repo}/{owner-bundle-2026-07-24d-pre}?wait_for_completion=true
    over all 16 RigSignal data streams, dynamically enumerated via
    `GET /_data_stream/*rigsignal*` (same shape as live-migration-m1.sh's
    snapshot phase); Kibana saved-object export of spaces `rigsignal` and
    `default` (RigSignal objects only). Absent Kibana spaces/objects count as
    a valid empty preimage — do not treat 404 here as a failure.
  - This phase only *captures*. Restoring from it is a human, break-glass-only
    decision made after evaluating the data-loss caveat (axiom 4) — no later
    phase in this runbook invokes _restore automatically.
  - mark BREAKGLASS_OK

PHASE=apply
  need PREIMAGE_OK
  - **Preflight call order, corrected (owner-ratified 2026-07-28, dashboard-origin v8 §5 —
    apply-sequence pseudocode amendment, matches installer:2934-3035 exactly):**
    admin_credential_kind(...) -> dispatch_clean_root(...) ->
    fence_remote_ownership_profile(...) -> run_topology_preflight(bundle, es_url, kb_url,
    authorization) [NEW — the W-B fail-closed saved-object topology preflight, v8 §2] ->
    test_pause("after-topology-preflight", unsafe_test_injection) [NEW — inert unless
    test-enabled] -> secure_root(...) -> bind_ownership_profile(...) ->
    TransactionJournal(root, profile, new_transaction=True). Both new steps run strictly
    before secure_root/bind_ownership_profile/journal construction and before any asset
    mutation; a refusal from either is a pure no-op against local and remote state (§5's
    write_intent-exemption note above).
  - Walk assets in the pinned installer's own ordered_assets() priority:
    component_templates, index_templates, security_roles, pipelines,
    transforms, kibana_spaces, kibana_roles, dashboard, then marker last.
  - Skip DEFERRED (external, §3) assets: `compatibility_projection()`,
    assert unchanged from preimage baseline; STOP if drifted — an
    uncoordinated external change is not this runbook's to silently paper
    over.
  - For every bundle-owned asset (including `logs-rigsignal.stream` template
    and pipeline, now unblocked — §4): persist `write_intent` (with
    `intended_after_sha256` and a durable request-body reference, §5)
    immediately before the mutation call — **including assets whose adapter
    finds live state already canonically equal to the bundle body** (the
    diagnosis component/index template pair; `logs-rigsignal.stream@pipeline`
    post-correction): these get action `noop` rather than being skipped, so
    every one of the 16 bundle-owned manifest assets is always journaled.
    Run the §1 apply op (a `noop` action makes no HTTP mutation); persist
    `write_verified` + after-hash immediately after `verify()` confirms the
    bundle pin (for `noop`, the after-hash is simply the pre-existing live
    hash, already equal to the pin).
  - Shipper key: `mint_key()` using the native-user credential -> persist
    intent through the state.json phase machine exactly as the pinned
    installer does (mint_intent -> candidate_staged -> candidate_verified ->
    committed); do not skip a phase.
  - Provisioning-proof docs created incidentally by live-write verification:
    persist the exact `event.id` as an intent **before** `_create`; record
    the returned `_index` afterward.
  - Dashboard import: persist every saved-object ID as an intent, each
    carrying its own `intended_after_sha256`, before the multipart import
    call (§5).
  - marker PUT only after every other non-skipped asset's `write_verified`
    is recorded; marker itself gets a `write_intent`/`write_verified` pair
    too, carrying `ownership_profile`/`ownership_table_version` and the two
    disjoint `applied_owned_assets`/`verified_external_assets` lists (all 16
    bundle-owned assets present in `applied_owned_assets`, each tagged with
    its actual `action` including `noop` — renamed from `installed_assets`,
    gate round 2, to stop implying every entry is a fresh write).
  - mark APPLY_OK

PHASE=verify
  need APPLY_OK
  - M1 anchors: 2 doc IDs + JCS hashes unchanged.
  - All 16 data streams / 18 backing index (name, UUID) pairs unchanged,
    dynamically enumerated.
  - Transform: config `verify()` == bundle pin (minus pivot, which was never
    touched) and `_stats.state` == preimage state (started); skip to
    verify-only if the `_meta`-absent-restore gate did not pass rehearsal.
  - Shipper key: exactly one active key for the mint name; role matrix
    matches `role_body(bundle)`.
  - Enrollment state.json: phase == committed, pending_revoke_ids == [],
    exactly one active_key_id.
  - Deferred (external) classes: still match their preimage baseline
    (untouched) via `compatibility_projection()`.
  - Dashboard render pointer only (A3.1 six-dashboard check owned by a
    separate task, not re-specified here).
  - mark VERIFY_OK

PHASE=rollback
  need PREIMAGE_OK        # resumable even if APPLY_OK never completed;
                           # acts only on the journal (§5), not on phase flags
  - Determine the journaled intent set. For any intent lacking
    write_verified, apply the ambiguous-crash three-way rule (§5) before
    proceeding.
  - Execute the corrected rollback order (§5): marker -> fence consumer ->
    revoke+confirm exact key -> remove enrollment publication -> remove
    exact transaction proofs (A4-exception-gated) -> restore owned assets in
    reverse dependency order, using each class's `request_body_from_preimage()`.
  - Revoke the exact minted key ID (or mint-name active_only=true recovery);
    accept ES 9.4.x's empty-list+error_count:0 response as confirmed-inactive.
  - Delete exact provisioning-proof doc(s) by exact backing index + `_id`
    recovered from the persisted intent — never a `provision-*` wildcard.
  - Remove the exact enrollment root apply created, via the installer's own
    guarded removal.
  - Re-run the verify-phase oracle set (§6 verify), but against preimage
    pins instead of bundle pins, plus: provisioning-proof count returns to
    the pre-transaction baseline, enrollment root == clean or rolled-back
    (owner-ratified 2026-07-25).
  - mark ROLLBACK_OK
```

### STOP conditions (any one aborts the current phase immediately)

- Preimage recapture mismatches a previously recorded preimage hash.
- Kibana endpoint is not HTTPS at preflight or apply time.
- Cluster health is red, or yellow with any unassigned primary or any
  pending task.
- Admin credential resolves to an API key, not a native user, at any
  invocation that reaches the mint step.
- Any DEFERRED (§3) class shows drift from its own preimage baseline during
  apply or verify — treat as an uncoordinated external change, not a
  green-light to write.
- Transform's live `pivot` ever differs from the preimage `pivot` at any
  checkpoint (the installer's own known update-hazard).
- Transform `_meta`-absent-restore has not been proven on the running stack
  version — fall back to verify-only rather than assuming restoration works.
- API-key invalidate response has nonzero `error_count`, or `error_details`
  contains an entry whose `id` is in the target set.
- Enrollment root fails the ownership/symlink guard at any phase.
- M1 anchor hash mismatch at verify or rollback — escalate to a break-glass
  restore evaluation rather than continuing automated rollback.
- An in-transaction rollover is observed on any tracked stream (§5) — fail
  closed before publication.
- `ownership_profile`/`ownership_table_version` in the journal/enrollment
  state disagrees with the supplied profile or the marker — refuse.
- An ambiguous-crash intent's live state matches neither the preimage nor
  the after-pin — concurrent drift, STOP (§5).
- Attempted deletion of a transaction proof without the ratified A4
  exception in force.
- **New rows (owner-ratified 2026-07-28, dashboard-origin v8 §5) — the topology preflight (W-B)
  refuses before any mutation:**
  - `saved_object_topology_conflict` — a bundle id already exists elsewhere (`literal_id_exists_elsewhere`),
    a legacy-url-alias references one (`alias_match`), or two bundle files define the same
    `(type, id, target_space)` divergently (`duplicate_divergent_definition`) or map the same
    `(type, id)` to more than one `target_space` (`inconsistent_target`) — resolve by hand per
    `elastic/README.md`'s two-part remediation, then re-run; no local or remote state was touched.
  - `saved_object_topology_unverifiable` — the topology could not be proven complete (non-`superuser`
    credential, unreadable/malformed/paginated space or `_find` response, malformed alias row) — never
    treat as clean; re-run with a `superuser` credential against a reachable Kibana.
  - `saved_object_id_regenerated` — Kibana regenerated a bundle id despite the preflight (a race);
    the installer's own targeted cleanup runs automatically.
  - `saved_object_id_regenerated_cleanup_failed` — the targeted cleanup's own DELETE failed; an
    orphaned UUID survives at the named `(type, destinationId, space)` — escalate, do not retry the
    install, resolve the orphan by hand first.

---

## Open items for the gate

Most round-1 open items are now resolved (see disposition table above:
native-user credential confirmed, wire gate green, pipeline reclassified).
Remaining:

1. Should break-glass capture (§6, `break-glass` phase) be mandatory-but-never-
   auto-restored as drafted, or fully optional? **Sol's binding ruling:
   optional.** This draft still describes it as available/optional per that
   ruling — no change needed, but flagging that the ruling supersedes this
   draft's earlier "assumes mandatory capture" framing.
2. STOP #1 (plaintext Kibana) resolution remains out of scope of this
   design — A5 §5's transport track owns it, subject to Sol #7's corrected
   security claims and the new gate requirements there.
3. Public adapter-module dependency (Sol #2, now adopted): sign-off needed
   on whether importing the pinned SHA's private helpers for the classes
   where they already work (vs. writing new public functions only for
   pipelines/transforms) is the right split, or whether all classes should
   get fresh public functions for uniformity.
4. The Phase 0.5 credential-hygiene STOP (0664 secret file, not shredded)
   must be fixed in the actual `CRED_FILE` handling before implementation —
   this draft specifies the M1 pattern but the fix itself is not yet built.
5. Confirm the transform `_meta`-absent-restore rehearsal (both versions) is
   scheduled for Phase 3 before Phase 4 relies on transform rollback, per
   the new gate in §1.2.
6. The A4 proof-deletion exception is **drafted, not ratified** — see
   `FLEET-COEXISTENCE-AMENDMENT-DRAFT.md` §8. Rollback's proof-deletion step
   is inert until that exception clears owner ratification.
