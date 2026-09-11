# Amendment A5 (Fleet-coexistence) — explicit ownership-aware installer profile

**STATUS: DRAFT v3 — gate round 1 (overseer + Codex-Sol xhigh) complete, both REWORK, folded into
v2; gate round 2 (Sol confirmation pass on v2) returned NOT CONFIRMED with six exact edits
(overseer CONFIRMED v2 unchanged), folded into this v3. Pending re-gate at the next implementing
SHA + new bundle hash (§4.3), then owner ratification.** Everything below is proposed "MUST"
text; it has **no normative force** until all three ratification boxes at the end are checked.
Do not cite this document as contract text before then.

- **Session:** `2026-07-24d-owner-bundle`
- **Evidence base:** `projects/Workflow/evidence/owner-bundle-2026-07-24d/{DIFF-REPORT.md,
  INVENTORY.tsv, CLUSTER-HEALTH.md, PREFLIGHT-REPORT.md, KEY-LIFECYCLE.md,
  BINARY-PROVENANCE.md, tls-proxy/}`. All owner-cluster requests behind this evidence were
  read-only GETs plus three documented read-only `_search` POSTs and exactly one authorized
  mint/invalidate API-key pair; no owner-cluster write touched writer state on the gaming host or the streaming client.
- **What this amends:**
  - `tasks/rigsignal-p1-provisioning-order.md` §"v2.2 Exact fresh fence, archive gate, and
    complete barrier" — specifically the unconditional obligation at line 263, "Install and
    verify every existing manifest asset ... before credential release/marker: component/index
    templates, pipelines, transforms, dashboards, and W1 assets in dependency order." This
    amendment carves a second, distinct, bounded exception into that obligation (Amendment
    7/A4's `--adopt-existing-w1-stream` exception is the first; see below).
  - `tools/install_assets.py` Steps 5–11, specifically the ordered complete-manifest barrier
    (`for asset in bundle.assets: install_asset(...)`, line 1716–1727) and marker semantics.
  - Relationship to `installer-adoption-2026-07-24c/ADOPTION-AMENDMENT.md` (Amendment 7 for
    `W1-DIAGNOSISEVENT-CONTRACT.md`, Amendment A4 for `W2-SPACE-ROLE-CONTRACT.md`): that
    amendment answers "may the installer adopt a compatible remote W1 stream onto a clean local
    root instead of refusing?" — a **local enrollment-state** question. This amendment answers
    a different question: "when a remote asset that the manifest would otherwise PUT is already
    owned and managed by a third party (Fleet), must the installer still PUT it?" — an
    **asset-ownership** question. The two compose: Amendment 7/A4's flag and matrix govern
    whether/how the diagnosis-stream fence opens; this amendment governs which of the other 54
    manifest assets get PUT at all once it does. This amendment makes **no change** to
    Amendment 7/A4's flag, matrix, or fence text, and makes no change to
    `W1-DIAGNOSISEVENT-CONTRACT.md`'s or `W2-SPACE-ROLE-CONTRACT.md`'s own numbered `§`
    sections — the DiagnosisEvent schema and the Kibana space/role/dashboard bodies are
    unaffected; only the installer's *application strategy* for already-built manifest assets
    changes. **§8 below is the one exception** — it proposes a narrowly-scoped amendment to
    ratified A4 §5.4 itself, flagged separately for explicit owner ratification.

---

## Gate round 1 disposition

Both reviewers issued this document REWORK on 2026-07-24d. Union of required edits below;
where they conflict, Sol's binding rulings win (evidence-grounded, later pass — see the
"Binding rulings" and "Exact ownership decisions" blocks Sol's review produced, both adopted
verbatim into §1/§2/§3 below).

| # | Source | Edit required | Disposition |
|---|---|---|---|
| 1 | Overseer #1 | Data-stream count wrong (18→16 streams) | Adopted — §0, §3.2 now say 16 streams/18 backing indices; dynamic enumeration |
| 2 | Overseer #2 | Row 9 pipeline PUT drops DIFF-REPORT's quiescence requirement | **Superseded by Sol finding 1**: the DIFF-REPORT quiescence requirement for the pipeline was itself an evidence artifact (server timestamps compared as payload, `phase05_inventory.py`'s pipeline branch never ran the installer's `projection()`, which rejects pipelines anyway). Corrected, the pipeline's operational body equals the bundle. Row 9's pipeline PUT is retained, un-gated on quiescence — see §1.2, `DIFF-REPORT.md` "Correction (gate round 1)". |
| 3 | Overseer #3 | Ownership-table arithmetic off by one (row 3 = 20 not 19; total 66 not 65) | Adopted — §1 table and total corrected |
| 4 | Overseer #4 | §3.2 repeats the data-stream error | Adopted — 16/18 |
| 5 | Overseer #5 | §-ref drift ("§3.3" should be "§3 item 4") | Adopted — §3 converted to numbered subsections §3.1–§3.4; §1.2/§1.3 now cite §3.4 correctly |
| 6 | Overseer #6 | §5 combined-CA claim needs code verification + proxy-CA private-key location | Adopted — §5.1 now marks the `install_assets.py:342,1637-1638` citation as re-verified-at-pinned-SHA (Sol's review re-derives the same mechanism independently, finding 7); key location stated |
| 7 | Sol #1 | §2.3 external-verify oracle self-contradictory (whole-body equality impossible for Fleet-composed templates) | Adopted — §2.3 rewritten around three class-specific `compatibility_projection()`s, never whole-bundle-body equality |
| 8 | Sol #5 | Marker granularity: 55 manifest assets not 65 expanded objects; manifest split is 16 owned / 39 external | Adopted — §2.5 (marker semantics) and §1 both now distinguish the illustrative expanded count (66, per-object) from the authoritative manifest-level split (16/39 of 55) |
| 9 | Sol #5 | `_meta.package` has no version field live | Adopted — §3.1 no longer claims/refuses on absent version; records `version: null` verbatim or queries Fleet API separately |
| 10 | Sol #6 | Stream counts / rollover semantics inconsistent, three-way rollover handling needed | Adopted — §3.2, §3.3, new rollover-cases text |
| 11 | Sol #7 | Transport security claims overstated: broadened trust not stated; Kibana `:5601` is `0.0.0.0`, not loopback; listener must allow `192.0.2.144` | Adopted — §5 rewritten: honest broadened-trust statement, corrected listener scope, NEW gate requirement to block remote plaintext `:5601`, flagged OPEN RATIFICATION ITEM with blast-radius note |
| 12 | Sol #4 | Proof deletion conflicts with ratified A4 §5.4 | Adopted — new §8, narrowly scoped, flagged for explicit owner ratification, does not assert already-ratified |
| — | (evidence) | Wire gate PASS 109/109; native-user credential confirmed | `BINARY-PROVENANCE.md` final section and `PREFLIGHT-REPORT.md` addendum. Sol's "Release/live STOP" is cleared; overseer blocker 5 is cleared. §6 below notes the credential is confirmed available, not merely required. |

### Round 2 (Sol confirmation pass)

Overseer's confirmation pass CONFIRMED both v2 docs unchanged. Sol's confirmation pass returned
**NOT CONFIRMED** on both, with six exact remaining edits (three land in this document; the
other three, plus one shared change, land in `ROLLBACK-DESIGN.md`). This is v3.

| # | Edit required | Disposition |
|---|---|---|
| R2-1 | Rename `installed_assets` → `applied_owned_assets` everywhere; define explicit `noop` action for owned assets whose live state already equals the bundle, so all 16 owned manifest assets always appear and 16+39=55 holds unconditionally | Adopted — §2.5 rewritten with `noop` action defined; §4's dirty-seeded-stack leg assertion updated |
| R2-2 | Dashboard/saved-object adapters bypassed the module contract | Lands in `ROLLBACK-DESIGN.md` §1.3 (new); this document is unaffected since it does not itself specify adapter internals |
| R2-3 | Journal after-pin / ambiguous-crash rule extension | Lands entirely in `ROLLBACK-DESIGN.md` §5 |
| R2-4 | Component-template adapter routing order | Lands entirely in `ROLLBACK-DESIGN.md` §1.2 |
| R2-5 | Transport: (a) label the accepted-risk `:5601` option a new deviation requiring its own fresh gate; (b) fix key-location statement — CA key on `192.0.2.144`, deployed leaf key/cert on `192.0.2.174` at a protected path, staging-shred + rollback removal | Adopted — §5 (item 1's key-location text, and the open-ratification-item paragraph) rewritten |
| R2-6 | `DIFF-REPORT.md` stale normalization bullet; correct "four server timestamps" prose | Lands in `DIFF-REPORT.md`; this document's §0 pipeline-correction prose corrected to match (projection still strips all four defensively, only the two `_millis` fields are observed on this cluster) |

---

## 0. Problem statement (recap of established evidence, not new claims)

The owner cluster's RigSignal assets were installed via Fleet, not via this installer. Live
inventory (`DIFF-REPORT.md`, `INVENTORY.tsv`) shows:

- **13 index templates** and **13 pipelines** are Fleet-managed: live `_meta` identifies them as
  `fleet`-owned, and each Fleet-managed index template's `composed_of` includes both
  `.fleet_globals-1` and `.fleet_agent_id_verification-1`, which the bundled templates do not
  reference.
- **13 component templates** back those same streams and differ from the bundled body only in
  `_meta.managed_by` (`fleet` live vs `rigsignal-asset-bundle` bundled) — cosmetic, not a
  mapping/settings change.
- **`metrics-rigsignal.profiles`** index template differs by `_meta.managed_by` only (cosmetic).
- **`logs-rigsignal.stream`** index template is standalone (empty `composed_of` on both sides,
  not Fleet-composed) but its declared lifecycle differs semantically:
  `logs-rigsignal-stream-30d` (live) vs the bundle's inherited default `logs@lifecycle`. Its
  pipeline, `logs-rigsignal.stream@pipeline`, is likewise not Fleet-managed by live `_meta`.
  **Corrected (gate round 1):** the pipeline's apparent diff was a comparison-methodology
  artifact — server-injected `created_date_millis`/`modified_date_millis` (the pair actually
  present in this cluster's pipeline captures; the projection strips the human-readable
  `created_date`/`modified_date` variants too, defensively, though neither appears here) were
  compared as payload by the phase-0.5 classifier, which never
  applied the installer's `projection()` to pipelines (it rejects the class,
  `install_assets.py:855`). After the corrected compatibility projection (§2.3), the pipeline's
  operational body (`processors`, `on_failure`, `description`) equals the bundle exactly — this
  is a metadata-only diff, not a semantic write-path change. See `DIFF-REPORT.md` "Correction
  (gate round 1)".
- `rigsignal_shipper` role, the `rigsignal` Kibana space, `rigsignal_viewer` role, all 15
  product-space saved objects, and all 3 default-space streaming-lab objects are **absent** live
  — no ownership conflict; ordinary bundle-owned install territory.
- `rigsignal-game-timeline` transform is `started` with a `pivot` exactly equal to the bundled
  config (only runtime `_meta` differs) — the installer's pivot-dropping update hazard was
  checked and did not trigger; transform behavior is approved for ordinary PUT/update.
- The pinned installer's Step 5 barrier (`install_assets.py:1716-1727`) PUTs every
  `bundle.assets` entry unconditionally, with no ownership branch. Applied as-is against this
  cluster it would (a) strip both Fleet composition components from 13 index templates and
  overwrite 13 Fleet pipeline bodies, risking a subsequent Fleet reinstall/upgrade reasserting
  its own bodies over the bundle's — an ownership-oscillation failure mode, not a one-time
  conflict — and (b) claim in the completion marker that it "installed" assets it should not
  have touched, or that it did not touch assets that in fact needed no installation.

This amendment's premise, confirmed live: **both** `logs-rigsignal-stream-30d` and
`logs@lifecycle` currently have **no delete phase** (`KEY-LIFECYCLE.md` ILM check,
`CLUSTER-HEALTH.md`). The lifecycle-identity change carries no immediate retention risk today,
and — corrected, gate round 1 — a composable index template PUT does not retroactively alter
the current backing index, so it also carries no immediate writer-quiescence exposure
(`DIFF-REPORT.md`, corrected writer-exposure table). It remains a policy-**identity** change,
not merely a cosmetic one, and still requires explicit ratification below (§1.2).

The owner cluster has **16 distinct RigSignal data streams / 18 backing indices** (3 `logs-*` +
13 `metrics-*`; `audio` and `ebpf` each have 2 backing indices) — ground truth:
`raw/data-streams.json`. All counts and loops below enumerate this set dynamically
(`GET /_data_stream/*rigsignal*`), never a hardcoded literal.

## 1. Ownership table (normative)

The installer MUST resolve every manifest asset's ownership from a fixed table keyed by asset
identity (`kind`, `name`), not from a live heuristic recomputed per invocation. A heuristic
("looks Fleet-managed, so skip it") is explicitly rejected: it would make installer behavior
depend on transient live `_meta` content instead of a ratified decision, and a differently
labeled but still-foreign asset could silently fall through either side.

| # | Asset class | Count | Live evidence | Disposition |
|---|---|---:|---|---|
| 1 | W1 diagnosis component template + index template chain | 2 | both `equal` live (`DIFF-REPORT.md`) | **bundle-owned** — PUT, standard v2.2 fence applies unchanged |
| 2 | `rigsignal_shipper` role | 1 | absent (404) | **bundle-owned** — PUT, standard install |
| 3 | Kibana `rigsignal` space, `rigsignal_viewer` role, all 15 product-space + 3 default-space saved objects | 20 | all absent (404) | **bundle-owned** — PUT, standard install (W2 territory, unaffected by Fleet) |
| 4 | Enrollment transaction (local `state.json`, `credentials.toml`, `handshake.toml`, `shipping-policy-v1.toml`, scoped API key) | — | N/A, local | **bundle-owned** — unchanged by this amendment |
| 5 | `rigsignal-game-timeline` transform | 1 | `different` (runtime `_meta` only); `pivot` exactly equal, `state=started` | **bundle-owned** — PUT/update approved explicitly; pivot-drop hazard checked, did not trigger; `_meta`-absent-restore proof required before rollback relies on it (`ROLLBACK-DESIGN.md` §1.2) |
| 6 | 13 Fleet-managed index templates | 13 | `different`; both Fleet components in `composed_of` live | **Fleet-owned/external** — compatibility-projection VERIFY only, **no PUT** |
| 7 | 13 Fleet-managed pipelines | 13 | ownership-metadata diff only, post-correction (operational body equal — see §0) | **Fleet-owned/external** — compatibility-projection VERIFY only, **no PUT**; ownership-scoped, not body-diff-scoped |
| 8 | 13 component templates backing row 6 | 13 | `different`, cosmetic `_meta.managed_by` only | **Fleet-owned/external** — VERIFY only, **no PUT** (see §1.1) |
| 9 | `logs-rigsignal.stream` index template + `logs-rigsignal.stream@pipeline` | 2 | template: `different`, lifecycle-name diff, not Fleet-composed; pipeline: metadata-only diff post-correction, not Fleet-composed | **separately-decided** — see §1.2 |
| 10 | `metrics-rigsignal.profiles` index template | 1 | `different`, cosmetic `_meta.managed_by` only | **separately-decided** — see §1.3 |

**Corrected arithmetic (Overseer #3):** row 3 = space(1) + viewer role(1) + 18 saved objects (15
product + 3 default) = **20**, not 19. Expanded per-object total:
2 + 1 + 20 + 1(transform) + 13 + 13 + 13 + 2 + 1 = **66** line items, not 65.

**This expanded count is illustrative accounting only.** Per Sol's binding ruling (gate round 1,
finding 5), the marker's authoritative lists operate at **manifest-asset** granularity, not this
per-object expansion: 55 total manifest assets (row 3's 20 live objects collapse to 9 manifest
assets — the space, the viewer role, and 7 dashboard-bundle `.ndjson` files, each bundling
multiple saved objects), split **16 bundle-owned / 39 external**, disjoint, union = 55:

- **16 bundle-owned:** diagnosis chain (2: component + index template, row 1) + `rigsignal_shipper`
  role (1, row 2) + Kibana space + viewer role + 7 dashboard bundles (9, row 3) + transform (1,
  row 5) + `logs-rigsignal.stream` template + pipeline (2, row 9) + `metrics-rigsignal.profiles`
  (1, row 10) = 16.
- **39 external:** 13 Fleet index templates + 13 Fleet pipelines + 13 Fleet component templates
  (rows 6–8) = 39.

Every manifest asset MUST resolve to exactly one row; an asset matching no row is a build defect
and MUST refuse before any mutation, not fall through to a default.

**Ratification (owner-ratified 2026-07-28, dashboard-origin v8 §5):** row 3's disposition —
Kibana `rigsignal` space, `rigsignal_viewer` role, and all 18 product/default-space saved objects
as **bundle-owned**, "W2 territory, unaffected by Fleet" — stands **verbatim, unchanged**; v8 §5
names it as "kept verbatim from v3 (no round-3 findings against these)". The dashboard-origin fix
adds a fail-closed read-only preflight (v8 §2 W-B, `run_topology_preflight`) and a Kibana
`_import`-response regeneration check in front of exactly these 20 objects' apply path; it does not
reclassify any of them as external, and it does not change this row's ownership disposition. The
`rigsignal` space named here is the same object `ERRATA-v8.md` E6 concerns (a rollback-fidelity gap
for a partial pre-existing space) and the same object the A4-LIVE-RUNBOOK's new P0 fence asserts
absent (`GET /api/spaces/space/rigsignal` -> 404) before every apply.

### 1.1 Component templates behind Fleet-managed streams (row 8)

Even though these 13 component templates' mapping/settings bodies are byte-identical to the
bundle's, this amendment proposes **verify-only, no PUT** rather than "PUT since it's a no-op."
Reason: PUTting them would flip `_meta.managed_by` from `fleet` to
`rigsignal-asset-bundle` even though the index templates that reference them remain
Fleet-owned — an ownership-metadata split that misrepresents which system currently owns the
composition chain. **Confirmed correct in gate round 1** (Sol, "Exact ownership decisions":
"Changing only `managed_by` would falsely split ownership across the Fleet composition chain").
No longer merely proposed — this is the settled disposition, subject only to final owner
ratification alongside the rest of this document.

### 1.2 `logs-rigsignal.stream` + its pipeline (row 9) — corrected disposition

**Bundle-owned, PUT allowed, for both assets, unconditionally on quiescence** (corrected, gate
round 1). Neither asset is Fleet-composed (empty `composed_of`, non-Fleet `_meta`), so there is
no third-party ownership conflict for either.

- **Pipeline:** the pre-correction "semantic active-write-path diff" was an evidence artifact
  (§0). Post-correction, the operational body equals the bundle — the pipeline PUT is
  metadata-only and therefore does not require writer quiescence. This resolves the round-1
  conflict between the rollback design (which had blocked it pending an undesigned quiescence
  procedure) and this amendment (which had un-blocked it without justifying why): both documents
  now agree it is unblocked, for the evidence reason above, not by fiat.
- **Template:** the lifecycle-identity change (`logs-rigsignal-stream-30d` → `logs@lifecycle`,
  both currently delete-phase-free) is a same-day-verified-safe policy-identity change. This is
  consistent with the Amendment 7/A4 clarification that the shipped W1 template's absence of an
  explicit `index.lifecycle.name` field means the inherited default (`logs@lifecycle`) is the
  canonical resolved policy, not a deviation. Its PUT effect is next-rollover-deferred (§0), so
  it likewise needs no quiescence — but it **does** require the ratification and live gate below.

This proposal is **conditional on ratification** and on the gate in **§3.4** (same-day
delete-phase-free re-read of **both** policies, immediately pre-PUT, in the live invocation
itself — not reused from this session's evidence).

### 1.3 `metrics-rigsignal.profiles` (row 10) — proposed decision

**Proposed: bundle-owned, PUT allowed**, since its diff is `_meta.managed_by` only and it is not
listed among the 13 templates carrying Fleet composition components. **Confirmed live in gate
round 1** (Sol, "Exact ownership decisions"): its live `composed_of` is explicitly empty
(`raw/be84e15cfb8c.json:9`), resolving what this draft previously flagged as an open
confirmation gap. The live gate (§4) still MUST re-confirm this immediately pre-write as a
standing precondition, not a one-time check — retain the immediate pre-write recheck.

## 2. New installer mode: `--ownership-profile fleet-coexist`

### 2.1 Flag scope

The flag selects a named, versioned ownership table (§1) compiled into the installer, not a
   runtime-inferred one. Omitting the flag preserves exactly today's behavior: every manifest
   asset is bundle-owned and PUT unconditionally, per the existing v2.2 barrier. The flag is
   **not** one-shot like `--adopt-existing-w1-stream` — ownership is a property of the target
   cluster's asset layout, not a single-invocation transition, so it MUST be supplied on every
   invocation against a Fleet-coexisting cluster, including reruns, and its absence on a rerun
   against such a cluster MUST refuse rather than silently reverting to PUT-everything.

### 2.2 Per-asset ownership resolution

For each manifest asset, the installer looks up its
   `(kind, name)` in the compiled table. `bundle-owned` assets follow the existing Step 5 PUT
   path unchanged. `external` assets follow the verify-only path (§2.3). Any asset absent from
   the table under `--ownership-profile fleet-coexist` MUST refuse the entire invocation before
   any mutation, with a distinct stable error naming the unresolved asset — this is what
   prevents the "silently falls through to PUT" failure mode when the bundle gains a new asset
   that the ownership table has not yet been updated to classify.

### 2.3 Verify-only path — rewritten (Sol #1, REWORK)

The original draft required, as a
   conjunction, "canonical-projection JCS equality against the bundled body" for templates and
   exact-body equality for pipelines. That is **self-contradictory**: the 13 Fleet templates are
   classified `external` precisely because their `composed_of` differs from the bundle by
   design (two Fleet components), so whole-bundle-body equality is *always false* for them —
   making the verify-only path either always-refuse or undefined. Corrected: for each `external`
   asset, the installer runs the class-specific **compatibility projection** (never whole-body
   equality against the bundle):
   - **Component templates:** strip server timestamps
     (`created_date`/`created_date_millis`/`modified_date`/`modified_date_millis`) and the
     ratified `_meta.managed_by` difference; require everything else equal.
   - **Fleet index templates:** additionally permit exactly the two Fleet `composed_of` members
     (`.fleet_globals-1`, `.fleet_agent_id_verification-1`) and corresponding managed-by fields;
     require every other field equal, **then** check effective owned
     mappings/settings/default-pipeline/lifecycle via `_simulate_index` outcome-equivalence
     (§3.2) — this is the step that proves the live, Fleet-composed template still produces
     RigSignal-compatible resolution outcomes, even though raw bodies differ by design.
   - **Pipelines:** extract `response[name]` (GET returns `{name: body}`, not the bare body);
     strip the four server timestamps above; permit only the ratified ownership-metadata
     difference; require `processors`, `on_failure`, and all other operational content equal.
     This is the exact projection whose absence produced the gate-round-1 evidence artifact
     (§0) — it is now load-bearing for the verify-only oracle, not just the inventory report.

   A verify-only asset that fails its class's compatibility projection MUST refuse the entire
   invocation before any mutation; it MUST NOT be silently skipped, logged as a warning, and
   left to proceed.

### 2.4 No-write guarantee

The installer performs **no PUT, no DELETE, and no dry-run PUT** against any `external`
   asset. It also MUST NOT attempt a partial or "safe subset" write (e.g., patching only
   `_meta`) — external means zero mutation, full stop.

### 2.5 Honest marker semantics, corrected granularity (Sol #5, renamed round 2)

`rigsignal-bundle-meta` MUST
   record `ownership_profile` (the exact profile name or `"default"`) and `ownership_table_version`,
   and two **disjoint, manifest-level** asset lists whose union is all 55 manifest assets — never
   the 66-item expanded per-object accounting in §1:
   - **`applied_owned_assets`** (renamed from `installed_assets`, gate round 2 — the prior name
     implied every entry was newly written, which is false for a no-op): `{kind, name, action,
     request_body_sha256}` for every **bundle-owned** manifest asset (all 16, §1), where `action`
     is one of `create` (PUT/POST on a 404-absent asset), `update` (PUT/POST-update on a
     differing asset), `import` (dashboard bundle), or **`noop`** (the asset's class adapter
     found live state already canonically equal to the bundle body — e.g. the diagnosis
     component/index template pair, or `logs-rigsignal.stream@pipeline` post gate-round-1
     reclassification). A `noop` entry still records `request_body_sha256` as the sha256 of the
     bundle body that *would* have been sent — the adapter ran its equality check, it just
     produced no HTTP mutation. **This makes `applied_owned_assets` unconditionally contain all
     16 bundle-owned manifest assets on every successful invocation, regardless of how many of
     them needed an actual write** — the 16+39=55 disjoint-union invariant below therefore holds
     unconditionally, not only on a "first ever install" run where everything happens to be
     absent.
   - `verified_external_assets`: `{kind, name, live_body_sha256, compatibility_projection_sha256,
     owner_metadata}` for every asset verified compatible but never mutated.

   The two sets MUST be disjoint and their union MUST equal all 55 manifest assets. The marker
   MUST NOT report a single aggregate "N assets installed" count that includes
   `verified_external_assets`, and existing consumers of that count (dashboards,
   `rigsignal status`, or any future audit tooling) MUST be updated to read the two lists
   separately rather than summing them. `ownership_profile` and `ownership_table_version` MUST
   also be persisted in protected transaction/enrollment state, not only the marker, and MUST be
   mismatch-fenced: a marker-write failure cannot permit a later default-profile rerun to
   silently diverge from the persisted state, and a supplied profile that differs from persisted
   state MUST refuse. A marker produced under `--ownership-profile fleet-coexist` that fails any
   of the above is a contract violation of this clause, independent of whether the underlying
   installation succeeded.

   **Owner ratification (2026-07-27, v3 gate rulings):**
   - *Fence direction (ruling 5):* the mismatch fence of this clause is directional for the
     profile field — remote `fleet-coexist` marker vs non-coexist invocation refuses; remote
     `default`/absent vs requested `fleet-coexist` is the amendment's own migration direction
     and is accepted, relying on the Fleet-composition check to fail closed when the remote is
     not Fleet-composed. The `ownership_table_version` field is mismatch-fenced without
     direction. Any prior reading of this clause as fully bidirectional for the profile field
     is superseded.
   - *Mappings-level `_meta` (v3 F5-v3/S2-v3):* the ownership-metadata compatibility exception
     of §1.1 covers `template.mappings._meta` in addition to top-level `_meta` — Fleet stamps
     both locations (ground-truthed 13/13 against live owner-cluster captures); the projection
     records the dropped object verbatim as `owner_metadata`.
   - *Accepted deviation (v3 ruling on F16-v2):* the pre-publication fence re-verifies all
     external asset bodies and re-fences W1 stream identity, but does not re-capture the full
     `fleet_stream_snapshot` across all RigSignal streams; accepted because the installer never
     mutates external streams inside the transaction window and W1 identity is independently
     re-fenced. Recorded as a deviation from the §5 "any rollover in-window is a STOP" wording,
     not silently closed.

   **Owner ratification (2026-07-28, dashboard-origin v8 §5):** this clause's marker semantics —
   the 16/39 disjoint-union invariant, the `create`/`update`/`import`/`noop` action vocabulary, and
   the mismatch-fenced `ownership_profile`/`ownership_table_version` persistence — stand
   **verbatim, unchanged**; v8 §5 names §2.5 as "kept verbatim from v3 (no round-3 findings against
   these)". The dashboard-origin fix's fail-closed topology preflight (v8 §2 W-B) and its regen-check
   inside `install_asset`'s dashboard branch run **before** an `import`/`noop` action is ever
   recorded for a dashboard-bundle manifest asset; a preflight refusal means no `write_intent` was
   persisted and no entry is added to `applied_owned_assets` at all (this section's marker is never
   reached), so the action vocabulary and the disjoint-union invariant above are unaffected. The new
   `RIGSIGNAL_DASHBOARD_IMPORT_RESULT` evidence line (v8 §6) is a P5 forensic artifact over the
   installer's stdout, not a marker field, and does not extend or alter this clause's schema.

## 3. Verification/assertion additions

### 3.1 Fleet integration version + live asset hashes

For every `external` asset, the installer MUST capture and persist (in the marker, alongside
`verified_external_assets`) the live canonical JCS SHA-256 of the compatibility-projected asset
body actually verified. **Corrected (Sol #5):** the live `_meta.package` block carries a package
`name` but, as observed on this cluster, **no `version` field** (`raw/data-streams.json` and the
Fleet-managed template/pipeline captures all show `_meta.package: {name: "rigsignal"}` with no
version key). This amendment MUST NOT claim templates/pipelines always expose a version, and
MUST NOT refuse an invocation solely because `_meta.package.version` is absent. Either query the
Kibana Fleet integration-package API separately for the installed version, or — if that call is
out of scope for a given invocation — record the live `_meta` verbatim with `version: null`
rather than guessing or refusing.

### 3.2 Pre/post `_simulate_index` equivalence for every active RigSignal stream

Not only the diagnosis stream (the existing fence's current scope). For each of the manifest's
**16 data streams / 18 backing indices** (`DIFF-REPORT.md` "All RigSignal backing indices",
`raw/data-streams.json` ground truth — dynamically enumerated via `GET /_data_stream/*rigsignal*`,
never a hardcoded count), before and immediately after the Step 5 barrier, the installer MUST
capture: effective mappings, effective settings, resolved default pipeline, resolved lifecycle
name, and — for Fleet-managed streams specifically — evidence that Fleet's verification
components (`.fleet_globals-1`, `.fleet_agent_id_verification-1`) remain present in the resolved
composition post-barrier. Any drift between pre- and post-barrier snapshots for an `external`
asset's stream is a contract violation (proof that "verify-only" was not actually
mutation-free) and MUST fail the invocation, even if it occurs after Step 9 publication would
otherwise have succeeded — this generalizes the existing TOCTOU fence
(Amendment 7/A4 §5.6) from the diagnosis stream to every active stream under this profile.

### 3.3 Backing `(name, UUID)` and M1 doc-hash invariance

Generalized: for every backing index captured under §3.2, the pre/post `(index_name, index_uuid)`
pair MUST be identical — no recreate, no rollover triggered by this installer's own action. For
the diagnosis stream specifically, both M1-migrated documents
(`13610797-13f7-5c07-b028-4bd88c0b3edd`, `76e28921-5229-50bc-96e6-79c5abbb1c7d`) MUST retain
their captured JCS source hashes (`INVENTORY.tsv` rows `diagnosis-doc:*`) unchanged pre/post,
exactly as Amendment 7/A4 §6.2 already requires for the adoption leg — this amendment requires
the same check to run even when adoption is not in play, because a Fleet-coexist invocation can
mutate assets alongside an already-adopted stream in the same run.

**Rollover semantics, three cases (Sol #6 — a stream cannot both guarantee an unchanged backing
UUID set and accept a forced in-transaction rollover; production code cannot reliably judge
"legitimate" vs. installer-caused mid-transaction):**

- **In-transaction rollover** (fires between the pre- and post-barrier snapshots of §3.2): fail
  closed before publication and exercise the journaled rollback/recovery path
  (`ROLLBACK-DESIGN.md` §5) — never attempt to classify it as "legitimate" mid-transaction.
- **Between-invocation rollover** (occurs after one successful invocation, before the next): a
  separate, successful rerun leg — rebaseline the new backing set and preserve the prior
  invocation's anchors; not a defect.
- **External Fleet upgrades:** may change external asset hashes at any time between invocations.
  Rollback and re-verification check **current** compatibility against live Fleet state; they
  never require restoring an obsolete external preimage.

### 3.4 Same-day `read_ilm` re-read, no-delete-phase precondition

Before any PUT that changes a lifecycle policy identity (currently: only §1.2's
`logs-rigsignal.stream` template), the installer MUST re-read both the outgoing policy
(`logs-rigsignal-stream-30d`) and the incoming policy (`logs@lifecycle`) in the same invocation
and confirm neither currently declares a `delete` phase, exactly reproducing this session's
manual check (`KEY-LIFECYCLE.md` "ILM owner keep-forever check"). A policy that has gained a
delete phase since this evidence was captured MUST refuse the identity-changing PUT — this
session's result is evidence for the ratification decision, not a standing exemption from the
live check.

**(Ref-drift fix, Overseer #5): §1.2 and §1.3 above now cite this subsection as `§3.4`, not the
prior "§3.3" — §3 did not previously have numbered subsections, which caused the drift Sol's
pass would otherwise have re-flagged.**

## 4. Gate requirements

1. The existing 19/19 standalone clean-stack matrix from Amendment 7/A4 (§6, legs 1–10, both
   version pairs) is **unchanged** and MUST continue to pass with `--ownership-profile` omitted
   or set to `default` — this amendment adds no regression to the non-coexistence path.
2. **New Fleet-coexistence legs**, both on (ES 9.4.3, Kibana 9.4.3) and (ES 9.4.4, Kibana 9.4.4):
   - **Dirty-seeded-stack leg:** seed an ephemeral stack with the 13 Fleet-managed index
     templates/pipelines/component templates (real Fleet-shaped bodies, including both
     verification components in `composed_of`) before running the installer with
     `--ownership-profile fleet-coexist`; assert `applied_owned_assets` contains **all 16**
     bundle-owned rows from §1 (each with `action` correctly `create`/`update`/`import`/`noop`
     per §2.5) and `verified_external_assets` contains exactly the 39 external rows (13+13+13),
     each with a captured compatibility-projection hash matching the seeded body.
   - **Fleet reinstall/upgrade rehearsal:** after a successful coexist install, simulate a Fleet
     integration reinstall/upgrade that rewrites the 13 templates/pipelines/component templates
     (bumping their `_meta` package version, where present — see §3.1 on absent-version
     handling); re-run the installer under the same profile and assert zero owned mutation to
     bundle-owned assets (§1 rows 1–5, 9, 10) and that the externally-verified hash capture
     reflects the new Fleet-side version — proving the ownership-oscillation risk in §0 does not
     manifest either direction.
   - **Rollover/write rehearsal:** force a rollover on at least one Fleet-managed stream and one
     bundle-owned stream between the pre- and post-barrier snapshots of §3.2; assert the
     in-transaction-rollover case (§3.3) fails closed and recovers via the journaled rollback
     path, rather than being misclassified as installer-caused drift or silently accepted.
   - **Owner ratification (2026-07-25):** the inline per-cluster pre-apply transform rehearsal
     is accepted as implemented: it briefly mutates the live transform to prove restorability,
     then records verify-only and journals the result on a failed proof. This ratifies the
     inline placement over the earlier rehearsal-environment wording; no redesign is authorized.
3. **Base commit and hash:** all new legs run against pinned SHA
   `0d427d37c277ae7fdc8df35503cbedab8a25692f` (bundle SHA-256
   `aa57aade36993ea143717c62366942ea736c1bf4235f0952c3cd86c49ece323a`, `BINARY-PROVENANCE.md`)
   plus whatever new commit implements this amendment. A **new** code SHA and a **new** bundle
   hash are required once §1–§3 are implemented; the pinned values above are the base, not the
   final gate artifact. **The standalone handshake wire gate is now green** (`BINARY-PROVENANCE.md`
   final section: PASS 109/109 against the pinned installed binary) — this clears Sol's round-1
   "Release/live STOP" on the wire gate as a precondition for scheduling these new legs.

## 5. Transport addendum — owner-cluster loopback TLS proxy (CONDITIONAL, not yet cleared)

**Rewritten, gate round 1 (Sol #7): the original text understated the trust consequence of the
combined-CA design and mis-scoped the listener/Kibana-binding requirements.**

1. **The deviation.** The owner Kibana endpoint is reached in plaintext HTTP at
   `192.0.2.174:5601` (`PREFLIGHT-REPORT.md` P0.2), which the pinned installer's
   `https_origin()` check rejects outright. Kibana currently listens on `0.0.0.0:5601` — **not**
   loopback (`tls-proxy/PROXY-REPORT.md:43`) — so it is reachable directly from the network
   today, proxy or no proxy. The proposed remediation is a TLS-terminating loopback proxy on
   `192.0.2.174:5643` in front of that HTTP listener, so the installer sees an HTTPS origin.
   Because the existing Elasticsearch CA's private key is root-locked (`/etc/elasticsearch` is
   `root:elasticsearch`, inaccessible without `sudo`, confirmed non-interactive-`sudo`-denied —
   `tls-proxy/PROXY-REPORT.md`), the proxy's server certificate cannot be signed by the real ES
   CA. The proposed resolution instead mints a **dedicated, NUC-held proxy CA**
   (`CN=RigSignal Owner Kibana Proxy CA 2026-07-24d`, self-signed, ECDSA P-256, `CA:TRUE`,
   minted `2026-07-24T16:05:36Z`) to sign the loopback listener's certificate. **Key-location
   statement, corrected (Sol round 2 — the v2 text wrongly placed both keys on the NUC; the
   listener runs on the owner host, so its key must too):**
   - The **proxy CA's own private key** stays on the NUC (`192.0.2.144`), mode `0600`, never committed
     to any repository — it is the signing authority and never needs to leave the host that
     mints certificates with it.
   - The **issued leaf key/cert pair actually used by the `:5643` listener** is *deployed to the
     owner host* (`192.0.2.174`) — a proxy that terminates TLS locally must hold its serving key
     locally; a leaf key that never left the NUC could not be used by a listener running on
     `192.0.2.174`. Protected location: `/etc/nginx/rigsignal-tls/` (owner-host-local, matching the
     proxy's expected reverse-proxy implementation), owned `root:root`, directory mode `0750`,
     leaf **key** file mode `0600`, leaf **cert** file mode `0644` (public by nature). Any
     staging copy used to transfer the leaf key/cert to `192.0.2.174` (e.g. a `/tmp` file used during
     `scp`/deployment) MUST be shredded (`shred -u`, not `rm`) immediately after the protected
     copy is confirmed in place and its mode verified — mirroring this session's own
     credential-hygiene lesson (`KEY-LIFECYCLE.md`'s 0664-not-shredded STOP). Rollback of this
     capsule removes the deployed leaf key/cert from `/etc/nginx/rigsignal-tls/` on `192.0.2.174`; the
     proxy CA's private key on `192.0.2.144` is never touched by a rollback of a single deployment (it
     is the durable signing authority, re-usable for a future re-deployment). See
     `ROLLBACK-DESIGN.md`'s TLS-proxy teardown capsule, extended to name these owner-host
     artifacts explicitly.
2. **Mechanism (re-verified at pinned SHA, Overseer #6 / independently derived by Sol #7):**
   `configure_https()` (`install_assets.py:342`) installs a single process-global `ssl.SSLContext`
   opener; the installer calls it twice (`install_assets.py:1637-1638`, once per endpoint). The
   **second** call's opener **replaces** the first — so supplying the same combined bundle
   (`tls-proxy/installer-ca-bundle.pem`, real ES CA + dedicated proxy CA) for both `--ca-file` and
   `--kibana-ca-file` works, but the mechanism is "the final opener trusts both roots
   simultaneously," not "each call gets its own independently-scoped opener."
3. **Honest trust consequence — corrected, this is the load-bearing fix of gate round 1:** the
   proxy CA becomes trusted for Elasticsearch too, for the duration of the invocation. Because
   ES and the proxy share IP `192.0.2.174`, **compromise of the proxy CA's private key could
   be used to issue a certificate the installer would accept for the Elasticsearch endpoint** —
   the prior draft's claim that the proxy CA "cannot be used to impersonate the ES cluster
   itself" is **withdrawn**; that claim only held under the false premise of per-call opener
   isolation. The combined-bundle design is still **conditionally accepted** (Sol's binding
   ruling), on the basis that: (a) the process-global opener trusts exactly one combined bundle
   for the duration of the invocation, not an unbounded or dynamically-updated root set; (b) the
   plaintext leg is confined to `127.0.0.1`/the owner host itself — no plaintext credential or
   payload crosses the network boundary; (c) the dedicated proxy CA signs only the loopback
   listener certificate today. But the broadened trust is real and MUST be recorded as such, not
   minimized.
4. **Listener scope, corrected:** the `:5643` listener MUST accept connections from `192.0.2.144` (the
   real installer host, running the Phase 4 invocation) plus explicitly authorized local health
   checks — a "loopback/owner-host connections only" restriction, as the original draft implied,
   would reject the actual installer and make the proxy useless. Restricting to `192.0.2.144` plus
   loopback (not open to the whole `192.0.2.0/24`) is the correct source-address scope.
5. **NEW gate requirement — remote plaintext `:5601` must be blocked.** Merely standing up the
   `:5643` proxy does not close the existing `0.0.0.0:5601` plaintext listener; anything on the
   network can still bypass the proxy and hit Kibana directly. Before this transport path may be
   used for any live provisioning invocation, `:5601` MUST be bound to loopback or firewalled
   against all non-loopback sources, with **proof that a direct remote connection to `192.0.2.174:5601`
   fails** (not merely that the proxy path succeeds).

   **This is an OPEN RATIFICATION ITEM, not yet resolved in this draft**, because of its
   blast radius: `next-session-prompt` / memory evidence records existing NUC consumers reaching
   Kibana over plain `http://…:5601` today. Blocking remote `:5601` access would break them
   unless they are migrated to the new `:5643` HTTPS endpoint first, or the owner explicitly
   accepts the risk of leaving `:5601` open as a scoped, ratified exception (e.g., restricted to
   a trusted subnet) instead of a full block. The owner must choose one of:
   - **(a) migrate** existing `:5601` consumers to `:5643` https before this gate closes — this
     is the only option this amendment's own gate (§5.6) can clear as-is; or
   - **(b) an explicit accepted-risk exception** for `:5601` with its own scope. **Labeled
     explicitly (Sol round 2): option (b) is a *new deviation* from this amendment's own
     transport design, not a variant already covered by it — it changes the threat model this
     document analyzed (§5.3's "no plaintext credential or payload crosses the network
     boundary" claim assumed the plaintext leg was loopback-confined; a scoped-subnet exception
     reintroduces a plaintext network path this document did not evidence or assert as safe).
     Choosing (b) THEREFORE CANNOT clear the live-transport STOP under this amendment as
     written — it requires its own fresh overseer+Sol double gate, evaluating whatever specific
     subnet/scope the owner proposes, before any live invocation may rely on it.** Option (b) is
     kept visible here only so the owner has a documented off-ramp if (a) is impractical; it is
     not pre-approved.
6. **Required assertion battery**, to be run and evidenced in a report that supersedes
   `tls-proxy/PROXY-REPORT.md` before this transport path may be used for any live provisioning
   invocation:
   - positive (installer completes a real request through the proxy)
   - installer-order replay (`configure_https(ES_CA)` then `configure_https(Kibana_CA)`, matching
     `install_assets.py` `main()` order, exactly as `ca-probe.py` already rehearses)
   - wrong-CA (a certificate NOT signed by the proxy CA is rejected)
   - plaintext-HTTP (a request that bypasses the proxy and hits `:5601` directly is refused,
     not silently accepted — this now requires the §5.5 block to be in place, not merely that the
     installer's own `https_origin()` check would reject it if pointed there)
   - source-address (the proxy accepts `192.0.2.144` and authorized local health checks; rejects other
     sources)
   - consumer-smoke (a real Kibana API call round-trips correctly through the proxy)
   - persistence (the proxy survives a reboot/restart in whatever form it is deployed — systemd
     unit or otherwise)
   - certificate (SAN `IP:192.0.2.174`, `CA:false` on the leaf, `serverAuth` key usage,
     expiry, unrelated-CA rejection, matching the minted proxy CA's issued leaf)
7. **Current status — OPEN, not cleared.** `tls-proxy/PROXY-REPORT.md` and
   `tls-proxy/ROLLBACK.md` (captured 16:03–16:04 UTC) record a STOP: no listener, certificate,
   proxy package, systemd unit, or firewall rule was created on `192.0.2.174`, because at that time the
   ES CA private key was believed required. The dedicated proxy CA bundle
   (`tls-proxy/installer-ca-bundle.pem`, minted 16:05:36 UTC) exists as a prepared artifact and
   is consistent with the resolution path above, but **no report in this evidence directory
   documents that a listener was actually deployed on `:5643`, that any item in §5.6's assertion
   battery has run, or that §5.5's `:5601` block is in place.** This clause is therefore
   **conditional**: it documents the proposed, ratifiable design and the artifact evidence
   supporting its feasibility, but does **not** assert the transport path is live-verified. See
   Open Questions §4.

## 6. Credential-source restriction — native-user admin credential required

1. `admin_authorization()` (`install_assets.py:321-329`) accepts two credential grammars from
   `--admin-credentials-file`: `{api_key: str}` or `{username, password}`. `mint_key()`
   (`install_assets.py:1362-1367`) then performs `POST /_security/api_key` with an explicit
   `role_descriptors` body to mint the scoped `rigsignal_shipper` production key. Elasticsearch
   restricts privileged API-key-descriptor derivation when the calling credential is itself an
   API key; a native user (username/password) authentication context does not carry that
   restriction. This amendment REQUIRES that `--admin-credentials-file` resolve via the
   `{username, password}` branch for any invocation that reaches the mint step — i.e., any
   non-dry-run, non-refusal invocation. The `{api_key: str}` branch remains defined in the file
   grammar for other (read-only/dry-run) uses but MUST be refused before Step 5 if the
   invocation is not a dry run.
2. This restriction is independent of `--ownership-profile`: it applies to the credential
   contract generally, because it is an Elasticsearch protocol invariant, not a Fleet-ownership
   concern. It is included in this amendment because it was surfaced during this session's live
   evidence gathering and has not yet been folded into `rigsignal-p1-provisioning-order.md`'s own
   credential-grammar text (§"v2.3 Installation interface and §15.3 capsule", line 269-271).
3. **Confirmed available (cleared overseer blocker 5).** `PREFLIGHT-REPORT.md` addendum:
   `GET /_security/_authenticate` with the `~/.elastic/kibana-local.env` credential returns
   `username: elastic`, `roles: [superuser]`, `authentication_realm.type: reserved`,
   `authentication_type: realm` — a native user, not an API key. This requirement is therefore
   satisfiable with existing material; Phase 4 does not dead-end at the mint step for lack of a
   qualifying credential.

## 7. Cluster-health explanation gate

1. Before Step 5's barrier, the installer (or its preflight wrapper) MUST assert cluster health
   is either `green`, or `yellow` **with an explanation**: zero `unassigned_primary_shards`,
   every unassigned shard copy is a replica (not a primary), and zero pending cluster tasks. This
   reproduces the session's live verdict (`CLUSTER-HEALTH.md`: status `yellow`,
   `unassigned_primary_shards: 0`, 140 unassigned shards all `single-node-replica: true`,
   pending tasks `0`) as a standing precondition, not a one-time manual judgment call. `status:
   red`, or `yellow` with any unassigned primary or any pending task, MUST refuse before
   mutation with a distinct stable error.
2. This check runs once per invocation, before Step 5, using the same admin credential — it adds
   one `GET _cluster/health` (and, if the aggregate counts are ambiguous, per-shard
   `_cluster/allocation/explain` calls) to the existing preflight sequence.

## 8. Proposed A4 amendment — scoped transaction-proof deletion (NEW, gate round 1, Sol #4)

**This section proposes an amendment to ratified `A4 §5.4`
(`installer-adoption-2026-07-24c/ADOPTION-AMENDMENT.md:154`), which currently states accepted
provisioning proofs are retained and never deleted. It is a distinct, narrowly-scoped sub-clause,
flagged separately for explicit owner ratification — it is not asserted as already in force, and
this amendment's own Non-goals clause ("does not alter Amendment 7/A4") is understood to exclude
this one deliberate, called-out exception.**

**Why it's needed:** `ROLLBACK-DESIGN.md` §2 requires deleting the exact provisioning-proof
document(s) a failed/rolled-back transaction created, to return the diagnosis stream to its
pre-transaction state. Ratified A4 §5.4's blanket retention rule would otherwise make rollback
unable to undo its own transaction's proof writes — a real gap, not a hypothetical one, since
`verify_stream_behavior()` (`install_assets.py:1477`) creates a proof as a side effect of live
apply verification.

**Proposed text:** "A successful installation retains its provisioning proof(s) per A4 §5.4,
unchanged. An explicit rollback invocation of a transaction that did not reach `APPLY_OK` (or
that is being deliberately reversed) MAY delete only the provisioning proof(s) created by that
exact transaction, identified by exact `event.id` and exact backing index — never by
wildcard search or `_delete_by_query`. Crash-safe capture: the exact `event.id` MUST be
persisted as an intent before the `_create` call; the returned `_index` MUST be persisted once
available. Crash recovery MAY search the diagnosis stream for that one exact ID, MUST require
zero or one hit, and then MAY delete by exact backing index and ID. A proof belonging to any
other transaction, or a proof whose owning transaction reached `APPLY_OK` and was not
subsequently rolled back, MUST NOT be deleted under this exception."

**Ratification status:** proposed here, not yet ratified. `ROLLBACK-DESIGN.md`'s proof-deletion
step is inert (a documented STOP) until this exception clears owner ratification alongside the
rest of this amendment.

---

## Non-goals

- This amendment does **not** migrate any Fleet-managed asset away from Fleet, does not disable
  Fleet management, and does not request Fleet stop managing the 13+13(+13) assets in §1 rows
  6–8.
- It does **not** deploy the TLS loopback proxy as a permanent production fixture; §5 documents
  a proposed, evidence-backed design and its required gate, not a shipped feature.
- It does **not** resolve the credential-hygiene STOP recorded in `KEY-LIFECYCLE.md` (the
  temporary inventory key's discarded secret file inherited mode `0664` and was removed rather
  than shredded) — that is a separate remediation, tracked independently, and this amendment's
  two-write credential whitelist for the current session remains exhausted regardless.
- It does **not** re-run or authorize the Phase 4 single live owner-cluster invocation itself;
  that remains gated on this amendment's ratification plus the open items below.
- It does **not** change `W1-DIAGNOSISEVENT-CONTRACT.md`'s or `W2-SPACE-ROLE-CONTRACT.md`'s own
  numbered `§` sections, and makes no change to the DiagnosisEvent schema, the shipper role
  body, or any Kibana saved-object body.
- It does **not** alter Amendment 7/A4's `--adopt-existing-w1-stream` flag, matrix, or fence
  text; the two amendments compose but neither rewrites the other — **except** §8's narrowly
  scoped, separately-ratified proof-deletion exception to A4 §5.4, called out explicitly above.

## Open questions

1. **§1.1 component-template disposition** — confirmed correct in gate round 1 (Sol), remaining
   open only for final owner ratification alongside the rest of this document, not for further
   technical debate.
2. **§1.3 `metrics-rigsignal.profiles`** — live `composed_of` confirmed empty in gate round 1
   (Sol, citing `raw/be84e15cfb8c.json:9`); remaining open only for owner ratification.
3. **§1.2 `logs-rigsignal.stream` lifecycle-identity change** — ratify or hold. Both policies are
   delete-phase-free today; if the owner wants to preserve the distinct
   `logs-rigsignal-stream-30d` policy name (e.g., to diverge its retention from `logs@lifecycle`
   later), this disposition should flip to "separately-decided: hold, do not PUT" instead.
4. **Transport path (§5) is unresolved**, and gate round 1 adds a new sub-item: the §5.5
   remote-`:5601`-block is an **open ratification item** with a real blast radius (existing NUC
   consumers reaching Kibana over plain `:5601` today) — the owner must choose migration or an
   explicit accepted-risk exception before this clears. No report in this evidence directory
   shows the loopback proxy actually deployed or any item of the §5.6 assertion battery executed.
   This blocks any live Fleet-coexist invocation over HTTP-only owner Kibana until a superseding
   report clears it.
5. **Credential-hygiene STOP** (0664 secret file, not shredded, two-write whitelist exhausted)
   remains open; no further key mint/invalidate operations should occur in this evidence chain
   until it is remediated per the runbook's S1/S4 requirement.
6. **Flag persistence model** — §2 proposes `--ownership-profile fleet-coexist` as a
   per-invocation, always-supplied mode rather than one-shot/state-persisted. Confirm this is
   preferred over persisting the choice in `state.json`, given ownership tables can themselves be
   amended over time and a persisted stale table would silently diverge from the compiled one.
   (Gate round 1 note: `ownership_profile`/`ownership_table_version` are now additionally
   persisted in protected transaction/enrollment state for mismatch-fencing, §2.5 — this is
   orthogonal to whether the *choice* itself becomes one-shot.)
7. **Future risk, out of current scope:** if the diagnosis stream itself is ever onboarded into
   Fleet management, §1 row 1 would need to move into the Fleet-owned/external category — flagged
   here so it is not missed as a silent regression risk, not actioned by this amendment.
8. **§8's A4 exception** — a new open question from gate round 1: is a narrowly-scoped exception
   to A4 §5.4 (as drafted) the right shape, or should proof-deletion-on-rollback instead be
   handled by never creating a "real" proof until a later verification checkpoint (avoiding the
   A4 conflict entirely by construction)? Flagged for owner/architect judgment, not resolved here.

---

## Ratification

- [x] Overseer gate — round 1 REWORK addressed (v2); round 2 CONFIRMED both docs
      2026-07-24 (GATE-ROUND1-OVERSEER.md; v3 edits were Sol-scoped tightening)
- [x] Sol cross-check (xhigh) — round 1 REWORK → v2 → round 2 six exact edits →
      v3 CONFIRMED all three docs 2026-07-24 (GATE-ROUND1-SOL.md, GATE-ROUND2-SOL.md)
- [x] Owner ratification — 2026-07-24, three decisions recorded verbatim:
      (1) ownership table ratified AS GATED (16 owned / 39 external verify-only,
      including the logs-rigsignal.stream lifecycle identity change
      logs-rigsignal-stream-30d → logs@lifecycle);
      (2) §8 A4 exception RATIFIED (transaction-scoped exact-ID proof deletion on
      explicit rollback only);
      (3) §5.5 transport: BLOCK remote plaintext :5601 + migrate NUC consumers to
      https://192.0.2.174:5643 (+combined CA) as a prep task in the
      implementation session, before the live run. Accepted-risk option rejected.

Design ratified at DRAFT v3. Per §4.3 the amendment still re-gates at the
implementing SHA + new bundle hash before any live invocation.

Until all three are checked, this document has no normative force and MUST NOT be cited as
ratified contract text.
