#!/usr/bin/env python3
"""Install a RigSignal asset bundle, with post-install presence verification."""

import argparse
import errno
import base64
import ctypes
import contextvars
import datetime
import fnmatch
import fcntl
import hashlib
import json
import os
import re
import shutil
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
import asset_adapters


ROOT = Path(__file__).resolve().parent.parent
ASSET_DIR = ROOT / "elastic"
DASHBOARD_DIR = ROOT / "dashboards" / "v0.3.1"
# Stay well under the 60 s prerequisite poll bound so a stalled endpoint cannot outlive it.
REQUEST_TIMEOUT_SECONDS = 30
ASSET_TYPES = {
    "component-templates": "component_templates",
    "index-templates": "index_templates",
    "pipelines": "pipelines",
    "transforms": "transforms",
    "security-roles": "security_roles",
    "kibana-spaces": "kibana_spaces",
    "kibana-roles": "kibana_roles",
}
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]*\.json\Z")
PRODUCT_DASHBOARDS = frozenset((
    "rigsignal-engine.ndjson",
    "rigsignal-flamegraph-dashboard.ndjson",
    "rigsignal-game-perf.ndjson",
    "rigsignal-home.ndjson",
    "rigsignal-software.ndjson",
    "rigsignal-system-health.ndjson",
))
STREAMING_LAB_DASHBOARD = "rigsignal-streaming-lab.ndjson"
DASHBOARD_SAVED_OBJECT_TYPES = frozenset(("dashboard", "index-pattern", "search", "tag", "visualization"))
W1_RAW_SHA256 = {
    "elastic/component-templates/logs-rigsignal.diagnosis-mappings.json": "345e0d2898279929eb613b60d2bd250bbf73a13c7b4bbd1b793384e2ae00410c",
    "elastic/index-templates/logs-rigsignal.diagnosis.json": "5f4d4f403fc17a1096b2d2b1c8a43bad94efa52b05c3b117961333b2f3d52199",
    "elastic/security-roles/rigsignal_shipper.json": "6eb0279c7e05b94bfd96083508a8c7e6ad5ca9cb65e531654bd6e0ae3eca7ed2",
}
TARGET_GENERATION_SCHEME = "rigsignal:target-generation:w1-assets:v1"
TARGET_GENERATION_KAT = "a7ed20a4b4bfe0b2e5597a065e8bdaa5161b0d962e1a502d3db3bbcc97e8ee7a"
ROLE_JCS_SHA256 = "05b58b8369bc4212fcffa0ea81621ef10d6d57f1de464fbc3f562842a9cbafd7"
VIEWER_ROLE_JCS_SHA256 = "895f2689e3641d7e7b80e3cbf3d09c7956d486367d78c63e3818a3d0e8509731"
DIAGNOSIS_STREAM = "logs-rigsignal.diagnosis-default"
W1_LIFECYCLE_POLICY = "logs@lifecycle"
PROBE_FIXTURE_PATH = "fixtures/diagnosis_event/v1/positive/15-diagnosis-non-finding-conditional.expected.json"
# Compatibility handle for source-tree test and owner tooling.  Production
# proof construction deliberately uses bundle_resource(), never this pathname.
PROBE_FIXTURE = ROOT / PROBE_FIXTURE_PATH
CANONICAL_COMPONENT_PATH = "elastic/component-templates/logs-rigsignal.diagnosis-mappings.json"
CANONICAL_INDEX_PATH = "elastic/index-templates/logs-rigsignal.diagnosis.json"
AUXILIARY_PATHS = frozenset((PROBE_FIXTURE_PATH,))
SEMVER_TOKEN = re.compile(r"(?<![0-9A-Za-z])([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?![0-9A-Za-z])")
STATE_KEYS = frozenset(("version", "phase", "expected_cluster_uuid", "target_generation",
                        "role_jcs_sha256", "enrollment_root", "active_key_id", "pending_revoke_ids",
                        "pending_mint_name", "candidate_key_id"))
STATE_PHASES = frozenset(("committed", "mint_intent", "candidate_staged", "candidate_verified"))
OWNERSHIP_PROFILE_FILE = "ownership-profile.json"
UUID_RE = re.compile(r"[A-Za-z0-9_-]{22}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
OWNERSHIP_TABLE_VERSION = "fleet-coexist-v1"
ASSETS_MARKER_SCHEMA_VERSION = 1
ASSETS_MARKER_FILE = "assets-marker.json"
RIGSIGNAL_MANAGED_BY = "rigsignal-asset-bundle"
_ES_ASSET_KINDS = frozenset(("component_templates", "index_templates", "pipelines",
                             "transforms", "security_roles"))
LOCAL_TRANSACTION_MIN_AVAILABLE_BLOCKS = 16

# This is deliberately an identity table, rather than a live `_meta` heuristic.
# A bundle addition has no safe default under the coexistence profile.
_OWNED_ASSET_KEYS = frozenset((
    ("component_templates", "logs-rigsignal.diagnosis-mappings"),
    ("index_templates", "logs-rigsignal.diagnosis"),
    ("index_templates", "logs-rigsignal.stream"),
    ("index_templates", "metrics-rigsignal.profiles"),
    ("pipelines", "logs-rigsignal.stream@pipeline"),
    ("security_roles", "rigsignal_shipper"),
    ("transforms", "rigsignal-game-timeline"),
    ("kibana_spaces", "rigsignal"),
    ("kibana_roles", "rigsignal_viewer"),
    *( ("dashboard", name) for name in PRODUCT_DASHBOARDS ),
    ("dashboard", STREAMING_LAB_DASHBOARD),
))
_EXTERNAL_ASSET_KEYS = frozenset((
    *( ("component_templates", name) for name in (
        "metrics-rigsignal.audio@package", "metrics-rigsignal.cpu@package",
        "metrics-rigsignal.ebpf@package", "metrics-rigsignal.ebpf_thread@package",
        "metrics-rigsignal.frame@package", "metrics-rigsignal.gpu@package",
        "metrics-rigsignal.memory@package", "metrics-rigsignal.network@package",
        "metrics-rigsignal.power@package", "metrics-rigsignal.session@package",
        "metrics-rigsignal.storage@package", "metrics-rigsignal.stream_client@package",
        "logs-rigsignal.events@package",
    )),
    *( ("index_templates", name) for name in (
        "logs-rigsignal.events", "metrics-rigsignal.audio", "metrics-rigsignal.cpu",
        "metrics-rigsignal.ebpf", "metrics-rigsignal.ebpf_thread", "metrics-rigsignal.frame",
        "metrics-rigsignal.gpu", "metrics-rigsignal.memory", "metrics-rigsignal.network",
        "metrics-rigsignal.power", "metrics-rigsignal.session", "metrics-rigsignal.storage",
        "metrics-rigsignal.stream_client",
    )),
    *( ("pipelines", name) for name in (
        "logs-rigsignal.events-0.5.0", "metrics-rigsignal.audio-0.5.0",
        "metrics-rigsignal.cpu-0.5.0", "metrics-rigsignal.ebpf-0.5.0",
        "metrics-rigsignal.ebpf_thread-0.5.0", "metrics-rigsignal.frame-0.5.0",
        "metrics-rigsignal.gpu-0.5.0", "metrics-rigsignal.memory-0.5.0",
        "metrics-rigsignal.network-0.5.0", "metrics-rigsignal.power-0.5.0",
        "metrics-rigsignal.session-0.5.0", "metrics-rigsignal.storage-0.5.0",
        "metrics-rigsignal.stream_client-0.5.0",
    )),
))


class InputError(Exception):
    """The requested source or bundle is incomplete or invalid."""


def reject_duplicate_keys(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = member
    return value


def parse_json(data: bytes, context: str):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise InputError(f"invalid JSON {context}: {error}") from error


class RequestFailure(Exception):
    def __init__(self, status: int | None, detail: str, body: bytes = b""):
        self.status = status
        self.body = body
        super().__init__(detail)


class RemoteReadRefusal(InputError):
    """A malformed or unverifiable remote read that must fail closed."""


class ProvisionError(Exception):
    """A deliberately sanitized, stable provisioning failure."""

    def __init__(self, prefix: str):
        self.prefix = prefix
        super().__init__(prefix)


class MutationTracker:
    """Invocation-local proof that a mutating request was about to be sent."""

    def __init__(self):
        self.mutation_issued = False

    def mark_issued(self) -> None:
        self.mutation_issued = True


_mutation_tracker: contextvars.ContextVar[MutationTracker | None] = contextvars.ContextVar(
    "rigsignal_mutation_tracker", default=None)


class FailureSite(Enum):
    PREFLIGHT = "preflight"
    ROOT_PREPARE = "root_prepare"
    ASSET_APPLY = "asset_apply"
    CANDIDATE_STAGE = "candidate_stage"
    PUBLICATION_STAGE = "publication_stage"
    PUBLICATION_EXCHANGE = "publication_exchange"
    PUBLICATION_ANCHOR = "publication_anchor"
    PUBLICATION_IDENTITY = "publication_identity"
    PUBLICATION_CLEANUP = "publication_cleanup"
    PUBLISHED_PROBE = "published_probe"
    LOCAL_COMMIT = "local_commit"


class FailureSiteTracker:
    """Invocation-local, credential-safe location for an enrollment failure."""
    def __init__(self):
        self.site = FailureSite.PREFLIGHT
        self.journal = None

    def attach_journal(self, journal) -> None:
        self.journal = journal

    def mark(self, site: FailureSite) -> None:
        if not isinstance(site, FailureSite):
            raise TypeError("failure site must be a FailureSite")
        self.site = site

    def persist(self) -> None:
        """Best-effort journal retention, after the original operation failed."""
        if self.journal is not None:
            try:
                self.journal.failure_site(self.site)
            except Exception:
                # Failure-site persistence is diagnostic only.  In particular,
                # a broken journal must never mask the original failure.
                pass

    def detach_journal(self) -> None:
        """Prevent a terminal identity failure from writing via a disputed name."""
        self.journal = None


def report_failure_site(site: FailureSite) -> None:
    """Emit only a coarse, non-secret failure classification."""
    if not isinstance(site, FailureSite):
        raise TypeError("failure site must be a FailureSite")
    print("RIGSIGNAL_FAILURE_SITE " + site.value, file=sys.stderr)


def finalize_failure(message: str, failure_tracker: FailureSiteTracker,
                     mutation_tracker: MutationTracker, *, local: bool = False) -> int:
    """Print one stable failure and select its contract exit status.

    ``mutation_tracker`` is deliberately the sole source for the 3/4 split.
    FailureSite and the transaction journal are diagnostic evidence only.
    """
    print(message, file=sys.stderr)
    failure_tracker.persist()
    report_failure_site(failure_tracker.site)
    # Once a mutating request has been issued, its remote state is authoritative
    # for the contract.  A later local failure cannot downgrade a possibly
    # partial operation from exit 4 to exit 2.
    if mutation_tracker.mutation_issued:
        return 4
    if local:
        return 2
    return 3


def is_local_failure_message(message: str) -> bool:
    """Classify only the row-11 local-validation families as exit 2."""
    return (message.startswith("install failed: bundle validation:")
            or any(token in message for token in (
                "agent_binary_unlaunchable", "agent_version_unparseable", "version_skew",
                "admin_credential_api_key",
                "assets_marker_directory",
                "enrollment ancestor is not protected:", "outbox preflight:",
                "enrollment preflight unavailable", "atomic_publication_filesystem_unsupported",
                "enrollment_publication_path_too_long", "enrollment_parent_fsync_unsupported",
                "local_transaction_storage_unavailable", "enrollment_ca_path_invalid")))


class StateBindingError(InputError):
    """A persisted enrollment state does not belong to this enrollment root."""


class OwnershipTableError(InputError):
    """A stable, user-facing ownership-table refusal."""

    def __init__(self, code: str, asset: tuple[str, str] | None = None):
        self.code, self.asset = code, asset
        suffix = "" if asset is None else ": " + asset[0] + "/" + asset[1]
        super().__init__(code + suffix)


class AssetConflictUnproven(ProvisionError):
    """A default-profile object exists but has no accepted ownership proof."""

    def __init__(self):
        super().__init__("install refused: asset_conflict_unproven")


@dataclass(frozen=True)
class Asset:
    kind: str
    name: str
    path: str
    data: bytes


class PredecessorRefusal(InputError):
    """A write-time predecessor pin no longer represents the live object."""

    def __init__(self, asset: Asset | str, object_type: str, object_id: str,
                 expected: str, observed: str, source: str):
        self.asset = asset.kind + "/" + asset.name if isinstance(asset, Asset) else asset
        self.object_type, self.object_id = object_type, object_id
        self.expected, self.observed, self.source = expected, observed, source
        super().__init__("predecessor recheck failed")

    def record(self) -> dict[str, str]:
        return {"asset": self.asset, "object_type": self.object_type,
                "object_id": self.object_id, "expected": self.expected,
                "observed": self.observed, "source": self.source}


@dataclass(frozen=True)
class Bundle:
    version: str
    source_commit: str
    assets: list[Asset]
    files: dict[str, bytes] | None = None


def ownership_for_assets(bundle: Bundle, profile: str) -> dict[tuple[str, str], str]:
    """Resolve every manifest member before the first network operation."""
    keys = {(asset.kind, asset.name) for asset in bundle.assets}
    if len(keys) != len(bundle.assets):
        raise InputError("bundle contains duplicate asset identities")
    if profile == "default":
        return {key: "bundle-owned" for key in keys}
    if profile != "fleet-coexist":
        raise InputError("ownership profile is invalid")
    if os.environ.get("RIGSIGNAL_TEST_UNRESOLVED_ASSET") == "1":
        raise OwnershipTableError("ownership_table_unresolved", ("test", "external"))
    known = _OWNED_ASSET_KEYS | _EXTERNAL_ASSET_KEYS
    unresolved = sorted(keys - known)
    stale = sorted(known - keys)
    if unresolved or stale:
        name = unresolved[0] if unresolved else stale[0]
        raise OwnershipTableError("ownership_table_unresolved", name)
    if (_OWNED_ASSET_KEYS & _EXTERNAL_ASSET_KEYS or len(_OWNED_ASSET_KEYS) != 16
            or len(_EXTERNAL_ASSET_KEYS) != 39 or len(keys) != 55):
        raise OwnershipTableError("ownership_table_cardinality")
    return {key: ("bundle-owned" if key in _OWNED_ASSET_KEYS else "external") for key in keys}


def verify_external_asset(es_url: str, authorization: str, asset: Asset) -> dict:
    """Read and verify an external object without issuing any mutation request."""
    response = json_response(request(es_url, es_path(asset), "GET", authorization))
    expected = parse_json(asset.data, asset.path)
    try:
        live_compatibility = asset_adapters.compatibility_projection(asset.kind, response)
        expected_compatibility = asset_adapters.compatibility_projection(asset.kind, expected)
    except asset_adapters.AdapterError as error:
        raise InputError("external asset projection is invalid") from error
    if asset_adapters.canonical_json(live_compatibility) != asset_adapters.canonical_json(expected_compatibility):
        raise InputError(f"external asset compatibility differs: {asset.kind}/{asset.name}")
    if asset.kind == "index_templates":
        live_template = asset_adapters.get_projection(asset.kind, response)
        composed = live_template.get("composed_of") if isinstance(live_template, dict) else None
        if (not isinstance(composed, list)
                or not asset_adapters.FLEET_COMPOSITION_COMPONENTS.issubset(composed)):
            raise InputError(f"external Fleet composition differs: {asset.kind}/{asset.name}")
        # Textual composed_of tolerance is not sufficient for Fleet index
        # templates.  Simulate the expected body only after replacing its real
        # index pattern: ES rejects an inline body that collides with the live
        # template at the same priority.  The live request uses a concrete
        # matching index and *no* body; {} is an invalid inline template.
        try:
            uniqueness = hashlib.sha256(asset.name.encode("utf-8")).hexdigest()[:16]
            expected_body, expected_index = asset_adapters.synthetic_simulation_template(expected, uniqueness)
            live_index = asset_adapters.concrete_index_name(expected.get("index_patterns"), "rigsignal-a5-probe")
            expected_path = "/_index_template/_simulate_index/" + urllib.parse.quote(expected_index, safe="")
            live_path = "/_index_template/_simulate_index/" + urllib.parse.quote(live_index, safe="")
            equivalent = asset_adapters.simulate_index_equivalent(
                lambda path, body: es_json(es_url, path, "POST", authorization, body),
                expected_path, expected_body, live_path)
        except asset_adapters.AdapterError as error:
            raise InputError("Fleet index simulation is invalid") from error
        if not equivalent:
            raise InputError(f"external index template simulation differs: {asset.kind}/{asset.name}")
    live = asset_adapters.get_projection(asset.kind, response)
    metadata = dict(live.get("_meta")) if isinstance(live, dict) and isinstance(live.get("_meta"), dict) else {}
    # Fleet captures have no package version.  Record the literal absence as
    # null instead of guessing a version or refusing the compatible asset.
    metadata.setdefault("version", None)
    return {"kind": asset.kind, "name": asset.name,
            "live_body_sha256": asset_adapters.sha256(live),
            "compatibility_projection_sha256": asset_adapters.sha256(live_compatibility),
            "owner_metadata": metadata}


def owned_action(es_url: str, kb_url: str, authorization: str, asset: Asset) -> str:
    """Classify an owned asset so the coexistence marker describes reruns honestly."""
    if (os.environ.get("RIGSIGNAL_TEST_ILM_DELETE_PHASE") == "1"
            and asset.kind == "index_templates" and asset.name == "logs-rigsignal.stream"):
        return "update"
    if asset.kind == "dashboard":
        expected = _dashboard_expected_objects(asset)
        try:
            for object_type, object_id, wanted in expected:
                live = json_response(request(kb_url, dashboard_object_path(asset, object_type, object_id),
                                             "GET", authorization, headers={"kbn-xsrf": "true"}))
                if asset_adapters.get_projection("dashboard", live) != wanted:
                    return "import"
        except RequestFailure as error:
            if error.status == 404:
                return "import"
            raise
        except asset_adapters.AdapterError as error:
            raise InputError("owned dashboard projection is invalid") from error
        return "noop"
    base = kb_url if asset.kind in {"kibana_spaces", "kibana_roles"} else es_url
    path = kibana_path(asset) if base == kb_url else es_path(asset)
    headers = {"kbn-xsrf": "true"} if base == kb_url else None
    try:
        response = json_response(request(base, path, "GET", authorization, headers=headers))
    except RequestFailure as error:
        if error.status == 404:
            return "create"
        raise
    if asset.kind in {"kibana_spaces", "kibana_roles"}:
        try:
            verify_kibana_asset(kb_url, authorization, asset)
            return "noop"
        except InputError:
            return "update"
    expected = parse_json(asset.data, asset.path)
    try:
        current = asset_adapters.get_projection(asset.kind, response)
        wanted = asset_adapters.get_projection(asset.kind, expected)
        if asset_adapters.canonical_json(current) == asset_adapters.canonical_json(wanted):
            return "noop"
    except asset_adapters.AdapterError as error:
        raise InputError("owned asset projection is invalid") from error
    return "update"


def cargo_version() -> str:
    candidates = [ROOT / "Cargo.toml"] + sorted(ROOT.glob("*/Cargo.toml"))
    for path in candidates:
        in_package = False
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise InputError("source Cargo.toml cannot be read") from error
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_package = stripped == "[package]"
            elif in_package:
                match = re.match(r'\s*version\s*=\s*"([^"]+)"\s*$', line)
                if match:
                    return match.group(1)
    raise InputError("no [package] version found in Cargo.toml")


def engine_version() -> str:
    """Return the build stamp, falling back only for a source-tree invocation."""
    stamp = TOOLS_DIR / "_version.py"
    if stamp.is_file():
        try:
            match = re.search(r'^ENGINE_VERSION = (["\'])([^"\']+)\1$',
                              stamp.read_text(encoding="utf-8"), re.MULTILINE)
        except OSError as error:
            raise InputError("engine version stamp cannot be read") from error
        if match is None:
            raise InputError("engine version stamp is invalid")
        return match.group(2)
    if not (ROOT / "Cargo.toml").is_file():
        raise InputError("engine version stamp is missing")
    return cargo_version()


def engine_source_commit() -> str | None:
    """Return the immutable engine commit, if this is a staged engine.

    A source-tree invocation intentionally has no release commit fence: its
    Cargo version remains the developer fallback.  A staged engine, however,
    must carry a non-empty commit stamp so a same-semver bundle from another
    source revision cannot cross the release boundary.
    """
    stamp = TOOLS_DIR / "_version.py"
    if not stamp.is_file():
        return None
    try:
        match = re.search(r'^SOURCE_COMMIT = (["\'])([^"\']*)\1$',
                          stamp.read_text(encoding="utf-8"), re.MULTILINE)
    except OSError as error:
        raise InputError("engine version stamp cannot be read") from error
    return match.group(2) if match is not None and match.group(2) else None


def agent_version(agent: Path) -> str:
    """Read one unambiguous semver token from the agent's version output."""
    try:
        result = subprocess.run([os.fspath(agent), "--version"], text=False,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except (OSError, RuntimeError) as error:
        raise ProvisionError("install refused: agent_binary_unlaunchable") from error
    if result.returncode != 0:
        raise ProvisionError("install refused: agent_binary_unlaunchable")
    try:
        stdout = (result.stdout or b"").decode("utf-8")
        stderr = (result.stderr or b"").decode("utf-8")
    except UnicodeError as error:
        raise ProvisionError("install refused: agent_version_unparseable") from error
    found = set(SEMVER_TOKEN.findall(stdout + "\n" + stderr))
    if len(found) != 1:
        raise ProvisionError("install refused: agent_version_unparseable")
    return found.pop()


def fence_versions(bundle: Bundle | None, agent: Path) -> None:
    """Require engine, agent, and verified manifest versions before HTTP."""
    engine, installed_agent = engine_version(), agent_version(agent)
    manifest = bundle.version if bundle is not None else "none"
    if engine != installed_agent or (bundle is not None and engine != manifest):
        raise ProvisionError("install refused: version_skew; "
                             f"engine={engine}; agent={installed_agent}; bundle={manifest}")
    if bundle is not None:
        stamped_commit = engine_source_commit()
        if stamped_commit is not None and stamped_commit == bundle.source_commit:
            return
        # A source tree is deliberately not a release artifact, so retain its
        # version-only development fallback.  A staged engine has _version.py
        # and therefore a missing/blank SOURCE_COMMIT is a fence failure too.
        if (TOOLS_DIR / "_version.py").is_file():
            raise ProvisionError("install refused: version_skew; "
                                 f"engine={engine}; agent={installed_agent}; bundle={manifest}; "
                                 f"engine_commit={stamped_commit or 'missing'}; "
                                 f"bundle_commit={bundle.source_commit}")


def check_version_fence(bundle: Bundle | None, agent: Path) -> None:
    """Run the version-only preflight before any recovery-side HTTP mutation."""
    # Direct unit callers can construct a Bundle without its verified member
    # map.  Every production load_bundle() result has one, and only that path
    # enters main(), so this keeps legacy unit fixtures from pretending to be
    # release bundles.
    if bundle is None or bundle.files is not None:
        fence_versions(bundle, _check_agent_binary(agent))


def bundle_resource(bundle: Bundle | None, path: str, context: str) -> bytes:
    """Resolve proof inputs from verified bundle bytes, or the source tree only."""
    if bundle is not None and bundle.files is not None:
        data = bundle.files.get(path)
        if data is None:
            raise InputError(f"bundle resource missing: {path}")
        return data
    try:
        return (ROOT / path).read_bytes()
    except OSError as error:
        raise InputError(f"source resource cannot be read: {context}") from error


def source_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def path_to_asset(path: str, data: bytes) -> Asset:
    parts = Path(path).parts
    if len(parts) == 3 and parts[0] == "elastic" and parts[1] in ASSET_TYPES:
        if not ASSET_NAME.fullmatch(parts[2]):
            raise InputError(f"invalid asset filename: {path}")
        try:
            parse_json(data, f"asset {path}")
        except InputError:
            raise
        return Asset(ASSET_TYPES[parts[1]], Path(parts[2]).stem, path, data)
    if len(parts) == 3 and parts[:2] == ("dashboards", "v0.3.1") and parts[2].endswith(".ndjson"):
        if not dashboard_objects(data):
            raise InputError(f"dashboard contains no saved objects: {path}")
        return Asset("dashboard", parts[2], path, data)
    raise InputError(f"unexpected bundle input path: {path}")


def dashboard_objects(data: bytes) -> list[tuple[str, str]]:
    objects: list[tuple[str, str]] = []
    try:
        lines = data.decode("utf-8").splitlines()
        for line in lines:
            if not line.strip():
                continue
            value = json.loads(line)
            object_type, object_id = value.get("type"), value.get("id")
            if not isinstance(object_type, str) or not isinstance(object_id, str):
                raise InputError("dashboard NDJSON object lacks type or id")
            objects.append((object_type, object_id))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InputError(f"invalid dashboard NDJSON: {error}") from error
    return objects


def load_source() -> Bundle:
    if not ASSET_DIR.is_dir():
        raise InputError(f"missing asset tree: {ASSET_DIR}")
    allowed_root = {"README.md", *ASSET_TYPES}
    for entry in ASSET_DIR.iterdir():
        if entry.name not in allowed_root:
            raise InputError(f"unexpected file in elastic tree: {entry.relative_to(ROOT)}")
    assets: list[Asset] = []
    for directory in ASSET_TYPES:
        base = ASSET_DIR / directory
        if not base.is_dir():
            raise InputError(f"missing input directory: {base.relative_to(ROOT)}")
        for entry in sorted(base.iterdir()):
            if not entry.is_file():
                raise InputError(f"missing input file or invalid entry: {entry.relative_to(ROOT)}")
            assets.append(path_to_asset(entry.relative_to(ROOT).as_posix(), entry.read_bytes()))
    dashboards = sorted(DASHBOARD_DIR.glob("*.ndjson"))
    if not dashboards:
        raise InputError(f"dashboard glob matched zero files: {DASHBOARD_DIR / '*.ndjson'}")
    assets.extend(path_to_asset(path.relative_to(ROOT).as_posix(), path.read_bytes()) for path in dashboards)
    files = {asset.path: asset.data for asset in assets}
    files.update({path: bundle_resource(None, path, "source auxiliary") for path in AUXILIARY_PATHS})
    return Bundle(cargo_version(), source_commit(), ordered_assets(assets), files)


def load_bundle(bundle_path: Path) -> Bundle:
    try:
        with tarfile.open(bundle_path, "r:gz") as tar:
            members = {}
            for member in tar.getmembers():
                if (not member.isfile() or member.issym() or member.islnk()
                        or member.name.startswith("/") or ".." in Path(member.name).parts):
                    raise InputError(f"unsafe archive member: {member.name}")
                if member.name in members:
                    raise InputError(f"duplicate archive member: {member.name}")
                members[member.name] = member
            manifest_member = members.pop("manifest.json", None)
            if manifest_member is None:
                raise InputError("bundle is missing manifest.json")
            manifest_data = tar.extractfile(manifest_member)
            if manifest_data is None:
                raise InputError("bundle manifest cannot be read")
            manifest = parse_json(manifest_data.read(), "bundle manifest")
            checksums = manifest.get("sha256")
            if not isinstance(checksums, dict):
                raise InputError("bundle manifest has no sha256 mapping")
            if set(members) != set(checksums):
                raise InputError("bundle files do not exactly match manifest sha256 entries")
            assets = []
            files = {}
            for path, expected in checksums.items():
                member = members.get(path)
                if member is None:
                    raise InputError(f"bundle missing input file: {path}")
                payload = tar.extractfile(member)
                if payload is None:
                    raise InputError(f"bundle input cannot be read: {path}")
                data = payload.read()
                if hashlib.sha256(data).hexdigest() != expected:
                    raise InputError(f"sha256 mismatch for bundle input: {path}")
                files[path] = data
                if path not in AUXILIARY_PATHS:
                    assets.append(path_to_asset(path, data))
    except (OSError, tarfile.TarError, json.JSONDecodeError) as error:
        raise InputError(f"cannot read bundle: {error}") from error
    counts = manifest.get("counts")
    actual_counts = count_assets(assets)
    if counts != actual_counts:
        raise InputError("bundle manifest counts do not match its input files")
    dashboards = manifest.get("dashboards")
    actual_dashboards = sorted(asset.path for asset in assets if asset.kind == "dashboard")
    if dashboards != actual_dashboards:
        raise InputError("bundle manifest dashboard list does not match its input files")
    if manifest.get("auxiliary") != sorted(AUXILIARY_PATHS):
        raise InputError("bundle manifest auxiliary inputs are invalid")
    version, commit = manifest.get("bundle_version"), manifest.get("source_commit")
    if not isinstance(version, str) or not isinstance(commit, str):
        raise InputError("bundle manifest lacks version or source_commit")
    # A transaction record binds this release-manifest value, never the
    # runtime source_commit() git probe.  Reject malformed archive metadata
    # before any caller can publish it into durable transaction state.
    if _V2_COMMIT_RE.fullmatch(commit) is None:
        raise InputError("bundle manifest source_commit is invalid")
    validate_w1_manifest(manifest, {asset.path: asset.data for asset in assets})
    return Bundle(version, commit, ordered_assets(assets), files)


def bundle_sha256(bundle_path: Path) -> str:
    """Hash the exact bundle file supplied for a Fleet transaction pin."""
    digest = hashlib.sha256()
    try:
        with bundle_path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise InputError(f"cannot read bundle: {error}") from error
    return digest.hexdigest()


def asset_set_sha256(bundle: Bundle) -> str:
    """Hash every source identity and body deterministically for rollback fencing."""
    digest = hashlib.sha256()
    for asset in sorted(bundle.assets, key=lambda item: (item.kind, item.name, item.path)):
        for value in (asset.kind, asset.name, asset.path):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        digest.update(hashlib.sha256(asset.data).digest())
    return digest.hexdigest()


def ordered_assets(assets: list[Asset]) -> list[Asset]:
    order = {"component_templates": 0, "index_templates": 1, "security_roles": 2,
             "pipelines": 3, "transforms": 4, "kibana_spaces": 5,
             "kibana_roles": 6, "dashboard": 7}
    return sorted(assets, key=lambda asset: (order[asset.kind], asset.name))


def count_assets(assets: list[Asset]) -> dict[str, int]:
    counts = {name: 0 for name in ASSET_TYPES.values()}
    counts["dashboards"] = 0
    for asset in assets:
        counts["dashboards" if asset.kind == "dashboard" else asset.kind] += 1
    return counts


def recompute_target_generation(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(TARGET_GENERATION_SCHEME.encode("utf-8") + b"\0")
    digest.update((3).to_bytes(4, "big"))
    for path in sorted(W1_RAW_SHA256):
        data = files.get(path)
        if data is None or hashlib.sha256(data).hexdigest() != W1_RAW_SHA256[path]:
            raise InputError(f"canonical W1 asset mismatch: {path}")
        encoded_path = path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(hashlib.sha256(data).digest())
    value = digest.hexdigest()
    if value != TARGET_GENERATION_KAT:
        raise InputError("target-generation KAT mismatch")
    return value


def validate_w1_manifest(manifest: dict, files: dict[str, bytes]) -> None:
    value = recompute_target_generation(files)
    expected_inputs = [
        {"path": path, "sha256": W1_RAW_SHA256[path]}
        for path in sorted(W1_RAW_SHA256)
    ]
    expected = {"scheme": TARGET_GENERATION_SCHEME, "algorithm": "sha256",
                "input_count": 3, "inputs": expected_inputs, "value": value}
    if manifest.get("target_generation") != expected:
        raise InputError("bundle manifest target_generation is invalid")


def auth_header(value: str) -> str:
    if value.startswith("ApiKey ") and value[7:]:
        return value
    if ":" in value:
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"
    raise InputError("RIGSIGNAL_ES_AUTH must be user:pass or ApiKey <key>")


def protected_regular_file(path: Path) -> bytes:
    """Read an invoking-user-owned, no-follow, 0600-or-stricter input."""
    try:
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)
                or st.st_uid != os.geteuid() or st.st_mode & 0o077):
            raise InputError(f"unprotected input file: {path}")
        return path.read_bytes()
    except OSError as error:
        raise InputError(f"cannot read protected input file: {path}") from error


def admin_authorization(path: Path) -> str:
    body = parse_json(b"{}", "internal")  # Keep duplicate-key parser coverage local.
    del body
    try:
        import tomllib
        config = tomllib.loads(protected_regular_file(path).decode("utf-8"))
        values = config["elasticsearch"]
        if set(values) == {"api_key"} and isinstance(values["api_key"], str):
            return auth_header("ApiKey " + values["api_key"])
        if set(values) == {"username", "password"}:
            return auth_header(f"{values['username']}:{values['password']}")
    except (KeyError, UnicodeDecodeError, ValueError, TypeError) as error:
        raise InputError("administrator credential file is invalid") from error
    raise InputError("administrator credential file is invalid")


def admin_credential_kind(path: Path) -> str:
    """Classify credential source without widening the accepted TOML grammar."""
    try:
        import tomllib
        values = tomllib.loads(protected_regular_file(path).decode("utf-8"))["elasticsearch"]
        if set(values) == {"api_key"} and isinstance(values["api_key"], str):
            return "api_key"
        if set(values) == {"username", "password"} and all(isinstance(values[key], str)
                                                               for key in values):
            return "native_user"
    except (KeyError, UnicodeDecodeError, ValueError, TypeError):
        pass
    raise InputError("administrator credential file is invalid")


def cluster_health_gate(es_url: str, authorization: str) -> None:
    """Permit green, or explained yellow with neither primaries nor tasks pending."""
    forced = os.environ.get("RIGSIGNAL_TEST_CLUSTER_HEALTH")
    if not forced:
        # Best effort only: the following protocol check remains the one
        # authoritative point-in-time health decision.
        try:
            es_json(es_url, "/_cluster/health?wait_for_events=languid&timeout=30s",
                    "GET", authorization)
        except (InputError, RequestFailure):
            pass
    response = ({"status": forced, "unassigned_primary_shards": 1,
                 "number_of_pending_tasks": 1} if forced else
                es_json(es_url, "/_cluster/health", "GET", authorization))
    if not isinstance(response, dict):
        raise ProvisionError("install refused: cluster_health")
    status = response.get("status")
    if status == "green":
        return
    if (status == "yellow" and response.get("unassigned_primary_shards") == 0
            and response.get("number_of_pending_tasks") == 0):
        return
    raise ProvisionError("install refused: cluster_health")


def lifecycle_delete_phase_free(es_url: str, authorization: str) -> None:
    """Re-read both policy identities immediately before the lifecycle PUT."""
    if os.environ.get("RIGSIGNAL_TEST_ILM_DELETE_PHASE") == "1":
        raise ProvisionError("install refused: ilm_delete_phase")
    for policy_name in ("logs-rigsignal-stream-30d", "logs@lifecycle"):
        try:
            response = es_json(es_url, "/_ilm/policy/" + urllib.parse.quote(policy_name, safe=""),
                               "GET", authorization)
        except RequestFailure as error:
            # §3.4 guards against a policy having GAINED a delete phase since
            # baseline. The owner-specific 30d policy may legitimately not
            # exist on other clusters — absence is trivially delete-phase-free.
            # logs@lifecycle is an ES builtin: its absence means a broken stack.
            if error.status == 404 and policy_name == "logs-rigsignal-stream-30d":
                continue
            raise
        policy = response.get(policy_name) if isinstance(response, dict) else None
        phases = policy.get("policy", {}).get("phases") if isinstance(policy, dict) else None
        if not isinstance(phases, dict) or "delete" in phases:
            raise ProvisionError("install refused: ilm_delete_phase")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def configure_https(ca_file: Path) -> None:
    ca = protected_regular_file(ca_file)
    try:
        context = ssl.create_default_context(cadata=ca.decode("utf-8"))
    except (ssl.SSLError, UnicodeDecodeError) as error:
        raise InputError("CA file is invalid") from error
    urllib.request.install_opener(urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context)))


def https_origin(value: str, flag: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise InputError(f"{flag} must be an HTTPS origin")
    return value.rstrip("/")


def request_response(base: str, path: str, method: str, authorization: str, data: bytes | None = None,
                     headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    audit_log = os.environ.get("RIGSIGNAL_HTTP_AUDIT_LOG")
    if audit_log:
        # Test/gate recording only: normal invocations never open an audit
        # file.  Store method+path before dispatch so a rejected write is
        # still visible to the audit leg.
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        descriptor = os.open(audit_log, flags, 0o600)
        try:
            st = os.fstat(descriptor)
            if not stat.S_ISREG(st.st_mode):
                raise InputError("HTTP audit log is not a regular file")
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "a", encoding="utf-8")
        except BaseException:
            os.close(descriptor)
            raise
        with handle:
            handle.write(method + " " + path + "\n")
    request_headers = {"Authorization": authorization, **(headers or {})}
    if data is not None and "Content-Type" not in request_headers:
        request_headers["Content-Type"] = "application/json"
    target = base.rstrip("/") + path
    req = urllib.request.Request(target, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        raise RequestFailure(error.code, f"HTTP {error.code}", error.read()) from error
    except urllib.error.URLError as error:
        raise RequestFailure(None, f"network error: {error.reason}") from error
    except TimeoutError as error:
        raise RequestFailure(None, f"network timeout after {REQUEST_TIMEOUT_SECONDS}s") from error


def request(base: str, path: str, method: str, authorization: str, data: bytes | None = None,
            headers: dict[str, str] | None = None) -> bytes:
    return request_response(base, path, method, authorization, data, headers)[1]


def mutation_request(base: str, path: str, method: str, authorization: str,
                     data: bytes | None = None,
                     headers: dict[str, str] | None = None) -> bytes:
    """Issue a known-mutating request after recording the invocation boundary."""
    tracker = _mutation_tracker.get()
    if tracker is not None:
        tracker.mark_issued()
    return request(base, path, method, authorization, data, headers)


def mark_mutation_issued() -> None:
    """Record a mutation for wrappers that return a status rather than bytes."""
    tracker = _mutation_tracker.get()
    if tracker is not None:
        tracker.mark_issued()


def es_path(asset: Asset) -> str:
    name = urllib.parse.quote(asset.name, safe="")
    paths = {
        "component_templates": f"/_component_template/{name}",
        "index_templates": f"/_index_template/{name}",
        "pipelines": f"/_ingest/pipeline/{name}",
        "transforms": f"/_transform/{name}",
        "security_roles": f"/_security/role/{name}",
    }
    return paths[asset.kind]


def kibana_path(asset: Asset) -> str:
    name = urllib.parse.quote(asset.name, safe="")
    paths = {
        "kibana_spaces": f"/api/spaces/space/{name}",
        "kibana_roles": f"/api/security/role/{name}",
    }
    return paths[asset.kind]


def multipart_dashboard(asset: Asset) -> tuple[bytes, str]:
    boundary = f"----rigsignal-{uuid.uuid4().hex}"
    head = (f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"{asset.name}\"\r\n"
            "Content-Type: application/ndjson\r\n\r\n").encode("utf-8")
    return head + asset.data + f"\r\n--{boundary}--\r\n".encode("utf-8"), boundary


def dashboard_import_path(asset: Asset) -> str:
    if asset.name in PRODUCT_DASHBOARDS:
        return "/s/rigsignal/api/saved_objects/_import?overwrite=true"
    if asset.name == STREAMING_LAB_DASHBOARD:
        return "/api/saved_objects/_import?overwrite=true"
    raise InputError("dashboard is not authorized for installation")


def space_prefix(space: str) -> str:
    """Return Kibana's scoped path prefix (the default space is unscoped)."""
    return "" if space == "default" else "/s/" + urllib.parse.quote(space, safe="")


def dashboard_target_space(asset_or_name) -> str:
    """Return the one ratified destination space for a dashboard asset."""
    name = asset_or_name.name if hasattr(asset_or_name, "name") else asset_or_name
    if name in PRODUCT_DASHBOARDS:
        return "rigsignal"
    if name == STREAMING_LAB_DASHBOARD:
        return "default"
    raise ProvisionError(
        f"install refused: saved_object_topology_conflict: unrecognized dashboard {name}")


def dashboard_object_path(asset: Asset, object_type: str, object_id: str) -> str:
    return (space_prefix(dashboard_target_space(asset)) + "/api/saved_objects/"
            + urllib.parse.quote(object_type, safe="") + "/"
            + urllib.parse.quote(object_id, safe=""))


def assert_dashboard_import_result(asset: Asset, response: object) -> None:
    expected = dashboard_objects(asset.data)
    if not isinstance(response, dict) or response.get("success") is not True:
        raise InputError("dashboard import did not report success")
    if response.get("successCount") != len(expected):
        raise InputError("dashboard import success count differs")
    if response.get("errors") not in (None, False, []):
        raise InputError("dashboard import reported errors")
    results = response.get("successResults")
    if not isinstance(results, list) or len(results) != len(expected):
        raise InputError("dashboard import result count differs")
    actual = []
    for result in results:
        if (not isinstance(result, dict) or result.get("error") not in (None, False)
                or not isinstance(result.get("type"), str) or not isinstance(result.get("id"), str)):
            raise InputError("dashboard import reported an object error")
        actual.append((result["type"], result["id"]))
    if sorted(actual) != sorted(expected):
        raise InputError("dashboard import result differs from submitted objects")


def _topology_refusal(token: str, reason: str) -> None:
    raise ProvisionError(f"install refused: {token}: {reason}")


def _strict_saved_object_find(kb_url: str, authorization: str, space: str,
                              object_type: str) -> list[dict]:
    """Read one complete saved-object type page, rejecting ambiguous answers."""
    path = (space_prefix(space) + "/api/saved_objects/_find?type="
            + urllib.parse.quote(object_type, safe="") + "&per_page=1000")
    try:
        status, raw = request_response(kb_url, path, "GET", authorization,
                                       headers={"kbn-xsrf": "true"})
        body = json_response(raw)
    except (RequestFailure, InputError) as error:
        raise InputError("find_response_malformed") from error
    if status != 200 or not isinstance(body, dict):
        raise InputError("find_response_malformed")
    total, rows = body.get("total"), body.get("saved_objects")
    if body.get("page") != 1 or not isinstance(total, int) or isinstance(total, bool):
        raise InputError("find_response_malformed")
    if not isinstance(rows, list) or total != len(rows):
        raise InputError("find_response_malformed")
    if total > 1000:
        raise InputError("pagination_incomplete")
    seen: set[str] = set()
    for row in rows:
        if (not isinstance(row, dict) or row.get("type") != object_type
                or not isinstance(row.get("id"), str)
                or ("originId" in row and not isinstance(row["originId"], str))):
            raise InputError("find_row_malformed")
        if row["id"] in seen:
            raise InputError("duplicate_row_id")
        seen.add(row["id"])
    return rows


def _dashboard_inventory(bundle: Bundle) -> list[tuple[str, str, str, dict, str]]:
    """Parse the dashboard definitions and enforce local canonical consistency."""
    grouped: dict[tuple[str, str, str], list[tuple[dict, str]]] = {}
    targets: dict[tuple[str, str], set[str]] = {}
    for asset in bundle.assets:
        if asset.kind != "dashboard":
            continue
        target = dashboard_target_space(asset)
        for line in asset.data.decode("utf-8").splitlines():
            if not line.strip():
                continue
            value = parse_json(line.encode("utf-8"), asset.path)
            if not isinstance(value, dict) or not isinstance(value.get("type"), str) or not isinstance(value.get("id"), str):
                _topology_refusal("saved_object_topology_conflict", "malformed_bundle_record")
            object_type, object_id = value["type"], value["id"]
            canonical = {"attributes": value.get("attributes", {})}
            if "references" in value:
                canonical["references"] = value["references"]
            grouped.setdefault((object_type, object_id, target), []).append((canonical, asset.name))
            targets.setdefault((object_type, object_id), set()).add(target)
    for (object_type, object_id), spaces in targets.items():
        if len(spaces) > 1:
            _topology_refusal("saved_object_topology_conflict",
                              f"inconsistent_target {object_type}/{object_id}")
    inventory = []
    for (object_type, object_id, target), entries in grouped.items():
        first = jcs(entries[0][0])
        if any(jcs(value) != first for value, _name in entries[1:]):
            names = ",".join(name for _value, name in entries)
            _topology_refusal("saved_object_topology_conflict",
                              f"duplicate_divergent_definition {object_type}/{object_id} files={names}")
        inventory.append((object_type, object_id, target, entries[0][0], entries[0][1]))
    return inventory


def _print_topology_remediation(target_space: str, object_type: str, physical_id: str) -> None:
    payload = {
        "method": "DELETE",
        "path": (space_prefix(target_space) + "/api/saved_objects/"
                 + urllib.parse.quote(object_type, safe="") + "/"
                 + urllib.parse.quote(physical_id, safe="")),
        "headers": {"kbn-xsrf": "true"},
    }
    print("RIGSIGNAL_REMEDIATION " + json.dumps(payload))


def run_topology_preflight(bundle: Bundle, es_url: str, kb_url: str, authorization: str,
                           ownership_profile: str) -> None:
    """Fail closed before any local or remote installation mutation."""
    inventory = _dashboard_inventory(bundle)
    if not inventory:
        return
    try:
        status, raw = request_response(es_url, "/_security/_authenticate", "GET", authorization)
        authenticated = json_response(raw)
        if (status != 200 or not isinstance(authenticated, dict)
                or not isinstance(authenticated.get("roles"), list)
                or "superuser" not in authenticated["roles"]):
            _topology_refusal("saved_object_topology_unverifiable", "privilege_unverified")
        status, raw = request_response(kb_url, "/api/spaces/space", "GET", authorization,
                                       headers={"kbn-xsrf": "true"})
        spaces_body = json_response(raw)
        if status != 200 or not isinstance(spaces_body, list):
            _topology_refusal("saved_object_topology_unverifiable", "space_list_unverifiable")
        if any(not isinstance(item, dict) or not isinstance(item.get("id"), str) for item in spaces_body):
            _topology_refusal("saved_object_topology_unverifiable", "space_list_unverifiable")
        spaces = {item["id"] for item in spaces_body}
        if "default" not in spaces:
            _topology_refusal("saved_object_topology_unverifiable", "space_list_unverifiable")
        table: dict[tuple[str, str], dict[str, str | None]] = {}
        for space in spaces:
            for object_type in DASHBOARD_SAVED_OBJECT_TYPES:
                table[(space, object_type)] = {
                    row["id"]: row.get("originId") for row in _strict_saved_object_find(
                        kb_url, authorization, space, object_type)
                }
        # legacy-url-alias is namespace-agnostic: a scoped _find returns the
        # SAME rows for every /s/<space> prefix (verified live on 9.4.3,
        # 2026-07-27 — a single alias appeared once per enumerated space,
        # multiplying the refusal reasons). Query once, unscoped; each row
        # names its own space via attributes.targetNamespace (validated as a
        # string like sourceId/targetId — absence is unverifiable, never
        # guessed).
        alias_rows = _strict_saved_object_find(kb_url, authorization, "default", "legacy-url-alias")
        alias_entries = []
        for row in alias_rows:
            attributes = row.get("attributes")
            if (not isinstance(attributes, dict) or not isinstance(attributes.get("sourceId"), str)
                    or not isinstance(attributes.get("targetId"), str)
                    or not isinstance(attributes.get("targetNamespace"), str)):
                _topology_refusal("saved_object_topology_unverifiable", "alias_row_malformed")
            alias_entries.append((attributes["sourceId"], attributes["targetId"],
                                  attributes["targetNamespace"]))
    except ProvisionError:
        raise
    except (RequestFailure, InputError, json.JSONDecodeError) as error:
        _topology_refusal("saved_object_topology_unverifiable", str(error) or "find_response_malformed")
    for object_type, object_id, target, _body, _name in inventory:
        reasons: list[str] = []
        orphan_ids: list[str] = []
        foreign_spaces: list[str] = []
        for space in spaces:
            if space != target and object_id in table[(space, object_type)]:
                reasons.append(f"literal_id_exists_elsewhere space={space}")
                foreign_spaces.append(space)
        for source_id, target_id, alias_space in alias_entries:
            if object_id in (source_id, target_id):
                reasons.append(f"alias_match space={alias_space}")
        if target in spaces:
            for physical_id, origin_id in table[(target, object_type)].items():
                if physical_id != object_id and origin_id == object_id:
                    reasons.append("target_origin_derivative "
                                   f"physical_id={physical_id} originId={origin_id} space={target}")
                    orphan_ids.append(physical_id)
        if reasons:
            if ownership_profile != "fleet-coexist":
                for space in foreign_spaces:
                    print("RIGSIGNAL_OPERATOR_ACTION resolve or remove foreign literal object "
                          f"{object_type}/{object_id} in space={space}")
                if any(reason.startswith("target_origin_derivative") for reason in reasons):
                    for physical_id in orphan_ids:
                        _print_topology_remediation(target, object_type, physical_id)
            _topology_refusal("saved_object_topology_conflict",
                              f"{object_type}/{object_id}: " + "; ".join(reasons))
        outcome = "proceed-as-rerun" if target in spaces and object_id in table[(target, object_type)] else "proceed-as-create"
        print(f"RIGSIGNAL_TOPOLOGY_OUTCOME {object_type}/{object_id} {target} {outcome}")


def assert_no_id_regeneration(kb_url: str, authorization: str, asset: Asset, response: dict) -> None:
    """Remove Kibana-generated ids, then refuse so they can never become owned."""
    target_space = dashboard_target_space(asset)
    flagged = [row for row in response.get("successResults", [])
               if isinstance(row, dict) and "destinationId" in row]
    if not flagged:
        return
    survivors = []
    valid = []
    for row in flagged:
        if not isinstance(row.get("type"), str) or not isinstance(row.get("id"), str) or not isinstance(row.get("destinationId"), str):
            raise ProvisionError(f"install refused: saved_object_id_regenerated: malformed destinationId row {row}")
        valid.append(row)
    for row in valid:
        object_type, destination_id = row["type"], row["destinationId"]
        try:
            mutation_request(kb_url, space_prefix(target_space) + "/api/saved_objects/"
                    + urllib.parse.quote(object_type, safe="") + "/"
                    + urllib.parse.quote(destination_id, safe=""), "DELETE", authorization,
                    headers={"kbn-xsrf": "true"})
        except RequestFailure as error:
            if error.status != 404:
                survivors.append((object_type, destination_id))
                continue
        fault("after-regen-cleanup-delete", f"{object_type}/{destination_id}")
    if survivors:
        raise ProvisionError("install refused: saved_object_id_regenerated_cleanup_failed: "
                             f"{survivors} space={target_space}")
    raise ProvisionError("install refused: saved_object_id_regenerated: "
                         f"{[(row['type'], row['id'], row['destinationId']) for row in valid]} space={target_space}")


def marker_body(bundle: Bundle, ownership_profile: str = "default",
                applied_owned_assets: list[dict] | None = None,
                verified_external_assets: list[dict] | None = None) -> bytes:
    meta = {"bundle_version": bundle.version, "source_commit": bundle.source_commit,
            "installed_at_field": "set by server", "ownership_profile": ownership_profile}
    if ownership_profile == "fleet-coexist":
        owned = applied_owned_assets or []
        external = verified_external_assets or []
        if len(owned) != 16 or len(external) != 39:
            raise InputError("fleet coexist marker accounting is incomplete")
        identities = {(item.get("kind"), item.get("name")) for item in owned + external}
        if len(identities) != 55 or any(not isinstance(item, dict) for item in owned + external):
            raise InputError("fleet coexist marker accounting is invalid")
        meta.update({"ownership_table_version": OWNERSHIP_TABLE_VERSION,
                     "applied_owned_assets": owned, "verified_external_assets": external})
    return json.dumps({"_meta": meta,
                       "template": {}}, sort_keys=True).encode("utf-8")


def fail_table(failures: list[tuple[str, str, str]]) -> None:
    print("asset failures:", file=sys.stderr)
    print("kind | asset | error", file=sys.stderr)
    print("--- | --- | ---", file=sys.stderr)
    for kind, name, error in failures:
        print(f"{kind} | {name} | {error}", file=sys.stderr)


def jcs(value: object) -> bytes:
    """The small JSON subset used by shipped assets, encoded deterministically.

    Elasticsearch's envelopes are projected before this function is called.  The
    role/template request bodies contain no floats, so Python's JSON encoder is
    an RFC-8785-compatible representation for this closed input set.
    """
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


# v2 default-profile transaction foundations.  These deliberately do not alter
# the established v1 marker/apply flow; Stage 2 wires the state machine to them.
V2_SCHEMA_VERSION = 2
V2_ASSET_OBLIGATION = "assets-66"
V2_FULL_FLOW_OBLIGATION = "full-flow-step-11"
BUNDLE_META_TARGET_KEY = "es/bundle-meta/rigsignal-bundle-meta"
AUTHORITATIVE_RECORD_READ_BOUNDARY = "after-assets-lock"
_V2_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_V2_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_V2_CLUSTER_RE = re.compile(r"[A-Za-z0-9_-]{22}\Z")
_V2_TRANSACTION_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_V2_SEGMENT_RE = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+\Z")
_V2_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?Z\Z")


def _v2_timestamp(value: object) -> bool:
    if not isinstance(value, str) or _V2_TIMESTAMP_RE.fullmatch(value) is None:
        return False
    try:
        datetime.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return True


def _v2_segment(value: object) -> bool:
    return isinstance(value, str) and _V2_SEGMENT_RE.fullmatch(value) is not None


def valid_target_key(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split("/")
    if len(parts) == 3 and parts[0] == "es":
        return parts[1] in {"component-template", "index-template", "ingest-pipeline",
                            "security-role", "transform", "bundle-meta"} and _v2_segment(parts[2])
    return len(parts) == 4 and parts[0] == "kibana" and all(_v2_segment(part) for part in parts[1:])


def _v2_quote(value: str) -> str:
    return urllib.parse.quote(value, safe="-._~")


def _target_digest(value: object) -> str:
    return hashlib.sha256(jcs(value)).hexdigest()


def transaction_targets(bundle: Bundle) -> list[dict[str, str]]:
    """Expand 46 ES + 18 saved-object + space + role identities to 66 targets."""
    es_kinds = {"component_templates": "component-template", "index_templates": "index-template",
                "pipelines": "ingest-pipeline", "security_roles": "security-role",
                "transforms": "transform"}
    targets: dict[str, str] = {}

    def add(key: str, semantic: object) -> None:
        digest = _target_digest(semantic)
        prior = targets.setdefault(key, digest)
        if prior != digest:
            raise InputError("duplicate expanded target differs")

    for asset in bundle.assets:
        if asset.kind in es_kinds:
            add("es/" + es_kinds[asset.kind] + "/" + _v2_quote(asset.name),
                parse_json(stamped_asset(asset).data, asset.path))
        elif asset.kind == "kibana_spaces":
            add("kibana/rigsignal/space/" + _v2_quote(asset.name), parse_json(asset.data, asset.path))
        elif asset.kind == "kibana_roles":
            add("kibana/default/role/" + _v2_quote(asset.name), parse_json(asset.data, asset.path))
        elif asset.kind == "dashboard":
            for line in asset.data.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                saved = parse_json(line.encode("utf-8"), asset.path)
                if not isinstance(saved, dict) or not isinstance(saved.get("type"), str) or not isinstance(saved.get("id"), str):
                    raise InputError("dashboard object is invalid")
                space = dashboard_target_space(asset)
                semantic = {key: saved[key] for key in ("attributes", "references") if key in saved}
                semantic["references"] = semantic.get("references", [])
                add("kibana/" + _v2_quote(space) + "/" + _v2_quote(saved["type"]) + "/" +
                    _v2_quote(saved["id"]), semantic)
    result = [{"digest": digest, "key": key} for key, digest in targets.items()]
    result.sort(key=lambda item: item["key"].encode("utf-8"))
    if len(result) != 66:
        raise InputError("expanded transaction target accounting is invalid")
    return result


def canonical_https_origin(value: str, flag: str) -> str:
    """Return the redaction-safe, comparison-safe HTTPS origin spelling."""
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise InputError(f"{flag} must be an HTTPS origin") from error
    if (not isinstance(value, str) or parsed.scheme.lower() != "https" or not parsed.netloc
            or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or parsed.hostname is None):
        raise InputError(f"{flag} must be an HTTPS origin")
    host = parsed.hostname
    if "%" in host:
        raise InputError(f"{flag} must be an HTTPS origin")
    try:
        import ipaddress
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            canonical_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise InputError(f"{flag} must be an HTTPS origin") from error
        if not canonical_host:
            raise InputError(f"{flag} must be an HTTPS origin")
    else:
        canonical_host = str(address)
        if address.version == 6:
            canonical_host = "[" + canonical_host + "]"
    if port is not None and not 1 <= port <= 65535:
        raise InputError(f"{flag} must be an HTTPS origin")
    return "https://" + canonical_host + ("" if port in (None, 443) else ":" + str(port))


def transaction_binding(bundle: Bundle, cluster: str, kibana_origin: str, archive_sha256: str) -> dict:
    """Construct the immutable binding after archive snapshot and remote binding."""
    return {"schema_version": V2_SCHEMA_VERSION, "cluster_uuid": cluster,
            "kibana_target": {"origin": canonical_https_origin(kibana_origin, "--kibana-endpoint"),
                              "spaces": ["default", "rigsignal"]}, "ownership_profile": "default",
            "bundle_version": bundle.version, "source_commit": bundle.source_commit,
            "bundle_sha256": archive_sha256, "asset_set_sha256": _target_digest(transaction_targets(bundle))}


def bundle_snapshot_digest(bundle: Bundle) -> str:
    """Fallback binding for in-memory/unit bundles.

    CLI callers replace this with the SHA-256 of the protected archive
    snapshot.  Keeping the fallback explicit prevents test fixtures from
    accidentally binding to a mutable pathname.
    """
    files = bundle.files or {asset.path: asset.data for asset in bundle.assets}
    return hashlib.sha256(jcs({path: base64.b64encode(data).decode("ascii")
                               for path, data in sorted(files.items())})).hexdigest()


def transaction_possible_mutation(path: Path) -> tuple[bool, str | None]:
    """Best-effort, redaction-safe uncertainty check for the exit boundary."""
    try:
        raw = protected_regular_file(path)
        value = parse_json(raw, "assets transaction record")
    except (InputError, OSError):
        return False, None
    token = value.get("transaction_id") if isinstance(value, dict) else None
    return bool(isinstance(value, dict) and jcs(value) == raw
                and value.get("schema_version") == V2_SCHEMA_VERSION
                and value.get("state") == "installing"
                and value.get("possible_mutation") is True
                and isinstance(token, str) and _V2_TRANSACTION_RE.fullmatch(token) is not None), None


def transaction_failure_status(record_path: Path) -> int:
    possible, _token = transaction_possible_mutation(record_path)
    if possible:
        # The record is untrusted diagnostic input.  UUID grammar is checked
        # above, but even a valid identifier is never emitted at this boundary.
        print("RIGSIGNAL_RECOVERY_STATE partial-remote-possible transaction=<redacted>", file=sys.stderr)
        return 4
    return 3


def transaction_boundary_preflight(record_path: Path) -> int | None:
    """Reject an unparseable durable boundary before mutable setup (A6).

    A syntactically valid ``possible_mutation`` record is deliberately *not*
    terminal here.  The shared transaction executor owns its recovery: it
    re-observes every target and may safely promote only after that complete
    verification pass.  Returning exit 4 at this early CLI boundary would
    bypass that recovery path for both callers.
    """
    try:
        # Do not turn a first-run absent state directory into a malformed
        # record.  Once a leaf exists, however, every malformed/protection
        # failure is a terminal boundary error rather than local input.
        record_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR}:
            return None
        return 3
    try:
        raw = protected_regular_file(record_path)
    except FileNotFoundError:
        return None
    except (InputError, OSError):
        return 3
    try:
        value = parse_json(raw, "assets transaction record")
    except InputError:
        return 3
    # Legacy private markers are not v2 transaction records and must continue
    # to reach their dedicated migration/refusal path.  A v2-shaped record is
    # different: malformed bytes are an A6 terminal error.
    legacy_shape = (isinstance(value, dict)
                    and set(value) == {"schema_version", "bundle_version", "source_commit", "identities"}
                    and value.get("schema_version") == ASSETS_MARKER_SCHEMA_VERSION)
    if not isinstance(value, dict) or value.get("schema_version") != V2_SCHEMA_VERSION:
        return None if legacy_shape else 3
    if jcs(value) != raw:
        return 3
    # A present record must at least be a recognizable v2 envelope.  Binding
    # validation follows after snapshot/remote binding is available.
    # This deliberately validates only the *exit* authority.  It does not
    # bind a record to the newly requested archive and consequently cannot
    # authorize a write; the executor performs that binding before recovery.
    possible, _token = transaction_possible_mutation(record_path)
    if possible:
        print("RIGSIGNAL_RECOVERY_STATE partial-remote-possible transaction=<redacted>", file=sys.stderr)
        return 4
    return None


def transaction_boundary_version_preflight(record_path: Path, bundle: Bundle, *,
                                           upgrade: bool, allow_downgrade: bool) -> int | None:
    """Classify the zero-transport same-version flag boundary.

    This deliberately has *no* recovery authority.  It only reads an existing
    protected leaf, proves that it is a canonical current v2 record using
    locally available bundle facts, and rejects flags which cannot possibly
    describe a transition.  In particular, a valid ``possible_mutation``
    record is left for the executor to reconcile; returning 4 here would
    preempt a recoverable transaction.
    """
    if not (upgrade or allow_downgrade):
        return None
    try:
        record_path.lstat()
    except FileNotFoundError:
        return 2
    except OSError as error:
        return 2 if error.errno in {errno.ENOENT, errno.ENOTDIR} else 3
    try:
        raw = protected_regular_file(record_path)
        value = parse_json(raw, "assets transaction record")
    except (InputError, OSError):
        return 3
    legacy_shape = (isinstance(value, dict)
                    and set(value) == {"schema_version", "bundle_version", "source_commit", "identities"}
                    and value.get("schema_version") == ASSETS_MARKER_SCHEMA_VERSION)
    if legacy_shape:
        # Legacy migration/refusal owns its historic ordering and flag rules.
        return None
    if not isinstance(value, dict) or value.get("schema_version") != V2_SCHEMA_VERSION or jcs(value) != raw:
        return 3
    kibana_target = value.get("kibana_target")
    try:
        strict_remote_shape = (isinstance(value.get("cluster_uuid"), str)
                               and _V2_CLUSTER_RE.fullmatch(value["cluster_uuid"]) is not None
                               and isinstance(kibana_target, dict)
                               and set(kibana_target) == {"origin", "spaces"}
                               and kibana_target.get("spaces") == ["default", "rigsignal"]
                               and isinstance(kibana_target.get("origin"), str)
                               and canonical_https_origin(kibana_target["origin"], "--kibana-endpoint")
                                   == kibana_target["origin"]
                               and isinstance(value.get("bundle_sha256"), str)
                               and _V2_SHA256_RE.fullmatch(value["bundle_sha256"]) is not None)
    except InputError:
        strict_remote_shape = False
    if not strict_remote_shape:
        return 3
    # Remote cluster and Kibana origin cannot be re-authorized at this local
    # boundary.  Reuse their recorded values solely to run the strict schema
    # validator, while pinning every locally knowable current-bundle member.
    targets = transaction_targets(bundle)
    local_binding = {
        "schema_version": V2_SCHEMA_VERSION,
        "cluster_uuid": value.get("cluster_uuid"),
        "kibana_target": value.get("kibana_target"),
        "ownership_profile": "default",
        "bundle_version": bundle.version,
        "source_commit": bundle.source_commit,
        "bundle_sha256": value.get("bundle_sha256"),
        "asset_set_sha256": _target_digest(targets),
    }
    try:
        record = validate_transaction_record(raw, local_binding, targets)
    except InputError:
        # A complete record from another release deliberately cannot validate
        # against the requested bundle binding above.  It is nevertheless a
        # valid input to the executor's explicit transition path: that path
        # rechecks version direction and the remote binding before a write.
        # Do not turn this locally recognizable predecessor into a malformed
        # record merely because its commit/archive/target digest is prior.
        if _v2_installed_valid(value, local_binding, targets, predecessor=True):
            return None
        return 3
    if record.get("possible_mutation") is True:
        return None
    # A validated predecessor is the only local shape in which direction
    # flags may be meaningful.  The executor still validates its direction
    # and all remote binding before it can mutate.
    if record.get("state") == "installing" and record.get("predecessor") is not None:
        return None
    return 2


def asset_executor_exit_code(outcome: str, record_path: Path | None = None) -> int:
    """Translate the complete asset-executor outcome domain at the CLI edge.

    Keeping this small mapping independent of transport details is deliberate:
    both main() callers must use the same process-status authority, while the
    persisted transaction record remains authoritative for the 3/4 split.
    """
    if outcome == "success":
        return 0
    if outcome == "local-input":
        return 2
    if outcome in {"refusal", "halt"}:
        return transaction_failure_status(record_path) if record_path is not None else 3
    raise InputError("asset executor outcome is invalid")


def transaction_boundary_failure(record_path: Path | None, fallback: int) -> int:
    """Make the protected record, not an incidental later exception, decide 3/4."""
    if record_path is None:
        return fallback
    status = transaction_boundary_preflight(record_path)
    return fallback if status is None else status


def _v2_common_is_valid(value: object, binding: dict, targets: list[dict[str, str]]) -> bool:
    if not isinstance(value, dict):
        return False
    expected = {**binding, "targets": targets}
    return (all(value.get(key) == item for key, item in expected.items())
            and value.get("schema_version") == 2)


def _v2_targets_valid(targets: object, expected: list[dict[str, str]]) -> bool:
    if not isinstance(targets, list) or targets != expected or len(targets) != 66:
        return False
    return all(isinstance(item, dict) and set(item) == {"digest", "key"}
               and valid_target_key(item["key"]) and isinstance(item["digest"], str)
               and _V2_SHA256_RE.fullmatch(item["digest"]) for item in targets)


def verified_target_set_digest(targets: list[dict[str, str]], obligations: object) -> str:
    """Digest the completed physical set (66 assets, plus M for full flow)."""
    verified = deepcopy(targets)
    if obligations == [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION]:
        verified.append({"key": BUNDLE_META_TARGET_KEY,
                         "digest": _target_digest(BUNDLE_META_TARGET_KEY)})
        verified.sort(key=lambda item: item["key"].encode("utf-8"))
    return _target_digest(verified)


def _v2_destination_map_valid(value: object, targets: list[dict[str, str]]) -> bool:
    """Validate persisted submitted-to-destination saved-object identities.

    A destination is deliberately retained in both active and completed
    records.  Kibana may remap an imported object; forgetting that identity at
    promotion would make the next verification guess at a physical object.
    """
    if not isinstance(value, list):
        return False
    submitted = set()
    target_keys = {item["key"] for item in targets}
    previous: bytes | None = None
    for item in value:
        if not isinstance(item, dict) or set(item) != {"destination_key", "submitted_key"}:
            return False
        source, destination = item.get("submitted_key"), item.get("destination_key")
        if (not isinstance(source, str) or not isinstance(destination, str)
                or source not in target_keys or not source.startswith("kibana/")
                or not destination.startswith("kibana/")
                or not valid_target_key(source) or not valid_target_key(destination)
                or source in submitted):
            return False
        try:
            same_identity_class = _v2_kibana_key_parts(source)[:2] == _v2_kibana_key_parts(destination)[:2]
        except InputError:
            return False
        if not same_identity_class:
            return False
        encoded = source.encode("utf-8")
        if previous is not None and encoded <= previous:
            return False
        previous = encoded
        submitted.add(source)
    return True


def _v2_kibana_key_parts(key: str) -> tuple[str, str, str]:
    """Return the validated (space, type, id) tuple for a v2 Kibana key."""
    parts = key.split("/")
    if len(parts) != 4 or parts[0] != "kibana":
        raise InputError("Kibana transaction key is invalid")
    decoded = tuple(urllib.parse.unquote(part) for part in parts[1:])
    if any(not item or _v2_quote(item) != encoded for item, encoded in zip(decoded, parts[1:])):
        raise InputError("Kibana transaction key is invalid")
    return decoded


def _v2_prior_installed_valid(value: object, binding: dict) -> bool:
    """Validate a complete prior release record used only for a transition.

    A predecessor belongs to an earlier exact bundle binding, so comparing its
    version, source commit, target digests, or archive digest to the current
    bundle would make every legitimate upgrade indistinguishable from a bad
    record.  Its own grammar and target-set digest still bind it tightly; the
    live cluster and Kibana destination remain invariant across the handoff.
    """
    if not isinstance(value, dict):
        return False
    allowed = {"asset_set_sha256", "bundle_sha256", "bundle_version", "cluster_uuid", "kibana_target",
               "ownership_profile", "schema_version", "source_commit", "state", "targets",
               "caller_obligations", "completed_at", "completed_transaction_id", "destination_map",
               "verified_target_set_sha256"}
    if set(value) != allowed:
        return False
    targets = value.get("targets")
    # A prior release may have a different inventory, but it remains a full
    # v2 installed record: exactly 66 distinct keys in their durable bytewise
    # order.  Do not weaken that grammar merely because its digests cannot be
    # compared with the current bundle.
    if (not isinstance(targets, list) or len(targets) != 66
            or targets != sorted(targets, key=lambda item: item.get("key", "").encode()
                                if isinstance(item, dict) else b"")):
        return False
    if any(not isinstance(item, dict) or set(item) != {"digest", "key"}
           or not valid_target_key(item.get("key"))
           or not isinstance(item.get("digest"), str)
           or _V2_SHA256_RE.fullmatch(item["digest"]) is None for item in targets):
        return False
    keys = [item["key"] for item in targets]
    if len(set(keys)) != len(keys):
        return False
    return (_v2_timestamp(value.get("completed_at"))
            and isinstance(value.get("completed_transaction_id"), str)
            and _V2_TRANSACTION_RE.fullmatch(value["completed_transaction_id"]) is not None
            and value.get("schema_version") == V2_SCHEMA_VERSION
            and value.get("ownership_profile") == "default"
            and value.get("state") == "installed"
            and value.get("cluster_uuid") == binding.get("cluster_uuid")
            and value.get("kibana_target") == binding.get("kibana_target")
            and isinstance(value.get("bundle_version"), str) and bool(value["bundle_version"])
            and isinstance(value.get("source_commit"), str)
            and _V2_COMMIT_RE.fullmatch(value["source_commit"]) is not None
            and isinstance(value.get("bundle_sha256"), str)
            and _V2_SHA256_RE.fullmatch(value["bundle_sha256"]) is not None
            and value.get("asset_set_sha256") == _target_digest(targets)
            and value.get("caller_obligations") in ([V2_ASSET_OBLIGATION],
                                                      [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION])
            and _v2_destination_map_valid(value.get("destination_map"), targets)
            and isinstance(value.get("verified_target_set_sha256"), str)
            and _V2_SHA256_RE.fullmatch(value["verified_target_set_sha256"]) is not None
            and value["verified_target_set_sha256"] == verified_target_set_digest(
                targets, value.get("caller_obligations")))


def _v2_installed_valid(value: object, binding: dict, targets: list[dict[str, str]], *, predecessor: bool = False) -> bool:
    if not isinstance(value, dict):
        return False
    common = {"asset_set_sha256", "bundle_sha256", "bundle_version", "cluster_uuid", "kibana_target",
              "ownership_profile", "schema_version", "source_commit", "state", "targets"}
    # T-REC-4 is the controlling erratum: installed records retain the
    # completed caller obligations even though the earlier prose omitted it.
    allowed = common | {"caller_obligations", "completed_at", "completed_transaction_id", "destination_map", "verified_target_set_sha256"}
    if set(value) != allowed:
        return False
    current_binding = (_v2_common_is_valid(value, binding, targets)
                       and _v2_targets_valid(value.get("targets"), targets))
    binding_is_valid = (_v2_prior_installed_valid(value, binding) if predecessor else current_binding)
    return (value.get("state") == "installed" and binding_is_valid and _v2_timestamp(value.get("completed_at"))
            and value.get("caller_obligations") in ([V2_ASSET_OBLIGATION], [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION])
            and _v2_destination_map_valid(value.get("destination_map"), value.get("targets") if predecessor else targets)
            and isinstance(value.get("completed_transaction_id"), str)
            and _V2_TRANSACTION_RE.fullmatch(value["completed_transaction_id"]) is not None
            and isinstance(value.get("verified_target_set_sha256"), str)
            and _V2_SHA256_RE.fullmatch(value["verified_target_set_sha256"]) is not None
            and value["verified_target_set_sha256"] == verified_target_set_digest(
                value["targets"], value.get("caller_obligations")))


def validate_transaction_record(raw: bytes, binding: dict, targets: list[dict[str, str]]) -> dict:
    """Strictly validate one byte-canonical v2 record without mutating it."""
    value = parse_json(raw, "assets transaction record")
    if jcs(value) != raw or not _v2_targets_valid(value.get("targets") if isinstance(value, dict) else None, targets):
        raise InputError("assets transaction record is invalid")
    if _v2_installed_valid(value, binding, targets):
        return value
    common = {"asset_set_sha256", "bundle_sha256", "bundle_version", "cluster_uuid", "kibana_target",
              "ownership_profile", "schema_version", "source_commit", "state", "targets"}
    required = common | {"caller_obligations", "created_at", "destination_map", "possible_mutation", "predecessor", "progress", "transaction_id"}
    if (not isinstance(value, dict) or set(value) != required
            or value.get("state") != "installing" or not _v2_common_is_valid(value, binding, targets)):
        raise InputError("assets transaction record is invalid")
    obligations = value.get("caller_obligations")
    if obligations not in ([V2_ASSET_OBLIGATION], [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION]):
        raise InputError("assets transaction record is invalid")
    keys = [item["key"] for item in targets] + ([BUNDLE_META_TARGET_KEY] if len(obligations) == 2 else [])
    progress = value.get("progress")
    if (not isinstance(progress, dict) or set(progress) != set(keys)
            or any(status not in {"planned", "write-issued", "verified"} for status in progress.values())
            or not _v2_timestamp(value.get("created_at")) or not isinstance(value.get("possible_mutation"), bool)
            or not isinstance(value.get("transaction_id"), str)
            or _V2_TRANSACTION_RE.fullmatch(value["transaction_id"]) is None):
        raise InputError("assets transaction record is invalid")
    if not _v2_destination_map_valid(value.get("destination_map"), targets):
        raise InputError("assets transaction record is invalid")
    predecessor_value = value.get("predecessor")
    if predecessor_value is not None and not _v2_installed_valid(predecessor_value, binding, targets, predecessor=True):
        raise InputError("assets transaction record is invalid")
    return value


def new_installing_record(binding: dict, targets: list[dict[str, str]], created_at: str) -> dict:
    value = {**binding, "state": "installing", "targets": deepcopy(targets), "transaction_id": str(uuid.uuid4()),
             "created_at": created_at, "predecessor": None, "caller_obligations": [V2_ASSET_OBLIGATION],
             "destination_map": [],
             "progress": {item["key"]: "planned" for item in targets}, "possible_mutation": False}
    validate_transaction_record(jcs(value), binding, targets)
    return value


def expand_full_flow_record(record: dict) -> dict:
    if record.get("state") != "installing" or record.get("caller_obligations") != [V2_ASSET_OBLIGATION]:
        raise InputError("assets transaction cannot add full-flow obligation")
    value = deepcopy(record)
    value["caller_obligations"] = [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION]
    value["progress"][BUNDLE_META_TARGET_KEY] = "planned"
    return value


def _installing_from_installed(record: dict, created_at: str) -> dict:
    """Start a fresh active transaction while retaining its exact predecessor."""
    if record.get("state") != "installed":
        raise InputError("assets transaction predecessor is not installed")
    value = {
        **{key: deepcopy(record[key]) for key in (
            "asset_set_sha256", "bundle_sha256", "bundle_version", "cluster_uuid", "kibana_target",
            "ownership_profile", "schema_version", "source_commit", "targets", "destination_map")
            if key in record},
        "state": "installing", "transaction_id": str(uuid.uuid4()), "created_at": created_at,
        "predecessor": deepcopy(record), "caller_obligations": deepcopy(record["caller_obligations"]),
        "progress": {item["key"]: "planned" for item in record["targets"]}, "possible_mutation": False,
    }
    # Installed records retain the completed obligation list, while their
    # target list deliberately contains only the 66 ordinary assets.  A
    # full-flow rerun that has to demote for a missing/drifted target must
    # restore the separately-bound Step-11 progress member as well.
    if value["caller_obligations"] == [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION]:
        value["progress"][BUNDLE_META_TARGET_KEY] = "planned"
    return value


def extend_installed_for_full_flow(record: dict, created_at: str) -> dict:
    """Durably model the assets-only-to-full-flow handoff before Step 11."""
    if record.get("state") != "installed":
        raise InputError("assets transaction is not installed")
    if record.get("caller_obligations") == [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION]:
        return deepcopy(record)
    if record.get("caller_obligations") != [V2_ASSET_OBLIGATION]:
        raise InputError("assets transaction obligations are invalid")
    value = _installing_from_installed(record, created_at)
    for key in value["progress"]:
        value["progress"][key] = "verified"
    return expand_full_flow_record(value)


def demote_installed_transaction(record: dict, created_at: str) -> dict:
    """Return the complete atomic installing shape used before any re-apply."""
    return _installing_from_installed(record, created_at)


def transition_from_prior_installed(record: dict, binding: dict, targets: list[dict[str, str]],
                                    created_at: str) -> dict:
    """Create the current release intent while retaining a validated prior S."""
    # Use the complete installed-record validator for the retained wire
    # object.  Its predecessor mode permits a changed release inventory while
    # preserving the frozen installed grammar and invariant remote binding.
    if not _v2_installed_valid(record, binding, targets, predecessor=True):
        raise InputError("assets transaction predecessor is invalid")
    value = new_installing_record(binding, targets, created_at)
    value["predecessor"] = deepcopy(record)
    if record["caller_obligations"] == [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION]:
        value = expand_full_flow_record(value)
    validate_transaction_record(jcs(value), binding, targets)
    return value


def _version_direction_is_valid(prior: str, current: str, *, upgrade: bool, allow_downgrade: bool) -> bool:
    """Compare release versions without treating a same-version digest as a transition."""
    def parts(value: str) -> tuple[object, ...]:
        return tuple(int(piece) if piece.isdecimal() else piece for piece in re.split(r"[.+-]", value))
    if prior == current or not (upgrade or allow_downgrade):
        return False
    try:
        comparison = (parts(prior) > parts(current)) - (parts(prior) < parts(current))
    except TypeError:
        # Mixed opaque prerelease spellings do not create transition authority.
        return False
    # Supplying both flags authorizes a version transition in either
    # direction, but deliberately grants no stamped-ES reconciliation
    # authority (the executor keeps that stricter XOR check below).
    if upgrade and allow_downgrade:
        return comparison != 0
    return comparison < 0 if upgrade else comparison > 0


def mark_transaction_write_issued(record: dict, target_key: str) -> dict:
    """Persist the uncertain state which must precede every transport write."""
    if record.get("state") != "installing" or record.get("progress", {}).get(target_key) not in {
            "planned", "write-issued"}:
        raise InputError("assets transaction target is not writable")
    value = deepcopy(record)
    value["progress"][target_key] = "write-issued"
    value["possible_mutation"] = True
    return value


def mark_transaction_verified(record: dict, target_key: str) -> dict:
    """Record a successful post-write or no-op verification."""
    if record.get("state") != "installing" or target_key not in record.get("progress", {}):
        raise InputError("assets transaction target is unknown")
    value = deepcopy(record)
    value["progress"][target_key] = "verified"
    return value


def promote_transaction_record(record: dict, completed_at: str) -> dict:
    if record.get("state") != "installing" or any(state != "verified" for state in record.get("progress", {}).values()):
        raise InputError("assets transaction is not fully verified")
    common = {key: deepcopy(record[key]) for key in ("asset_set_sha256", "bundle_sha256", "bundle_version", "cluster_uuid",
              "kibana_target", "ownership_profile", "schema_version", "source_commit", "targets")}
    completed = {**common, "state": "installed", "caller_obligations": deepcopy(record["caller_obligations"]),
                 "destination_map": deepcopy(record["destination_map"]),
                 "completed_transaction_id": record["transaction_id"], "completed_at": completed_at,
                 "verified_target_set_sha256": verified_target_set_digest(
                     record["targets"], record["caller_obligations"])}
    return completed


def default_bundle_meta_body(targets: list[dict[str, str]], version: str, source_commit: str, timestamp: str) -> bytes:
    return jcs({"_meta": {"asset_set": targets, "bundle_version": version,
                            "managed_by": RIGSIGNAL_MANAGED_BY, "ownership_profile": "default",
                            "source_commit": source_commit, "timestamp": timestamp}, "template": {}})


@dataclass
class BundleSnapshot:
    path: Path
    sha256: str

    def close(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def snapshot_bundle(bundle_path: Path, directory: Path, *, parse: bool = True) -> BundleSnapshot:
    """Copy a single no-follow opened archive to a private fsynced snapshot."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_fd: int | None = None
    fd: int | None = None
    temporary: str | None = None
    try:
        source_fd = os.open(bundle_path, flags)
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise InputError("bundle is not a regular file")
        fd, temporary = tempfile.mkstemp(prefix=".rigsignal-archive-", dir=directory)
    except (OSError, InputError) as error:
        for descriptor in (source_fd, fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise InputError("cannot snapshot bundle") from error
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(source_fd, "rb", closefd=True) as source, os.fdopen(fd, "wb", closefd=True) as output:
            source_fd = fd = None
            while chunk := source.read(1024 * 1024):
                output.write(chunk)
            output.flush(); os.fsync(output.fileno())
        fault("snapshot-after-copy-fsync")
        # ERRATA-1: bind the exact protected, fsynced snapshot bytes, rather
        # than the mutable source stream we happened to copy from.
        with open(temporary, "rb") as snapshot_handle:
            digest = hashlib.sha256()
            while chunk := snapshot_handle.read(1024 * 1024):
                digest.update(chunk)
        snapshot = BundleSnapshot(Path(temporary), digest.hexdigest())
        if parse:
            fault("snapshot-before-parse")
            load_bundle(snapshot.path)
        return snapshot
    except Exception:
        fault("snapshot-before-cleanup")
        for descriptor in (source_fd, fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        try: os.unlink(temporary)
        except (OSError, TypeError): pass
        raise


def cleanup_snapshot_residue(directory: Path, name: str) -> None:
    if not name.startswith(".rigsignal-") or "/" in name:
        raise InputError("snapshot residue is invalid")
    path = directory / name
    try: st = path.lstat()
    except FileNotFoundError: return
    if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077):
        raise InputError("snapshot residue is unsafe")
    fault("snapshot-residue-before-cleanup", name)
    path.unlink()


def cleanup_snapshot_residues(directory: Path) -> None:
    """Remove only validated private snapshot residue before a new snapshot."""
    try:
        names = [entry.name for entry in directory.iterdir() if entry.name.startswith(".rigsignal-")]
    except OSError as error:
        raise InputError("cannot inspect snapshot residue") from error
    for name in names:
        cleanup_snapshot_residue(directory, name)


def transaction_snapshot_directory(marker_path: Path | None) -> Path:
    """Prepare the protected record directory before opening a release bundle."""
    selected = marker_path or _asset_marker_default_path()
    if selected.name != ASSETS_MARKER_FILE:
        raise InputError("assets marker path is invalid")
    if marker_path is not None:
        return secure_root(selected.parent)
    shared = selected.parent.parent
    _reject_symlinked_path(shared)
    shared.mkdir(mode=0o755, parents=True, exist_ok=True)
    _validate_assets_marker_shared_parent(shared)
    return secure_root(selected.parent)


def read_transaction_record_if_present(path: Path, binding: dict | None, targets: list[dict[str, str]] | None) -> dict | None:
    _validate_transaction_record_parent(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise InputError("assets transaction record is unavailable") from error
    if binding is None or targets is None: raise InputError("transaction binding is required")
    return validate_transaction_record(protected_regular_file(path), binding, targets)


def read_prior_installed_record_if_present(path: Path, binding: dict | None) -> dict | None:
    """Read only a structurally complete previous-release record for transition."""
    _validate_transaction_record_parent(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise InputError("assets transaction record is unavailable") from error
    if binding is None:
        raise InputError("transaction binding is required")
    raw = protected_regular_file(path)
    value = parse_json(raw, "assets transaction record")
    if jcs(value) != raw or not _v2_prior_installed_valid(value, binding):
        raise InputError("assets transaction record is invalid")
    return value


def write_transaction_record(path: Path, record: dict, binding: dict, targets: list[dict[str, str]]) -> None:
    """Atomically publish only a fully validated, byte-canonical v2 record."""
    _validate_transaction_record_parent(path)
    raw = jcs(record)
    validate_transaction_record(raw, binding, targets)
    expected_prior: bytes | None = protected_regular_file(path) if path.exists() else None
    atomic_write(path.parent, path.name, raw, expected_prior=expected_prior)
    # Read-back is part of the durable transition boundary: callers must not
    # continue to a remote write from an unverifiable local intent.
    if protected_regular_file(path) != raw:
        raise InputError("assets transaction record verification failed")


def _read_private_v1_marker(path: Path, bundle: Bundle) -> bool:
    """Recognize only the former private v1 ownership marker.

    This reader is intentionally isolated from the old planner: it accepts no
    partial state and cannot create an active transaction.  A legacy marker in
    the old shared location is rejected by ``_prepare_assets_marker_path``;
    this is only the protected primary leaf migration described in §3.6.
    """
    value = parse_json(protected_regular_file(path), "assets transaction record")
    if (not isinstance(value, dict)
            or set(value) != {"schema_version", "bundle_version", "source_commit", "identities"}
            or value.get("schema_version") != ASSETS_MARKER_SCHEMA_VERSION
            or value.get("bundle_version") != bundle.version
            or value.get("source_commit") != bundle.source_commit
            or not isinstance(value.get("identities"), list)):
        return False
    expected = _asset_marker_identities(bundle)
    if any(not isinstance(item, dict) for item in value["identities"]):
        return False
    return value["identities"] == expected and len({(item["kind"], item["name"])
                                                     for item in value["identities"]}) == len(expected)


def _migrate_private_v1_record(path: Path, bundle: Bundle, binding: dict, targets: list[dict[str, str]],
                               es_url: str, kb_url: str, authorization: str, adapter: "SavedObjectAdapter",
                               *, full_flow: bool) -> dict:
    """Verify a current private v1 marker then replace it with installed v2.

    The operation is deliberately all-read until the final local replacement.
    A mismatch, ambiguity, or incomplete object set is refusal rather than an
    opportunity to repair a record whose former ownership semantics were less
    strict.
    """
    if not _read_private_v1_marker(path, bundle):
        raise AssetTransactionRefusal("assets transaction legacy record is invalid")
    record = new_installing_record(binding, targets, _transaction_now())
    if full_flow:
        record = expand_full_flow_record(record)
    for spec in _transaction_specs(bundle, full_flow):
        state, _live, _destination = _transaction_observe(es_url, kb_url, authorization, spec, bundle, adapter, record)
        if state != "exact":
            raise AssetTransactionRefusal("assets transaction legacy record is not exact")
        record = mark_transaction_verified(record, spec[0])
    migrated = promote_transaction_record(record, _transaction_now())
    fault("before-v1-v2-publication")
    write_transaction_record(path, migrated, binding, targets)
    fault("after-v1-v2-publication")
    return migrated


# The v2 executor deliberately lives beside the record implementation rather
# than the old ownership-marker planner below.  The latter is retained for the
# Fleet-coexist journal path; default-profile callers use this object-granular
# engine.  In particular, no caller is allowed to turn a dashboard file into a
# single all-or-nothing mutation: saved objects are individual targets.
class AssetTransactionRefusal(InputError):
    """A v2 remote observation was not an unambiguous safe write boundary."""


class AssetTransactionHalt(ProvisionError):
    """A write was issued and a detector/final verification made it unsafe."""


def _transaction_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _transaction_key_for_asset(asset: Asset) -> str:
    kinds = {"component_templates": "component-template", "index_templates": "index-template",
             "pipelines": "ingest-pipeline", "security_roles": "security-role", "transforms": "transform"}
    if asset.kind not in kinds:
        raise InputError("asset is not an ES transaction target")
    return "es/" + kinds[asset.kind] + "/" + _v2_quote(asset.name)


def _transaction_specs(bundle: Bundle, include_meta: bool = False) -> list[tuple[str, Asset | None, dict | None]]:
    """Return the complete ordered physical target map used by the v2 engine."""
    specs: dict[str, tuple[str, Asset | None, dict | None]] = {}

    def add(spec: tuple[str, Asset | None, dict | None]) -> None:
        # Source dashboard files may repeat an already-expanded saved-object
        # identity.  It is one physical target (and one record-progress
        # member), so every barrier and final reverify must retain one entry.
        specs.setdefault(spec[0], spec)

    for asset in bundle.assets:
        if asset.kind in _ES_ASSET_KINDS:
            add((_transaction_key_for_asset(asset), asset, None))
        elif asset.kind == "kibana_spaces":
            add(("kibana/rigsignal/space/" + _v2_quote(asset.name), asset, None))
        elif asset.kind == "kibana_roles":
            add(("kibana/default/role/" + _v2_quote(asset.name), asset, None))
        elif asset.kind == "dashboard":
            space = dashboard_target_space(asset)
            for line in asset.data.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                saved = parse_json(line.encode("utf-8"), asset.path)
                if not isinstance(saved, dict) or not isinstance(saved.get("type"), str) or not isinstance(saved.get("id"), str):
                    raise InputError("dashboard object is invalid")
                add(("kibana/" + _v2_quote(space) + "/" + _v2_quote(saved["type"]) + "/" + _v2_quote(saved["id"]), asset, saved))
    if include_meta:
        add((BUNDLE_META_TARGET_KEY, None, None))
    return sorted(specs.values(), key=lambda item: item[0].encode("utf-8"))


def _saved_object_projection(space: str, object_type: str, response: object) -> object:
    if not isinstance(response, dict) or not isinstance(response.get("attributes"), dict):
        raise AssetTransactionRefusal("saved-object response is ambiguous")
    return {"space": space, "type": object_type, "attributes": response["attributes"],
            "references": response.get("references", [])}


class SavedObjectAdapter:
    """The sole deprecated saved-object CRUD boundary used by v2.

    Keeping resolution, semantic projection and destination persistence here
    prevents direct endpoint calls from accidentally treating IDs as stable.
    """
    def __init__(self, kb_url: str, authorization: str):
        self.kb_url, self.authorization = kb_url, authorization

    @staticmethod
    def _path(space: str, object_type: str, object_id: str) -> str:
        return space_prefix(space) + "/api/saved_objects/" + urllib.parse.quote(object_type, safe="") + "/" + urllib.parse.quote(object_id, safe="")

    def observe(self, space: str, object_type: str, object_id: str,
                destination_id: str | None = None) -> tuple[str, object | None, str]:
        """GET and resolve a submitted identity, retaining an explicit remap.

        A mapping is never guessed from a response body.  If resolve names an
        alias target we read that physical target and make it the only identity
        returned to the transaction record.
        """
        requested = destination_id or object_id
        path = self._path(space, object_type, requested)
        missing_submitted = False
        try:
            response = json_response(request(self.kb_url, path, "GET", self.authorization,
                                             headers={"kbn-xsrf": "true"}))
        except RequestFailure as error:
            if error.status == 404:
                if destination_id is not None:
                    raise AssetTransactionRefusal("saved-object destination is absent") from error
                # A response-loss create may have been remapped.  Resolve the
                # submitted identity before it is ever classified as absent.
                missing_submitted = True
                response = None
            else:
                raise AssetTransactionRefusal("saved-object read refused") from error
        # Resolve is a verification read too.  It is required for the alias /
        # destinationId path, but a normal literal GET remains compatible with
        # servers which reply 404 for resolve of a non-aliased object.
        resolved_id = requested
        try:
            resolved = json_response(request(
                self.kb_url, space_prefix(space) + "/api/saved_objects/resolve/" +
                urllib.parse.quote(object_type, safe="") + "/" + urllib.parse.quote(requested, safe=""),
                "GET", self.authorization, headers={"kbn-xsrf": "true"}))
        except RequestFailure as error:
            if error.status != 404:
                raise AssetTransactionRefusal("saved-object resolve refused") from error
        else:
            if not isinstance(resolved, dict):
                raise AssetTransactionRefusal("saved-object resolve is ambiguous")
            candidate = resolved.get("alias_target_id") or resolved.get("destinationId")
            nested = resolved.get("saved_object")
            if candidate is not None:
                if not isinstance(candidate, str) or not candidate:
                    raise AssetTransactionRefusal("saved-object destination is ambiguous")
                resolved_id = candidate
                if candidate != requested:
                    try:
                        response = json_response(request(self.kb_url, self._path(space, object_type, candidate),
                                                         "GET", self.authorization, headers={"kbn-xsrf": "true"}))
                    except RequestFailure as error:
                        raise AssetTransactionRefusal("saved-object destination read refused") from error
            elif nested is not None:
                if not isinstance(nested, dict):
                    raise AssetTransactionRefusal("saved-object resolve is ambiguous")
                response = nested
        if response is None:
            if missing_submitted:
                return "absent", None, object_id
            raise AssetTransactionRefusal("saved-object response is ambiguous")
        return "present", _saved_object_projection(space, object_type, response), resolved_id

    def create(self, space: str, object_type: str, object_id: str, desired: dict) -> str:
        body = jcs({"attributes": desired["attributes"], "references": desired["references"]})
        try:
            mark_mutation_issued()
            _status, response = request_response(self.kb_url, self._path(space, object_type, object_id) + "?overwrite=false",
                                                 "POST", self.authorization, body, {"kbn-xsrf": "true"})
        except RequestFailure as error:
            if error.status != 409:
                raise AssetTransactionRefusal("saved-object create refused") from error
            return object_id
        try:
            value = json_response(response)
        except InputError as error:
            raise AssetTransactionRefusal("saved-object create response is ambiguous") from error
        destination = value.get("destinationId") if isinstance(value, dict) else None
        if destination is None:
            destination = value.get("id") if isinstance(value, dict) else None
        if destination is not None and (not isinstance(destination, str) or not destination):
            raise AssetTransactionRefusal("saved-object destination is ambiguous")
        return destination or object_id


def _transaction_diagnostic(record_path: Path, record: dict, *, target: str, nonce: str,
                            detector: str, observed: object) -> None:
    """Persist detector evidence without weakening the strict record grammar."""
    # This is deliberately a sibling, rather than an extension of the v2
    # record grammar.  Validate the same parent immediately before publishing
    # it: a detector must not turn a path substitution into a diagnostic write.
    _validate_transaction_record_parent(record_path)
    def safe_scalar(value: object) -> object:
        if value is None or isinstance(value, (bool, int, float)):
            return value
        # Remote strings and aggregate response values are deliberately not
        # evidence payloads: they can contain credentials or origins.
        return "<redacted>"
    if not isinstance(target, str) or not isinstance(nonce, str) or not isinstance(detector, str):
        raise InputError("assets transaction diagnostic is invalid")
    safe = {"transaction": "<redacted>", "target": target, "nonce": nonce,
            "detector": detector, "observed": safe_scalar(observed)}
    if detector == "created<modified" and isinstance(observed, dict):
        # Keep timestamp evidence useful without admitting an arbitrary remote
        # response object into the local protected diagnostic.
        safe["observed_created_millis"] = safe_scalar(observed.get("created"))
        safe["observed_modified_millis"] = safe_scalar(observed.get("modified"))
    diagnostic = record_path.parent / (record_path.name + ".diagnostic.json")
    expected_prior: bytes | None = protected_regular_file(diagnostic) if diagnostic.exists() else None
    atomic_write(record_path.parent, diagnostic.name, jcs(safe), expected_prior=expected_prior)


def _transaction_diagnostic_preflight(record_path: Path) -> None:
    """Reject an unsafe diagnostic sibling before an unconditional API PUT."""
    _validate_transaction_record_parent(record_path)
    diagnostic = record_path.parent / (record_path.name + ".diagnostic.json")
    if not diagnostic.exists():
        return
    try:
        protected_regular_file(diagnostic)
    except FileNotFoundError:
        return


def _validate_transaction_record_parent(record_path: Path) -> None:
    """Apply the record's protected-directory preflight to its diagnostics."""
    if record_path.name != ASSETS_MARKER_FILE:
        raise InputError("assets transaction record path is invalid")
    secure_root(record_path.parent)
    # Default state storage has a shared state-home parent which must retain
    # the same protection checks used by the marker preflight.
    if record_path.parent.name == "assets":
        _validate_assets_marker_shared_parent(record_path.parent.parent)


def _transaction_es_observe(es_url: str, authorization: str, asset: Asset, desired: Asset) -> tuple[str, object | None]:
    try:
        response = json_response(request(es_url, es_path(asset), "GET", authorization))
    except RequestFailure as error:
        if error.status == 404:
            return "absent", None
        raise AssetTransactionRefusal("ES target read refused") from error
    try:
        live = asset_adapters.get_projection(asset.kind, response)
        wanted = asset_adapters.get_projection(asset.kind, parse_json(desired.data, desired.path))
    except (asset_adapters.AdapterError, InputError) as error:
        raise AssetTransactionRefusal("ES target response is ambiguous") from error
    # A nonce is required in the immediate post-write desired projection, but
    # an installed record deliberately does not retain a transaction UUID.
    # Later ordinary verification therefore recognizes the installer-only
    # nonce as transport metadata, never as ownership or semantic drift.
    if isinstance(live, dict) and isinstance(wanted, dict):
        meta_key = "metadata" if asset.kind == "security_roles" else "_meta"
        if meta_key not in wanted and isinstance(live.get(meta_key), dict):
            live = deepcopy(live); live[meta_key].pop("controller_nonce", None)
        elif (isinstance(live.get(meta_key), dict) and isinstance(wanted.get(meta_key), dict)
              and "controller_nonce" not in wanted[meta_key]):
            live = deepcopy(live); live[meta_key].pop("controller_nonce", None)
    if jcs(live) == jcs(wanted):
        return "exact", response
    if _es_object_is_owned(response, asset):
        return "owned-divergent", response
    return "divergent", response


def _transaction_kibana_observe(adapter: SavedObjectAdapter, asset: Asset, saved: dict,
                                record: dict | None = None) -> tuple[str, object | None, str]:
    space, typ, ident = dashboard_target_space(asset), saved["type"], saved["id"]
    submitted_key = "kibana/" + _v2_quote(space) + "/" + _v2_quote(typ) + "/" + _v2_quote(ident)
    mapped = next((item["destination_key"] for item in (record or {}).get("destination_map", [])
                   if item["submitted_key"] == submitted_key), None)
    destination_id = _v2_kibana_key_parts(mapped)[2] if mapped else None
    state, live, destination = adapter.observe(space, typ, ident, destination_id)
    if state == "absent":
        return state, None, destination
    remaps = {item["submitted_key"]: item["destination_key"] for item in (record or {}).get("destination_map", [])}
    references = []
    for reference in saved.get("references", []):
        if not isinstance(reference, dict):
            raise AssetTransactionRefusal("saved-object reference is ambiguous")
        item = deepcopy(reference)
        ref_type, ref_id = item.get("type"), item.get("id")
        if isinstance(ref_type, str) and isinstance(ref_id, str):
            ref_key = "kibana/" + _v2_quote(space) + "/" + _v2_quote(ref_type) + "/" + _v2_quote(ref_id)
            if ref_key in remaps:
                item["id"] = _v2_kibana_key_parts(remaps[ref_key])[2]
        references.append(item)
    desired = {"space": space, "type": typ, "attributes": saved.get("attributes", {}),
               "references": references}
    return ("exact" if jcs(live) == jcs(desired) else "divergent"), live, destination


def _transaction_bundle_meta_asset(bundle: Bundle, record: dict) -> Asset:
    # ``created_at`` binds an active write intent.  Promotion deliberately
    # removes that transient field, but a completed full-flow obligation still
    # has to re-observe (and, if absent, recreate) its Step-11 marker.
    # ``completed_at`` is the durable timestamp available to that installed
    # record until a missing target demotes it into a fresh intent.
    timestamp = record.get("created_at", record.get("completed_at"))
    if not isinstance(timestamp, str):
        raise InputError("bundle-meta has no durable transaction timestamp")
    return Asset("component_templates", "rigsignal-bundle-meta", "v2 bundle-meta",
                 default_bundle_meta_body(transaction_targets(bundle), bundle.version,
                                          bundle.source_commit, timestamp))


def _installed_bundle_meta_matches(live: object, marker: Asset) -> bool:
    """Compare an installed Step-11 marker without inventing its old intent time.

    The marker timestamp documents the intent that wrote it, and is not a
    release-asset semantic.  Installed v2 records intentionally retain no
    ``created_at``, so a rerun cannot reconstruct that historical value.  Its
    stable binding fields remain exact, while requiring a scalar timestamp
    prevents a missing or malformed marker field from being accepted.
    """
    try:
        actual = asset_adapters.get_projection("component_templates", live)
        expected = asset_adapters.get_projection(
            "component_templates", parse_json(marker.data, marker.path))
    except (asset_adapters.AdapterError, InputError):
        return False
    if not isinstance(actual, dict) or not isinstance(expected, dict):
        return False
    actual_meta, expected_meta = actual.get("_meta"), expected.get("_meta")
    if (not isinstance(actual_meta, dict) or not isinstance(expected_meta, dict)
            or not isinstance(actual_meta.get("timestamp"), str)):
        return False
    actual = deepcopy(actual); expected = deepcopy(expected)
    actual["_meta"].pop("timestamp", None)
    expected["_meta"].pop("timestamp", None)
    return jcs(actual) == jcs(expected)


def _transaction_observe(es_url: str, kb_url: str, authorization: str, spec: tuple[str, Asset | None, dict | None],
                         bundle: Bundle, adapter: SavedObjectAdapter,
                         record: dict | None = None, desired_override: Asset | None = None) -> tuple[str, object | None, str | None]:
    key, asset, saved = spec
    if key == BUNDLE_META_TARGET_KEY:
        if record is None:
            raise AssetTransactionRefusal("bundle-meta has no transaction binding")
        marker = _transaction_bundle_meta_asset(bundle, record)
        state, live = _transaction_es_observe(es_url, authorization, marker, marker)
        if (state == "owned-divergent" and record.get("state") == "installed"
                and _installed_bundle_meta_matches(live, marker)):
            return "exact", live, None
        return state, live, None
    assert asset is not None
    if saved is not None:
        state, live, destination = _transaction_kibana_observe(adapter, asset, saved, record)
        return state, live, destination
    if asset.kind in _ES_ASSET_KINDS:
        state, live = _transaction_es_observe(es_url, authorization, asset, desired_override or stamped_asset(asset))
        return state, live, None
    try:
        response = json_response(request(kb_url, kibana_path(asset), "GET", authorization, headers={"kbn-xsrf": "true"}))
    except RequestFailure as error:
        if error.status == 404:
            return "absent", None, None
        raise AssetTransactionRefusal("Kibana target read refused") from error
    try:
        if asset.kind == "kibana_spaces":
            exact = jcs(asset_adapters.get_projection(asset.kind, response)) == jcs(asset_adapters.get_projection(asset.kind, parse_json(asset.data, asset.path)))
        else:
            # Kibana role endpoint projection is owned by asset_adapters too.
            exact = jcs(asset_adapters.get_projection(asset.kind, response)) == jcs(asset_adapters.get_projection(asset.kind, parse_json(asset.data, asset.path)))
    except (asset_adapters.AdapterError, InputError) as error:
        raise AssetTransactionRefusal("Kibana target response is ambiguous") from error
    return ("exact" if exact else "divergent"), response, None


def _transaction_put(es_url: str, kb_url: str, authorization: str, spec: tuple[str, Asset | None, dict | None],
                     bundle: Bundle, record: dict, adapter: SavedObjectAdapter, *, live: object | None = None,
                     state: str = "absent") -> Asset | None:
    """Perform exactly one class-specific guarded mutation after write-issued."""
    key, asset, saved = spec
    live = record.get("_observed_live") if live is None else live
    state = record.get("_observed_state", state)
    if saved is not None:
        space = dashboard_target_space(asset)
        remaps = {item["submitted_key"]: item["destination_key"] for item in record.get("destination_map", [])}
        references = []
        for reference in saved.get("references", []):
            item = deepcopy(reference)
            if isinstance(item, dict) and isinstance(item.get("type"), str) and isinstance(item.get("id"), str):
                ref_key = "kibana/" + _v2_quote(space) + "/" + _v2_quote(item["type"]) + "/" + _v2_quote(item["id"])
                if ref_key in remaps:
                    item["id"] = _v2_kibana_key_parts(remaps[ref_key])[2]
            references.append(item)
        adapter.create(space, saved["type"], saved["id"],
                       {"attributes": saved.get("attributes", {}), "references": references})
        return None
    if key == BUNDLE_META_TARGET_KEY:
        marker = _transaction_bundle_meta_asset(bundle, record)
        suffix = "?create=true" if state == "absent" else ""
        mutation_request(es_url, "/_component_template/rigsignal-bundle-meta" + suffix, "PUT", authorization, marker.data)
        return None
    assert asset is not None
    if asset.kind == "kibana_spaces":
        mutation_request(kb_url, "/api/spaces/space", "POST", authorization, asset.data, {"kbn-xsrf": "true"})
        return None
    if asset.kind == "kibana_roles":
        suffix = "?createOnly=true" if state == "absent" else ""
        mutation_request(kb_url, kibana_path(asset) + suffix, "PUT", authorization, asset.data, {"kbn-xsrf": "true"})
        return None
    desired = stamped_asset(asset)
    if asset.kind in {"component_templates", "index_templates"}:
        suffix = "?create=true" if state == "absent" else ""
        mutation_request(es_url, es_path(asset) + suffix, "PUT", authorization, desired.data)
        return None
    if asset.kind == "transforms":
        # PUT /_transform/{id} is inherently create-only (409 on an existing
        # id) and accepts no ?create parameter — live-caught on real 9.4.4.
        mutation_request(es_url, es_path(asset), "PUT", authorization, desired.data)
        return None
    nonce = transaction_detector_nonce(record["transaction_id"], key)
    body = parse_json(desired.data, desired.path)
    metadata = "metadata" if asset.kind == "security_roles" else "_meta"
    body[metadata] = {**body.get(metadata, {}), "controller_nonce": nonce}
    try:
        raw_live = asset_adapters.body_from_envelope(asset.kind, live) if live is not None else {}
    except asset_adapters.AdapterError as error:
        raise AssetTransactionRefusal("ES target response is ambiguous") from error
    version = raw_live.get("version") if isinstance(raw_live, dict) else None
    suffix = "?if_version=" + urllib.parse.quote(str(version), safe="") if version is not None else ""
    effective = Asset(asset.kind, asset.name, asset.path, jcs(body))
    response = mutation_request(es_url, es_path(asset) + suffix, "PUT", authorization, effective.data)
    if state == "absent" and asset.kind == "security_roles":
        try:
            parsed = json_response(response)
            created = parsed.get("role", {}).get("created") if isinstance(parsed, dict) else None
        except InputError:
            created = None
        if created is not True:
            _transaction_diagnostic(record_path=Path(record["_record_path"]), record=record, target=key,
                                    nonce=nonce, detector="created:false", observed=created)
            raise AssetTransactionHalt("partial-remote-possible")
    elif state == "absent":  # pipeline detector is checked only after the response.
        state, live = _transaction_es_observe(es_url, authorization, asset, Asset(asset.kind, asset.name, asset.path, jcs(body)))
        # The normal semantic projection intentionally drops timestamps.  The
        # detector is the narrowly-scoped exception and must inspect the raw
        # single-pipeline GET body before that projection removes them.
        raw_live = asset_adapters.body_from_envelope(asset.kind, live) if live is not None else {}
        created = raw_live.get("created_date_millis") if isinstance(raw_live, dict) else None
        modified = raw_live.get("modified_date_millis") if isinstance(raw_live, dict) else None
        if created is None or modified is None or created != modified:
            _transaction_diagnostic(record_path=Path(record["_record_path"]), record=record, target=key,
                                    nonce=nonce, detector="created<modified", observed={"created": created, "modified": modified})
            raise AssetTransactionHalt("partial-remote-possible")
    return effective


def _transaction_create_conflict(spec: tuple[str, Asset | None, dict | None], error: RequestFailure,
                                 state: str) -> bool:
    """Recognize only the documented create-race statuses for v2 targets."""
    if state != "absent":
        return False
    key, asset, _saved = spec
    if key == BUNDLE_META_TARGET_KEY:
        return error.status == 400
    if asset is None:
        return False
    if asset.kind in {"component_templates", "index_templates"}:
        return error.status == 400
    if asset.kind == "transforms":
        return error.status == 409
    if asset.kind in {"kibana_spaces", "kibana_roles"}:
        return error.status == 409
    return False


def _persist_destination_mapping(record: dict, key: str, destination: str) -> bool:
    """Store a resolved physical identity before claiming the target exact."""
    space, object_type, submitted_id = _v2_kibana_key_parts(key)
    if destination == submitted_id:
        return False
    destination_key = "kibana/" + _v2_quote(space) + "/" + _v2_quote(object_type) + "/" + _v2_quote(destination)
    # Validate before retaining any response-derived identifier.  This also
    # guards the reference rewrite path from a malformed resolver response.
    _v2_kibana_key_parts(destination_key)
    mapping = {"submitted_key": key, "destination_key": destination_key}
    updated = [item for item in record["destination_map"] if item["submitted_key"] != key] + [mapping]
    updated.sort(key=lambda item: item["submitted_key"].encode())
    if updated == record["destination_map"]:
        return False
    record["destination_map"] = updated
    return True


def transaction_detector_nonce(transaction_id: str, target_key: str) -> str:
    """Derive the detector nonce without extending the v2 record schema.

    Owner ratification 6 (TEST-MANIFEST residual entry 6, 2026-08-04)
    preserves the qualified ES-update race as a named residual; it does not
    authorize another durable record field.  The per-target nonce is therefore
    the deterministic SHA-256 of the canonical transaction UUID, a NUL
    separator, and the canonical target key.  AMBIGUITY-4 keeps observed
    detector values in the protected sibling diagnostic instead of the record.
    """
    if not isinstance(transaction_id, str) or _V2_TRANSACTION_RE.fullmatch(transaction_id) is None:
        raise InputError("assets transaction nonce binding is invalid")
    if not isinstance(target_key, str) or not target_key:
        raise InputError("assets transaction nonce target is invalid")
    return hashlib.sha256((transaction_id + "\0" + target_key).encode("utf-8")).hexdigest()


def run_default_asset_transaction(bundle: Bundle, es_url: str, kb_url: str, authorization: str, record_path: Path,
                                  binding: dict, *, full_flow: bool = False,
                                  repair: bool = False, upgrade: bool = False,
                                  allow_downgrade: bool = False, defer_step_11: bool = False,
                                  step_11_only: bool = False,
                                  unsafe_test_injection: bool = False,
                                  lock: "AssetTransactionLock | None" = None) -> str:
    """Execute the v2 default-profile asset transaction under its global lock.

    The caller supplies the already snapshotted archive binding; this is what
    keeps a resume tied to the exact opened bundle bytes rather than a pathname.
    """
    _validate_transaction_record_parent(record_path)
    targets = transaction_targets(bundle)
    adapter = SavedObjectAdapter(kb_url, authorization)
    owned_lock = lock is None
    lock = lock or AssetTransactionLock.acquire()
    try:
        prior_installed = False
        try:
            record = read_transaction_record_if_present(record_path, binding, targets)
        except InputError as current_error:
            # A complete older release is not a malformed current record.  It
            # can be consumed only by an explicit direction flag below; all
            # other non-current shapes retain the established v1/invalid
            # refusal behavior.
            try:
                record = read_prior_installed_record_if_present(record_path, binding)
                prior_installed = record is not None
            except InputError:
                record = None
            # A v1 marker is the sole non-v2 primary that can be consumed.
            # Its reader and verification pass are intentionally isolated;
            # malformed v1/v2 inputs remain untouched refusals.
            if record is None:
                if not _read_private_v1_marker(record_path, bundle):
                    raise current_error
                record = _migrate_private_v1_record(record_path, bundle, binding, targets,
                                                    es_url, kb_url, authorization, adapter,
                                                    full_flow=full_flow)
        # The initial no-record barrier is the one case where a stamped ES
        # divergence is a create-time reconciliation.  On a resumed/current
        # transaction it is a refusal until ``--repair`` is explicit.  This
        # is the engine counterpart of corrected table rows such as
        # I-assets-pm0/es-stamped-divergent/none (T-FLAG-3).
        started_without_record = record is None
        # Owner ratification 2 is absolute (T-EXIT-1): a persisted possible
        # mutation is never under-reported, even when the current command has
        # invalid flags or another local preflight refusal.  This is still
        # pre-read: no remote operation has happened in this invocation.
        # A durable write-issued edge is uncertain, not terminal.  Every
        # target is re-observed below and the record is promoted only after a
        # complete fresh verification pass (T-HASH-5/T-SM-7/8/9/T-DASH-3/T-GATE-3).
        reconciling_uncertainty = bool(record is not None and record.get("state") == "installing"
                                       and record.get("possible_mutation") is True)
        # Recovery re-observes first; it never lets a newly supplied flag turn
        # a persisted unknown outcome into a local-input escape hatch.
        version_flags = (upgrade or allow_downgrade) and not reconciling_uncertainty
        transition_pending = False
        if prior_installed:
            if not version_flags:
                raise AssetTransactionRefusal("assets transaction transition requires a direction flag")
            if not _version_direction_is_valid(record["bundle_version"], binding["bundle_version"],
                                               upgrade=upgrade, allow_downgrade=allow_downgrade):
                raise InputError("assets transaction version direction is invalid")
            # Keep the old S authoritative until a current write is needed or
            # the whole current verification pass succeeds.  This prevents an
            # unrelated later refusal from consuming a prior release record.
            record = transition_from_prior_installed(record, binding, targets, _transaction_now())
            transition_pending = True
        has_valid_predecessor = (record is not None and record.get("state") == "installing"
                                 and record.get("predecessor") is not None
                                 and record["predecessor"].get("bundle_version") != binding["bundle_version"])
        # Owner-ratified direction flags are meaningful only with a durable
        # predecessor.  The table deliberately permits both flags to reach
        # target classification; that combination simply has no stamped-ES
        # reconciliation authority.
        if version_flags and not has_valid_predecessor:
            raise InputError("assets transaction version flags require a validated predecessor")
        if has_valid_predecessor and not version_flags:
            raise AssetTransactionRefusal("assets transaction transition requires a direction flag")
        # Do not turn a complete assets-only record into a new installing
        # record until the full-flow observation barrier has passed.
        defer_full_flow_extension = False
        defer_installed_full_flow_extension = False
        if record is None:
            # A new transaction has no pre-existing remote authority.  Finish
            # the complete no-write observation barrier before publishing
            # intent or creating anything: a foreign/divergent target anywhere
            # in the release must not leave an earlier target newly created.
            record = new_installing_record(binding, targets, _transaction_now())
            if full_flow:
                # §3.4: the fresh full-flow intent contains M before the
                # first ordinary asset mutation; its PUT itself is deferred to
                # the real Step 11 site by the full-flow caller.
                record = expand_full_flow_record(record)
            # The fresh full-flow barrier includes M before publishing I.
            # Thus neither an ordinary nor Step-11 refusal can establish a
            # durable partial intent, let alone precede a remote write.
            # Dispatch may defer M to Step 11, but the full-flow observation
            # barrier never does: a marker refusal must precede every ordinary
            # asset and enrollment mutation.
            for barrier_spec in _transaction_specs(bundle, full_flow):
                barrier_state, _barrier_live, _barrier_destination = _transaction_observe(
                    es_url, kb_url, authorization, barrier_spec, bundle, adapter, record)
                if barrier_state == "divergent":
                    if barrier_spec[0].startswith("kibana/"):
                        raise AssetTransactionRefusal("Kibana target differs")
                    raise AssetTransactionRefusal("asset target differs")
                if barrier_state == "owned-divergent" and barrier_spec[0].startswith("kibana/"):
                    raise AssetTransactionRefusal("Kibana target differs")
            write_transaction_record(record_path, record, binding, targets)
            fault("after-v2-intent-publication")
        elif record["state"] == "installed":
            if full_flow and record["caller_obligations"] == [V2_ASSET_OBLIGATION]:
                defer_installed_full_flow_extension = True
            elif not full_flow and record["caller_obligations"] == [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION]:
                # Assets-only may validate but must never complete the missing
                # Step-11 obligation.
                return "noop"
            # A complete installed record stays installed while we reread it.
            # It is atomically demoted only when a missing target actually
            # needs a create-only write (T-SM-3), never merely because a
            # caller has begun a no-op verification pass.
        elif full_flow and record["caller_obligations"] == [V2_ASSET_OBLIGATION]:
            # A resumed assets-only intent earns the Step-11 obligation only
            # after the full-flow zero-write barrier below.  Otherwise a later
            # foreign target could turn a read-only refusal into durable
            # full-flow intent without reaching Step 11.
            defer_full_flow_extension = True
        elif (not full_flow and record["caller_obligations"] ==
              [V2_ASSET_OBLIGATION, V2_FULL_FLOW_OBLIGATION]):
            # T-SM-5/6: this caller cannot discharge Step 11, even if every
            # ordinary target happens to be exact.  Never silently promote.
            if not transition_pending:
                raise AssetTransactionHalt("partial-remote-possible")
            # A prior full-flow S already established Step 11.  The
            # assets-only transition is permitted to retain that completed
            # obligation while it revalidates the ordinary current targets.
            record = mark_transaction_verified(record, BUNDLE_META_TARGET_KEY)

        barrier_specs = _transaction_specs(bundle, full_flow)
        dispatch_specs = _transaction_specs(bundle, full_flow and not defer_step_11)
        specs = dispatch_specs
        if step_11_only:
            specs = [spec for spec in _transaction_specs(bundle, True) if spec[0] == BUNDLE_META_TARGET_KEY]
            # The full main() caller deliberately leaves M for Step 11 while
            # retaining its lock across enrollment publication.  It must not,
            # however, trust observations from the pre-Step-11 leg: an
            # ordinary target may have been replaced in that interval.  Fence
            # all 66 ordinary targets before M can issue a write.  This is a
            # recovery halt rather than an ordinary refusal because the
            # durable two-leg transaction can no longer assert a coherent
            # complete observation; publish that fact before returning the
            # public exit-4 boundary (R2FIX main orchestration oracle).
            for ordinary_spec in _transaction_specs(bundle):
                ordinary_state, _ordinary_live, _ordinary_destination = _transaction_observe(
                    es_url, kb_url, authorization, ordinary_spec, bundle, adapter, record)
                if ordinary_state != "exact":
                    if not record.get("possible_mutation"):
                        record["possible_mutation"] = True
                        write_transaction_record(record_path, record, binding, targets)
                    raise AssetTransactionHalt("partial-remote-possible")
        # A resumed full-flow transaction must not let the lexically first
        # Step-11 target escape ahead of a later ordinary refusal.  Re-observe
        # the complete dispatch set before *any* guarded write; this preserves
        # the same zero-write barrier used for a fresh transaction while still
        # allowing absent targets to take their normal create paths below.
        barrier_states: dict[str, str] = {}
        if full_flow and record is not None and not step_11_only:
            for barrier_spec in barrier_specs:
                barrier_state, _barrier_live, _barrier_destination = _transaction_observe(
                    es_url, kb_url, authorization, barrier_spec, bundle, adapter, record)
                barrier_states[barrier_spec[0]] = barrier_state
                if barrier_state == "divergent":
                    if barrier_spec[0].startswith("kibana/"):
                        raise AssetTransactionRefusal("Kibana target differs")
                    raise AssetTransactionRefusal("asset target differs")
                if barrier_state == "owned-divergent" and barrier_spec[0].startswith("kibana/"):
                    raise AssetTransactionRefusal("Kibana target differs")
                # Stamped ES divergence is writable only under the same
                # authority checked in the execution leg below.  Applying
                # that decision here prevents M (the first dispatch target)
                # from being written before a later static refusal.
                transition_es_authorized = (has_valid_predecessor and version_flags
                                            and (upgrade ^ allow_downgrade))
                repair_es_authorized = repair and not has_valid_predecessor
                if (barrier_state == "owned-divergent"
                        and not (started_without_record or transition_es_authorized
                                 or repair_es_authorized)):
                    raise AssetTransactionRefusal("stamped ES reconciliation requires --repair")
        if defer_installed_full_flow_extension:
            fault("before-full-flow-extension")
            record = extend_installed_for_full_flow(record, _transaction_now())
            # ``extend_installed_for_full_flow`` begins from an all-verified
            # installed predecessor.  The just-completed barrier may instead
            # have observed a creatable target; retain that fact as planned so
            # its guarded write is legal, without claiming it was verified.
            for key, state in barrier_states.items():
                if state != "exact":
                    record["progress"][key] = "planned"
            write_transaction_record(record_path, record, binding, targets)
            fault("after-full-flow-extension")
        if defer_full_flow_extension:
            fault("before-full-flow-extension")
            record = expand_full_flow_record(record)
            write_transaction_record(record_path, record, binding, targets)
            fault("after-full-flow-extension")
        # If an installed record is demoted mid-reread, retain the successful
        # observations already made in this invocation.  In particular the
        # lexical Step-11 marker precedes ordinary targets, so losing that
        # fact would leave its fresh progress entry planned at promotion.
        verified_this_pass: set[str] = set()
        for spec in specs:
            key = spec[0]
            desired_override: Asset | None = None
            state, live, destination = _transaction_observe(es_url, kb_url, authorization, spec, bundle, adapter, record)
            if state == "exact":
                verified_this_pass.add(key)
                if record["state"] == "installing":
                    # A resolver can recover a nonliteral destination after a
                    # response-loss crash.  It is durable authority for later
                    # reference rewrites, so publish it before verified.
                    if key.startswith("kibana/") and destination is not None and _persist_destination_mapping(record, key, destination):
                        write_transaction_record(record_path, record, binding, targets)
                        fault("after-destination-map-publication", key)
                    record = mark_transaction_verified(record, key)
                    if not transition_pending:
                        write_transaction_record(record_path, record, binding, targets)
                continue
            if state == "divergent":
                raise AssetTransactionRefusal("asset target differs")
            if state == "owned-divergent" and spec[0].startswith("kibana/"):
                raise AssetTransactionRefusal("Kibana target differs")
            transition_es_authorized = (has_valid_predecessor and version_flags and (upgrade ^ allow_downgrade))
            repair_es_authorized = repair and not has_valid_predecessor
            if state == "owned-divergent" and not (started_without_record or transition_es_authorized
                                                    or repair_es_authorized):
                raise AssetTransactionRefusal("stamped ES reconciliation requires --repair")
            if record["state"] == "installed":
                fault("before-installed-demotion")
                record = demote_installed_transaction(record, _transaction_now())
                for verified_key in verified_this_pass:
                    record = mark_transaction_verified(record, verified_key)
                write_transaction_record(record_path, record, binding, targets)
                fault("after-installed-demotion")
            if transition_pending:
                write_transaction_record(record_path, record, binding, targets)
                transition_pending = False
            # A stamped ES divergent object is a qualified reconciliation;
            # transforms use their documented update endpoint, all other
            # classes retain their creation guard and reread conflict signal.
            if spec[1] is not None and spec[1].kind in {"pipelines", "security_roles"}:
                _transaction_diagnostic_preflight(record_path)
            record = mark_transaction_write_issued(record, key)
            record["_record_path"] = str(record_path)  # runtime-only, never published
            public = deepcopy(record); del public["_record_path"]
            write_transaction_record(record_path, public, binding, targets)
            record = public
            fault("after-write-issued", key)
            if state == "owned-divergent" and spec[1] is not None and spec[1].kind == "transforms":
                asset = stamped_asset(spec[1])
                mutation_request(es_url, es_path(asset) + "/_update", "POST", authorization,
                                 jcs({key: value for key, value in parse_json(asset.data, asset.path).items() if key != "pivot"}))
            else:
                runtime = deepcopy(record); runtime["_record_path"] = str(record_path)
                runtime["_observed_live"] = live; runtime["_observed_state"] = state
                # This is deliberately after the final transaction GET and
                # durable write-issued edge, but immediately before the
                # class-specific PUT/POST.  Clean-stack detector gates use it
                # to create a foreign pipeline/role in the otherwise
                # untimeable GET→PUT window.  ``test_pause`` is inert unless
                # --unsafe-test-injection, an exact env point, and a loopback
                # endpoint are all present.
                test_pause("before-transaction-put", unsafe_test_injection, es_url, key)
                try:
                    desired_override = _transaction_put(es_url, kb_url, authorization, spec, bundle, runtime, adapter)
                except RequestFailure as error:
                    # A conditional create can race an already-existing
                    # target.  Do not classify generic 4xx errors as races;
                    # the proven class-specific statuses get one immediate
                    # observation below, which either verifies or halts.
                    if not _transaction_create_conflict(spec, error, state):
                        raise
            state, _live, verified_destination = _transaction_observe(es_url, kb_url, authorization, spec, bundle, adapter, record,
                                                                       desired_override=desired_override)
            if state != "exact":
                raise AssetTransactionHalt("partial-remote-possible")
            if spec[0].startswith("kibana/") and verified_destination is not None and _persist_destination_mapping(record, key, verified_destination):
                # Mapping is its own durable edge.  A response-loss crash may
                # leave write-issued progress, but never loses the physical
                # saved-object identity learned from a successful create.
                write_transaction_record(record_path, record, binding, targets)
                fault("after-destination-map-publication", key)
            record = mark_transaction_verified(record, key)
            write_transaction_record(record_path, record, binding, targets)
            fault("after-target-verification", key)
            test_halt("after-target-verification", unsafe_test_injection, es_url, key)

        if defer_step_11:
            # The executor's pre-Step-11 leg deliberately leaves M planned
            # and cannot promote.  The caller retains this same lock through
            # enrollment publication, handshake, revocation, and local commit.
            return "deferred"
        # Promotion is preceded by a complete ordered reread, never progress
        # bookkeeping alone (T-SM-8/T-RECON-7).
        # ``specs`` is deliberately narrowed to M for the Step-11 leg, but
        # promotion is a transaction-wide assertion.  Keep the same lock and
        # re-observe the complete barrier set immediately before promotion.
        for spec in barrier_specs:
            state, _live, _destination = _transaction_observe(es_url, kb_url, authorization, spec, bundle, adapter, record)
            if state != "exact":
                raise AssetTransactionHalt("partial-remote-possible")
        fault("after-final-reverify")
        if record["state"] == "installed":
            return "noop"
        fault("before-promotion")
        record = promote_transaction_record(record, _transaction_now())
        write_transaction_record(record_path, record, binding, targets)
        fault("after-promotion")
        return "applied"
    finally:
        if owned_lock:
            lock.close()


class AssetLockHeld(InputError):
    pass


class AssetTransactionLock:
    def __init__(self, fd: int): self.fd = fd

    @staticmethod
    def lock_path() -> Path:
        state = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))).expanduser().resolve()
        return state / "rigsignal" / "assets" / "assets-install.lock"

    @classmethod
    def acquire(cls) -> "AssetTransactionLock":
        path = cls.lock_path()
        try:
            _reject_symlinked_path(path.parent.parent)
            path.parent.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            _validate_assets_marker_shared_parent(path.parent.parent)
            path.parent.mkdir(mode=0o700, exist_ok=True); secure_root(path.parent)
            fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.fchmod(fd, 0o600)
            descriptor = os.fstat(fd)
            if (not stat.S_ISREG(descriptor.st_mode) or descriptor.st_uid != os.geteuid()
                    or descriptor.st_mode & 0o077):
                raise InputError("assets transaction lock is invalid")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            try: os.close(fd)
            except (OSError, UnboundLocalError): pass
            raise AssetLockHeld("assets transaction lock is held") from error
        except (OSError, InputError) as error:
            try: os.close(fd)
            except (OSError, UnboundLocalError): pass
            raise InputError("assets transaction lock is invalid") from error
        return cls(fd)

    def close(self) -> None:
        try: fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally: os.close(self.fd)


def json_response(data: bytes) -> object:
    return parse_json(data, "HTTP response")


def role_body(bundle: Bundle) -> dict:
    asset = next((item for item in bundle.assets if item.path ==
                  "elastic/security-roles/rigsignal_shipper.json"), None)
    if asset is None:
        raise InputError("canonical shipper role is missing")
    value = parse_json(asset.data, asset.path)
    if not isinstance(value, dict) or hashlib.sha256(jcs(value)).hexdigest() != ROLE_JCS_SHA256:
        raise InputError("canonical shipper role is invalid")
    # Ratification is deliberately structural too: a digest alone is not an
    # authorization policy review.
    if (set(value) != {"cluster", "indices"} or value.get("cluster") != ["monitor"]
            or not isinstance(value.get("indices"), list) or len(value["indices"]) != 1
            or value["indices"][0] != {"names": [DIAGNOSIS_STREAM],
                                        "privileges": ["view_index_metadata", "create_doc"]}):
        raise InputError("canonical shipper role is invalid")
    viewer_role_body(bundle)
    return value


def viewer_role_body(bundle: Bundle) -> dict:
    asset = next((item for item in bundle.assets if item.path ==
                  "elastic/kibana-roles/rigsignal_viewer.json"), None)
    if asset is None:
        raise InputError("canonical viewer role is missing")
    value = parse_json(asset.data, asset.path)
    if not isinstance(value, dict) or hashlib.sha256(jcs(value)).hexdigest() != VIEWER_ROLE_JCS_SHA256:
        raise InputError("canonical viewer role is invalid")
    if (set(value) != {"description", "elasticsearch", "kibana"}
            or value.get("description") != "RigSignal read-only dashboard viewer. Read + view_index_metadata on the rigsignal namespace only; feature reads scoped to the rigsignal space only. No cluster privileges, no write/delete, no other Kibana feature."
            or value.get("elasticsearch") != {"cluster": [], "indices": [{
                "names": ["logs-rigsignal.*", "metrics-rigsignal.*"],
                "privileges": ["read", "view_index_metadata"]}]}
            or value.get("kibana") != [{"base": [], "feature": {"dashboard_v2": ["read"]},
                                         "spaces": ["rigsignal"]}]):
        raise InputError("canonical viewer role is invalid")
    return value


def state_template(uuid_value: str, generation: str, active: str | None = None,
                   enrollment_root: str | None = None) -> dict:
    if not valid_enrollment_root(enrollment_root):
        raise InputError("enrollment root is invalid")
    return {"version": 1, "phase": "committed", "expected_cluster_uuid": uuid_value,
            "target_generation": generation, "role_jcs_sha256": ROLE_JCS_SHA256,
            "enrollment_root": enrollment_root, "active_key_id": active,
            "pending_revoke_ids": [], "pending_mint_name": None,
            "candidate_key_id": None}


def valid_enrollment_root(value: object) -> bool:
    """Check the persisted, canonical UTF-8 root representation without I/O."""
    if not isinstance(value, str) or not value or "\0" in value or not os.path.isabs(value):
        return False
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    if len(encoded) > 4096:
        return False
    try:
        return os.path.realpath(value) == value
    except (OSError, ValueError):
        return False


def validate_state_binding(value: object, root: Path) -> None:
    """Refuse state before it can establish ownership or expose key IDs."""
    if not isinstance(value, dict) or not valid_enrollment_root(value.get("enrollment_root")):
        raise StateBindingError("state enrollment root is invalid")
    actual = os.path.realpath(os.fspath(root))
    if value["enrollment_root"] != actual:
        raise StateBindingError("state enrollment root does not match")


def validate_state(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != STATE_KEYS:
        raise InputError("state.json schema is invalid")
    if type(value["version"]) is not int or value["version"] != 1 or value["phase"] not in STATE_PHASES:
        raise InputError("state.json schema is invalid")
    if not valid_enrollment_root(value["enrollment_root"]):
        raise InputError("state.json schema is invalid")
    if not isinstance(value["expected_cluster_uuid"], str) or not UUID_RE.fullmatch(value["expected_cluster_uuid"]):
        raise InputError("state.json schema is invalid")
    for key in ("target_generation", "role_jcs_sha256"):
        if not isinstance(value[key], str) or not HEX_RE.fullmatch(value[key]):
            raise InputError("state.json schema is invalid")
    for key, cap in (("active_key_id", 1024), ("candidate_key_id", 1024), ("pending_mint_name", 255)):
        item = value[key]
        if item is not None and (not isinstance(item, str) or not item
                                 or len(item.encode("utf-8")) > cap):
            raise InputError("state.json schema is invalid")
    pending = value["pending_revoke_ids"]
    if (not isinstance(pending, list) or any(not isinstance(item, str) or not item
                                             or len(item.encode("utf-8")) > 1024
                                             for item in pending)
            or pending != sorted(set(pending))):
        raise InputError("state.json schema is invalid")
    phase = value["phase"]
    if phase == "committed" and (value["active_key_id"] is None or pending or value["pending_mint_name"] is not None or value["candidate_key_id"] is not None):
        raise InputError("state.json invariant is invalid")
    if phase == "mint_intent" and (value["pending_mint_name"] is None or value["candidate_key_id"] is not None
                                    or pending):
        raise InputError("state.json invariant is invalid")
    if phase == "candidate_staged" and (value["pending_mint_name"] is None or value["candidate_key_id"] is None
                                         or pending or value["candidate_key_id"] == value["active_key_id"]):
        raise InputError("state.json invariant is invalid")
    if phase == "candidate_verified" and (value["pending_mint_name"] is None or value["candidate_key_id"] is None):
        raise InputError("state.json invariant is invalid")
    if phase == "candidate_verified" and value["active_key_id"] == value["candidate_key_id"]:
        # This is the post-directory-exchange state.  A first enrollment has
        # no replaced ID, so its pending list is correctly empty; the sentinel
        # distinguishes it from an uncommitted candidate.
        if value["pending_mint_name"] != "published-pending-revoke":
            raise InputError("state.json invariant is invalid")
    elif phase == "candidate_verified" and pending:
        raise InputError("state.json invariant is invalid")
    return value


def secure_read(path: Path, missing_ok: bool = False) -> bytes | None:
    if missing_ok and not path.exists():
        return None
    return protected_regular_file(path)


def load_state(root: Path) -> dict | None:
    raw = secure_read(root / "state.json", missing_ok=True)
    if raw is None:
        return None
    value = parse_json(raw, "state.json")
    validate_state_binding(value, root)
    return validate_state(value)


def load_ownership_profile(root: Path) -> str | None:
    raw = secure_read(root / OWNERSHIP_PROFILE_FILE, missing_ok=True)
    if raw is None:
        return None
    value = parse_json(raw, OWNERSHIP_PROFILE_FILE)
    if (not isinstance(value, dict) or set(value) != {"profile", "table_version"}
            or value.get("profile") != "fleet-coexist"
            or value.get("table_version") != OWNERSHIP_TABLE_VERSION):
        raise InputError("ownership profile state is invalid")
    return value["profile"]


def bind_ownership_profile(root: Path, requested: str, implicit_default: bool = False) -> None:
    """Fence profile changes in protected enrollment state before remote work."""
    persisted = load_ownership_profile(root)
    if persisted is not None and persisted != requested:
        raise ProvisionError("install refused: omitted_profile_on_coexist" if implicit_default
                             else "install refused: ownership_profile_mismatch")
    if requested == "default" and persisted is None:
        return
    if persisted is None:
        atomic_write(root, OWNERSHIP_PROFILE_FILE,
                     jcs({"profile": "fleet-coexist", "table_version": OWNERSHIP_TABLE_VERSION}) + b"\n")


def remote_ownership_profile(es_url: str, authorization: str) -> tuple[str, object, bool] | None:
    """Read the durable cluster-side profile fence before any local mutation."""
    try:
        raw = request(es_url, "/_component_template/rigsignal-bundle-meta", "GET", authorization)
        # Unit callers which model an otherwise irrelevant transport with an
        # unconstrained mock have no remote-marker response.  Real request()
        # always returns bytes; do not turn that test seam into an authority.
        if not isinstance(raw, (bytes, bytearray)):
            return None
        response = json_response(raw)
    except RequestFailure as error:
        if error.status == 404:
            return None
        raise
    try:
        marker = asset_adapters.get_projection("install_marker", response)
    except asset_adapters.AdapterError as error:
        raise InputError("remote ownership marker is invalid") from error
    meta = marker.get("_meta") if isinstance(marker, dict) else None
    profile = meta.get("ownership_profile") if isinstance(meta, dict) else None
    if profile not in {"default", "fleet-coexist"}:
        raise InputError("remote ownership marker is invalid")
    return profile, meta.get("ownership_table_version"), "ownership_table_version" in meta


def fence_remote_ownership_profile(es_url: str, authorization: str, requested: str,
                                   implicit_default: bool) -> None:
    remote = remote_ownership_profile(es_url, authorization)
    if remote is None:
        return
    remote_profile, remote_version, has_remote_version = remote
    # Pre-A5 default markers legitimately predate versioning, and that absence
    # is the accepted migration direction.  Every fleet-coexist marker writer
    # stamps the version, so a coexist marker lacking it is anomalous state,
    # not legacy input — both that and any present mismatch fence.
    if has_remote_version and remote_version != OWNERSHIP_TABLE_VERSION:
        raise ProvisionError("install refused: ownership_table_version_mismatch")
    if remote_profile == "fleet-coexist" and requested != "fleet-coexist":
        raise ProvisionError("install refused: omitted_profile_on_coexist" if implicit_default
                             else "install refused: ownership_profile_mismatch")
    if remote_profile == "fleet-coexist" and not has_remote_version:
        raise ProvisionError("install refused: ownership_table_version_mismatch")


_PUBLICATION_STAGE_PREFIX = b".rigsignal-publication-"
_PUBLICATION_STAGE_SUFFIX_RE = re.compile(br"[0-9a-f]{16}\Z")
_PUBLICATION_PROBE_PREFIX = b".rigsignal-publication-probe-"
_PUBLICATION_REQUIRED_MEMBERS = (b"credentials.toml", b"handshake.toml",
                                 b"shipping-policy-v1.toml", b"state.json")
_PUBLICATION_OPTIONAL_MEMBERS = (os.fsencode(OWNERSHIP_PROFILE_FILE), os.fsencode("fleet-coexist-journal.json"))


def _publication_stage_prefix(root: Path) -> bytes:
    """Return the bytes-safe sibling prefix for this canonical root leaf."""
    return _PUBLICATION_STAGE_PREFIX + os.fsencode(root.name)


def _publication_stage_legacy_name(root: Path) -> bytes:
    return _publication_stage_prefix(root)


def _publication_stage_name(root: Path) -> bytes:
    return _publication_stage_prefix(root) + b"-" + secrets.token_hex(8).encode("ascii")


def _is_publication_stage_name(root: Path, name: bytes) -> bool:
    """Recognize only the legacy exact or new random exact stage forms."""
    legacy = _publication_stage_legacy_name(root)
    if name == legacy:
        return True
    prefix = legacy + b"-"
    return name.startswith(prefix) and _PUBLICATION_STAGE_SUFFIX_RE.fullmatch(name[len(prefix):]) is not None


def _private_directory(st: os.stat_result) -> bool:
    return bool(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)
                and st.st_uid == os.geteuid() and (st.st_mode & 0o077) == 0)


def _publication_member_name(name: bytes) -> bool:
    """The one publication membership predicate, shared by writer and assertion."""
    return (name not in (b"", b".", b"..") and b"/" not in name
            and (name in _PUBLICATION_REQUIRED_MEMBERS or name in _PUBLICATION_OPTIONAL_MEMBERS
                 or name.startswith(b"fleet-coexist-body-")))


def _publication_debris(root: Path) -> bool:
    """Report inert lookalikes and return only owned, exact-shape private debris."""
    try:
        parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return False
    try:
        for entry in os.listdir(parent_fd):
            name = os.fsencode(entry)
            if not _is_publication_stage_name(root, name):
                continue
            try:
                candidate = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                print("inert enrollment publication lookalike could not be inspected", file=sys.stderr)
                continue
            if (stat.S_ISDIR(candidate.st_mode) and not stat.S_ISLNK(candidate.st_mode)
                    and candidate.st_uid == os.geteuid() and stat.S_IMODE(candidate.st_mode) == 0o700):
                return True
            print("inert enrollment publication lookalike is not owned private debris", file=sys.stderr)
        return False
    finally:
        os.close(parent_fd)


def enrollment_condition(root: Path) -> str:
    """Classify local enrollment ownership without creating or repairing it.

    This is intentionally read-only: adoption refusals must not turn a missing
    root into a newly owned root, nor clean up a recoverable candidate.
    """
    try:
        _reject_symlinked_path(root)
        if not root.exists():
            return "clean"
        st = root.lstat()
        if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_mode & 0o077):
            return "remediation"
        # Keep this after the missing-root guard: a first install with an absent
        # parent is clean, not an OSError-driven remediation refusal.
        if _publication_debris(root):
            return "remediation"
        entries = {entry.name for entry in root.iterdir()}
        allowed = {"state.json", "credentials.toml", "handshake.toml", "shipping-policy-v1.toml",
                   OWNERSHIP_PROFILE_FILE, JOURNAL_FILE, "candidate"}
        if not all(name in allowed or name.startswith("fleet-coexist-body-") for name in entries):
            return "remediation"
        for name in entries:
            if name.startswith("fleet-coexist-body-"):
                body = root / name
                body_st = body.lstat()
                if (not stat.S_ISREG(body_st.st_mode) or stat.S_ISLNK(body_st.st_mode)
                        or body_st.st_uid != os.geteuid() or body_st.st_mode & 0o077):
                    return "remediation"
        if "state.json" not in entries:
            # A completed coexistence rollback retains its audit journal and
            # body references.  This is a safe fresh-install state: a new
            # transaction archives the completed journal before mutation.
            retained = {JOURNAL_FILE}
            if entries and JOURNAL_FILE in entries and all(
                    name in retained or name.startswith("fleet-coexist-body-") for name in entries):
                journal = secure_read(root / JOURNAL_FILE)
                if journal is not None:
                    try:
                        value = parse_json(journal, JOURNAL_FILE)
                    except InputError:
                        return "remediation"
                    if isinstance(value, dict) and value.get("rollback_ok") is True:
                        return "rolled-back"
            return "clean" if not entries else "remediation"
        state = load_state(root)
        if state is None:
            return "remediation"
        if "candidate" in entries:
            # A candidate directory is normally an orphaned staging artifact.
            # The one exception is the durable, valid incomplete transaction
            # state left by a crash after candidate staging: ordinary recovery
            # must revoke it and remove the private tree before re-evaluating.
            # Inspect it without creating or changing anything so malformed
            # staging remains a remediation refusal.
            candidate = root / "candidate"
            candidate_st = candidate.lstat()
            if (not stat.S_ISDIR(candidate_st.st_mode) or stat.S_ISLNK(candidate_st.st_mode)
                    or candidate_st.st_uid != os.geteuid() or candidate_st.st_mode & 0o077):
                return "remediation"
            candidate_entries = {entry.name for entry in candidate.iterdir()}
            candidate_allowed = {"credentials.toml", "handshake.toml", "shipping-policy-v1.toml", "state.json"}
            if not candidate_entries.issubset(candidate_allowed):
                return "remediation"
            for entry in candidate.iterdir():
                item_st = entry.lstat()
                if (not stat.S_ISREG(item_st.st_mode) or stat.S_ISLNK(item_st.st_mode)
                        or item_st.st_uid != os.geteuid() or item_st.st_mode & 0o077):
                    return "remediation"
            if state["phase"] == "committed":
                return "remediation"
        return "committed" if state["phase"] == "committed" else "incomplete"
    except (InputError, OSError, ValueError):
        return "remediation"


def _reject_symlinked_path(root: Path) -> None:
    """Reject a symlink in any existing component of the lexical root path."""
    raw = os.fspath(root)
    try:
        raw.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise InputError("enrollment root is not protected") from error
    if "\0" in raw:
        raise InputError("enrollment root is not protected")
    lexical = os.path.abspath(raw)
    current = os.path.sep
    for component in Path(lexical).parts[1:]:
        current = os.path.join(current, component)
        try:
            member = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise InputError("enrollment root is not protected") from error
        if stat.S_ISLNK(member.st_mode):
            raise InputError("enrollment root is not protected")


def _ancestor_component_safe(st: os.stat_result) -> bool:
    """Return whether one existing enrollment-root ancestor is protected."""
    mode = st.st_mode
    return bool(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)
                and st.st_uid in (os.geteuid(), 0)
                and ((mode & 0o022) == 0 or (mode & stat.S_ISVTX and st.st_uid == 0)))


def _enrollment_parent_safe(st: os.stat_result) -> bool:
    """Return whether the directory that will contain the root is protected."""
    mode = st.st_mode
    # For an fd opened with O_NOFOLLOW|O_DIRECTORY the symlink limb is
    # unreachable; retain it here so the predicate is also safe for lstat users.
    return bool(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)
                and st.st_uid == os.geteuid() and (mode & 0o022) == 0)


def check_install_root_ancestors(root: Path, *, boundary: Path = Path("/")) -> None:
    """Refuse an install root beneath an unsafe existing lexical component."""
    try:
        root_path = Path(os.path.abspath(os.fspath(root)))
        boundary_path = Path(os.path.abspath(os.fspath(boundary)))
        relative = root_path.relative_to(boundary_path)
    except (TypeError, ValueError, OSError) as error:
        raise ProvisionError("install refused: enrollment ancestor is not protected:") from error
    # The immediate parent will hold the exchange staging sibling and needs
    # atomic_publication's stricter ownership rule.  Higher ancestors may be
    # root-owned sticky directories such as /tmp.
    components = []
    current = root_path if root_path == boundary_path else root_path.parent
    while True:
        components.append(current)
        if current == boundary_path:
            break
        current = current.parent
    for position, component in enumerate(components):
        try:
            component_st = os.lstat(component)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ProvisionError("install refused: enrollment ancestor is not protected:") from error
        safe = _enrollment_parent_safe(component_st) if position == 0 else _ancestor_component_safe(component_st)
        if not safe:
            raise ProvisionError("install refused: enrollment ancestor is not protected:")


def check_outbox_root(outbox_root: Path) -> None:
    """Refuse an existing outbox terminal that cannot be safely used later."""
    try:
        terminal = os.lstat(outbox_root)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ProvisionError("install refused: outbox preflight:") from error
    else:
        if not _enrollment_parent_safe(terminal):
            raise ProvisionError("install refused: outbox preflight:")
    # This delegated check is unreachable-failing while each call site checks the
    # same enrollment-root chain one line earlier; retain it as defence-in-depth.
    # test_main_outbox_preflight_order_is_pinned_at_both_call_sites pins that ordering;
    # see docs/outbox-ancestor-policy.md.
    check_install_root_ancestors(outbox_root)


def _nearest_existing_ancestor(path: Path) -> Path:
    """Return an existing lexical ancestor without following a missing tail."""
    try:
        current = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as error:
        raise ProvisionError("install refused: enrollment preflight unavailable") from error
    while True:
        try:
            os.lstat(current)
            return current
        except FileNotFoundError:
            if current == current.parent:
                raise ProvisionError("install refused: enrollment preflight unavailable")
            current = current.parent
        except OSError as error:
            raise ProvisionError("install refused: enrollment preflight unavailable") from error


def _mountinfo_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _mount_filesystem_type(path: Path) -> str:
    """Read the mount type for path from Linux's authoritative mount table."""
    target = os.path.abspath(os.fspath(path))
    best: tuple[int, str] | None = None
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as handle:
            for line in handle:
                fields = line.rstrip("\n").split()
                try:
                    separator = fields.index("-")
                    mountpoint = _mountinfo_unescape(fields[4])
                    filesystem = fields[separator + 1]
                    common = os.path.commonpath((target, mountpoint))
                except (IndexError, ValueError, OSError):
                    continue
                if common == mountpoint and (best is None or len(mountpoint) > best[0]):
                    best = (len(mountpoint), filesystem)
    except (OSError, UnicodeError, ValueError) as error:
        raise ProvisionError("install refused: atomic_publication_filesystem_unsupported") from error
    if best is None:
        raise ProvisionError("install refused: atomic_publication_filesystem_unsupported")
    return best[1]


def _rename_exchange_symbol_available() -> bool:
    try:
        ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        return False
    return True


def _probe_rename_exchange_capability(root: Path, ancestor: Path) -> None:
    """Perform one disposable, fd-anchored rename-exchange capability probe."""
    anchor = root.parent if root.parent.is_dir() else ancestor
    parent_fd = None
    names: list[bytes] = []
    try:
        parent_fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_CLOEXEC", 0))
        token = secrets.token_hex(8).encode("ascii")
        names = [_PUBLICATION_PROBE_PREFIX + token + b"-a",
                 _PUBLICATION_PROBE_PREFIX + token + b"-b"]
        for name in names:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        _rename_exchange(parent_fd, names[0], parent_fd, names[1])
    except OSError as error:
        if error.errno in (errno.EROFS, errno.ENOSPC):
            raise ProvisionError("install refused: local_transaction_storage_unavailable") from error
        # Diagnostic enrichment only, computed on failure: name the filesystem
        # in a separate stderr line so the stable refusal token stays pinned.
        try:
            print("enrollment preflight diagnostic: filesystem type "
                  + _mount_filesystem_type(anchor), file=sys.stderr)
        except ProvisionError:
            pass
        raise ProvisionError("install refused: atomic_publication_filesystem_unsupported") from error
    finally:
        if parent_fd is not None:
            for name in names:
                try:
                    os.rmdir(name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)


def _check_agent_binary(agent: Path) -> Path:
    try:
        raw_agent = os.fspath(agent)
        resolved = Path(raw_agent) if os.path.isabs(raw_agent) else shutil.which(raw_agent)
        if resolved is None:
            raise OSError("agent is not launchable")
        resolved = Path(resolved).resolve(strict=True)
        agent_st = os.lstat(resolved)
        if (not stat.S_ISREG(agent_st.st_mode) or stat.S_ISLNK(agent_st.st_mode)
                or not os.access(resolved, os.R_OK) or not os.access(resolved, os.X_OK)):
            raise OSError("agent is not launchable")
        result = subprocess.run([os.fspath(resolved), "--version"], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
        if result.returncode != 0:
            raise OSError("agent version failed")
        return resolved
    except (OSError, RuntimeError) as error:
        raise ProvisionError("install refused: agent_binary_unlaunchable") from error


def _check_publication_stage_path(root: Path, ancestor: Path) -> None:
    """Reject a stage path that mkdir(2) would reject after remote mutation."""
    try:
        canonical_root = Path(os.path.realpath(os.fspath(root)))
        stage_name = _publication_stage_prefix(canonical_root) + b"-" + b"f" * 16
        stage_path = os.path.join(os.fsencode(canonical_root.parent), stage_name)
        if len(stage_name) > os.pathconf(ancestor, "PC_NAME_MAX"):
            raise ProvisionError("install refused: enrollment_publication_path_too_long")
        if len(stage_path) >= os.pathconf(ancestor, "PC_PATH_MAX"):
            raise ProvisionError("install refused: enrollment_publication_path_too_long")
    except ProvisionError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise ProvisionError("install refused: enrollment_publication_path_too_long") from error


def _check_parent_fsync(ancestor: Path, eventual_parent: Path) -> None:
    """Exercise directory fsync only when this ancestor is the parent's device."""
    try:
        try:
            parent_st = os.lstat(eventual_parent)
        except FileNotFoundError:
            parent_st = None
        ancestor_st = os.lstat(ancestor)
        if parent_st is not None and parent_st.st_dev != ancestor_st.st_dev:
            return
        descriptor = os.open(ancestor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ProvisionError("install refused: enrollment_parent_fsync_unsupported") from error


def _check_local_transaction_readiness(ancestor: Path) -> None:
    try:
        values = os.statvfs(ancestor)
        readonly = getattr(os, "ST_RDONLY", 1)
        if (values.f_flag & readonly or values.f_bavail < LOCAL_TRANSACTION_MIN_AVAILABLE_BLOCKS
                or not os.access(ancestor, os.W_OK | os.X_OK)):
            raise ProvisionError("install refused: local_transaction_storage_unavailable")
    except ProvisionError:
        raise
    except OSError as error:
        raise ProvisionError("install refused: local_transaction_storage_unavailable") from error


def resolve_enrollment_ca_file(ca_file: Path) -> Path:
    """Validate the one canonical CA pathname emitted to enrollment TOML."""
    try:
        resolved = ca_file.resolve(strict=True)
        if not resolved.is_absolute():
            raise ValueError("CA path is not absolute")
        if protected_regular_file(resolved) != protected_regular_file(ca_file):
            raise ValueError("CA path changed while resolving")
        ancestor = _nearest_existing_ancestor(resolved)
        if len(os.fsencode(os.fspath(resolved))) > os.pathconf(ancestor, "PC_PATH_MAX"):
            raise ValueError("CA path is too long")
        return resolved
    except (InputError, OSError, UnicodeError, ValueError) as error:
        raise ProvisionError("install refused: enrollment_ca_path_invalid") from error


def check_install_preflight(root: Path, agent: Path, ca_file: Path) -> tuple[Path, Path]:
    """Run local bounded preflight before HTTP; it may probe private filesystem capability."""
    canonical_root = Path(os.path.realpath(os.fspath(root)))
    ancestor = _nearest_existing_ancestor(canonical_root.parent)
    resolved_agent = _check_agent_binary(agent)
    if not _rename_exchange_symbol_available():
        raise ProvisionError("install refused: atomic_publication_filesystem_unsupported")
    # Mount type is diagnostic enrichment only, emitted by the probe on
    # failure; a real exchange decides.
    _probe_rename_exchange_capability(canonical_root, ancestor)
    _check_publication_stage_path(canonical_root, ancestor)
    _check_parent_fsync(ancestor, canonical_root.parent)
    _check_local_transaction_readiness(ancestor)
    return resolve_enrollment_ca_file(ca_file), resolved_agent


def prepare_install_root(root: Path) -> Path:
    """Create each missing install-root component privately before secure_root()."""
    _reject_symlinked_path(root)
    try:
        current = Path(os.path.abspath(os.fspath(root)))
    except (TypeError, ValueError, OSError) as error:
        raise InputError("enrollment root is not protected") from error
    missing = []
    while True:
        try:
            os.lstat(current)
            break
        except FileNotFoundError:
            missing.append(current)
            if current == current.parent:
                raise InputError("enrollment root is not protected")
            current = current.parent
        except OSError as error:
            raise InputError("enrollment root is not protected") from error
    for component in reversed(missing):
        try:
            component.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise InputError("enrollment root is not protected") from error
        try:
            component_st = os.lstat(component)
        except OSError as error:
            raise InputError("enrollment root is not protected") from error
        if (not stat.S_ISDIR(component_st.st_mode) or stat.S_ISLNK(component_st.st_mode)
                or component_st.st_uid != os.geteuid() or component_st.st_mode & 0o077):
            raise InputError("enrollment root is not protected")
    return secure_root(root)


def secure_root(root: Path) -> Path:
    _reject_symlinked_path(root)
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    except (OSError, ValueError) as error:
        raise InputError("enrollment root is not protected") from error
    _reject_symlinked_path(root)
    canonical = Path(os.path.realpath(os.fspath(root)))
    st = canonical.lstat()
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o077):
        raise InputError("enrollment root is not protected")
    return canonical


def secure_candidate_root(root: Path) -> Path:
    """Return the private, non-consumer-visible staging directory."""
    secure_root(root)
    candidate = root / "candidate"
    candidate.mkdir(mode=0o700, exist_ok=True)
    st = candidate.lstat()
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o077):
        raise InputError("candidate enrollment directory is not protected")
    return candidate


def remove_candidate_root(root: Path) -> None:
    candidate = root / "candidate"
    if not candidate.exists():
        return
    secure_candidate_root(root)
    for name in ("credentials.toml", "handshake.toml", "shipping-policy-v1.toml", "state.json"):
        path = candidate / name
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise InputError("candidate enrollment output is invalid")
            path.unlink()
    candidate.rmdir()


def remove_recovered_state(root: Path) -> None:
    """Remove the validated null-active transaction record after recovery."""
    secure_root(root)
    path = root / "state.json"
    try:
        st = path.lstat()
    except OSError as error:
        raise InputError("recovered enrollment state is invalid") from error
    if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o077):
        raise InputError("recovered enrollment state is invalid")
    try:
        path.unlink()
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise InputError("cannot remove recovered enrollment state") from error


def atomic_write(root: Path, name: str, data: bytes, *, expected_prior: bytes | None | object = ... ) -> None:
    """Publish one protected file without following an existing target."""
    secure_root(root)
    if "/" in name or name.startswith("."):
        raise InputError("invalid enrollment file name")
    target = root / name

    def protected_leaf() -> tuple[os.stat_result, bytes] | None:
        try:
            leaf_fd = os.open(target, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return None
        try:
            leaf_stat = os.fstat(leaf_fd)
            if (not stat.S_ISREG(leaf_stat.st_mode) or leaf_stat.st_uid != os.geteuid()
                    or leaf_stat.st_mode & 0o077):
                raise InputError("enrollment output is not protected")
            with os.fdopen(leaf_fd, "rb", closefd=False) as leaf:
                contents = leaf.read()
            # Bind the validated descriptor to the name immediately before
            # replacement; a substituted sibling is never overwrite authority.
            named = os.lstat(target)
            if (named.st_dev, named.st_ino) != (leaf_stat.st_dev, leaf_stat.st_ino):
                raise InputError("enrollment output changed before replacement")
            return leaf_stat, contents
        finally:
            os.close(leaf_fd)

    prior = protected_leaf()
    actual_prior = None if prior is None else prior[1]
    if expected_prior is not ... and actual_prior != expected_prior:
        raise InputError("enrollment output changed before replacement")
    fd, temporary = tempfile.mkstemp(prefix=".rigsignal-", dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        fault("atomic-write-after-temp-fsync", name)
        # Repeat all leaf checks at the last possible point.  This is also
        # used by record and diagnostic replacement, whose caller supplied
        # the expected authoritative bytes.
        prior = protected_leaf()
        actual_prior = None if prior is None else prior[1]
        if expected_prior is not ... and actual_prior != expected_prior:
            raise InputError("enrollment output changed before replacement")
        os.replace(temporary, target)
        fault("atomic-write-after-replace", name)
        st = target.lstat()
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_mode & 0o077:
            raise InputError("enrollment output is not protected")
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        if isinstance(error, InputError):
            raise
        raise InputError("cannot publish enrollment output") from error


JOURNAL_FILE = "fleet-coexist-journal.json"
M1_ANCHOR_IDS = ("13610797-13f7-5c07-b028-4bd88c0b3edd",
                 "76e28921-5229-50bc-96e6-79c5abbb1c7d")


class TransactionJournal:
    """Protected, per-object mutation authority for Fleet coexistence."""
    def __init__(self, root: Path, profile: str, *, new_transaction: bool = False):
        self.root, self.profile = root, profile
        raw = secure_read(root / JOURNAL_FILE, missing_ok=True)
        if raw is None:
            self.value = {"version": 1, "ownership_profile": profile,
                          "ownership_table_version": OWNERSHIP_TABLE_VERSION,
                          "transaction_id": uuid.uuid4().hex, "apply_ok": False,
                          "intents": [], "proofs": [], "m1_anchors": {}, "transactions": []}
            self._persist()
        else:
            self.value = parse_json(raw, JOURNAL_FILE)
            if (not isinstance(self.value, dict)
                    or self.value.get("ownership_profile") != profile
                    or self.value.get("ownership_table_version") != OWNERSHIP_TABLE_VERSION
                    or not isinstance(self.value.get("version"), int)
                    or isinstance(self.value.get("version"), bool)
                    or self.value.get("version") != 1
                    or ("transaction_id" in self.value
                        and not isinstance(self.value.get("transaction_id"), str))
                    or not isinstance(self.value.get("intents"), list)
                    or not isinstance(self.value.get("proofs"), list)
                    or not isinstance(self.value.get("m1_anchors"), dict)
                    or not isinstance(self.value.get("apply_ok"), bool)
                    or (self.value.get("rollback_ok") is not None
                        and not isinstance(self.value.get("rollback_ok"), bool))
                    or ("transactions" in self.value
                        and not isinstance(self.value.get("transactions"), list))):
                raise ProvisionError("install refused: ownership_profile_mismatch")
            self.value.setdefault("transaction_id", uuid.uuid4().hex)
            self.value.setdefault("transactions", [])
            if new_transaction:
                # Archive the completed transaction immutably, then open a
                # fresh mutation authority.  In particular, never append
                # invocation N's proofs to invocation N-1.
                if self.value.get("apply_ok") is not True and self.value.get("rollback_ok") is not True:
                    raise ProvisionError("install refused: transaction_recovery_required")
                previous = {key: value for key, value in self.value.items() if key != "transactions"}
                history = list(self.value["transactions"])
                history.append(previous)
                self.value = {"version": 1, "ownership_profile": profile,
                              "ownership_table_version": OWNERSHIP_TABLE_VERSION,
                              "transaction_id": uuid.uuid4().hex, "apply_ok": False,
                              "intents": [], "proofs": [], "m1_anchors": {},
                              "transactions": history}
                self._persist()

    def _persist(self) -> None:
        atomic_write(self.root, JOURNAL_FILE, jcs(self.value) + b"\n")

    def persist(self) -> None:
        """Durably flush a deliberate direct journal mutation."""
        self._persist()

    def _body_ref(self, key: str, body: bytes) -> dict:
        digest = hashlib.sha256(body).hexdigest()
        # atomic_write is deliberately single-directory/no-slash; this is a
        # durable protected request-body path relative to the journal root.
        name = "fleet-coexist-body-" + hashlib.sha256(
            (str(self.value.get("transaction_id", "")) + ":" + key).encode("utf-8")).hexdigest()
        atomic_write(self.root, name, body)
        return {"path": name, "sha256": digest}

    def write_intent(self, kind: str, name: str, action: str, preimage_sha256: str,
                     intended_after_sha256: str, request_body: bytes, *, object_id: str | None = None,
                     preimage_body: bytes | None = None, preimage_stats_state: str | None = None) -> dict:
        """Persist intent, after-pin and request reference together before I/O."""
        key = f"{kind}:{name}:{object_id or ''}:{len(self.value['intents'])}"
        record = {"event": "write_intent", "kind": kind, "name": name, "action": action,
                  "preimage_sha256": preimage_sha256,
                  "intended_after_sha256": intended_after_sha256,
                  "request_body": self._body_ref(key, request_body)}
        if object_id is not None:
            record["object_id"] = object_id
        if preimage_stats_state is not None:
            record["preimage_stats_state"] = preimage_stats_state
        # The preimage is mutation authority too.  A hash alone cannot restore
        # an interrupted transaction without consulting the current manifest.
        if preimage_body is not None:
            record["preimage_body"] = self._body_ref("preimage:" + key, preimage_body)
        else:
            record["preimage_absent"] = True
        self.value["intents"].append(record)
        self._persist()
        return record

    def write_verified(self, record: dict, after_sha256: str) -> None:
        record["write_verified"] = True
        record["after_sha256"] = after_sha256
        self._persist()

    def mark_transform_verify_only(self, record: dict, reason: str) -> None:
        """Record a pre-apply transform gate decision before the apply loop."""
        record["verify_only"] = True
        record["verify_only_reason"] = reason
        record["action"] = "noop"
        self._persist()

    def proof_intent(self, event_id: str) -> dict:
        record = {"event_id": event_id, "created_index": None}
        self.value["proofs"].append(record)
        self._persist()
        return record

    def proof_index(self, record: dict, index: str) -> None:
        record["created_index"] = index
        self._persist()

    def api_key_id(self, record: dict, key_id: str) -> None:
        record["key_id"] = key_id
        self._persist()

    def pin_m1_anchors(self, pins: dict[str, str]) -> None:
        self.value["m1_anchors"] = pins
        self._persist()

    def pin_external_baselines(self, records: list[dict]) -> None:
        """Persist the exact compatibility pins captured at the no-write barrier."""
        self.value["external_baselines"] = [
            {key: record[key] for key in ("kind", "name", "compatibility_projection_sha256")}
            for record in records
        ]
        self._persist()

    def pin_bundle(self, bundle_path: Path, bundle: Bundle) -> None:
        """Persist the immutable source needed by the external rollback oracle."""
        self.value["bundle_pin"] = {"sha256": bundle_sha256(bundle_path),
                                    "source_commit": bundle.source_commit,
                                    "asset_set_sha256": asset_set_sha256(bundle)}
        self._persist()

    def pin_fleet_fence(self, plan: dict) -> None:
        """Persist the pre-mutation fence evidence and durable synthetic bodies."""
        stored = {}
        for stream, entry in plan.items():
            if not isinstance(entry, dict):
                continue
            value = deepcopy(entry)
            projection = value.get("projection")
            if isinstance(projection, dict):
                for key in ("pre_synth_body", "post_synth_body"):
                    body = projection.pop(key, None)
                    if isinstance(body, bytes):
                        projection[key + "_ref"] = self._body_ref("fleet:" + stream + ":" + key, body)
            stored[stream] = value
        self.value["fleet_fence"] = {"plan": stored, "snapshots": {}}
        self._persist()

    def fleet_fence_snapshot(self, phase: str, snapshot: dict[str, object]) -> None:
        fence = self.value.setdefault("fleet_fence", {"plan": {}, "snapshots": {}})
        fence.setdefault("snapshots", {})[phase] = {
            "sha256": hashlib.sha256(jcs(snapshot)).hexdigest(), "state": deepcopy(snapshot)}
        self._persist()

    def fleet_fence_failure(self, layer: str, stream: str | None, ops: list[dict],
                            reason: str | None = None) -> None:
        fence = self.value.setdefault("fleet_fence", {"plan": {}, "snapshots": {}})
        fence["failure"] = {"layer": layer, "stream": stream, "ops": deepcopy(ops)}
        if reason is not None:
            fence["failure"]["reason"] = reason
        self._persist()

    def predecessor_recheck_failure(self, refusal: PredecessorRefusal) -> None:
        entries = self.value.setdefault("predecessor_manifest", {})
        entries.setdefault(refusal.asset, {})["recheck_failure"] = refusal.record()
        self._persist()

    def failure_site(self, site: FailureSite) -> None:
        """Retain the latest coarse local failure site as transaction evidence."""
        self.value["failure_site"] = site.value
        self._persist()

    def published_probe_diagnosis(self, line: str) -> None:
        """Retain the agent's credential-free published-file diagnosis."""
        self.value["published_probe_diagnosis"] = line
        self._persist()

    def apply_ok(self) -> None:
        self.value["apply_ok"] = True
        self._persist()

def newest_non_rolled_back_transaction(journal: TransactionJournal) -> dict:
    """Select the active transaction once, refusing a rollback re-invocation.

    Archived transactions are evidence of prior completed installs, not a
    rollback stack: local publication is shared by the active generation.  A
    second rollback must therefore never silently unwind an older archive.
    """
    active = journal.value
    if active.get("rollback_ok") is True:
        raise ProvisionError("install refused: transaction_already_rolled_back")
    if not isinstance(active.get("transaction_id"), str):
        raise ProvisionError("install refused: transaction_journal_invalid")
    return active


def ambiguous_crash_outcome(intent: dict, live_sha256: str) -> str:
    """Apply the durable three-way rule; never consult the current manifest."""
    if live_sha256 == intent.get("intended_after_sha256"):
        return "restore"
    if live_sha256 == intent.get("preimage_sha256"):
        return "untouched"
    raise ProvisionError("install refused: transaction_concurrent_drift")


def journal_recovery_actions(journal: TransactionJournal, live_hash_for) -> list[dict]:
    """Select inverse operations from journaled intents only.

    ``live_hash_for`` is supplied by the class-specific GET adapter.  This
    deliberately has no manifest argument: recovery cannot invent a mutation
    for an asset the interrupted transaction never journaled.  The durable
    three-way test applies to *every* asset intent, including a verified one:
    a retry may be resuming after a prior rollback already restored its
    preimage.  In particular, ``_rollback_live_hash`` maps a GET 404 to the
    absent preimage hash, so a never-created object is a converged no-op, not
    a restore request that can fail with another 404.
    """
    actions = []
    for intent in journal.value.get("intents", []):
        if (intent.get("event") != "write_intent" or intent.get("kind") == "api_key"
                or intent.get("verify_only") is True):
            continue
        # Test preimage first because a journaled ``noop`` has equal before
        # and after pins.  It must remain a no-op rather than issue a needless
        # restore write.
        live_hash = live_hash_for(intent)
        if live_hash == intent.get("preimage_sha256"):
            continue
        if ambiguous_crash_outcome(intent, live_hash) == "restore":
            actions.append(intent)
    return actions


def exact_proof_recovery_hit(es_url: str, authorization: str, event_id: str) -> dict | None:
    """One exact ID query, zero-or-one result; never wildcard/delete-by-query."""
    result = es_json(es_url, "/" + DIAGNOSIS_STREAM + "/_search", "POST", authorization,
                     {"query": {"ids": {"values": [event_id]}}, "size": 2})
    hits = required_path(result, ("hits", "hits"))
    if not isinstance(hits, list) or len(hits) > 1:
        raise ProvisionError("install refused: transaction_proof_ambiguous")
    if not hits:
        return None
    hit = hits[0]
    if not isinstance(hit, dict) or hit.get("_id") != event_id or not isinstance(hit.get("_index"), str):
        raise ProvisionError("install refused: transaction_proof_ambiguous")
    return hit


def rollback_transaction_proofs(es_url: str, authorization: str, journal: TransactionJournal,
                                deliberately_reversed: bool = False) -> None:
    if journal.value.get("apply_ok") and not deliberately_reversed:
        raise ProvisionError("install refused: transaction_proof_delete_not_authorized")
    for proof in journal.value.get("proofs", []):
        event_id, index = proof.get("event_id"), proof.get("created_index")
        if not isinstance(event_id, str):
            raise ProvisionError("install refused: transaction_proof_ambiguous")
        if index is None:
            hit = exact_proof_recovery_hit(es_url, authorization, event_id)
            if hit is None:
                continue
            index = hit["_index"]
        mutation_request(es_url, "/" + urllib.parse.quote(index, safe="") + "/_doc/" +
                urllib.parse.quote(event_id, safe="") + "?refresh=wait_for", "DELETE", authorization)


def _rollback_source_mismatch(source_commit: str) -> ProvisionError:
    return ProvisionError("install refused: rollback_source_mismatch; provide the applied bundle "
                          f"for recorded source_commit {source_commit}")


def _rollback_source_unavailable() -> ProvisionError:
    return ProvisionError("install refused: rollback_source_unavailable; provide the applied bundle")


def _source_tree_available() -> bool:
    """Whether this engine is executing from a complete source checkout."""
    return ((ROOT / "Cargo.toml").is_file() and ASSET_DIR.is_dir()
            and DASHBOARD_DIR.is_dir())


def rollback_verified_bundle(journal: TransactionJournal, bundle_path: Path | None = None) -> Bundle:
    """Resolve rollback oracle inputs without reading an installed engine's ROOT.

    A supplied archive is verified by its transaction pin.  The source-tree
    fallback exists only for in-repository owner recovery; staged engines carry
    neither the asset tree nor authority to substitute it for the applied
    bundle.
    """
    pin = journal.value.get("bundle_pin")
    if pin is not None and (not isinstance(pin, dict) or not isinstance(pin.get("sha256"), str)
                            or not isinstance(pin.get("source_commit"), str)
                            or not isinstance(pin.get("asset_set_sha256"), str)):
        raise ProvisionError("install refused: rollback_source_mismatch")
    try:
        if bundle_path is not None:
            if pin is not None and bundle_sha256(bundle_path) != pin["sha256"]:
                raise _rollback_source_mismatch(pin["source_commit"])
            bundle = load_bundle(bundle_path)
        else:
            if not _source_tree_available():
                raise _rollback_source_unavailable()
            bundle = load_source()
    except InputError as error:
        if pin is not None:
            raise _rollback_source_mismatch(pin["source_commit"]) from error
        raise _rollback_source_unavailable() from error
    if pin is not None:
        if (bundle.source_commit != pin["source_commit"]
                or asset_set_sha256(bundle) != pin["asset_set_sha256"]):
            raise _rollback_source_mismatch(pin["source_commit"])
    return bundle


def verify_rollback_external_baselines(es_url: str, authorization: str, journal: TransactionJournal,
                                      bundle_path: Path | None = None,
                                      bundle: Bundle | None = None) -> None:
    """Re-run the external oracle using the applied source, never an unchecked tree."""
    if bundle is None:
        bundle = rollback_verified_bundle(journal, bundle_path)
    pin = journal.value.get("bundle_pin")
    if pin is not None:
        try:
            ownership = ownership_for_assets(bundle, "fleet-coexist")
        except InputError as error:
            raise _rollback_source_mismatch(pin["source_commit"]) from error
        # An abort between pin_bundle and pin_external_baselines journals no
        # baselines and no intents; there is nothing external to re-verify, and
        # comparing against the implicit empty set would refuse the exact
        # applied bundle the refusal text asks for (F1-v4/S2-v4).  A present
        # key still compares in full, including a present-but-empty list.
        if "external_baselines" in journal.value:
            expected = {(item.get("kind"), item.get("name"))
                        for item in journal.value.get("external_baselines", []) if isinstance(item, dict)}
            source_external = {key for key, value in ownership.items() if value == "external"}
            if source_external != expected:
                raise _rollback_source_mismatch(pin["source_commit"])
    assets = {(asset.kind, asset.name): asset for asset in bundle.assets}
    for baseline in journal.value.get("external_baselines", []):
        if not isinstance(baseline, dict) or not isinstance(baseline.get("kind"), str) or not isinstance(baseline.get("name"), str):
            raise ProvisionError("install refused: transaction_journal_invalid")
        asset = assets.get((baseline["kind"], baseline["name"]))
        if asset is None:
            raise ProvisionError("install refused: transaction_journal_invalid")
        try:
            verify_external_asset(es_url, authorization, asset)
        except (InputError, RequestFailure) as error:
            raise ProvisionError("install refused: rollback_external_compatibility") from error


def _journal_body(journal: TransactionJournal, reference: dict) -> bytes:
    """Read one durable journal body reference without accepting path traversal."""
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str) or not isinstance(reference.get("sha256"), str):
        raise ProvisionError("install refused: transaction_journal_invalid")
    name = reference["path"]
    if "/" in name or name.startswith("."):
        raise ProvisionError("install refused: transaction_journal_invalid")
    body = secure_read(journal.root / name)
    if body is None or hashlib.sha256(body).hexdigest() != reference["sha256"]:
        raise ProvisionError("install refused: transaction_journal_invalid")
    return body


def m1_anchor_pins(es_url: str, authorization: str) -> dict[str, str]:
    """Pin each contract M1 source using a data-stream ids search exactly once."""
    pins: dict[str, str] = {}
    for ident in M1_ANCHOR_IDS:
        value = es_json(es_url, "/" + DIAGNOSIS_STREAM + "/_search", "POST", authorization,
                        {"query": {"ids": {"values": [ident]}}, "size": 2, "_source": True})
        hits = value.get("hits", {}).get("hits") if isinstance(value, dict) and isinstance(value.get("hits"), dict) else None
        if not isinstance(hits, list) or len(hits) != 1:
            raise ProvisionError("install refused: m1_anchor_absent")
        hit = hits[0]
        if not isinstance(hit, dict) or hit.get("_id") != ident:
            raise ProvisionError("install refused: m1_anchor_absent")
        source = hit.get("_source")
        if not isinstance(source, dict):
            raise InputError("M1 anchor response is invalid")
        pins[ident] = hashlib.sha256(jcs(source)).hexdigest()
    return pins


def verify_m1_anchors(es_url: str, authorization: str, pins: dict[str, str]) -> None:
    if not isinstance(pins, dict) or set(pins) != set(M1_ANCHOR_IDS):
        raise ProvisionError("install refused: m1_anchor_mismatch_break_glass")
    try:
        current = m1_anchor_pins(es_url, authorization)
    except (InputError, RequestFailure) as error:
        raise ProvisionError("install refused: m1_anchor_mismatch_break_glass") from error
    if current != pins:
        # This is deliberately a STOP, never a prompt to continue automated
        # restoration over potentially changed diagnostic evidence.
        raise ProvisionError("install refused: m1_anchor_mismatch_break_glass")


def _rollback_asset_path(intent: dict) -> tuple[str, str, dict[str, str] | None]:
    """Resolve an inverse target solely from a journal identity."""
    kind, name = intent.get("kind"), intent.get("name")
    if not isinstance(kind, str) or not isinstance(name, str):
        raise ProvisionError("install refused: transaction_journal_invalid")
    if kind == "dashboard":
        object_id = intent.get("object_id")
        if not isinstance(object_id, str) or "/" not in object_id:
            raise ProvisionError("install refused: transaction_journal_invalid")
        object_type, ident = object_id.split("/", 1)
        asset = Asset("dashboard", name, "", b"")
        return "kibana", dashboard_object_path(asset, object_type, ident), {"kbn-xsrf": "true"}
    if kind in {"kibana_spaces", "kibana_roles"}:
        return "kibana", kibana_path(Asset(kind, name, "", b"")), {"kbn-xsrf": "true"}
    if kind in {"component_templates", "index_templates", "pipelines", "transforms", "security_roles"}:
        return "es", es_path(Asset(kind, name, "", b"")), None
    raise ProvisionError("install refused: transaction_journal_invalid")


def _rollback_live_hash(es_url: str, kb_url: str, authorization: str, intent: dict) -> str:
    target, path, headers = _rollback_asset_path(intent)
    try:
        live = json_response(request(es_url if target == "es" else kb_url, path, "GET", authorization, headers=headers))
    except RequestFailure as error:
        if error.status == 404:
            return asset_adapters.dashboard_absent_hash()
        raise
    return asset_adapters.sha256(asset_adapters.get_projection(intent["kind"], live))


def _delete_or_absent(base: str, path: str, authorization: str, headers: dict[str, str] | None = None) -> None:
    try:
        mutation_request(base, path, "DELETE", authorization, headers=headers)
    except RequestFailure as error:
        if error.status != 404:
            raise


_PIPELINE_IN_USE_REASON = "cannot be deleted because it is the default pipeline for"


def _pipeline_in_use_indices(error: RequestFailure) -> dict | None:
    """Return the indices from ES's non-overridable default-pipeline guard.

    This is deliberately narrower than a generic 400 handler: only the exact
    Elasticsearch delete guard means that restoring the recorded absent
    preimage is impossible.  All other delete failures remain fail-loud.
    """
    if error.status != 400:
        return None
    try:
        response = parse_json(error.body, "pipeline delete response")
    except InputError:
        return None
    if not isinstance(response, dict):
        return None
    causes = response.get("root_cause")
    nested = response.get("error")
    if causes is None and isinstance(nested, dict):
        causes = nested.get("root_cause")
    if not isinstance(causes, list) or not causes or not isinstance(causes[0], dict):
        return None
    cause = causes[0]
    reason = cause.get("reason")
    if cause.get("type") != "illegal_argument_exception" or not isinstance(reason, str):
        return None
    if _PIPELINE_IN_USE_REASON not in reason:
        return None
    match = re.search(r"\bincluding\s*\[([^\]]*)\]", reason)
    if match is None:
        return {"referencing_indices": [], "raw_reason": reason}
    return {"referencing_indices": [name.strip() for name in match.group(1).split(",") if name.strip()]}


def _retained_pipeline_report_details(root: Path) -> list[str]:
    """Return one-line-safe operator details from retained-pipeline journal intents."""
    journal = TransactionJournal(root, "fleet-coexist")
    details = []
    for intent in journal.value["intents"]:
        retained = intent.get("pipeline_retained_in_use")
        if not isinstance(retained, dict):
            continue
        name = intent.get("name")
        if not isinstance(name, str):
            raise ProvisionError("install refused: transaction_journal_invalid")
        reason = retained.get("raw_reason")
        if isinstance(reason, str):
            detail = "raw_reason: " + json.dumps(reason, ensure_ascii=False)
        else:
            indices = retained.get("referencing_indices")
            if not isinstance(indices, list) or not all(isinstance(index, str) for index in indices):
                raise ProvisionError("install refused: transaction_journal_invalid")
            detail = "referencing_indices: " + json.dumps(
                sorted(indices), ensure_ascii=False, separators=(",", ":"))
        details.append((name, detail))
    return [name + "; " + detail for name, detail in sorted(details)]


def _restore_transform_without_pivot(es_url: str, path: str, authorization: str, body: dict) -> None:
    """Issue the transform inverse, with a gate-only rejection injector.

    ``RIGSIGNAL_TEST_TRANSFORM_META_RESTORE_REJECT=1`` is inert unless a
    clean-stack gate explicitly requests the ES-rejection fallback rehearsal.
    """
    if os.environ.get("RIGSIGNAL_TEST_TRANSFORM_META_RESTORE_REJECT") == "1":
        raise RequestFailure(400, "test transform _meta restore rejection")
    mutation_request(es_url, path + "/_update", "POST", authorization, jcs(body))


def _transform_stats_state(es_url: str, path: str, authorization: str) -> str:
    """Return the single transform state; state is part of its preimage."""
    try:
        stats = json_response(request(es_url, path + "/_stats", "GET", authorization))
        transforms = stats.get("transforms") if isinstance(stats, dict) else None
        state = (transforms[0].get("state") if isinstance(transforms, list) and len(transforms) == 1
                 and isinstance(transforms[0], dict) else None)
    except (InputError, RequestFailure, ValueError) as error:
        raise InputError("transform state is invalid") from error
    if not isinstance(state, str):
        raise InputError("transform state is invalid")
    return state


def transform_preapply_restore_proven(es_url: str, authorization: str, asset: Asset,
                                      preimage: dict, preimage_state: str) -> bool:
    """Prove absent-_meta restoration *before* this transaction applies it.

    The rehearsal is deliberately confined to the target transform and restores
    its captured request body immediately.  A failed absence proof is not an
    apply-time surprise: the caller journals verify-only and skips apply.
    """
    if "_meta" in preimage:
        return True
    path = es_path(asset)
    desired = parse_json(asset.data, asset.path)
    if not isinstance(desired, dict):
        raise InputError("transform body is invalid")
    try:
        mutation_request(es_url, path + "/_update", "POST", authorization,
                jcs({key: value for key, value in desired.items() if key != "pivot"}))
        _restore_transform_without_pivot(
            es_url, path, authorization,
            {key: value for key, value in preimage.items() if key != "pivot"})
        live = asset_adapters.get_projection(
            "transforms", json_response(request(es_url, path, "GET", authorization)))
        if live != asset_adapters.get_projection("transforms", preimage):
            return False
        return _transform_stats_state(es_url, path, authorization) == preimage_state
    except (InputError, RequestFailure, ValueError, asset_adapters.AdapterError):
        # This is precisely the compatibility gate: an unproven version gets
        # the verify-only path, not a later best-effort rollback.
        return False


def transform_preapply_requires_verify_only(journal: TransactionJournal, record: dict, es_url: str,
                                            authorization: str, asset: Asset) -> bool:
    """Return whether an existing transform lacks a proven absent-_meta restore.

    A journaled absent preimage represents a transform that did not exist at
    all.  It has no state or body to rehearse, and must continue through the
    ordinary create and post-create verification path.
    """
    if record.get("preimage_absent") is True:
        return False
    preimage_body = record.get("preimage_body")
    preimage = (parse_json(_journal_body(journal, preimage_body), "journal preimage")
                if isinstance(preimage_body, dict) else None)
    state = record.get("preimage_stats_state")
    return (not isinstance(preimage, dict) or not isinstance(state, str)
            or not transform_preapply_restore_proven(es_url, authorization, asset, preimage, state))


def _fence_transaction_consumer(root: Path) -> None:
    """Make a published local consumer unable to use its key before revocation."""
    credentials = root / "credentials.toml"
    if not credentials.exists():
        return
    fenced = root / "fleet-coexist-fenced-credentials.toml"
    if fenced.exists():
        raise ProvisionError("install refused: transaction_journal_invalid")
    try:
        os.replace(credentials, fenced)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as error:
        raise ProvisionError("install refused: transaction_journal_invalid") from error


def _remove_transaction_publication(root: Path) -> None:
    """Remove only files published by this transaction; retain its audit journal."""
    secure_root(root)
    for name in ("credentials.toml", "fleet-coexist-fenced-credentials.toml", "handshake.toml",
                 "shipping-policy-v1.toml", "state.json", OWNERSHIP_PROFILE_FILE):
        path = root / name
        if path.exists():
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                raise ProvisionError("install refused: transaction_journal_invalid")
            path.unlink()
    remove_candidate_root(root)


_ROLLBACK_ORDER = {"dashboard": 0, "kibana_roles": 1, "kibana_spaces": 2,
                   "transforms": 3, "pipelines": 4, "security_roles": 5,
                   "index_templates": 6, "component_templates": 7}


def _recovery_sweep(kb_url: str, authorization: str, active: dict) -> list[str]:
    """Delete regenerated dashboard derivatives recorded by this transaction.

    This is deliberately a degradation-only recovery aid: malformed journal
    intents and every Kibana read/delete failure are reported per intent and
    never prevent the journaled inverse from completing.
    """
    operations: list[str] = []
    triples: dict[tuple[str, str, str], list[dict]] = {}
    try:
        intents = active.get("intents", []) if isinstance(active, dict) else []
        if not isinstance(intents, list):
            raise ValueError("dashboard intents malformed")
    except Exception:
        return ["unverified-orphan:dashboard/unknown"]
    for intent in intents:
        if not isinstance(intent, dict) or intent.get("kind") != "dashboard":
            continue
        try:
            name, object_id = intent["name"], intent["object_id"]
            if not isinstance(name, str) or not isinstance(object_id, str):
                raise ValueError("missing dashboard intent identity")
            object_type, separator, object_id_value = object_id.partition("/")
            if not separator or not object_type or not object_id_value:
                raise ValueError("malformed dashboard object identity")
            target = dashboard_target_space(name)
            triples.setdefault((object_type, object_id_value, target), []).append(intent)
        except Exception:
            suffix = intent.get("name") if isinstance(intent, dict) else None
            operations.append("unverified-orphan:dashboard/" + (str(suffix) if suffix else "unknown"))
    for (object_type, literal_id, target_space), intents in triples.items():
        try:
            rows = _strict_saved_object_find(kb_url, authorization, target_space, object_type)
            for row in rows:
                physical_id = row["id"]
                if physical_id == literal_id or row.get("originId") != literal_id:
                    continue
                # This is the installer adapter projection, intentionally not
                # a second document-spec canonicalizer.
                live_hash = asset_adapters.sha256(asset_adapters.get_projection("dashboard", row))
                if live_hash != intents[0].get("intended_after_sha256"):
                    print(json.dumps(row, sort_keys=True))
                try:
                    mutation_request(kb_url, space_prefix(target_space) + "/api/saved_objects/"
                            + urllib.parse.quote(object_type, safe="") + "/"
                            + urllib.parse.quote(physical_id, safe=""), "DELETE", authorization,
                            headers={"kbn-xsrf": "true"})
                except RequestFailure as error:
                    if error.status != 404:
                        raise
                fault("after-regen-cleanup-delete", f"{object_type}/{physical_id}")
            # A single final read is the convergence proof; persistent hits
            # are degraded, never re-looped.
            final_rows = _strict_saved_object_find(kb_url, authorization, target_space, object_type)
            if any(row["id"] != literal_id and row.get("originId") == literal_id for row in final_rows):
                operations.append(f"unverified-orphan:dashboard/{object_type}/{literal_id}/{target_space}")
        except Exception:
            operations.append(f"unverified-orphan:dashboard/{object_type}/{literal_id}/{target_space}")
    return operations


def rollback_transaction(es_url: str, kb_url: str, authorization: str, root: Path,
                         deliberately_reversed: bool = True,
                         bundle_path: Path | None = None) -> list[str]:
    """Execute the RD §5 inverse from a secured root, never from the manifest.

    The return value is an auditable operation sequence used by mocked-transport
    tests; production ignores it after a successful verify-oracle pass.
    """
    journal = TransactionJournal(root, "fleet-coexist")
    active = newest_non_rolled_back_transaction(journal)
    # Resolve all canonical/fixture authority before even recovery reads.  In
    # particular, a staged engine must never discover after a DELETE/PUT that
    # it was about to substitute its absent ROOT tree for the applied bundle.
    verified_bundle = rollback_verified_bundle(journal, bundle_path)
    fleet_before = None
    fence = active.get("fleet_fence")
    plan = fence.get("plan") if isinstance(fence, dict) else None
    if isinstance(plan, dict):
        journaled_pre = {}
        for stream, entry in plan.items():
            pre = entry.get("pre") if isinstance(entry, dict) else None
            if (isinstance(stream, str) and isinstance(pre, dict)
                    and isinstance(pre.get("backing"), list)):
                # G3-min compares this durable preimage with a second snapshot
                # after reversal; backing remains the independent rollover oracle.
                journaled_pre[stream] = {"backing": deepcopy(pre["backing"])}
                if isinstance(pre.get("stream_state"), dict):
                    journaled_pre[stream]["stream_state"] = deepcopy(pre["stream_state"])
        if journaled_pre:
            fleet_before = journaled_pre
    # P6 never restores a data-stream topology.  Observe it once, before the
    # reversal, then compare it with the transaction's durable pre-window plan.
    fleet_after = fleet_stream_snapshot(es_url, authorization) if fleet_before is not None else None
    unswept_operations = _recovery_sweep(kb_url, authorization, active)
    verify_rollback_external_baselines(es_url, authorization, journal, bundle_path, verified_bundle)
    actions = journal_recovery_actions(journal,
        lambda intent: _rollback_live_hash(es_url, kb_url, authorization, intent))
    operations: list[str] = []
    for intent in journal.value.get("intents", []):
        if intent.get("kind") == "transforms" and intent.get("verify_only") is True:
            operations.append("verify-only:transforms/" + str(intent.get("name")))
    marker = [item for item in actions if item.get("kind") == "component_templates" and item.get("name") == "rigsignal-bundle-meta"]
    for intent in marker:
        marker_path = es_path(Asset("component_templates", "rigsignal-bundle-meta", "", b""))
        if intent.get("preimage_absent"):
            _delete_or_absent(es_url, marker_path, authorization)
        else:
            preimage = parse_json(_journal_body(journal, intent.get("preimage_body")), "journal preimage")
            body = asset_adapters.request_body_from_preimage("component_templates", preimage)
            if not isinstance(body, dict):
                raise ProvisionError("install refused: transaction_journal_invalid")
            mutation_request(es_url, marker_path, "PUT", authorization, jcs(body))
        operations.append("marker")
    _fence_transaction_consumer(root); operations.append("fence")
    for item in journal.value.get("intents", []):
        if item.get("kind") != "api_key":
            continue
        key_id = item.get("key_id")
        if isinstance(key_id, str) and key_id:
            invalidate(es_url, authorization, [key_id])
        elif isinstance(item.get("name"), str):
            invalidate_mint_name(es_url, authorization, item["name"])
        else:
            raise ProvisionError("install refused: transaction_journal_invalid")
        operations.append("revoke")
    _remove_transaction_publication(root); operations.append("publication")
    # This is the sole production rollback caller of the §8 exact-ID helper.
    rollback_transaction_proofs(es_url, authorization, journal, deliberately_reversed=deliberately_reversed)
    if journal.value.get("proofs"):
        operations.append("proofs")
    for intent in sorted((item for item in actions if item not in marker),
                         key=lambda item: _ROLLBACK_ORDER.get(item.get("kind"), -1)):
        target, path, headers = _rollback_asset_path(intent)
        base = es_url if target == "es" else kb_url
        if intent.get("preimage_absent"):
            try:
                _delete_or_absent(base, path, authorization, headers)
            except RequestFailure as error:
                indices = (_pipeline_in_use_indices(error)
                           if intent.get("kind") == "pipelines" else None)
                if indices is None:
                    raise
                intent["pipeline_retained_in_use"] = indices
                journal._persist()
                operations.append("retained-in-use:pipelines/" + str(intent.get("name")))
                continue
        else:
            raw = _journal_body(journal, intent.get("preimage_body"))
            preimage = parse_json(raw, "journal preimage")
            body = asset_adapters.request_body_from_preimage(intent["kind"], preimage)
            if body is None:
                _delete_or_absent(base, path, authorization, headers)
            else:
                if intent["kind"] == "transforms" and isinstance(body, dict):
                    body = dict(body); body.pop("pivot", None)
                    _restore_transform_without_pivot(es_url, path, authorization, body)
                if intent["kind"] != "transforms":
                    mutation_request(base, path, "PUT", authorization, jcs(body), headers)
        operations.append("asset:" + str(intent.get("kind")) + "/" + str(intent.get("name")))
    for intent in actions:
        if intent in marker:
            continue
        if intent.get("pipeline_retained_in_use") is not None:
            continue
        expected = intent.get("preimage_sha256")
        if not isinstance(expected, str) or _rollback_live_hash(es_url, kb_url, authorization, intent) != expected:
            raise ProvisionError("install refused: rollback_verify_failed")
        if intent.get("kind") == "transforms":
            state = intent.get("preimage_stats_state")
            target, path, _headers = _rollback_asset_path(intent)
            if (target != "es" or (state is not None and
                                    (not isinstance(state, str)
                                     or _transform_stats_state(es_url, path, authorization) != state))):
                raise ProvisionError("install refused: rollback_verify_failed")
    verify_m1_anchors(es_url, authorization, journal.value.get("m1_anchors", {}))
    if fleet_before is not None:
        changed = []
        for stream in sorted(fleet_before):
            before = fleet_before.get(stream, {})
            after = fleet_after.get(stream, {}) if fleet_after is not None else {}
            if (isinstance(before, dict) and isinstance(after, dict)
                    and jcs(before.get("backing")) != jcs(after.get("backing"))):
                changed.append({"stream": stream, "pre_backing": before.get("backing"),
                                "post_backing": after.get("backing")})
        if changed:
            journal.value.setdefault("fleet_fence", {})["external_rollover_observed"] = True
            journal.value["fleet_fence"]["external_rollovers"] = changed
            operations.append("external_rollover_observed")
            plan_entries = plan if isinstance(plan, dict) else {}
            reports = []
            for item in changed:
                entry = plan_entries.get(item["stream"])
                status = (entry.get("classification", {}).get("status")
                          if isinstance(entry, dict) else None)
                if status not in {"L3", "L3-C"}:
                    continue
                # Journaled pre pairs are JSON lists; the live snapshot builds
                # tuples — accept both or the loop silently skips every pair.
                pre_names = {pair[0] for pair in item["pre_backing"] if isinstance(pair, (list, tuple)) and len(pair) == 2}
                for pair in item["post_backing"]:
                    if not isinstance(pair, (list, tuple)) or len(pair) != 2 or pair[0] in pre_names:
                        continue
                    index = pair[0]
                    try:
                        quoted = urllib.parse.quote(index, safe="")
                        reports.append({"stream": item["stream"], "index": index,
                                        "settings": es_json(es_url, "/" + quoted + "/_settings", "GET", authorization),
                                        "mappings": es_json(es_url, "/" + quoted + "/_mapping", "GET", authorization),
                                        "lifecycle": es_json(es_url, "/" + quoted + "/_ilm/explain", "GET", authorization)})
                    except (InputError, RequestFailure) as error:
                        # R5 reporting must never make a completed reversal fail.
                        reports.append({"stream": item["stream"], "index": index,
                                        "evidence_error": str(error)})
            if reports:
                journal.value["fleet_fence"]["rollover_under_installer_template"] = reports
                operations.append("rollover_under_installer_template")
        # G3-min is intentionally raw/report-only: no causal classification,
        # restoration, or rollback-completion decision is derived from it.
        post_reversal = fleet_stream_snapshot(es_url, authorization)
        stream_state_diffs = []
        for stream in sorted(fleet_before):
            before = fleet_before[stream]
            after = post_reversal.get(stream, {}) if isinstance(post_reversal, dict) else {}
            if (isinstance(before, dict) and isinstance(before.get("stream_state"), dict)
                    and isinstance(after, dict)):
                ops = rfc6901_diff({"stream_state": before.get("stream_state")},
                                  {"stream_state": after.get("stream_state")})
                if ops:
                    stream_state_diffs.append({"stream": stream, "ops": ops})
        journal.value.setdefault("fleet_fence", {})["post_reversal_stream_state_diffs"] = stream_state_diffs
    journal.value["rollback_ok"] = True
    journal._persist()
    operations.extend(unswept_operations)
    return operations


def _fd_identity(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def _name_has_identity(parent_fd: int, name: bytes, identity: tuple[int, int]) -> bool:
    try:
        return _fd_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == identity
    except OSError:
        return False


def _read_publication_member(root_fd: int, name: bytes) -> bytes | None:
    """Read an optional source through its held root fd, never a pathname."""
    try:
        # O_NONBLOCK: a FIFO planted at an optional name must not block the
        # open before the S_ISREG check below can reject it; harmless for
        # regular files.
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
    except FileNotFoundError:
        return None
    try:
        member = os.fstat(fd)
        if (not stat.S_ISREG(member.st_mode) or member.st_uid != os.geteuid()
                or member.st_mode & 0o077 or not _name_has_identity(root_fd, name, _fd_identity(member))):
            raise InputError("enrollment publication source is invalid")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def _write_publication_member(stage_fd: int, name: bytes, data: bytes) -> None:
    """Write one final stage member directly beneath the held private fd."""
    if not _publication_member_name(name):
        raise InputError("invalid enrollment publication member")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=stage_fd)
    try:
        # open(2)'s mode is masked by the umask; the membership assert requires
        # exactly 0600, so pin it explicitly (a 0277 umask would otherwise fail
        # every install after the remote key mint).
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(errno.EIO, "short enrollment publication write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _assert_publication_members(stage_fd: int, intended: set[bytes]) -> None:
    # btrfs (kernel >= 6.5, commit 357950361cbc) freezes a directory fd's
    # readdir cutoff at open time: stage_fd was opened on the EMPTY stage, so
    # listing through it never returns the members written afterwards.  List
    # through a fresh description anchored at the held fd instead — "." cannot
    # resolve anywhere else, so this stays fd-anchored on every filesystem.
    list_fd = os.open(b".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=stage_fd)
    try:
        actual = {os.fsencode(name) for name in os.listdir(list_fd)}
    finally:
        os.close(list_fd)
    if actual != intended or not all(_publication_member_name(name) for name in actual):
        raise InputError("enrollment publication stage membership is invalid")
    for name in actual:
        member = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
        if (not stat.S_ISREG(member.st_mode) or stat.S_ISLNK(member.st_mode)
                or member.st_uid != os.geteuid() or stat.S_IMODE(member.st_mode) != 0o600):
            raise InputError("enrollment publication stage member is invalid")
    os.fsync(stage_fd)


def _remove_candidate_root_fd(root_fd: int) -> None:
    """Remove a validated old-generation candidate through its parent fd."""
    try:
        candidate_fd = os.open(b"candidate", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
                               | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
    except FileNotFoundError:
        return
    try:
        candidate_st = os.fstat(candidate_fd)
        if not _private_directory(candidate_st):
            raise InputError("old enrollment generation is invalid")
        allowed = set(_PUBLICATION_REQUIRED_MEMBERS)
        entries = {os.fsencode(name) for name in os.listdir(candidate_fd)}
        if not entries.issubset(allowed):
            raise InputError("old enrollment generation is invalid")
        for name in entries:
            entry = os.stat(name, dir_fd=candidate_fd, follow_symlinks=False)
            if (not stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode)
                    or entry.st_uid != os.geteuid() or entry.st_mode & 0o077):
                raise InputError("old enrollment generation is invalid")
            os.unlink(name, dir_fd=candidate_fd)
        if not _name_has_identity(root_fd, b"candidate", _fd_identity(candidate_st)):
            raise InputError("old enrollment generation is invalid")
        os.rmdir(b"candidate", dir_fd=root_fd)
    finally:
        os.close(candidate_fd)


def _remove_old_enrollment_generation_fd(root_fd: int, parent_fd: int, stage_name: bytes,
                                         root_identity: tuple[int, int]) -> None:
    """Confined old-generation cleanup using only held descriptors and dirfds."""
    if not _private_directory(os.fstat(root_fd)):
        raise InputError("old enrollment generation is invalid")
    allowed = set(_PUBLICATION_REQUIRED_MEMBERS) | set(_PUBLICATION_OPTIONAL_MEMBERS) | {b"candidate"}
    # Fresh "."-anchored description for the listing: the pre-exchange abort
    # caller passes the stage fd, which was opened on the EMPTY stage — btrfs
    # freezes a dir fd's readdir cutoff at open time, so listing through it
    # would miss every member written afterwards (same class as
    # _assert_publication_members' fix; safe for both callers).
    list_fd = os.open(b".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=root_fd)
    try:
        entries = {os.fsencode(name) for name in os.listdir(list_fd)}
    finally:
        os.close(list_fd)
    if not all(name in allowed or name.startswith(b"fleet-coexist-body-") for name in entries):
        raise InputError("old enrollment generation is invalid")
    for name in entries:
        if name == b"candidate":
            continue
        entry = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (not stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode)
                or entry.st_uid != os.geteuid() or entry.st_mode & 0o077):
            raise InputError("old enrollment generation is invalid")
        os.unlink(name, dir_fd=root_fd)
    if b"candidate" in entries:
        _remove_candidate_root_fd(root_fd)
    if not _name_has_identity(parent_fd, stage_name, root_identity):
        raise InputError("old enrollment generation changed before removal")
    os.rmdir(stage_name, dir_fd=parent_fd)


def _rename_exchange(old_dir_fd: int, old_name: bytes, new_dir_fd: int, new_name: bytes) -> None:
    """Use renameat2(RENAME_EXCHANGE) exactly through the supplied directory fds."""
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:
        # Defence-in-depth: preflight's symbol gate makes this unreachable, but
        # an AttributeError here must surface as the documented OSError path,
        # never a raw traceback that skips finalize_failure.
        raise OSError(errno.ENOSYS, "renameat2 symbol unavailable") from error
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    if renameat2(old_dir_fd, old_name, new_dir_fd, new_name, 2) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _publication_anchor(root: Path) -> tuple[Path, int, int, bytes, tuple[int, int]]:
    """Open and bind parent/root descriptors without mutating filesystem paths."""
    canonical = Path(os.path.abspath(os.fspath(root)))
    parent_fd = os.open(canonical.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0))
    try:
        if not _enrollment_parent_safe(os.fstat(parent_fd)):
            raise InputError("enrollment parent is not protected")
        root_name = os.fsencode(canonical.name)
        root_fd = os.open(root_name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
                          | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        root_st = os.fstat(root_fd)
        if not _private_directory(root_st) or not _name_has_identity(parent_fd, root_name, _fd_identity(root_st)):
            os.close(root_fd)
            raise InputError("enrollment root is not protected")
        return canonical, parent_fd, root_fd, root_name, _fd_identity(root_st)
    except Exception:
        os.close(parent_fd)
        raise


def atomic_publication(root: Path, files: dict[str, bytes],
                       failure_tracker: FailureSiteTracker | None = None) -> None:
    """Publish one complete generation via fd-anchored same-parent exchange."""
    parent_fd = root_fd = stage_fd = None
    stage_name = None
    root_identity = stage_identity = None
    exchanged = False
    preserve_stage = False
    try:
        for attempt in range(2):
            try:
                root, parent_fd, root_fd, root_name, root_identity = _publication_anchor(root)
                break
            except FileNotFoundError as error:
                if attempt:
                    if failure_tracker is not None:
                        failure_tracker.mark(FailureSite.PUBLICATION_ANCHOR)
                    raise InputError("enrollment publication anchor is unavailable") from error
                # Existing root preparation is the sole narrowly-scoped fallback.
                # Its own failure must land on PUBLICATION_ANCHOR too — an
                # exception raised here would bypass the sibling handler below.
                try:
                    root = secure_root(root)
                except (InputError, OSError) as fallback_error:
                    if failure_tracker is not None:
                        failure_tracker.mark(FailureSite.PUBLICATION_ANCHOR)
                    if isinstance(fallback_error, InputError):
                        raise
                    raise InputError("cannot publish enrollment output") from fallback_error
            except (InputError, OSError) as error:
                if failure_tracker is not None:
                    failure_tracker.mark(FailureSite.PUBLICATION_ANCHOR)
                if isinstance(error, InputError):
                    raise
                raise InputError("cannot publish enrollment output") from error
        else:  # pragma: no cover - the loop either breaks or raises
            raise AssertionError("publication anchor retry exhausted")

        if failure_tracker is not None:
            failure_tracker.mark(FailureSite.PUBLICATION_STAGE)
        for _ in range(8):
            candidate = _publication_stage_name(root)
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_fd)
                stage_name = candidate
                break
            except FileExistsError:
                continue
        if stage_name is None:
            raise InputError("cannot create enrollment publication stage")
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
                           | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        stage_st = os.fstat(stage_fd)
        if not _private_directory(stage_st) or not _name_has_identity(parent_fd, stage_name, _fd_identity(stage_st)):
            raise InputError("enrollment publication stage is not protected")
        stage_identity = _fd_identity(stage_st)

        intended: set[bytes] = set()
        for name in _PUBLICATION_REQUIRED_MEMBERS:
            key = os.fsdecode(name)
            _write_publication_member(stage_fd, name, files[key])
            intended.add(name)
            fault("publication-" + key)
        for name in _PUBLICATION_OPTIONAL_MEMBERS:
            value = _read_publication_member(root_fd, name)
            if value is not None:
                _write_publication_member(stage_fd, name, value)
                intended.add(name)
        # Same fresh-description idiom as the other listings (btrfs freezes a
        # dir fd's readdir cutoff at open time; also keeps this safe if a body
        # is ever created after anchoring, and avoids the shared-offset hazard
        # of listing the same fd twice).
        body_list_fd = os.open(b".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=root_fd)
        try:
            body_entries = os.listdir(body_list_fd)
        finally:
            os.close(body_list_fd)
        for entry in body_entries:
            name = os.fsencode(entry)
            if name.startswith(b"fleet-coexist-body-"):
                value = _read_publication_member(root_fd, name)
                if value is None:
                    raise InputError("transaction journal body is invalid")
                _write_publication_member(stage_fd, name, value)
                intended.add(name)
        _assert_publication_members(stage_fd, intended)
        fault("publication-before-exchange")
        if (not _name_has_identity(parent_fd, root_name, root_identity)
                or not _name_has_identity(parent_fd, stage_name, stage_identity)):
            # This is a terminal, pre-exchange identity dispute.  Preserve the
            # complete private stage as Bundle-A remediation evidence; a later
            # run must refuse for operator inspection rather than deleting it.
            # The stage holds an UNCOMMITTED minted credential: its lifecycle
            # closes on the rerun, whose incomplete-recovery path revokes the
            # pending mint by name from state.json — which is why remediation
            # must remove only the debris, never the root's candidate record.
            preserve_stage = True
            if failure_tracker is not None:
                failure_tracker.mark(FailureSite.PUBLICATION_IDENTITY)
                failure_tracker.detach_journal()
            raise InputError("enrollment publication identity changed")
        if failure_tracker is not None:
            failure_tracker.mark(FailureSite.PUBLICATION_EXCHANGE)
        _rename_exchange(parent_fd, root_name, parent_fd, stage_name)
        exchanged = True
        fault("publication-exchange")
        if (not _name_has_identity(parent_fd, root_name, stage_identity)
                or not _name_has_identity(parent_fd, stage_name, root_identity)):
            if failure_tracker is not None:
                failure_tracker.mark(FailureSite.PUBLICATION_IDENTITY)
                failure_tracker.detach_journal()
            try:
                os.fsync(parent_fd)
            except OSError:
                pass
            raise InputError("enrollment publication identity changed")
        fault("publication-post-exchange-pre-parent-fsync")
        try:
            os.fsync(parent_fd)
        except OSError as error:
            if failure_tracker is not None:
                failure_tracker.mark(FailureSite.PUBLICATION_CLEANUP)
            raise InputError("enrollment publication cleanup failed") from error
        fault("publication-post-parent-fsync-pre-cleanup")
        try:
            _remove_old_enrollment_generation_fd(root_fd, parent_fd, stage_name, root_identity)
            fault("publication-cleanup-before-final-parent-fsync")
            os.fsync(parent_fd)
        except (InputError, OSError) as error:
            if failure_tracker is not None:
                failure_tracker.mark(FailureSite.PUBLICATION_CLEANUP)
            if isinstance(error, InputError):
                raise
            raise InputError("enrollment publication cleanup failed") from error
    except OSError as error:
        raise InputError("cannot publish enrollment output") from error
    finally:
        if (not exchanged and not preserve_stage and stage_fd is not None
                and stage_name is not None and stage_identity is not None):
            try:
                _remove_old_enrollment_generation_fd(stage_fd, parent_fd, stage_name, stage_identity)
            except (InputError, OSError):
                pass
        for descriptor in (stage_fd, root_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def fault(point: str, argument: str | None = None) -> None:
    """Test-only crash hook supporting ``point`` and ``point:argument``."""
    trigger, colon, requested = os.environ.get("RIGSIGNAL_TEST_CRASH_AT", "").partition(":")
    if trigger != point or (colon and requested != argument):
        return
    if trigger == point:
        # os._exit skips interpreter cleanup INCLUDING stream flushing —
        # block-buffered stdout (redirected to a log) would silently drop
        # everything printed since the last flush, e.g. the
        # RIGSIGNAL_DASHBOARD_IMPORT_RESULT capture lines a gate leg asserts
        # on (solo leg-k at 698cdaf). Same discipline as test_pause.
        sys.stdout.flush()
        sys.stderr.flush()
        # Crash-edge tests model abrupt process death, not a cooperative
        # exception or a normal exit.  SIGKILL gives the subprocess contract
        # its observable ``-9`` status and still skips every cleanup handler.
        os.kill(os.getpid(), signal.SIGKILL)


def test_rollover(point: str, es_url: str, authorization: str,
                  snapshot: dict[str, object]) -> None:
    """Inject one deterministic Fleet-stream rollover for the clean-stack gate.

    ``RIGSIGNAL_TEST_ROLLOVER_AT`` has no effect unless its point name (before
    an optional ``:stream`` suffix) exactly names this point.  It is
    deliberately not a production rollover mechanism.
    """
    trigger, _, requested = os.environ.get("RIGSIGNAL_TEST_ROLLOVER_AT", "").partition(":")
    if trigger != point:
        return
    if not snapshot:
        raise InputError("fleet rollover test stream is unavailable")
    stream = requested or sorted(snapshot)[0]
    if stream not in snapshot:
        raise InputError("fleet rollover test stream is unavailable")
    mutation_request(es_url, "/" + urllib.parse.quote(stream, safe="") + "/_rollover", "POST", authorization)


def test_candidate_drift(point: str, es_url: str, authorization: str, snapshot: dict[str, object]) -> None:
    """Non-fatal test-only rollover hook for the candidate-proof interval."""
    test_rollover(point, es_url, authorization, snapshot)


def external_write_test_allowed(es_url: str, unsafe_test_injection: bool) -> bool:
    """Keep the deliberate external-write probe confined to local gate stacks."""
    parsed = urllib.parse.urlsplit(es_url)
    return (os.environ.get("RIGSIGNAL_TEST_EXTERNAL_WRITE") == "1"
            and unsafe_test_injection
            and parsed.hostname in {"127.0.0.1", "::1", "localhost"})


def test_halt(point: str, unsafe_test_injection: bool, endpoint: str, argument: str | None = None) -> None:
    """Raise a caught recovery failure at an exact local-gate boundary.

    Unlike ``fault`` (which models a real SIGKILL), this hook exercises the
    documented direct-engine exit-4 path after a durable possible-mutation
    edge.  It is intentionally unusable without the hidden unsafe flag and a
    loopback endpoint; normal installations leave it entirely inert.
    """
    trigger, colon, requested = os.environ.get("RIGSIGNAL_TEST_HALT_AT", "").partition(":")
    if (trigger != point or (colon and requested != argument)
            or not unsafe_test_injection):
        return
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise InputError("test halt requires a loopback endpoint")
    raise AssetTransactionHalt("partial-remote-possible")


def test_pause(point: str, unsafe_test_injection: bool, endpoint: str,
               argument: str | None = None) -> None:
    """Pause a gate subprocess only behind explicit, loopback-scoped controls.

    ``RIGSIGNAL_TEST_PAUSE_AT`` uses the same ``point[:target]`` grammar as
    ``fault``.  Production callers never pass ``unsafe_test_injection`` and
    the only production-path call sites provide the parsed endpoint, so an
    active pause cannot be used against a non-loopback deployment.
    """
    trigger, colon, requested = os.environ.get("RIGSIGNAL_TEST_PAUSE_AT", "").partition(":")
    if (trigger != point or (colon and requested != argument)
            or not unsafe_test_injection):
        return
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise InputError("test pause requires a loopback endpoint")
    sentinel = os.environ.get("RIGSIGNAL_TEST_PAUSE_SENTINEL")
    if not sentinel:
        raise InputError("test pause requested without a sentinel path")
    print(f"RIGSIGNAL_TEST_PAUSE_REACHED {point}", flush=True)
    sentinel_path = Path(sentinel)
    while not sentinel_path.exists():
        time.sleep(0.05)


def projection(asset: Asset, response: object) -> object:
    if not isinstance(response, dict):
        raise InputError("canonical GET projection is missing")
    if asset.kind == "component_templates":
        values = response.get("component_templates")
        key = "component_template"
    elif asset.kind == "index_templates":
        values = response.get("index_templates")
        key = "index_template"
    elif asset.kind == "security_roles":
        # Security GET returns {role_name: body}; exactly the named object is
        # allowed, preventing an envelope or plural response from passing.
        if set(response) != {asset.name}:
            raise InputError("canonical role GET projection is missing")
        role = _strip_server_metadata(response[asset.name], _ROLE_SERVER_KEYS, _ROLE_EMPTY_DEFAULT_KEYS)
        if isinstance(role, dict) and isinstance(role.get("indices"), list):
            # GET injects allow_restricted_indices into each grant; false is
            # the server default and is stripped, true is an escalation and
            # is deliberately kept so equality fails.
            role = dict(role)
            role["indices"] = [
                {k: v for k, v in entry.items() if not (k == "allow_restricted_indices" and v is False)}
                if isinstance(entry, dict) else entry
                for entry in role["indices"]
            ]
        return role
    else:
        raise InputError("canonical GET projection is unsupported")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise InputError("canonical GET projection is missing")
    item = values[0]
    if item.get("name") not in (None, asset.name) or key not in item:
        raise InputError("canonical GET projection is missing")
    return _strip_server_metadata(item[key], _TEMPLATE_SERVER_KEYS, ())


# Spec v2.1: "Server envelope/name/timestamp/order is not projected."  ES 9.4
# stamps GET responses with server-generated metadata that the request body
# never carried.  Exactly-known keys are stripped unconditionally; the
# empty-default keys are stripped only when empty, so an unexpected non-empty
# grant (e.g. an injected applications entry) still fails equality.
_TEMPLATE_SERVER_KEYS = ("created_date", "created_date_millis", "modified_date", "modified_date_millis")
_ROLE_SERVER_KEYS = ("transient_metadata",)
_ROLE_EMPTY_DEFAULT_KEYS = ("applications", "run_as", "metadata", "remote_indices", "remote_cluster", "global")


def _strip_server_metadata(body: object, drop: tuple, drop_if_empty: tuple) -> object:
    if not isinstance(body, dict):
        return body
    projected = {k: v for k, v in body.items() if k not in drop}
    for key in drop_if_empty:
        if key in projected and projected[key] in ([], {}, None):
            del projected[key]
    return projected


def _strip_empty_defaults_omitted_by_expected(body: object, expected: object) -> object:
    """Remove known server defaults only when the packaged role omits them."""
    if not isinstance(body, dict):
        return body
    expected_keys = expected if isinstance(expected, dict) else {}
    return {
        key: value for key, value in body.items()
        if not (key in _ROLE_EMPTY_DEFAULT_KEYS and key not in expected_keys and value in ([], {}, None))
    }


def _normalize_settings_scalars(body: object) -> object:
    """ES stores index settings as strings and returns them so on GET; render
    both sides' template.settings scalars in ES string form before equality."""
    if not isinstance(body, dict):
        return body
    normalized = dict(body)
    template = normalized.get("template")
    if isinstance(template, dict) and isinstance(template.get("settings"), dict):
        def render(value: object) -> object:
            if isinstance(value, bool):
                return "true" if value else "false"
            if isinstance(value, (int, float)):
                return str(value)
            if isinstance(value, dict):
                return {k: render(v) for k, v in value.items()}
            if isinstance(value, list):
                return [render(v) for v in value]
            return value
        template = dict(template)
        template["settings"] = render(template["settings"])
        normalized["template"] = template
    return normalized


def verify_asset(base: str, authorization: str, asset: Asset) -> None:
    response = json_response(request(base, es_path(asset), "GET", authorization))
    expected = parse_json(asset.data, asset.path)
    if asset.kind in {"component_templates", "index_templates", "security_roles"}:
        got = _normalize_settings_scalars(projection(asset, response))
        want = _normalize_settings_scalars(expected)
        if jcs(got) != jcs(want):
            raise InputError("canonical asset GET differs")


def verify_kibana_asset(base: str, authorization: str, asset: Asset) -> None:
    response = json_response(request(base, kibana_path(asset), "GET", authorization,
                                     headers={"kbn-xsrf": "true"}))
    expected = parse_json(asset.data, asset.path)
    if asset.kind == "kibana_spaces":
        got = response
        want = expected
    elif asset.kind == "kibana_roles":
        if not isinstance(response, dict) or not isinstance(expected, dict):
            raise InputError("canonical Kibana role GET projection is missing")
        got = {key: response.get(key) for key in ("elasticsearch", "kibana")}
        want = {key: expected.get(key) for key in ("elasticsearch", "kibana")}
        # Kibana can inject the native role API's empty defaults both beside
        # elasticsearch/kibana and within elasticsearch.  Include those keys
        # in the projection first so a non-empty injected privilege remains a
        # verification failure, then remove only omitted empty defaults.
        for key in _ROLE_EMPTY_DEFAULT_KEYS:
            if key in response:
                got[key] = response[key]
            if key in expected:
                want[key] = expected[key]
        got = _strip_empty_defaults_omitted_by_expected(got, want)
        elasticsearch = got.get("elasticsearch")
        expected_elasticsearch = want.get("elasticsearch")
        if isinstance(elasticsearch, dict) and isinstance(elasticsearch.get("indices"), list):
            # Kibana GET injects allow_restricted_indices into each grant;
            # false is the server default and is stripped, while true remains
            # an escalation that must fail the exact equality comparison.
            elasticsearch = dict(elasticsearch)
            elasticsearch["indices"] = [
                {k: v for k, v in entry.items() if not (k == "allow_restricted_indices" and v is False)}
                if isinstance(entry, dict) else entry
                for entry in elasticsearch["indices"]
            ]
        got["elasticsearch"] = _strip_empty_defaults_omitted_by_expected(
            elasticsearch, expected_elasticsearch)
    else:
        raise InputError("canonical Kibana asset GET projection is unsupported")
    if jcs(got) != jcs(want):
        raise InputError("canonical Kibana asset GET differs")


def verify_prepublication_assets(es_url: str, kb_url: str, authorization: str, bundle: Bundle,
                                 ownership_profile: str, ownership: dict[tuple[str, str], str],
                                 external_baselines: list[dict] | None = None,
                                 default_assets_managed: bool = False) -> None:
    """Recheck assets after candidate proof and before consumer publication."""
    for asset in bundle.assets:
        if (ownership_profile == "fleet-coexist"
                and ownership[(asset.kind, asset.name)] == "external"):
            # The external pre-write barrier is intentionally repeated here:
            # another Fleet change before publication is uncoordinated drift.
            record = verify_external_asset(es_url, authorization, asset)
            if external_baselines is not None:
                expected = next((item for item in external_baselines
                                 if item.get("kind") == asset.kind and item.get("name") == asset.name), None)
                if (not isinstance(expected, dict)
                        or expected.get("compatibility_projection_sha256")
                        != record.get("compatibility_projection_sha256")):
                    raise InputError("external compatibility baseline drifted")
        elif asset.kind in {"component_templates", "index_templates", "security_roles"}:
            verify_asset(es_url, authorization,
                         stamped_asset(asset) if default_assets_managed else asset)
        elif asset.kind in {"kibana_spaces", "kibana_roles"}:
            verify_kibana_asset(kb_url, authorization, asset)


def prepublication_asset_fence(es_url: str, kb_url: str, authorization: str, bundle: Bundle,
                               ownership_profile: str, ownership: dict[tuple[str, str], str],
                               external_baselines: list[dict] | None = None,
                               default_assets_managed: bool = False) -> None:
    """Expose every late asset drift through the stable publication-fence category."""
    try:
        verify_prepublication_assets(es_url, kb_url, authorization, bundle,
                                     ownership_profile, ownership, external_baselines,
                                     default_assets_managed)
    except (InputError, RequestFailure) as error:
        raise ProvisionError("install failed: pre-publication fence:") from error


def es_json(base: str, path: str, method: str, authorization: str, payload: object | None = None) -> object:
    data = None if payload is None else jcs(payload)
    return json_response(request(base, path, method, authorization, data))


def es_json_status(base: str, path: str, method: str, authorization: str,
                   payload: object | None = None) -> tuple[int, object]:
    data = None if payload is None else jcs(payload)
    try:
        status, body = request_response(base, path, method, authorization, data)
        return status, json_response(body)
    except RequestFailure as error:
        if not error.body:
            raise
        return error.status or 0, json_response(error.body)


def response_status(base: str, path: str, method: str, authorization: str,
                    payload: object | None = None) -> int:
    """Return only a status for authorization-matrix rows.

    Real write proofs deliberately use ``es_json`` directly: reducing a write
    response to a status code would hide ``_ignored`` and failure-store use.
    """
    try:
        return es_json_status(base, path, method, authorization, payload)[0]
    except RequestFailure as error:
        return error.status or 0


def stamped_asset(asset: Asset) -> Asset:
    """Render the default-profile ES ownership stamp into a request body.

    The stamp is an ownership proof, not a content digest.  It is added only
    to ES objects; Kibana saved objects deliberately use the protected local
    marker because their APIs cannot retain this metadata.
    """
    if asset.kind not in _ES_ASSET_KINDS:
        return asset
    body = parse_json(asset.data, asset.path)
    if not isinstance(body, dict):
        raise InputError("asset body is not an object")
    # The security-role API is the lone ES asset endpoint that persists its
    # caller metadata under ``metadata`` rather than ``_meta``.  In
    # particular, PUT /_security/role rejects (or does not retain) ``_meta``.
    metadata_key = "metadata" if asset.kind == "security_roles" else "_meta"
    meta = body.get(metadata_key)
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        raise InputError("asset " + metadata_key + " is invalid")
    body[metadata_key] = {**meta, "managed_by": RIGSIGNAL_MANAGED_BY}
    return Asset(asset.kind, asset.name, asset.path, jcs(body))


def _asset_marker_default_path() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return state_home / "rigsignal" / "assets" / ASSETS_MARKER_FILE


def _asset_marker_old_default_path() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return state_home / "rigsignal" / ASSETS_MARKER_FILE


def _validate_assets_marker_shared_parent(path: Path) -> None:
    """Reject a writable or substituted shared state root before using its leaf."""
    _reject_symlinked_path(path)
    try:
        st = path.lstat()
    except OSError as error:
        raise InputError("assets marker directory is not protected") from error
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
            or st.st_uid != os.geteuid() or st.st_mode & 0o022):
        raise InputError("assets marker directory is not protected")


def _prepare_assets_marker_path(path: Path | None, bundle: Bundle) -> Path:
    """Preflight the marker destination and reject the old implicit default.

    An explicit path remains verbatim and is never a legacy-marker destination.
    ``atomic_write`` still rechecks the selected leaf when it publishes the
    marker; this preflight moves that deterministic local fault before writes.
    """
    explicit = path is not None
    marker_path = path if explicit else _asset_marker_default_path()
    try:
        if marker_path.name != ASSETS_MARKER_FILE:
            raise InputError("assets marker path is invalid")
        if explicit:
            # Do not repair or chmod a caller-selected directory.  secure_root
            # performs the same no-symlink/owner/no-group-or-other-bit checks
            # that the later atomic write will require.
            secure_root(marker_path.parent)
            return marker_path

        shared_parent = marker_path.parent.parent
        # Check before and after creating the private leaf: a writable shared
        # parent could otherwise replace that leaf between validation and use.
        # Supplying a mode for this leaf avoids inheriting a group-writable
        # ``rigsignal/`` from a permissive umask when state storage is fresh;
        # an existing shared directory is never chmod-repaired.
        # These lexical checks must precede mkdir: ``mkdir(parents=True)``
        # would otherwise follow a substituted XDG-state ancestor while
        # creating the shared parent or private leaf.
        _reject_symlinked_path(shared_parent)
        _reject_symlinked_path(marker_path.parent)
        shared_parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        _validate_assets_marker_shared_parent(shared_parent)
        secure_root(marker_path.parent)
        _validate_assets_marker_shared_parent(shared_parent)
        leaf = marker_path.parent.lstat()
        if stat.S_IMODE(leaf.st_mode) != 0o700:
            raise InputError("assets marker directory is not protected")

        old_marker = _asset_marker_old_default_path()
        try:
            old_marker.lstat()
        except FileNotFoundError:
            return marker_path
        if marker_path.exists():
            return marker_path
        # Do not automatically migrate the former shared-directory marker.
        # A source pathname may be rebound after its validation.  Python's
        # stdlib can link an opened inode on Linux through /proc/self/fd, but
        # has no atomic compare-and-unlink operation for the old directory
        # entry.  A post-link unlink could therefore remove a rebinding rather
        # than the validated source.  Refuse before reading or linking it so
        # both the source-rebind and destination-creation races fail closed.
        raise ProvisionError(f"install refused: assets_marker_directory; remove the legacy marker at {old_marker}")
    except (InputError, OSError, ValueError) as error:
        raise ProvisionError("install refused: assets_marker_directory") from error


def _asset_marker_identities(bundle: Bundle) -> list[dict[str, str]]:
    return [{"kind": asset.kind, "name": asset.name} for asset in bundle.assets]


def _read_assets_marker_record(path: Path, bundle: Bundle) -> tuple[str | None, set[tuple[str, str]]]:
    """Return a validated marker version and complete identity set.

    A version mismatch is a transition decision, not malformed ownership
    evidence.  Callers that only need current-version proof use the wrapper
    below; the planner uses this record to decide whether an explicit version
    flag authorizes a transition.
    """
    if not path.exists():
        return None, set()
    value = parse_json(protected_regular_file(path), ASSETS_MARKER_FILE)
    if (not isinstance(value, dict)
            or set(value) != {"schema_version", "bundle_version", "source_commit", "identities"}
            or value.get("schema_version") != ASSETS_MARKER_SCHEMA_VERSION
            or not isinstance(value.get("bundle_version"), str)
            or not value["bundle_version"]
            or not isinstance(value.get("source_commit"), str)
            or not value["source_commit"]
            or not isinstance(value.get("identities"), list)):
        raise InputError("assets marker is invalid")
    identities: set[tuple[str, str]] = set()
    for item in value["identities"]:
        if (not isinstance(item, dict) or set(item) != {"kind", "name"}
                or item.get("kind") not in {*_ES_ASSET_KINDS, "dashboard", "kibana_spaces", "kibana_roles"}
                or not isinstance(item.get("name"), str) or not item["name"]):
            raise InputError("assets marker is invalid")
        identity = (item["kind"], item["name"])
        if identity in identities:
            raise InputError("assets marker is invalid")
        identities.add(identity)
    if identities != {(asset.kind, asset.name) for asset in bundle.assets}:
        raise InputError("assets marker is invalid")
    return value["bundle_version"], identities


def _read_assets_marker(path: Path, bundle: Bundle) -> set[tuple[str, str]]:
    """Return current-version marker proof, never accepting a stale marker."""
    version, identities = _read_assets_marker_record(path, bundle)
    if version is not None and version != bundle.version:
        raise InputError("assets marker is invalid")
    return identities


def _write_assets_marker(path: Path, bundle: Bundle) -> None:
    if path.name != ASSETS_MARKER_FILE:
        raise InputError("assets marker path is invalid")
    value = {"schema_version": ASSETS_MARKER_SCHEMA_VERSION, "bundle_version": bundle.version,
             "source_commit": bundle.source_commit, "identities": _asset_marker_identities(bundle)}
    atomic_write(path.parent, path.name, jcs(value) + b"\n")
    # The read-back proves both the atomic write and the 0600 ownership fence.
    if _read_assets_marker(path, bundle) != {(item["kind"], item["name"])
                                             for item in value["identities"]}:
        raise InputError("assets marker verification failed")


def _es_object_is_owned(response: object, asset: Asset) -> bool:
    try:
        body = asset_adapters.get_projection(asset.kind, response)
    except asset_adapters.AdapterError as error:
        raise RemoteReadRefusal("asset ownership response is invalid") from error
    metadata_key = "metadata" if asset.kind == "security_roles" else "_meta"
    return isinstance(body, dict) and isinstance(body.get(metadata_key), dict) and (
        body[metadata_key].get("managed_by") == RIGSIGNAL_MANAGED_BY)


def _semver_compare(left: str, right: str) -> int:
    """Compare the release versions accepted by bundle manifests."""
    expression = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\Z")

    def parse(value: str) -> tuple[tuple[int, int, int], tuple[tuple[int, object], ...] | None]:
        match = expression.fullmatch(value)
        if match is None:
            raise InputError("assets marker version is invalid")
        release = tuple(int(match.group(index)) for index in range(1, 4))
        prerelease = match.group(4)
        if prerelease is None:
            return release, None
        identifiers: list[tuple[int, object]] = []
        for identifier in prerelease.split("."):
            identifiers.append((0, int(identifier)) if identifier.isdigit() else (1, identifier))
        return release, tuple(identifiers)

    left_release, left_pre = parse(left)
    right_release, right_pre = parse(right)
    if left_release != right_release:
        return -1 if left_release < right_release else 1
    if left_pre is None or right_pre is None:
        if left_pre is right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_part, right_part in zip(left_pre, right_pre):
        if left_part != right_part:
            return -1 if left_part < right_part else 1
    return (left_pre > right_pre) - (left_pre < right_pre)


def _es_object_matches_bundle(response: object, asset: Asset) -> bool:
    try:
        live = asset_adapters.get_projection(asset.kind, response)
    except asset_adapters.AdapterError as error:
        raise RemoteReadRefusal("asset ownership response is invalid") from error
    desired = asset_adapters.get_projection(
        asset.kind, parse_json(stamped_asset(asset).data, asset.path))
    return asset_adapters.canonical_json(live) == asset_adapters.canonical_json(desired)


def _dashboard_present(kb_url: str, authorization: str, asset: Asset) -> bool:
    present = False
    for object_type, object_id in dashboard_objects(asset.data):
        try:
            request(kb_url, dashboard_object_path(asset, object_type, object_id), "GET", authorization,
                    headers={"kbn-xsrf": "true"})
            present = True
        except RequestFailure as error:
            if error.status != 404:
                raise
    return present


def _asset_presence(es_url: str, kb_url: str, authorization: str, asset: Asset) -> tuple[bool, object | None]:
    if asset.kind == "dashboard":
        return _dashboard_present(kb_url, authorization, asset), None
    base = es_url if asset.kind in _ES_ASSET_KINDS else kb_url
    path = es_path(asset) if asset.kind in _ES_ASSET_KINDS else kibana_path(asset)
    headers = None if asset.kind in _ES_ASSET_KINDS else {"kbn-xsrf": "true"}
    try:
        response = json_response(request(base, path, "GET", authorization, headers=headers))
    except RequestFailure as error:
        if error.status == 404:
            return False, None
        raise
    except InputError as error:
        raise RemoteReadRefusal("asset presence response is invalid") from error
    return True, response


def assets_ownership_plan(bundle: Bundle, es_url: str, kb_url: str, authorization: str,
                          marker_path: Path | None = None, *, repair: bool = False,
                          upgrade: bool = False, allow_downgrade: bool = False) -> list[tuple[Asset, str]]:
    """Read all 55 targets and return a write plan without issuing a mutation."""
    identities = {(asset.kind, asset.name) for asset in bundle.assets}
    if len(identities) != 55 or len(identities) != len(bundle.assets):
        raise InputError("assets-only bundle cardinality is invalid")
    marker_path = marker_path or _asset_marker_default_path()
    marker_version, marker_identities = _read_assets_marker_record(marker_path, bundle)
    transition = False
    if marker_version is not None and marker_version != bundle.version:
        direction = _semver_compare(marker_version, bundle.version)
        if direction < 0:
            if not upgrade:
                raise ProvisionError("install refused: assets_marker_upgrade_required")
        elif not allow_downgrade:
            raise ProvisionError("install refused: assets_marker_downgrade_required")
        transition = True
    plan: list[tuple[Asset, str]] = []
    for asset in bundle.assets:
        present, response = _asset_presence(es_url, kb_url, authorization, asset)
        if not present:
            plan.append((asset, "create"))
            continue
        if asset.kind in _ES_ASSET_KINDS:
            if not _es_object_is_owned(response, asset):
                raise AssetConflictUnproven()
            plan.append((asset, "noop" if _es_object_matches_bundle(response, asset) else "update"))
        elif (asset.kind, asset.name) in marker_identities:
            # Same-version Kibana drift detection is expressly out of scope;
            # the marker proves ownership, and an explicit maintenance mode
            # is allowed to re-apply only that proven-owned object.
            plan.append((asset, "noop"))
        else:
            raise AssetConflictUnproven()
    # Upgrade/downgrade are transition authorizations, not same-version force
    # modes.  ``--repair`` remains the explicit same-version re-apply path.
    force = repair or transition
    if force:
        plan = [(asset, "update" if action != "create" else action) for asset, action in plan]
    return plan


def assets_only_install(bundle: Bundle, es_url: str, kb_url: str, authorization: str,
                        marker_path: Path | None = None, *, repair: bool = False,
                        upgrade: bool = False, allow_downgrade: bool = False,
                        archive_sha256: str | None = None,
                        unsafe_test_injection: bool = False,
                        allow_untested_stack_version: bool = False) -> str:
    """Run the shared v2 default asset transaction for the assets-only caller."""
    marker_path = marker_path or _prepare_assets_marker_path(None, bundle)
    # All default-profile callers, including in-memory test callers, enter
    # the same v2 state machine.  An in-memory bundle has a deterministic
    # content digest; release CLI calls replace it with the protected archive
    # snapshot digest.
    prerequisites(es_url, kb_url, authorization, allow_untested=allow_untested_stack_version)
    binding = transaction_binding(bundle, cluster_uuid(es_url, authorization), kb_url,
                                  archive_sha256 or bundle_snapshot_digest(bundle))
    return run_default_asset_transaction(bundle, es_url, kb_url, authorization, marker_path,
                                         binding, full_flow=False, repair=repair,
                                         upgrade=upgrade, allow_downgrade=allow_downgrade,
                                         unsafe_test_injection=unsafe_test_injection)


def install_asset(es_url: str, kb_url: str, authorization: str, asset: Asset, *, managed: bool = False) -> object:
    if managed:
        asset = stamped_asset(asset)
    if asset.kind == "dashboard":
        body, boundary = multipart_dashboard(asset)
        response = json_response(mutation_request(
            kb_url, dashboard_import_path(asset), "POST", authorization, body,
            {"Content-Type": f"multipart/form-data; boundary={boundary}", "kbn-xsrf": "true"},
        ))
        assert_dashboard_import_result(asset, response)
        fault("after-dashboard-response-before-regen-check", f"{asset.kind}/{asset.name}")
        assert_no_id_regeneration(kb_url, authorization, asset, response)
        projection = {"file": asset.name,
                      "results": sorted(({"type": row["type"], "id": row["id"],
                                          "destinationId_present": "destinationId" in row,
                                          "destinationId": row.get("destinationId")}
                                         for row in response["successResults"]),
                                        key=lambda row: (row["type"], row["id"]))}
        projection_sha256 = hashlib.sha256(jcs(projection)).hexdigest()
        print("RIGSIGNAL_DASHBOARD_IMPORT_RESULT " + json.dumps(
            {**projection, "sha256": projection_sha256}, sort_keys=True))
        for object_type, object_id in dashboard_objects(asset.data):
            request(kb_url, dashboard_object_path(asset, object_type, object_id), "GET", authorization,
                    headers={"kbn-xsrf": "true"})
        return response
    if asset.kind == "kibana_spaces":
        headers = {"kbn-xsrf": "true"}
        try:
            status, _body = request_response(kb_url, kibana_path(asset), "GET", authorization,
                                             headers=headers)
        except RequestFailure as error:
            if error.status != 404:
                raise
            mutation_request(kb_url, "/api/spaces/space", "POST", authorization, asset.data, headers)
        else:
            if status != 200:
                raise InputError("Kibana space preflight returned an unexpected status")
            mutation_request(kb_url, kibana_path(asset), "PUT", authorization, asset.data, headers)
        verify_kibana_asset(kb_url, authorization, asset)
        return
    if asset.kind == "kibana_roles":
        mutation_request(kb_url, kibana_path(asset), "PUT", authorization, asset.data, {"kbn-xsrf": "true"})
        verify_kibana_asset(kb_url, authorization, asset)
        return
    path = es_path(asset)
    if asset.kind == "index_templates" and asset.name in {"metrics-rigsignal.profiles", "logs-rigsignal.stream"}:
        # This separately-decided owned template is safe to write only while
        # it remains uncomposed.  Re-read immediately before PUT, not merely
        # at preimage capture, so a concurrent Fleet adoption cannot be lost.
        try:
            current = json_response(request(es_url, path, "GET", authorization))
        except RequestFailure as error:
            if error.status != 404:
                raise
        else:
            try:
                body = asset_adapters.get_projection("index_templates", current)
            except asset_adapters.AdapterError as error:
                message = ("profiles composition is invalid" if asset.name == "metrics-rigsignal.profiles"
                           else "stream composition is invalid")
                raise InputError(message) from error
            if not isinstance(body, dict) or body.get("composed_of") != []:
                token = ("profiles_composed_of" if asset.name == "metrics-rigsignal.profiles"
                         else "stream_composed_of")
                raise ProvisionError("install refused: " + token)
    if asset.kind == "transforms":
        try:
            request(es_url, path, "GET", authorization)
        except RequestFailure as error:
            if error.status != 404:
                raise
            mutation_request(es_url, path, "PUT", authorization, asset.data)
        else:
            mutation_request(es_url, path + "/_update", "POST", authorization,
                    jcs({key: value for key, value in parse_json(asset.data, asset.path).items() if key != "pivot"}))
        request(es_url, path, "GET", authorization)
        return
    mutation_request(es_url, path, "PUT", authorization, asset.data)
    verify_asset(es_url, authorization, asset)


def _dashboard_expected_objects(asset: Asset) -> list[tuple[str, str, dict]]:
    values = []
    for line in asset.data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        value = parse_json(line.encode("utf-8"), asset.path)
        if not isinstance(value, dict) or not isinstance(value.get("type"), str) or not isinstance(value.get("id"), str):
            raise InputError("dashboard object is invalid")
        body = {"attributes": value.get("attributes", {})}
        if "references" in value:
            body["references"] = value["references"]
        values.append((value["type"], value["id"], body))
    return values


def journal_owned_asset(journal: TransactionJournal, es_url: str, kb_url: str, authorization: str,
                        asset: Asset, action: str) -> list[dict]:
    """Capture all intent records before an owned asset can issue a write."""
    if asset.kind == "dashboard":
        records = []
        for object_type, object_id, expected in _dashboard_expected_objects(asset):
            try:
                live = json_response(request(kb_url, dashboard_object_path(asset, object_type, object_id), "GET",
                                             authorization, headers={"kbn-xsrf": "true"}))
                projected = asset_adapters.get_projection("dashboard", live)
                preimage = asset_adapters.sha256(projected)
                preimage_body = jcs(projected)
            except RequestFailure as error:
                if error.status != 404:
                    raise
                preimage = asset_adapters.dashboard_absent_hash()
                preimage_body = None
            records.append(journal.write_intent("dashboard", asset.name, action, preimage,
                                                 asset_adapters.sha256(expected), jcs(expected),
                                                 object_id=f"{object_type}/{object_id}",
                                                 preimage_body=preimage_body))
        return records
    base = kb_url if asset.kind in {"kibana_spaces", "kibana_roles"} else es_url
    headers = {"kbn-xsrf": "true"} if base == kb_url else None
    path = kibana_path(asset) if base == kb_url else es_path(asset)
    preimage_stats_state = None
    try:
        live = json_response(request(base, path, "GET", authorization, headers=headers))
        projected = asset_adapters.get_projection(asset.kind, live)
        preimage = asset_adapters.sha256(projected)
        preimage_body = jcs(projected)
        if asset.kind == "transforms":
            preimage_stats_state = _transform_stats_state(es_url, path, authorization)
    except RequestFailure as error:
        if error.status != 404:
            raise
        preimage = asset_adapters.dashboard_absent_hash()
        preimage_body = None
    expected = parse_json(asset.data, asset.path)
    intended = asset_adapters.sha256(asset_adapters.get_projection(asset.kind, expected))
    records = [journal.write_intent(asset.kind, asset.name, action, preimage, intended, asset.data,
                                    preimage_body=preimage_body,
                                    preimage_stats_state=preimage_stats_state)]
    return records


def journal_verify_owned_asset(journal: TransactionJournal, records: list[dict], es_url: str, kb_url: str,
                               authorization: str, asset: Asset) -> None:
    if asset.kind == "dashboard":
        expected = {f"{kind}/{ident}": body for kind, ident, body in _dashboard_expected_objects(asset)}
        for record in records:
            object_id = record["object_id"]
            kind, ident = object_id.split("/", 1)
            live = json_response(request(kb_url, dashboard_object_path(asset, kind, ident), "GET", authorization,
                                         headers={"kbn-xsrf": "true"}))
            after = asset_adapters.sha256(asset_adapters.get_projection("dashboard", live))
            if after != record["intended_after_sha256"] or after != asset_adapters.sha256(expected[object_id]):
                raise InputError("dashboard saved-object verification differs")
            journal.write_verified(record, after)
        return
    # Existing installer verification remains the authoritative class-specific
    # check; the journal immediately pins the same canonical after state.
    if asset.kind in {"component_templates", "index_templates", "security_roles"}:
        verify_asset(es_url, authorization, asset)
    elif asset.kind in {"kibana_spaces", "kibana_roles"}:
        verify_kibana_asset(kb_url, authorization, asset)
        # Kibana's role/space GET envelopes carry endpoint-specific defaults;
        # verify_kibana_asset is the pinned installer projection for them.
        journal.write_verified(records[0], records[0]["intended_after_sha256"])
        return
    base = kb_url if asset.kind in {"kibana_spaces", "kibana_roles"} else es_url
    path = kibana_path(asset) if base == kb_url else es_path(asset)
    headers = {"kbn-xsrf": "true"} if base == kb_url else None
    live = json_response(request(base, path, "GET", authorization, headers=headers))
    after = asset_adapters.sha256(asset_adapters.get_projection(asset.kind, live))
    if after != records[0]["intended_after_sha256"]:
        raise InputError("journal verification differs")
    if asset.kind == "transforms":
        expected_state = records[0].get("preimage_stats_state")
        if (records[0].get("preimage_absent") is not True
                and (not isinstance(expected_state, str)
                     or _transform_stats_state(es_url, path, authorization) != expected_state)):
            raise InputError("transform state differs")
    journal.write_verified(records[0], after)


def load_predecessor_manifest(path: Path | None) -> dict | None:
    """Load the owner-ratified v1 predecessor allow-set artifact."""
    if path is None:
        return None
    try:
        value = parse_json(path.read_bytes(), "predecessor manifest")
    except OSError as error:
        raise InputError("predecessor manifest cannot be read") from error
    assets = value.get("assets") if isinstance(value, dict) else None
    if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(assets, dict):
        raise InputError("predecessor manifest is invalid")
    for key, entry in assets.items():
        hashes = entry.get("approved_sha256") if isinstance(entry, dict) else None
        if (not isinstance(key, str) or not isinstance(hashes, list) or not hashes
                or not all(isinstance(item, str) for item in hashes)):
            raise InputError("predecessor manifest is invalid")
    return value


def _predecessor_hash(es_url: str, kb_url: str, authorization: str, asset: Asset) -> str:
    """Read the same canonical preimage used by the mutation journal."""
    if asset.kind == "dashboard":
        values = _dashboard_predecessor_values(es_url, kb_url, authorization, asset)
        return hashlib.sha256(jcs(values)).hexdigest()
    base = kb_url if asset.kind in {"kibana_spaces", "kibana_roles"} else es_url
    path = kibana_path(asset) if base == kb_url else es_path(asset)
    try:
        live = json_response(request(base, path, "GET", authorization,
                                     headers={"kbn-xsrf": "true"} if base == kb_url else None))
    except RequestFailure as error:
        if error.status != 404:
            raise
        return asset_adapters.dashboard_absent_hash()
    return asset_adapters.sha256(asset_adapters.get_projection(asset.kind, live))


def _dashboard_predecessor_values(es_url: str, kb_url: str, authorization: str,
                                  asset: Asset) -> list[list[object]]:
    """Read dashboard predecessor projections in the whole-asset hash order."""
    values = []
    for kind, ident, _expected in _dashboard_expected_objects(asset):
        try:
            live = json_response(request(kb_url, dashboard_object_path(asset, kind, ident), "GET", authorization,
                                         headers={"kbn-xsrf": "true"}))
            values.append([kind, ident, asset_adapters.get_projection("dashboard", live)])
        except RequestFailure as error:
            if error.status != 404:
                raise
            values.append([kind, ident, "ABSENT"])
    return values


def _dashboard_predecessor_object_pins(es_url: str, kb_url: str, authorization: str,
                                       asset: Asset) -> list[list[str]]:
    """Hash each dashboard predecessor projection without changing its aggregate pin."""
    return [[kind, ident, hashlib.sha256(jcs(value)).hexdigest()]
            for kind, ident, value in _dashboard_predecessor_values(es_url, kb_url, authorization, asset)]


def _journaled_dashboard_after_pin(journal: TransactionJournal, object_type: str,
                                  object_id: str) -> str | None:
    """Return the latest verified dashboard after-pin, or refuse an incomplete write."""
    identity = object_type + "/" + object_id
    matching = [record for record in journal.value.get("intents", [])
                if (isinstance(record, dict) and record.get("kind") == "dashboard"
                    and record.get("object_id") == identity and record.get("action") != "noop")]
    if not matching:
        return None
    record = matching[-1]
    after = record.get("after_sha256")
    if (record.get("write_verified") is not True or not isinstance(after, str)
            or after != record.get("intended_after_sha256")):
        return ""
    return after


def recheck_dashboard_predecessor_pins(es_url: str, kb_url: str, authorization: str,
                                       asset: Asset, barrier_pins: list[list[str]],
                                       journal: TransactionJournal) -> None:
    """Require every dashboard object to match its barrier or journaled after-pin."""
    current_pins = _dashboard_predecessor_object_pins(es_url, kb_url, authorization, asset)
    barrier_by_identity = {(kind, ident): pin for kind, ident, pin in barrier_pins}
    for object_type, object_id, observed in current_pins:
        barrier = barrier_by_identity.get((object_type, object_id))
        if not isinstance(barrier, str):
            raise PredecessorRefusal(asset, object_type, object_id, "MISSING", observed, "barrier")
        journaled = _journaled_dashboard_after_pin(journal, object_type, object_id)
        if journaled is None:
            if observed != barrier:
                raise PredecessorRefusal(asset, object_type, object_id, barrier, observed, "barrier")
        elif not journaled:
            raise PredecessorRefusal(asset, object_type, object_id, "MISSING", observed, "journaled")
        elif observed != journaled:
            raise PredecessorRefusal(asset, object_type, object_id, journaled, observed, "journaled")


def recheck_predecessor_pins(es_url: str, kb_url: str, authorization: str, asset: Asset,
                             barrier_pin: str | None, journal: TransactionJournal) -> None:
    """Repeat the barrier pin immediately before a potentially mutating write."""
    if asset.kind != "dashboard":
        current_pin = _predecessor_hash(es_url, kb_url, authorization, asset)
        if current_pin != barrier_pin:
            raise InputError("predecessor manifest mismatch")
        return
    predecessor_entry = journal.value.get("predecessor_manifest", {}).get(asset.kind + "/" + asset.name, {})
    barrier_object_pins = (predecessor_entry.get("barrier_object_pins")
                           if isinstance(predecessor_entry, dict) else None)
    if not isinstance(barrier_object_pins, list):
        raise PredecessorRefusal(asset, "", "", "MISSING", "MISSING", "barrier")
    recheck_dashboard_predecessor_pins(es_url, kb_url, authorization, asset, barrier_object_pins, journal)


def predecessor_recheck_provision_error(journal: TransactionJournal,
                                        refusal: PredecessorRefusal) -> ProvisionError:
    """Persist the exact predecessor refusal before exposing its stable oracle."""
    journal.predecessor_recheck_failure(refusal)
    return ProvisionError("install failed: predecessor recheck:")


def predecessor_manifest_barrier(es_url: str, kb_url: str, authorization: str, bundle: Bundle,
                                 ownership: dict[tuple[str, str], str], manifest: dict | None,
                                 journal: TransactionJournal | None = None) -> dict[tuple[str, str], str]:
    """P3/P4: fully pin approved preimages before, and again at, each write."""
    if manifest is None:
        return {}
    pinned = {}
    for asset in bundle.assets:
        if ownership.get((asset.kind, asset.name)) == "external":
            continue
        key = asset.kind + "/" + asset.name
        entry = manifest["assets"].get(key)
        if not isinstance(entry, dict):
            raise InputError("predecessor manifest has no asset approval")
        dashboard_values = None
        if asset.kind == "dashboard":
            dashboard_values = _dashboard_predecessor_values(es_url, kb_url, authorization, asset)
            observed = hashlib.sha256(jcs(dashboard_values)).hexdigest()
        else:
            observed = _predecessor_hash(es_url, kb_url, authorization, asset)
        approved = entry["approved_sha256"]
        if observed not in approved:
            raise InputError("predecessor manifest mismatch")
        pinned[(asset.kind, asset.name)] = observed
        if journal is not None:
            journal_record = journal.value.setdefault("predecessor_manifest", {})[key] = {
                "approved_predecessor_id": entry.get("id"), "predecessor_match": observed}
            if asset.kind == "dashboard":
                journal_record["barrier_object_pins"] = [
                    [kind, ident, hashlib.sha256(jcs(value)).hexdigest()]
                    for kind, ident, value in dashboard_values or []]
            journal.persist()
    return pinned


def cluster_uuid(es_url: str, authorization: str) -> str:
    response = es_json(es_url, "/", "GET", authorization)
    value = response.get("cluster_uuid") if isinstance(response, dict) else None
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise RemoteReadRefusal("cluster UUID is invalid")
    return value


# Bound the complete value before regex matching or integer conversion. Core
# tokens are consequently at most 124 digits (well below Python's int limit).
STACK_VERSION_MAX_LENGTH = 128
STACK_SUPPORTED_RANGE = ("supported range: >=9.4.3 <9.5.0; "
                         "Elasticsearch and Kibana major.minor must match")
STACK_VERSION_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", re.ASCII)


class StackVersionRefusal(ProvisionError):
    """Fixed public eligibility diagnostic, including on uncertain transactions."""


def stack_version(response: object) -> tuple[int, int, int]:
    version = response.get("version") if isinstance(response, dict) else None
    value = version.get("number") if isinstance(version, dict) else None
    if not isinstance(value, str) or not 1 <= len(value) <= STACK_VERSION_MAX_LENGTH:
        raise StackVersionRefusal("install refused: stack version; " + STACK_SUPPORTED_RANGE)
    match = STACK_VERSION_RE.fullmatch(value)
    if match is None:
        raise StackVersionRefusal("install refused: stack version; " + STACK_SUPPORTED_RANGE)
    return tuple(int(part) for part in match.groups())


def stack_version_preflight(es_url: str, kb_url: str, authorization: str, *,
                            allow_untested: bool = False) -> None:
    """Read-only eligibility boundary; metadata never enters diagnostics."""
    try:
        es = stack_version(es_json(es_url, "/", "GET", authorization))
        kb = stack_version(es_json(kb_url, "/api/status", "GET", authorization))
    except (RequestFailure, InputError) as error:
        raise ProvisionError("install failed: prerequisite:") from error
    eligible = (es[0] == kb[0] == 9 and es[:2] == kb[:2]
                and es >= (9, 4, 3) and kb >= (9, 4, 3))
    supported = eligible and es[:2] == (9, 4)
    if not eligible or (not supported and not allow_untested):
        guidance = ("; use --allow-untested-stack-version for this untested pair"
                    if eligible else "")
        raise StackVersionRefusal("install refused: stack version; " + STACK_SUPPORTED_RANGE + guidance)
    if not supported:
        print("warning: --allow-untested-stack-version accepted an untested stack: "
              "Elasticsearch " + ".".join(map(str, es)) + "; Kibana " + ".".join(map(str, kb))
              + "; " + STACK_SUPPORTED_RANGE, file=sys.stderr)


def prerequisites(es_url: str, kb_url: str, authorization: str, *,
                  allow_untested: bool = False, versions_checked: bool = False) -> None:
    if not versions_checked:
        stack_version_preflight(es_url, kb_url, authorization, allow_untested=allow_untested)
    try:
        deadline = time.monotonic() + 60
        required = ("logs@mappings", "logs@settings", "ecs@mappings")
        while True:
            absent = []
            for name in required:
                try:
                    request(es_url, "/_component_template/" + urllib.parse.quote(name, safe=""), "GET", authorization)
                except RequestFailure:
                    absent.append(name)
            if not absent:
                return
            if time.monotonic() >= deadline:
                raise InputError("required built-in component templates are absent")
            time.sleep(1)
    except (RequestFailure, InputError) as error:
        raise ProvisionError("install failed: prerequisite:") from error


def required_path(value: object, path: tuple[str, ...]) -> object:
    """Return an owned JSON path, rejecting an absent or malformed branch."""
    current = value
    for name in path:
        if not isinstance(current, dict) or name not in current:
            raise InputError("W1 owned mapping path is missing")
        current = current[name]
    return current


def setting_bool(value: object) -> bool:
    # Flat-settings responses serialize booleans as strings, while simulation
    # returns JSON booleans.  Normalize only these two unambiguous spellings.
    if value is True or value == "true":
        return True
    if value is False or value == "false":
        return False
    raise InputError("W1 owned setting is invalid")


def owned_mapping_projection(mappings: object, ignore_malformed: object,
                             failure_store_enabled: object) -> dict:
    paths = (
        ("properties", "@timestamp"),
        ("properties", "event", "properties", "id"),
        ("properties", "host", "properties", "name"),
        ("properties", "observer", "properties", "name"),
        ("dynamic",),
        ("properties", "rigsignal", "properties", "diagnosis", "dynamic"),
        ("properties", "rigsignal", "properties", "diagnosis", "properties"),
    )
    projected: dict = {"mappings": {}, "settings": {
        "index.mapping.ignore_malformed": setting_bool(ignore_malformed),
        "index.failure_store.enabled": setting_bool(failure_store_enabled),
    }}
    for path in paths:
        target = projected["mappings"]
        for part in path[:-1]:
            target = target.setdefault(part, {})
        target[path[-1]] = _drop_default_ignore_malformed(required_path(mappings, path))
    return projected


def _drop_default_ignore_malformed(node: object) -> object:
    """ES composition normalizes an explicit field-level ignore_malformed:false
    away (ratified P0 evidence: simulate renders @timestamp as {"type":"date"});
    the hardening is asserted at the settings level. Only the false default is
    dropped — ignore_malformed:true anywhere still fails equality."""
    if not isinstance(node, dict):
        return node
    projected = {k: _drop_default_ignore_malformed(v) for k, v in node.items()}
    if projected.get("ignore_malformed") is False:
        del projected["ignore_malformed"]
    return projected


def simulated_owned_mapping_projection(es_url: str, authorization: str) -> dict:
    # No body: a JSON body (even {}) is read as an inline template override
    # and ES then requires index_patterns.
    result = es_json(es_url, "/_index_template/_simulate_index/" + DIAGNOSIS_STREAM,
                     "POST", authorization, None)
    template = required_path(result, ("template",))
    mappings = required_path(template, ("mappings",))
    ignore_malformed = required_path(template, ("settings", "index", "mapping", "ignore_malformed"))
    failure_store_enabled = required_path(template, ("data_stream_options", "failure_store", "enabled"))
    return owned_mapping_projection(mappings, ignore_malformed, failure_store_enabled)


def canonical_owned_mapping_projection(bundle: Bundle | None = None) -> dict:
    """The fixed W1 owned surface, independent of live template simulation."""
    component = parse_json(
        bundle_resource(bundle, CANONICAL_COMPONENT_PATH, "canonical W1 component"),
        "canonical W1 component",
    )
    index = parse_json(
        bundle_resource(bundle, CANONICAL_INDEX_PATH, "canonical W1 index template"),
        "canonical W1 index template",
    )
    mappings = required_path(component, ("template", "mappings"))
    return owned_mapping_projection(
        mappings,
        required_path(index, ("template", "settings", "index", "mapping", "ignore_malformed")),
        required_path(index, ("template", "data_stream_options", "failure_store", "enabled")),
    )


def backing_owned_mapping_projection(es_url: str, authorization: str, index_name: str) -> dict:
    quoted = urllib.parse.quote(index_name, safe="")
    mapping_response = es_json(es_url, "/" + quoted + "/_mapping", "GET", authorization)
    settings_response = es_json(es_url, "/" + quoted + "/_settings?flat_settings=true", "GET", authorization)
    mappings = required_path(mapping_response, (index_name, "mappings"))
    settings = required_path(settings_response, (index_name, "settings"))
    # failure_store is a data-stream-level option: ES materializes no index
    # setting when it is disabled, so absence IS the required-disabled state;
    # a present value must still be false.
    failure_store = settings.get("index.failure_store.enabled", "false") if isinstance(settings, dict) else "false"
    return owned_mapping_projection(
        mappings,
        required_path(settings, ("index.mapping.ignore_malformed",)),
        failure_store,
    )


def _stream_backing_pairs(stream: object) -> frozenset[tuple[str, str]] | None:
    """Return the exact, unique backing-index identity set from a stream body."""
    if not isinstance(stream, dict) or stream.get("name") != DIAGNOSIS_STREAM:
        return None
    failure_store = required_path(stream, ("failure_store", "enabled"))
    if type(failure_store) is not bool or failure_store:
        return None
    indices = stream.get("indices")
    if not isinstance(indices, list) or not indices:
        return None
    pairs: set[tuple[str, str]] = set()
    for item in indices:
        if not isinstance(item, dict):
            return None
        name, index_uuid = item.get("index_name"), item.get("index_uuid")
        if not isinstance(name, str) or not name or not isinstance(index_uuid, str) or not index_uuid:
            return None
        pairs.add((name, index_uuid))
    return frozenset(pairs) if len(pairs) == len(indices) else None


def _index_lifecycle_is_compatible(es_url: str, authorization: str, index_name: str,
                                   expected_uuid: str) -> bool:
    quoted = urllib.parse.quote(index_name, safe="")
    settings_response = es_json(es_url, "/" + quoted + "/_settings?flat_settings=true", "GET", authorization)
    settings = required_path(settings_response, (index_name, "settings"))
    if (required_path(settings, ("index.uuid",)) != expected_uuid
            or required_path(settings, ("index.lifecycle.name",)) != W1_LIFECYCLE_POLICY):
        return False
    explain = es_json(es_url, "/" + quoted + "/_ilm/explain", "GET", authorization)
    explained = required_path(explain, ("indices", index_name))
    return isinstance(explained, dict) and explained.get("managed") is True and explained.get("policy") == W1_LIFECYCLE_POLICY


def stream_compatibility_snapshot(es_url: str, authorization: str, response: object,
                                  bundle: Bundle | None = None) -> frozenset[tuple[str, str]] | None:
    """Validate the remote W1 shape and return its immutable backing snapshot.

    ``None`` deliberately covers every malformed or incompatible response.  The
    caller turns it into the stable migration refusal without exposing remote
    cluster details.
    """
    try:
        streams = response.get("data_streams") if isinstance(response, dict) else None
        if not isinstance(streams, list) or len(streams) != 1:
            return None
        pairs = _stream_backing_pairs(streams[0])
        if pairs is None or streams[0].get("ilm_policy") != W1_LIFECYCLE_POLICY:
            return None
        policy = es_json(es_url, "/_ilm/policy/" + urllib.parse.quote(W1_LIFECYCLE_POLICY, safe=""), "GET", authorization)
        policy_body = policy.get(W1_LIFECYCLE_POLICY) if isinstance(policy, dict) else None
        phases = policy_body.get("policy", {}).get("phases") if isinstance(policy_body, dict) else None
        if not isinstance(phases, dict) or "delete" in phases:
            return None
        desired = canonical_owned_mapping_projection(bundle) if bundle is not None else canonical_owned_mapping_projection()
        for index_name, index_uuid in pairs:
            if not _index_lifecycle_is_compatible(es_url, authorization, index_name, index_uuid):
                return None
            if jcs(backing_owned_mapping_projection(es_url, authorization, index_name)) != jcs(desired):
                return None
        return pairs
    except InputError:
        return None


def existing_stream_is_compatible(es_url: str, authorization: str, state: dict | None, uuid_value: str,
                                  root: Path | None = None, adopt_existing: bool = False,
                                  bundle: Bundle | None = None) -> bool:
    if state is not None:
        if root is None:
            raise InputError("enrollment root is required for state ownership")
        validate_state_binding(state, root)
    try:
        response = es_json(es_url, "/_data_stream/" + DIAGNOSIS_STREAM, "GET", authorization)
    except RequestFailure as error:
        if error.status == 404:
            # A committed-state rerun may find that an operator removed the
            # stream between runs.  Preserve the established Step-5
            # self-healing path: compatibility here lets ensure_stream()
            # recreate it.  The flag-present/stream-absent refusal is decided
            # earlier, in main()'s clean-root dispatch.
            return True
        raise
    # Adoption replaces only the committed-state ownership conjunct.  All
    # remote shape checks remain identical for adoption and ordinary reruns.
    if not adopt_existing and (state is None or state["phase"] != "committed"
                               or state["expected_cluster_uuid"] != uuid_value):
        return False
    return stream_compatibility_snapshot(es_url, authorization, response, bundle) is not None


def fence(es_url: str, authorization: str, state: dict | None, uuid_value: str,
          root: Path | None = None, adopt_existing: bool = False,
          bundle: Bundle | None = None) -> None:
    try:
        compatible = existing_stream_is_compatible(es_url, authorization, state, uuid_value, root, adopt_existing,
                                                   bundle)
    except StateBindingError as error:
        raise ProvisionError("install refused: enrollment_remediation_required") from error
    except (RequestFailure, InputError) as error:
        raise ProvisionError("install refused: existing diagnosis stream is not W1; migration is required") from error
    if not compatible:
        raise ProvisionError("install refused: existing diagnosis stream is not W1; migration is required")


def remote_stream_condition(es_url: str, authorization: str,
                            bundle: Bundle | None = None) -> tuple[str, frozenset[tuple[str, str]] | None]:
    """Return absent, compatible, or incompatible without mutating the cluster."""
    try:
        response = es_json(es_url, "/_data_stream/" + DIAGNOSIS_STREAM, "GET", authorization)
    except RequestFailure as error:
        if error.status == 404:
            return "absent", None
        raise
    snapshot = stream_compatibility_snapshot(es_url, authorization, response, bundle)
    return ("compatible", snapshot) if snapshot is not None else ("incompatible", None)


def dispatch_clean_root(es_url: str, authorization: str, adopt_requested: bool,
                        bundle: Bundle | None = None) -> bool:
    """Apply the clean-root adoption matrix and return whether adoption is enabled."""
    remote_condition, _snapshot = remote_stream_condition(es_url, authorization, bundle)
    if adopt_requested:
        if remote_condition == "absent":
            raise ProvisionError("install refused: adoption_flag_stream_absent")
        if remote_condition != "compatible":
            raise ProvisionError("install refused: migration_required")
        return True
    if remote_condition == "compatible":
        raise ProvisionError("install refused: adoption_required")
    if remote_condition == "incompatible":
        raise ProvisionError("install refused: migration_required")
    return False


def ensure_stream(es_url: str, authorization: str) -> None:
    try:
        mutation_request(es_url, "/_data_stream/" + DIAGNOSIS_STREAM, "PUT", authorization)
    except RequestFailure as error:
        if error.status not in {400, 409}:
            raise
    result = es_json(es_url, "/_data_stream/" + DIAGNOSIS_STREAM, "GET", authorization)
    streams = result.get("data_streams") if isinstance(result, dict) else None
    if not isinstance(streams, list) or len(streams) != 1 or streams[0].get("name") != DIAGNOSIS_STREAM:
        raise InputError("exact diagnosis stream did not resolve")


def simulate(es_url: str, authorization: str, bundle: Bundle | None = None) -> None:
    try:
        actual = simulated_owned_mapping_projection(es_url, authorization)
    except InputError as error:
        raise InputError("W1 index simulation failed")
    if jcs(actual) != jcs(canonical_owned_mapping_projection(bundle)):
        raise InputError("W1 index simulation differs")


STREAM_STATE_FIELDS = ("lifecycle", "failure_store", "ilm_policy", "prefer_ilm",
                       "next_generation_managed_by", "generation", "hidden", "system",
                       "allow_custom_routing", "backing")
PROJECTED_STREAM_STATE_FIELDS = frozenset(("ilm_policy", "prefer_ilm",
                                           "next_generation_managed_by"))


def _normalized_stream_state(stream: dict, backing_state: list[dict]) -> dict:
    """Return the SI-1 schema: all fields materialize except absent ILM name."""
    state = {key: deepcopy(stream.get(key)) for key in STREAM_STATE_FIELDS
             if key not in {"ilm_policy", "prefer_ilm", "backing"}}
    # The §E probe confirmed ES's absent effective prefer_ilm default on 9.4.3
    # and 9.4.4.  Keep it materialized so snapshot add/remove is not API-shape drift.
    prefer = stream.get("prefer_ilm", True)
    if type(prefer) is not bool:
        raise InputError("fleet stream prefer_ilm is invalid")
    state["prefer_ilm"] = prefer
    if "ilm_policy" in stream:
        policy = stream["ilm_policy"]
        if not isinstance(policy, str) or not policy:
            raise InputError("fleet stream ilm_policy is invalid")
        state["ilm_policy"] = policy
    state["backing"] = sorted(backing_state, key=lambda value: (value["index_name"], value["index_uuid"]))
    return state


def fleet_stream_snapshot(es_url: str, authorization: str) -> dict[str, object]:
    """Capture all current RigSignal streams dynamically for the Step-5 fence."""
    response = es_json(es_url, "/_data_stream/*rigsignal*", "GET", authorization)
    streams = response.get("data_streams") if isinstance(response, dict) else None
    if not isinstance(streams, list):
        raise InputError("fleet stream enumeration is invalid")
    snapshot: dict[str, object] = {}
    for stream in streams:
        if not isinstance(stream, dict) or not isinstance(stream.get("name"), str):
            raise InputError("fleet stream enumeration is invalid")
        name = stream["name"]
        pairs = []
        backing_state = []
        for index in stream.get("indices", []):
            if not isinstance(index, dict) or not isinstance(index.get("index_name"), str) or not isinstance(index.get("index_uuid"), str):
                raise InputError("fleet backing index is invalid")
            pairs.append((index["index_name"], index["index_uuid"]))
            backing_state.append({key: index.get(key) for key in ("index_name", "index_uuid",
                                                                  "prefer_ilm", "managed_by")})
        # `_simulate_index` is the effective mappings/settings/default-pipeline/
        # lifecycle oracle, not merely a composed_of textual comparison.
        simulated = es_json(es_url, "/_index_template/_simulate_index/" + urllib.parse.quote(name, safe=""),
                            "POST", authorization, None)
        try:
            # This is the single ratified normalization for simulate results.
            # In particular, ES generates TSDB start/end boundaries from the
            # wall clock, so raw settings would make an unchanged stream look
            # different if the two Step-5 captures straddle a second.
            outcome = asset_adapters.simulation_outcome(simulated)
        except ValueError as error:
            raise InputError("fleet index simulation is invalid") from error
        # Keep every data-stream field which is a topology/lifecycle contract.
        # Do not retain status/health: those are explicitly volatile.  The
        # simulate normalization below remains the sole TSDB-boundary filter.
        state = _normalized_stream_state(stream, backing_state)
        snapshot[name] = {"backing": sorted(pairs), "stream_state": state,
                          # The matching template name is always materialized
                          # and is strict compared (R0/SI-1), never projected.
                          "data_stream_template": stream.get("template"), **outcome}
    return snapshot


def _pointer_escape(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


def rfc6901_diff(before: object, after: object, path: str = "") -> list[dict]:
    """Return a deterministic complete JSON-pointer operation list.

    Lists are atomic deliberately: ES mapping/template arrays have ordering
    semantics, and a positional patch would conceal a foreign reordering.
    """
    if isinstance(before, dict) and isinstance(after, dict):
        result: list[dict] = []
        for key in sorted(set(before) | set(after)):
            child = path + "/" + _pointer_escape(key)
            if key not in before:
                result.append({"op": "add", "path": child, "value": deepcopy(after[key])})
            elif key not in after:
                result.append({"op": "remove", "path": child})
            else:
                result.extend(rfc6901_diff(before[key], after[key], child))
        return result
    if before != after:
        return [{"op": "replace", "path": path, "value": deepcopy(after)}]
    return []


def _lifecycle_setting(settings: object, name: str) -> list[object]:
    """Read one setting from nested and flattened simulate renderings."""
    if not isinstance(settings, dict):
        raise InputError("fleet simulated lifecycle settings are invalid")
    values = []
    flat = "index.lifecycle." + name
    if flat in settings:
        values.append(settings[flat])
    index = settings.get("index")
    if isinstance(index, dict):
        lifecycle = index.get("lifecycle")
        if isinstance(lifecycle, dict) and name in lifecycle:
            values.append(lifecycle[name])
        flattened = "lifecycle." + name
        if flattened in index:
            values.append(index[flattened])
    elif index is not None:
        raise InputError("fleet simulated lifecycle settings are invalid")
    if not values:
        return []
    return values


def lifecycle_values_from_simulation(settings: object) -> dict[str, object]:
    """Extract the R2 lifecycle inputs from normalized `_simulate_index` settings."""
    names = _lifecycle_setting(settings, "name")
    prefers = _lifecycle_setting(settings, "prefer_ilm")
    result: dict[str, object] = {}
    if names:
        name = names[0]
        if not isinstance(name, str) or not name:
            raise InputError("fleet simulated lifecycle name is invalid")
        if any(value != name for value in names[1:]):
            raise InputError("fleet simulated lifecycle settings conflict")
        result["ilm_policy"] = name
    if not prefers:
        # Version-pinned by FENCE-V2B §E3 probe: absent => true on ES 9.4.3/9.4.4.
        result["prefer_ilm"] = True
    else:
        normalized = []
        for prefer in prefers:
            if type(prefer) is bool:
                normalized.append(prefer)
            elif isinstance(prefer, str) and prefer in {"true", "false"}:
                normalized.append(prefer == "true")
            else:
                raise InputError("fleet simulated lifecycle prefer_ilm is invalid")
        if any(value != normalized[0] for value in normalized[1:]):
            raise InputError("fleet simulated lifecycle settings conflict")
        result["prefer_ilm"] = normalized[0]
    return result


def _stream_dsl_enabled(template: object) -> bool:
    """Read the effective data-stream lifecycle switch from an index template."""
    if not isinstance(template, dict):
        raise InputError("fleet simulated data stream lifecycle is invalid")
    body = template.get("template", template)
    if not isinstance(body, dict):
        raise InputError("fleet simulated data stream lifecycle is invalid")
    options = body.get("data_stream_options")
    if options is None:
        return False
    if not isinstance(options, dict):
        raise InputError("fleet simulated data stream lifecycle is invalid")
    lifecycle = options.get("lifecycle")
    if lifecycle is None:
        return False
    if not isinstance(lifecycle, dict) or type(lifecycle.get("enabled")) is not bool:
        raise InputError("fleet simulated data stream lifecycle is invalid")
    return lifecycle["enabled"]


def projected_next_generation_managed_by(values: dict[str, object], stream_dsl_enabled: object) -> str:
    """R3's ratified five-row table; inputs outside it are a refusal."""
    policy = values.get("ilm_policy")
    prefer = values.get("prefer_ilm")
    if policy is not None and (not isinstance(policy, str) or not policy):
        raise InputError("fleet projected lifecycle policy is invalid")
    if type(prefer) is not bool or type(stream_dsl_enabled) is not bool:
        raise InputError("fleet projected lifecycle inputs are invalid")
    if policy is not None and not stream_dsl_enabled:
        return "Index Lifecycle Management"
    if policy is not None and stream_dsl_enabled and prefer:
        return "Index Lifecycle Management"
    if policy is not None and stream_dsl_enabled and not prefer:
        return "Data stream lifecycle"
    if policy is None and stream_dsl_enabled:
        return "Data stream lifecycle"
    if policy is None and not stream_dsl_enabled:
        return "Unmanaged"
    raise InputError("fleet projected lifecycle combination is unresolved")


def _stream_state_projection(pre: object, simulated_settings: object, template: object) -> list[dict]:
    if not isinstance(pre, dict):
        raise InputError("fleet stream snapshot is invalid")
    values = lifecycle_values_from_simulation(simulated_settings)
    values["next_generation_managed_by"] = projected_next_generation_managed_by(
        values, _stream_dsl_enabled(template))
    expected = deepcopy(pre)
    for field in PROJECTED_STREAM_STATE_FIELDS:
        if field in values:
            expected[field] = values[field]
        else:
            expected.pop(field, None)
    return rfc6901_diff({"stream_state": pre}, {"stream_state": expected})


def _merge_projection_dict(base: object, override: object) -> dict:
    """Merge a component's declared template subtree for lifecycle inputs."""
    if not isinstance(base, dict) or not isinstance(override, dict):
        raise InputError("fleet component lifecycle projection is invalid")
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_projection_dict(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _declared_paths(value: object, path: str = "") -> set[str]:
    """Return leaf pointers for a bundle-owned resolved template declaration."""
    if isinstance(value, dict):
        result: set[str] = set()
        for key, member in value.items():
            result.update(_declared_paths(member, path + "/" + _pointer_escape(key)))
        return result or {path}
    return {path}


def _declared_leaf_payloads(value: object, path: str = "") -> dict[str, object]:
    """Return RFC-6901 leaf pointers and payloads; lists are deliberately atomic."""
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, member in value.items():
            result.update(_declared_leaf_payloads(member, path + "/" + _pointer_escape(key)))
        return result or {path: {}}
    return {path: deepcopy(value)}


def _l3c_op_matches_owned_payload(op: object, owned: object) -> bool:
    """Accept an L3-C op only when its complete payload is bundle-declared.

    ``rfc6901_diff`` emits one operation for an added/replaced dictionary.
    That operation can therefore carry several owned leaves, but it must carry
    all and only the declared leaves beneath its path.  Lists remain one leaf,
    matching the differ's atomic-list contract.
    """
    if not isinstance(op, dict) or op.get("op") not in {"add", "replace"}:
        return False
    path = op.get("path")
    if not isinstance(path, str) or "value" not in op or not isinstance(owned, dict):
        return False
    expected = {leaf: value for leaf, value in owned.items()
                if isinstance(leaf, str) and (leaf == path or leaf.startswith(path + "/"))}
    return bool(expected) and _declared_leaf_payloads(op["value"], path) == expected


def _fleet_refusal(message: str, stream: str, ops: list[dict] | None = None,
                   reason: str | None = None) -> InputError:
    """Attach the per-stream evidence required by the durable fence journal."""
    error = InputError(message)
    error.stream = stream
    error.ops = deepcopy(ops or [])
    if reason is not None:
        error.reason = reason
    return error


def _annotate_fleet_refusal(error: InputError, stream: str) -> InputError:
    """Preserve a lower-level refusal while making its journal evidence whole."""
    if not isinstance(getattr(error, "stream", None), str):
        error.stream = stream
    if not isinstance(getattr(error, "ops", None), list):
        error.ops = []
    return error


def _matching_templates(index_templates: object, stream: str) -> list[dict]:
    if not isinstance(index_templates, dict):
        raise InputError("fleet template enumeration is invalid")
    result = []
    for name, raw in index_templates.items():
        try:
            body = asset_adapters.get_projection("index_templates",
                                                 raw.get("index_template") if isinstance(raw, dict) else raw)
        except asset_adapters.AdapterError as error:
            raise InputError("fleet template projection is invalid") from error
        if not isinstance(name, str) or not isinstance(body, dict):
            raise InputError("fleet template enumeration is invalid")
        patterns = body.get("index_patterns")
        priority = body.get("priority", 0)
        if (not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns)
                or type(priority) is not int):
            raise InputError("fleet template enumeration is invalid")
        if any(fnmatch.fnmatchcase(stream, pattern) for pattern in patterns):
            result.append({"name": name, "body": body, "priority": priority})
    return result


def _winner_evidence(es_url: str, authorization: str, stream: str, data_stream_template: object) -> dict:
    response = es_json(es_url, "/_index_template", "GET", authorization)
    entries = response.get("index_templates") if isinstance(response, dict) else None
    if not isinstance(entries, list):
        raise InputError("fleet template enumeration is invalid")
    templates = {item.get("name"): item for item in entries if isinstance(item, dict) and isinstance(item.get("name"), str)}
    matching = _matching_templates(templates, stream)
    if not matching:
        raise InputError("fleet template winner is absent")
    maximum = max(item["priority"] for item in matching)
    winners = [item for item in matching if item["priority"] == maximum]
    return {"matching_set": [{"name": item["name"], "priority": item["priority"]} for item in matching],
            "max_priority": maximum, "unique": len(winners) == 1,
            "winning_template": winners[0]["name"] if len(winners) == 1 else None,
            "winning_body": winners[0]["body"] if len(winners) == 1 else None,
            "data_stream_template": data_stream_template}


def _owned_component_closure(template: object, owned_components: set[str]) -> list[str]:
    """Resolve composed_of transitively from the single GET /_index_template set."""
    # The closure's component bodies are supplied by the caller as an internal
    # mapping, avoiding a new request for each component.
    if not isinstance(template, dict):
        raise InputError("fleet winning template is invalid")
    composed = template.get("composed_of", [])
    if not isinstance(composed, list) or not all(isinstance(value, str) for value in composed):
        raise InputError("fleet winning template is invalid")
    return sorted(value for value in composed if value in owned_components)


def _matching_owned_templates(owned_templates: dict[str, Asset], actions: dict[tuple[str, str], str],
                              stream: str) -> list[Asset]:
    """Return every changing bundle template whose declared patterns match stream."""
    result = []
    for asset in owned_templates.values():
        if actions.get((asset.kind, asset.name)) not in {"create", "update"}:
            continue
        try:
            body = asset_adapters.get_projection("index_templates", parse_json(asset.data, asset.path))
        except asset_adapters.AdapterError as error:
            raise InputError("fleet template projection is invalid") from error
        if not isinstance(body, dict):
            raise InputError("fleet template projection is invalid")
        patterns = body.get("index_patterns")
        if not isinstance(patterns, list) or not all(isinstance(pattern, str) for pattern in patterns):
            raise InputError("fleet template projection is invalid")
        if any(fnmatch.fnmatchcase(stream, pattern) for pattern in patterns):
            result.append(asset)
    return result


def _simulate_template(es_url: str, authorization: str, template: dict, uniqueness: str) -> tuple[dict, bytes]:
    try:
        body, probe = asset_adapters.synthetic_simulation_template(template, uniqueness)
        outcome = asset_adapters.simulation_outcome(es_json(
            es_url, "/_index_template/_simulate_index/" + urllib.parse.quote(probe, safe=""),
            "POST", authorization, body))
    except asset_adapters.AdapterError as error:
        raise InputError("fleet synthetic simulation is invalid") from error
    return outcome, jcs(body)


def plan_fleet_fence(es_url: str, authorization: str, snapshot: dict[str, object], bundle: Bundle,
                     actions: dict[tuple[str, str], str], journal: TransactionJournal | None = None) -> dict:
    """Pin L2/L3/L3-C classifications and projections before the first PUT."""
    owned_templates = {asset.name: asset for asset in bundle.assets
                       if asset.kind == "index_templates" and (asset.kind, asset.name) in actions}
    owned_components = {asset.name for asset in bundle.assets if asset.kind == "component_templates"
                        and (asset.kind, asset.name) in actions
                        and actions[(asset.kind, asset.name)] in {"create", "update"}}
    changed_templates = {name for name, asset in owned_templates.items()
                         if actions.get((asset.kind, asset.name)) in {"create", "update"}}
    plan: dict[str, object] = {}
    for stream, record in snapshot.items():
        if not isinstance(record, dict):
            raise InputError("fleet stream snapshot is invalid")
        if not changed_templates and not owned_components:
            plan[stream] = {"classification": {"status": "L2", "winning_template": None,
                                                 "winner_evidence": {}, "closure_owned_components": []},
                            "pre": deepcopy(record)}
            continue
        # N1: stream is taken only from fleet_stream_snapshot, never derived
        # from an index template name.
        try:
            evidence = _winner_evidence(es_url, authorization, stream,
                                        record.get("data_stream_template"))
            matching_owned = _matching_owned_templates(owned_templates, actions, stream)
        except InputError as error:
            raise _annotate_fleet_refusal(error, stream) from error
        winner = evidence["winning_template"]
        # Classification is deliberately derived from owned pattern matches,
        # not from the current winner.  Otherwise a foreign higher-priority
        # template with an identical resolved outcome could silently demote a
        # changing owned template to L2.
        if any(actions[(asset.kind, asset.name)] == "create" for asset in matching_owned):
            raise _fleet_refusal("fleet template preimage is absent", stream)
        if not evidence["unique"]:
            raise _fleet_refusal("fleet template winner is ambiguous", stream)
        if evidence["data_stream_template"] is not None and evidence["data_stream_template"] != winner:
            raise _fleet_refusal("fleet stream template corroboration differs", stream)
        for asset in matching_owned:
            if winner != asset.name:
                raise _fleet_refusal("fleet owned template is not the winner", stream)
        try:
            closure = _owned_component_closure(evidence["winning_body"], owned_components)
        except InputError as error:
            raise _annotate_fleet_refusal(error, stream) from error
        target = matching_owned[0] if matching_owned else None
        changed_template = target is not None
        status = "L3-C" if closure else "L3" if changed_template else "L2"
        if status == "L3-C" and stream != DIAGNOSIS_STREAM:
            raise _fleet_refusal("fleet L3-C stream is unattested", stream)
        classification = {"status": status, "winning_template": winner,
                          "winner_evidence": {key: evidence[key] for key in (
                              "matching_set", "max_priority", "unique", "data_stream_template")},
                          "closure_owned_components": closure}
        entry: dict = {"classification": classification, "pre": deepcopy(record)}
        if status == "L3-C":
            declared: set[str] = set()
            declared_payloads: dict[str, object] = {}
            for component in closure:
                asset = next((item for item in bundle.assets
                              if item.kind == "component_templates" and item.name == component), None)
                if asset is not None:
                    try:
                        body = parse_json(asset.data, asset.path)
                    except InputError as error:
                        raise _annotate_fleet_refusal(error, stream) from error
                    if isinstance(body, dict):
                        template_body = body.get("template", {})
                        declared.update(_declared_paths(template_body))
                        declared_payloads.update(_declared_leaf_payloads(template_body))
            if target is not None:
                try:
                    body = parse_json(target.data, target.path)
                except InputError as error:
                    raise _annotate_fleet_refusal(error, stream) from error
                if isinstance(body, dict):
                    template_body = body.get("template", {})
                    declared.update(_declared_paths(template_body))
                    declared_payloads.update(_declared_leaf_payloads(template_body))
            entry["owned_paths"] = sorted(declared)
            entry["owned_leaf_payloads"] = declared_payloads
            # A component-only update is still an affected stream (R1).  For
            # lifecycle declarations, apply the changed component subtree to
            # the normalized preimage before taking the same R2/R3 projection.
            # Other component surfaces remain the established L3-C path.
            projected_settings = deepcopy(record.get("settings"))
            projected_template = deepcopy(evidence["winning_body"])
            if not isinstance(projected_settings, dict) or not isinstance(projected_template, dict):
                raise _fleet_refusal("fleet component lifecycle projection is invalid", stream)
            component_template: dict = {}
            for component in closure:
                asset = next((item for item in bundle.assets
                              if item.kind == "component_templates" and item.name == component), None)
                if asset is None:
                    continue
                body = parse_json(asset.data, asset.path)
                template_body = body.get("template") if isinstance(body, dict) else None
                if not isinstance(template_body, dict):
                    raise _fleet_refusal("fleet component lifecycle projection is invalid", stream)
                settings = template_body.get("settings", {})
                if not isinstance(settings, dict):
                    raise _fleet_refusal("fleet component lifecycle projection is invalid", stream)
                projected_settings = _merge_projection_dict(projected_settings, settings)
                component_template = _merge_projection_dict(component_template, template_body)
            winner_template = projected_template.get("template", {})
            if not isinstance(winner_template, dict):
                raise _fleet_refusal("fleet component lifecycle projection is invalid", stream)
            # The composable template's own block has ES's final precedence.
            projected_template["template"] = _merge_projection_dict(component_template, winner_template)
            entry["stream_state_ops"] = _stream_state_projection(
                record.get("stream_state"), projected_settings, projected_template)
        if status == "L3":
            if target is None:
                raise _fleet_refusal("fleet template projection is unavailable", stream)
            # A create action proves no live T body exists, even if its name
            # somehow won through a concurrently changing response.
            if actions[(target.kind, target.name)] == "create":
                raise _fleet_refusal("fleet template preimage is absent", stream)
            try:
                live = es_json(es_url, es_path(target), "GET", authorization)
                pre_body = asset_adapters.get_projection("index_templates", live)
                post_body = asset_adapters.get_projection("index_templates", parse_json(target.data, target.path))
            except (InputError, asset_adapters.AdapterError) as error:
                raise _fleet_refusal("fleet template projection is invalid", stream) from error
            uniqueness = hashlib.sha256(target.name.encode()).hexdigest()[:16]
            try:
                pre_synth, pre_bytes = _simulate_template(es_url, authorization, pre_body, uniqueness)
                post_synth, post_bytes = _simulate_template(es_url, authorization, post_body, uniqueness)
            except InputError as error:
                raise _annotate_fleet_refusal(error, stream) from error
            pre_real = {key: record[key] for key in ("mappings", "settings", "aliases")}
            anchor_ok = jcs(pre_synth) == jcs(pre_real)
            if not anchor_ok:
                raise _fleet_refusal("fleet synthetic anchor differs", stream,
                                    rfc6901_diff(pre_synth, pre_real))
            entry["projection"] = {"template": target.name, "uniqueness": uniqueness, "anchor_ok": anchor_ok,
                                   "pre_synth": pre_synth, "post_synth": post_synth,
                                   "ops": rfc6901_diff(pre_synth, post_synth),
                                   "pre_synth_body": pre_bytes, "post_synth_body": post_bytes}
            entry["stream_state_ops"] = _stream_state_projection(
                record.get("stream_state"), post_synth.get("settings"), post_body)
        plan[stream] = entry
    if journal is not None:
        journal.pin_fleet_fence(plan)
    return plan


def verify_fleet_stream_overrides(es_url: str, authorization: str, plan: dict,
                                  journal: TransactionJournal | None = None,
                                  phase: str | None = None) -> None:
    """R1's four-checkpoint precondition: projection inputs have no overrides.

    The refusal is journaled as ``fleet_fence.failure`` at every checkpoint
    that passes a journal, so the operator can triage layer/source from the
    durable record rather than transient stderr.
    """
    try:
        for stream, entry in sorted(plan.items()):
            status = (entry.get("classification", {}).get("status")
                      if isinstance(entry, dict) else None)
            if status not in {"L3", "L3-C"}:
                continue
            quoted = urllib.parse.quote(stream, safe="")
            for suffix, key in (("/_settings", "settings"), ("/_mappings", "mappings")):
                response = es_json(es_url, "/_data_stream/" + quoted + suffix, "GET", authorization)
                rows = response.get("data_streams") if isinstance(response, dict) else None
                if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                    raise _fleet_refusal("fleet stream overrides are invalid", stream,
                                         reason="stream_overrides_invalid")
                value = rows[0].get(key)
                if not isinstance(value, dict) or value:
                    raise _fleet_refusal("fleet stream overrides are present", stream,
                                         reason="stream_overrides_present")
    except InputError as error:
        if journal is not None and phase is not None:
            journal.fleet_fence_failure(phase, getattr(error, "stream", None),
                                        getattr(error, "ops", []),
                                        getattr(error, "reason", None))
        raise


def verify_fleet_winner_proofs(es_url: str, authorization: str, plan: dict) -> None:
    """G1's post-write/late TOCTOU proof: identity and uniqueness only."""
    for stream, entry in sorted(plan.items()):
        if not isinstance(entry, dict):
            continue
        status = entry.get("classification", {}).get("status")
        expected = entry.get("classification", {}).get("winning_template")
        if status not in {"L3", "L3-C"} or not isinstance(expected, str):
            continue
        evidence = _winner_evidence(es_url, authorization, stream, None)
        if evidence.get("unique") is not True or evidence.get("winning_template") != expected:
            raise _fleet_refusal("fleet winner proof differs", stream)


def verify_fleet_fence(pre: dict[str, object], post: dict[str, object], plan: dict,
                       journal: TransactionJournal | None = None, phase: str = "post") -> None:
    """Apply L1/L2/L3/L3-C/L4.  Every refusal is journaled before escape."""
    try:
        extra = set(post) - set(pre)
        unexpected = sorted(extra - {DIAGNOSIS_STREAM})
        if unexpected or (DIAGNOSIS_STREAM in extra and DIAGNOSIS_STREAM in pre):
            stream = unexpected[0] if unexpected else DIAGNOSIS_STREAM
            raise _fleet_refusal("fleet stream set drifted", stream,
                                 rfc6901_diff(pre.get(stream), post.get(stream)))
        for stream, before in pre.items():
            after = post.get(stream)
            if not isinstance(before, dict) or not isinstance(after, dict):
                raise _fleet_refusal("fleet stream snapshot drifted", stream,
                                     rfc6901_diff(before, after))
            entry = plan.get(stream, {})
            status = entry.get("classification", {}).get("status", "L2") if isinstance(entry, dict) else "L2"
            # R5 is absolute: no L3/L3-C projection can accept a topology move.
            if before.get("backing") != after.get("backing"):
                raise _fleet_refusal("fleet L1 drifted", stream,
                                     rfc6901_diff({"backing": before.get("backing"),
                                                   "data_stream_template": before.get("data_stream_template")},
                                                  {"backing": after.get("backing"),
                                                   "data_stream_template": after.get("data_stream_template")}))
            # The matching template name was promoted to a strict R0 surface.
            if before.get("data_stream_template") != after.get("data_stream_template"):
                raise _fleet_refusal("fleet L1 drifted", stream,
                                     rfc6901_diff({"data_stream_template": before.get("data_stream_template")},
                                                  {"data_stream_template": after.get("data_stream_template")}))
            stream_ops = rfc6901_diff({"stream_state": before.get("stream_state")},
                                      {"stream_state": after.get("stream_state")})
            if status == "L3-C" and stream != DIAGNOSIS_STREAM:
                raise _fleet_refusal("fleet L3-C stream is unattested", stream)
            if status in {"L3", "L3-C"}:
                expected = entry.get("stream_state_ops") if isinstance(entry, dict) else None
                if not isinstance(expected, list) or stream_ops != expected:
                    raise _fleet_refusal("fleet stream_state projection differs", stream, stream_ops,
                                         "stream_state_projection")
            elif stream_ops:
                raise _fleet_refusal("fleet L1 drifted", stream, stream_ops)
            pre_real = {key: before[key] for key in ("mappings", "settings", "aliases")}
            post_real = {key: after[key] for key in ("mappings", "settings", "aliases")}
            if status == "L2" and jcs(pre_real) != jcs(post_real):
                raise _fleet_refusal("fleet L2 drifted", stream, rfc6901_diff(pre_real, post_real))
            if status == "L3":
                projection = entry.get("projection", {})
                ops = rfc6901_diff(pre_real, post_real)
                if ops != projection.get("ops"):
                    raise _fleet_refusal("fleet L3 projection differs", stream, ops)
            if status == "L3-C":
                # simulate() supplies the independent bundle-derived
                # attestation; unchanged non-owned resolved outcome is the
                # conservative pointer-equivalent check for this closed W1 set.
                # The owned diagnosis paths are intentionally the only surface
                # allowed to move in this class.
                owned = entry.get("owned_leaf_payloads")
                if stream != DIAGNOSIS_STREAM:
                    raise _fleet_refusal("fleet L3-C stream is unattested", stream)
                if not isinstance(owned, dict) or not owned:
                    raise _fleet_refusal("fleet L3-C attestation is unavailable", stream)
                for op in rfc6901_diff(pre_real, post_real):
                    if not _l3c_op_matches_owned_payload(op, owned):
                        raise _fleet_refusal("fleet L3-C outside-owned drifted", stream, [op])
        if journal is not None:
            journal.fleet_fence_snapshot(phase, post)
    except InputError as error:
        if journal is not None:
            journal.fleet_fence_failure(phase, getattr(error, "stream", None), getattr(error, "ops", []),
                                        getattr(error, "reason", None))
        raise


def verify_late_fleet_fence(post: dict[str, object], late: dict[str, object],
                            journal: TransactionJournal | None = None) -> None:
    """The publication fence admits no further Fleet topology or outcome move."""
    try:
        if set(post) != set(late):
            stream = sorted(set(post) ^ set(late))[0]
            raise _fleet_refusal("late fleet stream set drifted", stream,
                                 rfc6901_diff(post.get(stream), late.get(stream)))
        for stream, value in post.items():
            if late.get(stream) != value:
                raise _fleet_refusal("late fleet stream drifted", stream,
                                     rfc6901_diff(value, late.get(stream)))
        if journal is not None:
            journal.fleet_fence_snapshot("late", late)
    except InputError as error:
        if journal is not None:
            journal.fleet_fence_failure("late", getattr(error, "stream", None), getattr(error, "ops", []),
                                        getattr(error, "reason", None))
        raise


def mint_key(es_url: str, authorization: str, role: dict, name: str) -> tuple[str, str]:
    mark_mutation_issued()
    response = es_json(es_url, "/_security/api_key", "POST", authorization,
                       {"name": name, "role_descriptors": {"rigsignal_shipper": role}})
    if not isinstance(response, dict) or not isinstance(response.get("id"), str) or not isinstance(response.get("encoded"), str):
        raise InputError("API key mint response is invalid")
    return response["id"], response["encoded"]


def invalidate(es_url: str, authorization: str, ids: list[str]) -> None:
    if not ids:
        return
    mark_mutation_issued()
    response = es_json(es_url, "/_security/api_key", "DELETE", authorization, {"ids": ids})
    if not isinstance(response, dict):
        raise InputError("API key invalidation was not confirmed")
    invalidated = response.get("invalidated_api_keys")
    previously = response.get("previously_invalidated_api_keys")
    error_count = response.get("error_count", 0)
    error_details = response.get("error_details", [])
    if (not isinstance(invalidated, list) or not all(isinstance(item, str) for item in invalidated)
            or not isinstance(previously, list) or not all(isinstance(item, str) for item in previously)
            or type(error_count) is not int or error_count != 0
            or not isinstance(error_details, list) or not all(isinstance(item, dict) for item in error_details)
            or any(item.get("id") in ids for item in error_details)):
        raise InputError("API key invalidation was not confirmed")
    # ES 9.4.3 returns both ID lists empty, with error_count=0, when an
    # already-invalidated key is invalidated again.  With a valid successful
    # response, absence from both lists is therefore affirmative inactive
    # state, not an unconfirmed revocation.


def invalidate_mint_name(es_url: str, authorization: str, mint_name: str) -> None:
    """Find and revoke every candidate made after a persisted mint intent.

    A process can die after Elasticsearch creates a key but before it can persist
    the returned ID.  The intent name is therefore a recovery handle, not just
    diagnostic text.  Refuse a malformed lookup response rather than treating
    it as proof that no orphan exists.
    """
    response = es_json(es_url, "/_security/api_key?name=" + urllib.parse.quote(mint_name, safe="")
                       + "&active_only=true",
                       "GET", authorization)
    keys = response.get("api_keys") if isinstance(response, dict) else None
    if not isinstance(keys, list):
        raise InputError("API key recovery lookup is invalid")
    ids: list[str] = []
    for item in keys:
        if (not isinstance(item, dict) or item.get("name") != mint_name
                or not isinstance(item.get("id"), str) or not item["id"]
                or len(item["id"].encode("utf-8")) > 1024):
            raise InputError("API key recovery lookup is invalid")
        ids.append(item["id"])
    invalidate(es_url, authorization, sorted(set(ids)))


def candidate_document(suffix: str, bundle: Bundle | None = None) -> dict:
    document = parse_json(bundle_resource(bundle, PROBE_FIXTURE_PATH, "provision proof fixture"),
                          "provision proof fixture")
    if not isinstance(document, dict):
        raise InputError("provision proof fixture is invalid")
    event_id = "provision-" + suffix
    document["@timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")
    document["event"] = {"id": event_id}
    document["host"] = {"name": socket.gethostname().lower()}
    return document


def assert_write_has_no_artifacts(response: object) -> None:
    if not isinstance(response, dict):
        raise InputError("candidate write response is invalid")
    if "_ignored" in response or response.get("failure_store") == "used":
        raise InputError("candidate write used ignored fields or failure store")


def assert_accepted_write_clean(response: object) -> None:
    assert_write_has_no_artifacts(response)


def assert_no_failure_store_document(es_url: str, authorization: str, event_id: str) -> None:
    try:
        result = es_json(es_url, "/" + DIAGNOSIS_STREAM + "::failures/_search", "POST", authorization,
                         {"query": {"term": {"event.id": event_id}}, "size": 1})
    except RequestFailure as error:
        # A disabled failure store may expose no searchable failure index.  A
        # 404 is therefore affirmative absence; every other response failure
        # leaves the proof incomplete.
        if error.status == 404:
            return
        raise
    hits = required_path(result, ("hits", "hits"))
    if not isinstance(hits, list) or hits:
        raise InputError("failure-store document exists after candidate write")


def assert_exact_probe_refetch(es_url: str, authorization: str, event_id: str, document: dict) -> None:
    result = es_json(es_url, "/" + DIAGNOSIS_STREAM + "/_search", "POST", authorization, {
        "query": {"ids": {"values": [event_id]}}, "size": 2,
    })
    hits = required_path(result, ("hits", "hits"))
    if (not isinstance(hits, list) or len(hits) != 1 or not isinstance(hits[0], dict)
            or hits[0].get("_id") != event_id or "_ignored" in hits[0]
            or jcs(hits[0].get("_source")) != jcs(document)):
        raise InputError("candidate exact-stream refetch failed")


def assert_mapping_rejection(status: int, response: object, error_type: str,
                             caused_by: str | None = None) -> None:
    error = response.get("error") if isinstance(response, dict) else None
    if status != 400 or not isinstance(error, dict) or error.get("type") != error_type:
        raise InputError("candidate mapping rejection proof failed")
    if caused_by is not None:
        cause = error.get("caused_by")
        if not isinstance(cause, dict) or cause.get("type") != caused_by:
            raise InputError("candidate mapping rejection proof failed")


def verify_stream_behavior(es_url: str, authorization: str, admin_authorization: str, suffix: str,
                           journal: TransactionJournal | None = None,
                           bundle: Bundle | None = None) -> None:
    document = candidate_document(suffix, bundle)
    event_id = document["event"]["id"]
    path = "/" + DIAGNOSIS_STREAM + "/_create/" + event_id + "?refresh=wait_for"
    proof_record = journal.proof_intent(event_id) if journal is not None else None
    fault("proof-create")
    mark_mutation_issued()
    status, response = es_json_status(es_url, path, "POST", authorization, document)
    if status != 201 or not isinstance(response, dict) or response.get("result") != "created":
        raise InputError("candidate exact-stream create failed")
    if proof_record is not None:
        index = response.get("_index")
        if not isinstance(index, str):
            raise InputError("candidate exact-stream create failed")
        journal.proof_index(proof_record, index)
    assert_accepted_write_clean(response)
    assert_exact_probe_refetch(es_url, admin_authorization, event_id, document)
    assert_no_failure_store_document(es_url, admin_authorization, event_id)
    # Real strictness proof; do not infer it from _simulate_index.
    bad = json.loads(json.dumps(document)); bad["unknown_root"] = True
    bad_id = "provision-bad-" + suffix
    mark_mutation_issued()
    status, response = es_json_status(es_url, "/" + DIAGNOSIS_STREAM + "/_create/" + bad_id,
                                      "POST", authorization, bad)
    assert_mapping_rejection(status, response, "strict_dynamic_mapping_exception")
    assert_write_has_no_artifacts(response)
    assert_no_failure_store_document(es_url, admin_authorization, bad_id)
    nested = json.loads(json.dumps(document))
    nested["rigsignal"]["diagnosis"]["unknown_probe_field"] = True
    nested_id = "provision-nested-" + suffix
    mark_mutation_issued()
    status, response = es_json_status(es_url, "/" + DIAGNOSIS_STREAM + "/_create/" + nested_id,
                                      "POST", authorization, nested)
    assert_mapping_rejection(status, response, "strict_dynamic_mapping_exception")
    assert_write_has_no_artifacts(response)
    assert_no_failure_store_document(es_url, admin_authorization, nested_id)
    malformed = json.loads(json.dumps(document))
    malformed["rigsignal"]["diagnosis"]["confidence"] = "not-a-number"
    malformed_id = "provision-malformed-" + suffix
    mark_mutation_issued()
    status, response = es_json_status(es_url, "/" + DIAGNOSIS_STREAM + "/_create/" + malformed_id,
                                      "POST", authorization, malformed)
    assert_mapping_rejection(status, response, "document_parsing_exception", "number_format_exception")
    assert_write_has_no_artifacts(response)
    assert_no_failure_store_document(es_url, admin_authorization, malformed_id)


def verify_role_matrix(es_url: str, authorization: str, suffix: str,
                       bundle: Bundle | None = None) -> None:
    document = candidate_document(suffix, bundle)
    path = "/" + DIAGNOSIS_STREAM + "/_create/provision-" + suffix
    # Exact CAN rows and deny matrix.  A duplicate _create is delivery idempotency
    # (409), while PUT to the existing ID must be an authorization failure (403).
    can_paths = ("/", "/_component_template/logs-rigsignal.diagnosis-mappings?filter_path=component_templates.name,component_templates.component_template._meta.accepted_schema_versions",
                 "/" + DIAGNOSIS_STREAM + "/_mapping")
    for item in can_paths:
        if response_status(es_url, item, "GET", authorization) != 200:
            raise InputError("candidate privilege CAN check failed")
    mark_mutation_issued()
    if response_status(es_url, path, "POST", authorization, document) != 409:
        raise InputError("candidate duplicate create check failed")
    # Overwrite proof, two layers (live wire disproved the 403 expectation:
    # data streams reject index-ops at request validation BEFORE authorization,
    # so PUT _doc returns 400 for any principal — structural impossibility):
    # (1) the 400 op_type guard below, (2) _has_privileges must show every
    # mutating privilege false on the exact stream name.
    mark_mutation_issued()
    if response_status(es_url, "/" + DIAGNOSIS_STREAM + "/_doc/provision-" + suffix,
                       "PUT", authorization, document) != 400:
        raise InputError("candidate overwrite op_type guard check failed")
    privileges = es_json(es_url, "/_security/user/_has_privileges", "POST", authorization, {
        "index": [{"names": [DIAGNOSIS_STREAM],
                   "privileges": ["index", "write", "delete", "delete_index", "manage"]}]})
    granted = privileges.get("index", {}).get(DIAGNOSIS_STREAM, {}) if isinstance(privileges, dict) else {}
    if not granted or any(granted.get(p) is not False for p in
                          ("index", "write", "delete", "delete_index", "manage")):
        raise InputError("candidate overwrite privilege check failed")
    denied = (("/" + DIAGNOSIS_STREAM + "/_doc/provision-" + suffix, "GET", None, False),
              # _search is a read-only POST and must never move the mutation
              # boundary merely because its HTTP verb is POST.
              ("/" + DIAGNOSIS_STREAM + "/_search", "POST", {"query": {"match_all": {}}}, False),
              # Bodies must be minimally VALID: ES validates the request shape
              # before authorization, so {} would 400 without proving denial.
              ("/_component_template/forbidden", "PUT", {"template": {"settings": {}}}, True),
              ("/_index_template/forbidden", "PUT",
               {"index_patterns": ["forbidden-provision-probe-*"], "template": {"settings": {}}}, True),
              ("/logs-rigsignal.diagnosis-other/_create/no", "POST", document, True))
    for item, method, payload, mutates in denied:
        if mutates:
            mark_mutation_issued()
        if response_status(es_url, item, method, authorization, payload) != 403:
            raise InputError("candidate privilege CANNOT check failed")


def enrollment_files(endpoint: str, ca_file: Path, root: Path, uuid_value: str, generation: str,
                     encoded: str, state: dict) -> dict[str, bytes]:
    # Paths are JSON quoted to produce valid TOML basic strings without leaking a
    # shell interpolation path into configuration.
    q = lambda value: json.dumps(value, ensure_ascii=False)
    return {"credentials.toml": ("[elasticsearch]\napi_key = " + q(encoded) + "\n").encode(),
            "handshake.toml": ("[elasticsearch]\nendpoint = " + q(endpoint) + "\nca_cert = "
                               + q(str(ca_file)) + "\n").encode(),
            "shipping-policy-v1.toml": ("ship_mode = \"on\"\ninstall_profile = \"user\"\noutbox_root = "
                                        + q(str(root.parent / "outbox")) + "\ntarget_generation = \"" + generation
                                        + "\"\nexpected_cluster_uuid = \"" + uuid_value + "\"\n").encode(),
            "state.json": jcs(state) + b"\n"}


def run_handshake(agent: Path, root: Path, journal: TransactionJournal | None = None) -> None:
    environment = os.environ.copy()
    for key in ("RIGSIGNAL_ENDPOINT", "RIGSIGNAL_CA_FILE", "RIGSIGNAL_EXPECTED_CLUSTER_UUID",
                "RIGSIGNAL_PENDING_ENROLLMENT", "RIGSIGNAL_TARGET_GENERATION", "RIGSIGNAL_API_KEY"):
        environment.pop(key, None)
    result = subprocess.run([str(agent), "handshake", "check", "--config", str(root / "handshake.toml"),
                             "--credentials-file", str(root / "credentials.toml")], env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        # The line is journaled only after full validation: bounded size, single line, no
        # fields beyond the probe schema, scalar values only, and whitelisted enums for the
        # three surfaced fields. Anything else is discarded whole - the journal and the raised
        # message must never carry unvalidated agent output.
        line = ""
        diagnosis = None
        if result.stdout and len(result.stdout) <= 4096:
            try:
                line = result.stdout.decode("utf-8")
                diagnosis = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                diagnosis = None
        allowed = {
            "outcome": {"failed", "ready", "pending_enrollment"},
            "reason": {"ready", "pending_enrollment", "local_config", "connectivity", "auth",
                       "destination", "compatibility", "unclassified_4xx"},
            "failed_stage": {"none", "local", "root_info", "template_read", "mapping_read"},
        }
        schema_keys = {"probe_schema_version", "diagnosis_schema_version", "outcome", "reason",
                       "failed_stage", "target_generation", "observed_cluster_uuid",
                       "accepted_set_digest"}
        valid = (isinstance(diagnosis, dict) and line.endswith("\n") and line.count("\n") == 1
                 and set(diagnosis) <= schema_keys
                 and all(isinstance(value, (str, int)) or value is None
                         for value in diagnosis.values())
                 and all(isinstance(diagnosis.get(name), str) and diagnosis[name] in allowed[name]
                         for name in allowed))
        if valid:
            if journal is not None:
                journal.published_probe_diagnosis(line)
            raise InputError("published handshake failed: " + " ".join(
                name + "=" + diagnosis[name] for name in ("outcome", "reason", "failed_stage")))
        raise InputError("published handshake failed")


def default_root() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return base / "rigsignal" / "enrollment"


def main() -> int:
    # This context is created before parsing or bundle setup so even the
    # journal-free assets-only path has the same finalization protocol.
    failure_tracker = FailureSiteTracker()
    mutation_tracker = MutationTracker()
    _mutation_tracker.set(mutation_tracker)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, help="bundle tarball to install")
    parser.add_argument("--endpoint", required=True, help="Elasticsearch HTTPS origin")
    parser.add_argument("--ca-file", type=Path, required=True, help="Elasticsearch CA file")
    parser.add_argument("--kibana-endpoint", required=True, help="Kibana HTTPS origin")
    parser.add_argument("--kibana-ca-file", type=Path, required=True, help="Kibana CA file")
    parser.add_argument("--admin-credentials-file", type=Path, required=True,
                        help="protected administrator TOML credential")
    parser.add_argument("--agent-binary", type=Path, required=True)
    parser.add_argument("--profile", choices=("user", "system"), required=True)
    parser.add_argument("--assets-only", action="store_true",
                        help="install bundle assets without creating an enrollment root")
    parser.add_argument("--assets-marker", type=Path, metavar="MARKER",
                        help="protected local ownership marker for --assets-only")
    parser.add_argument("--allow-untested-stack-version", action="store_true",
                        help="allow untested stable 9.x pairs above the supported floor with matching major.minor")
    parser.add_argument("--repair", action="store_true", help="re-apply proven-owned assets")
    parser.add_argument("--upgrade", action="store_true", help="re-apply proven-owned assets")
    parser.add_argument("--allow-downgrade", action="store_true",
                        help="re-apply proven-owned assets")
    parser.add_argument("--enrollment-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--adopt-existing-w1-stream", action="store_true",
                        help="one-shot adoption of a compatible pre-existing W1 diagnosis stream")
    parser.add_argument("--ownership-profile", choices=("default", "fleet-coexist"), default=None,
                        help="ownership policy for a Fleet-coexisting cluster")
    parser.add_argument("--rollback", type=Path, metavar="TRANSACTION",
                        help="explicitly reverse the journaled Fleet-coexist transaction at TRANSACTION")
    parser.add_argument("--predecessor-manifest", type=Path, metavar="MANIFEST",
                        help="owner-approved Fleet predecessor allow-set artifact")
    parser.add_argument("--dry-run", action="store_true", help="list API calls without network access")
    parser.add_argument("--unsafe-test-injection", action="store_true", help=argparse.SUPPRESS)
    try:
        args = parser.parse_args()
    except SystemExit as error:
        # argparse already emitted its canonical usage text.  It has no engine
        # FailureSite, and its documented local-usage status is 2.
        return 0 if error.code == 0 else 2
    active_test_hooks = sorted(key for key, value in os.environ.items()
                               if key.startswith("RIGSIGNAL_TEST_") and value)
    if active_test_hooks and not args.unsafe_test_injection:
        # Test controls are opt-in at the process boundary.  Individual helper
        # tests can exercise their gates directly, but a normal CLI invocation
        # must not acquire behavior from an inherited test environment.
        for key in active_test_hooks:
            os.environ.pop(key, None)
        active_test_hooks = []
    if active_test_hooks:
        print("test hooks active: " + ",".join(active_test_hooks), file=sys.stderr)
    raw_ownership_profile = args.ownership_profile
    ownership_profile = raw_ownership_profile or "default"
    bundle_archive_sha256: str | None = None
    default_asset_lock: AssetTransactionLock | None = None
    # Keep the boundary classifier available to the failure exits below, but
    # do not invoke it as a second process-entry preflight.  Existing callers
    # have ordered local refusal/recovery work (including copied-state and W2
    # checks) before the transaction executor.  Most importantly, a valid
    # possible-mutation record is a recovery input: only an executor refusal
    # or an earlier failure that prevents recovery may turn it into exit 4.
    boundary_marker_path = getattr(args, "assets_marker", None) or _asset_marker_default_path()
    try:
        if args.profile != "user":
            raise InputError("profile system is unsupported/broker-required")
        es_url = https_origin(args.endpoint, "--endpoint")
        kb_url = https_origin(args.kibana_endpoint, "--kibana-endpoint")
        if args.rollback is not None:
            rollback_root = secure_root(args.rollback)
            if args.dry_run:
                raise InputError("rollback dry-run is unsupported")
            # The rollback boundary is fenced before any remote recovery work.
            # With no archive it still binds the staged engine to the agent;
            # a supplied archive additionally binds both version and commit.
            rollback_bundle = load_bundle(args.bundle) if args.bundle is not None else None
            check_version_fence(rollback_bundle, args.agent_binary)
            configure_https(args.ca_file)
            configure_https(args.kibana_ca_file)
            authorization = admin_authorization(args.admin_credentials_file)
            # Rollback is an invocation boundary too: the ratified invariant
            # (RD "every boundary", ruling 5 stamp) fences profile and table
            # version before any journaled reversal begins (S1-v4).  The
            # requested profile comes from the journaled transaction being
            # reversed: a completed rollback legitimately restores the
            # enrollment profile file away (second-rollback refusal shape),
            # and the journal is the durable record of this root's profile.
            try:
                requested_profile = load_ownership_profile(rollback_root) or "default"
            except InputError:
                requested_profile = "default"
            journal_raw = secure_read(rollback_root / JOURNAL_FILE, missing_ok=True)
            if journal_raw is not None:
                try:
                    recorded = parse_json(journal_raw, JOURNAL_FILE)
                except InputError as error:
                    raise ProvisionError("install refused: transaction_journal_invalid") from error
                if isinstance(recorded, dict) and recorded.get("ownership_profile") in {"default", "fleet-coexist"}:
                    requested_profile = recorded["ownership_profile"]
            stack_version_preflight(es_url, kb_url, authorization,
                                    allow_untested=getattr(args, "allow_untested_stack_version", False))
            fence_remote_ownership_profile(es_url, authorization, requested_profile, False)
            operations = rollback_transaction(es_url, kb_url, authorization, rollback_root,
                                             deliberately_reversed=True, bundle_path=args.bundle)
            reported = False
            if any(item.startswith("verify-only:transforms/") for item in operations):
                print("rollback completed from journaled intents; transform _meta absence could not be restored: "
                      "verify-only cosmetic drift accepted")
                reported = True
            retained = []
            if any(item.startswith("retained-in-use:pipelines/") for item in operations):
                retained = _retained_pipeline_report_details(rollback_root)
            if retained:
                print("rollback completed from journaled intents; pipeline retained: "
                      "in use as default pipeline for adopted stream indices; " + "; ".join(retained))
                reported = True
            if "external_rollover_observed" in operations:
                print("rollback completed from journaled intents; external_rollover_observed")
                reported = True
            for item in operations:
                if item.startswith("unverified-orphan:"):
                    print("rollback completed from journaled intents; recovery incomplete: " + item)
                    reported = True
            if not reported:
                print("rollback completed from journaled intents")
            return 0
        if args.bundle is None:
            raise InputError("--bundle is required unless --rollback is used")
        bundle = load_bundle(args.bundle)  # Step 1: no HTTP before this line succeeds.
        predecessor_manifest = load_predecessor_manifest(getattr(args, "predecessor_manifest", None))
        role = role_body(bundle)
        ownership = ownership_for_assets(bundle, ownership_profile)
    except ProvisionError as error:
        boundary_status = transaction_boundary_failure(boundary_marker_path, -1)
        if boundary_status != -1:
            if isinstance(error, StackVersionRefusal):
                print(error.prefix, file=sys.stderr)
            return boundary_status
        return finalize_failure(error.prefix, failure_tracker, mutation_tracker,
                                local=is_local_failure_message(error.prefix))
    except (InputError, RequestFailure, OSError) as error:
        boundary_status = transaction_boundary_failure(boundary_marker_path, -1)
        if boundary_status != -1:
            return boundary_status
        if isinstance(error, OwnershipTableError):
            return finalize_failure("install refused: " + str(error), failure_tracker,
                                    mutation_tracker, local=True)
        if args.rollback is not None:
            return finalize_failure("install failed: enrollment output:", failure_tracker,
                                    mutation_tracker)
        return finalize_failure("install failed: bundle validation:", failure_tracker,
                                mutation_tracker, local=True)

    # Fleet coexistence carries a journaled enrollment transaction and
    # external-asset verification obligations.  The assets-only shortcut has
    # neither, so it is invalid even when dry-run would otherwise stop before
    # planning or mutation.
    if getattr(args, "assets_only", False) and ownership_profile == "fleet-coexist":
        return finalize_failure("install refused: fleet_coexist_requires_full_flow", failure_tracker,
                                mutation_tracker)

    total = len(bundle.assets)
    if args.dry_run:
        for asset in bundle.assets:
            if ownership[(asset.kind, asset.name)] == "external":
                print(f"external {asset.kind} {asset.name} -> GET {es_path(asset)} (verify-only)")
                continue
            if asset.kind == "dashboard":
                print(f"dashboard {asset.name} -> POST {dashboard_import_path(asset)}")
            elif asset.kind == "kibana_spaces":
                print(f"kibana-space {asset.name} -> GET {kibana_path(asset)}; "
                      f"POST /api/spaces/space; PUT {kibana_path(asset)}")
            elif asset.kind == "kibana_roles":
                print(f"kibana-role {asset.name} -> PUT/GET {kibana_path(asset)}")
            elif asset.kind == "transforms":
                print(f"transform {asset.name} -> PUT/POST {es_path(asset)}")
            else:
                print(f"{asset.kind} {asset.name} -> PUT {es_path(asset)}")
        print("bundle marker rigsignal-bundle-meta -> PUT /_component_template/rigsignal-bundle-meta")
        print(f"ownership profile: {ownership_profile}")
        print(f"source assets: {total}")
        return 0

    if getattr(args, "assets_only", False):
        try:
            # ERRATA-6 is a local, non-authorizing boundary.  It intentionally
            # precedes the version fence, snapshot, credential read, and the
            # assets-only prerequisite/cluster reads.  Valid pm=true input is
            # not terminal here and therefore still reaches reconciliation.
            boundary_status = transaction_boundary_version_preflight(
                boundary_marker_path, bundle, upgrade=getattr(args, "upgrade", False),
                allow_downgrade=getattr(args, "allow_downgrade", False))
            if boundary_status is not None:
                return boundary_status
            # Slice 1's version/commit fence remains an invocation boundary,
            # while this path deliberately never resolves or creates an
            # enrollment root.
            check_version_fence(bundle, args.agent_binary)
            if args.bundle.is_file():
                snapshot_dir = transaction_snapshot_directory(getattr(args, "assets_marker", None))
                cleanup_snapshot_residues(snapshot_dir)
                snapshot = snapshot_bundle(args.bundle, snapshot_dir)
                try:
                    bundle = load_bundle(snapshot.path)
                    bundle_archive_sha256 = snapshot.sha256
                    check_version_fence(bundle, args.agent_binary)  # re-fence the snapshotted bytes
                finally:
                    snapshot.close()
            configure_https(args.ca_file)
            configure_https(args.kibana_ca_file)
            authorization = admin_authorization(args.admin_credentials_file)
            marker_path = _prepare_assets_marker_path(getattr(args, "assets_marker", None), bundle)
            failure_tracker.mark(FailureSite.ASSET_APPLY)
            outcome = assets_only_install(bundle, es_url, kb_url, authorization, marker_path,
                                          repair=getattr(args, "repair", False),
                                          upgrade=getattr(args, "upgrade", False),
                                          allow_downgrade=getattr(args, "allow_downgrade", False),
                                          archive_sha256=(bundle_archive_sha256 if args.bundle.is_file() else None),
                                          unsafe_test_injection=args.unsafe_test_injection,
                                          allow_untested_stack_version=getattr(args, "allow_untested_stack_version", False))
            print("assets-only " + outcome)
            return asset_executor_exit_code("success", marker_path)
        except (AssetTransactionHalt, AssetTransactionRefusal):
            # The record, not only this process's request tracker, is the
            # authority after a durable write-issued transition.
            status = asset_executor_exit_code("halt", marker_path)
            return status if status == 4 else finalize_failure(
                "install refused: assets_transaction_invalid", failure_tracker, mutation_tracker)
        except ProvisionError as error:
            boundary_status = transaction_boundary_failure(boundary_marker_path, -1)
            if boundary_status != -1:
                if isinstance(error, StackVersionRefusal):
                    print(error.prefix, file=sys.stderr)
                return boundary_status
            status = (asset_executor_exit_code("refusal", marker_path)
                      if "marker_path" in locals() else 3)
            if status == 4 and isinstance(error, StackVersionRefusal):
                print(error.prefix, file=sys.stderr)
            return 4 if status == 4 else finalize_failure(error.prefix, failure_tracker, mutation_tracker,
                                                           local=is_local_failure_message(error.prefix))
        except (InputError, RequestFailure, OSError) as error:
            message = "RIGSIGNAL_E_ASSETS_ONLY: " + type(error).__name__ + ": " + str(error)
            if "marker_path" in locals() and mutation_tracker.mutation_issued:
                return transaction_failure_status(marker_path)
            # Direction flags are parsed successfully but are locally invalid
            # unless a validated predecessor authorizes their use.  Preserve
            # the public local-input code rather than converting this into an
            # ordinary remote refusal merely because it arose in the shared
            # transaction executor.
            if ("marker_path" in locals() and isinstance(error, InputError)
                    and ("version flags" in str(error) or "version direction" in str(error))):
                return asset_executor_exit_code("local-input", marker_path)
            boundary_status = transaction_boundary_failure(boundary_marker_path, -1)
            if boundary_status != -1:
                return boundary_status
            return finalize_failure(message, failure_tracker,
                                    mutation_tracker,
                                    local=(not mutation_tracker.mutation_issued
                                           and not isinstance(error, (RequestFailure, RemoteReadRefusal, AssetLockHeld))
                                           and "assets transaction" not in str(error)))

    try:
        requested_root = args.enrollment_root or default_root()
        condition = enrollment_condition(requested_root)
        if condition == "remediation":
            raise ProvisionError("install refused: enrollment_remediation_required")
        adopt_requested = getattr(args, "adopt_existing_w1_stream", False)
        if adopt_requested and condition in {"committed", "incomplete"}:
            raise ProvisionError("install refused: adoption_flag_state_present")
        # Keep incomplete enrollment's key-recovery ordering intact: that
        # state can require a remote cleanup before an ordinary local refusal
        # is allowed to terminate the invocation.  All other default full-flow
        # calls get the same zero-transport flag boundary as assets-only.
        if ownership_profile == "default" and bundle.assets and condition != "incomplete":
            boundary_status = transaction_boundary_version_preflight(
                boundary_marker_path, bundle, upgrade=getattr(args, "upgrade", False),
                allow_downgrade=getattr(args, "allow_downgrade", False))
            if boundary_status is not None:
                return boundary_status
        check_version_fence(bundle, args.agent_binary)
        if args.bundle.is_file():
            snapshot_dir = transaction_snapshot_directory(getattr(args, "assets_marker", None))
            cleanup_snapshot_residues(snapshot_dir)
            snapshot = snapshot_bundle(args.bundle, snapshot_dir)
            try:
                bundle = load_bundle(snapshot.path)
                bundle_archive_sha256 = snapshot.sha256
                role = role_body(bundle)
                ownership = ownership_for_assets(bundle, ownership_profile)
                check_version_fence(bundle, args.agent_binary)  # re-fence the snapshotted bytes
            finally:
                snapshot.close()
        # Default to the no-HTTP publication guard.  Incomplete is the sole
        # exception: it must first reach its durable key-recovery path, so a
        # new local refusal cannot strand that key.  A future condition is
        # therefore fail-closed by preflighting rather than silently skipping
        # the guard as committed once did.
        enrollment_ca_file = args.ca_file
        resolved_agent: Path | None = None
        if condition != "incomplete":
            check_install_root_ancestors(requested_root)
            check_outbox_root(requested_root.parent / "outbox")
            enrollment_ca_file, resolved_agent = check_install_preflight(
                requested_root, args.agent_binary, args.ca_file)
        configure_https(enrollment_ca_file)
        configure_https(args.kibana_ca_file)
        authorization = admin_authorization(args.admin_credentials_file)
        if admin_credential_kind(args.admin_credentials_file) != "native_user":
            # API keys may still parse for dry-run/read-only tooling, but this
            # invocation will mint a descriptor-bearing shipper key.
            raise ProvisionError("install refused: admin_credential_api_key")
        # Authenticated eligibility and any override warning precede all
        # recovery mutations, including revocation of unfinished candidates.
        stack_version_preflight(es_url, kb_url, authorization,
                                allow_untested=getattr(args, "allow_untested_stack_version", False))
        needs_default_marker = ownership_profile == "default" and bool(bundle.assets)
        # Incomplete enrollment is the sole ordering exception: its pending
        # credential must be recovered or invalidated before a new local
        # marker-directory refusal can stop the invocation.
        default_marker_path = (None if not needs_default_marker or condition == "incomplete" else
                               _prepare_assets_marker_path(getattr(args, "assets_marker", None), bundle))
        # A clean root or the owner-ratified rolled-back audit-only root can
        # adopt a compatible remote stream.  Decide it before creating the
        # root or running recovery.
        adoption = (dispatch_clean_root(es_url, authorization, adopt_requested, bundle)
                     if condition in {"clean", "rolled-back"} else False)

        # The marker survives local rollback and a fresh enrollment root.  It
        # is therefore the authoritative rerun fence, ahead of secure_root()
        # and every subsequent mutation.
        if bundle.assets or ownership_profile == "fleet-coexist":
            fence_remote_ownership_profile(es_url, authorization, ownership_profile,
                                           raw_ownership_profile is None)
            run_topology_preflight(bundle, es_url, kb_url, authorization, ownership_profile)
        # Default profile has one transaction engine for every caller.  The
        # Fleet-coexist journal remains the only legacy transaction path.
        test_pause("after-topology-preflight", args.unsafe_test_injection, es_url)
        failure_tracker.mark(FailureSite.ROOT_PREPARE)
        root = prepare_install_root(requested_root)
        try:
            prior = load_state(root)
        except StateBindingError as error:
            raise ProvisionError("install refused: enrollment_remediation_required") from error
        bind_ownership_profile(root, ownership_profile, implicit_default=raw_ownership_profile is None)

        # Step 2: recover/pin before normal work.  Unpublished credentials are
        # never reused; their identifiers survive in state for deterministic
        # recovery.  A later run can safely revoke the listed candidate.
        uuid_value = cluster_uuid(es_url, authorization)
        if prior is not None and prior["expected_cluster_uuid"] != uuid_value:
            # A retained enrollment root pointed at another cluster is the
            # v2.4 rerun refusal, with the same no-mutation contract as an
            # incompatible existing diagnosis stream.
            raise ProvisionError("install refused: existing diagnosis stream is not W1; migration is required")
        published_recovery = None
        if prior is not None and prior["phase"] != "committed":
            # candidate_verified with candidate already named as active is the
            # only recoverable post-publication state: credentials/configuration
            # were atomically released and only old-key cleanup was interrupted.
            if (prior["phase"] == "candidate_verified" and prior["candidate_key_id"]
                    and prior["active_key_id"] == prior["candidate_key_id"]):
                # The exchanged directory is coherent, but a crash may have
                # happened before Step 10's zero-environment probe.  Defer the
                # probe until the incomplete-path preflight has returned the
                # verified agent identity below.
                published_recovery = prior
            else:
                # mint_intent is durable before the request.  A returned key ID
                # is therefore insufficient for recovery: a crash after the
                # server creates it but before our response is stored leaves an
                # otherwise unreachable live key.  Discover by the exact intent
                # name first, then invalidate the recorded ID as well.
                invalidate_mint_name(es_url, authorization, prior["pending_mint_name"])
                candidates = [item for item in (prior["candidate_key_id"],) if item]
                if candidates:
                    invalidate(es_url, authorization, candidates)
                remove_candidate_root(root)
                # Do not silently preserve an incomplete candidate as active.
                if prior["active_key_id"] is None:
                    remove_recovered_state(root)
                    prior = None
                else:
                    prior = state_template(uuid_value, prior["target_generation"], prior["active_key_id"],
                                           prior["enrollment_root"])
                    atomic_write(root, "state.json", jcs(prior) + b"\n")
        # A crash before exchange or during old-generation cleanup leaves an
        # owned private publication sibling.  Bundle-A deliberately refuses on
        # the next invocation so an operator, rather than this recovery path,
        # examines and removes the exact recognized debris.

        if condition == "incomplete" and prior is None:
            # A null-active recovery restores the clean-root condition.  Apply
            # the same remote decision matrix now that recovery side effects
            # are durable; adoption is one-shot and was already rejected above.
            dispatch_clean_root(es_url, authorization, False, bundle)

        if condition == "incomplete":
            # Recovery has now invalidated the unfinished candidate (or made
            # its successor state durable), so any same-class refusal below
            # cannot make an uncommitted minted key unreachable.
            check_install_root_ancestors(requested_root)
            check_outbox_root(requested_root.parent / "outbox")
            enrollment_ca_file, resolved_agent = check_install_preflight(root, args.agent_binary, args.ca_file)
            configure_https(enrollment_ca_file)
            if needs_default_marker:
                default_marker_path = _prepare_assets_marker_path(
                    getattr(args, "assets_marker", None), bundle)
        if resolved_agent is None:
            raise ProvisionError("install refused: agent_binary_unlaunchable")
        if published_recovery is not None:
            try:
                # Do not declare the recovered exchange committed until this
                # exact consumer check succeeds on the published paths.
                run_handshake(resolved_agent, root)
                invalidate(es_url, authorization, published_recovery["pending_revoke_ids"])
            except (InputError, RequestFailure) as error:
                raise ProvisionError("install failed: old shipper API key revocation:") from error
            prior = state_template(uuid_value, published_recovery["target_generation"],
                                   published_recovery["active_key_id"],
                                   published_recovery["enrollment_root"])
            atomic_write(root, "state.json", jcs(prior) + b"\n")
        failure_tracker.mark(FailureSite.ASSET_APPLY)
        prerequisites(es_url, kb_url, authorization, versions_checked=True)  # Step 3
        cluster_health_gate(es_url, authorization)  # protocol invariant, all profiles
        fence(es_url, authorization, prior, uuid_value, root, adoption, bundle)  # Step 4, before W1 PUT
        pre_put_condition, pre_put_snapshot = remote_stream_condition(es_url, authorization, bundle)
        if pre_put_condition == "absent":
            pre_put_snapshot = None
        elif pre_put_condition != "compatible":
            raise ProvisionError("install refused: migration_required")

        # Step 5: resolve every default-profile target before an asset write.
        # Fleet coexistence retains its separately-ratified 16/39 classifier.
        applied_owned_assets: list[dict] = []
        verified_external_assets: list[dict] = []
        journal: TransactionJournal | None = None
        pre_fleet_snapshot: dict[str, object] | None = None
        fleet_plan: dict = {}
        planned_actions: dict[tuple[str, str], str] = {}
        predecessor_pins: dict[tuple[str, str], str] = {}
        post_fleet_snapshot: dict[str, object] | None = None
        candidate_drift_done = False
        default_transaction_done = False
        if ownership_profile == "default" and needs_default_marker:
            if default_marker_path is None:
                raise InputError("assets transaction record path is unavailable")
            binding = transaction_binding(bundle, uuid_value, kb_url,
                                          bundle_archive_sha256 or bundle_snapshot_digest(bundle))
            default_asset_lock = AssetTransactionLock.acquire()
            try:
                run_default_asset_transaction(bundle, es_url, kb_url, authorization,
                                              default_marker_path, binding, full_flow=True,
                                              repair=getattr(args, "repair", False),
                                              upgrade=getattr(args, "upgrade", False),
                                              allow_downgrade=getattr(args, "allow_downgrade", False),
                                              defer_step_11=True,
                                              unsafe_test_injection=args.unsafe_test_injection,
                                              lock=default_asset_lock)
            except (AssetTransactionHalt, AssetTransactionRefusal):
                status = asset_executor_exit_code("halt", default_marker_path)
                if status == 4:
                    return 4
                raise ProvisionError("install refused: assets_transaction_invalid")
            except InputError:
                # Version-flag direction/same-version errors are local at the
                # actual full-flow boundary (ERRATA-6/T-EXIT-2).
                boundary_status = transaction_boundary_failure(default_marker_path, -1)
                if boundary_status != -1:
                    return boundary_status
                return asset_executor_exit_code("local-input", default_marker_path)
            default_transaction_done = True
        if ownership_profile == "fleet-coexist":
            try:
                # This capture dynamically enumerates the active stream set;
                # a rollover during this transaction is a fail-closed drift.
                pre_fleet_snapshot = fleet_stream_snapshot(es_url, authorization)
                test_rollover("after-fleet-snapshot", es_url, authorization, pre_fleet_snapshot)
                journal = TransactionJournal(root, ownership_profile, new_transaction=True)
                failure_tracker.attach_journal(journal)
                journal.pin_bundle(args.bundle, bundle)
                if not journal.value.get("m1_anchors"):
                    journal.pin_m1_anchors(m1_anchor_pins(es_url, authorization))
                # P3 is a complete no-write barrier.  P4 repeats each pin at
                # its write site below, rather than trusting this first read.
                for asset in bundle.assets:
                    if ownership[(asset.kind, asset.name)] != "external":
                        planned_actions[(asset.kind, asset.name)] = owned_action(es_url, kb_url, authorization, asset)
                predecessor_pins = predecessor_manifest_barrier(
                    es_url, kb_url, authorization, bundle, ownership, predecessor_manifest, journal)
                try:
                    fleet_plan = plan_fleet_fence(es_url, authorization, pre_fleet_snapshot,
                                                   bundle, planned_actions, journal)
                    verify_fleet_stream_overrides(es_url, authorization, fleet_plan)
                except (RequestFailure, InputError) as error:
                    journal.fleet_fence_failure("pre", getattr(error, "stream", None),
                                                getattr(error, "ops", []))
                    raise ProvisionError("install failed: fleet stream verification:") from error
                for asset in bundle.assets:
                    if ownership[(asset.kind, asset.name)] == "external":
                        if external_write_test_allowed(es_url, args.unsafe_test_injection):
                            # Gate-only negative control for the recording
                            # transport.  It is deliberately impossible to
                            # trigger without an explicit test environment.
                            mutation_request(es_url, es_path(asset), "PUT", authorization, asset.data)
                        verified_external_assets.append(verify_external_asset(es_url, authorization, asset))
                journal.pin_external_baselines(verified_external_assets)
            except (RequestFailure, InputError) as error:
                raise ProvisionError(f"install refused: external asset compatibility: {error}") from error
        for asset in bundle.assets:
            if default_transaction_done:
                continue
            if ownership[(asset.kind, asset.name)] == "external":
                continue
            try:
                action = planned_actions[(asset.kind, asset.name)]
                records: list[dict] = []
                if journal is not None:
                    if predecessor_manifest is not None and action != "noop":
                        recheck_predecessor_pins(
                            es_url, kb_url, authorization, asset,
                            predecessor_pins.get((asset.kind, asset.name)), journal)
                    if asset.kind == "index_templates" and asset.name == "logs-rigsignal.stream" and action != "noop":
                        lifecycle_delete_phase_free(es_url, authorization)
                    records = journal_owned_asset(journal, es_url, kb_url, authorization, asset, action)
                    if (asset.kind == "transforms" and action != "noop"
                            and transform_preapply_requires_verify_only(
                                journal, records[0], es_url, authorization, asset)):
                        journal.mark_transform_verify_only(
                            records[0], "meta_absent_restore_unproven_preapply")
                        action = "noop"
                    fault("after-write-intent")
                if action != "noop":
                    if (ownership_profile == "fleet-coexist" and asset.kind == "index_templates"):
                        try:
                            # R1: repeat immediately before every template PUT.
                            verify_fleet_stream_overrides(es_url, authorization, fleet_plan,
                                                          journal, "write")
                        except (RequestFailure, InputError) as error:
                            raise ProvisionError("install failed: fleet stream verification:") from error
                    if asset.kind == "dashboard":
                        fault("dashboard-multipart")
                    install_asset(es_url, kb_url, authorization, asset,
                                  managed=ownership_profile == "default")
                    fault("after-remote-mutation", f"{asset.kind}/{asset.name}")
                    if not candidate_drift_done:
                        test_candidate_drift("after-first-owned-write", es_url, authorization,
                                             pre_fleet_snapshot or {})
                        candidate_drift_done = True
                if journal is not None:
                    journal_verify_owned_asset(journal, records, es_url, kb_url, authorization, asset)
                    fault("after-write-verified")
                if ownership_profile == "fleet-coexist":
                    applied_owned_assets.append({"kind": asset.kind, "name": asset.name, "action": action,
                                                 "request_body_sha256": hashlib.sha256(asset.data).hexdigest()})
            except PredecessorRefusal as error:
                if journal is not None:
                    raise predecessor_recheck_provision_error(journal, error) from error
                raise ProvisionError("install failed: predecessor recheck:") from error
            except (RequestFailure, InputError) as error:
                if asset.kind == "security_roles":
                    category = "shipper role verification:"
                elif asset.kind in {"kibana_spaces", "kibana_roles", "dashboard"}:
                    category = "Kibana asset verification:"
                else:
                    category = "W1 asset verification:"
                raise ProvisionError("install failed: " + category) from error
        try:
            ensure_stream(es_url, authorization)
            simulate(es_url, authorization, bundle)
            if ownership_profile == "fleet-coexist":
                verify_fleet_stream_overrides(es_url, authorization, fleet_plan,
                                              journal, "post")
                post_fleet_snapshot = fleet_stream_snapshot(es_url, authorization)
                verify_fleet_fence(pre_fleet_snapshot or {}, post_fleet_snapshot,
                                   fleet_plan, journal, "post")
                verify_fleet_winner_proofs(es_url, authorization, fleet_plan)
        except (RequestFailure, InputError) as error:
            raise ProvisionError("install failed: fleet stream verification:") from error
        if pre_put_snapshot is None:
            # Fresh installation has no stream to snapshot before its W1
            # creates; from here on it receives the same drift protection.
            _, pre_put_snapshot = remote_stream_condition(es_url, authorization, bundle)
            if pre_put_snapshot is None:
                raise ProvisionError("install failed: diagnosis stream verification:")

        generation = recompute_target_generation({asset.path: asset.data for asset in bundle.assets})
        # A current key is only retained after a fresh proof.  Reading its secret
        # from the protected credential file is intentional and never logged.
        encoded: str | None = None
        reuse = prior is not None and prior["role_jcs_sha256"] == ROLE_JCS_SHA256
        if reuse:
            try:
                credential = parse_json(b"{}", "internal")
                del credential
                import tomllib
                encoded = tomllib.loads((secure_read(root / "credentials.toml") or b"").decode())["elasticsearch"]["api_key"]
                if not isinstance(encoded, str):
                    raise ValueError()
                proof_suffix = uuid.uuid4().hex
                verify_stream_behavior(es_url, "ApiKey " + encoded, authorization, proof_suffix, journal, bundle)
                verify_role_matrix(es_url, "ApiKey " + encoded, proof_suffix, bundle)
            except (InputError, ValueError, KeyError, TypeError, RequestFailure):
                reuse = False
                encoded = None
        old_id = prior["active_key_id"] if prior else None
        if not reuse:
            mint_name = "rigsignal-provision-" + uuid.uuid4().hex
            intent = state_template(uuid_value, generation, old_id, str(root))
            intent.update(phase="mint_intent", pending_mint_name=mint_name)
            failure_tracker.mark(FailureSite.CANDIDATE_STAGE)
            atomic_write(root, "state.json", jcs(intent) + b"\n")
            mint_journal = None
            if journal is not None:
                mint_request = jcs({"name": mint_name, "role_descriptors": {"rigsignal_shipper": role}})
                mint_journal = journal.write_intent("api_key", mint_name, "create",
                                                    asset_adapters.dashboard_absent_hash(),
                                                    hashlib.sha256(mint_request).hexdigest(), mint_request)
            fault("before-mint-response")
            candidate_id, encoded = mint_key(es_url, authorization, role, mint_name)
            if mint_journal is not None:
                # The exact request pin is the durable recovery discriminator;
                # the returned opaque key ID is persisted by the existing state
                # transition immediately after this verification record.
                journal.write_verified(mint_journal, mint_journal["intended_after_sha256"])
                journal.api_key_id(mint_journal, candidate_id)
            fault("after-mint-response")
            staged = dict(intent)
            staged.update(phase="candidate_staged", candidate_key_id=candidate_id)
            failure_tracker.mark(FailureSite.CANDIDATE_STAGE)
            atomic_write(root, "state.json", jcs(staged) + b"\n")
            failure_tracker.mark(FailureSite.CANDIDATE_STAGE)
            candidate_root = secure_candidate_root(root)
            candidate_files = enrollment_files(es_url, enrollment_ca_file, root, uuid_value, generation, encoded, staged)
            for name, contents in candidate_files.items():
                failure_tracker.mark(FailureSite.CANDIDATE_STAGE)
                atomic_write(candidate_root, name, contents)
            fault("candidate-write")
            try:
                proof_suffix = uuid.uuid4().hex
                verify_stream_behavior(es_url, "ApiKey " + encoded, authorization, proof_suffix, journal, bundle)  # Step 7
            except (InputError, RequestFailure):
                invalidate(es_url, authorization, [candidate_id])
                raise ProvisionError("install failed: diagnosis stream verification:")
            try:
                verify_role_matrix(es_url, "ApiKey " + encoded, proof_suffix, bundle)  # Step 8
            except (InputError, RequestFailure):
                invalidate(es_url, authorization, [candidate_id])
                raise ProvisionError("install failed: shipper credential verification:")
            staged["phase"] = "candidate_verified"
            failure_tracker.mark(FailureSite.CANDIDATE_STAGE)
            atomic_write(root, "state.json", jcs(staged) + b"\n")
            fault("candidate-verify")
        else:
            candidate_id = old_id
            staged = state_template(uuid_value, generation, candidate_id, str(root))

        assert encoded is not None and candidate_id is not None
        try:
            # The asset writes, candidate checks, and publication are separated
            # by a final read-only fence.  It closes the period in which a
            # rollover or template mutation could otherwise be published over.
            # This is deliberately after the candidate proof (Steps 7/8) and
            # before publication (Step 9), so the clean-stack late-rollover
            # leg exercises the actual final fence rather than an earlier
            # transaction drift path.  It is inert unless explicitly gated.
            if ownership_profile == "fleet-coexist":
                test_candidate_drift("before-publication", es_url, authorization,
                                     post_fleet_snapshot or {})
            if not default_transaction_done:
                prepublication_asset_fence(es_url, kb_url, authorization, bundle,
                                           ownership_profile, ownership,
                                           journal.value.get("external_baselines") if journal is not None else None,
                                           default_assets_managed=ownership_profile == "default")
            simulate(es_url, authorization, bundle)
            if ownership_profile == "fleet-coexist":
                if post_fleet_snapshot is None:
                    raise InputError("late fleet snapshot is unavailable")
                verify_fleet_stream_overrides(es_url, authorization, fleet_plan,
                                              journal, "late")
                verify_late_fleet_fence(post_fleet_snapshot,
                                        fleet_stream_snapshot(es_url, authorization), journal)
                verify_fleet_winner_proofs(es_url, authorization, fleet_plan)
            post_condition, post_snapshot = remote_stream_condition(es_url, authorization, bundle)
            if post_condition != "compatible" or post_snapshot != pre_put_snapshot:
                raise InputError("pre-publication stream snapshot drifted")
            if journal is not None:
                verify_m1_anchors(es_url, authorization, journal.value.get("m1_anchors", {}))
        except (InputError, RequestFailure) as error:
            # The durable candidate state is deliberately retained for the
            # established recovery path; no consumer publication or marker can
            # occur after this fence fails.
            # Phase-3 runbook classifies this with the Step-5 fence-abort string.
            raise ProvisionError("install failed: pre-publication fence:") from error
        final = state_template(uuid_value, generation, candidate_id, str(root))
        # Step 9.  During replacement the old ID is kept pending until published
        # files verify, but state is committed only after its confirmation.
        # The directory exchange publishes a coherent but deliberately
        # uncommitted generation.  Step 10's published-file probe is the only
        # operation allowed to advance it to committed, including a reuse-only
        # template generation where no key was minted.
        publish = dict(final)
        publish.update(phase="candidate_verified", pending_mint_name="published-pending-revoke",
                       candidate_key_id=candidate_id)
        if old_id and old_id != candidate_id:
            publish["pending_revoke_ids"] = [old_id]
        publication_files = enrollment_files(es_url, enrollment_ca_file, root, uuid_value, generation, encoded, publish)
        # A minted candidate is staged under the private candidate directory
        # before any named consumer file is touched.  Reuse has no new secret
        # to stage, so render the equivalent already-proved generation here.
        if not reuse:
            failure_tracker.mark(FailureSite.CANDIDATE_STAGE)
            candidate_root = secure_candidate_root(root)
            for name in publication_files:
                failure_tracker.mark(FailureSite.CANDIDATE_STAGE)
                atomic_write(candidate_root, name, publication_files[name])
        failure_tracker.mark(FailureSite.PUBLICATION_STAGE)
        atomic_publication(root, publication_files, failure_tracker)
        fault("published-state")

        # Step 10 has no endpoint/credential environment fallback.
        failure_tracker.mark(FailureSite.PUBLISHED_PROBE)
        if journal is None:
            run_handshake(resolved_agent, root)
        else:
            run_handshake(resolved_agent, root, journal)
        if old_id and old_id != candidate_id:
            try:
                fault("before-revoke")
                invalidate(es_url, authorization, [old_id])
                fault("after-revoke")
            except (InputError, RequestFailure) as error:
                raise ProvisionError("install failed: old shipper API key revocation:") from error
        failure_tracker.mark(FailureSite.LOCAL_COMMIT)
        atomic_write(root, "state.json", jcs(final) + b"\n")
        remove_candidate_root(root)

        # Step 11 and only step 11: marker is never an early partial-success bit.
        marker = Asset("component_templates", "rigsignal-bundle-meta", "", marker_body(
            bundle, ownership_profile, applied_owned_assets, verified_external_assets))
        try:
            if default_transaction_done:
                if default_marker_path is None or default_asset_lock is None:
                    raise InputError("assets transaction lock is unavailable")
                binding = transaction_binding(bundle, uuid_value, kb_url,
                                              bundle_archive_sha256 or bundle_snapshot_digest(bundle))
                run_default_asset_transaction(bundle, es_url, kb_url, authorization,
                                              default_marker_path, binding, full_flow=True,
                                              repair=getattr(args, "repair", False),
                                              upgrade=getattr(args, "upgrade", False),
                                              allow_downgrade=getattr(args, "allow_downgrade", False),
                                              step_11_only=True,
                                              unsafe_test_injection=args.unsafe_test_injection,
                                              lock=default_asset_lock)
            else:
                if journal is not None:
                    marker_records = journal_owned_asset(journal, es_url, kb_url, authorization, marker, "create")
                mutation_request(es_url, es_path(marker), "PUT", authorization, marker.data)
                verify_asset(es_url, authorization, marker)
                if journal is not None:
                    journal_verify_owned_asset(journal, marker_records, es_url, kb_url, authorization, marker)
                    journal.apply_ok()
        except (InputError, RequestFailure) as error:
            raise ProvisionError("install failed: bundle marker:") from error
        finally:
            if default_asset_lock is not None:
                default_asset_lock.close()
                default_asset_lock = None
        if ownership_profile == "fleet-coexist":
            print(f"applied {len(applied_owned_assets)} owned assets; verified "
                  f"{len(verified_external_assets)} external assets")
        else:
            print(f"installed {total}/{total} assets")
        return 0
    except ProvisionError as error:
        boundary_status = transaction_boundary_failure(boundary_marker_path, -1)
        if boundary_status != -1:
            if isinstance(error, StackVersionRefusal):
                print(error.prefix, file=sys.stderr)
            return boundary_status
        return finalize_failure(error.prefix, failure_tracker, mutation_tracker,
                                local=is_local_failure_message(error.prefix))
    except (InputError, RequestFailure, OSError):
        # The public contract deliberately avoids exposing response bodies and
        # exception text, which could contain credentials or cluster data.
        boundary_status = transaction_boundary_failure(boundary_marker_path, -1)
        if boundary_status != -1:
            return boundary_status
        if "default_marker_path" in locals() and default_marker_path is not None and mutation_tracker.mutation_issued:
            return transaction_failure_status(default_marker_path)
        return finalize_failure("install failed: enrollment output:", failure_tracker,
                                mutation_tracker, local=False)
    finally:
        if default_asset_lock is not None:
            default_asset_lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
