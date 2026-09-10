"""Scripted HTTP transport for v2 transaction tests.

This replaces ``urllib.request.urlopen`` rather than the installer request
helpers, so callers retain the real mutation tracker and guarded code paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError
from urllib.parse import parse_qs, unquote, urlsplit


@dataclass(frozen=True)
class HttpCall:
    method: str
    path: str
    query: Mapping[str, tuple[str, ...]]
    data: bytes | None


@dataclass(frozen=True)
class HttpReply:
    status: int = 200
    body: object = field(default_factory=dict)
    loss: bool = False


@dataclass(frozen=True)
class TargetScript:
    """Declarative response script for one v2 target.

    ``conditional`` maps ``create``, ``createOnly``, or ``if_version`` to a
    reply.  GET/PUT/resolve/import can each be one reply or a reply sequence.
    Pipeline timestamps, role ``created`` and saved-object ``destinationId``
    are explicit because the v2 detector consumes them directly.
    """

    live_state: str = "exact"
    get: object | None = None
    put: object | None = None
    resolve: object | None = None
    import_: object | None = None
    conditional: Mapping[str, object] = field(default_factory=dict)
    role_created: bool | None = None
    pipeline_created_millis: int | None = None
    pipeline_modified_millis: int | None = None
    version: int | None = None
    destination_id: str | None = None
    response_loss: bool = False


@dataclass(frozen=True)
class TransactionRow:
    """Row projection for later main()-runner conversion."""

    caller: str
    live_state: str
    flags: tuple[str, ...]

    @classmethod
    def from_row(cls, row: Sequence[str] | Mapping[str, str]) -> "TransactionRow":
        if isinstance(row, Mapping):
            caller = row["caller"]
            live = row.get("ordinary_live", row.get("live_state", "exact"))
            flags = row.get("flags", "none")
        else:
            caller, live, flags = row[0], row[2], row[4]
        return cls(caller, live, () if flags == "none" else tuple(flags.split("+")))


class _Response:
    def __init__(self, status: int, body: bytes):
        self.status, self._body = status, body

    def read(self) -> bytes:
        return self._body

    def close(self) -> None:
        """Match the file-like error body expected by ``urllib.HTTPError``."""

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


class _HttpError(HTTPError):
    """HTTPError with an in-memory body and no unclosed file wrapper."""

    def __init__(self, url: str, status: int, body: bytes):
        # Do not construct ``addinfourl``: unlike a real urllib response the
        # scripted body has no OS resource for HTTPError to clean up.
        Exception.__init__(self, url, status, "scripted response")
        self.url, self.code, self.headers, self.fp = url, status, {}, None
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __del__(self) -> None:
        # ``HTTPError`` normally owns a temporary response wrapper.  This
        # fake deliberately owns only immutable bytes.
        pass


class ScriptedTransactionTransport:
    """Reusable fake installed at the real ``urllib`` HTTP seam."""

    def __init__(self, install: Any, bundle: Any,
                 scripts: Mapping[str, TargetScript | Mapping[str, object]] | None = None,
                 *, row: TransactionRow | None = None,
                 on_mutation: Callable[[str], None] | None = None,
                 bundle_meta_timestamp: str | None = None):
        self.install, self.bundle, self.row = install, bundle, row
        self.calls: list[HttpCall] = []
        self.mutations: list[str] = []
        self._on_mutation = on_mutation
        self._bundle_meta_timestamp = bundle_meta_timestamp
        self._positions: dict[tuple[str, str], int] = {}
        self._scripts = {key: self._coerce(value) for key, value in (scripts or {}).items()}
        self._assets = {install._transaction_key_for_asset(asset): asset
                        for asset in bundle.assets if asset.kind in install._ES_ASSET_KINDS}
        self._specs = {key: (asset, saved) for key, asset, saved in install._transaction_specs(bundle)}
        self._specs[install.BUNDLE_META_TARGET_KEY] = (None, None)
        self._stored: dict[str, object] = {}
        self._routes = self._build_routes()

    @classmethod
    def from_table_row(cls, install: Any, bundle: Any, row: Sequence[str] | Mapping[str, str],
                       *, target_key: str | None = None,
                       target_script: TargetScript | Mapping[str, object] | None = None) -> "ScriptedTransactionTransport":
        projection = TransactionRow.from_row(row)
        target_key = target_key or cls._row_target(install, bundle, projection.live_state)
        script = target_script or TargetScript(live_state=cls._row_state(projection.live_state))
        return cls(install, bundle, {target_key: script}, row=projection)

    @staticmethod
    def _row_state(value: str) -> str:
        if value.startswith("absent:"):
            return "absent"
        return value if value in {"exact", "unreadable"} else "divergent"

    @staticmethod
    def _row_target(install: Any, bundle: Any, value: str) -> str:
        kind = "pipelines" if "pipeline-or-es-role" in value else "component_templates"
        asset = next(asset for asset in bundle.assets if asset.kind == kind)
        return install._transaction_key_for_asset(asset)

    @staticmethod
    def _coerce(value: TargetScript | Mapping[str, object]) -> TargetScript:
        if isinstance(value, TargetScript):
            return value
        copied = dict(value)
        if "import" in copied:
            copied["import_"] = copied.pop("import")
        return TargetScript(**copied)

    def _build_routes(self) -> dict[str, str]:
        routes: dict[str, str] = {}
        for key, asset in self._assets.items():
            routes[self.install.es_path(asset)] = key
        for asset in self.bundle.assets:
            if asset.kind in {"kibana_spaces", "kibana_roles"}:
                kind = "space" if asset.kind == "kibana_spaces" else "role"
                space = "rigsignal" if kind == "space" else "default"
                routes[self.install.kibana_path(asset)] = "kibana/" + space + "/" + kind + "/" + asset.name
        routes["/_component_template/rigsignal-bundle-meta"] = self.install.BUNDLE_META_TARGET_KEY
        return routes

    @staticmethod
    def _bytes(body: object) -> bytes:
        if isinstance(body, bytes):
            return body
        if isinstance(body, str):
            return body.encode()
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def _reply(self, value: object | None, fallback: HttpReply, key: str, action: str) -> HttpReply:
        if value is None:
            return fallback
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, dict)):
            index = self._positions.get((key, action), 0)
            self._positions[(key, action)] = index + 1
            value = value[min(index, len(value) - 1)]
        if isinstance(value, HttpReply):
            return value
        if isinstance(value, Mapping):
            return HttpReply(**value)
        raise AssertionError("invalid scripted HTTP reply")

    def _desired_body(self, key: str) -> object:
        if key in self._stored:
            return self._stored[key]
        if key == self.install.BUNDLE_META_TARGET_KEY:
            timestamp = self._bundle_meta_timestamp or "2026-08-04T12:34:56Z"
            return json.loads(self.install.default_bundle_meta_body(
                self.install.transaction_targets(self.bundle), self.bundle.version,
                self.bundle.source_commit, timestamp))
        spec = self._specs.get(key)
        if spec is not None and spec[1] is not None:
            _asset, saved = spec
            return {"attributes": saved.get("attributes", {}),
                    "references": saved.get("references", [])}
        if spec is not None and spec[0] is not None and spec[0].kind in {"kibana_spaces", "kibana_roles"}:
            return json.loads(spec[0].data)
        asset = self._assets.get(key)
        if asset is None:
            return {"attributes": {}, "references": []}
        body = json.loads(self.install.stamped_asset(asset).data)
        if asset.kind == "component_templates":
            return {"component_templates": [{"name": asset.name, "component_template": body}]}
        if asset.kind == "index_templates":
            return {"index_templates": [{"name": asset.name, "index_template": body}]}
        if asset.kind == "security_roles":
            return {asset.name: body}
        return body

    def _key_for_saved_object(self, path: str) -> str | None:
        parts = [unquote(part) for part in path.split("/") if part]
        try:
            marker = parts.index("saved_objects")
            object_type, object_id = parts[marker + 1:marker + 3]
        except (ValueError, IndexError):
            return None
        space = parts[1] if len(parts) > 2 and parts[0] == "s" else "default"
        key = "kibana/" + self.install._v2_quote(space) + "/" + self.install._v2_quote(object_type) + "/" + self.install._v2_quote(object_id)
        if key in self._specs or key in self._scripts:
            return key
        prefix = key.rsplit("/", 1)[0] + "/"
        for submitted, script in self._scripts.items():
            if (submitted.startswith(prefix) and script.destination_id is not None
                    and script.destination_id == object_id):
                return submitted
        return key

    def _route(self, path: str) -> tuple[str | None, str]:
        if path == "/api/spaces/space":
            return "kibana/rigsignal/space/rigsignal", "target"
        if "/api/saved_objects/_import" in path:
            return "dashboard-import", "import"
        if "/api/saved_objects/resolve/" in path:
            return self._key_for_saved_object(path.replace("/resolve", "", 1)), "resolve"
        if "/api/saved_objects/" in path:
            return self._key_for_saved_object(path), "saved"
        return self._routes.get(path), "target"

    def _default_get(self, key: str, script: TargetScript) -> HttpReply:
        if script.live_state == "absent":
            return HttpReply(404, {"error": "absent"})
        if script.live_state == "unreadable":
            return HttpReply(503, {"error": "unreadable"})
        body = self._desired_body(key) if script.live_state == "exact" else {"_fake": "divergent"}
        if script.live_state == "divergent" and key.startswith("kibana/"):
            body = self._desired_body(key)
            if isinstance(body, dict):
                body = dict(body)
                attributes = body.get("attributes")
                if isinstance(attributes, dict):
                    body["attributes"] = {**attributes, "_scripted_divergence": True}
                else:
                    body["_scripted_divergence"] = True
        if script.live_state == "owned-divergent":
            body = self._desired_body(key)
            if isinstance(body, dict):
                body = dict(body)
                if isinstance(body.get("component_templates"), list) and body["component_templates"]:
                    item = dict(body["component_templates"][0])
                    embedded = item.get("component_template")
                    if isinstance(embedded, dict):
                        item["component_template"] = {**embedded, "_scripted_divergence": True}
                        body["component_templates"] = [item]
                    else:
                        body["_scripted_divergence"] = True
                elif isinstance(body.get("index_templates"), list) and body["index_templates"]:
                    item = dict(body["index_templates"][0])
                    embedded = item.get("index_template")
                    if isinstance(embedded, dict):
                        item["index_template"] = {**embedded, "_scripted_divergence": True}
                        body["index_templates"] = [item]
                    else:
                        body["_scripted_divergence"] = True
                elif key in self._assets and self._assets[key].kind == "security_roles":
                    asset = self._assets[key]
                    inner = body.get(asset.name)
                    if isinstance(inner, dict):
                        body[asset.name] = {**inner, "_scripted_divergence": True}
                    else:
                        body["_scripted_divergence"] = True
                else:
                    body["_scripted_divergence"] = True
        asset = self._assets.get(key)
        if asset is not None and asset.kind == "pipelines" and isinstance(body, dict):
            body = dict(body)
            body["created_date_millis"] = 1 if script.pipeline_created_millis is None else script.pipeline_created_millis
            body["modified_date_millis"] = body["created_date_millis"] if script.pipeline_modified_millis is None else script.pipeline_modified_millis
            if script.version is not None:
                body["version"] = script.version
            # The ES GET API returns an object keyed by pipeline ID.
            body = {asset.name: body}
        elif asset is not None and asset.kind == "security_roles" and isinstance(body, dict):
            # ``_desired_body`` already models the role GET envelope.  Apply
            # response-only metadata to its single inner role body.
            body = dict(body)
            inner = body.get(asset.name)
            if isinstance(inner, dict) and script.version is not None:
                body[asset.name] = {**inner, "version": script.version}
        return HttpReply(200, body)

    def _default_put(self, key: str, script: TargetScript, query: Mapping[str, tuple[str, ...]]) -> HttpReply:
        conditional = "create" if query.get("create") == ("true",) else ("createOnly" if query.get("createOnly") == ("true",) else ("if_version" if "if_version" in query else None))
        if conditional and conditional in script.conditional:
            if script.conditional[conditional] == "echo":
                return HttpReply(200, {"if_version": query.get("if_version", ())})
            return self._reply(script.conditional[conditional], HttpReply(), key, "conditional:" + conditional)
        if conditional in {"create", "createOnly"} and script.live_state == "conflict":
            return HttpReply(400 if conditional == "create" else 409, {"error": "conflict"})
        asset = self._assets.get(key)
        if asset is not None and asset.kind == "security_roles":
            return HttpReply(200, {"role": {"created": True if script.role_created is None else script.role_created}}, script.response_loss)
        if key.startswith("kibana/") and script.destination_id is not None:
            return HttpReply(200, {"id": script.destination_id, "destinationId": script.destination_id}, script.response_loss)
        return HttpReply(200, {}, script.response_loss)

    def _remember_mutation(self, key: str | None, data: bytes | None) -> None:
        if key is None:
            return
        if data is not None:
            try:
                body = json.loads(data)
            except (TypeError, json.JSONDecodeError):
                body = None
            if body is not None:
                if key in self._assets and self._assets[key].kind == "pipelines" and isinstance(body, dict):
                    body = dict(body)
                    body.setdefault("created_date_millis", 1)
                    body.setdefault("modified_date_millis", 1)
                self._stored[key] = body
        prior = self._scripts.get(key, TargetScript())
        self._scripts[key] = TargetScript(
            live_state="exact", role_created=prior.role_created,
            pipeline_created_millis=prior.pipeline_created_millis,
            pipeline_modified_millis=prior.pipeline_modified_millis,
            version=prior.version, destination_id=prior.destination_id)
        self.mutations.append(key)
        if self._on_mutation is not None:
            self._on_mutation(key)

    # `timeout` is accepted and ignored: production passes
    # install_assets.REQUEST_TIMEOUT_SECONDS, and this double performs no real
    # I/O, so there is nothing to time out. Named explicitly rather than
    # swallowed by **kwargs so a future signature change fails loudly here.
    def urlopen(self, request: Any, timeout: float | None = None) -> _Response:
        parsed = urlsplit(request.full_url)
        query = {name: tuple(values) for name, values in parse_qs(parsed.query, keep_blank_values=True).items()}
        method, path = request.get_method(), parsed.path
        self.calls.append(HttpCall(method, path, query, request.data))
        key, route = self._route(path)
        script = self._scripts.get(key or "", TargetScript())
        if path == "/":
            reply = HttpReply(200, {"cluster_uuid": "0123456789ABCDEFGHIJKL", "version": {"number": "9.4.4"}})
        elif path == "/api/status":
            reply = HttpReply(200, {"version": {"number": "9.4.4"}})
        elif route == "import":
            reply = self._reply(script.import_, HttpReply(200, {"success": True, "successCount": 0, "successResults": []}), key or route, "import")
        elif route == "resolve":
            fallback = (HttpReply(200, {"destinationId": script.destination_id})
                        if script.destination_id is not None and script.live_state != "absent"
                        else HttpReply(404, {"error": "not an alias"}))
            reply = self._reply(script.resolve, fallback, key or route, "resolve")
        elif method == "GET":
            reply = self._reply(script.get, self._default_get(key or "", script), key or route, "get")
        else:
            reply = self._reply(script.put, self._default_put(key or "", script, query), key or route, "put")
        body = self._bytes(reply.body)
        if reply.loss:
            raise HTTPError(request.full_url, 599, "response lost", {}, None)
        if reply.status >= 400:
            raise _HttpError(request.full_url, reply.status, body)
        if method != "GET":
            self._remember_mutation(key, request.data)
        return _Response(reply.status, body)
