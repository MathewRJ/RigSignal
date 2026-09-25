#!/usr/bin/env python3
"""End-to-end ownership tests for the default-profile assets-only flow."""

import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from contextlib import redirect_stdout


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("install_assets", ROOT / "tools/install_assets.py")
INSTALL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(INSTALL)


class AssetTransport:
    """In-memory v2 wire transport with a remote-mutation sentinel.

    The former version of this fixture implemented the retired 55-asset
    planner API.  This one speaks the record engine's object-granular GET,
    resolve and guarded-create surface, including the cluster binding read.
    """

    def __init__(self, bundle, *, fail_on_nth_mutation=None):
        self.bundle = bundle
        self.es = {}
        self.kibana = {}
        self.calls = []
        self.fail_mutations = False
        self.fail_on_nth_mutation = fail_on_nth_mutation
        self.mutation_attempts = 0

    def _asset_for_path(self, path):
        path = path.split("?", 1)[0]
        for asset in self.bundle.assets:
            if asset.kind in INSTALL._ES_ASSET_KINDS and INSTALL.es_path(asset) == path:
                return asset
            if asset.kind not in INSTALL._ES_ASSET_KINDS and asset.kind != "dashboard" and INSTALL.kibana_path(asset) == path:
                return asset
        return None

    @staticmethod
    def _path(path):
        return path.split("?", 1)[0]

    def _es_response(self, asset, body):
        if asset.kind == "component_templates":
            return {"component_templates": [{"name": asset.name, "component_template": body}]}
        if asset.kind == "index_templates":
            return {"index_templates": [{"name": asset.name, "index_template": body}]}
        if asset.kind == "security_roles":
            return {asset.name: body}
        return body

    def request(self, base, path, method, _authorization, data=None, headers=None):
        self.calls.append((method, path))
        if method != "GET" and self.fail_mutations:
            raise AssertionError("mutation sentinel tripped: " + method + " " + path)
        if method != "GET":
            self.mutation_attempts += 1
            if self.fail_on_nth_mutation == self.mutation_attempts:
                raise INSTALL.RequestFailure(503, "deterministic mutation failure")
        clean_path = self._path(path)
        if method == "GET":
            if base == "https://es" and clean_path == "/":
                return b'{"cluster_uuid":"0123456789ABCDEFGHIJKL"}'
            if "/api/saved_objects/resolve/" in clean_path:
                # A normal literal object has no alias; the adapter explicitly
                # accepts this documented 404 resolution result.
                raise INSTALL.RequestFailure(404, "not an alias")
            if "/api/saved_objects/" in clean_path:
                if clean_path not in self.kibana:
                    raise INSTALL.RequestFailure(404, "absent")
                return json.dumps(self.kibana[clean_path]).encode()
            asset = self._asset_for_path(clean_path)
            store = self.es if base == "https://es" else self.kibana
            if asset is None or clean_path not in store:
                raise INSTALL.RequestFailure(404, "absent")
            body = store[clean_path]
            if base == "https://es":
                body = self._es_response(asset, body)
            return json.dumps(body).encode()
        if method == "POST" and "/api/saved_objects/" in clean_path:
            body = json.loads(data)
            self.kibana[clean_path] = body
            return json.dumps({"id": clean_path.rsplit("/", 1)[1]}).encode()
        if method == "POST" and clean_path == "/api/spaces/space":
            asset = next(item for item in self.bundle.assets if item.kind == "kibana_spaces")
            self.kibana[INSTALL.kibana_path(asset)] = json.loads(data)
            return b"{}"
        asset = self._asset_for_path(clean_path)
        if asset is None:
            # Transform updates carry an /_update suffix and retain the
            # preflight identity in the path.
            asset = self._asset_for_path(clean_path.removesuffix("/_update"))
            clean_path = clean_path.removesuffix("/_update")
        if asset is None:
            raise AssertionError("unexpected mutation " + method + " " + clean_path)
        body = json.loads(data)
        if asset.kind == "security_roles" and "_meta" in body:
            # Elasticsearch's role endpoint only persists caller metadata in
            # ``metadata``.  Rejecting the invalid shape makes this transport
            # expose the real API bug rather than accepting a mock-only body.
            raise AssertionError("security role PUT rejects _meta; use metadata")
        store = self.es if asset.kind in INSTALL._ES_ASSET_KINDS else self.kibana
        if asset.kind == "pipelines":
            # The nonce is persisted under _meta and is part of the immediate
            # desired projection used for clean-create verification.
            body.setdefault("created_date_millis", 1)
            body.setdefault("modified_date_millis", 1)
        store[clean_path] = body
        if asset.kind == "security_roles":
            return b'{"role":{"created":true}}'
        return b"{}"

    def request_response(self, base, path, method, authorization, data=None, headers=None):
        return 200, self.request(base, path, method, authorization, data, headers)

    @property
    def mutations(self):
        return [(method, path) for method, path in self.calls if method != "GET"]


class AssetsOnlyInstallTests(unittest.TestCase):
    def setUp(self):
        # Version transport has dedicated real-entrypoint coverage.
        gate = mock.patch.object(INSTALL, "stack_version_preflight")
        gate.start()
        self.addCleanup(gate.stop)

    @classmethod
    def setUpClass(cls):
        cls.bundle = INSTALL.load_source()
        assert len(cls.bundle.assets) == 55

    def install(self, transport, marker, **modes):
        with mock.patch.object(INSTALL, "request", transport.request), \
             mock.patch.object(INSTALL, "request_response", transport.request_response), \
             mock.patch.object(INSTALL, "prerequisites"), \
             mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(marker.parent / ".state")}), \
             redirect_stdout(io.StringIO()):
            return INSTALL.assets_only_install(self.bundle, "https://es", "https://kb", "admin", marker,
                                               **modes)

    @staticmethod
    def main_args(marker):
        return SimpleNamespace(
            bundle=Path("fixture.tar.gz"), endpoint="https://es", ca_file=Path("fixture-ca.pem"),
            kibana_endpoint="https://kb", kibana_ca_file=Path("fixture-kb-ca.pem"),
            admin_credentials_file=Path("admin.toml"), agent_binary=Path("agent"), profile="user",
            assets_only=True, assets_marker=marker, repair=False, upgrade=False, allow_downgrade=False,
            enrollment_root=None, adopt_existing_w1_stream=False, ownership_profile=None, rollback=None,
            predecessor_manifest=None, dry_run=False, unsafe_test_injection=False,
        )

    def main_assets(self, args, transport=None, *, load_bundle=None):
        patches = [mock.patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args),
                   mock.patch.object(INSTALL, "load_bundle", return_value=load_bundle or self.bundle),
                   mock.patch.object(INSTALL, "role_body", return_value={}),
                   mock.patch.object(INSTALL, "check_version_fence"),
                   mock.patch.object(INSTALL, "prerequisites"),
                   mock.patch.object(INSTALL, "configure_https"),
                   mock.patch.object(INSTALL, "admin_authorization", return_value="admin")]
        if transport is not None:
            patches.extend((mock.patch.object(INSTALL, "request", transport.request),
                            mock.patch.object(INSTALL, "request_response", transport.request_response)))
        with ExitStack() as stack:
            if args.assets_marker is not None:
                stack.enter_context(mock.patch.dict(
                    os.environ, {"XDG_STATE_HOME": str(args.assets_marker.parent / ".state")}))
            for patcher in patches:
                stack.enter_context(patcher)
            return INSTALL.main()

    def test_main_assets_exit_protocol_is_tracker_driven(self):
        """Break-one-thing: removing mutation_request makes the N=2 leg return 3."""
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
            stderr = io.StringIO()
            with redirect_stderr(stderr), mock.patch.object(
                    INSTALL, "load_bundle", side_effect=INSTALL.InputError("bad bundle")):
                args = self.main_args(marker)
                with mock.patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args):
                    self.assertEqual(INSTALL.main(), 2)
            self.assertEqual(stderr.getvalue(), "install failed: bundle validation:\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")

            transport = AssetTransport(self.bundle)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(self.main_assets(self.main_args(marker), transport), 0)
            self.assertEqual(stderr.getvalue(), "")

            conflict = AssetTransport(self.bundle)
            target = next(asset for asset in self.bundle.assets if asset.kind in INSTALL._ES_ASSET_KINDS)
            conflict.es[INSTALL.es_path(target)] = {"_meta": {"managed_by": "foreign"}}
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(self.main_assets(self.main_args(marker), conflict), 3)
            self.assertIn("install refused: assets_transaction_invalid\n", stderr.getvalue())
            self.assertIn("RIGSIGNAL_FAILURE_SITE asset_apply\n", stderr.getvalue())
            self.assertEqual(conflict.mutations, [])

            partial_marker = Path(raw) / "partial" / INSTALL.ASSETS_MARKER_FILE
            partial_marker.parent.mkdir(mode=0o700)
            partial_marker.parent.chmod(0o700)
            partial = AssetTransport(self.bundle, fail_on_nth_mutation=2)
            stderr = io.StringIO()
            with redirect_stderr(stderr), mock.patch.object(INSTALL, "rollback_transaction") as rollback:
                self.assertEqual(self.main_assets(self.main_args(partial_marker), partial), 4)
            self.assertEqual(stderr.getvalue(),
                             "RIGSIGNAL_RECOVERY_STATE partial-remote-possible transaction=<redacted>\n")
            self.assertEqual(len(partial.mutations), 2)
            self.assertTrue(partial_marker.exists())
            rollback.assert_not_called()

            # A malformed remote GET is not a local-input error.  Refuse
            # fail-closed before the first write with the safe remote code.
            remote_refusal = io.StringIO()
            with redirect_stderr(remote_refusal), \
                 mock.patch.object(INSTALL, "request", return_value=b"[]"):
                remote_marker = Path(raw) / "remote" / INSTALL.ASSETS_MARKER_FILE
                remote_marker.parent.mkdir(mode=0o700)
                remote_marker.parent.chmod(0o700)
                self.assertEqual(self.main_assets(self.main_args(remote_marker)), 3)
            self.assertEqual(remote_refusal.getvalue(), "RIGSIGNAL_E_ASSETS_ONLY: RemoteReadRefusal: "
                             "cluster UUID is invalid\n"
                             "RIGSIGNAL_FAILURE_SITE asset_apply\n")

    def test_default_marker_uses_private_leaf_under_a_0755_shared_state_root(self):
        """Regression: agent/enrollment's shared 0755 state root must not strand assets."""
        with tempfile.TemporaryDirectory() as raw:
            state_home = Path(raw) / "state"
            shared = state_home / "rigsignal"
            shared.mkdir(parents=True, mode=0o755)
            shared.chmod(0o755)
            transport = AssetTransport(self.bundle)
            args = self.main_args(None)
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                 redirect_stderr(io.StringIO()):
                self.assertEqual(self.main_assets(args, transport), 0)
            marker = state_home / "rigsignal" / "assets" / INSTALL.ASSETS_MARKER_FILE
            self.assertTrue(marker.is_file())
            self.assertEqual(stat.S_IMODE(marker.parent.stat().st_mode), 0o700)
            self.assertEqual(shared.stat().st_mode & 0o777, 0o755)
            # v2 expands the 55 source assets into 66 independently guarded
            # targets (46 ES plus 18 saved objects, space and role).
            self.assertEqual(len(transport.mutations), 66)

    def test_default_marker_fresh_state_dir_succeeds(self):
        with tempfile.TemporaryDirectory() as raw:
            state_home = Path(raw) / "fresh-state"
            transport = AssetTransport(self.bundle)
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                 redirect_stderr(io.StringIO()):
                self.assertEqual(self.main_assets(self.main_args(None), transport), 0)
            marker = state_home / "rigsignal" / "assets" / INSTALL.ASSETS_MARKER_FILE
            self.assertTrue(marker.is_file())
            self.assertEqual(stat.S_IMODE(marker.parent.stat().st_mode), 0o700)
            self.assertEqual(len(transport.mutations), 66)

    def test_marker_preflight_refuses_symlink_before_any_cluster_mutation(self):
        with tempfile.TemporaryDirectory() as raw:
            state_home = Path(raw) / "state"
            shared = state_home / "rigsignal"
            shared.mkdir(parents=True, mode=0o755)
            shared.chmod(0o755)
            safe = Path(raw) / "safe"
            safe.mkdir(mode=0o700)
            (shared / "assets").symlink_to(safe, target_is_directory=True)
            transport = AssetTransport(self.bundle)
            stderr = io.StringIO()
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                 redirect_stderr(stderr):
                self.assertEqual(self.main_assets(self.main_args(None), transport), 2)
            self.assertEqual(stderr.getvalue(), "install refused: assets_marker_directory\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            self.assertEqual(transport.mutations, [])

    def test_marker_preflight_refuses_symlinked_xdg_ancestor_before_any_write(self):
        with tempfile.TemporaryDirectory() as raw:
            safe_state = Path(raw) / "safe-state"
            safe_state.mkdir(mode=0o700)
            state_home = Path(raw) / "state-link"
            state_home.symlink_to(safe_state, target_is_directory=True)
            transport = AssetTransport(self.bundle)
            transport.fail_mutations = True
            stderr = io.StringIO()
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                 redirect_stderr(stderr):
                self.assertEqual(self.main_assets(self.main_args(None), transport), 2)
            self.assertEqual(stderr.getvalue(), "install refused: assets_marker_directory\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            self.assertEqual(transport.mutations, [])
            self.assertFalse((safe_state / "rigsignal").exists())

    def test_marker_preflight_refuses_unprotected_shared_parent_before_mutation(self):
        for mode in (0o775, 0o757):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as raw:
                state_home = Path(raw) / "state"
                shared = state_home / "rigsignal"
                shared.mkdir(parents=True, mode=0o755)
                shared.chmod(mode)
                transport = AssetTransport(self.bundle)
                transport.fail_mutations = True
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                     redirect_stderr(stderr):
                    self.assertEqual(self.main_assets(self.main_args(None), transport), 2)
                self.assertEqual(stderr.getvalue(), "install refused: assets_marker_directory\n"
                                 "RIGSIGNAL_FAILURE_SITE preflight\n")
                self.assertEqual(transport.mutations, [])

    def test_marker_preflight_refuses_nonprivate_leaf_before_mutation(self):
        for label, make_leaf in (
                ("non-directory", lambda leaf: leaf.write_text("not a directory")),
                ("wrong mode", lambda leaf: (leaf.mkdir(mode=0o750), leaf.chmod(0o750))),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                state_home = Path(raw) / "state"
                shared = state_home / "rigsignal"
                shared.mkdir(parents=True, mode=0o755)
                shared.chmod(0o755)
                make_leaf(shared / "assets")
                transport = AssetTransport(self.bundle)
                transport.fail_mutations = True
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                     redirect_stderr(stderr):
                    self.assertEqual(self.main_assets(self.main_args(None), transport), 2)
                self.assertEqual(stderr.getvalue(), "install refused: assets_marker_directory\n"
                                 "RIGSIGNAL_FAILURE_SITE preflight\n")
                self.assertEqual(transport.mutations, [])

    def test_marker_preflight_refuses_non_euid_leaf_before_mutation(self):
        """Simulate a foreign-owned leaf without requiring a root test runner."""
        with tempfile.TemporaryDirectory() as raw:
            state_home = Path(raw) / "state"
            leaf = state_home / "rigsignal" / "assets"
            leaf.mkdir(parents=True, mode=0o700)
            leaf.chmod(0o700)
            original_lstat = Path.lstat

            def foreign_leaf_lstat(subject):
                result = original_lstat(subject)
                if subject == leaf:
                    values = list(result)
                    values[4] = result.st_uid + 1
                    return os.stat_result(values)
                return result

            transport = AssetTransport(self.bundle)
            transport.fail_mutations = True
            stderr = io.StringIO()
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                 mock.patch.object(Path, "lstat", new=foreign_leaf_lstat), \
                 redirect_stderr(stderr):
                self.assertEqual(self.main_assets(self.main_args(None), transport), 2)
            self.assertEqual(stderr.getvalue(), "install refused: assets_marker_directory\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            self.assertEqual(transport.mutations, [])

    def test_old_default_marker_requires_manual_removal_and_explicit_marker_is_unchanged(self):
        with tempfile.TemporaryDirectory() as raw:
            state_home = Path(raw) / "state"
            old_marker = state_home / "rigsignal" / INSTALL.ASSETS_MARKER_FILE
            old_marker.parent.mkdir(parents=True, mode=0o700)
            old_marker.parent.chmod(0o700)
            transport = AssetTransport(self.bundle)
            self.assertEqual(self.install(transport, old_marker), "applied")
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}):
                with self.assertRaisesRegex(INSTALL.ProvisionError,
                                            "assets_marker_directory; remove the legacy marker at " + str(old_marker)):
                    INSTALL._prepare_assets_marker_path(None, self.bundle)
                self.assertTrue(old_marker.exists())
                self.assertFalse(INSTALL._asset_marker_default_path().exists())

            explicit = Path(raw) / "explicit" / INSTALL.ASSETS_MARKER_FILE
            explicit.parent.mkdir(mode=0o700)
            explicit.parent.chmod(0o700)
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}):
                self.assertEqual(INSTALL._prepare_assets_marker_path(explicit, self.bundle), explicit)
                self.assertTrue(old_marker.exists())
                self.assertFalse(INSTALL._asset_marker_default_path().exists())

    def test_implicit_old_marker_refusals_do_not_migrate_or_mutate(self):
        for label in ("malformed", "symlink", "foreign-owned"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                state_home = Path(raw) / "state"
                old_marker = state_home / "rigsignal" / INSTALL.ASSETS_MARKER_FILE
                old_marker.parent.mkdir(parents=True, mode=0o700)
                old_marker.parent.chmod(0o700)
                if label == "malformed":
                    old_marker.write_text("not a marker")
                    old_marker.chmod(0o600)
                elif label == "symlink":
                    target = Path(raw) / "old-marker-target"
                    target.write_text("not a marker")
                    target.chmod(0o600)
                    old_marker.symlink_to(target)
                else:
                    INSTALL._write_assets_marker(old_marker, self.bundle)

                original_lstat = Path.lstat

                def lstat_with_foreign_old_marker(subject):
                    result = original_lstat(subject)
                    if label == "foreign-owned" and subject == old_marker:
                        values = list(result)
                        values[4] = result.st_uid + 1
                        return os.stat_result(values)
                    return result

                transport = AssetTransport(self.bundle)
                transport.fail_mutations = True
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                     mock.patch.object(Path, "lstat", new=lstat_with_foreign_old_marker), \
                     redirect_stderr(stderr):
                    self.assertEqual(self.main_assets(self.main_args(None), transport), 2)
                marker = state_home / "rigsignal" / "assets" / INSTALL.ASSETS_MARKER_FILE
                self.assertEqual(stderr.getvalue(), "install refused: assets_marker_directory; remove the legacy marker at "
                                 + str(old_marker) + "\n"
                                 "RIGSIGNAL_FAILURE_SITE preflight\n")
                self.assertTrue(os.path.lexists(old_marker))
                self.assertFalse(marker.exists())
                self.assertEqual(transport.mutations, [])


    def test_legacy_marker_source_is_never_trusted_for_auto_migration(self):
        with tempfile.TemporaryDirectory() as raw:
            state_home = Path(raw) / "state"
            old_marker = state_home / "rigsignal" / INSTALL.ASSETS_MARKER_FILE
            old_marker.parent.mkdir(parents=True, mode=0o700)
            old_marker.parent.chmod(0o700)
            INSTALL._write_assets_marker(old_marker, self.bundle)
            replacement = Path(raw) / "replacement"
            replacement.write_text("rebound source")
            replacement.chmod(0o600)
            original_lstat = Path.lstat

            def rebind_old_marker(subject):
                if subject == old_marker:
                    old_marker.unlink()
                    old_marker.symlink_to(replacement)
                return original_lstat(subject)

            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                 mock.patch.object(Path, "lstat", new=rebind_old_marker), \
                 mock.patch.object(INSTALL.os, "link") as link:
                with self.assertRaisesRegex(INSTALL.ProvisionError,
                                            "assets_marker_directory; remove the legacy marker at " + str(old_marker)):
                    INSTALL._prepare_assets_marker_path(None, self.bundle)
                self.assertFalse(INSTALL._asset_marker_default_path().exists())
            self.assertTrue(old_marker.is_symlink())
            # T-LEGACY-3 binds the configured state domain only.  Once the
            # environment patch ends, the process default path is unrelated
            # test-host state and is not an authority for this fixture.
            link.assert_not_called()

    def test_assets_only_failure_surfaces_safe_cause_without_response_body(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "marker" / INSTALL.ASSETS_MARKER_FILE
            marker.parent.mkdir(mode=0o700)
            marker.parent.chmod(0o700)
            stderr = io.StringIO()
            with mock.patch.object(INSTALL, "assets_only_install",
                                   side_effect=INSTALL.RequestFailure(503, "safe cause", b"TOP-SECRET")), \
                 redirect_stderr(stderr):
                self.assertEqual(self.main_assets(self.main_args(marker)), 3)
            self.assertEqual(stderr.getvalue(), "RIGSIGNAL_E_ASSETS_ONLY: RequestFailure: safe cause\n"
                             "RIGSIGNAL_FAILURE_SITE asset_apply\n")
            self.assertNotIn("TOP-SECRET", stderr.getvalue())

    def test_assets_only_applies_elasticsearch_assets_before_kibana_assets(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
            transport = AssetTransport(self.bundle)
            self.assertEqual(self.install(transport, marker), "applied")
            writes = [path for method, path in transport.mutations]
            es_count = sum(path.startswith("/_") for path in writes)
            self.assertTrue(all(path.startswith("/_") for path in writes[:es_count]))
            self.assertTrue(all(not path.startswith("/_") for path in writes[es_count:]))
            # The dashboard rows are individual saved-object creates, never a
            # legacy all-or-nothing NDJSON import.
            self.assertEqual(sum("/api/saved_objects/" in path for path in writes), 18)

    def test_all_55_absent_creates_everything_and_writes_verified_marker(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
            transport = AssetTransport(self.bundle)
            self.assertEqual(self.install(transport, marker), "applied")
            self.assertEqual(len(transport.mutations), 66)
            for asset in self.bundle.assets:
                if asset.kind in INSTALL._ES_ASSET_KINDS:
                    self.assertIn(INSTALL.es_path(asset), transport.es)
                    proof_key = "metadata" if asset.kind == "security_roles" else "_meta"
                    self.assertEqual(transport.es[INSTALL.es_path(asset)][proof_key]["managed_by"],
                                     INSTALL.RIGSIGNAL_MANAGED_BY)
                elif asset.kind == "dashboard":
                    object_type, object_id = INSTALL.dashboard_objects(asset.data)[0]
                    self.assertIn(INSTALL.dashboard_object_path(asset, object_type, object_id), transport.kibana)
                else:
                    self.assertIn(INSTALL.kibana_path(asset), transport.kibana)
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
            recorded = json.loads(marker.read_text())
            self.assertEqual(recorded["schema_version"], 2)
            self.assertEqual(recorded["state"], "installed")
            self.assertEqual(len(recorded["targets"]), 66)
            self.assertEqual(recorded["caller_obligations"], ["assets-66"])

    def test_owned_same_version_is_a_clean_zero_put_noop(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
            transport = AssetTransport(self.bundle)
            self.assertEqual(self.install(transport, marker), "applied")
            transport.calls.clear()
            transport.fail_mutations = True  # sentinel covers every PUT/POST/DELETE.
            self.assertEqual(self.install(transport, marker), "noop")
            self.assertEqual(transport.mutations, [])
            transport.calls.clear()
            with self.assertRaisesRegex(INSTALL.InputError, "validated predecessor"):
                self.install(transport, marker, upgrade=True)
            self.assertEqual(transport.mutations, [])

    def test_unproven_present_object_refuses_before_any_mutation(self):
        es_target = next(asset for asset in self.bundle.assets if asset.kind in INSTALL._ES_ASSET_KINDS)
        role_target = next(asset for asset in self.bundle.assets if asset.kind == "security_roles")
        kibana_target = next(asset for asset in self.bundle.assets if asset.kind == "kibana_spaces")
        for label, target, body in (
                ("foreign stamp", es_target, {"_meta": {"managed_by": "foreign"}}),
                ("missing stamp", es_target, {}),
                ("role _meta is not ownership proof", role_target,
                 {"_meta": {"managed_by": INSTALL.RIGSIGNAL_MANAGED_BY}}),
                ("missing local marker", kibana_target, {})):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
                transport = AssetTransport(self.bundle)
                store = transport.es if target.kind in INSTALL._ES_ASSET_KINDS else transport.kibana
                path = INSTALL.es_path(target) if target.kind in INSTALL._ES_ASSET_KINDS else INSTALL.kibana_path(target)
                store[path] = body
                transport.fail_mutations = True  # sentinel makes a partial apply an immediate test failure.
                with self.assertRaises(INSTALL.AssetTransactionRefusal):
                    self.install(transport, marker)
                self.assertEqual(transport.mutations, [])

    def test_repair_reapplies_owned_but_still_refuses_an_unproven_object(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
            transport = AssetTransport(self.bundle)
            self.assertEqual(self.install(transport, marker), "applied")
            transport.calls.clear()
            # A repair flag does not turn an exact installed transaction into
            # writes; its only allowed role is a qualified divergent ES path.
            self.assertEqual(self.install(transport, marker, repair=True), "noop")
            self.assertEqual(transport.mutations, [])
            transport.calls.clear()
            target = next(asset for asset in self.bundle.assets if asset.kind in INSTALL._ES_ASSET_KINDS)
            transport.es[INSTALL.es_path(target)] = {"_meta": {"managed_by": "foreign"}}
            transport.fail_mutations = True
            with self.assertRaises(INSTALL.AssetTransactionRefusal):
                self.install(transport, marker, repair=True)
            self.assertEqual(transport.mutations, [])

    def test_version_transition_applies_all_owned_objects_and_keeps_unproven_fence(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
            transport = AssetTransport(self.bundle)
            # Superseded planner invariant: an arbitrary version switch could
            # reapply all objects.  V2 permits it only from an authenticated
            # installed predecessor, so flags alone are a local zero-write
            # refusal (the qualified rows are T-FLAG-3/T-SM-11).
            transport.fail_mutations = True
            for mode in ({"upgrade": True}, {"allow_downgrade": True}):
                with self.subTest(mode=mode), self.assertRaisesRegex(INSTALL.InputError, "validated predecessor"):
                    self.install(transport, marker, **mode)
            self.assertEqual(transport.mutations, [])

            # A foreign ES body is never transformed into transition authority.
            transport.fail_mutations = True
            target = next(asset for asset in self.bundle.assets if asset.kind in INSTALL._ES_ASSET_KINDS)
            transport.es[INSTALL.es_path(target)] = {"_meta": {"managed_by": "foreign"}}
            with self.assertRaises(INSTALL.AssetTransactionRefusal):
                self.install(transport, marker)
            self.assertEqual(transport.mutations, [])

    def test_version_delta_requires_its_matching_transition_flag(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
            transport = AssetTransport(self.bundle)
            transport.fail_mutations = True
            for mode in ({"upgrade": True, "allow_downgrade": True},
                         {"upgrade": True}, {"allow_downgrade": True}):
                with self.subTest(mode=mode), self.assertRaises(INSTALL.InputError):
                    self.install(transport, marker, **mode)
            self.assertEqual(transport.mutations, [])

    def test_assets_only_fleet_coexist_refuses_before_planning_or_mutation(self):
        for dry_run in (False, True):
            with self.subTest(dry_run=dry_run):
                args = SimpleNamespace(
                    bundle=Path("unused"), endpoint="https://es", ca_file=Path("unused"),
                    kibana_endpoint="https://kb", kibana_ca_file=Path("unused"),
                    admin_credentials_file=Path("unused"), agent_binary=Path("unused"), profile="user",
                    assets_only=True, assets_marker=None, repair=False, upgrade=False, allow_downgrade=False,
                    enrollment_root=None, adopt_existing_w1_stream=False, ownership_profile="fleet-coexist",
                    rollback=None, predecessor_manifest=None, dry_run=dry_run, unsafe_test_injection=False,
                )
                stderr = io.StringIO()
                stdout = io.StringIO()
                with mock.patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args), \
                     mock.patch.object(INSTALL, "load_bundle", return_value=self.bundle), \
                     mock.patch.object(INSTALL, "role_body", return_value={}), \
                     mock.patch.object(INSTALL, "check_version_fence") as version_fence, \
                     mock.patch.object(INSTALL, "assets_only_install") as install, \
                     redirect_stderr(stderr), redirect_stdout(stdout):
                    self.assertEqual(INSTALL.main(), 3)
                self.assertEqual(stderr.getvalue(), "install refused: fleet_coexist_requires_full_flow\n"
                                 "RIGSIGNAL_FAILURE_SITE preflight\n")
                self.assertEqual(stdout.getvalue(), "")
                version_fence.assert_not_called()
                install.assert_not_called()

    def test_full_main_bundle_meta_barrier_permutations_have_no_asset_enrollment_or_step11_writes(self):
        """F2: the real full ``main()`` route observes M before every write leg."""
        for position in (0, 33, 66):
            with self.subTest(position=position), tempfile.TemporaryDirectory() as raw:
                root = Path(raw) / "enrollment"
                marker = Path(raw) / INSTALL.ASSETS_MARKER_FILE
                Path(raw).chmod(0o700)
                args = self.main_args(marker)
                args.assets_only = False
                args.enrollment_root = root
                ordinary_writes = mock.Mock(side_effect=AssertionError("ordinary asset write escaped barrier"))
                enrollment_write = mock.Mock(side_effect=AssertionError("enrollment write escaped barrier"))
                step_11_write = mock.Mock(side_effect=AssertionError("Step 11 write escaped barrier"))
                original_specs = INSTALL._transaction_specs

                def ordered_specs(bundle, include_meta=False):
                    specs = original_specs(bundle, include_meta)
                    if include_meta:
                        meta = next(spec for spec in specs if spec[0] == INSTALL.BUNDLE_META_TARGET_KEY)
                        specs.remove(meta); specs.insert(position, meta)
                    return specs

                def observe(_es, _kb, _auth, spec, _bundle, _adapter, _record=None, **_kwargs):
                    if spec[0] == INSTALL.BUNDLE_META_TARGET_KEY:
                        return "divergent", None, None
                    return "exact", None, None

                patches = (
                    mock.patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args),
                    mock.patch.object(INSTALL, "load_bundle", return_value=self.bundle),
                    mock.patch.object(INSTALL, "role_body", return_value={}),
                    mock.patch.object(INSTALL, "ownership_for_assets", return_value={}),
                    mock.patch.object(INSTALL, "enrollment_condition", return_value="clean"),
                    mock.patch.object(INSTALL, "check_version_fence"),
                    mock.patch.object(INSTALL, "check_install_root_ancestors"),
                    mock.patch.object(INSTALL, "check_outbox_root"),
                    mock.patch.object(INSTALL, "check_install_preflight", return_value=(Path("/ca"), Path("/agent"))),
                    mock.patch.object(INSTALL, "configure_https"),
                    mock.patch.object(INSTALL, "admin_authorization", return_value="admin"),
                    mock.patch.object(INSTALL, "admin_credential_kind", return_value="native_user"),
                    mock.patch.object(INSTALL, "dispatch_clean_root", return_value=False),
                    mock.patch.object(INSTALL, "fence_remote_ownership_profile"),
                    mock.patch.object(INSTALL, "run_topology_preflight"),
                    mock.patch.object(INSTALL, "prepare_install_root", return_value=root),
                    mock.patch.object(INSTALL, "load_state", return_value=None),
                    mock.patch.object(INSTALL, "bind_ownership_profile"),
                    mock.patch.object(INSTALL, "cluster_uuid", return_value="0123456789ABCDEFGHIJKL"),
                    mock.patch.object(INSTALL, "prerequisites"),
                    mock.patch.object(INSTALL, "cluster_health_gate"),
                    mock.patch.object(INSTALL, "fence"),
                    mock.patch.object(INSTALL, "remote_stream_condition", return_value=("absent", None)),
                    mock.patch.object(INSTALL.AssetTransactionLock, "acquire", return_value=mock.Mock()),
                    mock.patch.object(INSTALL, "_transaction_specs", side_effect=ordered_specs),
                    mock.patch.object(INSTALL, "_transaction_observe", side_effect=observe),
                    mock.patch.object(INSTALL, "_transaction_put", ordinary_writes),
                    mock.patch.object(INSTALL, "atomic_publication", enrollment_write),
                    mock.patch.object(INSTALL, "mutation_request", step_11_write),
                )
                with ExitStack() as stack, redirect_stderr(io.StringIO()):
                    for patcher in patches:
                        stack.enter_context(patcher)
                    self.assertEqual(INSTALL.main(), 3)
                ordinary_writes.assert_not_called()
                enrollment_write.assert_not_called()
                step_11_write.assert_not_called()
                self.assertFalse(marker.exists())

    def test_full_default_flow_marker_preflight_refuses_before_remote_or_root_mutation(self):
        with tempfile.TemporaryDirectory() as raw:
            state_home = Path(raw) / "state"
            shared = state_home / "rigsignal"
            shared.mkdir(parents=True, mode=0o755)
            shared.chmod(0o755)
            safe = Path(raw) / "safe"
            safe.mkdir(mode=0o700)
            (shared / "assets").symlink_to(safe, target_is_directory=True)
            root = Path(raw) / "enrollment"
            args = self.main_args(None)
            args.assets_only = False
            args.enrollment_root = root
            transport = AssetTransport(self.bundle)
            transport.fail_mutations = True
            stderr = io.StringIO()
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                 mock.patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args), \
                 mock.patch.object(INSTALL, "load_bundle", return_value=self.bundle), \
                 mock.patch.object(INSTALL, "role_body", return_value={}), \
                 mock.patch.object(INSTALL, "enrollment_condition", return_value="clean"), \
                 mock.patch.object(INSTALL, "check_version_fence"), \
                 mock.patch.object(INSTALL, "check_install_root_ancestors"), \
                 mock.patch.object(INSTALL, "check_outbox_root"), \
                 mock.patch.object(INSTALL, "check_install_preflight",
                                   return_value=(Path("/canonical/ca.pem"), Path("/canonical/agent"))), \
                 mock.patch.object(INSTALL, "configure_https"), \
                 mock.patch.object(INSTALL, "admin_authorization", return_value="admin"), \
                 mock.patch.object(INSTALL, "admin_credential_kind", return_value="native_user"), \
                 mock.patch.object(INSTALL, "dispatch_clean_root") as dispatch, \
                 mock.patch.object(INSTALL, "prepare_install_root") as prepare_root, \
                 mock.patch.object(INSTALL, "request", transport.request), \
                 mock.patch.object(INSTALL, "request_response", transport.request_response), \
                 redirect_stderr(stderr):
                self.assertEqual(INSTALL.main(), 2)
            self.assertEqual(stderr.getvalue(), "install refused: assets_marker_directory\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            dispatch.assert_not_called()
            prepare_root.assert_not_called()
            self.assertFalse(root.exists())
            self.assertEqual(transport.mutations, [])


if __name__ == "__main__":
    unittest.main()
