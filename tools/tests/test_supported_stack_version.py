"""Version policy through the real CLI, prerequisite and recovery paths."""
import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("version_engine", Path(__file__).resolve().parents[1] / "install_assets.py")
I = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(I)
RANGE = "supported range: >=9.4.3 <9.5.0; Elasticsearch and Kibana major.minor must match"
SECRET = "METADATA-SECRET"


def response(value):
    return {"version": {"number": value}}


class SupportedVersionTests(unittest.TestCase):
    def invoke(self, es, kb, *, route="normal", override=False, failure=None,
               uncertain=False, transport_error=None, guard=None, credential_kind="native_user"):
        """Fake transport only; retain parser, eligibility and key invalidation."""
        with tempfile.TemporaryDirectory() as raw, ExitStack() as stack:
            root = Path(raw) / "enrollment"
            root.mkdir(mode=0o700)
            marker = Path(raw) / "marker" / "assets.json"
            argv = ["engine", "--bundle", str(Path(raw) / "absent.tar.gz"),
                    "--endpoint", "https://es.invalid", "--kibana-endpoint", "https://kb.invalid",
                    "--ca-file", "ca", "--kibana-ca-file", "ca", "--admin-credentials-file", "admin",
                    "--agent-binary", "agent", "--profile", "user", "--enrollment-root", str(root),
                    "--assets-marker", str(marker)]
            if override:
                argv.append("--allow-untested-stack-version")
            if route == "assets":
                argv.append("--assets-only")
            if route == "rollback":
                argv.extend(["--rollback", str(root)])
            state = None
            if route in {"incomplete", "published"}:
                state = I.state_template("KUrXRgwRRQu-RikmIJhm0Q", I.TARGET_GENERATION_KAT,
                                         "active", str(root))
                state.update(phase="candidate_verified" if route == "published" else "mint_intent",
                             candidate_key_id="active" if route == "published" else "candidate",
                             pending_mint_name="intent", pending_revoke_ids=["old"])
            err = io.StringIO()
            requests, writes, at_write = [], [], []

            def request(base, path, method, authorization, data=None, headers=None):
                requests.append((method, path))
                if method != "GET":
                    writes.append((method, path))
                    at_write.append(err.getvalue())
                    if failure == "mutation":
                        raise I.RequestFailure(500, SECRET, SECRET.encode())
                    return I.jcs({"invalidated_api_keys": ["candidate", "old"],
                                  "previously_invalidated_api_keys": [], "error_count": 0})
                if path in {"/", "/api/status"}:
                    if transport_error is not None:
                        raise transport_error
                    return I.jcs(es if path == "/" else kb)
                if path.startswith("/_security/api_key?"):
                    return I.jcs({"api_keys": []})
                if path.startswith("/_component_template/"):
                    if failure == "templates":
                        raise I.RequestFailure(404, SECRET, SECRET.encode())
                    return b"{}"
                self.fail("unexpected request " + method + " " + path)

            def stop_after_mutation(*args, **kwargs):
                I.invalidate("https://es.invalid", "admin", ["old"])
                if route == "assets":
                    return "installed"
                return []

            fake = {
                "load_bundle": I.load_source() if route == "assets" or guard in {"fence_remote_ownership_profile", "run_topology_preflight"} else I.Bundle("test", "test", []), "role_body": {},
                "check_version_fence": None, "configure_https": None,
                "admin_authorization": "admin", "admin_credential_kind": credential_kind,
                "enrollment_condition": "incomplete" if state else "clean",
                "check_install_root_ancestors": None, "check_outbox_root": None,
                "check_install_preflight": (Path("ca"), Path("agent")),
                "dispatch_clean_root": False, "fence_remote_ownership_profile": None,
                "run_topology_preflight": None, "prepare_install_root": root,
                "load_state": state, "bind_ownership_profile": None,
                "cluster_uuid": "KUrXRgwRRQu-RikmIJhm0Q", "remove_candidate_root": None,
                "atomic_write": None, "run_handshake": None,
                "transaction_boundary_failure": 4 if uncertain else -1,
                "transaction_boundary_version_preflight": None,
                "_prepare_assets_marker_path": marker,
            }
            for name, value in fake.items():
                stack.enter_context(patch.object(I, name, return_value=value))
            if guard:
                stack.enter_context(patch.object(I, guard, side_effect=I.ProvisionError("install refused: guard")))
            stack.enter_context(patch.object(sys, "argv", argv))
            stack.enter_context(patch.object(I, "request", side_effect=request))
            stack.enter_context(patch.object(I, "run_default_asset_transaction", side_effect=stop_after_mutation))
            stack.enter_context(patch.object(I, "rollback_transaction", side_effect=stop_after_mutation))
            # Halt after eligibility, templates and genuine recovery; normal
            # invokes a genuine invalidation before the same controlled halt.
            def health(*args):
                if route == "normal":
                    stop_after_mutation()
                raise I.ProvisionError("install refused: test stop")
            stack.enter_context(patch.object(I, "cluster_health_gate", side_effect=health))
            if failure == "templates":
                stack.enter_context(patch.object(I.time, "monotonic", side_effect=[0, 61]))
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                status = I.main()
            return status, err.getvalue(), requests, writes, at_write

    def test_supported_and_override_on_every_route(self):
        pairs = [("9.4.3", "9.4.3", False), ("9.4.4", "9.4.5", False),
                 ("9.4.999999", "9.4.3", True),
                 ("9.4.3+" + SECRET, "9.4.4+a.0-1", False),
                 ("9.5.0+" + SECRET, "9.5.1+" + SECRET, True)]
        for route in ("normal", "assets", "incomplete", "published", "rollback"):
            for es, kb, flag in pairs:
                with self.subTest(route=route, es=es, kb=kb, flag=flag):
                    status, log, reads, writes, snapshots = self.invoke(response(es), response(kb), route=route, override=flag)
                    self.assertEqual(status, 0 if route in {"assets", "rollback"} else 4)
                    self.assertTrue(writes)
                    self.assertEqual(reads.count(("GET", "/")), 1)
                    self.assertEqual(reads.count(("GET", "/api/status")), 1)
                    self.assertNotIn(SECRET, log)
                    warning_count = int(es.startswith("9.5"))
                    self.assertEqual(log.count("warning:"), warning_count)
                    for snapshot in snapshots:
                        self.assertEqual(snapshot.count("warning:"), warning_count)
                    if warning_count:
                        self.assertIn("Elasticsearch 9.5.0; Kibana 9.5.1", log)
                        self.assertIn("untested", log)
                        self.assertIn(RANGE, log)
                        self.assertIn("--allow-untested-stack-version", log)

    def test_refused_on_every_route_no_writes_even_with_override(self):
        cases = [("9.4.2", "9.4.3"), ("9.4.3", "9.4.2"), ("9.5.0", "9.4.3"),
                 ("10.0.0", "10.0.1"), ("9.4.3-rc.1", "9.4.3"),
                 ("9.4.3-rc.1+" + SECRET, "9.4.3"), ("9.4.3", "10.4.3")]
        for route in ("normal", "assets", "incomplete", "published", "rollback"):
            for es, kb in cases:
                for flag in (False, True):
                    with self.subTest(route=route, es=es, kb=kb, flag=flag):
                        status, log, _, writes, _ = self.invoke(response(es), response(kb), route=route, override=flag)
                        self.assertEqual(status, 3)
                        self.assertEqual(writes, [])
                        self.assertIn(RANGE, log)
                        self.assertNotIn(SECRET, log)
                        self.assertNotIn("warning:", log)

    def test_default_untested_guidance(self):
        for route in ("normal", "assets", "incomplete", "published", "rollback"):
            status, log, _, writes, _ = self.invoke(response("9.5.0"), response("9.5.1"), route=route)
            self.assertEqual(status, 3)
            self.assertEqual(writes, [])
            self.assertIn(RANGE, log)
            self.assertIn("--allow-untested-stack-version", log)

    def test_malformed_shapes_and_values_on_both_products(self):
        values = [None, True, 9.43, 943, [], {}, "", "9.4", "v9.4.3", "09.4.3", "9.04.3", "9.4.03",
                  "9.4.3 ", " 9.4.3", "9.4.3\n", "9.4.3\x00", "9.4.3\r" + SECRET,
                  "９.4.3", "9.4.3+", "9.4.3+a..b", "9.4.3+a_", "9.4.3+" + "a" * 123,
                  "9.4." + "9" * 125, "9" * 5000 + ".4.3"]
        values += ["9.4.3+" + chr(byte) + SECRET for byte in [*range(32), 127]]
        shapes = [None, [], True, {}, {"version": []}, {"version": "9.4.3"}, {"version": None}, {"version": {}}]
        for bad in shapes + [response(v) for v in values]:
            for swap in (False, True):
                with self.subTest(bad=bad, swap=swap):
                    es, kb = (bad, response("9.4.3")) if not swap else (response("9.4.3"), bad)
                    status, log, _, writes, _ = self.invoke(es, kb, override=True)
                    self.assertEqual(status, 3)
                    self.assertEqual(writes, [])
                    self.assertIn(RANGE, log)
                    self.assertNotIn(SECRET, log)
                    self.assertNotIn("\r", log)
                    self.assertNotIn("\x00", log)

    def test_length_and_numeric_boundaries(self):
        for value in ("9.4.3+" + "a" * 122, "9.4." + "9" * 124):
            self.assertEqual(len(value), 128)
            status, log, _, writes, _ = self.invoke(response(value), response("9.4.3"), route="assets")
            self.assertEqual(status, 0)
            self.assertTrue(writes)
            self.assertNotIn(value, log)
        for value in ("9.4.3+" + "a" * 123, "9.4." + "9" * 125):
            status, log, _, writes, _ = self.invoke(response(value), response("9.4.3"), override=True)
            self.assertEqual(status, 3)
            self.assertEqual(writes, [])

    def test_override_does_not_bypass_transport_or_templates(self):
        for error in (I.RequestFailure(401, SECRET, SECRET.encode()),
                      I.RequestFailure(None, "TLS " + SECRET), I.RequestFailure(None, "unreachable " + SECRET)):
            status, log, _, writes, _ = self.invoke(response("9.5.0"), response("9.5.1"), override=True,
                                                   transport_error=error)
            self.assertEqual(status, 3)
            self.assertEqual(writes, [])
            self.assertNotIn(SECRET, log)
        for route in ("normal", "assets"):
            status, log, _, writes, _ = self.invoke(response("9.5.0"), response("9.5.1"), override=True,
                                                   route=route, failure="templates")
            self.assertEqual(status, 3)
            self.assertEqual(writes, [])
            self.assertNotIn(SECRET, log)

    def test_override_preserves_guards_and_mutation_failure_exit(self):
        for guard in ("check_version_fence", "check_install_preflight", "admin_credential_kind",
                      "dispatch_clean_root", "fence_remote_ownership_profile", "run_topology_preflight"):
            status, log, _, writes, _ = self.invoke(response("9.5.0"), response("9.5.1"), override=True, guard=guard)
            self.assertEqual(status, 3)
            self.assertEqual(writes, [])
        status, log, _, writes, _ = self.invoke(response("9.5.0"), response("9.5.1"),
                                               override=True, credential_kind="api_key")
        self.assertEqual(status, 2)
        self.assertEqual(writes, [])
        self.assertIn("admin_credential_api_key", log)
        for route in ("normal", "incomplete", "published", "rollback"):
            status, log, _, writes, _ = self.invoke(response("9.5.0"), response("9.5.1"), override=True,
                                                   route=route, failure="mutation")
            self.assertEqual(status, 4)
            self.assertTrue(writes)
            self.assertNotIn(SECRET, log)

    def test_uncertain_transaction_keeps_visible_range_and_exit_four(self):
        for route in ("normal", "assets", "incomplete", "published", "rollback"):
            status, log, _, writes, _ = self.invoke(response("10.0.0"), response("10.0.0"), route=route,
                                                   override=True, uncertain=True)
            self.assertEqual(status, 4)
            self.assertEqual(writes, [])
            self.assertIn(RANGE, log)


if __name__ == "__main__":
    unittest.main()
