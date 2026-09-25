import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("install_assets", ROOT / "tools/install_assets.py")
INSTALL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(INSTALL)


class InstallAdoptionTests(unittest.TestCase):
    def setUp(self):
        gate = patch.object(INSTALL, "stack_version_preflight")
        gate.start()
        self.addCleanup(gate.stop)
        # main() deliberately uses the production boundary of /.  These
        # integration tests are about adoption, not host namespace ownership.
        self.ancestor_check = patch.object(INSTALL, "check_install_root_ancestors")
        self.install_preflight = patch.object(INSTALL, "check_install_preflight",
                                              return_value=(Path("/canonical/ca.pem"),
                                                            Path("/canonical/agent")))
        self.ancestor_check.start()
        self.install_preflight.start()

    def tearDown(self):
        self.ancestor_check.stop()
        self.install_preflight.stop()

    def installer_args(self, root: Path, adopt: bool = False) -> SimpleNamespace:
        return SimpleNamespace(
            bundle=Path("unused"), endpoint="https://es.invalid", ca_file=Path("unused"),
            kibana_endpoint="https://kb.invalid", kibana_ca_file=Path("unused"),
            admin_credentials_file=Path("unused"), agent_binary=Path("unused"), profile="user",
            enrollment_root=root, dry_run=False, adopt_existing_w1_stream=adopt,
            ownership_profile=None, rollback=None, unsafe_test_injection=False,
        )

    def test_enrollment_condition_keeps_adoption_path_narrow(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            self.assertEqual(INSTALL.enrollment_condition(root), "clean")
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            self.assertEqual(INSTALL.enrollment_condition(root), "clean")

            state = INSTALL.state_template("KUrXRgwRRQu-RikmIJhm0Q", INSTALL.TARGET_GENERATION_KAT,
                                           "active", str(root))
            INSTALL.atomic_write(root, "state.json", INSTALL.jcs(state) + b"\n")
            self.assertEqual(INSTALL.enrollment_condition(root), "committed")

            INSTALL.secure_candidate_root(root)
            self.assertEqual(INSTALL.enrollment_condition(root), "remediation")

            (root / "candidate").rmdir()
            state.update(phase="candidate_staged", active_key_id=None, pending_mint_name="unfinished",
                         candidate_key_id="candidate")
            INSTALL.atomic_write(root, "state.json", INSTALL.jcs(state) + b"\n")
            INSTALL.secure_candidate_root(root)
            self.assertEqual(INSTALL.enrollment_condition(root), "incomplete")

    def test_enrollment_condition_recognizes_only_completed_retained_journal_as_rolled_back(self):
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            journal = INSTALL.TransactionJournal(root, "fleet-coexist")
            journal.value["rollback_ok"] = True
            journal._persist()
            INSTALL.atomic_write(root, "fleet-coexist-body-test", b"audit body")
            self.assertEqual(INSTALL.enrollment_condition(root), "rolled-back")
            INSTALL.atomic_write(root, "unexpected", b"no")
            self.assertEqual(INSTALL.enrollment_condition(root), "remediation")

    def test_candidate_write_recovery_redispatches_clean_root_without_adoption(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            INSTALL.secure_root(root)
            state = INSTALL.state_template("KUrXRgwRRQu-RikmIJhm0Q", INSTALL.TARGET_GENERATION_KAT,
                                           None, str(root))
            state.update(phase="candidate_staged", pending_mint_name="unfinished", candidate_key_id="candidate")
            INSTALL.atomic_write(root, "state.json", INSTALL.jcs(state) + b"\n")
            INSTALL.secure_candidate_root(root)
            snapshot = frozenset({(".ds-recovered", "recovered-uuid")})
            expected_bundle = INSTALL.Bundle("test", "test", [])
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                                   return_value=self.installer_args(root)))
                patches.enter_context(patch.object(INSTALL, "load_bundle", return_value=expected_bundle))
                patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
                patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
                patches.enter_context(patch.object(INSTALL, "fence_remote_ownership_profile"))
                patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value=state["expected_cluster_uuid"]))
                invalidate_name = patches.enter_context(patch.object(INSTALL, "invalidate_mint_name"))
                invalidate = patches.enter_context(patch.object(INSTALL, "invalidate"))
                remote = patches.enter_context(patch.object(INSTALL, "remote_stream_condition",
                                                            return_value=("compatible", snapshot)))
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            invalidate_name.assert_called_once_with("https://es.invalid", "admin", "unfinished")
            invalidate.assert_called_once_with("https://es.invalid", "admin", ["candidate"])
            self.assertEqual(stderr.getvalue(), "install refused: adoption_required\n"
                             "RIGSIGNAL_FAILURE_SITE root_prepare\n")
            remote.assert_called_once_with("https://es.invalid", "admin", expected_bundle)
            self.assertFalse((root / "candidate").exists())
            self.assertFalse((root / "state.json").exists())

    def test_candidate_document_is_the_frozen_fixture_except_runtime_fields(self):
        expected = json.loads(INSTALL.PROBE_FIXTURE.read_bytes())
        document = INSTALL.candidate_document("fresh")
        self.assertEqual(document["event"]["id"], "provision-fresh")
        self.assertEqual(document["rigsignal"]["diagnosis"], expected["rigsignal"]["diagnosis"])
        self.assertEqual(set(document), {"@timestamp", "event", "host", "rigsignal"})
        self.assertEqual(document["host"]["name"], document["host"]["name"].lower())

    def test_mapping_rejection_requires_the_exact_oracle(self):
        INSTALL.assert_mapping_rejection(400, {"error": {"type": "strict_dynamic_mapping_exception"}},
                                         "strict_dynamic_mapping_exception")
        with self.assertRaises(INSTALL.InputError):
            INSTALL.assert_mapping_rejection(403, {"error": {"type": "strict_dynamic_mapping_exception"}},
                                             "strict_dynamic_mapping_exception")
        with self.assertRaises(INSTALL.InputError):
            INSTALL.assert_mapping_rejection(400, {"error": {"type": "document_parsing_exception"}},
                                             "document_parsing_exception", "number_format_exception")

    def test_clean_root_refusals_leave_no_local_artifact(self):
        old_parse = INSTALL.argparse.ArgumentParser.parse_args
        old_bundle, old_role = INSTALL.load_bundle, INSTALL.role_body
        old_configure, old_auth, old_remote = (INSTALL.configure_https, INSTALL.admin_authorization,
                                               INSTALL.remote_stream_condition)
        old_credential_kind = INSTALL.admin_credential_kind
        try:
            INSTALL.load_bundle = lambda _path: INSTALL.Bundle("test", "test", [])
            INSTALL.role_body = lambda _bundle: {}
            INSTALL.configure_https = lambda _path: None
            INSTALL.admin_authorization = lambda _path: "admin"
            INSTALL.admin_credential_kind = lambda _path: "native_user"
            for adopt, remote, code in (
                (False, "compatible", "adoption_required"),
                (False, "incompatible", "migration_required"),
                (True, "absent", "adoption_flag_stream_absent"),
                (True, "incompatible", "migration_required"),
            ):
                with self.subTest(adopt=adopt, remote=remote), tempfile.TemporaryDirectory() as raw:
                    root = Path(raw) / "enrollment"
                    args = SimpleNamespace(
                        bundle=Path("unused"), endpoint="https://es.invalid", ca_file=Path("unused"),
                        kibana_endpoint="https://kb.invalid", kibana_ca_file=Path("unused"),
                        admin_credentials_file=Path("unused"), agent_binary=Path("unused"), profile="user",
                        enrollment_root=root, dry_run=False, adopt_existing_w1_stream=adopt,
                        ownership_profile=None, rollback=None, unsafe_test_injection=False,
                    )
                    INSTALL.argparse.ArgumentParser.parse_args = lambda _parser: args
                    INSTALL.remote_stream_condition = lambda *_args: (remote, None)
                    stderr = io.StringIO()
                    with redirect_stderr(stderr):
                        self.assertEqual(INSTALL.main(), 3)
                    self.assertEqual(stderr.getvalue(), f"install refused: {code}\n"
                                     "RIGSIGNAL_FAILURE_SITE preflight\n")
                    self.assertFalse(root.exists())
        finally:
            (INSTALL.argparse.ArgumentParser.parse_args, INSTALL.load_bundle, INSTALL.role_body,
             INSTALL.configure_https, INSTALL.admin_authorization, INSTALL.remote_stream_condition,
             INSTALL.admin_credential_kind) = (
                old_parse, old_bundle, old_role, old_configure, old_auth, old_remote, old_credential_kind)

    def test_committed_rerun_remote_404_remains_compatible_for_self_healing(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            INSTALL.secure_root(root)
            state = INSTALL.state_template("KUrXRgwRRQu-RikmIJhm0Q", INSTALL.TARGET_GENERATION_KAT,
                                           "active", str(root))
            with patch.object(INSTALL, "es_json", side_effect=INSTALL.RequestFailure(404, "missing")):
                self.assertTrue(INSTALL.existing_stream_is_compatible(
                    "https://es.invalid", "admin", state, state["expected_cluster_uuid"], root))
                # fence acceptance is what allows Step 5 ensure_stream() to
                # recreate the deleted stream on the ordinary rerun path.
                INSTALL.fence("https://es.invalid", "admin", state, state["expected_cluster_uuid"], root)
            # The ordinary clean/fresh path has the same established 404
            # behavior, while main() separately rejects flag+absent.
            with patch.object(INSTALL, "es_json", side_effect=INSTALL.RequestFailure(404, "missing")):
                self.assertTrue(INSTALL.existing_stream_is_compatible(
                    "https://es.invalid", "admin", None, "KUrXRgwRRQu-RikmIJhm0Q"))
                INSTALL.fence("https://es.invalid", "admin", None, "KUrXRgwRRQu-RikmIJhm0Q")

    def test_flag_with_incomplete_state_refuses_before_recovery_or_secure_root(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            INSTALL.secure_root(root)
            state = INSTALL.state_template("KUrXRgwRRQu-RikmIJhm0Q", INSTALL.TARGET_GENERATION_KAT,
                                           None, str(root))
            state.update(phase="mint_intent", pending_mint_name="unfinished")
            INSTALL.atomic_write(root, "state.json", INSTALL.jcs(state) + b"\n")
            secure_root = MagicMock(side_effect=AssertionError("secure_root must not run"))
            recovery = MagicMock(side_effect=AssertionError("recovery must not run"))
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                              return_value=self.installer_args(root, True)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "secure_root", secure_root), \
                 patch.object(INSTALL, "invalidate_mint_name", recovery), \
                 patch.object(INSTALL, "invalidate", recovery):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install refused: adoption_flag_state_present\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            secure_root.assert_not_called()
            recovery.assert_not_called()

    def test_main_dispatch_refuses_flag_with_committed_or_remediation_root(self):
        for condition, code in (("committed", "adoption_flag_state_present"),
                                ("remediation", "enrollment_remediation_required")):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as raw:
                root = Path(raw) / "enrollment"
                remote = MagicMock(side_effect=AssertionError("remote inspection must not run"))
                secure_root = MagicMock(side_effect=AssertionError("secure_root must not run"))
                with patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                  return_value=self.installer_args(root, True)), \
                     patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                     patch.object(INSTALL, "role_body", return_value={}), \
                     patch.object(INSTALL, "enrollment_condition", return_value=condition), \
                     patch.object(INSTALL, "remote_stream_condition", remote), \
                     patch.object(INSTALL, "secure_root", secure_root):
                    stderr = io.StringIO()
                    with redirect_stderr(stderr):
                        self.assertEqual(INSTALL.main(), 3)
                self.assertEqual(stderr.getvalue(), f"install refused: {code}\n"
                                 "RIGSIGNAL_FAILURE_SITE preflight\n")
                remote.assert_not_called()
                secure_root.assert_not_called()

    def test_fence_state_binding_uses_stable_remediation_code(self):
        with patch.object(INSTALL, "existing_stream_is_compatible",
                          side_effect=INSTALL.StateBindingError("wrong root")):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "enrollment_remediation_required"):
                INSTALL.fence("https://es.invalid", "admin", None, "KUrXRgwRRQu-RikmIJhm0Q")

    def test_adoption_main_runs_full_transaction_without_adopted_phase(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            written_states: list[dict] = []
            def capture_write(_root, name, data):
                if name == "state.json":
                    written_states.append(json.loads(data))
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                                   return_value=self.installer_args(root, True)))
                patches.enter_context(patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])))
                patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
                patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
                patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value="KUrXRgwRRQu-RikmIJhm0Q"))
                patches.enter_context(patch.object(INSTALL, "prerequisites"))
                fence = patches.enter_context(patch.object(INSTALL, "fence"))
                patches.enter_context(patch.object(INSTALL, "remote_stream_condition", side_effect=[
                    ("compatible", frozenset({(".ds-old", "old-uuid")})),
                    ("compatible", frozenset({(".ds-old", "old-uuid")})),
                    ("compatible", frozenset({(".ds-old", "old-uuid")})),
                ]))
                ensure_stream = patches.enter_context(patch.object(INSTALL, "ensure_stream"))
                simulate = patches.enter_context(patch.object(INSTALL, "simulate"))
                patches.enter_context(patch.object(INSTALL, "recompute_target_generation", return_value="0" * 64))
                mint_key = patches.enter_context(patch.object(INSTALL, "mint_key", return_value=("candidate", "encoded")))
                patches.enter_context(patch.object(INSTALL, "enrollment_files", return_value={}))
                patches.enter_context(patch.object(INSTALL, "atomic_write", side_effect=capture_write))
                stream_proof = patches.enter_context(patch.object(INSTALL, "verify_stream_behavior"))
                role_proof = patches.enter_context(patch.object(INSTALL, "verify_role_matrix"))
                publication = patches.enter_context(patch.object(INSTALL, "atomic_publication"))
                handshake = patches.enter_context(patch.object(INSTALL, "run_handshake"))
                patches.enter_context(patch.object(INSTALL, "request"))
                marker_verify = patches.enter_context(patch.object(INSTALL, "verify_asset"))
                self.assertEqual(INSTALL.main(), 0)
            fence.assert_called_once()
            self.assertTrue(fence.call_args.args[-1])
            ensure_stream.assert_called_once()
            simulate.assert_called()
            mint_key.assert_called_once()
            stream_proof.assert_called_once()
            role_proof.assert_called_once()
            publication.assert_called_once()
            handshake.assert_called_once()
            marker_verify.assert_called_once()
            self.assertTrue(written_states)
            self.assertNotIn("adopted", {state["phase"] for state in written_states})
            self.assertIn("mint_intent", {state["phase"] for state in written_states})
            self.assertIn("candidate_verified", {state["phase"] for state in written_states})
            self.assertIn("committed", {state["phase"] for state in written_states})

    def test_successful_install_creates_no_preflight_artifact(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                                   return_value=self.installer_args(root, True)))
                patches.enter_context(patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])))
                patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
                patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
                patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value="KUrXRgwRRQu-RikmIJhm0Q"))
                patches.enter_context(patch.object(INSTALL, "prerequisites"))
                patches.enter_context(patch.object(INSTALL, "fence"))
                patches.enter_context(patch.object(INSTALL, "remote_stream_condition", return_value=("compatible", frozenset())))
                patches.enter_context(patch.object(INSTALL, "ensure_stream"))
                patches.enter_context(patch.object(INSTALL, "simulate"))
                patches.enter_context(patch.object(INSTALL, "recompute_target_generation", return_value="0" * 64))
                patches.enter_context(patch.object(INSTALL, "mint_key", return_value=("candidate", "encoded")))
                patches.enter_context(patch.object(INSTALL, "enrollment_files", return_value={}))
                patches.enter_context(patch.object(INSTALL, "atomic_write"))
                patches.enter_context(patch.object(INSTALL, "secure_candidate_root", return_value=root))
                patches.enter_context(patch.object(INSTALL, "verify_stream_behavior"))
                patches.enter_context(patch.object(INSTALL, "verify_role_matrix"))
                patches.enter_context(patch.object(INSTALL, "prepublication_asset_fence"))
                patches.enter_context(patch.object(INSTALL, "atomic_publication"))
                patches.enter_context(patch.object(INSTALL, "run_handshake"))
                patches.enter_context(patch.object(INSTALL, "request"))
                patches.enter_context(patch.object(INSTALL, "verify_asset"))
                self.assertEqual(INSTALL.main(), 0)
            self.assertEqual(list(root.glob(".rigsignal-preflight-*")), [])

    def test_rolled_back_root_adopts_compatible_stream_for_fresh_transaction(self):
        """Owner ruling 1 extends the clean-root adoption dispatch to audit-only roots."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            bundle = INSTALL.Bundle("test", "test", [])
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                                   return_value=self.installer_args(root, True)))
                patches.enter_context(patch.object(INSTALL, "enrollment_condition", return_value="rolled-back"))
                patches.enter_context(patch.object(INSTALL, "load_bundle", return_value=bundle))
                patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
                patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
                patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value="KUrXRgwRRQu-RikmIJhm0Q"))
                patches.enter_context(patch.object(INSTALL, "prerequisites"))
                fence = patches.enter_context(patch.object(INSTALL, "fence"))
                remote = patches.enter_context(patch.object(INSTALL, "remote_stream_condition", side_effect=[
                    ("compatible", frozenset({(".ds-old", "old-uuid")})),
                    ("compatible", frozenset({(".ds-old", "old-uuid")})),
                    ("compatible", frozenset({(".ds-old", "old-uuid")})),
                ]))
                patches.enter_context(patch.object(INSTALL, "ensure_stream"))
                patches.enter_context(patch.object(INSTALL, "simulate"))
                patches.enter_context(patch.object(INSTALL, "recompute_target_generation", return_value="0" * 64))
                patches.enter_context(patch.object(INSTALL, "mint_key", return_value=("candidate", "encoded")))
                patches.enter_context(patch.object(INSTALL, "enrollment_files", return_value={}))
                patches.enter_context(patch.object(INSTALL, "atomic_write"))
                patches.enter_context(patch.object(INSTALL, "verify_stream_behavior"))
                patches.enter_context(patch.object(INSTALL, "verify_role_matrix"))
                patches.enter_context(patch.object(INSTALL, "atomic_publication"))
                patches.enter_context(patch.object(INSTALL, "run_handshake"))
                patches.enter_context(patch.object(INSTALL, "request"))
                patches.enter_context(patch.object(INSTALL, "verify_asset"))
                self.assertEqual(INSTALL.main(), 0)
            self.assertEqual(remote.call_count, 3)
            fence.assert_called_once()
            self.assertTrue(fence.call_args.args[-2])
            self.assertIs(fence.call_args.args[-1], bundle)

    def test_fresh_main_dispatch_runs_full_transaction_after_absent_stream(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            snapshot = frozenset({(".ds-fresh", "fresh-uuid")})
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                                   return_value=self.installer_args(root)))
                patches.enter_context(patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])))
                patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
                patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
                patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value="KUrXRgwRRQu-RikmIJhm0Q"))
                patches.enter_context(patch.object(INSTALL, "prerequisites"))
                fence = patches.enter_context(patch.object(INSTALL, "fence"))
                remote = patches.enter_context(patch.object(INSTALL, "remote_stream_condition", side_effect=[
                    ("absent", None),
                    ("absent", None),
                    ("compatible", snapshot),
                    ("compatible", snapshot),
                ]))
                ensure_stream = patches.enter_context(patch.object(INSTALL, "ensure_stream"))
                patches.enter_context(patch.object(INSTALL, "simulate"))
                patches.enter_context(patch.object(INSTALL, "recompute_target_generation", return_value="0" * 64))
                patches.enter_context(patch.object(INSTALL, "mint_key", return_value=("candidate", "encoded")))
                patches.enter_context(patch.object(INSTALL, "enrollment_files", return_value={}))
                patches.enter_context(patch.object(INSTALL, "atomic_write"))
                patches.enter_context(patch.object(INSTALL, "verify_stream_behavior"))
                patches.enter_context(patch.object(INSTALL, "verify_role_matrix"))
                publication = patches.enter_context(patch.object(INSTALL, "atomic_publication"))
                handshake = patches.enter_context(patch.object(INSTALL, "run_handshake"))
                patches.enter_context(patch.object(INSTALL, "request"))
                marker_verify = patches.enter_context(patch.object(INSTALL, "verify_asset"))
                self.assertEqual(INSTALL.main(), 0)
            self.assertEqual(remote.call_count, 4)
            fence.assert_called_once()
            self.assertFalse(fence.call_args.args[-2])
            ensure_stream.assert_called_once()
            publication.assert_called_once()
            handshake.assert_called_once()
            marker_verify.assert_called_once()

    def test_prepublication_drift_fails_closed_without_publication_or_marker(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            written_states: list[dict] = []
            def capture_write(_root, name, data):
                if name == "state.json":
                    written_states.append(json.loads(data))
            publication = MagicMock()
            marker_request = MagicMock()
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                                   return_value=self.installer_args(root, True)))
                patches.enter_context(patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])))
                patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
                patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
                patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value="KUrXRgwRRQu-RikmIJhm0Q"))
                patches.enter_context(patch.object(INSTALL, "prerequisites"))
                patches.enter_context(patch.object(INSTALL, "fence"))
                patches.enter_context(patch.object(INSTALL, "remote_stream_condition", side_effect=[
                    ("compatible", frozenset({(".ds-old", "old-uuid")})),
                    ("compatible", frozenset({(".ds-old", "old-uuid")})),
                    ("compatible", frozenset({(".ds-new", "new-uuid")})),
                ]))
                patches.enter_context(patch.object(INSTALL, "ensure_stream"))
                patches.enter_context(patch.object(INSTALL, "simulate"))
                patches.enter_context(patch.object(INSTALL, "recompute_target_generation", return_value="0" * 64))
                patches.enter_context(patch.object(INSTALL, "mint_key", return_value=("candidate", "encoded")))
                patches.enter_context(patch.object(INSTALL, "enrollment_files", return_value={}))
                patches.enter_context(patch.object(INSTALL, "atomic_write", side_effect=capture_write))
                patches.enter_context(patch.object(INSTALL, "verify_stream_behavior"))
                patches.enter_context(patch.object(INSTALL, "verify_role_matrix"))
                patches.enter_context(patch.object(INSTALL, "atomic_publication", publication))
                patches.enter_context(patch.object(INSTALL, "request", marker_request))
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install failed: pre-publication fence:\n"
                             "RIGSIGNAL_FAILURE_SITE candidate_stage\n")
            publication.assert_not_called()
            self.assertFalse(any(call.args[2] == "PUT" for call in marker_request.call_args_list))
            self.assertNotIn("committed", {state["phase"] for state in written_states})

    def test_in_transaction_fleet_rollover_snapshot_drift_fails_before_publication(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            args = self.installer_args(root, True)
            args.ownership_profile = "fleet-coexist"
            publication = MagicMock()
            marker_request = MagicMock()
            before = {"logs-rigsignal.events-default": {"backing": [(".ds-old", "old-uuid")]}}
            after = {"logs-rigsignal.events-default": {"backing": [(".ds-new", "new-uuid")]}}
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args))
                patches.enter_context(patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])))
                patches.enter_context(patch.object(INSTALL, "bundle_sha256", return_value="test-bundle-sha"))
                patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
                patches.enter_context(patch.object(INSTALL, "ownership_for_assets", return_value={}))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
                patches.enter_context(patch.object(INSTALL, "dispatch_clean_root", return_value=True))
                patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value="KUrXRgwRRQu-RikmIJhm0Q"))
                patches.enter_context(patch.object(INSTALL, "prerequisites"))
                patches.enter_context(patch.object(INSTALL, "fence"))
                patches.enter_context(patch.object(INSTALL, "remote_stream_condition",
                                                   return_value=("compatible", frozenset({(".ds-old", "old-uuid")}))))
                patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
                snapshots = patches.enter_context(patch.object(INSTALL, "fleet_stream_snapshot",
                                                                side_effect=[before, after]))
                patches.enter_context(patch.object(INSTALL, "m1_anchor_pins",
                                                   return_value={ident: "pin" for ident in INSTALL.M1_ANCHOR_IDS}))
                patches.enter_context(patch.object(INSTALL, "ensure_stream"))
                patches.enter_context(patch.object(INSTALL, "simulate"))
                patches.enter_context(patch.object(INSTALL, "atomic_publication", publication))
                patches.enter_context(patch.object(INSTALL, "request", marker_request))
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install failed: fleet stream verification:\n"
                             "RIGSIGNAL_FAILURE_SITE asset_apply\n")
            self.assertEqual(snapshots.call_count, 2)
            publication.assert_not_called()
            marker_request.assert_called_once_with(
                "https://es.invalid", "/_component_template/rigsignal-bundle-meta", "GET", "admin")
            self.assertTrue((root / INSTALL.JOURNAL_FILE).exists())
            self.assertFalse((root / "state.json").exists())

    def test_proof_ids_are_unique_for_each_accepted_attempt(self):
        accepted: dict[str, dict] = {}
        def status(_url, path, _method, _authorization, document):
            event_id = path.split("/_create/", 1)[1].split("?", 1)[0]
            if event_id.startswith("provision-bad-") or event_id.startswith("provision-nested-"):
                return 400, {"error": {"type": "strict_dynamic_mapping_exception"}}
            if event_id.startswith("provision-malformed-"):
                return 400, {"error": {"type": "document_parsing_exception",
                                        "caused_by": {"type": "number_format_exception"}}}
            accepted[event_id] = document
            return 201, {"result": "created"}
        def get(_url, path, _method, _authorization, body=None):
            if "::failures" in path:
                raise INSTALL.RequestFailure(404, "failure store disabled")
            event_id = body["query"]["ids"]["values"][0]
            return {"hits": {"hits": [{"_id": event_id, "_source": accepted[event_id]}]}}
        with patch.object(INSTALL, "es_json_status", side_effect=status), \
             patch.object(INSTALL, "es_json", side_effect=get):
            INSTALL.verify_stream_behavior("https://es.invalid", "shipper", "admin", "first")
            INSTALL.verify_stream_behavior("https://es.invalid", "shipper", "admin", "second")
        self.assertEqual(set(accepted), {"provision-first", "provision-second"})
        self.assertTrue(all(doc["event"]["id"] == event_id for event_id, doc in accepted.items()))


if __name__ == "__main__":
    unittest.main()


class RollbackBoundaryFenceTests(unittest.TestCase):
    def setUp(self):
        # Version transport has dedicated real-entrypoint coverage.
        gate = patch.object(INSTALL, "stack_version_preflight")
        gate.start()
        self.addCleanup(gate.stop)

    def test_rollback_invocation_fences_remote_table_version(self):
        # S1-v4: rollback is an invocation boundary; a remote marker carrying a
        # different ownership_table_version must refuse before any reversal.
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            marker = {"component_templates": [{"component_template": {
                "_meta": {"ownership_profile": "fleet-coexist",
                          "ownership_table_version": "fleet-coexist-v0"}, "template": {}}}]}
            args = SimpleNamespace(
                bundle=None, endpoint="https://es.invalid", ca_file=Path("unused"),
                kibana_endpoint="https://kb.invalid", kibana_ca_file=Path("unused"),
                admin_credentials_file=Path("unused"), agent_binary=Path("unused"),
                profile="user", enrollment_root=root, dry_run=False,
                adopt_existing_w1_stream=False, ownership_profile=None,
                rollback=root, unsafe_test_injection=False)
            rollback = MagicMock()
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "check_version_fence"))
                patches.enter_context(patch.object(INSTALL, "load_ownership_profile", return_value="fleet-coexist"))
                patches.enter_context(patch.object(INSTALL, "request", return_value=json.dumps(marker).encode()))
                patches.enter_context(patch.object(INSTALL, "rollback_transaction", rollback))
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install refused: ownership_table_version_mismatch\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            rollback.assert_not_called()

    def test_rollback_refuses_malformed_present_journal_before_reversal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            INSTALL.atomic_write(root, INSTALL.JOURNAL_FILE, b"{")
            args = SimpleNamespace(
                bundle=None, endpoint="https://es.invalid", ca_file=Path("unused"),
                kibana_endpoint="https://kb.invalid", kibana_ca_file=Path("unused"),
                admin_credentials_file=Path("unused"), agent_binary=Path("unused"),
                profile="user", enrollment_root=root, dry_run=False,
                adopt_existing_w1_stream=False, ownership_profile=None,
                rollback=root, unsafe_test_injection=False)
            rollback = MagicMock()
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "check_version_fence"))
                patches.enter_context(patch.object(INSTALL, "rollback_transaction", rollback))
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install refused: transaction_journal_invalid\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            rollback.assert_not_called()

    def test_rollback_fence_request_failure_is_sanitized(self):
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            args = SimpleNamespace(
                bundle=None, endpoint="https://es.invalid", ca_file=Path("unused"),
                kibana_endpoint="https://kb.invalid", kibana_ca_file=Path("unused"),
                admin_credentials_file=Path("unused"), agent_binary=Path("unused"),
                profile="user", enrollment_root=root, dry_run=False,
                adopt_existing_w1_stream=False, ownership_profile=None,
                rollback=root, unsafe_test_injection=False)
            rollback = MagicMock()
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "check_version_fence"))
                patches.enter_context(patch.object(
                    INSTALL, "request", side_effect=INSTALL.RequestFailure(503, "sensitive response")))
                patches.enter_context(patch.object(INSTALL, "rollback_transaction", rollback))
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install failed: enrollment output:\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            rollback.assert_not_called()

    def test_second_rollback_reaches_journal_refusal_with_restored_coexist_marker(self):
        # Leg-i shape: after a completed rollback the enrollment profile file
        # is gone but the journal records fleet-coexist; the boundary fence
        # must derive the requested profile from the journal so the precise
        # transaction_already_rolled_back refusal is reachable.
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            INSTALL.TransactionJournal(root, "fleet-coexist")
            marker = {"component_templates": [{"component_template": {
                "_meta": {"ownership_profile": "fleet-coexist",
                          "ownership_table_version": INSTALL.OWNERSHIP_TABLE_VERSION},
                "template": {}}}]}
            args = SimpleNamespace(
                bundle=None, endpoint="https://es.invalid", ca_file=Path("unused"),
                kibana_endpoint="https://kb.invalid", kibana_ca_file=Path("unused"),
                admin_credentials_file=Path("unused"), agent_binary=Path("unused"),
                profile="user", enrollment_root=root, dry_run=False,
                adopt_existing_w1_stream=False, ownership_profile=None,
                rollback=root, unsafe_test_injection=False)
            rollback = MagicMock(side_effect=INSTALL.ProvisionError(
                "install refused: transaction_already_rolled_back"))
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=args))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "check_version_fence"))
                patches.enter_context(patch.object(INSTALL, "request", return_value=json.dumps(marker).encode()))
                patches.enter_context(patch.object(INSTALL, "rollback_transaction", rollback))
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install refused: transaction_already_rolled_back\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            rollback.assert_called_once()
