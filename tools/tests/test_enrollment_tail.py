import importlib.util
import inspect
import io
import ctypes
import errno
import os
import stat
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("install_assets_enrollment_tail",
                                              ROOT / "tools/install_assets.py")
INSTALL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(INSTALL)


def synthetic_stat(mode: int, uid: int) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 0, uid, 0, 0, 0, 0, 0))


class AncestorPredicateTests(unittest.TestCase):
    def test_predicate_controls_are_synthetic_and_hermetic(self):
        euid = os.geteuid()
        cases = (
            (stat.S_IFDIR | 0o775, euid, False),
            (stat.S_IFDIR | stat.S_ISVTX | 0o777, 0, True),
            (stat.S_IFDIR | 0o755, 0, True),
            (stat.S_IFDIR | 0o755, euid + 1, False),
            (stat.S_IFLNK | 0o777, euid, False),
            (stat.S_IFREG | 0o600, euid, False),
        )
        for mode, uid, expected in cases:
            with self.subTest(mode=oct(mode), uid=uid):
                self.assertIs(INSTALL._ancestor_component_safe(synthetic_stat(mode, uid)), expected)

    def test_traversal_boundary_skips_missing_trailing_components(self):
        with tempfile.TemporaryDirectory() as raw:
            boundary = Path(raw) / "base"
            boundary.mkdir(mode=0o700)
            boundary.chmod(0o700)
            existing = boundary / "existing"
            existing.mkdir(mode=0o700)
            existing.chmod(0o700)
            INSTALL.check_install_root_ancestors(existing / "not-created" / "enrollment",
                                                 boundary=boundary)

    def test_default_traversal_boundary_is_root(self):
        self.assertEqual(inspect.signature(INSTALL.check_install_root_ancestors)
                         .parameters["boundary"].default, Path("/"))

    def test_unsafe_ancestor_refuses_without_creating_root(self):
        with tempfile.TemporaryDirectory() as raw:
            boundary = Path(raw) / "base"
            boundary.mkdir(mode=0o700)
            boundary.chmod(0o700)
            unsafe = boundary / "unsafe"
            unsafe.mkdir(mode=0o775)
            unsafe.chmod(0o775)
            root = unsafe / "enrollment"
            with self.assertRaisesRegex(INSTALL.ProvisionError,
                                        "install refused: enrollment ancestor is not protected:"):
                INSTALL.check_install_root_ancestors(root, boundary=boundary)
            self.assertFalse(root.exists())

    def test_root_owned_sticky_immediate_parent_refuses_early(self):
        sticky_root = synthetic_stat(stat.S_IFDIR | stat.S_ISVTX | 0o777, 0)
        with patch.object(INSTALL.os, "lstat", return_value=sticky_root):
            with self.assertRaisesRegex(INSTALL.ProvisionError,
                                        "install refused: enrollment ancestor is not protected:"):
                INSTALL.check_install_root_ancestors(Path("/tmp/enrollment"), boundary=Path("/tmp"))


class OutboxPreflightTests(unittest.TestCase):
    def test_absent_and_safe_outbox_proceed(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            absent = base / "absent"
            safe = base / "safe"
            safe.mkdir(mode=0o700)
            safe.chmod(0o700)
            with patch.object(INSTALL, "check_install_root_ancestors") as ancestors:
                INSTALL.check_outbox_root(absent)
                INSTALL.check_outbox_root(safe)
            self.assertEqual(ancestors.call_args_list,
                             [((absent,), {}), ((safe,), {})])

    def test_unsafe_outbox_terminal_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            target = base / "target"
            target.mkdir(mode=0o700)
            target.chmod(0o700)
            symlink = base / "symlink"
            symlink.symlink_to(target, target_is_directory=True)
            writable = base / "writable"
            writable.mkdir(mode=0o775)
            writable.chmod(0o775)
            regular = base / "regular"
            regular.write_text("not a directory")
            for path in (symlink, writable, regular):
                with self.subTest(path=path.name), self.assertRaisesRegex(
                        INSTALL.ProvisionError, "install refused: outbox preflight:"):
                    INSTALL.check_outbox_root(path)

    @unittest.skipUnless(os.geteuid() == 0, "requires root to create a foreign-owned directory")
    def test_foreign_owned_outbox_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            outbox = Path(raw) / "outbox"
            outbox.mkdir(mode=0o700)
            os.chown(outbox, 1, -1)
            with self.assertRaisesRegex(INSTALL.ProvisionError, "install refused: outbox preflight:"):
                INSTALL.check_outbox_root(outbox)

    def test_fake_stat_foreign_owned_outbox_refuses_without_root(self):
        foreign_directory = synthetic_stat(stat.S_IFDIR | 0o700, os.geteuid() + 1)
        with patch.object(INSTALL.os, "lstat", return_value=foreign_directory):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "install refused: outbox preflight:"):
                INSTALL.check_outbox_root(Path("/synthetic/outbox"))


class HandshakeDiagnosisTests(unittest.TestCase):
    def test_failed_handshake_records_full_diagnosis_and_reports_whitelist(self):
        line = ('{"probe_schema_version":1,"diagnosis_schema_version":1,"outcome":"failed",'
                '"reason":"local_config","failed_stage":"local",'
                '"target_generation":null,"observed_cluster_uuid":null,'
                '"accepted_set_digest":null}\n')
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            journal = INSTALL.TransactionJournal(root, "fleet-coexist")
            agent = Path(raw) / "agent"
            agent.write_text("#!/bin/sh\nprintf '%s' '" + line + "'\nexit 1\n")
            agent.chmod(0o700)
            with self.assertRaisesRegex(
                    INSTALL.InputError,
                    "published handshake failed: outcome=failed reason=local_config failed_stage=local") as error:
                INSTALL.run_handshake(agent, root, journal)
            self.assertEqual(journal.value["published_probe_diagnosis"], line)
            self.assertNotIn("target_generation", str(error.exception))

    def test_successful_handshake_records_no_diagnosis(self):
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            journal = INSTALL.TransactionJournal(root, "fleet-coexist")
            agent = Path(raw) / "agent"
            agent.write_text("#!/bin/sh\necho ignored\nexit 0\n")
            agent.chmod(0o700)
            INSTALL.run_handshake(agent, root, journal)
            self.assertNotIn("published_probe_diagnosis", journal.value)

    def assert_diagnosis_discarded_whole(self, line: str):
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            journal = INSTALL.TransactionJournal(root, "fleet-coexist")
            agent = Path(raw) / "agent"
            agent.write_text("#!/bin/sh\nprintf '%s' '" + line + "'\nexit 1\n")
            agent.chmod(0o700)
            with self.assertRaisesRegex(INSTALL.InputError, "published handshake failed$"):
                INSTALL.run_handshake(agent, root, journal)
            self.assertNotIn("published_probe_diagnosis", journal.value)

    def test_non_string_outcome_is_discarded_whole_not_typeerror(self):
        self.assert_diagnosis_discarded_whole(
            '{"probe_schema_version":1,"diagnosis_schema_version":1,"outcome":[],'
            '"reason":"local_config","failed_stage":"local","target_generation":null,'
            '"observed_cluster_uuid":null,"accepted_set_digest":null}\n')

    def test_unknown_field_is_discarded_whole(self):
        self.assert_diagnosis_discarded_whole(
            '{"probe_schema_version":1,"diagnosis_schema_version":1,"outcome":"failed",'
            '"reason":"local_config","failed_stage":"local","target_generation":null,'
            '"observed_cluster_uuid":null,"accepted_set_digest":null,"extra":"x"}\n')

    def test_oversized_diagnosis_is_discarded_whole(self):
        self.assert_diagnosis_discarded_whole(
            '{"probe_schema_version":1,"diagnosis_schema_version":1,"outcome":"failed",'
            '"reason":"local_config","failed_stage":"local",'
            '"target_generation":"' + "a" * 5000 + '","observed_cluster_uuid":null,'
            '"accepted_set_digest":null}\n')


class InstallRootPreparationTests(unittest.TestCase):
    def test_prepare_install_root_creates_every_component_private_under_umask_0002(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw) / "base"
            base.mkdir(mode=0o700)
            base.chmod(0o700)
            root = base / "one" / "two" / "enrollment"
            prior_umask = os.umask(0o002)
            try:
                self.assertEqual(INSTALL.prepare_install_root(root), root)
            finally:
                os.umask(prior_umask)
            for component in (base / "one", base / "one" / "two", root):
                self.assertEqual(stat.S_IMODE(os.lstat(component).st_mode), 0o700)

    def test_secure_root_remains_reachable_below_unsafe_parent(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw) / "legacy"
            parent.mkdir(mode=0o775)
            parent.chmod(0o775)
            root = INSTALL.secure_root(parent / "enrollment")
            self.assertTrue(root.is_dir())

    def test_atomic_publication_late_parent_check_remains_live(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw) / "legacy"
            parent.mkdir(mode=0o775)
            parent.chmod(0o775)
            root = INSTALL.secure_root(parent / "enrollment")
            files = {name: b"new" for name in (
                "credentials.toml", "handshake.toml", "shipping-policy-v1.toml", "state.json")}
            with self.assertRaisesRegex(INSTALL.InputError, "enrollment parent is not protected"):
                INSTALL.atomic_publication(root, files)


class SameClassPreflightTests(unittest.TestCase):
    def test_agent_binary_controls_are_injectable(self):
        executable = synthetic_stat(stat.S_IFREG | 0o700, os.geteuid())
        with patch.object(INSTALL.shutil, "which", return_value="/resolved/agent"), \
             patch.object(Path, "resolve", return_value=Path("/resolved/agent")), \
             patch.object(INSTALL.os, "lstat", return_value=executable) as lstat, \
             patch.object(INSTALL.os, "access", return_value=True), \
             patch.object(INSTALL.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(INSTALL._check_agent_binary(Path("agent")), Path("/resolved/agent"))
        lstat.assert_called_once_with(Path("/resolved/agent"))
        self.assertEqual(run.call_args.args[0][0], "/resolved/agent")
        with patch.object(INSTALL.shutil, "which", return_value="/resolved/agent"), \
             patch.object(Path, "resolve", return_value=Path("/resolved/agent")), \
             patch.object(INSTALL.os, "lstat", return_value=executable), \
             patch.object(INSTALL.os, "access", side_effect=(True, False)):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "agent_binary_unlaunchable"):
                INSTALL._check_agent_binary(Path("agent"))
        with patch.object(INSTALL.shutil, "which", return_value=None):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "agent_binary_unlaunchable"):
                INSTALL._check_agent_binary(Path("agent"))

    def test_mountinfo_and_symbol_controls_are_hermetic(self):
        mountinfo = "31 20 0:28 / /sandbox rw - ext4 /dev/test rw\\n"
        with patch("builtins.open", return_value=io.StringIO(mountinfo)):
            self.assertEqual(INSTALL._mount_filesystem_type(Path("/sandbox/root")), "ext4")
        with patch.object(INSTALL, "_nearest_existing_ancestor", return_value=Path("/sandbox")), \
             patch.object(INSTALL, "_check_agent_binary", return_value=Path("/resolved/agent")), \
             patch.object(INSTALL, "_rename_exchange_symbol_available", return_value=True), \
             patch.object(INSTALL, "_mount_filesystem_type", return_value="ext4"), \
             patch.object(INSTALL, "_probe_rename_exchange_capability"), \
             patch.object(INSTALL, "_check_publication_stage_path"), \
             patch.object(INSTALL, "_check_parent_fsync"), \
             patch.object(INSTALL, "_check_local_transaction_readiness"), \
             patch.object(INSTALL, "resolve_enrollment_ca_file", return_value=Path("/ca")):
            self.assertEqual(INSTALL.check_install_preflight(Path("/sandbox/root"), Path("agent"), Path("ca")),
                             (Path("/ca"), Path("/resolved/agent")))
        with patch.object(INSTALL, "_nearest_existing_ancestor", return_value=Path("/sandbox")), \
             patch.object(INSTALL, "_check_agent_binary", return_value=Path("/resolved/agent")), \
             patch.object(INSTALL, "_rename_exchange_symbol_available", return_value=False):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "atomic_publication_filesystem_unsupported"):
                INSTALL.check_install_preflight(Path("/sandbox/root"), Path("agent"), Path("ca"))
        with patch.object(INSTALL, "_nearest_existing_ancestor", return_value=Path("/sandbox")), \
             patch.object(INSTALL, "_check_agent_binary", return_value=Path("/resolved/agent")), \
             patch.object(INSTALL, "_rename_exchange_symbol_available", return_value=True), \
             patch.object(INSTALL, "_mount_filesystem_type", return_value="nfs"), \
             patch.object(INSTALL, "_probe_rename_exchange_capability"), \
             patch.object(INSTALL, "_check_publication_stage_path"), \
             patch.object(INSTALL, "_check_parent_fsync"), \
             patch.object(INSTALL, "_check_local_transaction_readiness"), \
             patch.object(INSTALL, "resolve_enrollment_ca_file", return_value=Path("/ca")):
            self.assertEqual(INSTALL.check_install_preflight(Path("/sandbox/root"), Path("agent"), Path("ca")),
                             (Path("/ca"), Path("/resolved/agent")))

    def test_stage_path_length_has_positive_and_negative_controls(self):
        root = Path("/sandbox") / ("x" * 20)
        with patch.object(INSTALL.os, "pathconf", side_effect=(255, 4096)):
            INSTALL._check_publication_stage_path(root, Path("/sandbox"))
        with patch.object(INSTALL.os, "pathconf", side_effect=(8, 4096)):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "enrollment_publication_path_too_long"):
                INSTALL._check_publication_stage_path(root, Path("/sandbox"))
        with patch.object(INSTALL.os, "pathconf", side_effect=(255, 8)):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "enrollment_publication_path_too_long"):
                INSTALL._check_publication_stage_path(root, Path("/sandbox"))

    def test_stage_path_uses_canonical_root_and_refuses_exact_path_max(self):
        canonical_root = Path("/canonical/deep/enrollment")
        canonical_stage = canonical_root.parent / os.fsdecode(
            INSTALL._publication_stage_prefix(canonical_root) + b"-" + b"f" * 16)
        with patch.object(INSTALL.os.path, "realpath", return_value=str(canonical_root)), \
             patch.object(INSTALL.os, "pathconf",
                          side_effect=(255, len(os.fsencode(os.fspath(canonical_stage))))):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "enrollment_publication_path_too_long"):
                INSTALL._check_publication_stage_path(Path("relative-enrollment"), Path("/canonical"))

    def test_parent_fsync_controls_are_hermetic(self):
        same_device = synthetic_stat(stat.S_IFDIR | 0o700, os.geteuid())
        with patch.object(INSTALL.os, "lstat", return_value=same_device), \
             patch.object(INSTALL.os, "open", return_value=12), \
             patch.object(INSTALL.os, "fsync") as fsync, \
             patch.object(INSTALL.os, "close"):
            INSTALL._check_parent_fsync(Path("/sandbox"), Path("/sandbox/root"))
            fsync.assert_called_once_with(12)
        with patch.object(INSTALL.os, "lstat", return_value=same_device), \
             patch.object(INSTALL.os, "open", return_value=12), \
             patch.object(INSTALL.os, "fsync", side_effect=OSError("no fsync")), \
             patch.object(INSTALL.os, "close"):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "enrollment_parent_fsync_unsupported"):
                INSTALL._check_parent_fsync(Path("/sandbox"), Path("/sandbox/root"))

    def test_local_transaction_readiness_controls_are_hermetic(self):
        available = SimpleNamespace(f_flag=0, f_bavail=INSTALL.LOCAL_TRANSACTION_MIN_AVAILABLE_BLOCKS)
        readonly = SimpleNamespace(f_flag=getattr(os, "ST_RDONLY", 1), f_bavail=999)
        with patch.object(INSTALL.os, "statvfs", return_value=available), \
             patch.object(INSTALL.os, "access", return_value=True):
            INSTALL._check_local_transaction_readiness(Path("/sandbox"))
        with patch.object(INSTALL.os, "statvfs", return_value=readonly), \
             patch.object(INSTALL.os, "access", return_value=True):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "local_transaction_storage_unavailable"):
                INSTALL._check_local_transaction_readiness(Path("/sandbox"))

    def test_ca_resolution_is_single_canonical_protected_value(self):
        with patch.object(Path, "resolve", return_value=Path("/canonical/ca.pem")), \
             patch.object(INSTALL, "protected_regular_file", return_value=b"certificate"), \
             patch.object(INSTALL, "_nearest_existing_ancestor", return_value=Path("/canonical")), \
             patch.object(INSTALL.os, "pathconf", return_value=4096):
            self.assertEqual(INSTALL.resolve_enrollment_ca_file(Path("relative-ca")), Path("/canonical/ca.pem"))
        with patch.object(Path, "resolve", return_value=Path("/canonical/ca.pem")), \
             patch.object(INSTALL, "protected_regular_file", side_effect=(b"one", b"two")):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "enrollment_ca_path_invalid"):
                INSTALL.resolve_enrollment_ca_file(Path("relative-ca"))
        files = INSTALL.enrollment_files("https://es", Path("/canonical/ca.pem"), Path("/root"),
                                         "KUrXRgwRRQu-RikmIJhm0Q", "0" * 64, "secret", {})
        self.assertIn(b'ca_cert = "/canonical/ca.pem"', files["handshake.toml"])

    def test_malformed_mountinfo_fails_closed(self):
        malformed = io.TextIOWrapper(io.BytesIO(b"\xff\n"), encoding="utf-8")
        with patch("builtins.open", return_value=malformed):
            with self.assertRaisesRegex(INSTALL.ProvisionError,
                                        "atomic_publication_filesystem_unsupported"):
                INSTALL._mount_filesystem_type(Path("/sandbox/root"))


class PublicationProbeMatrixTests(unittest.TestCase):
    def test_real_exchange_probe_leaves_no_debris_and_swaps_real_directory_names(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "root"; root.mkdir(mode=0o700); root.chmod(0o700)
            left, right = root / "left", root / "right"
            left.mkdir(mode=0o700); right.mkdir(mode=0o700)
            (left / "which").write_text("left"); (right / "which").write_text("right")
            parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                INSTALL._rename_exchange(parent_fd, b"left", parent_fd, b"right")
            finally:
                os.close(parent_fd)
            self.assertEqual((left / "which").read_text(), "right")
            self.assertEqual((right / "which").read_text(), "left")
            INSTALL._probe_rename_exchange_capability(root / "enrollment", root)
            self.assertFalse(any(item.name.startswith(".rigsignal-publication-probe-")
                                 for item in root.iterdir()))

    def test_probe_mkdir_failures_and_collision_cleanup_are_refusals(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "root"; root.mkdir(mode=0o700); root.chmod(0o700)
            for failure_at in (1, 2):
                calls = []
                real_mkdir = os.mkdir
                def mkdir(name, mode=0o777, *, dir_fd=None):
                    calls.append(name)
                    if len(calls) == failure_at: raise OSError(errno.EACCES, "blocked")
                    return real_mkdir(name, mode, dir_fd=dir_fd)
                with self.subTest(failure_at=failure_at), patch.object(INSTALL.os, "mkdir", side_effect=mkdir):
                    with self.assertRaisesRegex(INSTALL.ProvisionError, "atomic_publication_filesystem_unsupported"):
                        INSTALL._probe_rename_exchange_capability(root / "enrollment", root)
                self.assertFalse(any(item.name.startswith(".rigsignal-publication-probe-")
                                     for item in root.iterdir()))

    def test_stage_collision_retries_then_exhausts_without_touching_existing_debris(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "root"; root.mkdir(mode=0o700); root.chmod(0o700)
            files = {os.fsdecode(name): b"new" for name in INSTALL._PUBLICATION_REQUIRED_MEMBERS}
            occupied = INSTALL._publication_stage_prefix(root) + b"-0000000000000000"
            parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.mkdir(occupied, 0o700, dir_fd=parent_fd)
            finally: os.close(parent_fd)
            fresh = INSTALL._publication_stage_prefix(root) + b"-1111111111111111"
            with patch.object(INSTALL, "_publication_stage_name", side_effect=(occupied, fresh)):
                INSTALL.atomic_publication(root, files)
            self.assertTrue((root.parent / os.fsdecode(occupied)).is_dir())
            # A fresh root cannot be published twice, so use a second root for
            # the exhaustion case and pin the eight bounded attempts.
            root2 = Path(raw) / "root2"; root2.mkdir(mode=0o700); root2.chmod(0o700)
            occupied2 = INSTALL._publication_stage_prefix(root2) + b"-2222222222222222"
            parent_fd = os.open(root2.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.mkdir(occupied2, 0o700, dir_fd=parent_fd)
            finally: os.close(parent_fd)
            with patch.object(INSTALL, "_publication_stage_name", return_value=occupied2):
                with self.assertRaisesRegex(INSTALL.InputError, "cannot create enrollment publication stage"):
                    INSTALL.atomic_publication(root2, files)

    def test_errno_return_from_libc_is_preserved_and_probe_maps_both_refusals(self):
        class FakeRename:
            def __init__(self, number): self.number = number
            def __call__(self, *_args): ctypes.set_errno(self.number); return -1
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "root"; root.mkdir(mode=0o700); root.chmod(0o700)
            for number, refusal in ((errno.EROFS, "local_transaction_storage_unavailable"),
                                    (errno.EINVAL, "atomic_publication_filesystem_unsupported")):
                fake = FakeRename(number)
                library = type("Library", (), {"renameat2": fake})()
                with self.subTest(errno=number), patch.object(INSTALL.ctypes, "CDLL", return_value=library):
                    parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with self.assertRaises(OSError) as raised:
                            INSTALL._rename_exchange(parent_fd, b"missing-a", parent_fd, b"missing-b")
                        self.assertEqual(raised.exception.errno, number)
                    finally:
                        os.close(parent_fd)
                with self.subTest(probe_errno=number), patch.object(INSTALL, "_rename_exchange",
                                                                      side_effect=OSError(number, "fake")):
                    with self.assertRaisesRegex(INSTALL.ProvisionError, refusal):
                        INSTALL._probe_rename_exchange_capability(root / "enrollment", root)

    def test_probe_precedes_later_preflight_checks_and_never_reaches_http(self):
        events = []
        with patch.object(INSTALL, "_nearest_existing_ancestor", return_value=Path("/sandbox")), \
             patch.object(INSTALL, "_check_agent_binary", return_value=Path("/agent")), \
             patch.object(INSTALL, "_rename_exchange_symbol_available", return_value=True), \
             patch.object(INSTALL, "_probe_rename_exchange_capability",
                          side_effect=lambda *_args: (events.append("probe"),
                                                       (_ for _ in ()).throw(INSTALL.ProvisionError(
                                                           "install refused: atomic_publication_filesystem_unsupported")))[1]), \
             patch.object(INSTALL, "_check_publication_stage_path", side_effect=lambda *_args: events.append("stage")):
            with self.assertRaisesRegex(INSTALL.ProvisionError, "atomic_publication_filesystem_unsupported"):
                INSTALL.check_install_preflight(Path("/sandbox/root"), Path("agent"), Path("ca"))
        self.assertEqual(events, ["probe"])

    def test_probe_uses_parent_then_fallback_ancestor_and_crash_litter_is_inert(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw) / "parent"; parent.mkdir(mode=0o700); parent.chmod(0o700)
            root = parent / "root"
            opened = []
            real_open = os.open
            def recorder(path, *args, **kwargs):
                opened.append(os.fspath(path)); return real_open(path, *args, **kwargs)
            with patch.object(INSTALL.os, "open", side_effect=recorder):
                INSTALL._probe_rename_exchange_capability(root, parent)
            self.assertEqual(opened[0], os.fspath(parent))
            fallback_root = Path(raw) / "missing-parent" / "root"
            opened.clear()
            with patch.object(INSTALL.os, "open", side_effect=recorder):
                INSTALL._probe_rename_exchange_capability(fallback_root, Path(raw))
            self.assertEqual(opened[0], os.fspath(Path(raw)))
            root.mkdir(mode=0o700); root.chmod(0o700)
            litter = parent / ".rigsignal-publication-probe-deadbeefdeadbeef-a"
            litter.mkdir(mode=0o700); litter.chmod(0o700)
            self.assertEqual(INSTALL.enrollment_condition(root), "clean")


class FailureSiteTests(unittest.TestCase):
    def setUp(self):
        # Version transport has dedicated real-entrypoint coverage.
        gate = patch.object(INSTALL, "stack_version_preflight")
        gate.start()
        self.addCleanup(gate.stop)

    @staticmethod
    def args(root: Path) -> SimpleNamespace:
        return SimpleNamespace(
            bundle=Path("unused"), endpoint="https://es.invalid", ca_file=Path("unused"),
            kibana_endpoint="https://kb.invalid", kibana_ca_file=Path("unused"),
            admin_credentials_file=Path("unused"), agent_binary=Path("unused"), profile="user",
            enrollment_root=root, dry_run=False, adopt_existing_w1_stream=False,
            ownership_profile=None, rollback=None, unsafe_test_injection=False,
            assets_marker=root.parent / "marker" / INSTALL.ASSETS_MARKER_FILE,
        )

    def patch_through_asset_apply(self, patches: ExitStack, root: Path, bundle: INSTALL.Bundle) -> None:
        patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                           return_value=self.args(root)))
        patches.enter_context(patch.object(INSTALL, "load_bundle", return_value=bundle))
        patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
        patches.enter_context(patch.object(INSTALL, "enrollment_condition", return_value="clean"))
        patches.enter_context(patch.object(INSTALL, "check_install_root_ancestors"))
        patches.enter_context(patch.object(INSTALL, "check_install_preflight",
                                           return_value=(Path("/canonical/ca.pem"), Path("/canonical/agent"))))
        patches.enter_context(patch.object(INSTALL, "configure_https"))
        patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
        patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
        patches.enter_context(patch.object(INSTALL, "dispatch_clean_root", return_value=False))
        patches.enter_context(patch.object(INSTALL, "fence_remote_ownership_profile"))
        patches.enter_context(patch.object(INSTALL, "run_topology_preflight"))
        patches.enter_context(patch.object(INSTALL, "prepare_install_root", return_value=root))
        patches.enter_context(patch.object(INSTALL, "load_state", return_value=None))
        patches.enter_context(patch.object(INSTALL, "bind_ownership_profile"))
        patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value="KUrXRgwRRQu-RikmIJhm0Q"))
        patches.enter_context(patch.object(INSTALL, "prerequisites"))
        patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
        patches.enter_context(patch.object(INSTALL, "fence"))
        patches.enter_context(patch.object(INSTALL, "remote_stream_condition",
                                           return_value=("compatible", frozenset())))

    def test_failure_site_tracker_starts_at_preflight(self):
        self.assertIs(INSTALL.FailureSiteTracker().site, INSTALL.FailureSite.PREFLIGHT)

    def test_prepare_install_root_refusal_reports_root_prepare(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            stderr = io.StringIO()
            with ExitStack() as patches:
                FailureSiteTests.patch_through_asset_apply(self, patches, root, INSTALL.Bundle("test", "test", []))
                patches.enter_context(patch.object(
                    INSTALL, "prepare_install_root",
                    side_effect=INSTALL.InputError("enrollment root is not protected")))
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install failed: enrollment output:\n"
                             "RIGSIGNAL_FAILURE_SITE root_prepare\n")

    def test_owned_asset_apply_failure_reports_asset_apply(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            asset = INSTALL.Asset("component_templates", "rigsignal-test", "unused", b"{}")
            stderr = io.StringIO()
            with ExitStack() as patches:
                self.patch_through_asset_apply(patches, root, INSTALL.Bundle("test", "test", [asset]))
                patches.enter_context(patch.object(INSTALL, "install_asset",
                                                   side_effect=OSError("transport failure")))
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install failed: enrollment output:\n"
                             "RIGSIGNAL_FAILURE_SITE asset_apply\n")

    def test_main_emits_separate_sanitized_failure_site_line(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            stderr = io.StringIO()
            with ExitStack() as patches:
                patches.enter_context(patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                                                   return_value=self.args(root)))
                patches.enter_context(patch.object(INSTALL, "load_bundle",
                                                   return_value=INSTALL.Bundle("test", "test", [])))
                patches.enter_context(patch.object(INSTALL, "role_body", return_value={}))
                patches.enter_context(patch.object(INSTALL, "check_install_root_ancestors"))
                patches.enter_context(patch.object(INSTALL, "check_install_preflight",
                                                   return_value=(Path("/canonical/ca.pem"), Path("/canonical/agent"))))
                patches.enter_context(patch.object(INSTALL, "configure_https"))
                patches.enter_context(patch.object(INSTALL, "admin_authorization", return_value="admin"))
                patches.enter_context(patch.object(INSTALL, "admin_credential_kind", return_value="native_user"))
                patches.enter_context(patch.object(INSTALL, "dispatch_clean_root", return_value=False))
                patches.enter_context(patch.object(INSTALL, "fence_remote_ownership_profile"))
                patches.enter_context(patch.object(INSTALL, "run_topology_preflight"))
                patches.enter_context(patch.object(INSTALL, "prepare_install_root", return_value=root))
                patches.enter_context(patch.object(INSTALL, "load_state", return_value=None))
                patches.enter_context(patch.object(INSTALL, "cluster_uuid", return_value="KUrXRgwRRQu-RikmIJhm0Q"))
                patches.enter_context(patch.object(INSTALL, "prerequisites"))
                patches.enter_context(patch.object(INSTALL, "cluster_health_gate"))
                patches.enter_context(patch.object(INSTALL, "fence"))
                patches.enter_context(patch.object(INSTALL, "remote_stream_condition",
                                                   return_value=("compatible", frozenset())))
                patches.enter_context(patch.object(INSTALL, "ensure_stream"))
                patches.enter_context(patch.object(INSTALL, "simulate"))
                patches.enter_context(patch.object(INSTALL, "recompute_target_generation", return_value="0" * 64))
                patches.enter_context(patch.object(INSTALL, "mint_key", return_value=("candidate", "encoded")))
                patches.enter_context(patch.object(INSTALL, "atomic_write"))
                patches.enter_context(patch.object(INSTALL, "secure_candidate_root", return_value=root))
                patches.enter_context(patch.object(INSTALL, "enrollment_files", return_value={}))
                patches.enter_context(patch.object(INSTALL, "verify_stream_behavior"))
                patches.enter_context(patch.object(INSTALL, "verify_role_matrix"))
                patches.enter_context(patch.object(INSTALL, "prepublication_asset_fence"))
                patches.enter_context(patch.object(INSTALL, "atomic_publication",
                                                   side_effect=OSError("response body /private/key")))
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install failed: enrollment output:\n"
                             "RIGSIGNAL_FAILURE_SITE publication_stage\n")
            self.assertNotIn("response body", stderr.getvalue())
            self.assertNotIn("/private/key", stderr.getvalue())

    def test_failure_site_persistence_is_best_effort_and_archived(self):
        broken_journal = MagicMock()
        broken_journal.failure_site.side_effect = OSError("unwritable")
        tracker = INSTALL.FailureSiteTracker()
        tracker.attach_journal(broken_journal)
        tracker.mark(INSTALL.FailureSite.PUBLICATION_EXCHANGE)
        tracker.persist()
        self.assertIs(tracker.site, INSTALL.FailureSite.PUBLICATION_EXCHANGE)

        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            journal = INSTALL.TransactionJournal(root, "fleet-coexist")
            journal.failure_site(INSTALL.FailureSite.LOCAL_COMMIT)
            journal.value["apply_ok"] = True
            journal._persist()
            archived = INSTALL.TransactionJournal(root, "fleet-coexist", new_transaction=True)
            self.assertEqual(archived.value["transactions"][-1]["failure_site"], "local_commit")

    def test_dirty_local_condition_wins_over_ancestor_topology_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            ancestor = MagicMock(side_effect=INSTALL.ProvisionError(
                "install refused: enrollment ancestor is not protected:"))
            configure = MagicMock()
            same_class = MagicMock(side_effect=INSTALL.ProvisionError(
                "install refused: enrollment_publication_path_too_long"))
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "enrollment_condition", return_value="remediation"), \
                 patch.object(INSTALL, "check_install_root_ancestors", ancestor), \
                 patch.object(INSTALL, "check_install_preflight", same_class), \
                 patch.object(INSTALL, "configure_https", configure):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install refused: enrollment_remediation_required\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            ancestor.assert_not_called()
            same_class.assert_not_called()
            configure.assert_not_called()

    def test_same_class_refusal_precedes_https_and_root_creation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "not-created" / "enrollment"
            configure = MagicMock()
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "check_install_root_ancestors"), \
                 patch.object(INSTALL, "check_install_preflight", side_effect=INSTALL.ProvisionError(
                     "install refused: enrollment_publication_path_too_long")), \
                 patch.object(INSTALL, "configure_https", configure):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 2)
            self.assertEqual(stderr.getvalue(), "install refused: enrollment_publication_path_too_long\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            configure.assert_not_called()
            self.assertFalse(root.exists())

    def test_ancestor_refusal_precedes_https_and_root_creation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "not-created" / "enrollment"
            configure = MagicMock()
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "check_install_root_ancestors",
                              side_effect=INSTALL.ProvisionError(
                                  "install refused: enrollment ancestor is not protected:")), \
                 patch.object(INSTALL, "configure_https", configure):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 2)
            self.assertEqual(stderr.getvalue(), "install refused: enrollment ancestor is not protected:\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            configure.assert_not_called()
            self.assertFalse(root.exists())

    def test_committed_root_refuses_unsafe_parent_before_remote_dispatch(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            ancestor = MagicMock(side_effect=INSTALL.ProvisionError(
                "install refused: enrollment ancestor is not protected:"))
            remote = MagicMock()
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "enrollment_condition", return_value="committed"), \
                 patch.object(INSTALL, "check_install_root_ancestors", ancestor), \
                 patch.object(INSTALL, "check_install_preflight") as preflight, \
                 patch.object(INSTALL, "admin_authorization", remote):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 2)
            self.assertEqual(stderr.getvalue(), "install refused: enrollment ancestor is not protected:\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            ancestor.assert_called_once_with(root)
            preflight.assert_not_called()
            remote.assert_not_called()


class MainPreflightRecoveryTests(unittest.TestCase):
    def setUp(self):
        # Version transport has dedicated real-entrypoint coverage.
        gate = patch.object(INSTALL, "stack_version_preflight")
        gate.start()
        self.addCleanup(gate.stop)

    @staticmethod
    def args(root: Path, *, rollback: Path | None = None) -> SimpleNamespace:
        return SimpleNamespace(
            bundle=Path("unused"), endpoint="https://es.invalid", ca_file=Path("unused"),
            kibana_endpoint="https://kb.invalid", kibana_ca_file=Path("unused"),
            admin_credentials_file=Path("unused"), agent_binary=Path("agent"), profile="user",
            enrollment_root=root, dry_run=False, adopt_existing_w1_stream=False,
            ownership_profile=None, rollback=rollback, unsafe_test_injection=False,
            predecessor_manifest=None,
        )

    def test_passing_main_boundary_runs_real_preflight_before_remote_dispatch(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "check_install_root_ancestors"), \
                 patch.object(INSTALL, "_check_agent_binary") as agent, \
                 patch.object(INSTALL, "_rename_exchange_symbol_available", return_value=True), \
                 patch.object(INSTALL, "_mount_filesystem_type", return_value="ext4"), \
                 patch.object(INSTALL, "_check_publication_stage_path") as stage, \
                 patch.object(INSTALL, "_check_parent_fsync"), \
                 patch.object(INSTALL, "_check_local_transaction_readiness"), \
                 patch.object(INSTALL, "resolve_enrollment_ca_file", return_value=Path("/canonical/ca.pem")), \
                 patch.object(INSTALL, "configure_https"), \
                 patch.object(INSTALL, "admin_authorization", return_value="admin"), \
                 patch.object(INSTALL, "admin_credential_kind", return_value="native_user"), \
                 patch.object(INSTALL, "dispatch_clean_root",
                              side_effect=INSTALL.ProvisionError("install refused: boundary_stop")):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            self.assertEqual(stderr.getvalue(), "install refused: boundary_stop\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            agent.assert_called_once_with(Path("agent"))
            stage.assert_called_once()

    def test_outbox_refusal_precedes_http_dispatch(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            refusal = INSTALL.ProvisionError("install refused: outbox preflight:")
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "check_install_root_ancestors"), \
                 patch.object(INSTALL, "check_outbox_root", side_effect=refusal), \
                 patch.object(INSTALL, "check_install_preflight") as preflight, \
                 patch.object(INSTALL, "configure_https") as configure, \
                 patch.object(INSTALL, "admin_authorization") as transport:
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 2)
            self.assertEqual(stderr.getvalue(), "install refused: outbox preflight:\n"
                             "RIGSIGNAL_FAILURE_SITE preflight\n")
            preflight.assert_not_called()
            configure.assert_not_called()
            transport.assert_not_called()

    def test_main_outbox_preflight_order_is_pinned_at_both_call_sites(self):
        refusal = INSTALL.ProvisionError("install refused: outbox preflight:")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "default-enrollment"
            calls = []

            def ancestor(path):
                calls.append(("ancestor", path))

            def outbox(path):
                calls.append(("outbox", path))
                raise refusal

            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "enrollment_condition", return_value="clean"), \
                 patch.object(INSTALL, "check_install_root_ancestors", side_effect=ancestor), \
                 patch.object(INSTALL, "check_outbox_root", side_effect=outbox):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(INSTALL.main(), 2)
            self.assertEqual(calls, [("ancestor", root), ("outbox", root.parent / "outbox")])

        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "incomplete-enrollment")
            state = INSTALL.state_template("KUrXRgwRRQu-RikmIJhm0Q", INSTALL.TARGET_GENERATION_KAT,
                                           None, str(root))
            state.update(phase="mint_intent", pending_mint_name="unfinished")
            INSTALL.atomic_write(root, "state.json", INSTALL.jcs(state) + b"\n")
            calls = []

            def ancestor(path):
                calls.append(("ancestor", path))

            def outbox(path):
                calls.append(("outbox", path))
                raise refusal

            def recover_unfinished(_base, path, method, _authorization, data=None, headers=None):
                if path == "/_security/api_key?name=unfinished&active_only=true" and method == "GET":
                    return INSTALL.jcs({"api_keys": [{"name": "unfinished", "id": "orphan"}]})
                if path == "/_security/api_key" and method == "DELETE":
                    return INSTALL.jcs({"invalidated_api_keys": ["orphan"],
                                        "previously_invalidated_api_keys": [], "error_count": 0,
                                        "error_details": []})
                self.fail("unexpected recovery request " + method + " " + path)

            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "check_install_root_ancestors", side_effect=ancestor), \
                 patch.object(INSTALL, "check_outbox_root", side_effect=outbox), \
                 patch.object(INSTALL, "configure_https"), \
                 patch.object(INSTALL, "admin_authorization", return_value="admin"), \
                 patch.object(INSTALL, "admin_credential_kind", return_value="native_user"), \
                 patch.object(INSTALL, "fence_remote_ownership_profile"), \
                 patch.object(INSTALL, "run_topology_preflight"), \
                 patch.object(INSTALL, "cluster_uuid", return_value=state["expected_cluster_uuid"]), \
                 patch.object(INSTALL, "request", side_effect=recover_unfinished), \
                 patch.object(INSTALL, "dispatch_clean_root", return_value=False):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(INSTALL.main(), 4)
            self.assertEqual(calls, [("ancestor", root), ("outbox", root.parent / "outbox")])

    def test_incomplete_recovery_precedes_preflight_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            state = INSTALL.state_template("KUrXRgwRRQu-RikmIJhm0Q", INSTALL.TARGET_GENERATION_KAT,
                                           None, str(root))
            state.update(phase="mint_intent", pending_mint_name="unfinished")
            INSTALL.atomic_write(root, "state.json", INSTALL.jcs(state) + b"\n")
            refusal = INSTALL.ProvisionError("install refused: atomic_publication_filesystem_unsupported")
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "check_install_root_ancestors"), \
                 patch.object(INSTALL, "configure_https"), \
                 patch.object(INSTALL, "admin_authorization", return_value="admin"), \
                 patch.object(INSTALL, "admin_credential_kind", return_value="native_user"), \
                 patch.object(INSTALL, "fence_remote_ownership_profile"), \
                 patch.object(INSTALL, "run_topology_preflight"), \
                 patch.object(INSTALL, "cluster_uuid", return_value=state["expected_cluster_uuid"]), \
                 patch.object(INSTALL, "request", side_effect=lambda _base, path, method, _authorization,
                              data=None, headers=None: (
                                  INSTALL.jcs({"api_keys": [{"name": "unfinished", "id": "orphan"}]})
                                  if (path == "/_security/api_key?name=unfinished&active_only=true"
                                      and method == "GET")
                                  else INSTALL.jcs({"invalidated_api_keys": ["orphan"],
                                                    "previously_invalidated_api_keys": [],
                                                    "error_count": 0, "error_details": []})
                                  if (path == "/_security/api_key" and method == "DELETE")
                                  else self.fail("unexpected recovery request " + method + " " + path))), \
                 patch.object(INSTALL, "dispatch_clean_root", return_value=False), \
                 patch.object(INSTALL, "check_install_preflight", side_effect=refusal) as preflight:
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 4)
            preflight.assert_called_once_with(root, Path("agent"), Path("unused"))
            self.assertEqual(stderr.getvalue(), "install refused: atomic_publication_filesystem_unsupported\n"
                             "RIGSIGNAL_FAILURE_SITE root_prepare\n")
            self.assertFalse((root / "state.json").exists())

    def test_incomplete_recovery_precedes_bad_default_marker_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            state = INSTALL.state_template("KUrXRgwRRQu-RikmIJhm0Q", INSTALL.TARGET_GENERATION_KAT,
                                           None, str(root))
            state.update(phase="mint_intent", pending_mint_name="unfinished")
            INSTALL.atomic_write(root, "state.json", INSTALL.jcs(state) + b"\n")
            state_home = Path(raw) / "state"
            shared = state_home / "rigsignal"
            shared.mkdir(parents=True, mode=0o755)
            shared.chmod(0o755)
            safe = Path(raw) / "safe"
            safe.mkdir(mode=0o700)
            (shared / "assets").symlink_to(safe, target_is_directory=True)
            recovery_requests = []
            asset = INSTALL.Asset("component_templates", "rigsignal-test", "unused", b"{}")

            def recover_unfinished(_base, path, method, _authorization, data=None, headers=None):
                recovery_requests.append((method, path))
                if path == "/_security/api_key?name=unfinished&active_only=true" and method == "GET":
                    return INSTALL.jcs({"api_keys": [{"name": "unfinished", "id": "orphan"}]})
                if path == "/_security/api_key" and method == "DELETE":
                    return INSTALL.jcs({"invalidated_api_keys": ["orphan"],
                                        "previously_invalidated_api_keys": [], "error_count": 0,
                                        "error_details": []})
                self.fail("unexpected recovery request " + method + " " + path)

            with patch.dict(os.environ, {"XDG_STATE_HOME": str(state_home)}), \
                 patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [asset])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "check_install_root_ancestors"), \
                 patch.object(INSTALL, "check_outbox_root"), \
                 patch.object(INSTALL, "check_install_preflight",
                              return_value=(Path("/canonical/ca.pem"), Path("/canonical/agent"))), \
                 patch.object(INSTALL, "configure_https"), \
                 patch.object(INSTALL, "admin_authorization", return_value="admin"), \
                 patch.object(INSTALL, "admin_credential_kind", return_value="native_user"), \
                 patch.object(INSTALL, "fence_remote_ownership_profile"), \
                 patch.object(INSTALL, "run_topology_preflight"), \
                 patch.object(INSTALL, "dispatch_clean_root", return_value=False), \
                 patch.object(INSTALL, "cluster_uuid", return_value=state["expected_cluster_uuid"]), \
                 patch.object(INSTALL, "request", side_effect=recover_unfinished):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 4)
            self.assertEqual(recovery_requests, [
                ("GET", "/_security/api_key?name=unfinished&active_only=true"),
                ("DELETE", "/_security/api_key"),
            ])
            self.assertEqual(stderr.getvalue(), "install refused: assets_marker_directory\n"
                             "RIGSIGNAL_FAILURE_SITE root_prepare\n")
            self.assertFalse((root / "state.json").exists())

    def test_recovery_handshake_uses_preflight_validated_agent_path(self):
        with tempfile.TemporaryDirectory() as raw:
            root = INSTALL.secure_root(Path(raw) / "enrollment")
            state = INSTALL.state_template("KUrXRgwRRQu-RikmIJhm0Q", INSTALL.TARGET_GENERATION_KAT,
                                           "candidate", str(root))
            state.update(phase="candidate_verified", candidate_key_id="candidate",
                         pending_mint_name="published-pending-revoke")
            INSTALL.atomic_write(root, "state.json", INSTALL.jcs(state) + b"\n")
            resolved_agent = Path("/canonical/agent")
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args", return_value=self.args(root)), \
                 patch.object(INSTALL, "load_bundle", return_value=INSTALL.Bundle("test", "test", [])), \
                 patch.object(INSTALL, "role_body", return_value={}), \
                 patch.object(INSTALL, "enrollment_condition", return_value="incomplete"), \
                 patch.object(INSTALL, "configure_https"), \
                 patch.object(INSTALL, "admin_authorization", return_value="admin"), \
                 patch.object(INSTALL, "admin_credential_kind", return_value="native_user"), \
                 patch.object(INSTALL, "fence_remote_ownership_profile"), \
                 patch.object(INSTALL, "run_topology_preflight"), \
                 patch.object(INSTALL, "cluster_uuid", return_value=state["expected_cluster_uuid"]), \
                 patch.object(INSTALL, "check_install_root_ancestors"), \
                 patch.object(INSTALL, "check_install_preflight",
                              return_value=(Path("/canonical/ca.pem"), resolved_agent)) as preflight, \
                 patch.object(INSTALL, "run_handshake",
                              side_effect=INSTALL.InputError("probe failed")) as handshake:
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(INSTALL.main(), 3)
            preflight.assert_called_once_with(root, Path("agent"), Path("unused"))
            handshake.assert_called_once_with(resolved_agent, root)
            self.assertEqual(stderr.getvalue(), "install failed: old shipper API key revocation:\n"
                             "RIGSIGNAL_FAILURE_SITE root_prepare\n")

    def test_published_handshake_uses_preflight_validated_agent_path(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "enrollment"
            resolved_agent = Path("/canonical/agent")
            with ExitStack() as patches:
                FailureSiteTests.patch_through_asset_apply(
                    self, patches, root, INSTALL.Bundle("test", "test", []))
                patches.enter_context(patch.object(
                    INSTALL, "check_install_preflight",
                    return_value=(Path("/canonical/ca.pem"), resolved_agent)))
                patches.enter_context(patch.object(INSTALL, "ensure_stream"))
                patches.enter_context(patch.object(INSTALL, "simulate"))
                patches.enter_context(patch.object(INSTALL, "recompute_target_generation",
                                                   return_value="0" * 64))
                patches.enter_context(patch.object(INSTALL, "mint_key", return_value=("candidate", "encoded")))
                patches.enter_context(patch.object(INSTALL, "atomic_write"))
                patches.enter_context(patch.object(INSTALL, "secure_candidate_root", return_value=root))
                patches.enter_context(patch.object(INSTALL, "enrollment_files", return_value={}))
                patches.enter_context(patch.object(INSTALL, "verify_stream_behavior"))
                patches.enter_context(patch.object(INSTALL, "verify_role_matrix"))
                patches.enter_context(patch.object(INSTALL, "prepublication_asset_fence"))
                patches.enter_context(patch.object(INSTALL, "atomic_publication"))
                handshake = patches.enter_context(patch.object(
                    INSTALL, "run_handshake", side_effect=INSTALL.InputError("probe failed")))
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(INSTALL.main(), 3)
            handshake.assert_called_once_with(resolved_agent, root)

    def test_rollback_remains_reachable_below_unsafe_parent(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw) / "legacy"
            parent.mkdir(mode=0o775)
            parent.chmod(0o775)
            root = INSTALL.secure_root(parent / "enrollment")
            rollback_args = self.args(root, rollback=root)
            rollback_args.bundle = None
            with patch.object(INSTALL.argparse.ArgumentParser, "parse_args",
                              return_value=rollback_args), \
                 patch.object(INSTALL, "configure_https"), \
                 patch.object(INSTALL, "admin_authorization", return_value="admin"), \
                 patch.object(INSTALL, "check_version_fence"), \
                 patch.object(INSTALL, "fence_remote_ownership_profile"), \
                 patch.object(INSTALL, "rollback_transaction", return_value=[]), \
                 patch.object(INSTALL, "check_install_root_ancestors") as ancestors:
                stdout = io.StringIO()
                with redirect_stderr(io.StringIO()), patch("sys.stdout", stdout):
                    self.assertEqual(INSTALL.main(), 0)
            self.assertEqual(stdout.getvalue(), "rollback completed from journaled intents\n")
            ancestors.assert_not_called()


if __name__ == "__main__":
    unittest.main()
