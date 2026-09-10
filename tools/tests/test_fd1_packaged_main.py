#!/usr/bin/env python3
"""FD-1 packaged ``main()`` publication integration tests.

The child imports the staged engine as ``__main__``.  In particular it never
loads ``tools/install_assets.py``: the repository contributes only the
scripted urllib seam.  S7 discharges cmt-2026-08-26-rigsignal-fd-2(a).
"""

import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRATCH = Path(os.environ.get("RIGSIGNAL_FD1_TMPDIR", tempfile.gettempdir()))
REQUIRED = frozenset(("credentials.toml", "handshake.toml",
                      "shipping-policy-v1.toml", "state.json"))


@dataclass
class ProductResult:
    """Keep the product's contract status separate from harness success."""

    product_rc: int
    harness_attested: bool
    stderr: str
    stdout: str
    mutations: frozenset[str]
    transport_calls: tuple[str, ...]
    filesystem_type: str


CHILD = r'''
import importlib.util
import os
import re
import sys
from pathlib import Path

repo, engine, bundle_path, root, marker, audit = map(Path, sys.argv[1:7])
sys.path.insert(0, str(repo))
spec = importlib.util.spec_from_file_location("__main__", engine)
install = importlib.util.module_from_spec(spec)
sys.modules["__main__"] = install
from tools.tests.transaction_transport import ScriptedTransactionTransport
print("FD1_ENGINE " + str(install.__spec__.origin), file=sys.stderr, flush=True)
print("FD1_TRANSPORT installed", file=sys.stderr, flush=True)
agent = root.parent / "fd1-agent"
# The stub must report the version the fence will read, not a literal: a release commit moves
# the engine stamp and a hardcoded version would make fence_versions() refuse every release
# candidate.  Two deliberate choices keep the stub and the fence in agreement by construction:
#   * .resolve() mirrors install_assets.TOOLS_DIR = Path(__file__).resolve().parent, so both
#     read the same stamp file even if the engine is reached through a symlink;
#   * the pattern below is install_assets.engine_version()'s pattern verbatim, so the two
#     cannot disagree on a quoting or escaping edge that one parser accepts and the other does not.
stamp = engine.resolve().parent / "_version.py"
stamp_match = re.search(r'^ENGINE_VERSION = (["\'])([^"\']+)\1$',
                        stamp.read_text(encoding="utf-8"), re.MULTILINE)
if stamp_match is None:
    raise SystemExit("fd1: no readable ENGINE_VERSION stamp at " + str(stamp))
agent_version = stamp_match.group(2)
agent.write_text("#!/bin/sh\nif [ \"$1\" = --version ]; then echo " + agent_version + "; fi\nexit 0\n")
agent.chmod(0o700)
# Emitted only after the stub exists and is executable, so the line attests a usable stub.
# unittest surfaces captured child stderr only on failure, so the parent ASSERTS on this line
# rather than relying on it reaching a green log.
print("FD1_AGENT_VERSION " + agent_version, file=sys.stderr, flush=True)
admin = root.parent / "fd1-admin.toml"
admin.write_text("[elasticsearch]\nusername = \"fd1\"\npassword = \"fd1\"\n")
admin.chmod(0o600)
ca = root.parent / "fd1-ca.pem"
ca.write_text("unused by the in-process scripted transport\n")
ca.chmod(0o600)
args = [str(engine), "--bundle", str(bundle_path), "--endpoint", "https://es.invalid",
        "--ca-file", str(ca), "--kibana-endpoint", "https://kb.invalid", "--kibana-ca-file", str(ca),
        "--admin-credentials-file", str(admin), "--agent-binary", str(agent), "--profile", "user",
        "--enrollment-root", str(root), "--assets-marker", str(marker)]
if os.environ.get("RIGSIGNAL_FD1_UPGRADE"):
    args.append("--upgrade")
sys.argv = args

def install_seam(frame):
    """Install the urllib seam at the first instruction of staged ``main``."""
    values = frame.f_globals
    bundle = values["load_bundle"](bundle_path)
    transport = ScriptedTransactionTransport(install, bundle)
    def recorded_urlopen(request, timeout=None):
        with audit.open("a", encoding="utf-8") as handle:
            handle.write(request.get_method() + " " + request.full_url + "\n")
        return transport.urlopen(request, timeout)
    values["urllib"].request.urlopen = recorded_urlopen
    values["configure_https"] = lambda *_args: None
    # The checkout's fixed 0775 worktree ancestor is outside the disposable
    # ext4 root; all enrollment-root and publication operations remain real.
    values["check_install_root_ancestors"] = lambda *_args, **_kwargs: None
    values["check_outbox_root"] = lambda *_args, **_kwargs: None
    values["dispatch_clean_root"] = lambda *_args: False
    for name in ("fence_remote_ownership_profile", "run_topology_preflight", "prerequisites",
                 "cluster_health_gate", "fence", "ensure_stream", "simulate",
                 "verify_role_matrix", "invalidate", "prepublication_asset_fence"):
        values[name] = lambda *_args, **_kwargs: None
    checks = {"stream": 0}
    def stream_condition(*_args):
        checks["stream"] += 1
        return ("absent", None) if checks["stream"] == 1 else ("compatible", {"fd1": 1})
    values["remote_stream_condition"] = stream_condition
    def verify_stream(*call_args):
        if os.environ.get("RIGSIGNAL_FD1_FORCE_ROTATE") and call_args[1] == "ApiKey fd1-secret-one":
            raise values["InputError"]("force a real candidate publication")
    values["verify_stream_behavior"] = verify_stream
    def mint(*_args):
        values["mark_mutation_issued"]()
        key = os.environ.get("RIGSIGNAL_FD1_KEY", "one")
        return ("fd1-candidate-" + key, "fd1-secret-" + key)
    values["mint_key"] = mint
    real_transaction = values["run_default_asset_transaction"]
    def transaction(*call_args, **kwargs):
        if kwargs.get("step_11_only") or marker.exists():
            return "noop"
        return real_transaction(*call_args, **kwargs)
    values["run_default_asset_transaction"] = transaction
    sys.settrace(None)

def tracer(frame, event, _argument):
    if event == "call" and frame.f_code.co_name == "main" and frame.f_globals.get("__file__") == str(engine):
        install_seam(frame)
    return tracer

sys.settrace(tracer)
assert spec.loader is not None
spec.loader.exec_module(install)
'''


class PackagedMainTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self._require_ext4_evidence()
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.work = Path(self.temp.name)
        self.case = self.work / "case"
        self.case.mkdir(mode=0o700)
        self.case.chmod(0o700)
        self.enrollment_root = self.case / "enrollment"
        self.archive = self.work / "assets.tar.gz"
        self.engine_root = self.work / "staged-engine"
        self._build_staged_package()
        self.engine = self.engine_root / "install_assets.py"
        self.assertTrue(self.engine.is_file(), "the builder did not stage the package engine")

    def tearDown(self):
        self.temp.cleanup()

    def _require_ext4_evidence(self):
        """``stat`` calls ext4 ``ext2/ext3`` on this host; accept that spelling."""
        shm = subprocess.run(["stat", "-f", "-c", "%T", "/dev/shm"], text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if shm.returncode or shm.stdout.strip() != "tmpfs":
            self.skipTest("FD1 filesystem probe self-test failed: /dev/shm did not report tmpfs")
        probe = subprocess.run(["stat", "-f", "-c", "%T", str(SCRATCH)], text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        fs_type = probe.stdout.strip() if probe.returncode == 0 else "unknown"
        if fs_type == "tmpfs" or fs_type not in {"ext2/ext3"}:
            self.skipTest("FD1 requires ext4 evidence; RIGSIGNAL_FD1_TMPDIR reports " + fs_type)
        self.fs_type = fs_type

    def _build_staged_package(self):
        command = [sys.executable, str(ROOT / "tools/build_asset_bundle.py"),
                   "--source-commit", subprocess.check_output(
                       ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                   "--output", str(self.archive), "--engine-output", str(self.engine_root)]
        built = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False)
        self.assertEqual(built.returncode, 0, built.stderr)
        # Archive validation makes the build an asset-bundle build, while
        # --engine-output is the builder's release staging/extraction surface.
        with tarfile.open(self.archive, "r:gz") as bundle:
            self.assertIn("manifest.json", bundle.getnames())
            self.bundle_version = json.loads(
                bundle.extractfile("manifest.json").read().decode("utf-8"))["bundle_version"]

    def _mutate_engine(self):
        mutant = os.environ.get("RIGSIGNAL_FD1_MUTANT")
        if not mutant:
            return
        if getattr(self, "_mutated", False):
            return
        source = self.engine.read_text(encoding="utf-8")
        edits = {
            "owned_residue_proceeds": (
                'if condition == "remediation":\n            raise ProvisionError("install refused: enrollment_remediation_required")',
                'if False:\n            raise ProvisionError("install refused: enrollment_remediation_required")'),
            "legacy_proceeds": (
                "if name == legacy:\n        return True",
                "if name == legacy:\n        return False"),
            "random_proceeds": (
                "return name.startswith(prefix) and _PUBLICATION_STAGE_SUFFIX_RE.fullmatch(name[len(prefix):]) is not None",
                "return False"),
            "foreign_deleted": (
                'print("inert enrollment publication lookalike is not owned private debris", file=sys.stderr)',
                'os.rmdir(name, dir_fd=parent_fd)'),
        }
        self.assertIn(mutant, edits, "unknown RIGSIGNAL_FD1_MUTANT")
        before, after = edits[mutant]
        self.assertIn(before, source, "mutant source anchor missing")
        self.engine.write_text(source.replace(before, after, 1), encoding="utf-8")
        self._mutated = True

    @staticmethod
    def _tree(root):
        if not root.exists():
            return {}
        result = {}
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root).as_posix()
            if path.is_dir():
                result[rel + "/"] = None
            else:
                result[rel] = path.read_bytes()
        return result

    def _run(self, root, *, update=False, rotate=False):
        self._require_ext4_evidence()  # Probe and tmpfs self-test before every product run.
        self._mutate_engine()
        marker = self.work / "marker-home" / "assets-marker.json"
        audit = self.case / "transport.log"
        before = self._tree(self.case)
        env = os.environ.copy()
        env.update({"XDG_STATE_HOME": str(self.case / "state-home"),
                    "RIGSIGNAL_FD1_UPGRADE": "1" if update else "",
                    "RIGSIGNAL_FD1_FORCE_ROTATE": "1" if rotate else "",
                    "RIGSIGNAL_FD1_KEY": "two" if rotate else "one"})
        completed = subprocess.run([sys.executable, "-c", CHILD, str(ROOT), str(self.engine),
                                    str(self.archive), str(root), str(marker), str(audit)],
                                   cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, check=False)
        after = self._tree(self.case)
        changed = frozenset(set(before) ^ set(after) | {
            name for name in set(before) & set(after) if before[name] != after[name]})
        calls = tuple(audit.read_text(encoding="utf-8").splitlines()) if audit.exists() else ()
        engine_attested = ("FD1_ENGINE " + str(self.engine) in completed.stderr
                           and self.engine.is_relative_to(self.engine_root))
        transport_installed = "FD1_TRANSPORT installed" in completed.stderr
        filesystem_probe_recorded = self.fs_type == "ext2/ext3"
        result = ProductResult(completed.returncode,
                               engine_attested and transport_installed and filesystem_probe_recorded,
                               completed.stderr, completed.stdout,
                               changed, calls, self.fs_type)
        self.assertTrue(result.harness_attested)
        self.assertIn("FD1_ENGINE " + str(self.engine), result.stderr)
        self.assertNotIn(str(ROOT / "tools") + "/install_assets.py", result.stderr)
        self.assertIn("FD1_TRANSPORT installed", result.stderr)
        # ADDED: the stub agent was built from the staged engine stamp and reports the version the
        # bundle records.  Additive and strictly stricter -- it cannot turn a red run green.  It
        # compares two separately written artefacts (stage_engine's _version.py, read with the
        # fence's own pattern, against the archive manifest), so a staging inconsistency fails
        # here instead of surfacing later as an unexplained version_skew.
        self.assertIn("FD1_AGENT_VERSION " + self.bundle_version, result.stderr)
        return result

    def _assert_published(self, root):
        self.assertTrue(root.is_dir(), "main() did not create the published generation")
        self.assertEqual({item.name for item in root.iterdir()}, REQUIRED)
        for name in REQUIRED:
            item = root / name
            self.assertTrue(item.is_file())
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
        self.assertEqual(json.loads((root / "state.json").read_text())["phase"], "committed")

    def _owned_stage(self, root, *, legacy=False, private=True):
        root.mkdir(mode=0o700, exist_ok=True)
        root.chmod(0o700)
        name = ".rigsignal-publication-" + root.name
        if not legacy:
            name += "-0123456789abcdef"
        stage = root.parent / name
        stage.mkdir(mode=0o700)
        stage.chmod(0o700 if private else 0o755)
        return stage

    def _assert_remediation_refusal(self, result):
        self.assertEqual(result.product_rc, 3)
        self.assertIn("install refused: enrollment_remediation_required", result.stderr)
        self.assertEqual(result.transport_calls, ())

    def test_s1_genuine_packaged_install(self):
        root = self.enrollment_root
        result = self._run(root)
        self.assertEqual(result.product_rc, 0, result.stderr)
        self.assertTrue(result.transport_calls, "main() never reached urllib transport")
        self._assert_published(root)
        self.assertIn("enrollment/", result.mutations)
        self.assertEqual(result.filesystem_type, "ext2/ext3")

    def test_s2_update_publishes_a_complete_new_generation(self):
        root = self.enrollment_root
        first = self._run(root)
        self.assertEqual(first.product_rc, 0, first.stderr)
        old = {name: (root / name).read_bytes() for name in REQUIRED}
        second = self._run(root, rotate=True)
        self.assertEqual(second.product_rc, 0, second.stderr)
        self.assertTrue(second.transport_calls)
        self._assert_published(root)
        current = {name: (root / name).read_bytes() for name in REQUIRED}
        self.assertNotEqual(current, old)
        self.assertEqual(current["handshake.toml"], old["handshake.toml"])
        self.assertEqual(current["shipping-policy-v1.toml"], old["shipping-policy-v1.toml"])
        self.assertIn(b"fd1-secret-two", current["credentials.toml"])
        self.assertEqual(json.loads(current["state.json"])["active_key_id"], "fd1-candidate-two")
        self.assertIn("enrollment/state.json", second.mutations)
        self.assertFalse(any(path.name.startswith(".rigsignal-publication-enrollment-")
                             for path in self.case.iterdir()), "successful cleanup left owned residue")

    def test_s3_owned_bundle_a_residue_refuses_without_transport_or_publication_mutation(self):
        root = self.enrollment_root
        self._owned_stage(root)
        before = self._tree(root)
        result = self._run(root)
        self._assert_remediation_refusal(result)
        self.assertIn("RIGSIGNAL_FAILURE_SITE preflight", result.stderr)
        self.assertEqual(self._tree(root), before)

    def test_s4_legacy_exact_name_debris_refuses(self):
        root = self.enrollment_root
        self._owned_stage(root, legacy=True)
        result = self._run(root)
        self._assert_remediation_refusal(result)
        self.assertFalse(any(path.startswith("enrollment/") for path in result.mutations))

    def test_s5_random_owned_debris_refuses(self):
        root = self.enrollment_root
        self._owned_stage(root)
        result = self._run(root)
        self._assert_remediation_refusal(result)
        self.assertFalse(any(path.startswith("enrollment/") for path in result.mutations))

    def test_s6_foreign_exact_shape_lookalike_is_inert_and_nonblocking(self):
        root = self.enrollment_root
        lookalike = self._owned_stage(root, private=False)
        before = self._tree(lookalike)
        result = self._run(root)
        self.assertEqual(result.product_rc, 0, result.stderr)
        self.assertTrue(result.transport_calls)
        self.assertIn("inert enrollment publication lookalike is not owned private debris", result.stderr)
        self.assertTrue(lookalike.exists(), "foreign lookalike was deleted")
        self.assertEqual(self._tree(lookalike), before)
        self._assert_published(root)

    # cmt-2026-08-26-rigsignal-fd-2(a).
    def test_s7_fd2a_real_foreign_root_refuses_at_preflight_before_any_root_mutation(self):
        root = self.enrollment_root
        root.mkdir(mode=0o700)
        root.chmod(0o000)
        if os.geteuid() != 0:
            self.skipTest("S7 requires root to create a real foreign-owned root")
        try:
            os.chown(root, os.geteuid() + 1, -1)
        except PermissionError:
            self.skipTest("S7 requires permission to create a real foreign-owned root")
        before_tree = self._tree(root)
        before = (root.lstat().st_dev, root.lstat().st_ino, root.lstat().st_uid,
                  stat.S_IMODE(root.lstat().st_mode))
        result = self._run(root)
        self.assertEqual(result.product_rc, 3)
        self.assertIn("RIGSIGNAL_FAILURE_SITE preflight", result.stderr)
        self.assertEqual(result.transport_calls, ())
        self.assertEqual((root.lstat().st_dev, root.lstat().st_ino, root.lstat().st_uid,
                          stat.S_IMODE(root.lstat().st_mode)), before)
        self.assertEqual(self._tree(root), before_tree)
