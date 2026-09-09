"""Real uripack planner/executor, synthetic Guard; never production evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from prepare_uripack import prepare


class TestGuard:
    identity = "uriprocess-test-only:not-production-guard"
    required_checks = ["uriprocess.test.upstream"]

    def __init__(self, deny=False):
        self.deny = deny
        self.actions = []

    def call(self, action, plan, payload=None):
        from uripack_refactor.common import fail
        from uripack_refactor.planner import artifact_digest
        self.actions.append(action)
        if self.deny:
            fail("UPK-GUARD-001", "Synthetic test denial")
        if action == "tool":
            # Actual upstream tests, isolated from the extraction staging tree.
            import shutil
            with tempfile.TemporaryDirectory() as temporary:
                copied = Path(temporary) / "copy"
                shutil.copytree(payload["staging_root"], copied)
                for manifest in copied.glob("packs/*/tree/poa/*/*/*/package.json"):
                    subprocess.run(["node", "--test", *map(str, sorted((manifest.parent / "tests").glob("*.test.mjs")))],
                                   cwd=manifest.parent, check=True, capture_output=True)
                for manifest in copied.glob("packs/*/tree/native/*/*/pyproject.toml"):
                    from check_native import complete_test_count
                    report = Path(temporary) / (manifest.parent.parent.name + "-tests.xml")
                    env = {"PATH": os.environ.get("PATH", os.defpath), "PYTHONPATH": str(manifest.parent),
                           "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
                    subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml", str(report), "tests"],
                                   cwd=manifest.parent, env=env, check=True, capture_output=True)
                    complete_test_count(report)
        return {"allowed": True, "decision_ref": "test:decision", "lease_ref": "test:lease",
                "fencing_token": 1, "expires_at": int(time.time()) + 120,
                "result": {"schema": "uripack.check-result/v1", "status": "passed",
                           "subject_sha256": plan["plan_sha256"], "artifact_sha256": artifact_digest(plan),
                           "evidence_refs": ["test:upstream-tests;synthetic-guard"]}}


@unittest.skipUnless(os.environ.get("URIPROCESS_SOURCE"), "Set URIPROCESS_SOURCE for pinned runtime integration")
class UripackIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name) / "work"
        self.config = json.loads((ROOT / "selections/runtime-v1.json").read_text())
        self.plan = prepare(self.config, Path(os.environ["URIPROCESS_SOURCE"]), self.workspace)

    def test_real_extraction_preserves_packages_and_executable_modes(self):
        from uripack_refactor.common import UripackError
        from uripack_refactor.executor import apply_plan, verify_artifact
        from uripack_refactor.planner import build_plan
        self.assertEqual(self.plan, build_plan(self.plan["request"], self.plan["source_root"], self.plan["target_root"]))
        guard = TestGuard()
        result = apply_plan(self.plan, guard)
        self.assertEqual(result["status"], "EXTRACTED")
        self.assertFalse(result["production_cutover"])
        self.assertEqual(guard.actions, ["admit", "tool", "publish", "complete"])
        self.assertEqual(verify_artifact(self.plan)["status"], "passed")
        for process in json.loads((ROOT / "catalog.json").read_text())["processes"]:
            original = ROOT / process["path"]
            extracted = self.workspace / "extracted/packs" / "-".join(Path(process["path"]).parts) / "tree" / process["path"]
            for name in process["files"]:
                self.assertEqual((original / name).read_bytes(), (extracted / name).read_bytes())
            self.assertTrue(os.access(extracted / "bin.mjs", os.X_OK))
        self.assertTrue(apply_plan(self.plan, guard)["already_materialized"])
        self.assertEqual(len(guard.actions), 4)
        victim = next((self.workspace / "extracted").glob("packs/*/tree/poa/*/*/*/bin.mjs"))
        victim.write_text("tampered")
        with self.assertRaises(UripackError):
            verify_artifact(self.plan)

    def test_upstream_check_rejects_self_consistent_forged_provenance(self):
        import hashlib
        candidate = self.workspace / "candidate"
        catalog = json.loads((candidate / "catalog.json").read_text())
        process = catalog["processes"][0]
        base = candidate / process["path"]
        provenance = json.loads((base / "provenance.json").read_text())
        record = next(item for item in provenance["files"] if item["destination"].endswith(".mjs"))
        victim = base / record["destination"]
        victim.write_bytes(victim.read_bytes() + b"\n// changed source\n")
        record["sha256"] = hashlib.sha256(victim.read_bytes()).hexdigest()
        process["files"][record["destination"]] = record["sha256"]
        (base / "provenance.json").write_text(json.dumps(provenance))
        process["files"]["provenance.json"] = hashlib.sha256((base / "provenance.json").read_bytes()).hexdigest()
        (candidate / "catalog.json").write_text(json.dumps(catalog))
        result = subprocess.run([sys.executable, str(ROOT / "tools/check.py"), "--root", str(candidate),
                                 "--source", os.environ["URIPROCESS_SOURCE"]], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Package differs from pinned upstream Git object", result.stderr)

    def test_denied_admission_leaves_no_target(self):
        from uripack_refactor.common import UripackError
        from uripack_refactor.executor import apply_plan
        with self.assertRaises(UripackError):
            apply_plan(self.plan, TestGuard(deny=True))
        self.assertFalse((self.workspace / "extracted").exists())

    def test_source_drift_rejected(self):
        from uripack_refactor.common import UripackError
        from uripack_refactor.executor import apply_plan
        source = next((self.workspace / "candidate").glob("poa/*/*/*/bin.mjs"))
        source.write_text("changed after planning")
        with self.assertRaises(UripackError):
            apply_plan(self.plan, TestGuard())
        self.assertFalse((self.workspace / "extracted").exists())

    def test_existing_workspace_preserved(self):
        with self.assertRaises(FileExistsError):
            prepare(self.config, Path(os.environ["URIPROCESS_SOURCE"]), self.workspace)
        self.assertEqual(json.loads((self.workspace / "plan.json").read_text()), self.plan)


if __name__ == "__main__":
    unittest.main()
