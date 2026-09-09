import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from generate import read_object
from generate_native import generate_native
from prepare_uripack import prepare
from test_uripack import TestGuard


@unittest.skipUnless(os.environ.get("URIPROCESS_CONNECTORS_SOURCE"), "Set URIPROCESS_CONNECTORS_SOURCE for native-package integration")
class NativePackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = Path(os.environ["URIPROCESS_CONNECTORS_SOURCE"])
        self.config = json.loads((ROOT / "selections/connectors-v1.json").read_text())

    def test_projection_preserves_native_metadata_source_tests_and_routes(self):
        output = self.root / "candidate"
        generate_native(self.config, self.source, output)
        catalog = json.loads((output / "native-catalog.json").read_text())
        self.assertEqual(len(catalog["packages"]), 2)
        self.assertEqual(sum(len(p["public_uris"]) for p in catalog["packages"]), 11)
        for package in catalog["packages"]:
            base = output / package["path"]
            provenance = json.loads((base / "provenance.json").read_text())
            for item in provenance["files"]:
                self.assertEqual((base / item["destination"]).read_bytes(),
                                 read_object(self.source, self.config["source_revision"], item["source"]))
            self.assertFalse((base / "bin.mjs").exists())

    def test_rejects_widened_uris_missing_tests_and_duplicate_files(self):
        for change in ("uri", "tests", "duplicate", "outside"):
            config = copy.deepcopy(self.config)
            package = config["packages"][0]
            if change == "uri":
                package["public_uris"].append("planfile://subactor/tickets/command/delete")
            elif change == "tests":
                package["files"] = [p for p in package["files"] if "/tests/" not in p]
            elif change == "duplicate":
                package["files"].append(package["files"][0])
            else:
                package["files"].append("../outside")
            with self.subTest(change=change), self.assertRaises(ValueError):
                generate_native(config, self.source, self.root / "candidate")
            self.assertFalse((self.root / "candidate").exists())

    def test_uripack_roundtrip_runs_native_tests_and_preserves_all_files(self):
        from uripack_refactor.executor import apply_plan, verify_artifact
        plan = prepare(self.config, self.source, self.root / "work")
        guard = TestGuard()
        result = apply_plan(plan, guard)
        self.assertEqual(result["status"], "EXTRACTED")
        self.assertEqual(guard.actions, ["admit", "tool", "publish", "complete"])
        self.assertEqual(verify_artifact(plan)["status"], "passed")
        catalog = json.loads((self.root / "work/candidate/native-catalog.json").read_text())
        for package in catalog["packages"]:
            destination = self.root / "work/extracted/packs" / "-".join(Path(package["path"]).parts) / "tree" / package["path"]
            for name in package["files"]:
                self.assertEqual((destination / name).read_bytes(),
                                 (self.root / "work/candidate" / package["path"] / name).read_bytes())

    def test_checker_rejects_source_omitted_from_forged_provenance(self):
        from check_native import check
        candidate = self.root / "candidate"
        generate_native(self.config, self.source, candidate)
        catalog = json.loads((candidate / "native-catalog.json").read_text())
        package = catalog["packages"][0]
        base = candidate / package["path"]
        provenance = json.loads((base / "provenance.json").read_text())
        provenance["files"].pop()
        (base / "provenance.json").write_text(json.dumps(provenance))
        package["files"]["provenance.json"] = hashlib.sha256((base / "provenance.json").read_bytes()).hexdigest()
        (candidate / "native-catalog.json").write_text(json.dumps(catalog))
        with self.assertRaisesRegex(ValueError, "provenance is incomplete"):
            check(candidate, self.source, self.root / "verification", sys.executable)
        self.assertFalse((self.root / "verification/verification.json").exists())


if __name__ == "__main__":
    unittest.main()
