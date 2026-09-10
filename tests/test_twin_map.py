"""Incremental source revisions, signed twin conformance and real extraction."""
import copy
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
from generate_native_catalog import generate_catalog, selected_groups
from prepare_uripack import prepare


def selection():
    return json.loads((ROOT / "selections/twin-map-v1.json").read_text())


def batch():
    return json.loads((ROOT / "selections/native-v2.json").read_text())


class IncrementalSelectionTests(unittest.TestCase):
    def test_another_revision_preserves_old_groups_but_duplicate_pin_is_rejected(self):
        config = batch()
        sources = dict.fromkeys(("connectors", "platform", "twin"), ROOT)
        self.assertEqual(len(selected_groups(config, ROOT, sources)), 3)
        self.assertEqual(config["groups"][:2], json.loads((ROOT / "selections/native-v1.json").read_text())["groups"])
        config["groups"][2] = {**copy.deepcopy(config["groups"][0]), "source_id": "twin"}
        with self.assertRaisesRegex(ValueError, "Duplicate native source"):
            selected_groups(config, ROOT, sources)

    def test_version_one_still_rejects_repeated_repository_and_missing_mapping_fails(self):
        config = batch()
        config["version"] = 1
        with self.assertRaisesRegex(ValueError, "Duplicate native source"):
            selected_groups(config, ROOT, dict.fromkeys(("connectors", "platform", "twin"), ROOT))
        with self.assertRaisesRegex(ValueError, "mapping"):
            selected_groups(batch(), ROOT, {"connectors": ROOT, "platform": ROOT})


@unittest.skipUnless(all(os.environ.get("URIPROCESS_" + name + "_SOURCE")
                        for name in ("CONNECTORS", "PLATFORM", "TWIN")),
                     "Explicit pinned source inputs are required")
class TwinMapExtractionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = {name: Path(os.environ["URIPROCESS_" + name.upper() + "_SOURCE"])
                        for name in ("connectors", "platform", "twin")}

    def test_nine_package_catalog_reproduces_exact_files_and_original_pins(self):
        candidate = self.root / "candidate"
        generate_catalog(batch(), ROOT, self.sources, candidate)
        packages = json.loads((candidate / "native-catalog.json").read_text())["packages"]
        self.assertEqual(len(packages), 9)
        self.assertEqual(sum(len(p["public_uris"]) for p in packages), 29)
        for package in packages:
            for name in package["files"]:
                self.assertEqual((candidate / package["path"] / name).read_bytes(),
                                 (ROOT / package["path"] / name).read_bytes())

    def test_real_uripack_extracts_all_six_uris_and_complete_original_tests(self):
        from test_uripack import TestGuard
        from uripack_refactor.executor import apply_plan, verify_artifact
        plan = prepare(selection(), self.sources["twin"], self.root / "pack")
        self.assertEqual(len(plan["request"]["units"]), 1)
        self.assertEqual(len(plan["request"]["units"][0]["public_uris"]), 6)
        self.assertEqual(apply_plan(plan, TestGuard())["status"], "EXTRACTED")
        self.assertEqual(verify_artifact(plan)["status"], "passed")
        package = json.loads((self.root / "pack/candidate/native-catalog.json").read_text())["packages"][0]
        base = self.root / "pack/extracted/packs" / "-".join(Path(package["path"]).parts) / "tree" / package["path"]
        provenance = json.loads((base / "provenance.json").read_text())
        self.assertIn("tests/conftest.py", package["files"])
        self.assertIn("tests/fixtures/pins.json", package["files"])
        for item in provenance["files"]:
            self.assertEqual((base / item["destination"]).read_bytes(),
                             read_object(self.sources["twin"], selection()["source_revision"], item["source"]))

    def test_revision_specific_source_runs_all_39_cases_against_source_and_wheel(self):
        from check_native import check
        candidate = self.root / "candidate"
        selected = selection()
        generate_native(selected, self.sources["twin"], candidate)
        key = selected["source_repository"] + "@" + selected["source_revision"]
        # Deliberately unusable fallback proves the exact revision mapping wins.
        result = check(candidate, {key: self.sources["twin"], selected["source_repository"]: self.root / "absent"},
                       self.root / "wheel", sys.executable)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["packages"]), 1)
        package = result["packages"][0]
        self.assertEqual(package["upstream_test_count"], 39)
        self.assertEqual(package["test_identity_comparison"], "passed")
        self.assertEqual(package["installed_bindings"], "passed")
        self.assertEqual(len(package["public_uris"]), 6)
        self.assertFalse(result["production_cutover"])

    def test_wrong_revision_mapping_cannot_publish_a_success_receipt(self):
        from check_native import check
        candidate = self.root / "candidate"
        selected = selection()
        generate_native(selected, self.sources["twin"], candidate)
        with self.assertRaisesRegex(ValueError, "mapping is incomplete"):
            check(candidate, {selected["source_repository"] + "@" + "0" * 40: self.sources["twin"]},
                  self.root / "wrong", sys.executable)
        self.assertFalse((self.root / "wrong/verification.json").exists())
