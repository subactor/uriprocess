"""Exercise actual Platform source, mixed catalogs and installed native wheels."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from generate import encode, read_object
from generate_native_catalog import generate_catalog, selected_groups, source_mapping
from prepare_uripack import prepare


def config():
    return json.loads((ROOT / "selections/native-v1.json").read_text())


class NativeCatalogSelectionTests(unittest.TestCase):
    def test_mapping_requires_exact_group_coverage_and_unique_cli_names(self):
        for sources in ({}, {"connectors": ROOT}, {"connectors": ROOT, "platform": ROOT, "extra": ROOT}):
            with self.subTest(sources=sources), self.assertRaisesRegex(ValueError, "mapping"):
                selected_groups(config(), ROOT, sources)
        for values in (["connectors"], ["=path"], ["connectors="], ["connectors=a", "connectors=b"]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                source_mapping(values)

    def test_selection_drift_unsafe_paths_and_duplicate_groups_are_rejected(self):
        for change in ("digest", "path", "duplicate", "unknown", "version"):
            selection = config()
            if change == "digest":
                selection["groups"][0]["selection_sha256"] = "0" * 64
            elif change == "path":
                selection["groups"][0]["selection"] = "../outside.json"
            elif change == "duplicate":
                selection["groups"].append(copy.deepcopy(selection["groups"][0]))
            elif change == "unknown":
                selection["approved"] = True
            else:
                selection["version"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                selected_groups(selection, ROOT, {"connectors": ROOT, "platform": ROOT})


@unittest.skipUnless(os.environ.get("URIPROCESS_CONNECTORS_SOURCE") and os.environ.get("URIPROCESS_PLATFORM_SOURCE"),
                     "Set both explicit repositories for native catalog integration")
class NativeCatalogTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = {name: Path(os.environ[variable]) for name, variable in (
            ("connectors", "URIPROCESS_CONNECTORS_SOURCE"), ("platform", "URIPROCESS_PLATFORM_SOURCE"))}

    def test_batch_reproduces_all_packages_and_the_tracked_catalog(self):
        candidate = self.root / "candidate"
        generate_catalog(config(), ROOT, self.sources, candidate)
        self.assertEqual((candidate / "native-catalog.json").read_bytes(), (ROOT / "native-catalog.json").read_bytes())
        packages = json.loads((candidate / "native-catalog.json").read_text())["packages"]
        self.assertEqual(len(packages), 8)
        self.assertEqual(sum(len(p["public_uris"]) for p in packages), 23)
        for package in packages:
            for name in package["files"]:
                self.assertEqual((candidate / package["path"] / name).read_bytes(),
                                 (ROOT / package["path"] / name).read_bytes())

    def test_real_uripack_plan_and_extraction_preserve_platform_contracts(self):
        from test_uripack import TestGuard
        from uripack_refactor.executor import apply_plan, verify_artifact
        selection = json.loads((ROOT / "selections/platform-v1.json").read_text())
        plan = prepare(selection, self.sources["platform"], self.root / "platform")
        self.assertEqual(len(plan["request"]["units"]), 2)
        self.assertEqual(sum(len(p["public_uris"]) for p in plan["request"]["units"]), 4)
        guard = TestGuard()
        self.assertEqual(apply_plan(plan, guard)["status"], "EXTRACTED")
        self.assertEqual(guard.actions, ["admit", "tool", "publish", "complete"])
        self.assertEqual(verify_artifact(plan)["status"], "passed")
        packages = json.loads((self.root / "platform/candidate/native-catalog.json").read_text())["packages"]
        for package in packages:
            base = self.root / "platform/extracted/packs" / "-".join(Path(package["path"]).parts) / "tree" / package["path"]
            provenance = json.loads((base / "provenance.json").read_text())
            for item in provenance["files"]:
                self.assertEqual((base / item["destination"]).read_bytes(),
                                 read_object(self.sources["platform"], selection["source_revision"], item["source"]))

    def test_batch_uri_plan_requires_explicit_selection_root_and_disjoint_sources(self):
        with self.assertRaisesRegex(ValueError, "selection root"):
            prepare(config(), self.sources, self.root / "missing")
        with self.assertRaisesRegex(ValueError, "disjoint"):
            prepare(config(), self.sources, self.sources["platform"] / "candidate", selection_root=ROOT)
        plan = prepare(config(), self.sources, self.root / "batch", selection_root=ROOT)
        self.assertEqual(len(plan["request"]["units"]), 8)
        self.assertEqual(sum(len(p["public_uris"]) for p in plan["request"]["units"]), 23)
        self.assertFalse(Path(plan["target_root"]).exists())

    def test_collision_across_source_groups_never_publishes_partial_output(self):
        selection_root = self.root / "selection"
        shutil.copytree(ROOT / "selections", selection_root / "selections")
        other = json.loads((selection_root / "selections/connectors-v3.json").read_text())
        other["source_repository"] = "https://github.com/subactor/other"
        path = selection_root / "selections/platform-v1.json"
        path.write_bytes(encode(other))
        batch = config()
        batch["groups"][1]["selection_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        output = self.root / "collision"
        with self.assertRaisesRegex(ValueError, "collision"):
            generate_catalog(batch, selection_root, dict.fromkeys(self.sources, self.sources["connectors"]), output)
        self.assertFalse(output.exists())

    def test_all_native_wheels_preserve_upstream_cases_and_real_installed_bindings(self):
        from check_native import check
        sources = {"https://github.com/subactor/" + key: value for key, value in self.sources.items()}
        result = check(ROOT, sources, self.root / "wheels", sys.executable)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["packages"]), 8)
        self.assertFalse(result["production_calls"])
        self.assertFalse(result["production_cutover"])
        self.assertEqual({p["source_repository"] for p in result["packages"]}, set(sources))
        for package in result["packages"]:
            self.assertGreater(package["upstream_test_count"], 0)
            self.assertEqual(package["test_identity_comparison"], "passed")
            self.assertEqual(package["installed_bindings"], "passed")

    def test_missing_explicit_repository_cannot_produce_verification_success(self):
        from check_native import check
        platform = self.root / "platform"
        selection = json.loads((ROOT / "selections/platform-v1.json").read_text())
        from generate_native import generate_native
        generate_native(selection, self.sources["platform"], platform)
        output = self.root / "missing-repository"
        with self.assertRaisesRegex(ValueError, "mapping is incomplete"):
            check(platform, {"https://github.com/subactor/connectors": self.sources["connectors"]}, output, sys.executable)
        self.assertFalse((output / "verification.json").exists())
