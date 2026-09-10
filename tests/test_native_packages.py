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


class NativeTestEvidenceTests(unittest.TestCase):
    def test_equal_counts_cannot_hide_replaced_parameter_or_module(self):
        from check_native import matching_test_cases
        with tempfile.TemporaryDirectory() as temporary:
            source, installed = (Path(temporary) / name for name in ("source.xml", "installed.xml"))
            source.write_text("<testsuite><testcase classname='tests.ticket' name='test_route[allowed]'/></testsuite>")
            for module, name in (("tests.ticket", "test_route[denied]"), ("tests.other", "test_route[allowed]")):
                installed.write_text(f"<testsuite><testcase classname='{module}' name='{name}'/></testsuite>")
                with self.subTest(module=module, name=name), self.assertRaisesRegex(ValueError, "identities"):
                    matching_test_cases(source, installed)

    def test_identity_comparison_ignores_order_but_preserves_multiplicity(self):
        from check_native import matching_test_cases
        with tempfile.TemporaryDirectory() as temporary:
            source, installed = (Path(temporary) / name for name in ("source.xml", "installed.xml"))
            def report(names):
                return "<testsuite>" + "".join(f"<testcase name='{name}'/>" for name in names) + "</testsuite>"
            source.write_text(report(["a", "a", "b"]))
            installed.write_text(report(["b", "a", "a"]))
            self.assertEqual(matching_test_cases(source, installed), 3)
            installed.write_text(report(["a", "b", "b"]))
            with self.assertRaisesRegex(ValueError, "identities"):
                matching_test_cases(source, installed)

    def test_group_writable_checkout_preserves_git_mode_but_execution_changes_it(self):
        from check_native import git_file_mode
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "module.py"
            path.write_text("source")
            for mode in (0o644, 0o664, 0o600):
                path.chmod(mode)
                self.assertEqual(git_file_mode(path), 0o644)
            for mode in (0o755, 0o775, 0o700):
                path.chmod(mode)
                self.assertEqual(git_file_mode(path), 0o755)

    def test_missing_or_skipped_tests_cannot_report_complete_verification(self):
        from check_native import complete_test_count
        reports = ["<testsuite tests='100' failures='0'/>", "<testsuite><testcase><skipped/></testcase></testsuite>",
                   "<testsuite><testcase><failure/></testcase></testsuite>",
                   "<testsuite><testcase><error/></testcase></testsuite>",
                   "<testsuite><testcase/></testsuite>", "<invalid"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.xml"
            for report in reports:
                path.write_text(report)
                with self.subTest(report=report), self.assertRaises(ValueError):
                    complete_test_count(path)

    def test_complete_report_counts_observed_cases(self):
        from check_native import complete_test_count
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.xml"
            path.write_text("<testsuites><testsuite><testcase name='a'/><testcase name='b'/></testsuite></testsuites>")
            self.assertEqual(complete_test_count(path), 2)


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

    def test_historical_v2_selection_preserves_hub_and_existing_packages(self):
        from uripack_refactor.executor import apply_plan, verify_artifact
        config = json.loads((ROOT / "selections/connectors-v2.json").read_text())
        plan = prepare(config, self.source, self.root / "extended")
        candidate = self.root / "extended/candidate"
        packages = json.loads((candidate / "native-catalog.json").read_text())["packages"]
        self.assertEqual(len(packages), 3)
        self.assertEqual(sum(len(p["public_uris"]) for p in packages), 15)
        result = apply_plan(plan, TestGuard())
        self.assertEqual(result["status"], "EXTRACTED")
        self.assertEqual(verify_artifact(plan)["status"], "passed")
        for package in packages:
            extracted = self.root / "extended/extracted/packs" / "-".join(Path(package["path"]).parts) / "tree" / package["path"]
            for name in package["files"]:
                self.assertEqual((extracted / name).read_bytes(), (ROOT / package["path"] / name).read_bytes())

    def test_historical_v3_selection_extracts_unchanged_control_connectors(self):
        from uripack_refactor.executor import apply_plan, verify_artifact
        config = json.loads((ROOT / "selections/connectors-v3.json").read_text())
        plan = prepare(config, self.source, self.root / "current")
        candidate = self.root / "current/candidate"
        packages = json.loads((candidate / "native-catalog.json").read_text())["packages"]
        current = {p["path"]: p for p in json.loads((ROOT / "native-catalog.json").read_text())["packages"]}
        for package in packages:
            if package["id"] == "subactor-account-twin":
                self.assertEqual(package["path"], "native/subactor-account-twin/v0.1.0")
                self.assertNotIn(package["path"], current)
            else:
                self.assertEqual(package, current[package["path"]])
        self.assertEqual(len(packages), 6)
        self.assertEqual(sum(len(p["public_uris"]) for p in packages), 19)
        result = apply_plan(plan, TestGuard())
        self.assertEqual(result["status"], "EXTRACTED")
        self.assertEqual(verify_artifact(plan)["status"], "passed")
        for package in packages:
            extracted = self.root / "current/extracted/packs" / "-".join(Path(package["path"]).parts) / "tree" / package["path"]
            for name in package["files"]:
                self.assertEqual((extracted / name).read_bytes(), (ROOT / package["path"] / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
