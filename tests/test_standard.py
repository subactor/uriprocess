"""Exercise the adopted standard on real packages and reject bundle drift."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_standard import BUNDLE_FILES, check_catalogs, load_standard, main


class StandardAdoptionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.adopter = self.root / "adopter"
        shutil.copytree(ROOT / ".governance", self.adopter / ".governance")
        self.bundle = self.adopter / ".governance/uriprocess"
        self.lock = self.adopter / ".governance/uriprocess.lock.json"

    def packages(self):
        target = self.root / "packages"
        target.mkdir()
        for name, field in (("catalog.json", "processes"), ("native-catalog.json", "packages")):
            shutil.copyfile(ROOT / name, target / name)
            for record in json.loads((ROOT / name).read_text())[field]:
                shutil.copytree(ROOT / record["path"], target / record["path"])
        return target

    def test_exact_bundle_checks_all_eleven_real_packages_and_thirty_one_uris(self):
        result = check_catalogs(ROOT)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["packages"]), 11)
        self.assertEqual(result["public_uri_count"], 31)
        self.assertEqual({p["profile"] for p in result["packages"]}, {"poa-node-v1", "python-native-v1"})
        self.assertEqual(result["standard_receipt"]["version"], "0.1.0")
        self.assertTrue(result["standard_receipt"]["bundle_verified"])
        self.assertFalse(result["standard_receipt"]["source_revision_authenticated"])
        self.assertFalse(result["execution_authority"])
        self.assertTrue(all(not p["upstream_git_verified"] and not p["behavior_verified"] for p in result["packages"]))

    def test_every_bundle_file_is_verified_before_loading_code(self):
        for name in sorted(BUNDLE_FILES):
            with self.subTest(file=name):
                path = self.bundle / name
                original = path.read_bytes()
                path.write_bytes(original + b"\nchanged")
                with patch("builtins.exec", side_effect=AssertionError("Unverified code must not load")):
                    with self.assertRaisesRegex(ValueError, "differs from the pinned bundle"):
                        with load_standard(self.adopter):
                            self.fail("Corrupt bundle accepted")
                path.write_bytes(original)

    def test_mutable_revision_and_replaced_bundle_digest_are_rejected(self):
        original = json.loads(self.lock.read_text())
        for key, value in (("source_revision", "main"), ("source_revision", "1234567"),
                           ("bundle_sha256", "0" * 64)):
            self.lock.write_text(json.dumps({**original, key: value}))
            with self.assertRaises(ValueError):
                with load_standard(self.adopter):
                    self.fail("Invalid pin accepted")

    def test_missing_symlink_and_special_bundle_files_are_not_consumed(self):
        path = self.bundle / "schemas/package.schema.json"
        path.unlink()
        with self.assertRaises(OSError):
            with load_standard(self.adopter):
                self.fail("Missing schema accepted")
        path.symlink_to(self.root / "outside")
        with self.assertRaises(OSError):
            with load_standard(self.adopter):
                self.fail("Symlink accepted")
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            with load_standard(self.adopter):
                self.fail("FIFO accepted")

    def test_self_consistent_bundle_with_unsafe_member_is_rejected(self):
        path = self.bundle / "bundle.json"
        bundle = json.loads(path.read_text())
        bundle["files"]["../../unexpected.py"] = "0" * 64
        raw = json.dumps(bundle).encode()
        path.write_bytes(raw)
        lock = json.loads(self.lock.read_text())
        lock["bundle_sha256"] = hashlib.sha256(raw).hexdigest()
        self.lock.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, "Incomplete or unsupported"):
            with load_standard(self.adopter):
                self.fail("Unselected member accepted")

    def test_verified_policy_is_frozen_before_projected_files_can_change(self):
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in self.bundle.rglob("*") if p.is_file()}
        with load_standard(self.adopter) as (standard, receipt):
            self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before})
            (self.bundle / "policy.json").write_text("{}")
            result = standard.check_package(ROOT / "poa/ticket-currency/subactor.com/v1")
            self.assertEqual(result["version"], receipt["version"])
            self.assertEqual(result["status"], "passed")

    def test_catalog_uri_drift_and_duplicate_ownership_are_rejected(self):
        root = self.packages()
        path = root / "catalog.json"
        original = json.loads(path.read_text())
        catalog = json.loads(path.read_text())
        catalog["processes"][0]["process_ref"] += "/different"
        path.write_text(json.dumps(catalog))
        with self.assertRaisesRegex(ValueError, "URI identities or ownership"):
            check_catalogs(root)
        original["processes"].append(original["processes"][0])
        path.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, "URI identities or ownership"):
            check_catalogs(root)

    def test_original_tests_cannot_be_removed_by_rehashing_local_metadata(self):
        root = self.packages()
        catalog_path = root / "catalog.json"
        catalog = json.loads(catalog_path.read_text())
        record = catalog["processes"][0]
        base = root / record["path"]
        provenance_path = base / "provenance.json"
        provenance = json.loads(provenance_path.read_text())
        for item in list(provenance["files"]):
            if item["destination"].startswith("tests/"):
                (base / item["destination"]).unlink()
                record["files"].pop(item["destination"])
                provenance["files"].remove(item)
        provenance_path.write_text(json.dumps(provenance))
        record["files"]["provenance.json"] = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
        catalog_path.write_text(json.dumps(catalog))
        with self.assertRaisesRegex(ValueError, "URP-TESTS-001"):
            check_catalogs(root)

    def test_cli_emits_bounded_failure_without_a_success_receipt(self):
        empty = self.root / "empty"
        empty.mkdir()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--root", str(empty)]), 2)
        self.assertEqual(json.loads(output.getvalue()), {"status": "invalid", "code": "URIPROCESS_STANDARD_REJECTED",
                                                         "execution_authority": False})


if __name__ == "__main__":
    unittest.main()
