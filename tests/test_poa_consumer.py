"""Pinned consumer exports must retain complete packages and reject drift."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from export_poa_consumer import check_projection, export_consumer, projected_files


class POAConsumerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.catalog = json.loads((ROOT / "catalog.json").read_text())
        shutil.copyfile(ROOT / "catalog.json", self.source / "catalog.json")
        for record in self.catalog["processes"]:
            shutil.copytree(ROOT / record["path"], self.source / record["path"])
        self.git("init", "-q")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Fixture")
        self.pin()
        self.uris = [r["process_ref"] for r in self.catalog["processes"]]

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.source), *args], stderr=subprocess.PIPE)

    def pin(self, refresh_catalog=False):
        if refresh_catalog:
            for record in self.catalog["processes"]:
                for name in record["files"]:
                    record["files"][name] = hashlib.sha256((self.source / record["path"] / name).read_bytes()).hexdigest()
            (self.source / "catalog.json").write_text(json.dumps(self.catalog))
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.revision = self.git("rev-parse", "HEAD").decode().strip()
        self.digest = hashlib.sha256((self.source / "catalog.json").read_bytes()).hexdigest()

    def files(self, **kwargs):
        return projected_files(self.source, kwargs.get("revision", self.revision),
                               kwargs.get("digest", self.digest), kwargs.get("uris", self.uris))

    def export(self, output=None):
        return export_consumer(self.source, self.revision, self.digest, self.uris,
                               output or self.root / "consumer")

    def test_complete_projection_ignores_dirty_source_and_preserves_modes(self):
        expected = self.files()
        first = self.catalog["processes"][0]
        (self.source / first["path"] / "bin.mjs").write_text("uncommitted code must not run")
        (self.source / first["path"] / "untracked.mjs").write_text("untracked")
        lock = self.export()
        check_projection(self.root / "consumer", expected)
        self.assertEqual(len(lock["packages"]), 2)
        self.assertEqual(lock["source_revision"], self.revision)
        self.assertFalse(lock["execution_authority"])
        self.assertFalse(lock["production_binding_verified"])
        for record in lock["packages"]:
            self.assertEqual(record["modes"]["bin.mjs"], 0o755)
            self.assertEqual(set(record["modes"]), set(record["files"]))

    def test_selection_requires_distinct_existing_original_uris(self):
        one = self.files(uris=self.uris[:1])
        lock = json.loads(one["consumer-lock.json"][0])
        self.assertEqual([p["process_ref"] for p in lock["packages"]], self.uris[:1])
        for uris in ([], self.uris * 2, ["poa://subactor.com/process/missing/v1"]):
            with self.subTest(uris=uris), self.assertRaises(ValueError):
                self.files(uris=uris)

    def test_mutable_revision_and_wrong_catalog_digest_are_rejected(self):
        for revision in ("HEAD", "main", self.revision[:8]):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                self.files(revision=revision)
        with self.assertRaisesRegex(ValueError, "independent digest"):
            self.files(digest="0" * 64)

    def test_missing_or_unlisted_tracked_files_are_rejected(self):
        path = self.source / self.catalog["processes"][0]["path"] / "extra.mjs"
        path.write_text("extra")
        self.pin()
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.files()
        path.unlink()
        (self.source / self.catalog["processes"][0]["path"] / "bin.mjs").unlink()
        self.pin()
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.files()

    def test_changed_blob_and_symlink_are_rejected_before_export(self):
        path = self.source / self.catalog["processes"][0]["path"] / "bin.mjs"
        original = path.read_bytes()
        path.write_bytes(original + b"\n// changed\n")
        self.pin()
        with self.assertRaisesRegex(ValueError, "content differs"):
            self.export()
        self.assertFalse((self.root / "consumer").exists())
        path.unlink()
        path.symlink_to("/outside")
        self.pin()
        with self.assertRaisesRegex(ValueError, "Regular Git"):
            self.files()

    def test_self_consistent_catalog_cannot_change_contract_identity(self):
        path = self.source / self.catalog["processes"][0]["path"] / "process.poa.json"
        contract = json.loads(path.read_text())
        contract["process_ref"] = "poa://subactor.com/process/other/v1"
        path.write_text(json.dumps(contract))
        provenance_path = path.parent / "provenance.json"
        provenance = json.loads(provenance_path.read_text())
        for record in provenance["files"]:
            if record["destination"] == "process.poa.json":
                record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        provenance_path.write_text(json.dumps(provenance))
        self.pin(refresh_catalog=True)
        with self.assertRaisesRegex(ValueError, "URP-IDENTITY"):
            self.files()

    def test_existing_output_and_symlink_parent_are_preserved(self):
        self.export()
        with self.assertRaises(FileExistsError):
            self.export()
        outside = self.root / "outside"
        outside.mkdir()
        link = self.root / "link"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.export(link / "consumer")
        self.assertEqual(list(outside.iterdir()), [])

    def test_consumer_verification_rejects_bytes_modes_and_extra_files(self):
        self.export()
        expected = self.files()
        output = self.root / "consumer"
        path = output / self.catalog["processes"][0]["path"] / "bin.mjs"
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValueError, "bytes or Git mode"):
            check_projection(output, expected)
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "bytes or Git mode"):
            check_projection(output, expected)
        path.chmod(0o755)
        (output / "extra").touch()
        with self.assertRaisesRegex(ValueError, "inventory"):
            check_projection(output, expected)


if __name__ == "__main__":
    unittest.main()
