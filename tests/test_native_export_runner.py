import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_native_export as native


class NativeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "entry.py").write_text("original\n")
        (self.repo / "entry.py").chmod(0o755)
        (self.repo / "link").symlink_to("entry.py")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True)

    def test_snapshot_ignores_dirty_and_untracked_code_and_preserves_mode(self):
        (self.repo / "entry.py").write_text("changed\n")
        (self.repo / "foreign.py").write_text("untracked\n")
        output = self.root / "snapshot"
        native.snapshot(self.repo, self.revision, ["entry.py"], output)
        self.assertEqual((output / "entry.py").read_text(), "original\n")
        self.assertEqual((output / "entry.py").stat().st_mode & 0o777, 0o755)
        self.assertFalse((output / "foreign.py").exists())
        with self.assertRaises(ValueError):
            native.snapshot(self.repo, self.revision, ["entry.py"], output)
        self.assertEqual((output / "entry.py").read_text(), "original\n")

    def test_snapshot_rejects_mutable_pins_missing_paths_and_symlinks(self):
        for revision, paths in [("HEAD", ["entry.py"]), (self.revision, ["missing"]),
                                 (self.revision, ["entry.py", "link"])]:
            output = self.root / "snapshot"
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                native.snapshot(self.repo, revision, paths, output)
            self.assertFalse(output.exists())

    def test_download_verification_rejects_changed_bytes_even_with_success_report(self):
        path = "poa/example/subactor.com/v1"
        package = self.repo / path
        package.mkdir(parents=True)
        (package / "bin.mjs").write_text("original")
        catalog = {"processes": [{"path": path, "files": {"bin.mjs": "not-trusted"}}]}
        (self.repo / "catalog.json").write_text(json.dumps(catalog))
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "package")
        revision = self.git("rev-parse", "HEAD").strip()
        downloaded = self.root / "exports/example" / path
        downloaded.mkdir(parents=True)
        (downloaded / "bin.mjs").write_text("original")
        report = {"status": "passed", "source_revision": revision, "production_guard": False,
                  "production_cutover": False, "test_principals": True,
                  "results": [{"unit": "example", "status": "materialized", "docker": "passed",
                               "npm_install": "passed", "upstream_tests": "passed", "native_http": "passed"}]}
        with patch.object(native, "PACKAGE_REVISION", revision):
            native.verify_downloads(self.repo, self.root / "exports", report)
            (downloaded / "bin.mjs").write_text("changed")
            with self.assertRaisesRegex(ValueError, "differs from source Git"):
                native.verify_downloads(self.repo, self.root / "exports", report)
            report["production_guard"] = True
            with self.assertRaisesRegex(ValueError, "scope mismatch"):
                native.verify_downloads(self.repo, self.root / "exports", report)


if __name__ == "__main__":
    unittest.main()
