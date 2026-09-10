"""Reproduce serialized export failures and verify the revised native package."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_native import INSTALLED_BINDINGS_PROBE
from generate_native import generate_native
from generate_native_catalog import generate_catalog
from prepare_uripack import prepare


class InstalledExportTests(unittest.TestCase):
    def probe(self, *, export="handler", module="fixture_package"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed = root / "installed"
            installed.mkdir()
            distribution = installed / "fixture_package-1.0.dist-info"
            distribution.mkdir()
            (distribution / "METADATA").write_text("Name: fixture-package\nVersion: 1.0\n")
            (distribution / "entry_points.txt").write_text("[urirun.bindings]\nfixture = fixture_package:bindings\n")
            uri = "fixture://host/query/read"
            binding = {uri: {"python": {"module": module, "export": export}}}
            (installed / "fixture_package.py").write_text(
                "def handler(**payload):\n    return payload\nnot_callable = 1\n"
                f"def bindings():\n    return {{'bindings': {binding!r}}}\n")
            return subprocess.run(
                [sys.executable, "-B", "-c", INSTALLED_BINDINGS_PROBE, str(installed),
                 "fixture-package", json.dumps([uri])], cwd=root,
                env={**os.environ, "PYTHONPATH": str(installed)},
                text=True, capture_output=True, timeout=15,
            )

    def test_installed_callable_is_accepted_without_invoking_it(self):
        result = self.probe()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_registered_but_missing_or_noncallable_exports_are_rejected(self):
        for export, reason in (("query_resource", "AttributeError"),
                               ("not_callable", "not callable")):
            with self.subTest(export=export):
                result = self.probe(export=export)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stderr)

    def test_callable_outside_installed_tree_is_rejected(self):
        result = self.probe(module="json", export="loads")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Handler import leaked", result.stderr)


class AccountTwinExtractionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = Path(os.environ["URIPROCESS_ACCOUNT_SOURCE"])
        self.selection = json.loads((ROOT / "selections/account-twin-v1.json").read_text())

    def test_current_catalog_reproduces_every_active_package_from_exact_sources(self):
        batch = json.loads((ROOT / "selections/native-v3.json").read_text())
        sources = {name: Path(os.environ["URIPROCESS_" + name.upper() + "_SOURCE"])
                   for name in ("connectors", "platform", "twin", "account")}
        output = self.root / "catalog"
        generate_catalog(batch, ROOT, sources, output)
        self.assertEqual((output / "native-catalog.json").read_bytes(), (ROOT / "native-catalog.json").read_bytes())
        records = json.loads((output / "native-catalog.json").read_text())["packages"]
        self.assertEqual(len(records), 9)
        self.assertEqual(sum(len(record["public_uris"]) for record in records), 29)
        for record in records:
            for name in record["files"]:
                self.assertEqual((output / record["path"] / name).read_bytes(),
                                 (ROOT / record["path"] / name).read_bytes())

    def test_real_uripack_extracts_complete_corrected_package(self):
        from test_uripack import TestGuard
        from uripack_refactor.executor import apply_plan, verify_artifact
        plan = prepare(self.selection, self.source, self.root / "pack")
        self.assertEqual(len(plan["request"]["units"]), 1)
        self.assertEqual(len(plan["request"]["units"][0]["public_uris"]), 10)
        self.assertEqual(apply_plan(plan, TestGuard())["status"], "EXTRACTED")
        self.assertEqual(verify_artifact(plan)["status"], "passed")
        record, = json.loads((self.root / "pack/candidate/native-catalog.json").read_text())["packages"]
        exported = self.root / "pack/extracted/packs" / "-".join(Path(record["path"]).parts) / "tree" / record["path"]
        for name in record["files"]:
            self.assertEqual((exported / name).read_bytes(), (ROOT / record["path"] / name).read_bytes())

    def test_historical_broken_exports_cannot_receive_installed_success(self):
        from check_native import check
        historical = json.loads((ROOT / "selections/connectors-v3.json").read_text())
        historical["packages"] = [p for p in historical["packages"]
                                  if p["package_root"] == "urirun-connector-subactor-account-twin"]
        source = Path(os.environ["URIPROCESS_CONNECTORS_SOURCE"])
        candidate, result = self.root / "legacy", self.root / "verification"
        generate_native(historical, source, candidate)
        with self.assertRaises(subprocess.CalledProcessError):
            check(candidate, source, result, sys.executable)
        self.assertFalse((result / "verification.json").exists())
        log = (result / "verification.log").read_text()
        self.assertIn("AttributeError", log)
        self.assertIn("query_resource", log)
