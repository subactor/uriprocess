"""Repository split integration uses the real URIpack compiler and test Guard."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from generate import read_object
from prepare_repositories import prepare_repositories, selection_groups
from test_uripack import TestGuard


def config():
    return json.loads((ROOT / "selections/repositories-v1.json").read_text())


class RepositorySelectionTests(unittest.TestCase):
    def test_rejects_mutable_pins_unknown_fields_and_unsafe_destinations(self):
        for change in ("pin", "unknown", "path", "owner", "case", "duplicate", "source"):
            selection = config()
            group = selection["groups"][0]
            package = next(iter(group["repositories"]))
            if change == "pin":
                selection["package_revision"] = "main"
            elif change == "unknown":
                selection["approved"] = True
            elif change == "path":
                group["selection"] = "../selection.json"
            elif change == "source":
                selection["groups"][1]["source_id"] = group["source_id"]
            else:
                group["repositories"][package] = {
                    "owner": "subactor/ticket-currency", "case": "uriprocess/Ticket-Currency",
                    "duplicate": "uriprocess/ticket-readiness"}[change]
            with self.subTest(change=change), self.assertRaises(ValueError):
                selection_groups(selection)


@unittest.skipUnless(os.environ.get("URIPROCESS_SOURCE") and os.environ.get("URIPROCESS_CONNECTORS_SOURCE"),
                     "Set both explicit source repositories for repository-plan integration")
class RepositoryPlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "work"
        self.config = config()
        self.sources = {"runtime": Path(os.environ["URIPROCESS_SOURCE"]),
                        "connectors": Path(os.environ["URIPROCESS_CONNECTORS_SOURCE"])}

    def prepare(self):
        return prepare_repositories(self.config, ROOT, self.sources, self.workspace)

    def test_eight_independent_guarded_extractions_preserve_pinned_sources_and_uris(self):
        from uripack_refactor.executor import apply_plan, verify_artifact
        from uripack_refactor.planner import validate_plan

        index = self.prepare()
        self.assertEqual(len(index["repositories"]), 8)
        self.assertEqual(len(index["uri_owners"]), 21)
        self.assertFalse(index["execution_authority"])
        self.assertFalse(index["remote_publication"])
        self.assertEqual(list((self.workspace / "repositories").iterdir()), [])
        for record in index["repositories"]:
            with self.subTest(repository=record["repository"]):
                plan = json.loads((self.workspace / record["plan_path"]).read_text())
                validate_plan(plan)
                self.assertEqual(plan["plan_sha256"], record["plan_sha256"])
                self.assertEqual(len(plan["request"]["units"]), 1)
                self.assertEqual(plan["request"]["units"][0]["public_uris"], record["public_uris"])
                guard = TestGuard()
                self.assertEqual(apply_plan(plan, guard)["status"], "EXTRACTED")
                self.assertEqual(guard.actions, ["admit", "tool", "publish", "complete"])
                self.assertEqual(verify_artifact(plan)["status"], "passed")
                package = Path(plan["target_root"]) / record["package_root"]
                for path in package.rglob("*"):
                    if path.is_file():
                        self.assertEqual(path.read_bytes(), read_object(ROOT, self.config["package_revision"],
                            record["package_path"] + "/" + path.relative_to(package).as_posix()))
                provenance = json.loads((package / "provenance.json").read_text())
                source = self.sources["runtime" if "/runtime" in provenance["repository"] else "connectors"]
                for item in provenance["files"]:
                    self.assertEqual((package / item["destination"]).read_bytes(),
                                     read_object(source, provenance["revision"], item["source"]))
                if (package / "bin.mjs").exists():
                    self.assertTrue((package / "bin.mjs").stat().st_mode & 0o100)
                name = record["repository"].split("/")[1]
                binding = Path(plan["target_root"]) / f"packs/{name}/tree/repository-targets/{name}.json"
                self.assertEqual(json.loads(binding.read_text())["repository"], record["repository"])

    def test_destination_binding_drift_is_rejected_before_guard_or_materialization(self):
        from uripack_refactor.common import UripackError
        from uripack_refactor.executor import apply_plan

        index = self.prepare()
        record = index["repositories"][0]
        plan = json.loads((self.workspace / record["plan_path"]).read_text())
        name = record["repository"].split("/")[1]
        binding = Path(plan["source_root"]) / f"repository-targets/{name}.json"
        value = json.loads(binding.read_text())
        value["repository"] = "uriprocess/different-owner"
        binding.write_text(json.dumps(value))
        guard = TestGuard()
        with self.assertRaises(UripackError):
            apply_plan(plan, guard)
        self.assertFalse(Path(plan["target_root"]).exists())
        self.assertEqual(guard.actions, [])

    def test_denied_repository_does_not_materialize_or_admit_other_repositories(self):
        from uripack_refactor.common import UripackError
        from uripack_refactor.executor import apply_plan

        index = self.prepare()
        plan = json.loads((self.workspace / index["repositories"][0]["plan_path"]).read_text())
        guard = TestGuard(deny=True)
        with self.assertRaises(UripackError):
            apply_plan(plan, guard)
        self.assertEqual(guard.actions, ["admit"])
        self.assertEqual(list((self.workspace / "repositories").iterdir()), [])

    def test_missing_extra_and_overlapping_mapping_rejects_complete_batch(self):
        for change in ("missing", "extra", "uri-collision"):
            self.config = config()
            self.workspace = self.root / change
            group = self.config["groups"][0]
            if change == "missing":
                group["repositories"].pop(next(iter(group["repositories"])))
            elif change == "extra":
                group["repositories"]["poa/unknown/subactor.com/v1"] = "uriprocess/unknown"
            else:
                duplicate = copy.deepcopy(group)
                duplicate["source_id"] = "duplicate"
                duplicate["repositories"] = {p: r + "-duplicate" for p, r in group["repositories"].items()}
                self.config["groups"].append(duplicate)
                self.sources["duplicate"] = self.sources["runtime"]
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse((self.workspace / "repository-plans.json").exists())
            self.assertEqual(list((self.workspace / "repositories").iterdir()), [])

    def test_dirty_selection_checkout_is_not_executed(self):
        clone = self.root / "package-source"
        subprocess.run(["git", "clone", "--shared", "--no-checkout", str(ROOT), str(clone)],
                       check=True, capture_output=True)
        (clone / "selections").mkdir()
        for name in ("runtime-v1.json", "connectors-v3.json"):
            (clone / "selections" / name).write_text('{"source_revision":"main"}')
        index = prepare_repositories(self.config, clone, self.sources, self.workspace)
        self.assertEqual(len(index["repositories"]), 8)
        self.assertEqual({r["package_revision"] for r in index["repositories"]},
                         {self.config["package_revision"]})

    def test_occupied_workspace_and_symlink_parent_are_preserved(self):
        from uripack_refactor.common import UripackError

        self.workspace.mkdir()
        marker = self.workspace / "keep"
        marker.write_bytes(b"user work")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(marker.read_bytes(), b"user work")
        link = self.root / "link"
        link.symlink_to(self.workspace, target_is_directory=True)
        self.workspace = link / "new"
        with self.assertRaises(UripackError):
            self.prepare()
        self.assertFalse(self.workspace.exists())

    def test_requires_exact_explicit_sources_and_disjoint_workspace(self):
        original = self.sources.copy()
        for sources in ({"runtime": original["runtime"]}, {**original, "extra": ROOT}):
            self.sources = sources
            with self.assertRaisesRegex(ValueError, "exactly"):
                self.prepare()
            self.assertFalse(self.workspace.exists())
        self.sources = original
        self.workspace = original["runtime"] / "forbidden-repository-plan"
        with self.assertRaisesRegex(ValueError, "disjoint"):
            self.prepare()
        self.assertFalse(self.workspace.exists())


if __name__ == "__main__":
    unittest.main()
