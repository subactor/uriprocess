"""Inspect real partial extractions without issuing or replaying Guard effects."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from inspect_repositories import inspect_repositories, main
from prepare_repositories import prepare_repositories
from test_uripack import TestGuard


@unittest.skipUnless(os.environ.get("URIPROCESS_SOURCE") and os.environ.get("URIPROCESS_CONNECTORS_SOURCE"),
                     "Set both explicit source repositories for repository inspection")
class RepositoryInspectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "batch"
        self.config = json.loads((ROOT / "selections/repositories-v1.json").read_text())
        self.sources = {"runtime": Path(os.environ["URIPROCESS_SOURCE"]),
                        "connectors": Path(os.environ["URIPROCESS_CONNECTORS_SOURCE"])}
        self.index = prepare_repositories(self.config, ROOT, self.sources, self.workspace)
        self.plans = [json.loads((self.workspace / record["plan_path"]).read_text())
                      for record in self.index["repositories"]]

    def inspect(self):
        with patch("uripack_refactor.guard.GuardBridge.call", side_effect=AssertionError("No Guard effects")), \
                patch("uripack_refactor.executor.apply_plan", side_effect=AssertionError("No replay")):
            return inspect_repositories(self.config, ROOT, self.sources, self.workspace)

    def extract(self, index=0, guard=None):
        from uripack_refactor.executor import apply_plan
        return apply_plan(self.plans[index], guard or TestGuard())

    def snapshot(self):
        result = {}
        for path in self.workspace.rglob("*"):
            mode = path.lstat().st_mode
            content = path.read_bytes() if stat.S_ISREG(mode) else os.readlink(path) if stat.S_ISLNK(mode) else None
            result[str(path.relative_to(self.workspace))] = (mode, content, path.lstat().st_mtime_ns)
        return result

    def rewrite_receipt(self, mutate):
        from uripack_refactor.common import digest, json_bytes
        path = Path(self.plans[0]["target_root"]) / ".uripack/receipt.json"
        receipt = json.loads(path.read_text())
        mutate(receipt)
        receipt["receipt_sha256"] = digest({k: v for k, v in receipt.items() if k != "receipt_sha256"})
        path.write_bytes(json_bytes(receipt))

    def test_prepared_batch_is_observed_without_writes_or_authority(self):
        before = self.snapshot()
        result = self.inspect()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(result["status"], "observed")
        self.assertEqual(len(result["repositories"]), 8)
        self.assertEqual(result["verification"]["public_uri_count"], 21)
        self.assertEqual({row["status"] for row in result["repositories"]}, {"not_materialized"})
        for flag in ("guard_receipts_authenticated", "execution_authority", "automatic_retry",
                     "remote_publication", "production_cutover", "observation_atomic"):
            self.assertIs(result[flag], False)

    def test_partial_and_complete_extraction_remain_local_observations(self):
        self.extract()
        partial = self.inspect()
        self.assertEqual([row["status"] for row in partial["repositories"]],
                         ["extracted_local"] + ["not_materialized"] * 7)
        for index in range(1, 8):
            self.extract(index)
        before = self.snapshot()
        result = self.inspect()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(result["status"], "observed")
        self.assertEqual({row["status"] for row in result["repositories"]}, {"extracted_local"})
        self.assertTrue(all(row["artifact_verification"]["status"] == "passed" for row in result["repositories"]))
        self.assertFalse(result["guard_receipts_authenticated"])

    def test_failed_completion_is_preserved_and_requires_independent_recovery(self):
        from uripack_refactor.common import UripackError, fail

        class IncompleteGuard(TestGuard):
            def call(self, action, plan, payload=None):
                if action == "complete":
                    fail("UPK-GUARD-001", "Completion outcome unavailable")
                return super().call(action, plan, payload)

        with self.assertRaises(UripackError):
            self.extract(guard=IncompleteGuard())
        before = self.snapshot()
        result = self.inspect()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(result["repositories"][0]["status"], "pending_completion")
        self.assertTrue(result["independent_recovery_required"])
        self.assertFalse(result["automatic_retry"])

    def test_invalid_artifact_does_not_hide_later_repository_observations(self):
        self.extract()
        self.extract(1)
        target = Path(self.plans[0]["target_root"]) / self.plans[0]["operations"][0]["target"]
        target.write_bytes(target.read_bytes() + b"\nchanged")
        result = self.inspect()
        self.assertEqual(result["status"], "requires_reconciliation")
        self.assertEqual(result["repositories"][0]["status"], "inconsistent")
        self.assertEqual(result["repositories"][1]["status"], "extracted_local")
        self.assertEqual(len(result["repositories"]), 8)

    def test_rehashed_wrong_plan_artifact_source_and_check_bindings_are_rejected(self):
        self.extract()
        path = Path(self.plans[0]["target_root"]) / ".uripack/receipt.json"
        original = path.read_bytes()
        changes = [lambda r, key=key: r.update({key: "0" * 64})
                   for key in ("plan_sha256", "artifact_sha256", "source_sha256")]
        changes += [lambda r: r["checks"][0].update(subject_sha256="0" * 64),
                    lambda r: r.update(events=[]), lambda r: r.update(checks=[]),
                    lambda r: r.update(source_files_copied=0)]
        for mutate in changes:
            with self.subTest(mutation=changes.index(mutate)):
                path.write_bytes(original)
                self.rewrite_receipt(mutate)
                row = self.inspect()["repositories"][0]
                self.assertEqual(row["code"], "BATCH_RECEIPT_INCONSISTENT")

    def test_malformed_missing_symlink_and_special_receipts_are_preserved(self):
        self.extract()
        path = Path(self.plans[0]["target_root"]) / ".uripack/receipt.json"
        for malformed in (b"[]", b'{"status": "EXTRACTED", "status": "EXTRACTED"}', b"{broken"):
            path.write_bytes(malformed)
            self.assertEqual(self.inspect()["repositories"][0]["status"], "inconsistent")
            self.assertEqual(path.read_bytes(), malformed)
        path.unlink()
        self.assertEqual(self.inspect()["repositories"][0]["status"], "inconsistent")
        secret = self.root / "private"
        secret.write_text("must not be read or emitted")
        path.symlink_to(secret)
        self.assertEqual(self.inspect()["repositories"][0]["status"], "inconsistent")
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(self.inspect()["repositories"][0]["status"], "inconsistent")
        self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))

    def test_foreign_writer_staging_and_unexpected_entries_are_not_cleaned(self):
        target = Path(self.plans[0]["target_root"])
        lock = target.with_name("." + target.name + ".uripack-writer.lock")
        lock.symlink_to(self.root / "absent-secret")
        stage = target.with_name("." + target.name + ".uripack-stage-test")
        stage.mkdir()
        (stage / "keep").write_text("unfinished")
        (target.parent / "unexpected").mkdir()
        before = self.snapshot()
        result = self.inspect()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(result["status"], "requires_reconciliation")
        self.assertTrue(result["repositories"][0]["writer_lock_present"])
        self.assertEqual(result["repositories"][0]["staging_entries"], 1)
        self.assertEqual(result["unexpected_entries"], 1)

    def test_concurrent_receipt_change_is_reported_without_retry(self):
        from uripack_refactor.executor import verify_artifact
        self.extract()

        def changing(plan):
            result = verify_artifact(plan)
            self.rewrite_receipt(lambda r: r.update(guard="changed-during-observation"))
            return result

        with patch("uripack_refactor.executor.verify_artifact", side_effect=changing):
            result = self.inspect()
        self.assertEqual(result["repositories"][0]["code"], "BATCH_OBSERVATION_CHANGED")
        self.assertTrue(result["independent_recovery_required"])

    def test_directory_change_during_observation_requires_reconciliation(self):
        from inspect_repositories import _target_observation
        self.extract()

        def changing(plan):
            result = _target_observation(plan)
            (self.workspace / "repositories/new-writer-state").mkdir()
            return result

        with patch("inspect_repositories._target_observation", side_effect=changing):
            result = self.inspect()
        self.assertTrue(result["directory_changed_during_observation"])
        self.assertEqual(result["status"], "requires_reconciliation")

    def test_pinned_plan_and_source_verification_precede_target_inspection(self):
        victim = Path(self.plans[0]["source_root"]) / self.plans[0]["operations"][0]["source"]
        victim.write_bytes(victim.read_bytes() + b"changed source")
        with patch("inspect_repositories._target_observation", side_effect=AssertionError("Preflight first")):
            from uripack_refactor.common import UripackError
            with self.assertRaises((UripackError, ValueError)):
                self.inspect()

    def test_cli_emits_complete_observation_and_nonzero_attention(self):
        args = ["--selection", str(ROOT / "selections/repositories-v1.json"), "--package-source", str(ROOT),
                "--workspace", str(self.workspace)]
        for name, path in self.sources.items():
            args.extend(["--source", f"{name}={path}"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(args), 0)
        self.assertEqual(len(json.loads(output.getvalue())["repositories"]), 8)
        (self.workspace / "repositories/unknown").mkdir()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(args), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "requires_reconciliation")
        (self.workspace / "repository-plans.json").write_text("{}")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(args), 2)
        blocked = json.loads(output.getvalue())
        self.assertEqual(blocked["code"], "BATCH_INSPECTION_PREFLIGHT_FAILED")
        for flag in ("execution_authority", "automatic_retry", "guard_receipts_authenticated",
                     "observation_atomic", "remote_publication", "production_cutover"):
            self.assertIs(blocked[flag], False)


if __name__ == "__main__":
    unittest.main()
