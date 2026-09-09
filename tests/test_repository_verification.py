"""Reject self-consistent local forgeries using independently pinned Git inputs."""
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
from generate import encode
from prepare_repositories import prepare_repositories
from verify_repositories import main, verify_repositories
from test_uripack import TestGuard


@unittest.skipUnless(os.environ.get("URIPROCESS_SOURCE") and os.environ.get("URIPROCESS_CONNECTORS_SOURCE"),
                     "Set both explicit source repositories for repository verification")
class RepositoryVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "batch"
        self.config = json.loads((ROOT / "selections/repositories-v1.json").read_text())
        self.sources = {"runtime": Path(os.environ["URIPROCESS_SOURCE"]),
                        "connectors": Path(os.environ["URIPROCESS_CONNECTORS_SOURCE"])}
        self.index = prepare_repositories(self.config, ROOT, self.sources, self.workspace)

    def verify(self, **kwargs):
        return verify_repositories(self.config, ROOT, self.sources, self.workspace, **kwargs)

    def plans(self):
        return [json.loads((self.workspace / record["plan_path"]).read_text())
                for record in self.index["repositories"]]

    def test_complete_plan_batch_is_checked_without_writes_or_authority(self):
        def snapshot():
            return {str(p.relative_to(self.workspace)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode)
                    for p in self.workspace.rglob("*") if p.is_file()}
        before = snapshot()
        result = self.verify()
        self.assertEqual(before, snapshot())
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["repositories"]), 8)
        self.assertEqual(result["public_uri_count"], 21)
        for flag in ("artifacts_checked", "guard_receipts_authenticated", "execution_authority",
                     "behavioral_equivalence_claimed", "remote_publication", "production_cutover"):
            self.assertIs(result[flag], False)
        self.assertEqual(result["artifacts"], [])

    def test_complete_extracted_batch_checks_all_files_and_rejects_tampering(self):
        from uripack_refactor.common import UripackError
        from uripack_refactor.executor import apply_plan
        plans = self.plans()
        for plan in plans:
            apply_plan(plan, TestGuard())
        result = self.verify(extracted=True)
        self.assertTrue(result["artifacts_checked"])
        self.assertEqual(len(result["artifacts"]), 8)
        self.assertFalse(result["guard_receipts_authenticated"])
        self.assertFalse(result["execution_authority"])
        target = Path(plans[-1]["target_root"]) / plans[-1]["operations"][0]["target"]
        target.write_bytes(target.read_bytes() + b"\nchanged")
        with self.assertRaises(UripackError):
            self.verify(extracted=True)

    def test_partial_extraction_cannot_report_complete_migration(self):
        from uripack_refactor.executor import apply_plan
        apply_plan(self.plans()[0], TestGuard())
        with self.assertRaisesRegex(ValueError, "Complete extraction"):
            self.verify(extracted=True)
        self.assertFalse(self.verify()["artifacts_checked"])

    def test_self_consistent_forged_source_plan_and_index_are_rejected(self):
        from uripack_refactor.planner import artifact_digest, build_plan, validate_plan
        record = self.index["repositories"][0]
        plan = self.plans()[0]
        candidate = Path(plan["source_root"])
        package = candidate / record["package_path"]
        victim = package / "src/ticket-currency.mjs"
        victim.write_bytes(victim.read_bytes() + b"\n// self-consistent local forgery\n")
        provenance = json.loads((package / "provenance.json").read_text())
        for item in provenance["files"]:
            if item["destination"] == "src/ticket-currency.mjs":
                item["sha256"] = hashlib.sha256(victim.read_bytes()).hexdigest()
        (package / "provenance.json").write_bytes(encode(provenance))
        forged = build_plan(plan["request"], candidate, plan["target_root"])
        validate_plan(forged)  # Consistent local hashes alone really do pass.
        (self.workspace / record["plan_path"]).write_bytes(encode(forged))
        record["plan_sha256"], record["artifact_sha256"] = forged["plan_sha256"], artifact_digest(forged)
        (self.workspace / "repository-plans.json").write_bytes(encode(self.index))
        with self.assertRaisesRegex(ValueError, "pinned upstream reconstruction"):
            self.verify()

    def test_target_rebinding_is_rejected_even_with_a_recomputed_plan(self):
        from uripack_refactor.planner import artifact_digest, build_plan
        record = self.index["repositories"][0]
        plan = self.plans()[0]
        binding = Path(plan["source_root"]) / "repository-targets/ticket-currency.json"
        value = json.loads(binding.read_text())
        value["repository"] = "uriprocess/substituted"
        binding.write_bytes(encode(value))
        forged = build_plan(plan["request"], plan["source_root"], plan["target_root"])
        (self.workspace / record["plan_path"]).write_bytes(encode(forged))
        record.update(repository=value["repository"], plan_sha256=forged["plan_sha256"],
                      artifact_sha256=artifact_digest(forged))
        (self.workspace / "repository-plans.json").write_bytes(encode(self.index))
        with self.assertRaisesRegex(ValueError, "pinned upstream reconstruction"):
            self.verify()

    def test_index_omissions_paths_uri_owners_and_authority_flags_are_rejected(self):
        for change in ("missing", "path", "uri", "authority", "boolean-type"):
            index = copy.deepcopy(self.index)
            if change == "missing":
                index["repositories"].pop()
            elif change == "path":
                index["repositories"][0]["plan_path"] = "../../outside.json"
            elif change == "uri":
                index["uri_owners"][next(iter(index["uri_owners"]))] = "uriprocess/substituted"
            elif change == "authority":
                index["execution_authority"] = True
            else:
                index["execution_authority"] = 0  # Python equality must not treat 0 as False.
            (self.workspace / "repository-plans.json").write_bytes(encode(index))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "index differs"):
                self.verify()

    def test_missing_extra_or_symlinked_plan_is_rejected(self):
        from uripack_refactor.common import UripackError
        plan = self.workspace / self.index["repositories"][0]["plan_path"]
        data = plan.read_bytes()
        plan.unlink()
        with self.assertRaisesRegex(ValueError, "plan files"):
            self.verify()
        plan.write_bytes(data)
        extra = plan.parent / "extra.json"
        extra.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "plan files"):
            self.verify()
        extra.unlink()
        external = self.root / "external.json"
        external.write_bytes(data)
        plan.unlink()
        plan.symlink_to(external)
        with self.assertRaises(UripackError):
            self.verify()

    def test_local_selection_cannot_replace_explicit_expected_mapping(self):
        value = copy.deepcopy(self.config)
        value["groups"][0]["repositories"]["poa/ticket-currency/subactor.com/v1"] = "uriprocess/changed"
        (self.workspace / "repository-selection.json").write_bytes(encode(value))
        with self.assertRaisesRegex(ValueError, "explicitly expected selection"):
            self.verify()

    def test_cli_preserves_occupied_receipts_and_emits_none_for_failed_extraction(self):
        output = self.root / "verification.json"
        args = ["--selection", str(ROOT / "selections/repositories-v1.json"), "--package-source", str(ROOT),
                "--workspace", str(self.workspace), "--out", str(output)]
        for key, source in self.sources.items():
            args.extend(["--source", f"{key}={source}"])
        with self.assertRaisesRegex(ValueError, "Complete extraction"):
            main([*args, "--extracted"])
        self.assertFalse(output.exists())
        self.assertEqual(main(args), 0)
        before = output.read_bytes()
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, "must be new"):
            main(args)
        self.assertEqual(output.read_bytes(), before)
        args[args.index("--out") + 1] = str(self.workspace / "forbidden-receipt.json")
        with self.assertRaisesRegex(ValueError, "outside"):
            main(args)
        self.assertFalse((self.workspace / "forbidden-receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
