"""Real URIpack extraction; synthetic authorization is confined to these tests."""
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from apply_repositories import apply_repositories, main, ApplicationOutcomeUnknown
from generate import encode
from prepare_repositories import prepare_repositories
from test_uripack import TestGuard


@unittest.skipUnless(os.environ.get("URIPROCESS_SOURCE") and os.environ.get("URIPROCESS_CONNECTORS_SOURCE"),
                     "Set both source repositories for batch application integration")
class RepositoryApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace, self.output = self.root / "batch", self.root / "evidence"
        self.config = json.loads((ROOT / "selections/repositories-v1.json").read_text())
        self.sources = {"runtime": Path(os.environ["URIPROCESS_SOURCE"]),
                        "connectors": Path(os.environ["URIPROCESS_CONNECTORS_SOURCE"])}
        self.index = prepare_repositories(self.config, ROOT, self.sources, self.workspace)
        # The real stdio bridge fixture denies every request. Success tests
        # explicitly patch only its authorization call with the existing test role.
        bridge = self.root / "deny-bridge.py"
        bridge.write_text('''#!/usr/bin/python3
import json,sys,time
r=json.load(sys.stdin)
print(json.dumps({"schema":"uripack.guard-response/v1","request_id":r["request_id"],
"subject_sha256":r["subject_sha256"],"allowed":False,"decision_ref":"test:denied",
"lease_ref":"test:lease","fencing_token":1,"expires_at":int(time.time())+60}))
''')
        bridge.chmod(0o755)
        self.bridge_path = self.root / "guard.json"
        self.bridge_path.write_bytes(encode({"schema": "uripack.guard-config/v1", "argv": [str(bridge)],
            "pinned_files": {str(bridge): hashlib.sha256(bridge.read_bytes()).hexdigest()},
            "required_checks": ["uriprocess.test.upstream"], "timeout_seconds": 10}))
        self.guards = {r["repository"]: self.bridge_path for r in self.index["repositories"]}

    def apply(self):
        return apply_repositories(self.config, ROOT, self.sources, self.workspace, self.guards, self.output)

    def test_explicit_batch_executes_all_plans_and_independently_reads_back(self):
        roles = {}
        def call(bridge, action, plan, payload=None):
            role = roles.setdefault(plan["plan_sha256"], TestGuard())
            return role.call(action, plan, payload)
        with patch("uripack_refactor.guard.GuardBridge.call", new=call):
            result = self.apply()
        self.assertEqual(result["status"], "extracted")
        self.assertEqual(len(result["repositories"]), 8)
        self.assertTrue(result["readback"]["artifacts_checked"])
        self.assertEqual(result["readback"]["public_uri_count"], 21)
        self.assertEqual(len(roles), 8)
        self.assertTrue(all(role.actions == ["admit", "tool", "publish", "complete"] for role in roles.values()))
        self.assertFalse(result["remote_publication"])
        self.assertFalse(result["production_cutover"])
        self.assertTrue((self.output / "batch-extraction.json").is_file())
        self.assertEqual(len(list(self.output.glob("completed-*.json"))), 8)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in self.output.iterdir()))

    def test_real_stdio_denial_halts_before_any_target_or_following_plan(self):
        result = self.apply()
        self.assertEqual(result["status"], "halted")
        self.assertEqual(result["code"], "UPK-GUARD-001")
        self.assertEqual(result["completed"], [])
        self.assertEqual(list((self.workspace / "repositories").iterdir()), [])
        self.assertTrue((self.output / "attempt-01.json").exists())
        self.assertFalse((self.output / "attempt-02.json").exists())
        self.assertFalse((self.output / "batch-extraction.json").exists())

    def test_failure_after_publication_preserves_pending_target_without_replay(self):
        from uripack_refactor.common import fail
        actions = []
        role = TestGuard()
        def call(bridge, action, plan, payload=None):
            actions.append(action)
            if action == "complete":
                fail("UPK-GUARD-001", "test-only unknown completion")
            return role.call(action, plan, payload)
        with patch("uripack_refactor.guard.GuardBridge.call", new=call):
            result = self.apply()
        self.assertEqual(result["status"], "halted")
        self.assertEqual(result["code"], "UPK-RECONCILE-001")
        self.assertEqual(actions, ["admit", "tool", "publish", "complete"])
        targets = list((self.workspace / "repositories").iterdir())
        self.assertEqual(len(targets), 1)
        receipt = json.loads((targets[0] / ".uripack/receipt.json").read_text())
        self.assertEqual(receipt["status"], "MATERIALIZED_PENDING_COMPLETION")
        self.output = self.root / "retry"
        with patch("uripack_refactor.guard.GuardBridge.call") as observed:
            with self.assertRaisesRegex(ValueError, "independent recovery"):
                self.apply()
            observed.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_incomplete_mapping_or_invalid_last_bridge_prevents_every_effect(self):
        from uripack_refactor.common import UripackError
        last = self.index["repositories"][-1]["repository"]
        del self.guards[last]
        with patch("uripack_refactor.guard.GuardBridge.call") as observed:
            with self.assertRaisesRegex(ValueError, "every repository"):
                self.apply()
            observed.assert_not_called()
        self.guards[last] = self.root / "missing.json"
        with patch("uripack_refactor.guard.GuardBridge.call") as observed:
            with self.assertRaises((OSError, UripackError)):
                self.apply()
            observed.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertEqual(list((self.workspace / "repositories").iterdir()), [])

    def test_bridge_pins_and_evidence_cannot_be_hosted_in_another_batch_source(self):
        code = self.workspace / "candidates/connectors/bridge.py"
        code.write_text("untrusted source controlled bridge")
        code.chmod(0o755)
        self.bridge_path.write_bytes(encode({"schema": "uripack.guard-config/v1", "argv": [str(code)],
            "pinned_files": {str(code): hashlib.sha256(code.read_bytes()).hexdigest()},
            "required_checks": ["test.check"]}))
        with patch("uripack_refactor.guard.GuardBridge.call") as observed:
            with self.assertRaisesRegex(ValueError, "every batch source"):
                self.apply()
            observed.assert_not_called()
        self.output = self.workspace / "evidence"
        with self.assertRaisesRegex(ValueError, "disjoint"):
            self.apply()
        self.assertFalse(self.output.exists())

    def test_existing_evidence_is_preserved(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_bytes(b"previous run")
        with self.assertRaisesRegex(ValueError, "must be new"):
            self.apply()
        self.assertEqual(marker.read_bytes(), b"previous run")

    def test_cli_missing_bridge_reports_actionable_preflight_without_effects(self):
        output = io.StringIO()
        args = ["--selection", str(ROOT / "selections/repositories-v1.json"),
                "--package-source", str(ROOT), "--workspace", str(self.workspace),
                "--output", str(self.output)]
        for key, source in self.sources.items():
            args.extend(["--source", f"{key}={source}"])
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(args), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["code"], "BATCH_GUARD_MAPPING_INCOMPLETE")
        self.assertEqual(result["stage"], "preflight")
        self.assertFalse(result["execution_started"])
        self.assertFalse(self.output.exists())
        self.assertEqual(list((self.workspace / "repositories").iterdir()), [])

    def test_evidence_write_failure_after_extraction_preserves_unknown_outcome(self):
        from uripack_refactor.executor import _write
        role = TestGuard()
        def call(bridge, action, plan, payload=None):
            return role.call(action, plan, payload)
        def write(root, name, data, mode):
            if root == self.output and name in {"completed-01.json", "halted.json"}:
                raise OSError("test-only evidence storage failure")
            return _write(root, name, data, mode)
        with patch("uripack_refactor.guard.GuardBridge.call", new=call), \
                patch("uripack_refactor.executor._write", new=write):
            with self.assertRaises(ApplicationOutcomeUnknown):
                self.apply()
        targets = list((self.workspace / "repositories").iterdir())
        self.assertEqual(len(targets), 1)
        self.assertEqual(json.loads((targets[0] / ".uripack/receipt.json").read_text())["status"], "EXTRACTED")
        self.assertTrue((self.output / "attempt-01.json").exists())
        self.assertFalse((self.output / "attempt-02.json").exists())


if __name__ == "__main__":
    unittest.main()
