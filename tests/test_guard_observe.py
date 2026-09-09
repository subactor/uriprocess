import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("guard_observe", ROOT / "tools/guard_observe.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ClientDouble:
    """Only client validation tests; not evidence of a running Guard service."""
    def __init__(self, statuses=None):
        self.calls = []
        self.statuses = statuses or [{"ok": True, "head": "a" * 40, "dirty": False, "unmerged": []}] * 2

    def call(self, operation, params):
        self.calls.append((operation, params))
        if operation == "system.discover":
            return {"ok": True, "name": "organism-guard", "version": "0.9.0", "contract_sha256": "b" * 64}
        return self.statuses.pop(0)


class GuardObservationTests(unittest.TestCase):
    def test_only_native_read_operations_and_no_authority(self):
        client = ClientDouble()
        result = module.observe(client, "uriprocess", "a" * 40, "b" * 64)
        self.assertEqual([op for op, _ in client.calls], ["system.discover", "git.status", "git.status"])
        self.assertFalse(result["execution_authority"])
        self.assertFalse(result["architecture_verified"])
        self.assertFalse(result["publication_authorized"])

    def test_contract_drift_stops_before_repository_access(self):
        client = ClientDouble()
        with self.assertRaisesRegex(module.ObservationRejected, "CONTRACT_MISMATCH"):
            module.observe(client, "uriprocess", "a" * 40, "c" * 64)
        self.assertEqual(len(client.calls), 1)

    def test_dirty_conflicted_stale_and_malformed_states_fail_closed(self):
        good = {"ok": True, "head": "a" * 40, "dirty": False, "unmerged": []}
        for change in [{"dirty": True}, {"dirty": 0}, {"head": "c" * 40}, {"unmerged": [{}]}, {"ok": False}]:
            with self.subTest(change=change), self.assertRaises(module.ObservationRejected):
                module.observe(ClientDouble([good, {**good, **change}]), "uriprocess", "a" * 40, "b" * 64)

    def test_mutable_or_missing_pins_never_contact_server(self):
        for head, contract in [("main", "b" * 64), ("a" * 40, "")]:
            client = ClientDouble()
            with self.assertRaises(module.ObservationRejected):
                module.observe(client, "uriprocess", head, contract)
            self.assertEqual(client.calls, [])

    def test_missing_token_does_not_produce_success_file(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict("os.environ", {}, clear=True):
            output = Path(temporary) / "observation.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = module.main(["--base-url", "http://127.0.0.1:1", "--repository-id", "uriprocess",
                    "--expected-head", "a" * 40, "--expected-contract-sha256", "b" * 64, "--out", str(output)])
            self.assertEqual(status, 2)
            self.assertFalse(output.exists())
            self.assertEqual(json.loads(stderr.getvalue())["code"], "GUARD_TOKEN_MISSING")
