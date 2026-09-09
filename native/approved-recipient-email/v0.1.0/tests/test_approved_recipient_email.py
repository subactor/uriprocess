import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


class FakeConnector:
    def __init__(self, connector_id, scheme=None):
        self.connector_id = connector_id
        self.scheme = scheme
        self.routes = {}

    def handler(self, uri, **options):
        def decorate(function):
            self.routes[uri] = {
                "uri": uri,
                "meta": {"connector": self.connector_id, **options.get("meta", {})},
            }
            return function
        return decorate

    def bindings(self):
        return {"version": "urirun.bindings.v2", "bindings": self.routes}


fake_urirun = types.ModuleType("urirun")
fake_urirun.connector = lambda connector_id, scheme=None: FakeConnector(connector_id, scheme)
fake_urirun.ok = lambda **value: {"ok": True, **value}
fake_urirun.fail = lambda error, **value: {"ok": False, "error": error, **value}
fake_urirun.load_manifest = lambda _package: None
sys.modules.setdefault("urirun", fake_urirun)

from urirun_connector_approved_recipient_email import core


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def grant(secret, plan_hash, artifact_sha256, *, jti="grant-once"):
    header = {"alg": "HS256", "typ": "apply-grant"}
    claims = {
        "run_id": "PLF-852-send-approved",
        "actor": core.ACTOR,
        "intent_pack": "connect-first-outreach@1",
        "plan_hash": plan_hash,
        "artifact_sha256": artifact_sha256,
        "target": core.ROUTE,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "risk_class": "boundary",
        "jti": jti,
        "iat": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    first = b64url(json.dumps(header, separators=(",", ":")).encode())
    second = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{first}.{second}".encode()
    signature = b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{first}.{second}.{signature}"


class ApprovedRecipientEmailTest(unittest.TestCase):
    def arguments(self):
        return {
            "source_ticket_id": "PLF-852",
            "to": ["approved@example.test"],
            "subject": "Approved pilot",
            "body": "This exact outreach was approved.",
        }

    def test_exact_route_is_registered(self):
        self.assertEqual(set(core.bindings()["bindings"]), {core.ROUTE})
        self.assertEqual(
            core.bindings()["bindings"][core.ROUTE]["meta"]["connector"],
            core.CONNECTOR_ID,
        )

    def test_dry_run_has_all_structural_readiness_receipts(self):
        with (
            patch.object(core, "_smtp_settings", return_value={"transport": "external"}),
            patch.object(core, "_preflight") as preflight,
        ):
            result = core.send(**self.arguments())
        self.assertTrue(result["ok"])
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["production_apply"])
        self.assertFalse(result["authority_granted"])
        self.assertTrue(result["adapter_implemented"])
        self.assertTrue(result["exact_route_registered"])
        self.assertTrue(result["uri_coverage_verified"])
        self.assertTrue(result["source_readiness_preflight_green"])
        self.assertRegex(result["plan_hash"], r"^[a-f0-9]{64}$")
        self.assertRegex(result["artifact_sha256"], r"^[a-f0-9]{64}$")
        preflight.assert_called_once()

    def test_apply_requires_matching_hash_and_signed_one_time_grant(self):
        secret = "test-secret-not-for-production"
        with tempfile.TemporaryDirectory() as directory:
            store = str(Path(directory) / "grant-jti.json")
            env = {
                "APPLY_GRANT_HMAC_SECRET": secret,
                "APPLY_GRANT_JTI_STORE": store,
            }
            with (
                patch.dict(os.environ, env, clear=False),
                patch.object(core, "_smtp_settings", return_value={"transport": "external"}),
                patch.object(core, "_preflight") as preflight,
                patch.object(core, "_deliver", return_value=[{"recipient": "approved@example.test", "status": "accepted"}]) as deliver,
            ):
                planned = core.send(**self.arguments())
                preflight.reset_mock()
                missing = core.send(**self.arguments(), apply=True, plan_hash=planned["plan_hash"])
                self.assertFalse(missing["ok"])
                self.assertEqual(missing["error"], "apply_grant_required")
                preflight.assert_not_called()

                token = grant(secret, planned["plan_hash"], planned["artifact_sha256"])
                applied = core.send(
                    **self.arguments(),
                    apply=True,
                    plan_hash=planned["plan_hash"],
                    apply_grant=token,
                )
                self.assertTrue(applied["ok"])
                self.assertTrue(applied["production_apply"])
                self.assertTrue(applied["authority_granted"])
                deliver.assert_called_once()

                replay = core.send(
                    **self.arguments(),
                    apply=True,
                    plan_hash=planned["plan_hash"],
                    apply_grant=token,
                )
                self.assertFalse(replay["ok"])
                self.assertEqual(replay["error"], "apply_grant_replay")

    def test_actor_cannot_select_transport_vault_sender_or_authority(self):
        for override in (
            {"smtp_host": "attacker.invalid"},
            {"vault_entry_id": "actor-selected"},
            {"sender": "attacker@example.test"},
            {"actor": "bot:attacker"},
        ):
            with self.assertRaises(TypeError):
                core.send(**self.arguments(), **override)

    def test_input_validation_fails_closed_before_preflight(self):
        with patch.object(core, "_smtp_settings") as settings:
            result = core.send(
                source_ticket_id="PLF-852",
                recipients=["Name <approved@example.test>"],
                subject="Approved pilot",
                body="body",
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "approved_recipient_invalid")
        settings.assert_not_called()


if __name__ == "__main__":
    unittest.main()
