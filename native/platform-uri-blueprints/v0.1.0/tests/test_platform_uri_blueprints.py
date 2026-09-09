import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from urirun_connector_platform_uri_blueprints import core


class Response:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return json.dumps(self.body).encode()


class PlatformUriBlueprintsTest(unittest.TestCase):
    def test_exact_route_is_registered(self):
        self.assertEqual(
            set(core.bindings()["bindings"]),
            set(core.BLUEPRINTS),
        )

    def test_real_structural_compiler_preflight_is_green(self):
        calls = []
        document = {
            "ok": True,
            "results": [
                {
                    "action": "already_compiled",
                    "coding_ticket_id": "PLF-2333",
                    "meta": {
                        "source_ticket_id": "PLF-682",
                        "missing_route": core.ROUTE,
                        "repository": "platform",
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "control-token"
            token_file.write_text("scoped-control-token\n", encoding="utf-8")

            def fake_urlopen(request, timeout):
                calls.append((request, timeout))
                return Response(document)

            with (
                patch.dict(
                    core.os.environ,
                    {
                        "SUBACTOR_CONTROL_URL": "http://hr-control:8181",
                        "SUBACTOR_CONTROL_TOKEN": "",
                        "SUBACTOR_CONTROL_TOKEN_FILE": str(token_file),
                    },
                    clear=False,
                ),
                patch.object(core, "urlopen", fake_urlopen),
            ):
                result = core.implement(routes=list(core.EXPECTED_ROUTES))

        self.assertTrue(result["ok"])
        self.assertTrue(result["source_readiness_preflight_green"])
        self.assertFalse(result["production_apply"])
        self.assertFalse(result["authority_granted"])
        self.assertEqual(result["source_ticket_id"], "PLF-633")
        self.assertEqual(result["structural_source_ticket_id"], "PLF-682")
        self.assertEqual(result["coding_ticket_id"], "PLF-2333")
        request, timeout = calls[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(
            request.full_url,
            "http://hr-control:8181/api/autonomy/structural/compile"
            "?dry_run=1&commit=0&limit=10",
        )
        self.assertEqual(request.headers["Authorization"], "Bearer scoped-control-token")
        self.assertEqual(timeout, 30.0)
        self.assertNotIn("scoped-control-token", json.dumps(result))

    def test_project_and_secret_blueprints_use_their_exact_live_contracts(self):
        document = {
            "ok": True,
            "results": [
                {
                    "action": "already_compiled",
                    "coding_ticket_id": "PLF-2335",
                    "meta": {
                        "source_ticket_id": "PLF-683",
                        "missing_route": core.PROJECT_ROUTE,
                        "repository": "core",
                    },
                },
                {
                    "action": "already_compiled",
                    "coding_ticket_id": "PLF-2334",
                    "meta": {
                        "source_ticket_id": "PLF-684",
                        "missing_route": core.SECRET_INTAKE_ROUTE,
                        "repository": "platform",
                    },
                },
            ],
        }
        with (
            patch.dict(
                core.os.environ,
                {
                    "SUBACTOR_CONTROL_URL": "http://hr-control:8181",
                    "SUBACTOR_CONTROL_TOKEN": "scoped-control-token",
                },
                clear=False,
            ),
            patch.object(core, "urlopen", lambda *_args, **_kwargs: Response(document)),
        ):
            project = core.implement_project_orchestration(
                routes=list(core.BLUEPRINTS[core.PROJECT_ROUTE]["routes"]),
            )
            secret = core.implement_secret_intake(
                routes=list(core.BLUEPRINTS[core.SECRET_INTAKE_ROUTE]["routes"]),
            )
        self.assertTrue(project["ok"])
        self.assertEqual(project["structural_source_ticket_id"], "PLF-683")
        self.assertEqual(project["repository"], "core")
        self.assertEqual(project["coding_ticket_id"], "PLF-2335")
        self.assertTrue(secret["ok"])
        self.assertEqual(secret["structural_source_ticket_id"], "PLF-684")
        self.assertEqual(secret["repository"], "platform")
        self.assertEqual(secret["coding_ticket_id"], "PLF-2334")

    def test_fails_closed_for_other_source_or_red_compiler_result(self):
        self.assertFalse(core.implement("PLF-682", list(core.EXPECTED_ROUTES))["ok"])
        self.assertFalse(core.implement(routes=[])["ok"])
        self.assertFalse(core.implement(routes=["email://attacker.invalid/command/send"])["ok"])
        self.assertFalse(core.implement_project_orchestration(routes=[])["ok"])
        self.assertFalse(core.implement_secret_intake(routes=[])["ok"])
        document = {"ok": False, "results": []}
        with (
            patch.dict(
                core.os.environ,
                {
                    "SUBACTOR_CONTROL_URL": "http://hr-control:8181",
                    "SUBACTOR_CONTROL_TOKEN": "scoped-control-token",
                },
                clear=False,
            ),
            patch.object(core, "urlopen", lambda *_args, **_kwargs: Response(document)),
        ):
            result = core.implement(routes=list(core.EXPECTED_ROUTES))
        self.assertFalse(result["ok"])

    def test_completed_remediation_stays_ready_when_compiler_queue_is_empty(self):
        document = {"ok": True, "results": []}
        with (
            patch.dict(
                core.os.environ,
                {
                    "SUBACTOR_CONTROL_URL": "http://hr-control:8181",
                    "SUBACTOR_CONTROL_TOKEN": "scoped-control-token",
                },
                clear=False,
            ),
            patch.object(core, "urlopen", lambda *_args, **_kwargs: Response(document)),
        ):
            result = core.implement(routes=list(core.EXPECTED_ROUTES))
        self.assertTrue(result["ok"])
        self.assertEqual(result["compiler_action"], "preflight_available")
        self.assertTrue(result["source_readiness_preflight_green"])

    def test_actor_cannot_supply_apply_target_or_credentials(self):
        with self.assertRaises(TypeError):
            core.implement(
                source_ticket_id="PLF-633",
                routes=list(core.EXPECTED_ROUTES),
                apply=True,
                plan_hash="unverified",
                grant="actor-controlled",
                url="http://attacker.invalid",
            )


if __name__ == "__main__":
    unittest.main()
