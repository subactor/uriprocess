import json

import pytest

from urirun_connector_subactor_llm_account_hub import core


class Response:
    status = 200

    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return json.dumps(self._body).encode()


@pytest.fixture()
def control_env(monkeypatch):
    monkeypatch.setenv("SUBACTOR_CONTROL_URL", "http://control.invalid:8181")
    monkeypatch.setenv("SUBACTOR_LLM_ACCOUNT_CONTROL_TOKEN", "scoped-control-token")


@pytest.fixture()
def calls(monkeypatch):
    captured = []

    def fake_urlopen(request, timeout=None):
        payload = json.loads(request.data.decode()) if request.data else None
        captured.append({
            "url": request.full_url,
            "method": request.get_method(),
            "payload": payload,
            "timeout": timeout,
            "authorization": request.headers.get("Authorization"),
        })
        if request.full_url.endswith("/api/llm-account-hub/mcp?account_id=test"):
            return Response({
                "authority": "subactor-grant-and-intent",
                "endpoints": [{
                    "account_id": "test",
                    "email": "test@example.test",
                    "provider": "chatgpt",
                    "tool_id": "codex",
                    "state": "auth_profile_present",
                    "resource": "container:test:chatgpt:codex",
                    "required_scope": "container.cli.execute",
                    "password": "must-not-cross",
                }],
            })
        if request.full_url.endswith("/api/llm-account-hub/cli?account_id=test"):
            return Response({
                "arbitrary_shell": False,
                "containers": [{
                    "account_id": "test",
                    "email": "test@example.test",
                    "container_name": "hub-test",
                    "runtime_status": "running",
                    "runtime_health": "healthy",
                    "execution_location": "account_container",
                    "providers": [{
                        "id": "chatgpt",
                        "tools": [{
                            "id": "codex",
                            "installed": True,
                            "mcp": {
                                "resource": "llm-account:test:provider:chatgpt:cli:codex",
                                "required_scope": "container.cli.execute",
                            },
                        }],
                    }],
                }],
            })
        if request.full_url.endswith("/api/llm-account-hub/cli/plan"):
            return Response({
                "ok": True,
                "plan": {
                    "execution_id": "exec-1",
                    "plan_hash": "hash-1",
                    "valid_until": "2030-01-01T00:00:00Z",
                },
            })
        if request.full_url.endswith("/api/llm-account-hub/cli/execute"):
            return Response({
                "ok": True,
                "result": {"ok": True, "stdout": "done"},
                "receipt": {"execution_boundary": "account-container"},
                "authorization_cleanup": {"intent_completed": True, "grant_revoked": True},
            })
        raise AssertionError(f"unexpected URL: {request.full_url}")

    monkeypatch.setattr(core, "urlopen", fake_urlopen)
    return captured


def test_exact_routes_are_registered():
    assert set(core.bindings()["bindings"]) == {
        core.DISCOVERY_ROUTE,
        core.STATUS_ROUTE,
        core.PLAN_ROUTE,
        core.EXECUTE_ROUTE,
    }


def test_discovery_filters_unknown_fields_and_scopes_account(control_env, calls):
    result = core.list_bindings("test")

    assert result["ok"] is True
    assert result["count"] == 1
    assert result["authority"] == "subactor-grant-and-intent"
    assert "password" not in result["endpoints"][0]
    assert calls[0]["url"].endswith("/api/llm-account-hub/mcp?account_id=test")
    assert calls[0]["authorization"] == "Bearer scoped-control-token"


def test_status_selects_exact_binding_from_control_inventory(control_env, calls):
    result = core.cli_status("test", "chatgpt", "codex")

    assert result["ok"] is True
    assert result["result"]["tool"]["id"] == "codex"
    assert result["result"]["arbitrary_shell"] is False
    assert calls[0]["url"].endswith("/api/llm-account-hub/cli?account_id=test")
    assert calls[0]["payload"] is None


def test_plan_uses_typed_control_api_with_exact_scope(control_env, calls):
    result = core.cli_plan(
        "test", "chatgpt", "codex", project="subactor", arguments=["--version"], timeout_seconds=20
    )

    assert result["ok"] is True
    request = calls[0]["payload"]
    assert calls[0]["url"].endswith("/api/llm-account-hub/cli/plan")
    assert request["account_id"] == "test"
    assert request["provider"] == "chatgpt"
    assert request["tool_id"] == "codex"
    assert request["arguments"] == ["--version"]
    assert "url" not in request
    assert "token" not in request


def test_execute_requires_control_authorization_before_network(control_env, calls):
    result = core.cli_execute(
        "test", "chatgpt", "codex", project="subactor", arguments=["--version"]
    )

    assert result["ok"] is False
    assert result["error"] == "missing_execution_id"
    assert calls == []


def test_execute_forwards_exact_authorization_to_control_and_uses_bounded_timeout(control_env, calls):
    result = core.cli_execute(
        "test",
        "chatgpt",
        "codex",
        project="subactor",
        arguments=["--version"],
        timeout_seconds=20,
        valid_until="2030-01-01T00:00:00Z",
        execution_id="exec-1",
        plan_hash="hash-1",
        grant_id="grant-1",
        intent_id="intent-1",
        ticket="PLF-1",
    )

    assert result["ok"] is True
    assert result["result"]["receipt"]["execution_boundary"] == "account-container"
    request = calls[0]
    assert request["url"].endswith("/api/llm-account-hub/cli/execute")
    assert request["payload"]["grant_id"] == "grant-1"
    assert result["result"]["authorization_cleanup"]["grant_revoked"] is True
    assert request["timeout"] == 30.0


@pytest.mark.parametrize(
    ("field", "values"),
    [
        ("account_id", ("../test", "chatgpt", "codex")),
        ("provider", ("test", "chat/gpt", "codex")),
        ("tool_id", ("test", "chatgpt", "../../sh")),
    ],
)
def test_invalid_scope_ids_never_reach_control(control_env, calls, field, values):
    result = core.cli_status(*values)
    assert result["ok"] is False
    assert result["error"] == f"invalid_{field}"
    assert calls == []


def test_endpoint_and_token_cannot_be_selected_by_payload(control_env, calls):
    core.cli_status("test", "chatgpt", "codex")
    assert calls[0]["url"].startswith("http://control.invalid:8181/")
    assert calls[0]["authorization"] == "Bearer scoped-control-token"
