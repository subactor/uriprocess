import json

from urirun_connector_subactor_ticket_lifecycle import core


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return json.dumps({"ok": True, "schema": "subactor.ticket-lifecycle-reconciliation.v1"}).encode()


def test_exact_route_is_registered():
    assert list(core.bindings()["bindings"]) == [core.ROUTE]


def test_reconcile_uses_only_configured_control_target(monkeypatch, tmp_path):
    calls = []
    token_file = tmp_path / "control-token"
    token_file.write_text("scoped-control-token\n")
    monkeypatch.setenv("SUBACTOR_CONTROL_URL", "http://hr-control:8181")
    monkeypatch.delenv("SUBACTOR_CONTROL_TOKEN", raising=False)
    monkeypatch.setenv("SUBACTOR_CONTROL_TOKEN_FILE", str(token_file))
    monkeypatch.setattr(core, "urlopen", lambda request, timeout: calls.append((request, timeout)) or Response())

    result = core.reconcile_lifecycle("PLF-810", False)

    assert result["ok"] is True
    request, timeout = calls[0]
    assert request.full_url == "http://hr-control:8181/api/tickets/lifecycle/reconcile"
    assert request.headers["Authorization"] == "Bearer scoped-control-token"
    assert json.loads(request.data) == {"apply": False, "ticket_id": "PLF-810"}
    assert timeout == 60.0
    assert "scoped-control-token" not in json.dumps(result)


def test_reconcile_rejects_unbounded_or_mutating_actor_input(monkeypatch):
    assert core.reconcile_lifecycle("../tokens", False)["ok"] is False
    assert core.reconcile_lifecycle("PLF-810", True)["ok"] is False
    try:
        core.reconcile_lifecycle("PLF-810", url="http://actor", token="secret")
    except TypeError:
        pass
    else:
        raise AssertionError("actor-controlled URL and token must be rejected")

