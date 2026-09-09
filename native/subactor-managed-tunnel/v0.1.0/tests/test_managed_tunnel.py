from urllib.error import HTTPError

from urirun_connector_subactor_managed_tunnel import core


class Response:
    def __init__(self, status, body=b"{}"):
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return self.body


def test_exact_route_is_registered():
    assert list(core.bindings()["bindings"]) == [core.ROUTE]


def test_preflight_is_read_only_and_reports_exact_missing_configuration(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        if request.full_url.endswith("/api/me"):
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)
        return Response(200)

    monkeypatch.setattr(core, "urlopen", fake_urlopen)
    monkeypatch.setenv("SUBACTOR_CONTROL_URL", "http://hr-control:8181")
    monkeypatch.delenv("SUBACTOR_TUNNEL_PROVIDER", raising=False)
    monkeypatch.delenv("SUBACTOR_TUNNEL_TOKEN", raising=False)
    monkeypatch.delenv("SUBACTOR_TUNNEL_TOKEN_FILE", raising=False)
    monkeypatch.delenv("URIRUN_VAULT_URL", raising=False)
    monkeypatch.delenv("URIRUN_VAULT_TOKEN", raising=False)

    result = core.preflight(
        hostname="founder.subactor.com",
        upstream="http://127.0.0.1:8091",
        mode="read_only",
        apply=False,
        authentication_required=True,
        secrets_in_payload=False,
    )

    assert result["ok"] is True
    assert result["apply"] is False
    assert result["authenticated_upstream_assessed"] is True
    assert result["credential_material_not_exposed"] is True
    assert result["authentication_assessment"]["challenge_observed"] is True
    assert result["blockers"] == [
        "tunnel_provider_not_configured",
        "tunnel_credential_not_configured",
    ]
    assert calls == [
        ("http://hr-control:8181/health", 10.0),
        ("http://hr-control:8181/api/me", 10.0),
    ]


def test_preflight_reports_ready_plan_without_exposing_token(monkeypatch):
    def fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/me"):
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)
        if request.full_url.endswith("/vault"):
            return Response(200, b'{"entries":[{"id":"managed-outbound-tunnel","secrets":{"api_token":"***"}}]}')
        return Response(200)

    monkeypatch.setattr(core, "urlopen", fake_urlopen)
    monkeypatch.delenv("SUBACTOR_TUNNEL_PROVIDER", raising=False)
    monkeypatch.delenv("SUBACTOR_TUNNEL_TOKEN", raising=False)
    monkeypatch.setenv("URIRUN_VAULT_URL", "http://browser-agent:8087")
    monkeypatch.setenv("URIRUN_VAULT_TOKEN", "scoped-service-token")

    result = core.preflight(
        hostname="founder.subactor.com",
        upstream="http://127.0.0.1:8091",
        mode="read_only",
        apply=False,
        authentication_required=True,
        secrets_in_payload=False,
    )

    assert result["ok"] is True
    assert result["ready_for_plan"] is True
    assert result["provider"]["id"] == "cloudflare_managed"
    assert result["credential"]["configured"] is True
    assert result["credential"]["material_exposed"] is False
    assert "scoped-service-token" not in str(result)


def test_preflight_rejects_mutating_or_actor_selected_targets():
    common = {
        "hostname": "founder.subactor.com",
        "upstream": "http://127.0.0.1:8091",
        "mode": "read_only",
        "apply": False,
        "authentication_required": True,
        "secrets_in_payload": False,
    }
    assert core.preflight(**{**common, "hostname": "attacker.example"})["ok"] is False
    assert core.preflight(**{**common, "upstream": "http://attacker.example"})["ok"] is False
    assert core.preflight(**{**common, "apply": True})["ok"] is False
