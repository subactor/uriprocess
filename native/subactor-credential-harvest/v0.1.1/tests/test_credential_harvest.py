import json

import pytest

from urirun_connector_subactor_credential_harvest import core


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
def hub_env(monkeypatch):
    monkeypatch.setenv("SUBACTOR_LLM_ACCOUNT_HUB_URL", "http://hub.invalid:8099")
    monkeypatch.setenv("SUBACTOR_LLM_ACCOUNT_HUB_TOKEN", "test-token")


@pytest.fixture()
def calls(monkeypatch):
    """Capture outgoing hub requests; default answer is a reference-only result."""
    captured = []

    def fake_urlopen(request, timeout=None):
        payload = json.loads(request.data.decode()) if request.data else {}
        captured.append({
            "url": request.full_url,
            "method": request.get_method(),
            "payload": payload,
            "timeout": timeout,
        })
        response = {
            "ok": True,
            "vault_entry_id": "plesk-runtime",
            "source_kind": "firefox-logins",
            "counts": {"matched": 1},
        }
        if payload.get("credential_ref"):
            response["credential_ref"] = payload["credential_ref"]
        return Response(response)

    monkeypatch.setattr(core, "urlopen", fake_urlopen)
    return captured


def test_exact_route_is_registered():
    assert list(core.bindings()["bindings"]) == [core.ROUTE]
    assert core.ROUTE == "hub://host/credential/command/harvest"


def test_happy_path_maps_plan_payload_to_hub_contract(hub_env, calls):
    result = core.harvest_credential(
        provider="plesk",
        account_id="softreck",
        grant_id="grant-123",
        grant_scope="credential.harvest",
        vault_entry_id="plesk-runtime",
        source_ticket_id="PLF-3816",
    )

    assert result["ok"] is True
    assert len(calls) == 1
    assert calls[0]["url"].endswith("/v1/commands/harvest-auto")
    assert calls[0]["payload"] == {
        "provider": "plesk",
        "account_id": "softreck",
        "grant_id": "grant-123",
        "vault_path": "plesk-runtime",
        "ticket": "PLF-3816",
    }


def test_exact_reference_uses_fail_closed_hub_endpoint(hub_env, calls):
    credential_ref = (
        "credential-ref://browser_firefox/browser_login/cref_exact_plesk"
    )
    result = core.harvest_credential(
        provider="plesk",
        account_id="softreck",
        grant_id="grant-123",
        grant_scope="credential.harvest",
        vault_entry_id="plesk-runtime",
        source_ticket_id="PLF-3816",
        credential_ref=credential_ref,
    )

    assert result["ok"] is True
    assert calls[0]["url"].endswith("/v1/commands/harvest-reference")
    assert calls[0]["payload"]["credential_ref"] == credential_ref
    assert result["result"]["credential_ref"] == credential_ref


@pytest.mark.parametrize(
    "credential_ref",
    [
        " https://example.test/not-an-inventory-reference",
        "https://example.test/not-an-inventory-reference",
        "credential-ref://user@example.test/item/ref",
        "credential-ref://browser_firefox/item/ref?secret=value",
    ],
)
def test_invalid_exact_reference_fails_without_contacting_hub(
    hub_env, calls, credential_ref
):
    result = core.harvest_credential(
        provider="plesk",
        account_id="softreck",
        grant_id="grant-123",
        credential_ref=credential_ref,
    )

    assert result["ok"] is False
    assert result["error"] == "invalid_credential_ref"
    assert calls == []


def test_exact_reference_requires_hub_selection_proof(hub_env, monkeypatch):
    def response_without_reference(request, timeout=None):
        return Response({"ok": True, "vault_entry_id": "plesk-runtime"})

    monkeypatch.setattr(core, "urlopen", response_without_reference)
    result = core.harvest_credential(
        provider="plesk",
        account_id="softreck",
        grant_id="grant-123",
        credential_ref="credential-ref://browser_firefox/browser_login/cref_exact",
    )

    assert result["ok"] is False
    assert result["error"] == "hub_credential_ref_mismatch"


def test_missing_grant_id_fails_closed_without_contacting_hub(hub_env, calls):
    result = core.harvest_credential(
        provider="plesk",
        account_id="prototypowanie",
        grant_scope="credential.harvest",
        vault_entry_id="plesk-runtime",
        source_ticket_id="PLF-3816",
    )

    assert result["ok"] is False
    assert result["error"] == "missing_grant_id"
    assert calls == []


def test_missing_account_id_uses_default_env_account(hub_env, calls, monkeypatch):
    monkeypatch.setenv("SUBACTOR_LLM_ACCOUNT_HUB_HARVEST_ACCOUNT", "softreck")
    result = core.harvest_credential(provider="plesk", grant_id="grant-123")
    assert result["ok"] is True
    assert calls[0]["payload"]["account_id"] == "softreck"


def test_wrong_grant_scope_is_refused(hub_env, calls):
    result = core.harvest_credential(
        provider="plesk",
        account_id="softreck",
        grant_id="grant-123",
        grant_scope="verify",
    )

    assert result["ok"] is False
    assert result["error"] == "invalid_grant_scope"
    assert calls == []


def test_invalid_provider_is_refused(hub_env, calls):
    result = core.harvest_credential(provider="../etc", account_id="softreck", grant_id="grant-123")

    assert result["ok"] is False
    assert result["error"] == "invalid_provider"
    assert calls == []


def test_invalid_ticket_is_refused(hub_env, calls):
    result = core.harvest_credential(
        provider="plesk",
        account_id="softreck",
        grant_id="grant-123",
        source_ticket_id="'; DROP TABLE",
    )

    assert result["ok"] is False
    assert result["error"] == "invalid_source_ticket_id"
    assert calls == []


def test_secret_shaped_fields_never_cross_the_boundary(hub_env, monkeypatch):
    """A hub regression must not leak a value through the URI node."""

    def leaky_urlopen(request, timeout=None):
        return Response({
            "ok": True,
            "vault_entry_id": "plesk-runtime",
            "password": "hunter2",
            "secrets": {"admin": "hunter2"},
        })

    monkeypatch.setattr(core, "urlopen", leaky_urlopen)

    result = core.harvest_credential(provider="plesk", account_id="softreck", grant_id="grant-123")

    assert result["ok"] is True
    serialized = json.dumps(result)
    assert "hunter2" not in serialized
    assert "password" not in result["result"]
    assert result["result"]["dropped_fields"] == 2


def test_unconfigured_endpoint_fails_closed(monkeypatch, calls):
    for name in (
        "SUBACTOR_LLM_ACCOUNT_HUB_URL",
        "LLM_ACCOUNT_HUB_URL",
        "SUBACTOR_LLM_ACCOUNT_HUB_TOKEN",
        "LLM_ACCOUNT_HUB_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)

    result = core.harvest_credential(provider="plesk", account_id="softreck", grant_id="grant-123")

    assert result["ok"] is False
    assert result["error"] == "LLM_ACCOUNT_HUB_URL is not configured"
    assert calls == []


def test_endpoint_and_token_are_never_taken_from_the_payload(hub_env, calls):
    """The actor cannot redirect the harvest to an endpoint it controls."""
    core.harvest_credential(provider="plesk", account_id="softreck", grant_id="grant-123")

    assert calls[0]["url"].startswith("http://hub.invalid:8099/")
    assert "token" not in calls[0]["payload"]
    assert "url" not in calls[0]["payload"]
