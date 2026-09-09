import json

from urirun_connector_subactor_secret_intake import core


class Response:
    def __init__(self, body, status=200):
        self.status = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, _limit):
        return json.dumps(self._body).encode()


def test_exact_routes_are_registered():
    assert set(core.bindings()["bindings"]) == {core.REQUEST_ROUTE, core.CONSUME_ROUTE}


def test_request_mints_via_control_without_secrets(monkeypatch, tmp_path):
    calls = []
    token_file = tmp_path / "control-token"
    token_file.write_text("scoped-control-token\n")
    monkeypatch.setenv("SUBACTOR_CONTROL_URL", "http://hr-control:8181")
    monkeypatch.delenv("SUBACTOR_CONTROL_TOKEN", raising=False)
    monkeypatch.setenv("SUBACTOR_CONTROL_TOKEN_FILE", str(token_file))

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        return Response({
            "ok": True,
            "process_ticket_id": "PLF-R1",
            "consume_ticket_id": "PLF-C1",
            "submission_url": "https://agent.example/secret-intake/plesk#token=secret",
            "request": {"id": "intake-1", "expires_at": "2030-01-01T00:00:00Z"},
        }, status=201)

    monkeypatch.setattr(core, "urlopen", fake_urlopen)
    result = core.request_intake(provider="plesk", source_ticket_id="PLF-3816")
    assert result["ok"] is True
    request, timeout = calls[0]
    assert request.full_url == "http://hr-control:8181/api/secret-intake/requests"
    assert request.get_method() == "POST"
    assert json.loads(request.data) == {
        "provider": "plesk",
        "ticket_id": "PLF-3816",
        "ttl_seconds": 900,
    }
    assert "password" not in json.dumps(result)
    assert "secret" not in json.dumps(result["result"]).lower() or result["result"]["secrets_included"] is False
    assert result["result"]["submission_url_present"] is True
    assert "submission_url" not in result["result"]
    assert timeout == 60.0


def test_consume_ready_and_waiting(monkeypatch, tmp_path):
    token_file = tmp_path / "control-token"
    token_file.write_text("token\n")
    monkeypatch.setenv("SUBACTOR_CONTROL_URL", "http://hr-control:8181")
    monkeypatch.setenv("SUBACTOR_CONTROL_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("SUBACTOR_CONTROL_TOKEN", raising=False)

    monkeypatch.setattr(
        core,
        "urlopen",
        lambda request, timeout: Response({
            "ok": True,
            "intake_status": "ready",
            "provider": "plesk",
            "runtime_vault_entry_id": "plesk-runtime",
            "vault_present": True,
        }),
    )
    ready = core.consume_intake(provider="plesk", source_ticket_id="PLF-3816")
    assert ready["ok"] is True
    assert ready["result"]["intake_status"] == "ready"

    monkeypatch.setattr(
        core,
        "urlopen",
        lambda request, timeout: Response({
            "ok": True,
            "intake_status": "waiting_human",
            "pending_request": {"id": "intake-9", "expires_at": "2030-01-01T00:00:00Z"},
        }),
    )
    waiting = core.consume_intake(provider="plesk", source_ticket_id="PLF-3816")
    assert waiting["ok"] is False
    assert waiting.get("error") == "secret_intake_waiting_human" or "secret_intake_waiting_human" in json.dumps(waiting)


def test_deployment_request_forwards_exact_metadata_and_reports_auto_resolution(monkeypatch, tmp_path):
    calls = []
    token_file = tmp_path / "control-token"
    token_file.write_text("scoped-control-token\n")
    monkeypatch.setenv("SUBACTOR_CONTROL_URL", "http://hr-control:8181")
    monkeypatch.setenv("SUBACTOR_CONTROL_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("SUBACTOR_CONTROL_TOKEN", raising=False)

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        return Response({
            "ok": True,
            "auto_resolved": True,
            "submission_url": None,
            "request": {"id": "intake-auto-1", "expires_at": "2030-01-01T00:00:00Z"},
            "credential_source": {
                "source_id": "credential-source-0123456789abcdef01234567",
                "kind": "vault",
                "label": "must not cross connector boundary",
                "detail": "vault entry metadata",
                "scope_target": "domain:subactor.com",
                "fields": ["sftp.username", "sftp.password", "ftp.username", "ftp.password"],
                "secret_values_included": False,
            },
        }, status=201)

    monkeypatch.setattr(core, "urlopen", fake_urlopen)
    result = core.request_intake(
        provider="deployment",
        source_ticket_id="PLF-7989",
        deployment_origin="https://panel.example.test/",
        deployment_domain="founder.subactor.com",
        deployment_webspace="subactor.com",
        sftp_vault_entry_id="deployment.founder-subactor-com.sftp",
        ftp_vault_entry_id="deployment.founder-subactor-com.ftp",
    )

    assert result["ok"] is True
    payload = json.loads(calls[0][0].data)
    assert payload == {
        "provider": "deployment",
        "ticket_id": "PLF-7989",
        "ttl_seconds": 900,
        "deployment_origin": "https://panel.example.test",
        "deployment_domain": "founder.subactor.com",
        "deployment_webspace": "subactor.com",
        "sftp_vault_entry_id": "deployment.founder-subactor-com.sftp",
        "ftp_vault_entry_id": "deployment.founder-subactor-com.ftp",
    }
    assert result["result"]["auto_resolved"] is True
    assert result["result"]["submission_url_present"] is False
    assert result["result"]["credential_source"] == {
        "source_id": "credential-source-0123456789abcdef01234567",
        "kind": "vault",
        "scope_target": "domain:subactor.com",
        "fields": ["sftp.username", "sftp.password", "ftp.username", "ftp.password"],
        "secret_values_included": False,
    }
    assert "label" not in json.dumps(result["result"])
    assert "detail" not in json.dumps(result["result"])


def test_deployment_request_fails_closed_on_incomplete_or_unsafe_bindings():
    common = {
        "provider": "deployment",
        "source_ticket_id": "PLF-7987",
        "deployment_origin": "https://panel.example.test",
        "deployment_domain": "wydruk.subactor.com",
        "deployment_webspace": "subactor.com",
        "sftp_vault_entry_id": "deployment.wydruk-subactor-com.sftp",
        "ftp_vault_entry_id": "deployment.wydruk-subactor-com.ftp",
    }
    assert core.request_intake(**{**common, "deployment_webspace": "example.net"})["ok"] is False
    assert core.request_intake(**{**common, "deployment_origin": "http://panel.example.test"})["ok"] is False
    assert core.request_intake(**{**common, "deployment_origin": "https://user:pass@panel.example.test"})["ok"] is False
    assert core.request_intake(**{**common, "deployment_webspace": ""})["ok"] is False
    assert core.request_intake(**{**common, "ftp_vault_entry_id": common["sftp_vault_entry_id"]})["ok"] is False
    assert core.request_intake(**{**common, "ttl_seconds": 10})["ok"] is False


def test_rejects_bad_provider_and_secret_kwargs():
    assert core.request_intake(provider="evil", source_ticket_id="PLF-1")["ok"] is False
    try:
        core.request_intake(provider="plesk", source_ticket_id="PLF-1", password="nope")
    except TypeError:
        pass
    else:
        raise AssertionError("password kw must be rejected by signature")
