import json

import pytest

from urirun_connector_subactor_account_twin import core


class Response:
    status = 200

    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit):
        return json.dumps(self._body).encode()


@pytest.fixture()
def calls(monkeypatch):
    captured = []

    def fake_urlopen(request, timeout=None):
        captured.append({"url": request.full_url, "timeout": timeout, "authorization": request.headers.get("Authorization")})
        return Response(
            {
                "schema": "subactor.account-twin.query/v1",
                "profileId": "twin-subactor-account",
                "accountId": "subactor",
                "projectionDigest": "sha256:" + "a" * 64,
                "resource": "projects",
                "items": [],
            }
        )

    monkeypatch.setenv("TWIN_SUBACTOR_URL", "http://twin-subactor:8188")
    monkeypatch.setattr(core, "urlopen", fake_urlopen)
    return captured


def test_exact_read_only_routes_are_registered():
    assert set(core.bindings()["bindings"]) == set(core.ROUTES.values())
    assert all("/query/" in route for route in core.ROUTES.values())


def test_project_query_uses_deployment_selected_twin_and_bounded_filters(calls):
    result = core.query_projects(organization="subactor", query="wydruk", limit=25)

    assert result["ok"] is True
    assert result["result"]["profileId"] == "twin-subactor-account"
    assert calls[0]["url"] == (
        "http://twin-subactor:8188/v1/account/projects?"
        "limit=25&offset=0&organization=subactor&q=wydruk"
    )
    assert calls[0]["authorization"] is None


@pytest.mark.parametrize(
    "kwargs,error",
    [
        ({"limit": 1001}, "invalid_pagination"),
        ({"offset": -1}, "invalid_pagination"),
        ({"query": "x\nforged"}, "invalid_q"),
    ],
)
def test_query_rejects_unbounded_input_before_network(calls, kwargs, error):
    result = core.query_projects(**kwargs)
    assert result["ok"] is False
    assert result["error"] == error
    assert calls == []


def test_manifest_matches_runtime_bindings():
    assert set(core.manifest()["routes"]) == set(core.ROUTES.values())
