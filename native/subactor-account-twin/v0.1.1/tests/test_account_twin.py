import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest
import urirun

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


@pytest.fixture()
def twin_endpoint():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            requests.append((parsed.path, parse_qs(parsed.query)))
            body = json.dumps({
                "schema": "subactor.account-twin.query/v1",
                "resource": parsed.path.rsplit("/", 1)[-1],
                "items": [],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            thread.join(timeout=5)


@pytest.mark.parametrize("resource", core.RESOURCES)
def test_serialized_binding_executes_correct_query_in_subprocess(resource, twin_endpoint, tmp_path):
    endpoint, requests = twin_endpoint
    # Use the serialized binding and the same runner as the deployed node.
    # Paths come from the modules under test, also when installed in a wheel.
    binding = json.loads(json.dumps(core.bindings()))["bindings"][core.ROUTES[resource]]
    assert binding["adapter"] == "local-function-subprocess"
    python = binding["python"]
    reference = f"{python['module']}:{python['export']}"
    environment = {
        **os.environ,
        "TWIN_SUBACTOR_URL": endpoint,
        "PYTHONPATH": os.pathsep.join(str(Path(module.__file__).resolve().parent.parent)
                                    for module in (core, urirun)),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    result = subprocess.run(
        [sys.executable, "-B", "-m", "urirun.exec", reference],
        input=json.dumps({"organization": "subactor", "query": "wydruk", "limit": 25}),
        capture_output=True, text=True, cwd=tmp_path, env=environment, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["ok"] is True
    assert document["result"]["resource"] == resource
    assert requests == [(f"/v1/account/{resource}", {
        "limit": ["25"], "offset": ["0"], "organization": ["subactor"], "q": ["wydruk"],
    })]
