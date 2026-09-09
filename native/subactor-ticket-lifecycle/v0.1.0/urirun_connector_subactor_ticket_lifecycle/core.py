"""Exact URI adapter for the shared Subactor ticket-lifecycle contract."""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import urirun

CONNECTOR_ID = "subactor-ticket-lifecycle"
ROUTE = "planfile://subactor/tickets/command/reconcile-lifecycle"
conn = urirun.connector(CONNECTOR_ID, scheme="planfile")


def _control_token() -> str:
    token = os.environ.get("SUBACTOR_CONTROL_TOKEN", "").strip()
    token_file = os.environ.get("SUBACTOR_CONTROL_TOKEN_FILE", "").strip()
    if token or not token_file:
        return token
    with open(token_file, "r", encoding="utf-8") as stream:
        return stream.read(8192).strip()


def _call_control(payload: dict[str, Any]) -> dict[str, Any]:
    base = os.environ.get("SUBACTOR_CONTROL_URL", "").strip().rstrip("/")
    if not base:
        return urirun.fail("SUBACTOR_CONTROL_URL is not configured", connector=CONNECTOR_ID)
    try:
        token = _control_token()
    except (OSError, ValueError):
        return urirun.fail("SUBACTOR_CONTROL_TOKEN_FILE is unavailable", connector=CONNECTOR_ID)
    if not token:
        return urirun.fail("SUBACTOR_CONTROL_TOKEN is not configured", connector=CONNECTOR_ID)
    request = Request(
        base + "/api/tickets/lifecycle/reconcile",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "accept": "application/json",
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": "urirun-connector-subactor-ticket-lifecycle/0.1",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=60.0) as response:
            raw = response.read(8 * 1024 * 1024).decode("utf-8", errors="replace")
            result = json.loads(raw) if raw else {}
            if result.get("ok") is not True:
                return urirun.fail("Subactor lifecycle preflight failed", connector=CONNECTOR_ID, status=response.status)
            return urirun.ok(connector=CONNECTOR_ID, status=response.status, result=result)
    except HTTPError as exc:
        return urirun.fail("Subactor Control rejected lifecycle reconciliation", connector=CONNECTOR_ID, status=exc.code)
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return urirun.fail("Subactor Control lifecycle endpoint is unavailable", connector=CONNECTOR_ID, error_type=type(exc).__name__)


@conn.handler(
    ROUTE,
    isolated=True,
    external=True,
    meta={"label": "Reconcile governed ticket lifecycle through the canonical Control preflight"},
)
def reconcile_lifecycle(ticket_id: str = "", apply: bool = False) -> dict[str, Any]:
    """Observe one ticket or the bounded lifecycle queue; never mutate broadly."""
    clean_ticket_id = str(ticket_id or "").strip()
    if clean_ticket_id and not re.fullmatch(r"PLF-[0-9]+", clean_ticket_id):
        return urirun.fail("invalid_ticket_id", connector=CONNECTOR_ID)
    if apply is not False:
        return urirun.fail("apply_must_equal_false", connector=CONNECTOR_ID)
    payload: dict[str, Any] = {"apply": False}
    if clean_ticket_id:
        payload["ticket_id"] = clean_ticket_id
    return _call_control(payload)


def bindings() -> dict[str, Any]:
    return conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return bindings()


def manifest() -> dict[str, Any]:
    document = urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}
    document["routes"] = sorted(bindings()["bindings"])
    return document

