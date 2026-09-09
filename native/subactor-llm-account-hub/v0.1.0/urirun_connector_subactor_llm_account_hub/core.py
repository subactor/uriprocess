"""Exact URI adapter for account-scoped CLI tools exposed by LLM Account Hub.

The Hub is the execution boundary, while Subactor Control remains the sole
authority boundary. Every request therefore goes through Control's typed Hub
API before a command can run inside the selected account container. This
connector never issues grants, starts intents, selects a host-shell target, or
accepts an upstream URL/token from the actor.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import urirun

CONNECTOR_ID = "subactor-llm-account-hub"
SCHEMA = "subactor.llm-account-hub-uri/v1"
DISCOVERY_ROUTE = "llm-account://host/bindings/query"
STATUS_ROUTE = "llm-account://host/cli/query/status"
PLAN_ROUTE = "llm-account://host/cli/query/plan"
EXECUTE_ROUTE = "llm-account://host/cli/command/execute"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_AUTHORIZATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_PROJECT = re.compile(r"^\.?[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")

conn = urirun.connector(CONNECTOR_ID, scheme="llm-account")


def _control_base() -> str:
    return os.environ.get("SUBACTOR_CONTROL_URL", "").strip().rstrip("/")


def _control_token() -> str:
    for name in ("SUBACTOR_LLM_ACCOUNT_CONTROL_TOKEN", "SUBACTOR_CONTROL_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    for name in ("SUBACTOR_LLM_ACCOUNT_CONTROL_TOKEN_FILE", "SUBACTOR_CONTROL_TOKEN_FILE"):
        path = os.environ.get(name, "").strip()
        if path:
            with open(path, "r", encoding="utf-8") as stream:
                return stream.read(8192).strip()
    return ""


def _request_json(
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 35.0,
) -> dict[str, Any]:
    base = _control_base()
    if not base:
        return urirun.fail("SUBACTOR_CONTROL_URL is not configured", connector=CONNECTOR_ID)
    try:
        token = _control_token()
    except (OSError, ValueError):
        return urirun.fail("SUBACTOR_CONTROL_TOKEN_FILE is unavailable", connector=CONNECTOR_ID)
    if not token:
        return urirun.fail("SUBACTOR_CONTROL_TOKEN is not configured", connector=CONNECTOR_ID)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        base + path,
        data=body,
        headers={
            "accept": "application/json",
            "authorization": f"Bearer {token}",
            **({"content-type": "application/json"} if body is not None else {}),
            "user-agent": "urirun-connector-subactor-llm-account-hub/0.1",
        },
        method=method,
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return urirun.fail("control_response_too_large", connector=CONNECTOR_ID)
            result = json.loads(raw.decode("utf-8")) if raw else {}
            if not isinstance(result, dict):
                return urirun.fail("control returned a non-object result", connector=CONNECTOR_ID)
            return {"ok": True, "status": int(response.status), "result": result}
    except HTTPError as exc:
        remote_error = ""
        try:
            document = json.loads(exc.read(4096).decode("utf-8"))
            candidate = str(document.get("error") or "") if isinstance(document, dict) else ""
            if re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", candidate):
                remote_error = candidate
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        return urirun.fail(
            remote_error or "control refused the governed Hub request",
            connector=CONNECTOR_ID,
            status=int(exc.code),
        )
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return urirun.fail(
            "Control governed Hub endpoint is unavailable",
            connector=CONNECTOR_ID,
            error_type=type(exc).__name__,
        )


def _clean_identifier(value: str, field: str) -> tuple[str, dict[str, Any] | None]:
    clean = str(value or "").strip().lower()
    if not _IDENTIFIER.fullmatch(clean):
        return "", urirun.fail(f"invalid_{field}", connector=CONNECTOR_ID)
    return clean, None


def _clean_project(value: str) -> tuple[str, dict[str, Any] | None]:
    clean = str(value or "").strip()
    if not clean:
        return "", None
    if clean in {".", ".."} or not _PROJECT.fullmatch(clean):
        return "", urirun.fail("invalid_project", connector=CONNECTOR_ID)
    return clean, None


def _clean_arguments(value: Any) -> tuple[list[str], dict[str, Any] | None]:
    if value is None:
        return [], None
    if not isinstance(value, list) or len(value) > 64 or not all(isinstance(item, str) for item in value):
        return [], urirun.fail("invalid_arguments", connector=CONNECTOR_ID)
    if any(len(item) > 8192 for item in value):
        return [], urirun.fail("invalid_arguments", connector=CONNECTOR_ID)
    return value, None


def _scope(account_id: str, provider: str, tool_id: str) -> tuple[dict[str, str], dict[str, Any] | None]:
    account, error = _clean_identifier(account_id, "account_id")
    if error:
        return {}, error
    clean_provider, error = _clean_identifier(provider, "provider")
    if error:
        return {}, error
    tool, error = _clean_identifier(tool_id, "tool_id")
    if error:
        return {}, error
    return {"account_id": account, "provider": clean_provider, "tool_id": tool}, None


def _execution_arguments(
    *,
    project: str,
    arguments: Any,
    stdin: str,
    timeout_seconds: int,
    valid_until: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    clean_project, error = _clean_project(project)
    if error:
        return {}, error
    clean_arguments, error = _clean_arguments(arguments)
    if error:
        return {}, error
    clean_stdin = str(stdin or "")
    if len(clean_stdin) > 100_000:
        return {}, urirun.fail("stdin_too_large", connector=CONNECTOR_ID)
    try:
        clean_timeout = int(timeout_seconds)
    except (TypeError, ValueError):
        return {}, urirun.fail("invalid_timeout_seconds", connector=CONNECTOR_ID)
    if clean_timeout < 1 or clean_timeout > 300:
        return {}, urirun.fail("invalid_timeout_seconds", connector=CONNECTOR_ID)
    return {
        "project": clean_project,
        "arguments": clean_arguments,
        "stdin": clean_stdin,
        "timeout_seconds": clean_timeout,
        "valid_until": str(valid_until or "").strip(),
    }, None


@conn.handler(
    DISCOVERY_ROUTE,
    isolated=True,
    external=True,
    meta={"label": "List account/provider/tool MCP bindings without credential material"},
)
def list_bindings(account_id: str = "") -> dict[str, Any]:
    clean_account = str(account_id or "").strip().lower()
    if clean_account and not _IDENTIFIER.fullmatch(clean_account):
        return urirun.fail("invalid_account_id", connector=CONNECTOR_ID)
    query = f"?{urlencode({'account_id': clean_account})}" if clean_account else ""
    response = _request_json(f"/api/llm-account-hub/mcp{query}")
    if not response.get("ok"):
        return response
    document = response.get("result") or {}
    safe_fields = {
        "account_id", "email", "provider", "tool_id", "state", "transport",
        "endpoint", "resource", "read_access", "execute_access", "required_scope", "subject",
    }
    endpoints = [
        {key: item[key] for key in safe_fields if key in item}
        for item in document.get("endpoints", [])
        if isinstance(item, dict)
    ]
    return urirun.ok(
        connector=CONNECTOR_ID,
        schema=SCHEMA,
        authority=document.get("authority"),
        endpoints=endpoints,
        count=len(endpoints),
    )


@conn.handler(
    STATUS_ROUTE,
    isolated=True,
    external=True,
    meta={"label": "Read one exact account/provider/tool CLI binding through Control"},
)
def cli_status(account_id: str = "", provider: str = "", tool_id: str = "") -> dict[str, Any]:
    scope, error = _scope(account_id, provider, tool_id)
    if error:
        return error
    query = f"?{urlencode({'account_id': scope['account_id']})}"
    response = _request_json(f"/api/llm-account-hub/cli{query}")
    if not response.get("ok"):
        return response
    inventory = response.get("result") or {}
    try:
        container = next(
            item for item in inventory.get("containers", [])
            if item.get("account_id") == scope["account_id"]
        )
        provider_item = next(
            item for item in container.get("providers", [])
            if item.get("id") == scope["provider"]
        )
        tool = next(
            item for item in provider_item.get("tools", [])
            if item.get("id") == scope["tool_id"]
        )
    except StopIteration:
        return urirun.fail("cli_binding_not_found", connector=CONNECTOR_ID)
    mcp = tool.get("mcp") or {}
    binding = {
        "account_id": container.get("account_id"),
        "email": container.get("email"),
        "provider": provider_item.get("id"),
        "tool": tool,
        "container_name": container.get("container_name"),
        "runtime_status": container.get("runtime_status"),
        "runtime_health": container.get("runtime_health"),
        "execution_location": container.get("execution_location"),
        "resource": mcp.get("resource"),
        "required_scope": mcp.get("required_scope"),
        "arbitrary_shell": inventory.get("arbitrary_shell") is True,
    }
    return urirun.ok(connector=CONNECTOR_ID, schema=SCHEMA, result=binding)


@conn.handler(
    PLAN_ROUTE,
    isolated=True,
    external=True,
    meta={"label": "Plan one exact account-container CLI execution without running it"},
)
def cli_plan(
    account_id: str = "",
    provider: str = "",
    tool_id: str = "",
    project: str = "",
    arguments: Any = None,
    stdin: str = "",
    timeout_seconds: int = 120,
    valid_until: str = "",
) -> dict[str, Any]:
    scope, error = _scope(account_id, provider, tool_id)
    if error:
        return error
    execution, error = _execution_arguments(
        project=project,
        arguments=arguments,
        stdin=stdin,
        timeout_seconds=timeout_seconds,
        valid_until=valid_until,
    )
    if error:
        return error
    response = _request_json(
        "/api/llm-account-hub/cli/plan",
        method="POST",
        payload={**scope, **execution},
        timeout=35.0,
    )
    if not response.get("ok"):
        return response
    document = response.get("result") or {}
    plan = document.get("plan")
    if document.get("ok") is not True or not isinstance(plan, dict):
        return urirun.fail("control_cli_plan_invalid", connector=CONNECTOR_ID)
    return urirun.ok(connector=CONNECTOR_ID, schema=SCHEMA, result=plan)


@conn.handler(
    EXECUTE_ROUTE,
    isolated=True,
    external=True,
    meta={"label": "Execute an authorized exact CLI plan inside one account container"},
)
def cli_execute(
    account_id: str = "",
    provider: str = "",
    tool_id: str = "",
    project: str = "",
    arguments: Any = None,
    stdin: str = "",
    timeout_seconds: int = 120,
    valid_until: str = "",
    execution_id: str = "",
    plan_hash: str = "",
    grant_id: str = "",
    intent_id: str = "",
    ticket: str = "",
) -> dict[str, Any]:
    scope, error = _scope(account_id, provider, tool_id)
    if error:
        return error
    execution, error = _execution_arguments(
        project=project,
        arguments=arguments,
        stdin=stdin,
        timeout_seconds=timeout_seconds,
        valid_until=valid_until,
    )
    if error:
        return error
    authorization = {
        "execution_id": str(execution_id or "").strip(),
        "plan_hash": str(plan_hash or "").strip(),
        "grant_id": str(grant_id or "").strip(),
        "intent_id": str(intent_id or "").strip(),
    }
    for field, value in authorization.items():
        if not value:
            return urirun.fail(f"missing_{field}", connector=CONNECTOR_ID)
        if not _AUTHORIZATION_ID.fullmatch(value):
            return urirun.fail(f"invalid_{field}", connector=CONNECTOR_ID)
    response = _request_json(
        "/api/llm-account-hub/cli/execute",
        method="POST",
        payload={
            **scope,
            **execution,
            **authorization,
            "ticket": str(ticket or "").strip(),
        },
        timeout=float(execution["timeout_seconds"] + 10),
    )
    if not response.get("ok"):
        return response
    document = response.get("result") or {}
    if document.get("ok") is not True:
        return urirun.fail("control_cli_execution_failed", connector=CONNECTOR_ID)
    return urirun.ok(connector=CONNECTOR_ID, schema=SCHEMA, result=document)


def bindings() -> dict[str, Any]:
    return conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return bindings()


def manifest() -> dict[str, Any]:
    document = urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}
    document["routes"] = sorted(bindings()["bindings"])
    return document
