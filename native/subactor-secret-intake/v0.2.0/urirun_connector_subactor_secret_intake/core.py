"""Exact URI adapters for Subactor secret-intake (Control-mediated, secret-free)."""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

import urirun

CONNECTOR_ID = "subactor-secret-intake"
REQUEST_ROUTE = "browser://host/secret-intake/command/request"
CONSUME_ROUTE = "browser://host/secret-intake/command/consume"
ALLOWED_PROVIDERS = frozenset({"plesk", "mailbox", "smtp", "cloudflare", "deployment"})
TICKET_RE = re.compile(r"^PLF-[0-9]+$")
DNS_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
VAULT_ENTRY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
CREDENTIAL_SOURCE_ID_RE = re.compile(r"^credential-source-[a-f0-9]{24}$")
conn = urirun.connector(CONNECTOR_ID, scheme="browser")


def _control_token() -> str:
    token = os.environ.get("SUBACTOR_CONTROL_TOKEN", "").strip()
    token_file = os.environ.get("SUBACTOR_CONTROL_TOKEN_FILE", "").strip()
    if token or not token_file:
        return token
    with open(token_file, "r", encoding="utf-8") as stream:
        return stream.read(8192).strip()


def _call_control(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    base = os.environ.get("SUBACTOR_CONTROL_URL", "").strip().rstrip("/")
    if not base:
        return urirun.fail("SUBACTOR_CONTROL_URL is not configured", connector=CONNECTOR_ID)
    try:
        token = _control_token()
    except (OSError, ValueError):
        return urirun.fail("SUBACTOR_CONTROL_TOKEN_FILE is unavailable", connector=CONNECTOR_ID)
    if not token:
        return urirun.fail("SUBACTOR_CONTROL_TOKEN is not configured", connector=CONNECTOR_ID)
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
        "user-agent": "urirun-connector-subactor-secret-intake/0.1",
    }
    if body is not None:
        headers["content-type"] = "application/json"
    request = Request(base + path, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=60.0) as response:
            raw = response.read(8 * 1024 * 1024).decode("utf-8", errors="replace")
            result = json.loads(raw) if raw else {}
            return urirun.ok(connector=CONNECTOR_ID, status=response.status, result=result)
    except HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(4096).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — best-effort error body
            detail = ""
        code = "secret_intake_control_rejected"
        try:
            parsed = json.loads(detail) if detail else {}
            code = str(parsed.get("error") or parsed.get("code") or code)
        except Exception:  # noqa: BLE001
            pass
        return urirun.fail(code, connector=CONNECTOR_ID, status=exc.code)
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return urirun.fail(
            "Subactor Control secret-intake endpoint is unavailable",
            connector=CONNECTOR_ID,
            error_type=type(exc).__name__,
        )


def _ticket_id(source_ticket_id: str = "", ticket_id: str = "") -> str:
    return str(source_ticket_id or ticket_id or "").strip()


def _validate_common(provider: str, ticket: str) -> dict[str, Any] | None:
    clean_provider = str(provider or "").strip()
    if clean_provider not in ALLOWED_PROVIDERS:
        return urirun.fail("provider_not_allowed", connector=CONNECTOR_ID)
    if ticket and not TICKET_RE.fullmatch(ticket):
        return urirun.fail("invalid_ticket_id", connector=CONNECTOR_ID)
    if not ticket:
        return urirun.fail("ticket_id_required", connector=CONNECTOR_ID)
    return None


def _deployment_origin(value: str) -> str:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("deployment_origin_invalid")
    if parsed.scheme != "https" and not loopback:
        raise ValueError("deployment_origin_https_required")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("deployment_origin_credentials_or_parameters_forbidden")
    if parsed.path not in {"", "/"}:
        raise ValueError("deployment_origin_path_forbidden")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _dns_name(value: str, field: str) -> str:
    name = str(value or "").strip().rstrip(".").lower()
    if len(name) > 253 or "." not in name or not DNS_NAME_RE.fullmatch(name):
        raise ValueError(f"{field}_invalid")
    return name


def _vault_entry_id(value: str, field: str) -> str:
    entry_id = str(value or "").strip()
    if not VAULT_ENTRY_ID_RE.fullmatch(entry_id):
        raise ValueError(f"{field}_invalid")
    return entry_id


def _deployment_bindings(
    *,
    deployment_origin: str,
    deployment_domain: str,
    deployment_webspace: str,
    sftp_vault_entry_id: str,
    ftp_vault_entry_id: str,
) -> dict[str, str]:
    origin = _deployment_origin(deployment_origin)
    domain = _dns_name(deployment_domain, "deployment_domain")
    webspace = _dns_name(deployment_webspace, "deployment_webspace")
    if domain != webspace and not domain.endswith(f".{webspace}"):
        raise ValueError("deployment_webspace_domain_mismatch")
    sftp_id = _vault_entry_id(sftp_vault_entry_id, "sftp_vault_entry_id")
    ftp_id = _vault_entry_id(ftp_vault_entry_id, "ftp_vault_entry_id")
    if sftp_id == ftp_id:
        raise ValueError("deployment_vault_entry_ids_must_differ")
    return {
        "deployment_origin": origin,
        "deployment_domain": domain,
        "deployment_webspace": webspace,
        "sftp_vault_entry_id": sftp_id,
        "ftp_vault_entry_id": ftp_id,
    }


def _public_credential_source(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    kind = str(value.get("kind") or "")
    if kind not in {"vault", "environment"}:
        return None
    source_id = str(value.get("source_id") or "")
    scope_target = str(value.get("scope_target") or "")
    try:
        scope_domain = _dns_name(scope_target.removeprefix("domain:"), "credential_source_scope")
    except ValueError:
        return None
    if not CREDENTIAL_SOURCE_ID_RE.fullmatch(source_id) or scope_target != f"domain:{scope_domain}":
        return None
    fields = value.get("fields") if isinstance(value.get("fields"), list) else []
    return {
        "source_id": source_id,
        "kind": kind,
        "scope_target": scope_target,
        "fields": [
            field for field in fields
            if field in {"sftp.username", "sftp.password", "ftp.username", "ftp.password"}
        ],
        "secret_values_included": False,
    }


@conn.handler(
    REQUEST_ROUTE,
    isolated=True,
    external=True,
    meta={"label": "Mint one-time secret-intake form via Control (no secret values)"},
)
def request_intake(
    provider: str = "plesk",
    source_ticket_id: str = "",
    ticket_id: str = "",
    base_url: str = "",
    username: str = "",
    deployment_origin: str = "",
    deployment_domain: str = "",
    deployment_webspace: str = "",
    sftp_vault_entry_id: str = "",
    ftp_vault_entry_id: str = "",
    ttl_seconds: int = 900,
) -> dict[str, Any]:
    """Resolve a deployment profile or create one-time intake; never accepts secrets."""
    ticket = _ticket_id(source_ticket_id, ticket_id)
    invalid = _validate_common(provider, ticket)
    if invalid is not None:
        return invalid
    try:
        ttl = int(ttl_seconds or 900)
    except (TypeError, ValueError):
        return urirun.fail("ttl_seconds_invalid", connector=CONNECTOR_ID)
    if ttl < 60 or ttl > 3600:
        return urirun.fail("ttl_seconds_invalid", connector=CONNECTOR_ID)
    payload: dict[str, Any] = {
        "provider": str(provider).strip(),
        "ticket_id": ticket,
        "ttl_seconds": ttl,
    }
    if str(base_url or "").strip():
        payload["base_url"] = str(base_url).strip()
    if str(username or "").strip():
        payload["username"] = str(username).strip()
    if payload["provider"] == "deployment":
        if "base_url" in payload or "username" in payload:
            return urirun.fail("deployment_legacy_fields_forbidden", connector=CONNECTOR_ID)
        try:
            payload.update(_deployment_bindings(
                deployment_origin=deployment_origin,
                deployment_domain=deployment_domain,
                deployment_webspace=deployment_webspace,
                sftp_vault_entry_id=sftp_vault_entry_id,
                ftp_vault_entry_id=ftp_vault_entry_id,
            ))
        except ValueError as exc:
            return urirun.fail(str(exc), connector=CONNECTOR_ID)
    outcome = _call_control("/api/secret-intake/requests", method="POST", payload=payload)
    if outcome.get("ok") is not True:
        return outcome
    result = outcome.get("result") or {}
    credential_source = _public_credential_source(result.get("credential_source"))
    if result.get("auto_resolved") is True and credential_source is None:
        return urirun.fail("auto_resolved_credential_source_invalid", connector=CONNECTOR_ID)
    # Strip any accidental secret-bearing fields before returning through urirun.
    safe = {
        "provider": payload["provider"],
        "ticket_id": ticket,
        "process_ticket_id": result.get("process_ticket_id"),
        "consume_ticket_id": result.get("consume_ticket_id"),
        "request_id": (result.get("request") or {}).get("id"),
        "expires_at": (result.get("request") or {}).get("expires_at"),
        "auto_resolved": result.get("auto_resolved") is True,
        "credential_source": credential_source,
        "submission_url_present": bool(result.get("submission_url")),
        "secrets_included": False,
    }
    return urirun.ok(connector=CONNECTOR_ID, status=outcome.get("status") or 201, result=safe)


@conn.handler(
    CONSUME_ROUTE,
    isolated=True,
    external=True,
    meta={"label": "Poll secret-intake readiness (waiting_human vs vault ready); never accepts secrets"},
)
def consume_intake(
    provider: str = "plesk",
    source_ticket_id: str = "",
    ticket_id: str = "",
    runtime_vault_entry_id: str = "",
    delivery_channel: str = "",
    operator_hint: str = "",
    operator_note: str = "",
) -> dict[str, Any]:
    """Observe whether human intake completed. Does not accept or forward secrets."""
    ticket = _ticket_id(source_ticket_id, ticket_id)
    invalid = _validate_common(provider, ticket)
    if invalid is not None:
        return invalid
    query = {
        "provider": str(provider).strip(),
        "ticket_id": ticket,
    }
    if str(runtime_vault_entry_id or "").strip():
        query["runtime_vault_entry_id"] = str(runtime_vault_entry_id).strip()
    outcome = _call_control(f"/api/secret-intake/status?{urlencode(query)}", method="GET")
    if outcome.get("ok") is not True:
        return outcome
    status_doc = outcome.get("result") or {}
    intake_status = str(status_doc.get("intake_status") or "missing")
    if intake_status == "ready":
        return urirun.ok(
            connector=CONNECTOR_ID,
            status=200,
            result={
                "intake_status": "ready",
                "provider": status_doc.get("provider"),
                "ticket_id": ticket,
                "runtime_vault_entry_id": status_doc.get("runtime_vault_entry_id"),
                "vault_present": bool(status_doc.get("vault_present")),
                "secrets_included": False,
                "delivery_channel": str(delivery_channel or "") or None,
                "operator_hint": str(operator_hint or "") or None,
            },
        )
    if intake_status == "waiting_human":
        return urirun.fail(
            "secret_intake_waiting_human",
            connector=CONNECTOR_ID,
            status=409,
            intake_status="waiting_human",
            request_id=(status_doc.get("pending_request") or {}).get("id"),
            expires_at=(status_doc.get("pending_request") or {}).get("expires_at"),
            secrets_included=False,
        )
    return urirun.fail(
        "secret_intake_request_missing",
        connector=CONNECTOR_ID,
        status=404,
        intake_status="missing",
        secrets_included=False,
    )


def bindings() -> dict[str, Any]:
    return conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return bindings()


def manifest() -> dict[str, Any]:
    document = urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}
    document["routes"] = sorted(bindings()["bindings"])
    return document
