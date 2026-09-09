"""Exact URI adapter for grant-gated credential harvest into the private Vault.

The route is the missing runtime seam for the ``harvest-credential`` process in
the ``plesk_system_profile_not_ready`` remediation plan: the LLM Account Hub
implements the harvest (``POST /v1/commands/harvest``) but no connector
registered the ``hub://`` scheme, so the URI node could not dispatch it.

Fail-closed rules:

* endpoint and token come from the deployment environment only — never from the
  actor payload;
* a live ``credential.harvest`` grant issued by the Control authority is
  required. This adapter never issues authority for itself;
* ``account_id`` comes from the plan payload or
  ``SUBACTOR_LLM_ACCOUNT_HUB_HARVEST_ACCOUNT`` (default ``prototypowanie``);
* the response is reduced to references (vault entry id, source kind, counts).
  A secret value must never cross this boundary, so unknown fields are dropped
  rather than forwarded.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import urirun

CONNECTOR_ID = "subactor-credential-harvest"
ROUTE = "hub://host/credential/command/harvest"
REQUIRED_GRANT_SCOPE = "credential.harvest"
DEFAULT_HARVEST_ACCOUNT = "prototypowanie"

# The hub answers with references only. Anything outside this set is dropped so
# a future hub change cannot silently start leaking a value through the URI node.
SAFE_RESULT_FIELDS = frozenset({
    "ok",
    "provider",
    "account_id",
    "grant_id",
    "vault_entry_id",
    "vault_path",
    "entry_id",
    "lease_id",
    "label",
    "origin",
    "source_kind",
    "counts",
    "credential_ref",
    "harvested",
    "stored",
    "ticket",
    "command_id",
    "audit_event",
})

_ACCOUNT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_GRANT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_TICKET = re.compile(r"^PLF-[0-9]+$")

conn = urirun.connector(CONNECTOR_ID, scheme="hub")


def _hub_base() -> str:
    for name in ("SUBACTOR_LLM_ACCOUNT_HUB_URL", "LLM_ACCOUNT_HUB_URL"):
        value = os.environ.get(name, "").strip().rstrip("/")
        if value:
            return value
    return ""


def _hub_token() -> str:
    for name in ("SUBACTOR_LLM_ACCOUNT_HUB_TOKEN", "LLM_ACCOUNT_HUB_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    for name in ("SUBACTOR_LLM_ACCOUNT_HUB_TOKEN_FILE", "LLM_ACCOUNT_HUB_TOKEN_FILE"):
        path = os.environ.get(name, "").strip()
        if path:
            with open(path, "r", encoding="utf-8") as stream:
                return stream.read(8192).strip()
    return ""


def _default_account_id() -> str:
    for name in ("SUBACTOR_LLM_ACCOUNT_HUB_HARVEST_ACCOUNT", "LLM_ACCOUNT_HUB_HARVEST_ACCOUNT"):
        value = os.environ.get(name, "").strip().lower()
        if value:
            return value
    return DEFAULT_HARVEST_ACCOUNT


def _validated_credential_ref(value: str) -> str:
    """Validate an opaque Inventory reference without treating it as authority."""
    raw = str(value or "")
    if not raw:
        return ""
    if (
        raw != raw.strip()
        or len(raw) > 512
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw)
    ):
        raise ValueError("invalid_credential_ref")
    try:
        parsed = urlsplit(raw)
        user_info_present = bool(parsed.username or parsed.password)
    except ValueError as exc:
        raise ValueError("invalid_credential_ref") from exc
    if (
        not raw.startswith("credential-ref://")
        or parsed.scheme != "credential-ref"
        or not parsed.netloc
        or not parsed.path.strip("/")
        or parsed.query
        or parsed.fragment
        or user_info_present
    ):
        raise ValueError("invalid_credential_ref")
    return raw


def _safe_result(result: dict[str, Any]) -> dict[str, Any]:
    """Keep reference fields only and report how many were dropped."""
    kept = {key: value for key, value in result.items() if key in SAFE_RESULT_FIELDS}
    dropped = len(result) - len(kept)
    if dropped:
        kept["dropped_fields"] = dropped
    return kept


def _hub_request(path: str, payload: dict[str, Any], *, timeout: float = 120.0) -> dict[str, Any]:
    base = _hub_base()
    if not base:
        return urirun.fail("LLM_ACCOUNT_HUB_URL is not configured", connector=CONNECTOR_ID)
    try:
        token = _hub_token()
    except (OSError, ValueError):
        return urirun.fail("LLM_ACCOUNT_HUB_TOKEN_FILE is unavailable", connector=CONNECTOR_ID)
    if not token:
        return urirun.fail("LLM_ACCOUNT_HUB_TOKEN is not configured", connector=CONNECTOR_ID)
    request = Request(
        base + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "accept": "application/json",
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": "urirun-connector-subactor-credential-harvest/0.1",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(1024 * 1024).decode("utf-8", errors="replace")
            result = json.loads(raw) if raw else {}
            if not isinstance(result, dict):
                return urirun.fail("hub returned a non-object result", connector=CONNECTOR_ID)
            return {
                "ok": True,
                "status": response.status,
                "result": result,
            }
    except HTTPError as exc:
        detail = ""
        try:
            body = exc.read(4096).decode("utf-8", errors="replace")
            parsed = json.loads(body) if body else {}
            detail = str(parsed.get("message") or parsed.get("error") or "")[:200]
        except Exception:  # noqa: BLE001
            detail = ""
        return urirun.fail(
            detail or "hub refused the harvest command",
            connector=CONNECTOR_ID,
            status=exc.code,
        )
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return urirun.fail(
            "hub harvest endpoint is unavailable",
            connector=CONNECTOR_ID,
            error_type=type(exc).__name__,
        )


@conn.handler(
    ROUTE,
    isolated=True,
    external=True,
    meta={"label": "Harvest a provider credential from an isolated hub profile into the private Vault"},
)
def harvest_credential(
    provider: str = "",
    account_id: str = "",
    grant_id: str = "",
    grant_scope: str = "",
    vault_entry_id: str = "",
    source_ticket_id: str = "",
    credential_ref: str = "",
) -> dict[str, Any]:
    """Dispatch one grant-gated harvest; never accept or return a secret value.

    The parameter names mirror the remediation plan payload exactly — urirun
    drops keys that fall outside the handler signature, so a rename here
    silently discards the caller's input.
    """
    clean_provider = str(provider or "").strip().lower()
    if not _ACCOUNT.match(clean_provider):
        return urirun.fail("invalid_provider", connector=CONNECTOR_ID)

    clean_account = str(account_id or "").strip().lower() or _default_account_id()
    if not _ACCOUNT.match(clean_account):
        return urirun.fail("missing_account_id", connector=CONNECTOR_ID)

    clean_scope = str(grant_scope or REQUIRED_GRANT_SCOPE).strip()
    if clean_scope != REQUIRED_GRANT_SCOPE:
        return urirun.fail("invalid_grant_scope", connector=CONNECTOR_ID)

    clean_entry = str(vault_entry_id or "").strip().lower()
    if clean_entry and not _ACCOUNT.match(clean_entry):
        return urirun.fail("invalid_vault_entry_id", connector=CONNECTOR_ID)

    clean_ticket = str(source_ticket_id or "").strip()
    if clean_ticket and not _TICKET.match(clean_ticket):
        return urirun.fail("invalid_source_ticket_id", connector=CONNECTOR_ID)

    try:
        clean_credential_ref = _validated_credential_ref(credential_ref)
    except ValueError:
        return urirun.fail("invalid_credential_ref", connector=CONNECTOR_ID)

    clean_grant = str(grant_id or "").strip().lower()
    if not clean_grant:
        return urirun.fail("missing_grant_id", connector=CONNECTOR_ID)
    if not _GRANT.match(clean_grant):
        return urirun.fail("invalid_grant_id", connector=CONNECTOR_ID)

    hub_payload = {
        "provider": clean_provider,
        "account_id": clean_account,
        "grant_id": clean_grant,
        "vault_path": clean_entry,
        "ticket": clean_ticket,
    }
    endpoint = "/v1/commands/harvest-auto"
    if clean_credential_ref:
        # Never send the selector to the legacy endpoint: an older Hub may
        # ignore unknown fields and perform a broad provider/origin harvest.
        endpoint = "/v1/commands/harvest-reference"
        hub_payload["credential_ref"] = clean_credential_ref
    harvest = _hub_request(endpoint, hub_payload)
    if not harvest.get("ok"):
        return harvest
    raw_result = harvest.get("result") or {}
    if clean_credential_ref and raw_result.get("credential_ref") != clean_credential_ref:
        return urirun.fail("hub_credential_ref_mismatch", connector=CONNECTOR_ID)
    result = _safe_result(raw_result)
    result["grant_id"] = clean_grant
    result["account_id"] = clean_account
    return urirun.ok(
        connector=CONNECTOR_ID,
        status=harvest.get("status", 200),
        result=result,
    )


def bindings() -> dict[str, Any]:
    return conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return bindings()


def manifest() -> dict[str, Any]:
    document = urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}
    document["routes"] = sorted(bindings()["bindings"])
    return document
