"""Exact, read-only URI adapter for a managed outbound-tunnel preflight."""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import urirun

CONNECTOR_ID = "subactor-managed-tunnel"
ROUTE = "tunnel://host/outbound/query/preflight"
SCHEMA = "subactor.managed-outbound-tunnel-preflight/v1"
SUPPORTED_PROVIDERS = {"cloudflare", "cloudflare_managed", "cloudflare_tunnel"}
conn = urirun.connector(CONNECTOR_ID, scheme="tunnel")


def _csv_environment(name: str, fallback: str) -> set[str]:
    return {value.strip() for value in os.environ.get(name, fallback).split(",") if value.strip()}


def _probe(url: str, expected_statuses: set[int]) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "accept": "application/json",
            "user-agent": "urirun-connector-subactor-managed-tunnel/0.1",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=10.0) as response:
            status = int(response.status)
            response.read(8192)
    except HTTPError as exc:
        status = int(exc.code)
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "reachable": False,
            "status": None,
            "expected": False,
            "error_type": type(exc).__name__,
        }
    return {
        "reachable": True,
        "status": status,
        "expected": status in expected_statuses,
        "error_type": None,
    }


def _vault_credential_configured() -> tuple[bool, str]:
    base_url = os.environ.get("URIRUN_VAULT_URL", "").strip().rstrip("/")
    service_token = os.environ.get("URIRUN_VAULT_TOKEN", "").strip()
    entry_id = os.environ.get("SUBACTOR_TUNNEL_VAULT_ENTRY_ID", "managed-outbound-tunnel").strip()
    if not base_url or not service_token or not entry_id:
        return False, "vault_unavailable"
    request = Request(
        f"{base_url}/vault",
        headers={
            "accept": "application/json",
            "authorization": f"Bearer {service_token}",
            "user-agent": "urirun-connector-subactor-managed-tunnel/0.1",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=10.0) as response:
            document = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return False, "vault_unavailable"
    entries = document.get("entries", []) if isinstance(document, dict) else []
    return any(str(item.get("id", "")) == entry_id for item in entries if isinstance(item, dict)), "vault"


def _credential_configured() -> tuple[bool, str]:
    configured, source = _vault_credential_configured()
    if configured:
        return configured, source
    if os.environ.get("SUBACTOR_TUNNEL_TOKEN", "").strip():
        return True, "environment"
    token_file = os.environ.get("SUBACTOR_TUNNEL_TOKEN_FILE", "").strip()
    if not token_file:
        return False, "missing"
    try:
        return Path(token_file).is_file() and Path(token_file).stat().st_size > 0, "file"
    except OSError:
        return False, "file_unavailable"


@conn.handler(
    ROUTE,
    isolated=True,
    external=False,
    meta={"label": "Assess managed outbound-tunnel readiness without creating or changing a tunnel"},
)
def preflight(
    hostname: str = "",
    upstream: str = "",
    mode: str = "",
    apply: bool = False,
    authentication_required: bool = True,
    secrets_in_payload: bool = False,
) -> dict[str, Any]:
    """Assess a deployment-controlled tunnel target; never create or mutate it."""
    clean_hostname = str(hostname or "").strip().lower()
    clean_upstream = str(upstream or "").strip()
    allowed_hostnames = _csv_environment("SUBACTOR_TUNNEL_ALLOWED_HOSTS", "founder.subactor.com")
    allowed_upstreams = _csv_environment("SUBACTOR_TUNNEL_ALLOWED_UPSTREAMS", "http://127.0.0.1:8091")
    if clean_hostname not in allowed_hostnames:
        return urirun.fail("hostname_not_allowed", connector=CONNECTOR_ID, schema=SCHEMA)
    if clean_upstream not in allowed_upstreams:
        return urirun.fail("upstream_not_allowed", connector=CONNECTOR_ID, schema=SCHEMA)
    if mode != "read_only" or apply is not False:
        return urirun.fail("read_only_preflight_required", connector=CONNECTOR_ID, schema=SCHEMA)
    if authentication_required is not True or secrets_in_payload is not False:
        return urirun.fail("security_contract_invalid", connector=CONNECTOR_ID, schema=SCHEMA)

    control_url = os.environ.get("SUBACTOR_CONTROL_URL", "http://hr-control:8181").strip().rstrip("/")
    health = _probe(f"{control_url}/health", {200})
    authentication = _probe(f"{control_url}/api/me", {401, 403})
    provider = os.environ.get("SUBACTOR_TUNNEL_PROVIDER", "").strip().lower()
    credential_configured, credential_source = _credential_configured()
    if not provider and credential_configured and credential_source == "vault":
        provider = "cloudflare_managed"
    blockers: list[str] = []
    if not health["expected"]:
        blockers.append("control_upstream_unreachable")
    if not authentication["expected"]:
        blockers.append("authenticated_upstream_boundary_not_observed")
    if not provider:
        blockers.append("tunnel_provider_not_configured")
    elif provider not in SUPPORTED_PROVIDERS:
        blockers.append("tunnel_provider_unsupported")
    if not credential_configured:
        blockers.append("tunnel_credential_not_configured")

    ready_for_plan = not blockers
    return urirun.ok(
        connector=CONNECTOR_ID,
        schema=SCHEMA,
        route=ROUTE,
        mode="read_only",
        apply=False,
        hostname=clean_hostname,
        upstream=clean_upstream,
        provider={
            "configured": bool(provider),
            "id": provider or None,
            "supported": bool(provider) and provider in SUPPORTED_PROVIDERS,
        },
        credential={
            "configured": credential_configured,
            "source": credential_source,
            "material_exposed": False,
        },
        upstream_assessment={
            "reachable": health["reachable"],
            "status": health["status"],
            "health_expected": health["expected"],
        },
        authentication_assessment={
            "required": True,
            "challenge_observed": authentication["expected"],
            "status": authentication["status"],
        },
        authenticated_upstream_assessed=True,
        credential_material_not_exposed=True,
        ready_for_plan=ready_for_plan,
        ready_for_apply=False,
        blockers=blockers,
        next_action=(
            "prepare_bounded_tunnel_plan"
            if ready_for_plan
            else "configure_provider_and_secret_via_governed_intake"
        ),
    )


def bindings() -> dict[str, Any]:
    return conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return bindings()


def manifest() -> dict[str, Any]:
    document = urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}
    document["routes"] = sorted(bindings()["bindings"])
    return document
