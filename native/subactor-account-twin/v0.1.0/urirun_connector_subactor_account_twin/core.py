"""Fixed URI Process queries over the Subactor account Digital Twin.

The connector is deliberately thin. `twin-subactor` owns collection, secret
redaction, SQLite and source provenance; this adapter only validates bounded
query arguments and forwards them to the deployment-selected internal service.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

import urirun

CONNECTOR_ID = "subactor-account-twin"
SCHEMA = "subactor.account-twin-uri/v1"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
RESOURCES = (
    "summary",
    "sources",
    "organizations",
    "repositories",
    "projects",
    "tickets",
    "deployments",
    "project-reconciliations",
    "combinations",
    "entities",
)
ROUTES = {resource: f"twin://subactor/account/query/{resource}" for resource in RESOURCES}
_FILTER = re.compile(r"^[^\x00-\x1f\x7f]{0,160}$")

conn = urirun.connector(CONNECTOR_ID, scheme="twin")


def _base_url() -> str:
    value = os.environ.get("TWIN_SUBACTOR_URL", "http://127.0.0.1:8188").strip().rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
        return ""
    return value


def _bounded_filter(value: Any, name: str) -> tuple[str, dict[str, Any] | None]:
    selected = str(value or "").strip()
    if not _FILTER.fullmatch(selected):
        return "", urirun.fail(f"invalid_{name}", connector=CONNECTOR_ID)
    return selected, None


def _query(
    resource: str,
    *,
    organization: str = "",
    project: str = "",
    status: str = "",
    source: str = "",
    query: str = "",
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    if resource not in RESOURCES:
        return urirun.fail("invalid_resource", connector=CONNECTOR_ID)
    try:
        selected_limit = int(limit)
        selected_offset = int(offset)
    except (TypeError, ValueError):
        return urirun.fail("invalid_pagination", connector=CONNECTOR_ID)
    if not 1 <= selected_limit <= 1000 or not 0 <= selected_offset <= 1_000_000:
        return urirun.fail("invalid_pagination", connector=CONNECTOR_ID)
    params: dict[str, Any] = {"limit": selected_limit, "offset": selected_offset}
    for name, raw in (
        ("organization", organization),
        ("project", project),
        ("status", status),
        ("source", source),
        ("q", query),
    ):
        selected, error = _bounded_filter(raw, name)
        if error:
            return error
        if selected:
            params[name] = selected
    base = _base_url()
    if not base:
        return urirun.fail("TWIN_SUBACTOR_URL is invalid", connector=CONNECTOR_ID)
    request = Request(
        f"{base}/v1/account/{resource}?{urlencode(params)}",
        headers={"accept": "application/json", "user-agent": "urirun-connector-subactor-account-twin/0.1"},
    )
    try:
        with urlopen(request, timeout=15) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            return urirun.fail("account_twin_response_too_large", connector=CONNECTOR_ID)
        document = json.loads(raw)
        if not isinstance(document, dict) or not str(document.get("schema", "")).startswith("subactor.account-twin."):
            return urirun.fail("account_twin_response_invalid", connector=CONNECTOR_ID)
        return urirun.ok(connector=CONNECTOR_ID, schema=SCHEMA, result=document)
    except HTTPError as error:
        return urirun.fail("account_twin_query_refused", connector=CONNECTOR_ID, status=int(error.code))
    except (OSError, ValueError, json.JSONDecodeError, URLError, TimeoutError) as error:
        return urirun.fail(
            "account_twin_unavailable",
            connector=CONNECTOR_ID,
            error_type=type(error).__name__,
        )


def _handler(resource: str):
    @conn.handler(
        ROUTES[resource],
        isolated=True,
        external=False,
        meta={"label": f"Query Subactor account Twin {resource}"},
    )
    def query_resource(
        organization: str = "",
        project: str = "",
        status: str = "",
        source: str = "",
        query: str = "",
        limit: int = 200,
        offset: int = 0,
    ) -> dict[str, Any]:
        return _query(
            resource,
            organization=organization,
            project=project,
            status=status,
            source=source,
            query=query,
            limit=limit,
            offset=offset,
        )

    query_resource.__name__ = f"query_{resource.replace('-', '_')}"
    return query_resource


for _resource in RESOURCES:
    globals()[f"query_{_resource.replace('-', '_')}"] = _handler(_resource)


def bindings() -> dict[str, Any]:
    return conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return bindings()


def manifest() -> dict[str, Any]:
    document = urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}
    document["routes"] = sorted(bindings()["bindings"])
    return document
