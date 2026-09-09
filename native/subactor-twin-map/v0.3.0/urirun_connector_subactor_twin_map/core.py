"""Capability-map URI Process over uri-twin baselines.

A connector answers "do this". This one answers the question that has to be
settled first: *can* this be done on this instance, by which connectors, with
which credentials — and if not, what single thing is missing.

Without that answer a task enters a connector, fails on a precondition nobody
declared, and the failure escalates into a ticket that asks a human to
rediscover a fact the system already had. The map turns that into either an
ordered plan or one named gap.

Baseline comes from git (github.com/uri-twin), shipped as package data and
loaded at import. Live observation may only downgrade a capability or satisfy a
feature flag; it can never introduce one that was not reviewed in the baseline.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
import os
from pathlib import Path
import re
from typing import Any

import urirun

from .baseline_loader import BaselineSnapshot, load_baseline

CONNECTOR_ID = "subactor-twin-map"
MAP_SCHEMA = "uri-twin.map/v1"

EXECUTABLE = "executable"
CREDENTIAL_MISSING = "credential-missing"
DISCOVERY_ONLY = "discovery-only"
PRECONDITION_BLOCKED = "precondition-blocked"
ABSENT = "absent"
SECRETISH = re.compile(r"(password|secret|token|api[_-]?key|authorization)", re.I)
PROPOSAL_SECRETISH = re.compile(r"(authorization|password|secret|token|api[_-]?key|credential)", re.I)
SAFE_PROPOSAL_ATTRIBUTES = {"active", "category", "name", "vendor", "version"}

MAP_ROUTE = "twin://plesk/map/query/snapshot"
RESOLVE_ROUTE = "twin://plesk/map/query/resolve"
REFRESH_ROUTE = "twin://plesk/map/query/refresh"
PROPOSAL_ROUTE = "twin://plesk/map/query/proposal"
CONFORMANCE_ROUTE = "twin://plesk/map/query/conformance"
ATTESTATION_ROUTE = "twin://plesk/map/query/attestation"

conn = urirun.connector(CONNECTOR_ID, scheme="twin")

def _embedded_baseline(family: str = "plesk") -> dict[str, Any]:
    package = resources.files(__package__) / "baseline" / f"{family}-surface.v1.json"
    return json.loads(package.read_text(encoding="utf-8"))


BASELINE_SNAPSHOT: BaselineSnapshot = load_baseline(fallback=_embedded_baseline())
BASELINE = BASELINE_SNAPSHOT.document
INTENTS: dict[str, list[str]] = {
    name: [str(item) for item in workflow.get("requires", [])]
    for name, workflow in (BASELINE.get("workflows") or {}).items()
}


def reload_baseline() -> BaselineSnapshot:
    global BASELINE_SNAPSHOT, BASELINE, INTENTS
    BASELINE_SNAPSHOT = load_baseline(fallback=_embedded_baseline())
    BASELINE = BASELINE_SNAPSHOT.document
    INTENTS = {
        name: [str(item) for item in workflow.get("requires", [])]
        for name, workflow in (BASELINE.get("workflows") or {}).items()
    }
    return BASELINE_SNAPSHOT


def _stable(value: Any) -> Any:
    if isinstance(value, list):
        return [_stable(item) for item in value]
    if isinstance(value, dict):
        return {key: _stable(value[key]) for key in sorted(value)}
    return value


def _canonical_provider(value: dict[str, Any] | None) -> dict[str, Any]:
    provider = value or {}
    bindings = {
        str(key): sorted(str(item) for item in value) if isinstance(value, list) else str(value)
        for key, value in (provider.get("requires_bindings") or {}).items()
    }
    return {
        "connector": str(provider.get("connector") or ""),
        "uri": str(provider.get("uri") or ""),
        "preconditions": sorted(str(item) for item in provider.get("preconditions", [])),
        "requires_credentials": sorted(str(item) for item in provider.get("requires_credentials", [])),
        "requires_feature_flags": sorted(str(item) for item in provider.get("requires_feature_flags", [])),
        "requires_bindings": _stable(bindings),
    }


def _canonical_capability(entry: dict[str, Any]) -> dict[str, Any]:
    selected = entry.get("selected_provider")
    return {
        "id": str(entry.get("id") or ""),
        "effect": str(entry.get("effect") or ""),
        "transport": str(entry.get("transport") or ""),
        "status": str(entry.get("status") or "available"),
        "risk": str(entry.get("risk") or ""),
        "execution_policy": str(entry.get("execution_policy") or ""),
        "requires_capabilities": sorted(str(item) for item in entry.get("requires_capabilities", [])),
        "requires_credentials": sorted(str(item) for item in entry.get("requires_credentials", [])),
        "produces_credentials": sorted(str(item) for item in entry.get("produces_credentials", [])),
        "requires_feature_flags": sorted(str(item) for item in entry.get("requires_feature_flags", [])),
        "provided_by": [_canonical_provider(provider) for provider in entry.get("provided_by", [])],
        "blockers": sorted(
            ({"kind": str(blocker.get("kind") or ""), "detail": str(blocker.get("detail") or "")}
             for blocker in entry.get("blockers", [])),
            key=lambda blocker: f"{blocker['kind']}\0{blocker['detail']}",
        ),
        "selected_provider": None if not selected else {
            "connector": str(selected.get("connector") or ""),
            "uri": str(selected.get("uri") or ""),
        },
    }


def _reject_secret_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            if SECRETISH.search(str(key)):
                raise ValueError(f"map_resource_secret_key_forbidden:{path}.{key}")
            _reject_secret_keys(item, f"{path}.{key}")


def _project_twin_facts(observed: dict[str, Any]) -> dict[str, Any]:
    projected = _stable(observed)
    capabilities = dict(projected.get("capabilities") or {})
    bindings = dict(projected.get("bindings") or {})
    resources_seen = list(projected.get("resources") or [])
    for fact in projected.get("twin_facts") or []:
        if not isinstance(fact, dict):
            continue
        twin_type = str(fact.get("twin_type") or "")
        payload = fact.get("payload") if isinstance(fact.get("payload"), dict) else {}
        quality = str(fact.get("fact_quality") or "")
        if twin_type == "plesk.site.docroot":
            domain = str(payload.get("domain") or "")
            if domain:
                resources_seen.append({
                    "type": "plesk.site", "id": domain, "service": "plesk-xml-api",
                    "attributes": {
                        "domain": domain,
                        "docroot": payload.get("expected") or payload.get("observed") or payload.get("docroot"),
                    },
                })
            if quality != "fresh" or payload.get("decision") == "refuse":
                capabilities["plesk.site.publish"] = {
                    "state": "blocked",
                    "blockers": [{
                        "kind": "fact_refused" if payload.get("decision") == "refuse" else "fact_not_fresh",
                        "detail": "plesk.site.docroot",
                    }],
                }
        elif twin_type == "plesk.dns.authority":
            hostname = str(payload.get("hostname") or "")
            plane = str(payload.get("management_plane") or "")
            if hostname:
                resources_seen.append({
                    "type": "dns.zone", "id": hostname, "service": "plesk-xml-api",
                    "attributes": {"hostname": hostname, "management_plane": plane},
                })
            if plane:
                bindings["dns_management_plane"] = plane
        elif twin_type == "plesk.subscription":
            for subscription in payload.get("subscriptions") or []:
                if not isinstance(subscription, dict):
                    continue
                resource_id = str(subscription.get("id") or subscription.get("name") or "")
                if resource_id:
                    resources_seen.append({
                        "type": "plesk.subscription", "id": resource_id, "service": "plesk-xml-api",
                        "attributes": {
                            "name": subscription.get("name"),
                            "domains_limit": subscription.get("domains_limit"),
                            "domains_used": subscription.get("domains_used"),
                        },
                    })
    projected["capabilities"] = capabilities
    projected["bindings"] = bindings
    projected["resources"] = resources_seen
    return projected


def _presence(capability_id: str, observed: dict[str, Any]) -> str:
    state = (observed.get("capabilities") or {}).get(capability_id)
    if state is None:
        return "present"
    if isinstance(state, dict):
        return str(state.get("state") or "present")
    if state is False:
        return ABSENT
    if state == DISCOVERY_ONLY:
        return DISCOVERY_ONLY
    return "present"


def _provider_blockers(
    capability: dict[str, Any], provider: dict[str, Any], observed: dict[str, Any], held: set[str],
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    connectors = observed.get("connectors")
    routes = observed.get("routes")
    flags = observed.get("feature_flags") or {}
    bindings = observed.get("bindings") or {}
    if isinstance(connectors, list) and provider.get("connector") not in connectors:
        blockers.append({"kind": "connector_unavailable", "detail": str(provider.get("connector") or "")})
    if isinstance(routes, list) and provider.get("uri") not in routes:
        blockers.append({"kind": "route_unavailable", "detail": str(provider.get("uri") or "")})
    for flag in provider.get("requires_feature_flags", []):
        if flags.get(flag) is not True:
            blockers.append({"kind": "feature_flag_off", "detail": str(flag)})
    for name, expected in (provider.get("requires_bindings") or {}).items():
        accepted = sorted(str(item) for item in expected) if isinstance(expected, list) else [str(expected)]
        if str(bindings.get(name, "")) not in accepted:
            blockers.append({"kind": "binding_mismatch", "detail": f"{name}={'|'.join(accepted)}"})
    required = [*capability.get("requires_credentials", []), *provider.get("requires_credentials", [])]
    for handle in required:
        if handle not in held:
            blockers.append({"kind": "credential_missing", "detail": str(handle)})
    return blockers


def _select_provider(
    capability: dict[str, Any], observed: dict[str, Any], held: set[str],
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    first: tuple[dict[str, Any] | None, list[dict[str, str]]] = (None, [{"kind": "provider_missing", "detail": capability["id"]}])
    for index, provider in enumerate(capability.get("provided_by", [])):
        blockers = _provider_blockers(capability, provider, observed, held)
        if index == 0:
            first = (provider, blockers)
        if not blockers:
            return provider, []
    return first


def _inventory(document: dict[str, Any], observed: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    reviewed = {str(item.get("id") or "") for item in document.get("resource_types", [])}
    resources_seen: list[dict[str, Any]] = []
    discoveries: list[dict[str, str]] = []
    for item in observed.get("resources", []):
        if not isinstance(item, dict):
            continue
        resource_type = str(item.get("type") or "")
        resource_id = str(item.get("id") or "")
        if not resource_type or not resource_id:
            continue
        if resource_type not in reviewed:
            discoveries.append({"type": resource_type, "id": resource_id, "status": "review-required"})
            continue
        attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        _reject_secret_keys(attributes, f"resources.{resource_type}.{resource_id}")
        resources_seen.append({
            "type": resource_type,
            "id": resource_id,
            "service": str(item.get("service") or ""),
            "attributes": _stable(attributes),
        })
    resources_seen = list({f"{item['type']}\0{item['id']}": item for item in resources_seen}.values())
    discoveries = list({f"{item['type']}\0{item['id']}": item for item in discoveries}.values())
    resources_seen.sort(key=lambda item: f"{item['type']}\0{item['id']}")
    discoveries.sort(key=lambda item: f"{item['type']}\0{item['id']}")
    return resources_seen, discoveries


def compose_map(
    observed: dict[str, Any] | None = None,
    credentials: list[str] | None = None,
    instance_id: str = "",
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Join the reviewed baseline with observation and held credential handles."""
    document = baseline or BASELINE
    observed = _project_twin_facts(observed or {})
    held = set(credentials or [])
    flags = observed.get("feature_flags") or {}
    resources_seen, discoveries = _inventory(document, observed)

    entries: list[dict[str, Any]] = []
    for capability in document["capabilities"]:
        missing_flags = [f for f in capability.get("requires_feature_flags", []) if flags.get(f) is not True]
        state = _presence(capability["id"], observed)
        observed_capability = (observed.get("capabilities") or {}).get(capability["id"])

        policy = EXECUTABLE
        blockers: list[dict[str, str]] = []
        selected_provider: dict[str, Any] | None = None
        # Absence beats credentials: telling an operator to find a token for an
        # extension that is not installed sends them after a change that would
        # not help.
        if capability.get("status") == "planned":
            policy = DISCOVERY_ONLY
            blockers.append({"kind": "provider_not_implemented", "detail": capability["id"]})
        elif state == "blocked":
            policy = PRECONDITION_BLOCKED
            reported = observed_capability.get("blockers", []) if isinstance(observed_capability, dict) else []
            blockers.extend({
                "kind": str(blocker.get("kind") or "precondition_blocked"),
                "detail": str(blocker.get("detail") or capability["id"]),
            } for blocker in (reported or [{"kind": "precondition_blocked", "detail": capability["id"]}]))
        elif state == ABSENT or missing_flags:
            policy = ABSENT
            if state == ABSENT:
                blockers.append({"kind": "not_installed", "detail": capability["id"]})
            blockers.extend({"kind": "feature_flag_off", "detail": flag} for flag in missing_flags)
        elif state == DISCOVERY_ONLY:
            policy = DISCOVERY_ONLY
            blockers.append({"kind": "no_reviewed_profile", "detail": capability["id"]})
        else:
            selected_provider, provider_blockers = _select_provider(capability, observed, held)
            if provider_blockers:
                selected_provider = None
                blockers.extend(provider_blockers)
                policy = CREDENTIAL_MISSING if any(
                    blocker["kind"] == "credential_missing" for blocker in blockers
                ) else ABSENT

        entries.append({
            **capability,
            "selected_provider": selected_provider if policy == EXECUTABLE else None,
            "execution_policy": policy,
            "blockers": blockers,
        })

    index = {entry["id"]: entry for entry in entries}
    for entry in entries:
        if entry["execution_policy"] != EXECUTABLE:
            continue
        for dependency in entry.get("requires_capabilities", []):
            target = index.get(dependency)
            if target is None or target["execution_policy"] != EXECUTABLE:
                entry["execution_policy"] = target["execution_policy"] if target else ABSENT
                entry["blockers"] = entry["blockers"] + [{"kind": "dependency_unmet", "detail": dependency}]

    body = _stable({
        "capabilities": [_canonical_capability(entry) for entry in entries],
        "resources": resources_seen,
    })
    digest = hashlib.sha256(
        json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return {
        "schema": MAP_SCHEMA,
        "twin_family": document["twin_family"],
        "baseline_version": str(document["version"]),
        "instance_id": str(instance_id),
        "map_hash": f"sha256:{digest}",
        "baseline": BASELINE_SNAPSHOT.provenance() if document is BASELINE else {
            "source": "in-memory", "revision": f"v{document.get('version')}",
            "digest": f"sha256:{hashlib.sha256(json.dumps(_stable(document), separators=(',', ':')).encode()).hexdigest()}",
            "loaded_from": "provided", "stale": False,
        },
        "environment": _stable(document.get("environment") or {}),
        "services": _stable(document.get("services") or []),
        "resource_types": _stable(document.get("resource_types") or []),
        "workflows": _stable(document.get("workflows") or {}),
        "resources": resources_seen,
        "discoveries": discoveries,
        "capabilities": entries,
    }


def resolve_intent(twin_map: dict[str, Any], intent: str, requires: list[str]) -> dict[str, Any]:
    """Return an ordered plan, or the single deepest unmet precondition."""
    index = {entry["id"]: entry for entry in twin_map["capabilities"]}
    plan: list[dict[str, Any]] = []
    seen: set[str] = set()
    produced_credentials: set[str] = set()

    def visit(capability_id: str, trail: tuple[str, ...]) -> dict[str, Any] | None:
        if capability_id in seen:
            return None
        if capability_id in trail:
            raise ValueError(f"capability_cycle:{capability_id}")
        entry = index.get(capability_id)
        if entry is None:
            return {"kind": "capability_unknown", "detail": capability_id, "capability": capability_id}
        for dependency in entry.get("requires_capabilities", []):
            gap = visit(dependency, trail + (capability_id,))
            if gap is not None:
                return gap
        remaining_blockers = [
            blocker for blocker in entry.get("blockers", [])
            if blocker.get("kind") != "credential_missing"
            or str(blocker.get("detail") or "") not in produced_credentials
        ]
        executable_after_provisioning = (
            entry["execution_policy"] == CREDENTIAL_MISSING and not remaining_blockers
        )
        if entry["execution_policy"] != EXECUTABLE and not executable_after_provisioning:
            blocker = (
                remaining_blockers[0] if remaining_blockers
                else entry["blockers"][0] if entry["blockers"]
                else {"kind": "not_executable", "detail": capability_id}
            )
            return {**blocker, "capability": capability_id, "execution_policy": entry["execution_policy"]}
        seen.add(capability_id)
        provider = entry.get("selected_provider") or entry["provided_by"][0]
        plan.append({
            "capability": entry["id"],
            "effect": entry["effect"],
            "connector": provider["connector"],
            "uri": provider["uri"],
            "transport": entry["transport"],
            "risk": entry.get("risk", "R1"),
            "produces_credentials": list(entry.get("produces_credentials", [])),
        })
        produced_credentials.update(str(handle) for handle in entry.get("produces_credentials", []))
        return None

    for capability_id in requires:
        gap = visit(capability_id, ())
        if gap is not None:
            return {"schema": MAP_SCHEMA, "intent": intent, "resolved": False, "gap": gap, "plan": []}
    return {"schema": MAP_SCHEMA, "intent": intent, "resolved": True, "gap": None, "plan": plan}


def _names(value: Any, field: str) -> list[str]:
    """Inputs are scalars or lists of short names — never structures, never secrets."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [item.strip() for item in value.split(",") if item.strip()]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of names")
    for item in value:
        # A handle is a name. Rejecting anything secret-shaped outright is
        # deliberate: redacting it instead would teach callers that passing a
        # real credential here works.
        if len(item) > 128 or any(ch.isspace() for ch in item):
            raise ValueError(f"{field} must contain short handle names, not secrets")
    return value


def _json_object(value: Any, field: str) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field} must be a JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a JSON object")
    _reject_secret_keys(value, field)
    return value


def _json_array(value: Any, field: str) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field} must be a JSON array") from exc
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a JSON array")
    _reject_secret_keys(value, field)
    return value


def _proposal_text(value: Any, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > 160 or PROPOSAL_SECRETISH.search(normalized):
        raise ValueError(f"review_proposal_{field}_invalid")
    return normalized


def _proposal_attributes(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for key in sorted(value):
        if PROPOSAL_SECRETISH.search(str(key)):
            raise ValueError("review_proposal_secret_forbidden")
        if key not in SAFE_PROPOSAL_ATTRIBUTES:
            continue
        item = value[key]
        if not isinstance(item, (bool, int, float, str)):
            continue
        result[key] = _proposal_text(item, "attribute") if isinstance(item, str) else item
    return result


def build_review_proposal(
    discoveries: list[Any], baseline_digest: str, observed_at: str = "", instance_id: str = "",
) -> dict[str, Any]:
    """Build a deterministic draft proposal that grants no runtime authority."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(baseline_digest or "")):
        raise ValueError("review_proposal_baseline_digest_invalid")
    unique: dict[str, dict[str, Any]] = {}
    for raw in discoveries:
        if not isinstance(raw, dict) or raw.get("status") != "review-required":
            continue
        discovery = {
            "type": _proposal_text(raw.get("type"), "type"),
            "id": _proposal_text(raw.get("id"), "id"),
            "attributes": _proposal_attributes(raw.get("attributes")),
        }
        unique[f"{discovery['type']}\0{discovery['id']}"] = discovery
    reviewed = [unique[key] for key in sorted(unique)]
    if not reviewed:
        raise ValueError("review_proposal_discoveries_missing")
    canonical = _stable({"baselineDigest": baseline_digest, "reviewed": reviewed})
    proposal_id = hashlib.sha256(
        json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:20]
    return {
        "schema": "uri-twin.change-proposal/v1",
        "version": 1,
        "proposal_id": f"plesk-{proposal_id}",
        "mode": "review-required",
        "authority_change": "none",
        "base": {
            "repository": "https://github.com/uri-twin/uri-twin-plesk.git",
            "baseline_digest": baseline_digest,
        },
        "observation": {
            "observed_at": str(observed_at or ""),
            "instance_id": str(instance_id or ""),
            "discoveries": reviewed,
        },
        "required_reviews": [
            "human-baseline-review",
            "connector-manifest-route-conformance",
            "signed-baseline-attestation",
        ],
        "pull_request": {
            "draft": True,
            "title": f"Review Plesk discoveries ({len(reviewed)})",
            "labels": ["review-required", "uri-twin", "no-authority"],
        },
    }


def _observation(
    feature_flags_on: Any,
    discovery_only: Any,
    absent: Any,
    api_observation: Any = None,
    available_connectors: Any = None,
    available_routes: Any = None,
    environment_bindings: Any = None,
) -> dict[str, Any]:
    observed: dict[str, Any] = _json_object(api_observation, "api_observation")
    observed["feature_flags"] = {
        **(observed.get("feature_flags") or {}),
        **{name: True for name in _names(feature_flags_on, "feature_flags_on")},
    }
    observed["capabilities"] = dict(observed.get("capabilities") or {})
    for name in _names(discovery_only, "discovery_only"):
        observed["capabilities"][name] = DISCOVERY_ONLY
    for name in _names(absent, "absent"):
        observed["capabilities"][name] = False
    if available_connectors is not None:
        observed["connectors"] = _names(available_connectors, "available_connectors")
    if available_routes is not None:
        observed["routes"] = _names(available_routes, "available_routes")
    if environment_bindings is not None:
        observed["bindings"] = {
            str(key): str(value) for key, value in _json_object(environment_bindings, "environment_bindings").items()
        }
    return observed


@conn.handler(
    MAP_ROUTE,
    isolated=True,
    external=False,
    meta={"label": "Compose the reviewed Plesk capability baseline with live observation"},
)
def map_snapshot(
    instance_id: str = "",
    credential_handles: Any = None,
    feature_flags_on: Any = None,
    discovery_only: Any = None,
    absent: Any = None,
    api_observation: Any = None,
    available_connectors: Any = None,
    available_routes: Any = None,
    environment_bindings: Any = None,
) -> dict[str, Any]:
    try:
        observed = _observation(
            feature_flags_on, discovery_only, absent, api_observation,
            available_connectors, available_routes, environment_bindings,
        )
        credentials = _names(credential_handles, "credential_handles")
    except ValueError as exc:
        return urirun.fail(str(exc), connector=CONNECTOR_ID)
    return urirun.ok(connector=CONNECTOR_ID, result=compose_map(observed, credentials, str(instance_id)))


@conn.handler(
    RESOLVE_ROUTE,
    isolated=True,
    external=False,
    meta={"label": "Resolve an intent into an ordered connector plan or one named gap"},
)
def map_resolve(
    intent: str = "",
    instance_id: str = "",
    credential_handles: Any = None,
    feature_flags_on: Any = None,
    discovery_only: Any = None,
    absent: Any = None,
    requires: Any = None,
    api_observation: Any = None,
    available_connectors: Any = None,
    available_routes: Any = None,
    environment_bindings: Any = None,
) -> dict[str, Any]:
    try:
        observed = _observation(
            feature_flags_on, discovery_only, absent, api_observation,
            available_connectors, available_routes, environment_bindings,
        )
        credentials = _names(credential_handles, "credential_handles")
        explicit = _names(requires, "requires")
    except ValueError as exc:
        return urirun.fail(str(exc), connector=CONNECTOR_ID)

    wanted = explicit or INTENTS.get(str(intent), [])
    if not wanted:
        return urirun.fail(f"unknown intent: {intent or '(missing)'}", connector=CONNECTOR_ID)

    twin_map = compose_map(observed, credentials, str(instance_id))
    try:
        result = resolve_intent(twin_map, str(intent), list(wanted))
    except ValueError as exc:
        return urirun.fail(str(exc), connector=CONNECTOR_ID)
    result["map_hash"] = twin_map["map_hash"]
    result["baseline_version"] = twin_map["baseline_version"]
    result["baseline"] = twin_map["baseline"]
    return urirun.ok(connector=CONNECTOR_ID, result=result)


@conn.handler(
    REFRESH_ROUTE,
    isolated=True,
    external=False,
    meta={"label": "Refresh the reviewed Plesk baseline from Git and report exact provenance"},
)
def map_refresh() -> dict[str, Any]:
    snapshot = reload_baseline()
    return urirun.ok(
        connector=CONNECTOR_ID,
        result={
            "schema": MAP_SCHEMA,
            "twin_family": snapshot.document["twin_family"],
            "baseline_version": str(snapshot.document["version"]),
            "baseline": snapshot.provenance(),
        },
    )


@conn.handler(
    PROPOSAL_ROUTE,
    isolated=True,
    external=False,
    meta={"label": "Build a deterministic review-only proposal for unknown Plesk discoveries"},
)
def map_proposal(
    instance_id: str = "",
    observed_at: str = "",
    discoveries: Any = None,
    api_observation: Any = None,
) -> dict[str, Any]:
    try:
        reviewed = _json_array(discoveries, "discoveries")
        if not reviewed and api_observation not in (None, ""):
            observed = _json_object(api_observation, "api_observation")
            reviewed = compose_map(observed, [], str(instance_id))["discoveries"]
        proposal = build_review_proposal(
            reviewed,
            BASELINE_SNAPSHOT.provenance()["digest"],
            str(observed_at),
            str(instance_id),
        )
    except ValueError as exc:
        return urirun.fail(str(exc), connector=CONNECTOR_ID)
    return urirun.ok(
        connector=CONNECTOR_ID,
        result={
            **proposal,
            "baseline": BASELINE_SNAPSHOT.provenance(),
        },
    )


def _connector_manifest(connector_id: str) -> tuple[dict[str, Any], str]:
    roots = [
        Path(os.environ.get("URIRUN_CONNECTOR_REPOS_ROOT", "/connector-repos")),
        Path.home() / "github" / "urirun-connectors",
    ]
    for root in roots:
        candidates = sorted((root / connector_id).glob("*/connector.manifest.json"))
        if candidates:
            raw = candidates[0].read_bytes()
            return json.loads(raw), f"sha256:{hashlib.sha256(raw).hexdigest()}"
    raise ValueError(f"connector_manifest_missing:{connector_id}")


@conn.handler(
    CONFORMANCE_ROUTE,
    isolated=True,
    external=False,
    meta={"label": "Verify active twin provider URIs against installed connector manifests"},
)
def map_conformance(proposal_id: str = "", expected_baseline_digest: str = "") -> dict[str, Any]:
    provenance = BASELINE_SNAPSHOT.provenance()
    if str(expected_baseline_digest) != provenance["digest"]:
        return urirun.fail("twin_review_baseline_digest_mismatch", connector=CONNECTOR_ID)
    connector_ids = sorted({
        str(provider["connector"])
        for capability in BASELINE["capabilities"] if capability.get("status") != "planned"
        for provider in capability.get("provided_by", [])
    })
    try:
        manifests = {connector_id: _connector_manifest(connector_id) for connector_id in connector_ids}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return urirun.fail(str(exc), connector=CONNECTOR_ID)
    missing = []
    for capability in BASELINE["capabilities"]:
        if capability.get("status") == "planned":
            continue
        for provider in capability.get("provided_by", []):
            routes = set(manifests[str(provider["connector"])][0].get("routes", []))
            if provider.get("uri") not in routes:
                missing.append({"capability": capability["id"], "connector": provider["connector"], "uri": provider.get("uri")})
    if missing:
        return urirun.fail("connector_manifest_route_conformance_failed", connector=CONNECTOR_ID, missing=missing)
    return urirun.ok(connector=CONNECTOR_ID, result={
        "schema": "uri-twin.review-receipt/v1", "review": "connector-manifest-route-conformance",
        "proposal_id": str(proposal_id), "baseline_digest": provenance["digest"], "passed": True,
        "authority_change": "none",
        "manifests": [{"connector": connector_id, "digest": manifests[connector_id][1], "route_count": len(manifests[connector_id][0].get("routes", []))} for connector_id in connector_ids],
    })


@conn.handler(
    ATTESTATION_ROUTE,
    isolated=True,
    external=False,
    meta={"label": "Verify the loaded twin baseline attestation against the expected digest"},
)
def map_attestation(proposal_id: str = "", expected_baseline_digest: str = "") -> dict[str, Any]:
    provenance = BASELINE_SNAPSHOT.provenance()
    attestation = provenance.get("attestation") or {}
    passed = (
        str(expected_baseline_digest) == provenance.get("digest")
        and attestation.get("verified") is True
        and attestation.get("subject_digest") == provenance.get("digest")
    )
    if not passed:
        return urirun.fail("signed_baseline_attestation_review_failed", connector=CONNECTOR_ID)
    return urirun.ok(connector=CONNECTOR_ID, result={
        "schema": "uri-twin.review-receipt/v1", "review": "signed-baseline-attestation",
        "proposal_id": str(proposal_id), "baseline_digest": provenance["digest"], "passed": True,
        "authority_change": "none", "attestation": attestation,
    })


def bindings() -> dict[str, Any]:
    return conn.bindings()


def urirun_bindings() -> dict[str, Any]:
    return bindings()


def manifest() -> dict[str, Any]:
    document = urirun.load_manifest(__package__) or {"id": CONNECTOR_ID}
    document["routes"] = sorted(bindings()["bindings"])
    return document
