"""Behaviour of the capability map, plus conformance with the JS reference."""

from __future__ import annotations

import json
import subprocess

import pytest

from urirun_connector_subactor_twin_map.core import (
    BASELINE,
    INTENTS,
    build_review_proposal,
    compose_map,
    map_proposal,
    map_attestation,
    map_conformance,
    map_resolve,
    map_snapshot,
    resolve_intent,
)

FULL = ["plesk-xml-subscription-owner", "plesk-admin-api-key", "plesk-sftp-subscription-user"]
FLAGS_ON = ["has_dns_module", "has_ssl_it"]


def build_map(credentials=None, flags=None, discovery=None, absent=None):
    observed = {
        "feature_flags": {name: True for name in (FLAGS_ON if flags is None else flags)},
        "capabilities": {
            **{name: "discovery-only" for name in (discovery or [])},
            **{name: False for name in (absent or [])},
        },
    }
    return compose_map(observed, FULL if credentials is None else credentials, "prototypowanie-pl")


def test_baseline_declares_provider_and_credentials_for_every_capability():
    for capability in BASELINE["capabilities"]:
        assert capability["provided_by"], capability["id"]
        assert capability["id"].startswith(("plesk.", "dns."))


def test_fully_credentialed_panel_resolves_publish_site_in_order():
    result = resolve_intent(build_map(), "publish-site", INTENTS["publish-site"])

    assert result["resolved"] is True
    assert [step["capability"] for step in result["plan"]] == [
        "plesk.subscription.snapshot",
        "plesk.site.docroot",
        "plesk.site.publish",
    ]
    assert [step["effect"] for step in result["plan"]] == ["query", "query", "command"]


def test_admin_key_only_names_the_xml_credential_as_the_gap():
    result = resolve_intent(build_map(credentials=["plesk-admin-api-key"]), "publish-site", INTENTS["publish-site"])

    assert result["resolved"] is False
    assert result["plan"] == []
    assert result["gap"]["capability"] == "plesk.subscription.snapshot"
    assert result["gap"]["kind"] == "credential_missing"
    assert result["gap"]["detail"] == "plesk-xml-subscription-owner"


def test_reviewed_provisioner_supplies_a_credential_to_a_dependent_capability():
    baseline = {
        "twin_family": "demo",
        "version": "1",
        "capabilities": [
            {
                "id": "demo.credential.provision",
                "effect": "command",
                "transport": "api",
                "risk": "R2",
                "requires_credentials": ["demo-admin-key"],
                "produces_credentials": ["demo-sftp-user"],
                "provided_by": [{
                    "connector": "urirun-connector-demo",
                    "uri": "demo://host/credential/command/ensure",
                }],
            },
            {
                "id": "demo.publish",
                "effect": "command",
                "transport": "sftp",
                "risk": "R2",
                "requires_credentials": ["demo-sftp-user"],
                "requires_capabilities": ["demo.credential.provision"],
                "provided_by": [{
                    "connector": "urirun-connector-demo",
                    "uri": "demo://host/site/command/publish",
                }],
            },
        ],
    }
    twin_map = compose_map({}, ["demo-admin-key"], "demo-1", baseline=baseline)
    result = resolve_intent(twin_map, "provision-and-publish", ["demo.publish"])

    assert result["resolved"] is True
    assert [step["capability"] for step in result["plan"]] == [
        "demo.credential.provision",
        "demo.publish",
    ]
    assert result["plan"][0]["produces_credentials"] == ["demo-sftp-user"]


def test_credential_production_does_not_bypass_provisioner_authority():
    baseline = {
        "twin_family": "demo",
        "version": "1",
        "capabilities": [
            {
                "id": "demo.credential.provision",
                "effect": "command",
                "transport": "api",
                "requires_credentials": ["demo-admin-key"],
                "produces_credentials": ["demo-sftp-user"],
                "provided_by": [{"connector": "demo", "uri": "demo://host/credential/command/ensure"}],
            },
            {
                "id": "demo.publish",
                "effect": "command",
                "transport": "sftp",
                "requires_credentials": ["demo-sftp-user"],
                "requires_capabilities": ["demo.credential.provision"],
                "provided_by": [{"connector": "demo", "uri": "demo://host/site/command/publish"}],
            },
        ],
    }
    result = resolve_intent(
        compose_map({}, [], "demo-1", baseline=baseline),
        "provision-and-publish",
        ["demo.publish"],
    )

    assert result["resolved"] is False
    assert result["gap"]["capability"] == "demo.credential.provision"
    assert result["gap"]["detail"] == "demo-admin-key"


def test_public_dns_authority_does_not_pretend_to_require_a_plesk_dns_module():
    result = resolve_intent(
        build_map(flags=["has_ssl_it"]), "publish-site-with-tls", INTENTS["publish-site-with-tls"]
    )

    assert result["resolved"] is True


def test_unreviewed_extension_operation_stays_discovery_only():
    twin_map = build_map(discovery=["plesk.ssl.ensure"])
    entry = next(item for item in twin_map["capabilities"] if item["id"] == "plesk.ssl.ensure")

    assert entry["execution_policy"] == "discovery-only"
    assert entry["blockers"][0]["kind"] == "no_reviewed_profile"


def test_observation_cannot_introduce_an_unreviewed_capability():
    twin_map = compose_map(
        {"feature_flags": {name: True for name in FLAGS_ON}, "capabilities": {"plesk.rootkit.install": True}},
        FULL,
        "prototypowanie-pl",
    )

    ids = {entry["id"] for entry in twin_map["capabilities"]}
    assert "plesk.rootkit.install" not in ids
    assert len(twin_map["capabilities"]) == len(BASELINE["capabilities"])


def test_root_ssh_capability_stays_planned_even_if_a_credential_is_later_present():
    entry = next(item for item in build_map()["capabilities"] if item["id"] == "plesk.server.utility")

    assert entry["execution_policy"] == "discovery-only"
    assert entry["blockers"] == [{"kind": "provider_not_implemented", "detail": "plesk.server.utility"}]


def test_handler_rejects_a_secret_shaped_handle_instead_of_redacting_it():
    response = map_snapshot(instance_id="x", credential_handles=["not a handle but a passphrase"])
    assert response.get("ok") is not True

    long_handle = "a" * 129
    assert map_snapshot(instance_id="x", credential_handles=[long_handle]).get("ok") is not True


def test_handler_accepts_a_comma_separated_scalar_for_list_inputs():
    response = map_snapshot(
        instance_id="prototypowanie-pl",
        credential_handles=",".join(FULL),
        feature_flags_on="has_dns_module,has_ssl_it",
    )
    assert response.get("ok") is True
    assert response["result"]["instance_id"] == "prototypowanie-pl"


def test_resolve_handler_refuses_an_unknown_intent():
    assert map_resolve(intent="teleport", instance_id="x").get("ok") is not True


def test_resolve_handler_returns_plan_and_map_provenance():
    response = map_resolve(
        intent="publish-site",
        instance_id="prototypowanie-pl",
        credential_handles=FULL,
        feature_flags_on=FLAGS_ON,
    )

    assert response.get("ok") is True
    result = response["result"]
    assert result["resolved"] is True
    assert result["baseline_version"] == BASELINE["version"]
    assert result["map_hash"].startswith("sha256:")
    assert result["baseline"]["digest"].startswith("sha256:")


def test_review_proposal_is_deterministic_and_grants_no_authority():
    discoveries = [{
        "type": "plesk.capability",
        "id": "plesk.application.runtime",
        "status": "review-required",
        "attributes": {"active": True, "internal_path": "/private"},
    }]
    first = build_review_proposal(discoveries, "sha256:" + "a" * 64, "2026-07-29T18:00:00Z", "panel-1")
    second = build_review_proposal(list(reversed(discoveries)), "sha256:" + "a" * 64, "later", "panel-2")

    assert first["proposal_id"] == second["proposal_id"]
    assert first["mode"] == "review-required"
    assert first["authority_change"] == "none"
    assert first["pull_request"]["draft"] is True
    assert first["observation"]["discoveries"] == [{
        "type": "plesk.capability",
        "id": "plesk.application.runtime",
        "attributes": {"active": True},
    }]


def test_proposal_handler_can_turn_api_discovery_into_review_only_work():
    response = map_proposal(
        instance_id="panel-1",
        observed_at="2026-07-29T18:00:00Z",
        api_observation={
            "resources": [{"type": "plesk.module.experimental", "id": "node-runtime", "attributes": {"active": True}}]
        },
    )

    assert response.get("ok") is True
    assert response["result"]["authority_change"] == "none"
    assert response["result"]["baseline"]["digest"].startswith("sha256:")


def test_proposal_handler_rejects_secret_shaped_discovery_data():
    response = map_proposal(discoveries=[{
        "type": "plesk.module.experimental",
        "id": "unsafe",
        "status": "review-required",
        "attributes": {"api_token": "nope"},
    }])

    assert response.get("ok") is not True


def test_loaded_route_inventory_blocks_a_stale_provider_uri():
    routes = [
        provider["uri"]
        for capability in BASELINE["capabilities"]
        for provider in capability["provided_by"]
        if capability["id"] != "plesk.ssl.ensure"
    ]
    observed = {"feature_flags": {name: True for name in FLAGS_ON}, "routes": routes}
    result = resolve_intent(
        compose_map(observed, FULL, "prototypowanie-pl"),
        "publish-site-with-tls",
        INTENTS["publish-site-with-tls"],
    )

    assert result["resolved"] is False
    assert result["gap"]["kind"] == "route_unavailable"
    assert result["gap"]["detail"] == "plesk://host/site/command/ssl-ensure"


def test_api_inventory_enriches_reviewed_resources_and_quarantines_unknown_modules():
    response = map_snapshot(
        instance_id="prototypowanie-pl",
        credential_handles=FULL,
        feature_flags_on=FLAGS_ON,
        api_observation=json.dumps({
            "resources": [
                {"type": "plesk.subscription", "id": "12", "service": "plesk-xml-api", "attributes": {"name": "main"}},
                {"type": "plesk.module.experimental", "id": "ai-button", "attributes": {"active": True}},
            ]
        }),
    )

    assert response.get("ok") is True
    twin_map = response["result"]
    assert any(item["type"] == "plesk.subscription" and item["id"] == "12" for item in twin_map["resources"])
    assert twin_map["discoveries"] == [
        {"type": "plesk.module.experimental", "id": "ai-button", "status": "review-required"}
    ]


def test_managed_dns_workflow_selects_namecheap_without_exposing_credential_values():
    routes = [provider["uri"] for capability in BASELINE["capabilities"] for provider in capability["provided_by"]]
    observed = {
        "feature_flags": {name: True for name in FLAGS_ON},
        "connectors": ["urirun-connector-plesk", "urirun-connector-namecheap-dns"],
        "routes": routes,
        "bindings": {"dns_management_plane": "namecheap"},
    }
    twin_map = compose_map(observed, [*FULL, "namecheap-dns-api"], "prototypowanie-pl")
    result = resolve_intent(
        twin_map, "publish-site-with-managed-dns", INTENTS["publish-site-with-managed-dns"]
    )

    assert result["resolved"] is True
    dns = next(step for step in result["plan"] if step["capability"] == "dns.records.reconcile")
    assert dns["connector"] == "urirun-connector-namecheap-dns"
    assert dns["uri"] == "dns://host/records/command/apply"
    assert "namecheap-dns-api" not in json.dumps(result)


def test_api_inventory_rejects_secret_fields_instead_of_redacting_them():
    response = map_snapshot(
        instance_id="x",
        api_observation=json.dumps({
            "resources": [{"type": "plesk.site", "id": "x", "attributes": {"api_token": "nope"}}]
        }),
    )
    assert response.get("ok") is not True


def test_refused_docroot_fact_projection_blocks_publish_before_command_execution():
    response = map_resolve(
        intent="publish-site",
        instance_id="panel-1",
        credential_handles=FULL,
        feature_flags_on=FLAGS_ON,
        api_observation=json.dumps({
            "twin_facts": [{
                "twin_type": "plesk.site.docroot",
                "fact_quality": "fresh",
                "payload": {"domain": "docs.subactor.com", "observed": "/docs.subactor.com", "decision": "refuse"},
            }]
        }),
    )

    assert response.get("ok") is True
    result = response["result"]
    assert result["resolved"] is False
    assert result["gap"]["kind"] == "fact_refused"
    assert result["gap"]["detail"] == "plesk.site.docroot"
    assert result["gap"]["execution_policy"] == "precondition-blocked"


def test_cloudflaredns_binding_selects_the_plesk_dns_provider():
    routes = [provider["uri"] for capability in BASELINE["capabilities"] for provider in capability["provided_by"]]
    twin_map = compose_map({
        "feature_flags": {name: True for name in FLAGS_ON},
        "connectors": ["urirun-connector-plesk", "urirun-connector-namecheap-dns"],
        "routes": routes,
        "bindings": {"dns_management_plane": "cloudflaredns"},
    }, FULL, "panel-1")
    result = resolve_intent(
        twin_map, "publish-site-with-managed-dns", INTENTS["publish-site-with-managed-dns"]
    )

    assert result["resolved"] is True
    dns = next(step for step in result["plan"] if step["capability"] == "dns.records.reconcile")
    assert dns["connector"] == "urirun-connector-plesk"


CONFORMANCE_SCRIPT = """
import {observedFromExtensionCatalog, pleskMap, resolveNamedIntent} from "./src/map.mjs";
const scenarios = JSON.parse(process.argv[1]);
const out = scenarios.map(({credentials, dnsModule, extensions, reviewedOperations, intent}) => {
  const observed = observedFromExtensionCatalog({extensions, reviewedOperations, dnsModule});
  const map = pleskMap({observed, credentials, instanceId: "prototypowanie-pl"});
  const result = resolveNamedIntent(map, intent);
  return {
    resolved: result.resolved,
    plan: result.plan.map((step) => step.capability),
    gap: result.gap && {kind: result.gap.kind, detail: result.gap.detail, capability: result.gap.capability},
    map_hash: map.map_hash,
  };
});
process.stdout.write(JSON.stringify(out));
"""

SCENARIOS = [
    {"credentials": FULL, "dnsModule": True, "extensions": [{"id": "sslit", "active": True}],
     "reviewedOperations": ["plesk.ssl.ensure"], "intent": "publish-site"},
    {"credentials": ["plesk-admin-api-key"], "dnsModule": True, "extensions": [{"id": "sslit", "active": True}],
     "reviewedOperations": ["plesk.ssl.ensure"], "intent": "publish-site"},
    {"credentials": FULL, "dnsModule": False, "extensions": [{"id": "sslit", "active": True}],
     "reviewedOperations": ["plesk.ssl.ensure"], "intent": "publish-site-with-tls"},
    {"credentials": FULL, "dnsModule": True, "extensions": [{"id": "sslit", "active": True}],
     "reviewedOperations": [], "intent": "publish-site-with-tls"},
    {"credentials": FULL, "dnsModule": True, "extensions": [], "reviewedOperations": ["plesk.ssl.ensure"],
     "intent": "create-mailbox"},
]


def _python_outcome(scenario):
    flags = []
    if scenario["dnsModule"]:
        flags.append("has_dns_module")
    if any(item.get("id") == "sslit" and item.get("active") for item in scenario["extensions"]):
        flags.append("has_ssl_it")
    discovery = [] if "plesk.ssl.ensure" in scenario["reviewedOperations"] else ["plesk.ssl.ensure"]

    twin_map = build_map(credentials=scenario["credentials"], flags=flags, discovery=discovery)
    result = resolve_intent(twin_map, scenario["intent"], INTENTS[scenario["intent"]])
    gap = result["gap"]
    return {
        "resolved": result["resolved"],
        "plan": [step["capability"] for step in result["plan"]],
        "gap": None if gap is None else {"kind": gap["kind"], "detail": gap["detail"], "capability": gap["capability"]},
        "map_hash": twin_map["map_hash"],
    }


def test_python_matches_the_js_reference_implementation(js_reference):
    """Two implementations of one contract diverge unless something compares them.

    The baseline JSON is the shared contract; this pins the decision surface —
    resolved, plan order and the reported gap — across both runtimes.
    """
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", CONFORMANCE_SCRIPT, json.dumps(SCENARIOS)],
        cwd=js_reference, capture_output=True, text=True, timeout=60, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == [_python_outcome(scenario) for scenario in SCENARIOS]


def test_every_active_provider_uri_exists_in_its_connector_manifest(connector_workspace):
    manifests = {}
    for connector in ("urirun-connector-plesk", "urirun-connector-namecheap-dns"):
        candidates = list((connector_workspace / connector).glob("*/connector.manifest.json"))
        assert candidates, f"manifest missing for {connector}"
        manifests[connector] = set(json.loads(candidates[0].read_text(encoding="utf-8"))["routes"])

    missing = []
    for capability in BASELINE["capabilities"]:
        if capability.get("status") == "planned":
            continue
        for provider in capability["provided_by"]:
            if provider["uri"] not in manifests[provider["connector"]]:
                missing.append((capability["id"], provider["connector"], provider["uri"]))

    assert missing == []


def test_machine_review_routes_return_digest_bound_read_only_receipts(monkeypatch, connector_workspace):
    from urirun_connector_subactor_twin_map.core import BASELINE_SNAPSHOT

    monkeypatch.setenv("URIRUN_CONNECTOR_REPOS_ROOT", str(connector_workspace))
    digest = BASELINE_SNAPSHOT.provenance()["digest"]
    conformance = map_conformance("plesk-review-test", digest)
    attestation = map_attestation("plesk-review-test", digest)

    assert conformance["ok"] is True
    assert conformance["result"]["review"] == "connector-manifest-route-conformance"
    assert conformance["result"]["authority_change"] == "none"
    assert attestation["ok"] is True
    assert attestation["result"]["review"] == "signed-baseline-attestation"
    assert attestation["result"]["attestation"]["verified"] is True
    assert map_attestation("plesk-review-test", "sha256:" + "0" * 64)["ok"] is False
