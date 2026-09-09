import {composeMap, defineCapability, resolveIntent} from "@uri-twin/core/capability";
import baseline from "../baseline/plesk-surface.v1.json" with {type: "json"};

export {baseline};

/**
 * Git is the default; the API only enriches.
 *
 * The baseline ships in this repo and is what a cold twin loads. Live
 * observation may downgrade a capability (not installed, no reviewed profile)
 * or satisfy a feature flag, but it can never introduce a capability nobody
 * reviewed. That asymmetry is what keeps a compromised or simply chatty panel
 * from widening what the system believes it may do.
 */

export function pleskBaseline() {
  return {
    ...baseline,
    capabilities: baseline.capabilities.map((entry) =>
      defineCapability({
        id: entry.id,
        twinFamily: baseline.twin_family,
        effect: entry.effect,
        transport: entry.transport,
        status: entry.status || "available",
        risk: entry.risk,
        requiresCredentials: entry.requires_credentials || [],
        producesCredentials: entry.produces_credentials || [],
        requiresCapabilities: entry.requires_capabilities || [],
        requiresFeatureFlags: entry.requires_feature_flags || [],
        providedBy: entry.provided_by,
        summary: entry.summary,
      })),
  };
}

const EXTENSION_FEATURE_FLAGS = Object.freeze({
  "sslit": "has_ssl_it",
  "git": "has_git_extension",
});

/**
 * Turn a live extension catalog into the observed layer.
 *
 * An installed extension with no reviewed profile becomes discovery-only rather
 * than executable, mirroring the connector's own extension capability model: a
 * button in the panel is not proof of a supported remote operation.
 */
export function observedFromExtensionCatalog({extensions = [], reviewedOperations = [], dnsModule = false} = {}) {
  const featureFlags = {has_dns_module: Boolean(dnsModule)};
  const capabilities = {};

  for (const extension of extensions) {
    const id = String(extension?.id || "");
    const flag = EXTENSION_FEATURE_FLAGS[id];
    if (flag) featureFlags[flag] = Boolean(extension?.active);
  }

  const reviewed = new Set(reviewedOperations.map(String));
  for (const entry of baseline.capabilities) {
    if (entry.transport !== "extension-xml" || entry.effect !== "command") continue;
    if (!reviewed.has(entry.id)) capabilities[entry.id] = "discovery-only";
  }

  return {feature_flags: featureFlags, capabilities};
}

/**
 * Normalize API responses into instance inventory without granting authority.
 * Unknown resource types stay visible as review-required discoveries in core.
 */
export function observedFromApiInventory({
  extensions = [],
  reviewedOperations = [],
  dnsModule = false,
  subscriptions = [],
  sites = [],
  dnsZones = [],
  discoveries = [],
  twinFacts = [],
  connectors,
  routes,
  bindings = {},
} = {}) {
  const observed = observedFromExtensionCatalog({extensions, reviewedOperations, dnsModule});
  const capabilities = {...observed.capabilities};
  const factSites = [];
  const factDnsZones = [];
  const factBindings = {};
  for (const fact of twinFacts) {
    const payload = fact?.payload || {};
    if (fact?.twin_type === "plesk.site.docroot") {
      factSites.push({domain: payload.domain, docroot: payload.expected || payload.observed || payload.docroot});
      if (fact?.fact_quality !== "fresh" || payload.decision === "refuse") {
        capabilities["plesk.site.publish"] = {
          state: "blocked",
          blockers: [{
            kind: payload.decision === "refuse" ? "fact_refused" : "fact_not_fresh",
            detail: "plesk.site.docroot",
          }],
        };
      }
    }
    if (fact?.twin_type === "plesk.dns.authority") {
      factDnsZones.push({
        hostname: payload.hostname,
        management_plane: payload.management_plane,
        service: "plesk-xml-api",
      });
      if (payload.management_plane) factBindings.dns_management_plane = String(payload.management_plane);
    }
  }
  return {
    ...observed,
    capabilities,
    connectors: Array.isArray(connectors) ? connectors.map(String) : undefined,
    routes: Array.isArray(routes) ? routes.map(String) : undefined,
    bindings: {
      ...factBindings,
      ...Object.fromEntries(Object.entries(bindings).map(([key, value]) => [String(key), String(value)])),
    },
    resources: [
      ...subscriptions.map((item) => ({
        type: "plesk.subscription",
        id: String(item?.id || item?.name || ""),
        service: "plesk-xml-api",
        attributes: {
          name: String(item?.name || ""),
          domains_limit: item?.domains_limit ?? null,
          domains_used: item?.domains_used ?? null,
        },
      })),
      ...[...sites, ...factSites].map((item) => ({
        type: "plesk.site",
        id: String(item?.domain || ""),
        service: "plesk-xml-api",
        attributes: {domain: String(item?.domain || ""), docroot: item?.docroot == null ? null : String(item.docroot)},
      })),
      ...extensions.map((item) => ({
        type: "plesk.extension",
        id: String(item?.id || ""),
        service: "plesk-extensions",
        attributes: {name: String(item?.name || ""), version: String(item?.version || ""), active: Boolean(item?.active)},
      })),
      ...[...dnsZones, ...factDnsZones].map((item) => ({
        type: "dns.zone",
        id: String(item?.hostname || ""),
        service: String(item?.service || ""),
        attributes: {hostname: String(item?.hostname || ""), management_plane: String(item?.management_plane || "")},
      })),
      ...discoveries,
    ],
  };
}

export function pleskMap({observed, credentials, instanceId, observedAt}) {
  return composeMap({baseline: pleskBaseline(), observed, credentials, instanceId, observedAt});
}

export function resolvePleskIntent(map, intent) {
  return resolveIntent(map, intent);
}

/** Named intents, so callers ask for an outcome rather than assembling URIs. */
export const PLESK_INTENTS = Object.freeze(Object.fromEntries(
  Object.entries(baseline.workflows || {}).map(([name, workflow]) => [name, workflow.requires.map(String)]),
));

export function resolveNamedIntent(map, name) {
  const requires = PLESK_INTENTS[name];
  if (!requires) throw new Error(`plesk_intent_unknown:${name}`);
  return resolveIntent(map, {intent: name, requires});
}
