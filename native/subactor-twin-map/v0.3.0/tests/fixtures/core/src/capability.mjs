import {createHash} from "node:crypto";

export const TWIN_CAPABILITY_SCHEMA = "uri-twin.capability/v1";
export const TWIN_MAP_SCHEMA = "uri-twin.map/v1";
const SECRETISH = /(password|secret|token|api[_-]?key|authorization)/i;

/**
 * Why this layer exists.
 *
 * A twin fact answers "what is" — the docroot is /X. It cannot answer the
 * question that actually stalls autonomy: "can this task be done here, and if
 * not, what exactly is missing?" Without that answer a connector fails, the
 * failure becomes a ticket, and a human is asked to rediscover a precondition
 * the system already knew about.
 *
 * A capability is the declared affordance: an effect reachable over a named
 * transport, requiring named credentials, provided by named connectors. The map
 * is baseline (git, reviewed) joined with observation (live API) and with the
 * credential handles actually held. Resolution then returns an executable plan
 * or a single named gap — never a bare failure.
 */

export const EXECUTION_POLICY = Object.freeze({
  EXECUTABLE: "executable",
  CREDENTIAL_MISSING: "credential-missing",
  DISCOVERY_ONLY: "discovery-only",
  PRECONDITION_BLOCKED: "precondition-blocked",
  ABSENT: "absent",
});

/** Baseline entry: reviewed, versioned, shipped in git. Never holds a secret. */
export function defineCapability({
  id,
  twinFamily,
  effect,
  transport,
  status = "available",
  risk = "R1",
  requiresCredentials = [],
  producesCredentials = [],
  providedBy = [],
  requiresCapabilities = [],
  requiresFeatureFlags = [],
  summary = "",
}) {
  if (!/^[a-z][a-z0-9.-]{1,95}$/.test(String(id || ""))) throw new Error("capability_id_invalid");
  if (!["query", "command"].includes(effect)) throw new Error("capability_effect_invalid");
  if (!providedBy.length) throw new Error("capability_provider_required");
  for (const handle of producesCredentials) {
    if (!/^[a-z][a-z0-9._-]{1,127}$/.test(String(handle || ""))) {
      throw new Error("capability_produced_credential_handle_invalid");
    }
  }
  return {
    id: String(id),
    twin_family: String(twinFamily),
    effect,
    transport: String(transport),
    status: String(status),
    risk: String(risk),
    requires_credentials: requiresCredentials.map(String),
    produces_credentials: producesCredentials.map(String),
    requires_capabilities: requiresCapabilities.map(String),
    requires_feature_flags: requiresFeatureFlags.map(String),
    provided_by: providedBy.map((entry) => ({
      connector: String(entry.connector),
      uri: String(entry.uri),
      preconditions: (entry.preconditions || []).map(String),
      requires_credentials: (entry.requiresCredentials || entry.requires_credentials || []).map(String),
      requires_feature_flags: (entry.requiresFeatureFlags || entry.requires_feature_flags || []).map(String),
      requires_bindings: Object.fromEntries(Object.entries(entry.requiresBindings || entry.requires_bindings || {})
        .map(([key, value]) => [String(key), Array.isArray(value) ? value.map(String).sort() : String(value)])),
    })),
    summary: String(summary),
  };
}

function providerBlockers(capability, provider, observed, held) {
  const blockers = [];
  const connectors = Array.isArray(observed?.connectors) ? new Set(observed.connectors.map(String)) : null;
  const routes = Array.isArray(observed?.routes) ? new Set(observed.routes.map(String)) : null;
  const flags = observed?.feature_flags || {};
  const bindings = observed?.bindings || {};

  if (connectors && !connectors.has(provider.connector)) {
    blockers.push({kind: "connector_unavailable", detail: provider.connector});
  }
  if (routes && !routes.has(provider.uri)) {
    blockers.push({kind: "route_unavailable", detail: provider.uri});
  }
  for (const flag of provider.requires_feature_flags || []) {
    if (flags[flag] !== true) blockers.push({kind: "feature_flag_off", detail: flag});
  }
  for (const [name, expected] of Object.entries(provider.requires_bindings || {})) {
    const accepted = Array.isArray(expected) ? expected.map(String) : [String(expected)];
    if (!accepted.includes(String(bindings[name] ?? ""))) {
      blockers.push({kind: "binding_mismatch", detail: `${name}=${accepted.join("|")}`});
    }
  }
  for (const handle of [...capability.requires_credentials, ...(provider.requires_credentials || [])]) {
    if (!held.has(handle)) blockers.push({kind: "credential_missing", detail: handle});
  }
  return blockers;
}

function selectProvider(capability, observed, credentials) {
  const held = new Set(credentials || []);
  const candidates = capability.provided_by.map((provider) => ({
    provider,
    blockers: providerBlockers(capability, provider, observed, held),
  }));
  const selected = candidates.find((candidate) => candidate.blockers.length === 0);
  return selected || candidates[0];
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

const CANONICAL_ENTRY_KEYS = Object.freeze([
  "blockers",
  "effect",
  "execution_policy",
  "id",
  "produces_credentials",
  "provided_by",
  "requires_capabilities",
  "requires_credentials",
  "requires_feature_flags",
  "risk",
  "selected_provider",
  "status",
  "transport",
]);

/**
 * The portable identity of one map entry.
 *
 * `map_hash` is only useful if two runtimes computing it from the same inputs
 * agree, and they will not if each hashes whatever shape it happens to hold.
 * This pins a fixed key set, sorts every set-like list, and drops fields that
 * carry no decision: `twin_family` is already in the map header, and `summary`
 * is prose — rewording a description must not look like a changed map.
 *
 * Any implementation in any language that produces this shape and serialises it
 * with sorted keys and no whitespace computes the same hash.
 */
export function canonicalCapabilityEntry(entry) {
  const provider = (value) => ({
    connector: String(value?.connector || ""),
    uri: String(value?.uri || ""),
    preconditions: [...(value?.preconditions || [])].map(String).sort(),
    requires_credentials: [...(value?.requires_credentials || [])].map(String).sort(),
    requires_feature_flags: [...(value?.requires_feature_flags || [])].map(String).sort(),
    requires_bindings: stable(value?.requires_bindings || {}),
  });

  const selected = entry?.selected_provider;
  return {
    id: String(entry?.id || ""),
    effect: String(entry?.effect || ""),
    transport: String(entry?.transport || ""),
    status: String(entry?.status || "available"),
    risk: String(entry?.risk || ""),
    execution_policy: String(entry?.execution_policy || ""),
    requires_capabilities: [...(entry?.requires_capabilities || [])].map(String).sort(),
    requires_credentials: [...(entry?.requires_credentials || [])].map(String).sort(),
    produces_credentials: [...(entry?.produces_credentials || [])].map(String).sort(),
    requires_feature_flags: [...(entry?.requires_feature_flags || [])].map(String).sort(),
    provided_by: (entry?.provided_by || []).map(provider),
    // Blockers are a set for identity purposes; resolveIntent still reads the
    // unsorted originals, where first-reported order carries meaning.
    blockers: [...(entry?.blockers || [])]
      .map((blocker) => ({kind: String(blocker?.kind || ""), detail: String(blocker?.detail || "")}))
      .sort((left, right) => `${left.kind}\x00${left.detail}`.localeCompare(`${right.kind}\x00${right.detail}`)),
    selected_provider: selected ? {connector: String(selected.connector), uri: String(selected.uri)} : null,
  };
}

export function canonicalMapBody(entries, resources = []) {
  return stable({
    capabilities: entries.map(canonicalCapabilityEntry),
    resources,
  });
}

export {CANONICAL_ENTRY_KEYS};

function safeObservedResources(baseline, observed) {
  const reviewed = new Set((baseline.resource_types || []).map((entry) => String(entry.id)));
  const resources = [];
  const discoveries = [];
  for (const item of observed?.resources || []) {
    const type = String(item?.type || "");
    const id = String(item?.id || "");
    if (!type || !id) continue;
    if (!reviewed.has(type)) {
      discoveries.push({type, id, status: "review-required"});
      continue;
    }
    const attributes = item?.attributes && typeof item.attributes === "object" ? item.attributes : {};
    const assertSafe = (value, path) => {
      if (Array.isArray(value)) return value.forEach((child, index) => assertSafe(child, `${path}[${index}]`));
      if (!value || typeof value !== "object") return;
      for (const [key, child] of Object.entries(value)) {
        if (SECRETISH.test(key)) throw new Error(`map_resource_secret_key_forbidden:${path}.${key}`);
        assertSafe(child, `${path}.${key}`);
      }
    };
    assertSafe(attributes, type);
    resources.push({type, id, service: String(item?.service || ""), attributes: stable(attributes)});
  }
  const uniqueResources = [...new Map(resources.map((item) => [`${item.type}\0${item.id}`, item])).values()];
  const uniqueDiscoveries = [...new Map(discoveries.map((item) => [`${item.type}\0${item.id}`, item])).values()];
  uniqueResources.sort((left, right) => `${left.type}\0${left.id}`.localeCompare(`${right.type}\0${right.id}`));
  uniqueDiscoveries.sort((left, right) => `${left.type}\0${left.id}`.localeCompare(`${right.type}\0${right.id}`));
  return {resources: uniqueResources, discoveries: uniqueDiscoveries};
}

/**
 * Absence must be observed, not inferred. An unobserved capability is assumed
 * present so that feature flags remain the single place where "this panel does
 * not have it" is decided; inferring absence here too produced two blockers for
 * one cause.
 */
function presence(capability, observed) {
  const state = observed?.capabilities?.[capability.id];
  if (state === undefined) return "present";
  if (state && typeof state === "object") return String(state.state || "present");
  if (state === false) return "absent";
  if (state === "discovery-only") return "discovery-only";
  return "present";
}

function missingFlags(capability, observed) {
  const flags = observed?.feature_flags || {};
  return capability.requires_feature_flags.filter((flag) => flags[flag] !== true);
}

/**
 * Join baseline with observation and held credentials.
 *
 * Order matters: absence beats credentials. Reporting "no credential" for an
 * extension that is not installed would send someone hunting for a token that
 * would change nothing.
 */
export function composeMap({baseline, observed = {}, credentials = [], instanceId, observedAt = new Date().toISOString()}) {
  if (!baseline?.capabilities?.length) throw new Error("map_baseline_required");
  const inventory = safeObservedResources(baseline, observed);
  const entries = baseline.capabilities.map((capability) => {
    const flags = missingFlags(capability, observed);
    const state = presence(capability, observed);
    const observedCapability = observed?.capabilities?.[capability.id];
    let policy = EXECUTION_POLICY.EXECUTABLE;
    const blockers = [];
    if (capability.status === "planned") {
      policy = EXECUTION_POLICY.DISCOVERY_ONLY;
      blockers.push({kind: "provider_not_implemented", detail: capability.id});
    } else if (state === "blocked") {
      policy = EXECUTION_POLICY.PRECONDITION_BLOCKED;
      const reported = Array.isArray(observedCapability?.blockers) ? observedCapability.blockers : [];
      blockers.push(...(reported.length ? reported : [{kind: "precondition_blocked", detail: capability.id}])
        .map((blocker) => ({kind: String(blocker.kind || "precondition_blocked"), detail: String(blocker.detail || capability.id)})));
    } else if (state === "absent" || flags.length) {
      policy = EXECUTION_POLICY.ABSENT;
      if (state === "absent") blockers.push({kind: "not_installed", detail: capability.id});
      for (const flag of flags) blockers.push({kind: "feature_flag_off", detail: flag});
    } else if (state === "discovery-only") {
      policy = EXECUTION_POLICY.DISCOVERY_ONLY;
      blockers.push({kind: "no_reviewed_profile", detail: capability.id});
    } else {
      const selection = selectProvider(capability, observed, credentials);
      if (selection?.blockers.length) {
        blockers.push(...selection.blockers);
        policy = blockers.some((blocker) => blocker.kind === "credential_missing")
          ? EXECUTION_POLICY.CREDENTIAL_MISSING
          : EXECUTION_POLICY.ABSENT;
      }
      capability = {...capability, selected_provider: selection?.blockers.length ? null : selection?.provider || null};
    }

    return {...capability, execution_policy: policy, blockers};
  });

  const index = new Map(entries.map((entry) => [entry.id, entry]));
  // A capability is only as executable as the capabilities it stands on.
  for (const entry of entries) {
    if (entry.execution_policy !== EXECUTION_POLICY.EXECUTABLE) continue;
    for (const dependency of entry.requires_capabilities) {
      const target = index.get(dependency);
      if (!target || target.execution_policy !== EXECUTION_POLICY.EXECUTABLE) {
        entry.execution_policy = target ? target.execution_policy : EXECUTION_POLICY.ABSENT;
        entry.blockers = [...entry.blockers, {kind: "dependency_unmet", detail: dependency}];
      }
    }
  }

  const body = canonicalMapBody(entries, inventory.resources);
  return {
    schema: TWIN_MAP_SCHEMA,
    twin_family: String(baseline.twin_family),
    baseline_version: String(baseline.version),
    instance_id: String(instanceId),
    observed_at: String(observedAt),
    map_hash: `sha256:${createHash("sha256").update(JSON.stringify(body)).digest("hex")}`,
    environment: stable(baseline.environment || {}),
    services: stable(baseline.services || []),
    resource_types: stable(baseline.resource_types || []),
    workflows: stable(baseline.workflows || {}),
    resources: inventory.resources,
    discoveries: inventory.discoveries,
    capabilities: entries,
  };
}

/**
 * Resolve an intent into an ordered plan or a single actionable gap.
 *
 * The gap is deliberately one item, not a list: an operator handed five
 * simultaneous blockers reopens the same triage the twin is meant to end.
 * Dependencies come first, so the reported gap is the deepest unmet one.
 */
export function resolveIntent(map, {intent, requires = []}) {
  const index = new Map(map.capabilities.map((entry) => [entry.id, entry]));
  const plan = [];
  const seen = new Set();
  const producedCredentials = new Set();

  const visit = (id, trail) => {
    if (seen.has(id)) return null;
    if (trail.includes(id)) throw new Error(`capability_cycle:${id}`);
    const entry = index.get(id);
    if (!entry) return {kind: "capability_unknown", detail: id, capability: id};

    for (const dependency of entry.requires_capabilities) {
      const gap = visit(dependency, [...trail, id]);
      if (gap) return gap;
    }
    const remainingBlockers = (entry.blockers || []).filter((blocker) => (
      blocker.kind !== "credential_missing" || !producedCredentials.has(String(blocker.detail))
    ));
    const executableAfterProvisioning = entry.execution_policy === EXECUTION_POLICY.CREDENTIAL_MISSING
      && remainingBlockers.length === 0;
    if (entry.execution_policy !== EXECUTION_POLICY.EXECUTABLE && !executableAfterProvisioning) {
      const blocker = remainingBlockers[0] || entry.blockers[0] || {kind: "not_executable", detail: id};
      return {...blocker, capability: id, execution_policy: entry.execution_policy};
    }
    seen.add(id);
    plan.push({
      capability: entry.id,
      effect: entry.effect,
      connector: (entry.selected_provider || entry.provided_by[0]).connector,
      uri: (entry.selected_provider || entry.provided_by[0]).uri,
      transport: entry.transport,
      risk: entry.risk,
      produces_credentials: [...(entry.produces_credentials || [])],
    });
    for (const handle of entry.produces_credentials || []) producedCredentials.add(String(handle));
    return null;
  };

  for (const id of requires) {
    const gap = visit(id, []);
    if (gap) return {schema: TWIN_MAP_SCHEMA, intent, resolved: false, gap, plan: []};
  }
  return {schema: TWIN_MAP_SCHEMA, intent, resolved: true, gap: null, plan};
}
