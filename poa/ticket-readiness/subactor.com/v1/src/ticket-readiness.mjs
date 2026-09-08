/** Shared, deterministic readiness contract for governed Planfile tickets. */

export const TERMINAL_TICKET_STATUSES = new Set(["done", "canceled", "failed", "blocked"]);
export const TERMINAL_EXECUTION_STATES = new Set(["done", "canceled", "failed"]);
export const CURRENT_TICKET_CONTRACT_VERSION = "planfile.ticket/v1";

export function ticketContractCompatibility(ticket) {
  const version = String(ticket?.contract_version || "").trim();
  if (!version) return {version: null, mode: "legacy", supported: true};
  if (version === CURRENT_TICKET_CONTRACT_VERSION) {
    return {version, mode: "native", supported: true};
  }
  return {version, mode: "unsupported", supported: false};
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

export function normalizeTicketActorId(value) {
  return String(value || "").trim().replace(/^(?:bot|human|machine|service|authority):/, "");
}

export function isActiveTicket(ticket) {
  return !TERMINAL_TICKET_STATUSES.has(String(ticket?.status || ""))
    && !TERMINAL_EXECUTION_STATES.has(String(ticket?.execution?.state || ""));
}

export function expectedTerminalExecutionState(ticket) {
  const status = String(ticket?.status || "");
  return TERMINAL_TICKET_STATUSES.has(status) ? status : null;
}

export function terminalExecutionMismatch(ticket) {
  const expected = expectedTerminalExecutionState(ticket);
  if (!expected) return null;
  const actual = String(ticket?.execution?.state || "");
  return actual === expected ? null : {ticket_id: ticket?.id || null, expected, actual: actual || null};
}

/** When execution is terminal but ticket.status still projects as active. */
export function terminalStatusMismatch(ticket) {
  const executionState = String(ticket?.execution?.state || "");
  if (!TERMINAL_EXECUTION_STATES.has(executionState)) return null;
  const expected = executionState;
  const actual = String(ticket?.status || "");
  return actual === expected ? null : {ticket_id: ticket?.id || null, expected, actual: actual || null};
}

function orderedProcesses(processes) {
  const byId = new Map();
  for (const process of processes) {
    const id = String(process?.id || "").trim();
    if (!id || byId.has(id)) return {ok: false, reason: "process_id_invalid_or_duplicate"};
    byId.set(id, process);
  }
  for (const process of processes) {
    for (const dependency of list(process.depends_on).map(String)) {
      if (!byId.has(dependency)) return {ok: false, reason: `process_dependency_missing:${dependency}`};
    }
  }
  const ordered = [];
  const completed = new Set();
  while (ordered.length < processes.length) {
    const ready = processes
      .filter((process) => !completed.has(String(process.id)))
      .filter((process) => list(process.depends_on).every((id) => completed.has(String(id))))
      .sort((left, right) => String(left.id).localeCompare(String(right.id)));
    if (!ready.length) return {ok: false, reason: "process_dependency_cycle"};
    for (const process of ready) {
      completed.add(String(process.id));
      ordered.push(process);
    }
  }
  return {ok: true, processes: ordered};
}

function expectationCoverage(eql, processIds) {
  const covered = new Set();
  for (const expectation of eql) {
    const verifiedBy = list(expectation?.verified_by).map(String).filter(Boolean);
    const verifiedByControl = list(expectation?.verified_by_control).map(String).filter(Boolean);
    // Control-level invariants (for example secret redaction) are valid
    // evidence even though they are intentionally not process steps. Older
    // readiness code treated these as unbound and stranded secure intake
    // tickets in waiting_input forever.
    if (!verifiedBy.length && !verifiedByControl.length) {
      return {ok: false, reason: `expectation_unbound:${String(expectation?.id || "unknown")}`};
    }
    for (const id of verifiedBy) {
      if (!processIds.has(id)) return {ok: false, reason: `expectation_verifier_unknown:${id}`};
      covered.add(id);
    }
  }
  const missing = [...processIds].filter((id) => !covered.has(id));
  return missing.length ? {ok: false, reason: `process_without_expectation:${missing.join(",")}`} : {ok: true};
}

function exactRouteSet(routes) {
  return new Set(list(routes)
    .map((route) => String(typeof route === "string" ? route : route?.uri || ""))
    .filter(Boolean));
}

function sameStringList(left, right) {
  return JSON.stringify(list(left).map(String)) === JSON.stringify(list(right).map(String));
}

function bindExecutableProcesses(ticket, definitions) {
  const declared = list(definitions?.uri);
  const executionSteps = list(ticket?.inputs?.uri_processes);
  const executionById = new Map();
  for (const step of executionSteps) {
    const id = String(step?.id || "").trim();
    if (!id || executionById.has(id)) return {ok: false, reason: "process_execution_id_invalid_or_duplicate"};
    executionById.set(id, step);
  }
  const declaredIds = new Set(declared.map((process) => String(process?.id || "").trim()).filter(Boolean));
  const unknown = [...executionById.keys()].find((id) => !declaredIds.has(id));
  if (unknown) return {ok: false, reason: `process_execution_step_unknown:${unknown}`};

  const processes = [];
  for (const definition of declared) {
    const id = String(definition?.id || "").trim();
    const step = executionById.get(id) || null;
    const declaredUri = String(definition?.uri || "");
    const executionUri = String(step?.uri || "");
    if (step && declaredUri && executionUri && declaredUri !== executionUri) {
      return {ok: false, reason: `process_uri_mismatch:${id}`};
    }
    const declaredActor = normalizeTicketActorId(definition?.actor);
    const executionActor = normalizeTicketActorId(step?.actor);
    if (declaredActor && executionActor && declaredActor !== executionActor) {
      return {ok: false, reason: `process_actor_mismatch:${id}`};
    }
    if (Object.hasOwn(definition || {}, "depends_on") && step && Object.hasOwn(step, "depends_on")
      && !sameStringList(definition.depends_on, step.depends_on)) {
      return {ok: false, reason: `process_dependencies_mismatch:${id}`};
    }
    if (Object.hasOwn(definition || {}, "human_approval") && step && Object.hasOwn(step, "human_approval")
      && Boolean(definition.human_approval) !== Boolean(step.human_approval)) {
      const isApprovedOrDone = step.status === "approved" || step.status === "done";
      if (!isApprovedOrDone) {
        return {ok: false, reason: `process_human_boundary_mismatch:${id}`};
      }
    }

    processes.push({
      ...definition,
      uri: declaredUri || executionUri,
      actor: definition?.actor || step?.actor || "",
      depends_on: Object.hasOwn(definition || {}, "depends_on") ? list(definition.depends_on) : list(step?.depends_on),
      human_approval: (step?.status === "approved" || step?.status === "done")
        ? false
        : (Object.hasOwn(definition || {}, "human_approval")
          ? definition.human_approval === true
          : step?.human_approval === true),
      status: step?.status || definition?.status || "pending",
    });
  }
  return {ok: true, processes};
}

function result(ticket, action, reason, extra = {}) {
  return {ticket_id: ticket?.id || null, action, ok: action === "execute" || action === "notify", reason, ...extra};
}

/**
 * Assess whether a ticket can enter the autonomous execution path.
 *
 * Human-owned tickets remain valid work, but are deliberately returned as
 * `notify`. Bot-owned work is executable only when its v2 envelope, EQL step
 * bindings, dependency graph, actor contracts and exact runtime routes agree.
 */
export function ticketReadinessDecision(ticket, {
  actors = [],
  routes = [],
  actorCoversRequirements = null,
} = {}) {
  if (!isActiveTicket(ticket)) return result(ticket, "ignore", "ticket_terminal");
  const handler = normalizeTicketActorId(ticket?.execution?.assigned_to || ticket?.executor?.handler);
  const actor = actors.find((item) => item.id === handler) || null;
  const actorFields = {actor_id: actor?.id || handler || null};
  if (String(ticket?.execution?.state || "") === "waiting_input") {
    const previousReadinessReason = String(ticket?.execution?.last_error || "")
      .replace(/^readiness_preflight:/, "");
    if (previousReadinessReason.startsWith("human_boundary_requires_child_ticket:")) {
      return result(ticket, "blocked", previousReadinessReason, actorFields);
    }
    return result(ticket, "notify", "waiting_for_input", actorFields);
  }
  if (String(ticket?.execution?.state || "") !== "ready") {
    return result(ticket, "ignore", "not_ready", actorFields);
  }
  const attempt = Number(ticket?.execution?.attempt || 0);
  const maxAttempts = Number(ticket?.execution?.max_attempts || 0);
  if (Number.isFinite(maxAttempts) && maxAttempts > 0 && attempt >= maxAttempts) {
    return result(ticket, "blocked", "attempt_budget_exhausted", {...actorFields, attempt, max_attempts: maxAttempts});
  }
  if (!actor) return result(ticket, "blocked", "assigned_bot_not_registered", actorFields);
  if (actor.kind === "human") return result(ticket, "notify", "human_executor", {actor_id: actor.id});
  if (actor.kind !== "bot") return result(ticket, "blocked", "autonomous_bot_executor_required", {actor_id: actor.id});

  const ticketContract = ticketContractCompatibility(ticket);
  if (!ticketContract.supported) {
    return result(ticket, "blocked", "ticket_contract_version_unsupported", {
      actor_id: actor.id,
      ticket_contract: ticketContract,
    });
  }
  const manifest = ticket?.inputs?.process_manifest;
  if (manifest?.schema !== "subactor.process-envelope.v2") {
    return result(ticket, "blocked", "process_envelope_v2_required", {actor_id: actor.id});
  }
  const definitions = manifest.definitions || {};
  const processBinding = bindExecutableProcesses(ticket, definitions);
  if (!processBinding.ok) return result(ticket, "blocked", processBinding.reason, {actor_id: actor.id});
  const processes = processBinding.processes;
  if (!list(definitions.aql).length || !list(definitions.eql).length || !list(definitions.oql).length || !processes.length) {
    return result(ticket, "blocked", "process_definitions_incomplete", {actor_id: actor.id});
  }
  const processIds = new Set(processes.map((process) => String(process?.id || "")).filter(Boolean));
  const coverage = expectationCoverage(definitions.eql, processIds);
  if (!coverage.ok) return result(ticket, "blocked", coverage.reason, {actor_id: actor.id});
  const ordering = orderedProcesses(processes);
  if (!ordering.ok) return result(ticket, "blocked", ordering.reason, {actor_id: actor.id});
  const humanBoundary = processes.find((process) => process?.human_approval === true && process?.status !== "approved" && process?.status !== "done");
  if (humanBoundary) {
    return result(ticket, "blocked", `human_boundary_requires_child_ticket:${humanBoundary.id}`, {actor_id: actor.id});
  }

  if (typeof actorCoversRequirements !== "function") {
    return result(ticket, "blocked", "actor_contract_validator_required", {actor_id: actor.id});
  }

  const processActors = {};
  for (const process of processes) {
    // Completed steps have already been executed; skip actor contract and route
    // validation for them so a stale or unavailable route on a prior step does
    // not block the remaining executable work.
    if (String(process?.status || "") === "completed") continue;
    const assignedId = normalizeTicketActorId(process?.actor);
    const assignedActor = actors.find((item) => item.id === assignedId) || null;
    if (!assignedActor) {
      return result(ticket, "blocked", `process_actor_not_registered:${process.id}`, {actor_id: actor.id});
    }
    if (assignedActor.kind !== "bot") {
      return result(ticket, "blocked", `process_actor_not_autonomous:${process.id}`, {actor_id: actor.id});
    }
    const contractCoverage = actorCoversRequirements(assignedActor, {uri_processes: [String(process?.uri || "")]});
    if (!contractCoverage.ok) {
      return result(ticket, "blocked", `actor_contract_gap:${process.id}:${contractCoverage.reasons.join(",")}`, {actor_id: actor.id});
    }
    processActors[String(process.id)] = assignedActor.id;
  }

  const availableRoutes = exactRouteSet(routes);
  const missingRoutes = processes
    .filter((process) => String(process?.status || "") !== "completed")
    .map((process) => String(process?.uri || ""))
    .filter((uri) => !availableRoutes.has(uri));
  if (missingRoutes.length) {
    return result(ticket, "blocked", "exact_route_missing", {missing_routes: missingRoutes, actor_id: actor.id});
  }
  return result(ticket, "execute", "ready", {
    actor_id: actor.id,
    ticket_contract: ticketContract,
    process_actors: processActors,
    processes: ordering.processes,
  });
}
