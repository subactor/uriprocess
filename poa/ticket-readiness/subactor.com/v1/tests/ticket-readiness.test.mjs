import assert from "node:assert/strict";
import test from "node:test";
import {terminalExecutionMismatch, terminalStatusMismatch, ticketReadinessDecision} from "../src/ticket-readiness.mjs";

const URI = "planfile://subactor/tickets/command/reconcile-lifecycle";

function bot(id = "project-operator-bot") {
  return {id, kind: "bot"};
}

function ticket() {
  return {
    id: "PLF-900",
    status: "open",
    executor: {handler: "project-operator-bot"},
    execution: {state: "ready", assigned_to: "project-operator-bot"},
    inputs: {
      uri_processes: [{id: "reconcile", uri: URI, actor: "bot:project-operator-bot", depends_on: [], human_approval: false}],
      process_manifest: {schema: "subactor.process-envelope.v2", definitions: {
        aql: [{actor: "bot:project-operator-bot"}],
        eql: [{id: "reconciled", verified_by: ["reconcile"]}],
        oql: [{id: "reconcile", op: "ticket.lifecycle.reconcile"}],
        uri: [{id: "reconcile", uri: URI}],
      }},
    },
  };
}

const covered = () => ({ok: true, reasons: []});

test("shared readiness contract accepts an exact, actor-covered v2 process", () => {
  const decision = ticketReadinessDecision(ticket(), {actors: [bot()], routes: [URI], actorCoversRequirements: covered});
  assert.equal(decision.ok, true);
  assert.equal(decision.action, "execute");
  assert.deepEqual(decision.process_actors, {reconcile: "project-operator-bot"});
});

test("shared readiness contract binds execution actor and graph to the canonical URI definition", () => {
  const value = ticket();
  value.inputs.uri_processes[0].depends_on = [];
  const decision = ticketReadinessDecision(value, {actors: [bot()], routes: [URI], actorCoversRequirements: covered});
  assert.equal(decision.action, "execute");
  assert.equal(decision.processes[0].actor, "bot:project-operator-bot");
});

test("shared readiness contract rejects disagreement between canonical and executable steps", () => {
  const actorMismatch = ticket();
  actorMismatch.inputs.process_manifest.definitions.uri[0].actor = "bot:security-bot";
  assert.equal(ticketReadinessDecision(actorMismatch, {actors: [bot()], routes: [URI], actorCoversRequirements: covered}).reason, "process_actor_mismatch:reconcile");

  const uriMismatch = ticket();
  uriMismatch.inputs.uri_processes[0].uri = "repo://workspace/other/command/run";
  assert.equal(ticketReadinessDecision(uriMismatch, {actors: [bot()], routes: [URI], actorCoversRequirements: covered}).reason, "process_uri_mismatch:reconcile");

  const boundaryMismatch = ticket();
  boundaryMismatch.inputs.process_manifest.definitions.uri[0].human_approval = true;
  boundaryMismatch.inputs.uri_processes[0].human_approval = false;
  boundaryMismatch.inputs.uri_processes[0].status = "pending";
  assert.equal(ticketReadinessDecision(boundaryMismatch, {actors: [bot()], routes: [URI], actorCoversRequirements: covered}).reason, "process_human_boundary_mismatch:reconcile");

  const boundaryApproved = ticket();
  boundaryApproved.inputs.process_manifest.definitions.uri[0].human_approval = true;
  boundaryApproved.inputs.uri_processes[0].human_approval = false;
  boundaryApproved.inputs.uri_processes[0].status = "approved";
  assert.equal(ticketReadinessDecision(boundaryApproved, {actors: [bot()], routes: [URI], actorCoversRequirements: covered}).ok, true);
});


test("shared readiness contract fails closed without a route or contract validator", () => {
  assert.equal(ticketReadinessDecision(ticket(), {actors: [bot()], routes: [URI]}).reason, "actor_contract_validator_required");
  const decision = ticketReadinessDecision(ticket(), {actors: [bot()], routes: [], actorCoversRequirements: covered});
  assert.equal(decision.reason, "exact_route_missing");
  assert.deepEqual(decision.missing_routes, [URI]);
});

test("human and waiting-input tickets are notification work, not autonomous execution", () => {
  const humanTicket = ticket();
  humanTicket.execution.assigned_to = "founder";
  assert.equal(ticketReadinessDecision(humanTicket, {actors: [{id: "founder", kind: "human"}]}).action, "notify");
  const waiting = ticket();
  waiting.execution.state = "waiting_input";
  assert.equal(ticketReadinessDecision(waiting, {actors: [bot()]}).reason, "waiting_for_input");
});

test("a waiting ticket preserves an earlier human-boundary diagnosis so its child can be materialized", () => {
  const waiting = ticket();
  waiting.execution = {
    ...waiting.execution,
    state: "waiting_input",
    last_error: "readiness_preflight:human_boundary_requires_child_ticket:publish",
  };
  const decision = ticketReadinessDecision(waiting, {actors: [bot()]});
  assert.equal(decision.action, "blocked");
  assert.equal(decision.reason, "human_boundary_requires_child_ticket:publish");
});

test("a stale ready projection cannot exceed its execution attempt budget", () => {
  const exhausted = ticket();
  exhausted.execution.attempt = 1;
  exhausted.execution.max_attempts = 1;
  const decision = ticketReadinessDecision(exhausted, {actors: [bot()], routes: [URI], actorCoversRequirements: covered});
  assert.equal(decision.action, "blocked");
  assert.equal(decision.reason, "attempt_budget_exhausted");
  assert.equal(decision.attempt, 1);
});

test("every process must be covered by a concrete EQL verified_by binding", () => {
  const value = ticket();
  value.inputs.process_manifest.definitions.eql[0].verified_by = [];
  assert.match(ticketReadinessDecision(value, {actors: [bot()], routes: [URI], actorCoversRequirements: covered}).reason, /^expectation_unbound/);
});

test("control-only EQL expectations bind without pretending to be process steps", () => {
  const value = ticket();
  value.inputs.process_manifest.definitions.eql.push({
    id: "no-disclosure",
    expected: "secret_is_absent_from_ticket_and_audit",
    verified_by_control: ["secret-redaction"],
  });
  const decision = ticketReadinessDecision(value, {
    actors: [bot()],
    routes: [URI],
    actorCoversRequirements: covered,
  });
  assert.notEqual(decision.reason, "expectation_unbound:no-disclosure");
});

test("terminal lifecycle projection names the exact execution state to repair", () => {
  assert.deepEqual(terminalExecutionMismatch({id: "PLF-1", status: "done", execution: {state: "waiting_input"}}), {
    ticket_id: "PLF-1", expected: "done", actual: "waiting_input",
  });
  assert.equal(terminalExecutionMismatch({id: "PLF-2", status: "failed", execution: {state: "failed"}}), null);
  assert.equal(terminalExecutionMismatch({id: "PLF-3", status: "open", execution: {state: "ready"}}), null);
});

test("completed process steps are skipped in actor contract and route checks", () => {
  const GATE_URI = "planfile://tickets/PLF-849/query/result";
  const SEND_URI = "email://approved-recipients/message/command/send";
  const multiStepTicket = {
    id: "PLF-852",
    status: "open",
    executor: {handler: "communications-bot"},
    execution: {state: "ready", assigned_to: "communications-bot"},
    inputs: {
      uri_processes: [
        {id: "approval-gate", uri: GATE_URI, actor: "bot:communications-bot", depends_on: [], human_approval: false, status: "completed"},
        {id: "send-approved", uri: SEND_URI, actor: "bot:communications-bot", depends_on: ["approval-gate"], human_approval: false, status: "approved"},
      ],
      process_manifest: {schema: "subactor.process-envelope.v2", definitions: {
        aql: [{actor: "bot:communications-bot"}],
        eql: [
          {id: "approval-checked", verified_by: ["approval-gate"]},
          {id: "sent", verified_by: ["send-approved"]},
        ],
        oql: [
          {id: "approval-gate", op: "ticket.query.result"},
          {id: "send-approved", op: "email.send"},
        ],
        uri: [
          {id: "approval-gate", uri: GATE_URI},
          {id: "send-approved", uri: SEND_URI},
        ],
      }},
    },
  };
  const commBot = {id: "communications-bot", kind: "bot"};
  // Only the send URI has a route — the gate URI does not, but it's completed.
  const routes = [SEND_URI];
  // The contract validator only covers the send URI — the gate URI is not covered, but it's completed.
  const selectiveCover = (actor, req) => {
    const uris = (req?.uri_processes || []);
    const allCovered = uris.every((u) => u === SEND_URI);
    return allCovered ? {ok: true, reasons: []} : {ok: false, reasons: [`uri_process_not_allowed:${uris.join(",")}`]};
  };
  const decision = ticketReadinessDecision(multiStepTicket, {actors: [commBot], routes, actorCoversRequirements: selectiveCover});
  assert.equal(decision.action, "execute", `expected execute but got ${decision.action}: ${decision.reason}`);
  assert.equal(decision.reason, "ready");
  assert.deepEqual(decision.process_actors, {"send-approved": "communications-bot"});
});

test("completed steps are still included in EQL coverage and ordering checks", () => {
  const GATE_URI = "planfile://tickets/PLF-849/query/result";
  const SEND_URI = "email://approved-recipients/message/command/send";
  const multiStepTicket = {
    id: "PLF-853",
    status: "open",
    executor: {handler: "communications-bot"},
    execution: {state: "ready", assigned_to: "communications-bot"},
    inputs: {
      uri_processes: [
        {id: "approval-gate", uri: GATE_URI, actor: "bot:communications-bot", depends_on: [], human_approval: false, status: "completed"},
        {id: "send-approved", uri: SEND_URI, actor: "bot:communications-bot", depends_on: ["approval-gate"], human_approval: false},
      ],
      process_manifest: {schema: "subactor.process-envelope.v2", definitions: {
        aql: [{actor: "bot:communications-bot"}],
        eql: [
          {id: "approval-checked", verified_by: ["approval-gate"]},
          {id: "sent", verified_by: ["send-approved"]},
        ],
        oql: [
          {id: "approval-gate", op: "ticket.query.result"},
          {id: "send-approved", op: "email.send"},
        ],
        uri: [
          {id: "approval-gate", uri: GATE_URI},
          {id: "send-approved", uri: SEND_URI},
        ],
      }},
    },
  };
  const commBot = {id: "communications-bot", kind: "bot"};
  const routes = [GATE_URI, SEND_URI];
  const decision = ticketReadinessDecision(multiStepTicket, {actors: [commBot], routes, actorCoversRequirements: covered});
  assert.equal(decision.action, "execute");
  assert.equal(decision.reason, "ready");
});

test("terminal status mismatch flags open tickets with terminal execution state", () => {
  assert.equal(terminalStatusMismatch({id: "PLF-1", status: "open", execution: {state: "ready"}}), null);
  const mismatch = terminalStatusMismatch({id: "PLF-2", status: "open", execution: {state: "done"}});
  assert.deepEqual(mismatch, {ticket_id: "PLF-2", expected: "done", actual: "open"});
  assert.equal(terminalStatusMismatch({id: "PLF-3", status: "done", execution: {state: "done"}}), null);
});
