import assert from "node:assert/strict";
import test from "node:test";
import {ticketCurrencyDecision} from "../src/ticket-currency.mjs";

const active = (id, labels = []) => ({id, status: "open", execution: {state: "waiting_input"}, labels});

test("ticket currency remains current without a declared supersession constraint", () => {
  const ticket = active("PLF-1");
  assert.deepEqual(ticketCurrencyDecision(ticket, {tickets: [ticket]}), {
    schema: "subactor.ticket-currency/v1",
    ticket_id: "PLF-1",
    status: "current",
    current: true,
    cancel_recommended: false,
    reason: "no_explicit_currency_constraint",
    related_ticket_id: null,
    relations: [],
  });
});

test("derived work becomes obsolete only when its explicit source is terminal", () => {
  const child = active("PLF-2", ["source:PLF-1"]);
  const source = {...active("PLF-1"), status: "done", execution: {state: "done"}};
  const result = ticketCurrencyDecision(child, {tickets: [child, source]});
  assert.equal(result.status, "obsolete");
  assert.equal(result.cancel_recommended, true);
  assert.equal(result.reason, "source_ticket_done");
});

test("missing related state is uncertain and never an automatic cancellation", () => {
  const result = ticketCurrencyDecision(active("PLF-2", ["superseded-by:PLF-3"]), {tickets: []});
  assert.equal(result.status, "uncertain");
  assert.equal(result.cancel_recommended, false);
});

test("explicit live successor makes the old ticket obsolete", () => {
  const previous = active("PLF-2", ["superseded-by:PLF-3"]);
  const result = ticketCurrencyDecision(previous, {tickets: [previous, active("PLF-3")]});
  assert.equal(result.status, "obsolete");
  assert.equal(result.related_ticket_id, "PLF-3");
});
