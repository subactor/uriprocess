import {isActiveTicket} from "./ticket-readiness.mjs";

const RELATION = /^(source|superseded-by):([A-Z]+-[0-9]+)$/;

export const TICKET_CURRENCY_SCHEMA = "subactor.ticket-currency/v1";

export function ticketCurrencyDecision(ticket, {tickets = []} = {}) {
  const relations = explicitCurrencyRelations(ticket);
  if (!isActiveTicket(ticket)) {
    return decision(ticket, "terminal", false, "ticket_already_terminal", relations);
  }

  const supersedingId = relations.find((item) => item.type === "superseded-by")?.ticket_id || null;
  if (supersedingId) {
    const successor = tickets.find((item) => item?.id === supersedingId) || null;
    if (!successor) return decision(ticket, "uncertain", false, "superseding_ticket_not_observed", relations);
    if (String(successor.status || "") !== "canceled") {
      return decision(ticket, "obsolete", true, "ticket_explicitly_superseded", relations, supersedingId);
    }
  }

  const sourceId = relations.find((item) => item.type === "source")?.ticket_id
    || String(ticket?.inputs?.source_ticket_id || "").trim()
    || null;
  if (!sourceId) return decision(ticket, "current", false, "no_explicit_currency_constraint", relations);
  const source = tickets.find((item) => item?.id === sourceId) || null;
  if (!source) return decision(ticket, "uncertain", false, "source_ticket_not_observed", relations, sourceId);
  if (!isActiveTicket(source)) {
    return decision(ticket, "obsolete", true, `source_ticket_${String(source.status || "terminal")}`, relations, sourceId);
  }
  return decision(ticket, "current", false, "source_ticket_active", relations, sourceId);
}

export function explicitCurrencyRelations(ticket) {
  return (ticket?.labels || [])
    .map((label) => String(label).match(RELATION))
    .filter(Boolean)
    .map((match) => ({type: match[1], ticket_id: match[2]}));
}

function decision(ticket, status, cancelRecommended, reason, relations, relatedTicketId = null) {
  return {
    schema: TICKET_CURRENCY_SCHEMA,
    ticket_id: String(ticket?.id || ""),
    status,
    current: status === "current",
    cancel_recommended: cancelRecommended,
    reason,
    related_ticket_id: relatedTicketId,
    relations,
  };
}
