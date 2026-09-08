#!/usr/bin/env node
import { ticketReadinessDecision as decide } from "./src/ticket-readiness.mjs";
let input = '';
try {
  for await (const chunk of process.stdin) {
    input += chunk;
    if (Buffer.byteLength(input) > 1048576) throw new Error('request too large');
  }
  const request = JSON.parse(input);
  if (!request || Array.isArray(request) || typeof request !== 'object'
      || Object.keys(request).some(k => !['ticket', 'context'].includes(k))
      || !request.ticket || typeof request.ticket !== 'object' || Array.isArray(request.ticket))
    throw new Error('invalid request');
  const context = request.context ?? {};
  if (typeof context !== 'object' || Array.isArray(context)
      || Object.keys(context).some(k => !['tickets', 'actors', 'routes'].includes(k))
      || Object.values(context).some(v => !Array.isArray(v))) throw new Error('invalid context');
  process.stdout.write(JSON.stringify(decide(request.ticket, context)) + '\n');
} catch {
  process.stderr.write('{"error":"invalid_process_request"}\n');
  process.exitCode = 2;
}
