/**
 * Scheduling MCP server — hand-built, stateless (2026-07-28 model).
 *
 * Demonstrates the fidelity-contract statelessness property: continuity lives
 * in explicit `slot_hold_id` HANDLES, and hold state lives in Postgres (shared),
 * NOT in server memory. Any replica can serve any request — hold a slot on one,
 * confirm it on another after the first is killed.
 *
 * Same OAuth 2.1 resource-server posture as fhir-clinical (both use
 * @mcp-lab/shared): PRM, audience binding, per-tool scope challenge.
 */
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { McpServer, type AuthInfo } from '@modelcontextprotocol/server';
import {
  auditToolCall,
  checkToolPolicy,
  claimsOf,
  createMcpApp,
  type Decision,
  type ToolPolicy,
} from '@mcp-lab/shared';
import type { JWTVerifyGetKey } from 'jose';
import type { SchedulingConfig } from './config.js';
import { confirmHold, findSlots, holdSlot, releaseHold, type Db, type HoldOutcome } from './holds.js';

// Per-tool required scope (missing -> 403 insufficient_scope, step-up).
const TOOL_SCOPE: Record<string, string | undefined> = {
  'find-slots': undefined, // floor
  'hold-slot': 'mcp:scheduling:hold-slot:execute',
  'confirm-hold': 'mcp:scheduling:confirm:execute',
  'release-hold': 'mcp:scheduling:confirm:execute',
};

export function policyFor(toolName: string): ToolPolicy | undefined {
  const requiredScope = TOOL_SCOPE[toolName];
  return requiredScope ? { requiredScope } : undefined;
}

function textResult(payload: unknown, isError = false) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload) }], ...(isError ? { isError } : {}) };
}

export function buildMcpServer(config: SchedulingConfig, db: Db, auth?: AuthInfo): McpServer {
  const claims = claimsOf(auth);
  const subject = (typeof claims.sub === 'string' && claims.sub) || auth?.clientId || '';
  const server = new McpServer({ name: 'scheduling-mcp', version: '2.0.0' });
  const audit = (tool: string, decision: Decision, reason?: string) =>
    auditToolCall(config.resource.resourceUri, auth, tool, decision, reason);

  // Shared wrapper: policy check, subject check, outcome → result + audit.
  const guarded =
    <A>(tool: string, run: (args: A) => Promise<HoldOutcome>) =>
    async (args: A) => {
      const denied = checkToolPolicy(policyFor(tool), auth, config.mfaScopes);
      if (denied) {
        audit(tool, 'deny', denied.reason);
        return { content: denied.content, isError: true };
      }
      if (!subject) {
        audit(tool, 'deny', 'no_subject');
        return textResult({ error: 'token carries no usable subject' }, true);
      }
      try {
        const out = await run(args);
        if (!out.ok) {
          audit(tool, 'deny', out.reason);
          return textResult({ error: out.error }, true);
        }
        audit(tool, 'allow');
        const { ok: _ok, ...payload } = out;
        return textResult(payload);
      } catch (err) {
        // Database detail stays in the server log, not in the client result.
        console.error(`scheduling-mcp: ${tool} failed: ${(err as Error).message}`);
        audit(tool, 'deny', 'error');
        return textResult({ error: 'internal error' }, true);
      }
    };

  server.registerTool(
    'find-slots',
    {
      description: 'List available appointment slots',
      inputSchema: z.object({ date: z.string().optional(), provider: z.string().optional() }),
    },
    async ({ date, provider }) => {
      audit('find-slots', 'allow');
      return textResult(findSlots(date ?? '', provider ?? ''));
    },
  );

  server.registerTool(
    'hold-slot',
    {
      description: 'Place a hold on a slot; returns an explicit slot_hold_id handle',
      inputSchema: z.object({ slot_id: z.string() }),
    },
    guarded<{ slot_id: string }>('hold-slot', ({ slot_id }) =>
      holdSlot(db, slot_id, subject, config.holdTtlSeconds, randomUUID),
    ),
  );

  server.registerTool(
    'confirm-hold',
    {
      description: 'Confirm a previously placed hold by its slot_hold_id',
      inputSchema: z.object({ slot_hold_id: z.uuid() }),
    },
    guarded<{ slot_hold_id: string }>('confirm-hold', ({ slot_hold_id }) => confirmHold(db, slot_hold_id, subject)),
  );

  server.registerTool(
    'release-hold',
    {
      description: 'Release a hold by its slot_hold_id',
      inputSchema: z.object({ slot_hold_id: z.uuid() }),
    },
    guarded<{ slot_hold_id: string }>('release-hold', ({ slot_hold_id }) => releaseHold(db, slot_hold_id, subject)),
  );

  return server;
}

export function createApp(config: SchedulingConfig, db: Db, deps: { keySet?: JWTVerifyGetKey } = {}) {
  return createMcpApp({
    host: config.host,
    publicBaseUrl: config.publicBaseUrl,
    allowedOrigins: config.allowedOrigins,
    resource: config.resource,
    dpopHtu: config.dpopHtu,
    policyFor,
    mfaScopes: config.mfaScopes,
    onDeny: (auth, tool, reason) => auditToolCall(config.resource.resourceUri, auth, tool, 'deny', reason),
    buildServer: (auth) => buildMcpServer(config, db, auth),
    keySet: deps.keySet,
  });
}
