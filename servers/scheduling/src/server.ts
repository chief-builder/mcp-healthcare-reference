/**
 * Scheduling MCP server — hand-built, stateless (2026-07-28 model).
 *
 * Demonstrates the fidelity-contract statelessness property: continuity lives
 * in explicit `slot_hold_id` HANDLES, and hold state lives in Postgres (shared),
 * NOT in server memory. Any replica can serve any request — hold a slot on one,
 * confirm it on another after the first is killed.
 *
 * Same OAuth 2.1 resource-server posture as the generated servers (reuses their
 * oauth-resource-server module): PRM, audience binding, per-tool scope 403.
 */
import express, { type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import {
  buildProtectedResourceMetadata,
  createTokenVerifier,
  type ResourceServerConfig,
} from './oauth-resource-server.js';

const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT || '3000', 10);
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://${HOST}:${PORT}`;
const RESOURCE_CONFIG: ResourceServerConfig = {
  resourceUri: process.env.MCP_RESOURCE_URI || 'mcp://srv/scheduling',
  authorizationServers: (process.env.MCP_AUTHORIZATION_SERVERS || '').split(',').map((s) => s.trim()).filter(Boolean),
  jwksUri: process.env.MCP_JWKS_URI || '',
  issuer: process.env.MCP_ISSUER || undefined,
};

// Per-tool required scope (missing -> 403 insufficient_scope, step-up).
const TOOL_SCOPE: Record<string, string | undefined> = {
  'find-slots': undefined, // floor
  'hold-slot': 'mcp:scheduling:hold-slot:execute',
  'confirm-hold': 'mcp:scheduling:confirm:execute',
  'release-hold': 'mcp:scheduling:confirm:execute',
};

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export async function initSchema(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scheduling_holds (
      slot_hold_id UUID PRIMARY KEY,
      slot_id      TEXT NOT NULL,
      subject      TEXT NOT NULL,
      status       TEXT NOT NULL DEFAULT 'held',
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
}

// Synthetic, deterministic slot catalogue (no state; a real server would query
// the practice-management system).
function findSlots(date: string, provider: string): Array<{ slot_id: string; start: string }> {
  const day = date || '2026-07-10';
  return ['09:00', '09:30', '10:00'].map((t) => ({
    slot_id: `slot-${provider || 'dr-smith'}-${day}-${t.replace(':', '')}`,
    start: `${day}T${t}:00`,
  }));
}

function buildMcpServer(auth?: AuthInfo): McpServer {
  const subject = (auth?.extra as any)?.sub || auth?.clientId || 'unknown';
  const server = new McpServer({ name: 'scheduling-mcp', version: '1.0.0' });

  server.registerTool('find-slots',
    { description: 'List available appointment slots', inputSchema: { date: z.string().optional(), provider: z.string().optional() } },
    async ({ date, provider }) => ({
      content: [{ type: 'text', text: JSON.stringify(findSlots(date ?? '', provider ?? ''), null, 2) }],
    }));

  server.registerTool('hold-slot',
    { description: 'Place a hold on a slot; returns an explicit slot_hold_id handle', inputSchema: { slot_id: z.string() } },
    async ({ slot_id }) => {
      const slotHoldId = randomUUID();
      await pool.query('INSERT INTO scheduling_holds (slot_hold_id, slot_id, subject) VALUES ($1,$2,$3)',
        [slotHoldId, slot_id, subject]);
      return { content: [{ type: 'text', text: JSON.stringify({ slot_hold_id: slotHoldId, slot_id, status: 'held' }) }] };
    });

  server.registerTool('confirm-hold',
    { description: 'Confirm a previously placed hold by its slot_hold_id', inputSchema: { slot_hold_id: z.string() } },
    async ({ slot_hold_id }) => {
      const r = await pool.query(
        "UPDATE scheduling_holds SET status='confirmed' WHERE slot_hold_id=$1 AND subject=$2 RETURNING slot_id, status",
        [slot_hold_id, subject]);
      if (r.rowCount === 0) {
        return { content: [{ type: 'text', text: JSON.stringify({ error: 'unknown or unowned slot_hold_id' }) }], isError: true };
      }
      return { content: [{ type: 'text', text: JSON.stringify({ slot_hold_id, ...r.rows[0] }) }] };
    });

  server.registerTool('release-hold',
    { description: 'Release a hold by its slot_hold_id', inputSchema: { slot_hold_id: z.string() } },
    async ({ slot_hold_id }) => {
      await pool.query('DELETE FROM scheduling_holds WHERE slot_hold_id=$1 AND subject=$2', [slot_hold_id, subject]);
      return { content: [{ type: 'text', text: JSON.stringify({ slot_hold_id, status: 'released' }) }] };
    });

  return server;
}

export function createApp() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  const resourceMetadataUrl = `${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource`;
  app.use('/.well-known/oauth-protected-resource',
    metadataHandler(buildProtectedResourceMetadata(RESOURCE_CONFIG)));

  const bearer = requireBearerAuth({ verifier: createTokenVerifier(RESOURCE_CONFIG), resourceMetadataUrl });

  function enforceToolScope(req: Request, res: Response, next: NextFunction): void {
    if (req.body?.method !== 'tools/call') return next();
    const need = TOOL_SCOPE[req.body?.params?.name];
    if (!need) return next();
    if ((req.auth?.scopes || []).includes(need)) return next();
    res.status(403)
      .set('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${need}", resource_metadata="${resourceMetadataUrl}"`)
      .json({ error: 'insufficient_scope', scope: need });
  }

  app.post('/mcp', bearer, enforceToolScope, async (req: Request, res: Response) => {
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    const server = buildMcpServer(req.auth);
    res.on('close', () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  return app;
}
