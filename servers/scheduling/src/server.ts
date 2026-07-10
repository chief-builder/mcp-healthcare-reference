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
import { auditToolCall } from './audit.js';

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

// A hold that is neither confirmed nor released expires after this window and
// frees the slot again (safe-minimum production semantics).
const HOLD_TTL_S = parseInt(process.env.HOLD_TTL_S || '300', 10);

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export async function initSchema(): Promise<void> {
  const client = await pool.connect();
  try {
    // Serialize the migration across replicas: two replicas booting together
    // otherwise race on CREATE UNIQUE INDEX (one crashes on a duplicate relation).
    await client.query('SELECT pg_advisory_lock(hashtext($1))', ['scheduling_holds_init']);
    await client.query(`
      CREATE TABLE IF NOT EXISTS scheduling_holds (
        slot_hold_id UUID PRIMARY KEY,
        slot_id      TEXT NOT NULL,
        subject      TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'held',
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at   TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
    await client.query(
      "ALTER TABLE scheduling_holds ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT now()");
    // Collapse any pre-constraint duplicate held rows (keep the newest per slot)
    // so the one-active-hold-per-slot unique index can be created safely. The
    // constraint covers 'held' only: it guards the concurrent-hold race, while a
    // terminal 'confirmed' row does not permanently occupy the slot (the lab's
    // deterministic catalogue is shared with a live workload).
    await client.query(`
      UPDATE scheduling_holds SET status='expired'
      WHERE status='held' AND slot_hold_id NOT IN (
        SELECT DISTINCT ON (slot_id) slot_hold_id FROM scheduling_holds
        WHERE status='held' ORDER BY slot_id, created_at DESC)`);
    // Drop first so a predicate change from an earlier revision takes effect
    // (CREATE ... IF NOT EXISTS would keep a stale predicate). Safe: we hold the
    // advisory lock and the server is not yet serving.
    await client.query('DROP INDEX IF EXISTS scheduling_holds_active_slot');
    await client.query(`
      CREATE UNIQUE INDEX scheduling_holds_active_slot
        ON scheduling_holds (slot_id) WHERE status='held'`);
  } finally {
    await client.query('SELECT pg_advisory_unlock(hashtext($1))', ['scheduling_holds_init']).catch(() => {});
    client.release();
  }
}

// Synthetic, deterministic slot catalogue (no state; a real server would query
// the practice-management system).
const SLOT_TIMES = ['09:00', '09:30', '10:00'];
function findSlots(date: string, provider: string): Array<{ slot_id: string; start: string }> {
  const day = date || '2026-07-10';
  return SLOT_TIMES.map((t) => ({
    slot_id: `slot-${provider || 'dr-smith'}-${day}-${t.replace(':', '')}`,
    start: `${day}T${t}:00`,
  }));
}

// A slot_id is bookable only if it has the catalogue's shape: a provider, an
// ISO date, and one of the catalogue's time suffixes.
const SLOT_SUFFIXES = SLOT_TIMES.map((t) => t.replace(':', ''));
function isCatalogueSlot(slotId: string): boolean {
  const m = /^slot-.+-\d{4}-\d{2}-\d{2}-(\d{4})$/.exec(slotId);
  return !!m && SLOT_SUFFIXES.includes(m[1]);
}

function textResult(payload: unknown, isError = false) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(payload) }], ...(isError ? { isError } : {}) };
}

function buildMcpServer(auth?: AuthInfo): McpServer {
  const subject = (auth?.extra as any)?.sub || auth?.clientId || '';
  const server = new McpServer({ name: 'scheduling-mcp', version: '1.0.0' });
  const audit = (tool: string, decision: 'allow' | 'deny', reason?: string) =>
    auditToolCall(RESOURCE_CONFIG.resourceUri, auth, tool, decision, reason);

  server.registerTool('find-slots',
    { description: 'List available appointment slots', inputSchema: { date: z.string().optional(), provider: z.string().optional() } },
    async ({ date, provider }) => {
      audit('find-slots', 'allow');
      return textResult(findSlots(date ?? '', provider ?? ''));
    });

  server.registerTool('hold-slot',
    { description: 'Place a hold on a slot; returns an explicit slot_hold_id handle', inputSchema: { slot_id: z.string() } },
    async ({ slot_id }) => {
      if (!subject) { audit('hold-slot', 'deny', 'no_subject'); return textResult({ error: 'token carries no usable subject' }, true); }
      if (!isCatalogueSlot(slot_id)) { audit('hold-slot', 'deny', 'unknown_slot'); return textResult({ error: 'unknown slot_id' }, true); }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        // Free any expired hold on this slot before contending for it.
        await client.query(
          "UPDATE scheduling_holds SET status='expired' WHERE slot_id=$1 AND status='held' AND expires_at <= now()",
          [slot_id]);
        const slotHoldId = randomUUID();
        const ins = await client.query(
          `INSERT INTO scheduling_holds (slot_hold_id, slot_id, subject, status, expires_at)
             VALUES ($1,$2,$3,'held', now() + $4 * interval '1 second')
             ON CONFLICT (slot_id) WHERE status='held'
             DO NOTHING RETURNING slot_hold_id`,
          [slotHoldId, slot_id, subject, HOLD_TTL_S]);
        if (ins.rowCount === 1) {
          await client.query('COMMIT');
          audit('hold-slot', 'allow');
          return textResult({ slot_hold_id: slotHoldId, slot_id, status: 'held' });
        }
        // Slot already actively held: the owner gets their existing handle back
        // (idempotent); anyone else is refused until it releases or expires.
        const cur = await client.query(
          "SELECT slot_hold_id, subject, status FROM scheduling_holds WHERE slot_id=$1 AND status='held'",
          [slot_id]);
        await client.query('COMMIT');
        const row = cur.rows[0];
        if (row && row.subject === subject) {
          audit('hold-slot', 'allow');
          return textResult({ slot_hold_id: row.slot_hold_id, slot_id, status: row.status });
        }
        audit('hold-slot', 'deny', 'slot_taken');
        return textResult({ error: 'slot is already held' }, true);
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        audit('hold-slot', 'deny', 'error');
        return textResult({ error: (err as Error).message }, true);
      } finally {
        client.release();
      }
    });

  server.registerTool('confirm-hold',
    { description: 'Confirm a previously placed hold by its slot_hold_id', inputSchema: { slot_hold_id: z.string() } },
    async ({ slot_hold_id }) => {
      if (!subject) { audit('confirm-hold', 'deny', 'no_subject'); return textResult({ error: 'token carries no usable subject' }, true); }
      const r = await pool.query(
        'SELECT slot_id, subject, status, (expires_at <= now()) AS expired FROM scheduling_holds WHERE slot_hold_id=$1',
        [slot_hold_id]);
      const row = r.rows[0];
      if (!row) { audit('confirm-hold', 'deny', 'unknown'); return textResult({ error: 'unknown slot_hold_id' }, true); }
      if (row.subject !== subject) { audit('confirm-hold', 'deny', 'unowned'); return textResult({ error: 'slot_hold_id belongs to another subject' }, true); }
      if (row.status === 'released') { audit('confirm-hold', 'deny', 'released'); return textResult({ error: 'hold was released' }, true); }
      if (row.status === 'confirmed') { audit('confirm-hold', 'allow'); return textResult({ slot_hold_id, slot_id: row.slot_id, status: 'confirmed' }); }
      if (row.status === 'expired' || row.expired) { audit('confirm-hold', 'deny', 'expired'); return textResult({ error: 'hold expired' }, true); }
      await pool.query("UPDATE scheduling_holds SET status='confirmed' WHERE slot_hold_id=$1 AND subject=$2 AND status='held'",
        [slot_hold_id, subject]);
      audit('confirm-hold', 'allow');
      return textResult({ slot_hold_id, slot_id: row.slot_id, status: 'confirmed' });
    });

  server.registerTool('release-hold',
    { description: 'Release a hold by its slot_hold_id', inputSchema: { slot_hold_id: z.string() } },
    async ({ slot_hold_id }) => {
      if (!subject) { audit('release-hold', 'deny', 'no_subject'); return textResult({ error: 'token carries no usable subject' }, true); }
      const r = await pool.query('SELECT subject, status FROM scheduling_holds WHERE slot_hold_id=$1', [slot_hold_id]);
      const row = r.rows[0];
      if (!row) { audit('release-hold', 'deny', 'unknown'); return textResult({ error: 'unknown slot_hold_id' }, true); }
      if (row.subject !== subject) { audit('release-hold', 'deny', 'unowned'); return textResult({ error: 'slot_hold_id belongs to another subject' }, true); }
      if (row.status === 'released') { audit('release-hold', 'allow'); return textResult({ slot_hold_id, status: 'released' }); }
      await pool.query("UPDATE scheduling_holds SET status='released' WHERE slot_hold_id=$1 AND subject=$2", [slot_hold_id, subject]);
      audit('release-hold', 'allow');
      return textResult({ slot_hold_id, status: 'released' });
    });

  return server;
}

export function createApp() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // RFC 9728 path-insertion (endpoint /mcp); root kept as a back-compat alias.
  const resourceMetadataUrl = `${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource/mcp`;
  const prm = metadataHandler(buildProtectedResourceMetadata(RESOURCE_CONFIG));
  app.use('/.well-known/oauth-protected-resource/mcp', prm);
  app.use('/.well-known/oauth-protected-resource', prm);

  const bearer = requireBearerAuth({ verifier: createTokenVerifier(RESOURCE_CONFIG), resourceMetadataUrl });

  function enforceToolScope(req: Request, res: Response, next: NextFunction): void {
    if (req.body?.method !== 'tools/call') return next();
    const need = TOOL_SCOPE[req.body?.params?.name];
    if (!need) return next();
    if ((req.auth?.scopes || []).includes(need)) return next();
    auditToolCall(RESOURCE_CONFIG.resourceUri, req.auth, req.body?.params?.name, 'deny', 'insufficient_scope');
    res.status(403)
      .set('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${need}", resource_metadata="${resourceMetadataUrl}"`)
      .json({ error: 'insufficient_scope', scope: need });
  }

  app.post('/mcp', bearer, enforceToolScope, async (req: Request, res: Response) => {
    // Each tool audits its own final outcome (allow only on success); nothing
    // is logged here before the work runs.
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    const server = buildMcpServer(req.auth);
    res.on('close', () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  return app;
}
