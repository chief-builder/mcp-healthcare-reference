import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { setAuditSink } from '@mcp-lab/shared';
import { loadConfig } from '../src/config.js';
import { initSchema } from '../src/holds.js';
import { createApp } from '../src/server.js';
import {
  captureAudit,
  createTestIssuer,
  listen,
  modernBody,
  modernClient,
  MODERN_HEADERS,
  type TestIssuer,
} from '../../shared/test/helpers.js';
import { createTestDb } from './pglite-db.js';

const RESOURCE = 'mcp://srv/scheduling';
const HOLD = 'mcp:scheduling:hold-slot:execute';
const CONFIRM = 'mcp:scheduling:confirm:execute';
const SLOT = 'slot-loop-agent-2026-07-10-0930';

const ENV = {
  MCP_AUTHORIZATION_SERVERS: 'http://localhost:8080/realms/mcp-plane',
  MCP_JWKS_URI: 'http://keycloak:8080/realms/mcp-plane/protocol/openid-connect/certs',
  DATABASE_URL: 'postgres://u:p@db:5432/scheduling',
};

let issuer: TestIssuer;
let db: Awaited<ReturnType<typeof createTestDb>>;
let server: Awaited<ReturnType<typeof listen>>;
let audit: { lines: string[] };

beforeAll(async () => {
  issuer = await createTestIssuer(RESOURCE);
  db = await createTestDb();
  await initSchema(db);
  server = await listen(createApp(loadConfig(ENV), db, { keySet: issuer.keySet }));
});
afterAll(() => server.close());
beforeEach(async () => {
  await db.query('DELETE FROM scheduling_holds');
  audit = captureAudit(setAuditSink);
});
afterEach(() => setAuditSink((line) => console.log(line)));

const parse = (result: { content: unknown }) => JSON.parse((result.content as { text: string }[])[0].text);

describe('config', () => {
  it('requires the authorization server, JWKS, and database settings', () => {
    expect(() => loadConfig({})).toThrow(/MCP_AUTHORIZATION_SERVERS[\s\S]*MCP_JWKS_URI[\s\S]*DATABASE_URL/);
  });
});

describe('stateless hold flow over 2026-07-28', () => {
  it('find → hold → confirm with explicit handles; any client instance continues it', async () => {
    const token = await issuer.sign({ sub: 'agent-1', scope: `openid ${HOLD} ${CONFIRM}` });
    const a = await modernClient(server.base, token);
    const slots = parse(await a.callTool({ name: 'find-slots', arguments: { provider: 'loop-agent' } }));
    expect(slots.map((s: { slot_id: string }) => s.slot_id)).toContain(SLOT);
    const held = parse(await a.callTool({ name: 'hold-slot', arguments: { slot_id: SLOT } }));
    expect(held.status).toBe('held');
    await a.close();

    // A brand-new client (no shared session) confirms by handle alone.
    const b = await modernClient(server.base, token);
    const confirmed = parse(await b.callTool({ name: 'confirm-hold', arguments: { slot_hold_id: held.slot_hold_id } }));
    expect(confirmed).toMatchObject({ slot_hold_id: held.slot_hold_id, status: 'confirmed' });
    await b.close();
    expect(audit.lines.map((l) => JSON.parse(l).decision)).toEqual(['allow', 'allow', 'allow']);
  });

  it('another subject cannot confirm or release a hold it does not own', async () => {
    const owner = await modernClient(server.base, await issuer.sign({ sub: 'alice', scope: `${HOLD} ${CONFIRM}` }));
    const held = parse(await owner.callTool({ name: 'hold-slot', arguments: { slot_id: SLOT } }));
    const thief = await modernClient(server.base, await issuer.sign({ sub: 'mallory', scope: `${HOLD} ${CONFIRM}` }));
    for (const name of ['confirm-hold', 'release-hold']) {
      const r = await thief.callTool({ name, arguments: { slot_hold_id: held.slot_hold_id } });
      expect(r.isError).toBe(true);
      expect(parse(r).error).toMatch(/another subject/);
    }
    await owner.close();
    await thief.close();
  });

  it('rejects a malformed handle at input validation', async () => {
    const c = await modernClient(server.base, await issuer.sign({ scope: CONFIRM }));
    const r = await c.callTool({ name: 'confirm-hold', arguments: { slot_hold_id: 'not-a-uuid' } });
    expect(r.isError).toBe(true);
    await c.close();
  });
});

describe('per-tool scope enforcement', () => {
  const post = (token: string, body: unknown, headers: Record<string, string> = {}) =>
    fetch(`${server.base}/mcp`, {
      method: 'POST',
      headers: { ...MODERN_HEADERS, authorization: `Bearer ${token}`, ...headers },
      body: JSON.stringify(body),
    });

  it('floor tool needs no extra scope', async () => {
    const c = await modernClient(server.base, await issuer.sign({ scope: 'openid' }));
    expect((await c.callTool({ name: 'find-slots', arguments: {} })).isError).toBeFalsy();
    await c.close();
  });

  it('hold without the hold scope → 403 insufficient_scope', async () => {
    const r = await post(
      await issuer.sign({ scope: 'openid' }),
      modernBody('tools/call', { name: 'hold-slot', arguments: { slot_id: SLOT } }),
      { 'mcp-method': 'tools/call', 'mcp-name': 'hold-slot' },
    );
    expect(r.status).toBe(403);
    expect(r.headers.get('www-authenticate')).toContain(`scope="${HOLD}"`);
    expect((await db.query('SELECT count(*)::int AS n FROM scheduling_holds')).rows[0].n).toBe(0);
  });

  it('S1 regression: a batch cannot place a hold without the scope', async () => {
    const r = await post(await issuer.sign({ scope: 'openid' }), [
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'hold-slot', arguments: { slot_id: SLOT } } },
    ]);
    expect(r.status).toBe(400);
    expect((await db.query('SELECT count(*)::int AS n FROM scheduling_holds')).rows[0].n).toBe(0);
  });

  it('a token with no usable subject is refused', async () => {
    const c = await modernClient(server.base, await issuer.sign({ scope: HOLD, sub: '', azp: '' }));
    const r = await c.callTool({ name: 'hold-slot', arguments: { slot_id: SLOT } });
    expect(r.isError).toBe(true);
    expect(JSON.parse(audit.lines.at(-1)!)).toMatchObject({ reason: 'no_subject' });
    await c.close();
  });
});
