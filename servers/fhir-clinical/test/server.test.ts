import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { setAuditSink } from '@mcp-lab/shared';
import { loadConfig } from '../src/config.js';
import { buildMcpServer, createApp } from '../src/mcp-server.js';
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import {
  captureAudit,
  createDpopKey,
  createTestIssuer,
  listen,
  modernBody,
  modernClient,
  MODERN_HEADERS,
  type TestIssuer,
} from '../../shared/test/helpers.js';

const RESOURCE = 'mcp://srv/fhir-clinical';
const STEP_UP = 'mcp:fhir-clinical:everything:read';
const CLINICIAN = { groups: ['mcp-clinical-tools'], amr: ['pwd', 'mfa'] };

// Upstream FHIR stand-in: records every URL the server asks for.
let upstreamCalls: string[] = [];
let upstreamReply: () => Response = () => new Response(JSON.stringify({ resourceType: 'Bundle', entry: [] }));
const fakeFetch = (async (url: string | URL) => {
  upstreamCalls.push(String(url));
  return upstreamReply();
}) as typeof fetch;

let issuer: TestIssuer;
let server: Awaited<ReturnType<typeof listen>>;
let audit: { lines: string[] };

beforeAll(async () => {
  issuer = await createTestIssuer(RESOURCE);
  const config = loadConfig({ UPSTREAM_TIMEOUT_MS: '200', MAX_UPSTREAM_BYTES: '1000', MAX_FHIR_COUNT: '50' });
  server = await listen(createApp(config, { keySet: issuer.keySet, fetchImpl: fakeFetch }));
});
afterAll(() => server.close());
beforeEach(() => {
  upstreamCalls = [];
  upstreamReply = () => new Response(JSON.stringify({ resourceType: 'Bundle', entry: [] }));
  audit = captureAudit(setAuditSink);
});
afterEach(() => setAuditSink((line) => console.log(line)));

const post = (token: string | undefined, body: unknown, headers: Record<string, string> = {}) =>
  fetch(`${server.base}/mcp`, {
    method: 'POST',
    headers: { ...MODERN_HEADERS, ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: JSON.stringify(body),
  });

const callBody = (name: string, args: Record<string, unknown>, id = 1) =>
  modernBody('tools/call', { name, arguments: args }, id);
const callHeaders = (name: string) => ({ 'mcp-method': 'tools/call', 'mcp-name': name });

describe('discovery and authentication', () => {
  it('serves Protected Resource Metadata at the path-inserted URI and the root alias', async () => {
    for (const path of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource']) {
      const r = await fetch(`${server.base}${path}`);
      expect(r.status).toBe(200);
      expect(await r.json()).toMatchObject({ resource: RESOURCE, dpop_signing_alg_values_supported: ['ES256'] });
    }
  });

  it('challenges a request without a token with resource_metadata', async () => {
    const r = await post(undefined, modernBody('tools/list'), { 'mcp-method': 'tools/list' });
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain('/.well-known/oauth-protected-resource/mcp');
  });

  it('rejects a token minted for another resource (401 invalid_token)', async () => {
    const token = await issuer.sign({ aud: ['mcp://srv/scheduling', 'mcp://tier/internal'] });
    const r = await post(token, modernBody('tools/list'), { 'mcp-method': 'tools/list' });
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain('invalid_token');
  });

  it('rejects a DPoP-bound token presented without a proof', async () => {
    const key = await createDpopKey();
    const token = await issuer.sign({ ...CLINICIAN, cnf: { jkt: key.jkt } });
    const r = await post(token, modernBody('tools/list'), { 'mcp-method': 'tools/list' });
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toMatch(/^DPoP/);
  });

  it('accepts a DPoP-bound token with a valid proof', async () => {
    const key = await createDpopKey();
    const token = await issuer.sign({ ...CLINICIAN, cnf: { jkt: key.jkt } });
    const r = await fetch(`${server.base}/mcp`, {
      method: 'POST',
      headers: {
        ...MODERN_HEADERS,
        'mcp-method': 'tools/list',
        authorization: `DPoP ${token}`,
        dpop: await key.proof({ htu: 'http://127.0.0.1:3000/mcp', token }),
      },
      body: JSON.stringify(modernBody('tools/list')),
    });
    expect(r.status).toBe(200);
  });
});

describe('MCP 2026-07-28 serving', () => {
  it('negotiates 2026-07-28 with the v2 client and lists role-visible tools', async () => {
    const client = await modernClient(server.base, await issuer.sign(CLINICIAN));
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'getPatient',
      'patientEverything',
      'searchCondition',
      'searchMedicationRequest',
      'searchObservation',
    ]);
    await client.close();
  });

  it('hides the clinical-only tool from callers outside the group', async () => {
    const client = await modernClient(server.base, await issuer.sign({ groups: ['analysts'] }));
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).not.toContain('patientEverything');
    expect(names).toContain('getPatient');
    await client.close();
  });

  it('still serves a 2025-era client through the stateless legacy fallback', async () => {
    const token = await issuer.sign(CLINICIAN);
    const init = await fetch(`${server.base}/mcp`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 0,
        method: 'initialize',
        params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'legacy', version: '1' } },
      }),
    });
    expect(init.status).toBe(200);
    expect(await init.text()).toContain('"protocolVersion":"2025-11-25"');
  });

  it('answers GET and DELETE with 405 (no sessions, no server stream)', async () => {
    const token = await issuer.sign(CLINICIAN);
    for (const method of ['GET', 'DELETE']) {
      const r = await fetch(`${server.base}/mcp`, {
        method,
        headers: { authorization: `Bearer ${token}`, accept: 'text/event-stream' },
      });
      expect(r.status).toBe(405);
    }
  });
});

describe('per-tool authorization (step-up, MFA, batch)', () => {
  it('under-scoped call → 403 insufficient_scope naming the scope, upstream untouched', async () => {
    const token = await issuer.sign(CLINICIAN);
    const r = await post(token, callBody('patientEverything', { id: 'p1' }), callHeaders('patientEverything'));
    expect(r.status).toBe(403);
    expect(r.headers.get('www-authenticate')).toContain(`scope="${STEP_UP}"`);
    expect(upstreamCalls).toEqual([]);
    expect(JSON.parse(audit.lines.at(-1)!)).toMatchObject({ decision: 'deny', reason: 'insufficient_scope' });
  });

  it('stepped-up call with MFA → allowed and audited allow', async () => {
    const client = await modernClient(server.base, await issuer.sign({ ...CLINICIAN, scope: `openid ${STEP_UP}` }));
    const result = await client.callTool({ name: 'patientEverything', arguments: { id: 'p1' } });
    expect(result.isError).toBe(false);
    expect(upstreamCalls).toEqual(['http://hapi:8081/fhir/Patient/p1/$everything']);
    expect(JSON.parse(audit.lines.at(-1)!)).toMatchObject({ tool: 'patientEverything', decision: 'allow' });
    await client.close();
  });

  it('stepped-up call WITHOUT the mfa mark → 401 insufficient_user_authentication (RFC 9470)', async () => {
    const token = await issuer.sign({ groups: ['mcp-clinical-tools'], amr: ['pwd'], scope: `openid ${STEP_UP}` });
    const r = await post(token, callBody('patientEverything', { id: 'p1' }), callHeaders('patientEverything'));
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain('error="insufficient_user_authentication"');
    expect(upstreamCalls).toEqual([]);
    expect(JSON.parse(audit.lines.at(-1)!)).toMatchObject({ reason: 'insufficient_user_authentication' });
  });

  it('a token with no amr claim is treated as not MFA-authenticated', async () => {
    const token = await issuer.sign({ groups: ['mcp-clinical-tools'], scope: `openid ${STEP_UP}` });
    const r = await post(token, callBody('patientEverything', { id: 'p1' }), callHeaders('patientEverything'));
    expect(r.status).toBe(401);
  });

  it('S1 regression: a JSON-RPC batch cannot smuggle a tools/call past the scope check', async () => {
    const token = await issuer.sign(CLINICIAN); // no step-up scope
    const legacyCall = {
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'patientEverything', arguments: { id: 'p1' } },
    };
    for (const batch of [[legacyCall], [callBody('patientEverything', { id: 'p1' })], [legacyCall, legacyCall]]) {
      const r = await post(token, batch);
      expect(r.status).toBe(400);
      expect((await r.json()).error.code).toBe(-32600);
    }
    expect(upstreamCalls).toEqual([]);
    expect(audit.lines.filter((l) => l.includes('"decision":"allow"'))).toEqual([]);
  });

  it('the tool handler re-checks policy with no HTTP layer in front of it', async () => {
    // Drive the per-request McpServer directly over an in-memory transport:
    // no bearer/scope middleware runs, so only the handler-level guard stands
    // between an under-scoped caller and the upstream.
    const auth = {
      token: 't',
      clientId: 'c',
      scopes: ['openid'],
      extra: { ...CLINICIAN, sub: 'u', jti: 'j' },
    };
    const mcp = buildMcpServer(loadConfig({}), auth, fakeFetch);
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await mcp.connect(serverSide);
    const client = new Client({ name: 'in-memory', version: '1' });
    await client.connect(clientSide);
    const result = await client.callTool({ name: 'patientEverything', arguments: { id: 'p1' } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain('insufficient_scope');
    expect(upstreamCalls).toEqual([]);
    expect(JSON.parse(audit.lines.at(-1)!)).toMatchObject({ decision: 'deny', reason: 'insufficient_scope' });
    await client.close();
  });
});

describe('patient compartment (Auth0 path)', () => {
  const patient = (scopes: string) =>
    issuer.sign({
      idp_origin: 'auth0',
      fhir_patient: 'p-mine',
      aud: [RESOURCE, 'mcp://tier/external'],
      mcp_tier: 'external',
      scope: scopes,
    });

  it('search is hard-scoped to the token patient, whatever the client asks', async () => {
    const client = await modernClient(server.base, await patient('openid patient/Observation.read'));
    const result = await client.callTool({ name: 'searchObservation', arguments: { patient: 'p-other', _count: 5 } });
    expect(result.isError).toBe(false);
    expect(upstreamCalls).toEqual(['http://hapi:8081/fhir/Observation?patient=p-mine&_count=5']);
    await client.close();
  });

  it('by-id read of another patient is refused without an upstream call', async () => {
    const client = await modernClient(server.base, await patient('openid patient/Patient.read'));
    const result = await client.callTool({ name: 'getPatient', arguments: { id: 'p-other' } });
    expect(result.isError).toBe(true);
    expect(upstreamCalls).toEqual([]);
    expect(JSON.parse(audit.lines.at(-1)!)).toMatchObject({ decision: 'deny', reason: 'compartment' });
    await client.close();
  });

  it('a patient token without the per-resource scope is refused (403)', async () => {
    const token = await patient('openid patient/Patient.read');
    const r = await post(token, callBody('searchCondition', {}), callHeaders('searchCondition'));
    expect(r.status).toBe(403);
    expect(r.headers.get('www-authenticate')).toContain('scope="patient/Condition.read"');
  });
});

describe('upstream guardrails', () => {
  const clinician = () => issuer.sign(CLINICIAN);

  it('clamps _count to MAX_FHIR_COUNT', async () => {
    const client = await modernClient(server.base, await clinician());
    await client.callTool({ name: 'searchObservation', arguments: { patient: 'p1', _count: 100000 } });
    expect(upstreamCalls[0]).toContain('_count=50');
    await client.close();
  });

  it('rejects a non-positive _count without calling upstream', async () => {
    const client = await modernClient(server.base, await clinician());
    const result = await client.callTool({ name: 'searchObservation', arguments: { patient: 'p1', _count: 0 } });
    expect(result.isError).toBe(true);
    expect(upstreamCalls).toEqual([]);
    await client.close();
  });

  it('caps the buffered upstream response size', async () => {
    upstreamReply = () => new Response('x'.repeat(5000));
    const client = await modernClient(server.base, await clinician());
    const result = await client.callTool({ name: 'getPatient', arguments: { id: 'p1' } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain('exceeded 1000 bytes');
    expect(JSON.parse(audit.lines.at(-1)!)).toMatchObject({ decision: 'deny', reason: 'upstream_error' });
    await client.close();
  });

  it('reports an upstream error status as a denied, isError result', async () => {
    upstreamReply = () => new Response('{"resourceType":"OperationOutcome"}', { status: 404 });
    const client = await modernClient(server.base, await clinician());
    const result = await client.callTool({ name: 'getPatient', arguments: { id: 'missing' } });
    expect(result.isError).toBe(true);
    expect(JSON.parse(audit.lines.at(-1)!)).toMatchObject({ decision: 'deny', reason: 'upstream_404' });
    await client.close();
  });
});

describe('host hardening and audit hygiene', () => {
  it('rejects a browser Origin that is not allowlisted', async () => {
    const r = await post(await issuer.sign(CLINICIAN), modernBody('tools/list'), {
      'mcp-method': 'tools/list',
      origin: 'http://evil.example',
    });
    expect(r.status).toBe(403);
  });

  it('never writes token material into audit lines', async () => {
    const token = await issuer.sign({ ...CLINICIAN, scope: `openid ${STEP_UP}` });
    const client = await modernClient(server.base, token);
    await client.callTool({ name: 'patientEverything', arguments: { id: 'p1' } });
    await client.close();
    expect(audit.lines.length).toBeGreaterThan(0);
    for (const line of audit.lines) {
      expect(line).not.toContain(token);
      expect(line).not.toContain(token.split('.')[2]);
    }
  });
});
