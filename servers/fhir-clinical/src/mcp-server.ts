/**
 * fhir-clinical-mcp — MCP server generated from an OpenAPI specification.
 *
 * Built on the official @modelcontextprotocol/sdk. Transport is Streamable HTTP
 * in STATELESS mode (a fresh server + transport per request, no sessions) — the
 * 2026-07-28 architectural model, and what lets this run behind a plain load
 * balancer. The advertised protocolVersion is whatever the installed SDK
 * negotiates; bump the SDK to move the wire version, no code change here.
 *
 * Security posture (MCP Authorization spec):
 *   - OAuth 2.1 resource server: every request carries a Bearer token that is
 *     signature/issuer/expiry verified AND audience-bound to this server's
 *     canonical resource URI (RFC 8707).
 *   - Protected Resource Metadata (RFC 9728) at /.well-known/oauth-protected-resource.
 *   - Binds to loopback by default; validates Origin and Host (DNS-rebinding).
 *   - The caller's token is NEVER forwarded upstream (no confused deputy). The
 *     upstream API credential is a separate secret from the environment.
 */
import express, { type Request, type Response, type NextFunction } from 'express';
import { z, type ZodTypeAny } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import { dpopSchemeShim, requireDpop } from './dpop.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import {
  buildProtectedResourceMetadata,
  createTokenVerifier,
  type ResourceServerConfig,
} from './oauth-resource-server.js';
import { authorize } from './authz-hook.js';
import { auditToolCall } from './audit.js';

// --- generation-time configuration (overridable via environment) -------------
const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT || '3000', 10);
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://${HOST}:${PORT}`;
const UPSTREAM_BASE_URL = process.env.UPSTREAM_BASE_URL || 'http://hapi:8081/fhir';
const UPSTREAM_AUTH_MODE: string = 'none'; // none | env-credential | passthrough
// Upstream guardrails: bound the fan-out (_count), the wait (timeout), and the
// response we buffer, so one tool call can't exhaust the server or HAPI.
const MAX_FHIR_COUNT = parseInt(process.env.MAX_FHIR_COUNT || '100', 10);
const UPSTREAM_TIMEOUT_MS = parseInt(process.env.UPSTREAM_TIMEOUT_MS || '10000', 10);
const MAX_UPSTREAM_BYTES = parseInt(process.env.MAX_UPSTREAM_BYTES || '2000000', 10);

const REQUIRED_SCOPES = (process.env.MCP_REQUIRED_SCOPES ?? '')
  .split(',').map((s) => s.trim()).filter(Boolean);
const GROUPS_CLAIM = 'groups'; // token claim carrying the caller's groups
const RESOURCE_CONFIG: ResourceServerConfig = {
  resourceUri: process.env.MCP_RESOURCE_URI || 'mcp://srv/fhir-clinical',
  authorizationServers: (process.env.MCP_AUTHORIZATION_SERVERS || 'http://localhost:8080/realms/mcp-plane')
    .split(',').map((s) => s.trim()).filter(Boolean),
  jwksUri: process.env.MCP_JWKS_URI || 'http://keycloak:8080/realms/mcp-plane/protocol/openid-connect/certs',
  issuer: process.env.MCP_ISSUER || '' || undefined,
  scopesSupported: REQUIRED_SCOPES,
};
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);

// --- tool descriptors (embedded from the OpenAPI spec) -----------------------
interface ToolDescriptor {
  name: string;
  title?: string;
  description?: string;
  inputSchema: Record<string, any>;
  annotations?: Record<string, unknown>;
  method: string;
  path: string;
  pathParams: string[];
  queryParams: string[];
  bodyParams: string[];
  requiredScope?: string;
  requiredGroup?: string;
  /** Scope a patient-origin token (fhir_patient present) must hold for this
   *  tool's resource type (contract §3/§6.5). Not required of workforce tokens. */
  requiredPatientScope?: string;
}
const TOOLS: ToolDescriptor[] = [
  {
    "name": "getPatient",
    "title": "Get Patient",
    "description": "Read a single Patient resource. Patient-scoped callers may only read their own record.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "description": "FHIR Patient logical id"
        }
      },
      "required": [
        "id"
      ]
    },
    "annotations": {
      "title": "Get Patient",
      "readOnlyHint": true,
      "destructiveHint": false,
      "idempotentHint": true,
      "openWorldHint": true
    },
    "method": "GET",
    "path": "/Patient/{id}",
    "pathParams": [
      "id"
    ],
    "queryParams": [],
    "bodyParams": [],
    "requiredPatientScope": "patient/Patient.read"
  },
  {
    "name": "patientEverything",
    "title": "Patient Everything",
    "description": "Return the full patient compartment. Broad operation: clinical role + step-up scope required.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "description": "FHIR Patient logical id"
        }
      },
      "required": [
        "id"
      ]
    },
    "annotations": {
      "title": "Patient Everything",
      "readOnlyHint": true,
      "destructiveHint": false,
      "idempotentHint": true,
      "openWorldHint": true
    },
    "method": "GET",
    "path": "/Patient/{id}/$everything",
    "pathParams": [
      "id"
    ],
    "queryParams": [],
    "bodyParams": [],
    "requiredScope": "mcp:fhir-clinical:everything:read",
    "requiredGroup": "mcp-clinical-tools"
  },
  {
    "name": "searchObservation",
    "title": "Search Observation",
    "description": "Search Observations",
    "inputSchema": {
      "type": "object",
      "properties": {
        "patient": {
          "type": "string",
          "description": "Patient reference (id)"
        },
        "code": {
          "type": "string",
          "description": "Observation code (LOINC)"
        },
        "_count": {
          "type": "integer",
          "description": "Max results"
        }
      }
    },
    "annotations": {
      "title": "Search Observation",
      "readOnlyHint": true,
      "destructiveHint": false,
      "idempotentHint": true,
      "openWorldHint": true
    },
    "method": "GET",
    "path": "/Observation",
    "pathParams": [],
    "queryParams": [
      "patient",
      "code",
      "_count"
    ],
    "bodyParams": [],
    "requiredPatientScope": "patient/Observation.read"
  },
  {
    "name": "searchCondition",
    "title": "Search Condition",
    "description": "Search Conditions",
    "inputSchema": {
      "type": "object",
      "properties": {
        "patient": {
          "type": "string",
          "description": "Patient reference (id)"
        },
        "_count": {
          "type": "integer",
          "description": "Max results"
        }
      }
    },
    "annotations": {
      "title": "Search Condition",
      "readOnlyHint": true,
      "destructiveHint": false,
      "idempotentHint": true,
      "openWorldHint": true
    },
    "method": "GET",
    "path": "/Condition",
    "pathParams": [],
    "queryParams": [
      "patient",
      "_count"
    ],
    "bodyParams": [],
    "requiredPatientScope": "patient/Condition.read"
  },
  {
    "name": "searchMedicationRequest",
    "title": "Search Medication Request",
    "description": "Search MedicationRequests",
    "inputSchema": {
      "type": "object",
      "properties": {
        "patient": {
          "type": "string",
          "description": "Patient reference (id)"
        },
        "_count": {
          "type": "integer",
          "description": "Max results"
        }
      }
    },
    "annotations": {
      "title": "Search Medication Request",
      "readOnlyHint": true,
      "destructiveHint": false,
      "idempotentHint": true,
      "openWorldHint": true
    },
    "method": "GET",
    "path": "/MedicationRequest",
    "pathParams": [],
    "queryParams": [
      "patient",
      "_count"
    ],
    "bodyParams": [],
    "requiredPatientScope": "patient/MedicationRequest.read"
  }
];
const TOOLS_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

function tokenGroups(auth?: AuthInfo): string[] {
  const g = (auth?.extra as any)?.[GROUPS_CLAIM];
  return Array.isArray(g) ? g : typeof g === 'string' ? [g] : [];
}
// Visibility: a caller sees a tool only if its required group (if any) is held.
function toolVisible(tool: ToolDescriptor, auth?: AuthInfo): boolean {
  return !tool.requiredGroup || tokenGroups(auth).includes(tool.requiredGroup);
}

// --- JSON Schema (per-tool inputSchema) -> Zod raw shape ---------------------
function jsonSchemaToZod(schema: any): ZodTypeAny {
  if (!schema || typeof schema !== 'object') return z.any();
  if (Array.isArray(schema.enum) && schema.enum.length > 0) {
    const vals = schema.enum.filter((v: unknown) => typeof v === 'string') as string[];
    if (vals.length === schema.enum.length) return z.enum(vals as [string, ...string[]]);
  }
  switch (schema.type) {
    case 'string': return z.string();
    case 'integer':
    case 'number': return z.number();
    case 'boolean': return z.boolean();
    case 'array': return z.array(jsonSchemaToZod(schema.items || {}));
    case 'object': return z.object({}).passthrough();
    default: return z.any();
  }
}
function toZodShape(inputSchema: any): Record<string, ZodTypeAny> {
  const shape: Record<string, ZodTypeAny> = {};
  const props = (inputSchema && inputSchema.properties) || {};
  const required: string[] = (inputSchema && inputSchema.required) || [];
  for (const [name, propSchema] of Object.entries(props)) {
    let field = jsonSchemaToZod(propSchema);
    const desc = (propSchema as any)?.description;
    if (desc) field = field.describe(desc);
    if (!required.includes(name)) field = field.optional();
    shape[name] = field;
  }
  return shape;
}

// --- upstream call (never forwards the caller's token by default) ------------
function upstreamAuthHeaders(callerToken?: string): Record<string, string> {
  if (UPSTREAM_AUTH_MODE === 'env-credential') {
    const key = process.env.UPSTREAM_API_KEY;
    return key ? { Authorization: `Bearer ${key}` } : {};
  }
  if (UPSTREAM_AUTH_MODE === 'passthrough') {
    // Opt-in only; discouraged. Forwards the inbound token to the upstream API.
    return callerToken ? { Authorization: `Bearer ${callerToken}` } : {};
  }
  return {};
}

async function callUpstream(tool: ToolDescriptor, args: Record<string, any>, callerToken?: string) {
  let path = tool.path;
  for (const p of tool.pathParams) {
    if (args[p] === undefined) throw new Error(`missing required path parameter: ${p}`);
    path = path.replace(`{${p}}`, encodeURIComponent(String(args[p])));
  }
  const query = new URLSearchParams();
  for (const q of tool.queryParams) {
    if (args[q] === undefined) continue;
    // Clamp _count so a caller can't ask HAPI for an unbounded page.
    if (q === '_count') {
      const n = Math.trunc(Number(args[q]));
      if (!Number.isFinite(n) || n < 1) throw new Error('_count must be a positive integer');
      query.set(q, String(Math.min(n, MAX_FHIR_COUNT)));
    } else {
      query.set(q, String(args[q]));
    }
  }
  const qs = query.toString();
  const url = `${UPSTREAM_BASE_URL}${path}${qs ? `?${qs}` : ''}`;

  const headers: Record<string, string> = { Accept: 'application/json', ...upstreamAuthHeaders(callerToken) };
  let body: string | undefined;
  if (tool.method !== 'GET' && tool.bodyParams.length > 0) {
    const payload: Record<string, any> = {};
    for (const b of tool.bodyParams) if (args[b] !== undefined) payload[b] = args[b];
    body = JSON.stringify(payload);
    headers['Content-Type'] = 'application/json';
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  let res: Awaited<ReturnType<typeof fetch>>;
  try {
    res = await fetch(url, { method: tool.method, headers, body, signal: controller.signal });
  } catch (err) {
    clearTimeout(timer);
    if ((err as Error)?.name === 'AbortError') throw new Error('upstream request timed out');
    throw err;
  }
  try {
    const text = await readCapped(res, MAX_UPSTREAM_BYTES);
    let data: unknown = text;
    try { data = JSON.parse(text); } catch { /* non-JSON upstream body */ }
    return { ok: res.ok, status: res.status, data };
  } finally {
    clearTimeout(timer);
  }
}

// Read the body but stop once the cap is exceeded, so an oversized upstream
// response can't blow up the server's memory. (Fetch Response, not Express's.)
async function readCapped(res: Awaited<ReturnType<typeof fetch>>, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return res.text();
  const decoder = new TextDecoder();
  let out = '';
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`upstream response exceeded ${maxBytes} bytes`);
    }
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}

// --- MCP server (fresh per request; stateless) -------------------------------
// Only tools visible to this caller's groups are registered, so tools/list
// returns exactly the role-permitted set.
function buildMcpServer(auth?: AuthInfo): McpServer {
  const server = new McpServer({ name: 'fhir-clinical-mcp', version: '1.0.0' });
  for (const tool of TOOLS) {
    if (!toolVisible(tool, auth)) continue;
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: toZodShape(tool.inputSchema),
        annotations: tool.annotations as any,
      },
      async (args: Record<string, any>) => {
        // Audit reflects the FINAL outcome (contract §9): allow only after a
        // successful upstream read; deny for compartment/validation/upstream
        // failures. No request bodies or token material are logged.
        try {
          // Optional per-request authorization hook (e.g. data compartment filter);
          // may throw {status,message} or return mutated args.
          args = await authorize({ auth, tool, args });
        } catch (err) {
          auditToolCall(RESOURCE_CONFIG.resourceUri, auth, tool.name, 'deny', 'compartment');
          throw err;
        }
        let result;
        try {
          result = await callUpstream(tool, args, auth?.token);
        } catch (err) {
          auditToolCall(RESOURCE_CONFIG.resourceUri, auth, tool.name, 'deny', 'upstream_error');
          return {
            content: [{ type: 'text' as const, text: (err as Error).message }],
            isError: true,
          };
        }
        auditToolCall(RESOURCE_CONFIG.resourceUri, auth, tool.name,
          result.ok ? 'allow' : 'deny', result.ok ? undefined : `upstream_${result.status}`);
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result.data, null, 2) }],
          isError: !result.ok,
        };
      },
    );
  }
  return server;
}

// --- Express host ------------------------------------------------------------
function isLoopbackHost(hostHeader?: string): boolean {
  if (!hostHeader) return false;
  const name = hostHeader.split(':')[0];
  return name === 'localhost' || name === '127.0.0.1' || name === '[::1]' || name === '::1';
}

function securityGuard(req: Request, res: Response, next: NextFunction): void {
  // DNS-rebinding defense: on a loopback bind, reject unexpected Host headers.
  if (HOST === '127.0.0.1' && !isLoopbackHost(req.headers.host) && !ALLOWED_ORIGINS.length) {
    res.status(421).json({ error: 'misdirected_request', message: 'unexpected Host header' });
    return;
  }
  const origin = req.headers.origin;
  if (origin) {
    // Any browser Origin must be explicitly allowlisted (default: none).
    if (!ALLOWED_ORIGINS.includes(origin)) {
      res.status(403).json({ error: 'forbidden_origin' });
      return;
    }
  }
  next();
}

export function createApp() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(securityGuard);

  // RFC 9728 path-insertion: the MCP endpoint is /mcp, so its metadata lives at
  // /.well-known/oauth-protected-resource/mcp. Challenges point here; the root
  // path is kept as a back-compat alias.
  const resourceMetadataUrl = `${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource/mcp`;

  // Protected Resource Metadata (RFC 9728) — public, no auth.
  // metadataHandler returns a Router serving GET '/', so mount with app.use.
  const prm = metadataHandler(buildProtectedResourceMetadata(RESOURCE_CONFIG));
  app.use('/.well-known/oauth-protected-resource/mcp', prm);
  app.use('/.well-known/oauth-protected-resource', prm);

  const bearer = requireBearerAuth({
    verifier: createTokenVerifier(RESOURCE_CONFIG),
    requiredScopes: REQUIRED_SCOPES,
    resourceMetadataUrl,
  });
  const dpop = requireDpop({ htu: process.env.DPOP_HTU || `${PUBLIC_BASE_URL}/mcp`, resourceMetadataUrl });

  // Per-tool scope enforcement (draft-spec step-up). For a tools/call, the tool's
  // `x-mcp-scope` must be held; otherwise a single-shot 403 insufficient_scope
  // names the required scope so the client can step up and retry.
  function enforceToolScope(req: Request, res: Response, next: NextFunction): void {
    const body = req.body;
    if (!body || body.method !== 'tools/call') return next();
    const tool = TOOLS_BY_NAME.get(body?.params?.name);
    if (!tool) return next();
    const scopes = req.auth?.scopes || [];
    // A patient-origin token (fhir_patient present) must carry the per-resource
    // patient scope for this tool (contract §3/§6.5). Workforce tokens are
    // governed by group ACLs and keep floor-read access (no patient scope).
    const isPatient = (req.auth?.extra as any)?.fhir_patient !== undefined;
    const required = tool.requiredScope
      ?? (isPatient ? tool.requiredPatientScope : undefined);
    if (!required || scopes.includes(required)) return next();
    auditToolCall(RESOURCE_CONFIG.resourceUri, req.auth, body?.params?.name, 'deny', 'insufficient_scope');
    res
      .status(403)
      .set('WWW-Authenticate',
        `Bearer error="insufficient_scope", scope="${required}", resource_metadata="${resourceMetadataUrl}"`)
      .json({ error: 'insufficient_scope', scope: required });
  }

  // Stateless MCP endpoint: authenticate, enforce tool scope, then a fresh
  // server+transport per request.
  app.post('/mcp', dpopSchemeShim, bearer, dpop, enforceToolScope, async (req: Request, res: Response) => {
    // The tools/call outcome is audited inside the tool handler (allow only on
    // success), so nothing is logged here before the work runs.
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    const server = buildMcpServer(req.auth);
    res.on('close', () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // Stateless: no server-initiated stream, no session teardown.
  const methodNotAllowed = (_req: Request, res: Response) =>
    res.status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null });
  app.get('/mcp', dpopSchemeShim, bearer, dpop, methodNotAllowed);
  app.delete('/mcp', dpopSchemeShim, bearer, dpop, methodNotAllowed);

  return app;
}

export function startServer(): void {
  const app = createApp();
  app.listen(PORT, HOST, () => {
    // eslint-disable-next-line no-console
    console.error(`fhir-clinical-mcp listening on http://${HOST}:${PORT}/mcp (resource ${RESOURCE_CONFIG.resourceUri})`);
  });
}
