/**
 * fhir-clinical-mcp — MCP server generated from an OpenAPI specification.
 *
 * Built on the official MCP TypeScript SDK v2 (2026-07-28). Stateless: a fresh
 * McpServer per request, no sessions (see @mcp-lab/shared createMcpApp).
 *
 * Security posture (MCP Authorization spec):
 *   - OAuth 2.1 resource server: every request carries a token that is
 *     signature/issuer/expiry verified AND audience-bound to this server's
 *     canonical resource URI (RFC 8707), with the claims-contract shape.
 *   - Protected Resource Metadata (RFC 9728) at /.well-known/oauth-protected-resource/mcp.
 *   - Binds to loopback by default; validates Origin and Host (DNS-rebinding).
 *   - Per-tool step-up scope, per-resource patient scope, MFA for clinical
 *     scopes, group-gated visibility, and the patient compartment filter.
 *   - The caller's token is NEVER forwarded upstream (no confused deputy).
 */
import { z } from 'zod';
import { McpServer, type AuthInfo, type ToolAnnotations } from '@modelcontextprotocol/server';
import { auditToolCall, checkToolPolicy, createMcpApp, stringListClaim } from '@mcp-lab/shared';
import type { JWTVerifyGetKey } from 'jose';
import { authorize } from './authz-hook.js';
import type { FhirConfig } from './config.js';
import { TOOLS, policyFor, type ToolDescriptor } from './tools.js';
import { callUpstream } from './upstream.js';

const GROUPS_CLAIM = 'groups'; // token claim carrying the caller's groups

// Visibility: a caller sees a tool only if its required group (if any) is held.
export function toolVisible(tool: ToolDescriptor, auth?: AuthInfo): boolean {
  return !tool.requiredGroup || stringListClaim(auth, GROUPS_CLAIM).includes(tool.requiredGroup);
}

// --- JSON Schema (per-tool inputSchema) -> Zod ------------------------------
function jsonSchemaToZod(schema: Record<string, unknown> | undefined): z.ZodType {
  if (!schema || typeof schema !== 'object') return z.any();
  if (Array.isArray(schema.enum) && schema.enum.length > 0) {
    const vals = schema.enum.filter((v): v is string => typeof v === 'string');
    if (vals.length === schema.enum.length) return z.enum(vals as [string, ...string[]]);
  }
  switch (schema.type) {
    case 'string':
      return z.string();
    case 'integer':
      return z.number().int();
    case 'number':
      return z.number();
    case 'boolean':
      return z.boolean();
    case 'array':
      return z.array(jsonSchemaToZod(schema.items as Record<string, unknown> | undefined));
    case 'object':
      return z.looseObject({});
    default:
      return z.any();
  }
}

export function toZodObject(inputSchema: ToolDescriptor['inputSchema']) {
  const shape: Record<string, z.ZodType> = {};
  const props = (inputSchema?.properties ?? {}) as Record<string, Record<string, unknown>>;
  const required: string[] = inputSchema?.required ?? [];
  for (const [name, propSchema] of Object.entries(props)) {
    let field = jsonSchemaToZod(propSchema);
    const desc = propSchema?.description;
    if (typeof desc === 'string') field = field.describe(desc);
    shape[name] = required.includes(name) ? field : field.optional();
  }
  return z.object(shape);
}

// --- MCP server (fresh per request; stateless) -------------------------------
// Only tools visible to this caller's groups are registered, so tools/list
// returns exactly the role-permitted set.
export function buildMcpServer(config: FhirConfig, auth?: AuthInfo, fetchImpl: typeof fetch = fetch): McpServer {
  const server = new McpServer({ name: 'fhir-clinical-mcp', version: '2.0.0' });
  const resource = config.resource.resourceUri;
  for (const tool of TOOLS) {
    if (!toolVisible(tool, auth)) continue;
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: toZodObject(tool.inputSchema),
        annotations: tool.annotations as ToolAnnotations,
      },
      async (input: Record<string, unknown>) => {
        // Audit reflects the FINAL outcome (contract §9): allow only after a
        // successful upstream read; deny for policy/compartment/upstream
        // failures. No request bodies or token material are logged.
        const denied = checkToolPolicy(policyFor(tool.name), auth, config.mfaScopes);
        if (denied) {
          auditToolCall(resource, auth, tool.name, 'deny', denied.reason);
          return { content: denied.content, isError: true };
        }
        let args: Record<string, unknown>;
        try {
          // Patient compartment filter: may rewrite args or throw a 403.
          args = await authorize({ auth, tool, args: input });
        } catch (err) {
          auditToolCall(resource, auth, tool.name, 'deny', 'compartment');
          return { content: [{ type: 'text' as const, text: (err as Error).message }], isError: true };
        }
        let result;
        try {
          result = await callUpstream(config, tool, args, fetchImpl);
        } catch (err) {
          auditToolCall(resource, auth, tool.name, 'deny', 'upstream_error');
          return { content: [{ type: 'text' as const, text: (err as Error).message }], isError: true };
        }
        auditToolCall(
          resource,
          auth,
          tool.name,
          result.ok ? 'allow' : 'deny',
          result.ok ? undefined : `upstream_${result.status}`,
        );
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result.data, null, 2) }],
          isError: !result.ok,
        };
      },
    );
  }
  return server;
}

export function createApp(config: FhirConfig, deps: { keySet?: JWTVerifyGetKey; fetchImpl?: typeof fetch } = {}) {
  return createMcpApp({
    host: config.host,
    publicBaseUrl: config.publicBaseUrl,
    allowedOrigins: config.allowedOrigins,
    resource: config.resource,
    requiredScopes: config.requiredScopes,
    dpopHtu: config.dpopHtu,
    rateLimitPerMinute: config.rateLimitPerMinute,
    policyFor,
    mfaScopes: config.mfaScopes,
    onDeny: (auth, tool, reason) => auditToolCall(config.resource.resourceUri, auth, tool, 'deny', reason),
    buildServer: (auth) => buildMcpServer(config, auth, deps.fetchImpl),
    keySet: deps.keySet,
  });
}
