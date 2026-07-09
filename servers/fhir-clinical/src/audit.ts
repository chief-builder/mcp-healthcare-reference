/**
 * Audit records per claims-contract §9: one JSON line per tools/call on
 * stdout — the phase 6 audit spine ships container logs to Loki. Records
 * carry ids and names only, never token material or request bodies.
 */
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';

export function auditToolCall(
  server: string,
  auth: AuthInfo | undefined,
  tool: string,
  decision: 'allow' | 'deny',
  reason?: string,
): void {
  const claims = (auth?.extra ?? {}) as Record<string, any>;
  console.log(JSON.stringify({
    audit: 'mcp-server',
    server,
    tool,
    decision,
    reason: reason ?? null,
    token_id: claims.jti ?? null,
    principal: claims.sub ?? null,
    acting_agent: claims.act?.sub ?? null,
    client: claims.azp ?? null,
    origin_idp: claims.idp_origin ?? null,
    tier: claims.mcp_tier ?? null,
    patient_compartment: claims.fhir_patient ?? null,
    ts: Date.now() / 1000,
  }));
}
