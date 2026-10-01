/** fhir-clinical configuration: every setting, its default, validated at startup. */
import { EnvReader, type ResourceServerConfig } from '@mcp-lab/shared';

export interface FhirConfig {
  host: string;
  port: number;
  publicBaseUrl: string;
  allowedOrigins: string[];
  dpopHtu?: string;
  /** Requests per minute per client address on /mcp; 0 disables. */
  rateLimitPerMinute: number;
  resource: ResourceServerConfig;
  requiredScopes: string[];
  /** Step-up scopes that additionally require `amr` to include `mfa`. */
  mfaScopes: string[];
  upstreamBaseUrl: string;
  /** Optional server-owned upstream credential (never the caller's token). */
  upstreamApiKey?: string;
  maxFhirCount: number;
  upstreamTimeoutMs: number;
  maxUpstreamBytes: number;
}

export function loadConfig(env: Record<string, string | undefined> = process.env): FhirConfig {
  const e = new EnvReader(env);
  const host = e.string('HOST', '127.0.0.1');
  const port = e.int('PORT', 3000, { min: 1 });
  const requiredScopes = e.list('MCP_REQUIRED_SCOPES');
  const config: FhirConfig = {
    host,
    port,
    publicBaseUrl: e.url('PUBLIC_BASE_URL', `http://${host}:${port}`),
    allowedOrigins: e.list('ALLOWED_ORIGINS'),
    dpopHtu: e.optional('DPOP_HTU'),
    rateLimitPerMinute: e.int('MCP_RATE_LIMIT_PER_MIN', 600),
    resource: {
      resourceUri: e.url('MCP_RESOURCE_URI', 'mcp://srv/fhir-clinical', ['mcp:', 'http:', 'https:']),
      authorizationServers: e.urlList('MCP_AUTHORIZATION_SERVERS', ['http://localhost:8080/realms/mcp-plane']),
      jwksUri: e.url('MCP_JWKS_URI', 'http://keycloak:8080/realms/mcp-plane/protocol/openid-connect/certs'),
      issuer: e.optional('MCP_ISSUER'),
    },
    requiredScopes,
    mfaScopes: e.list('MCP_MFA_SCOPES', ['mcp:fhir-clinical:everything:read']),
    upstreamBaseUrl: e.url('UPSTREAM_BASE_URL', 'http://hapi:8081/fhir'),
    upstreamApiKey: e.optional('UPSTREAM_API_KEY'),
    // Upstream guardrails: bound the fan-out (_count), the wait (timeout), and
    // the response we buffer, so one tool call can't exhaust the server or HAPI.
    maxFhirCount: e.int('MAX_FHIR_COUNT', 100, { min: 1 }),
    upstreamTimeoutMs: e.int('UPSTREAM_TIMEOUT_MS', 10000, { min: 1 }),
    maxUpstreamBytes: e.int('MAX_UPSTREAM_BYTES', 2000000, { min: 1 }),
  };
  e.done();
  return config;
}
