/** scheduling configuration: every setting, its default, validated at startup. */
import { EnvReader, type ResourceServerConfig } from '@mcp-lab/shared';

export interface SchedulingConfig {
  host: string;
  port: number;
  publicBaseUrl: string;
  allowedOrigins: string[];
  dpopHtu?: string;
  resource: ResourceServerConfig;
  /** Step-up scopes that additionally require `amr` to include `mfa` (none by default). */
  mfaScopes: string[];
  databaseUrl: string;
  /** A hold neither confirmed nor released expires after this many seconds. */
  holdTtlSeconds: number;
}

export function loadConfig(env: Record<string, string | undefined> = process.env): SchedulingConfig {
  const e = new EnvReader(env);
  const host = e.string('HOST', '127.0.0.1');
  const port = e.int('PORT', 3000, { min: 1 });
  const config: SchedulingConfig = {
    host,
    port,
    publicBaseUrl: e.url('PUBLIC_BASE_URL', `http://${host}:${port}`),
    allowedOrigins: e.list('ALLOWED_ORIGINS'),
    dpopHtu: e.optional('DPOP_HTU'),
    resource: {
      resourceUri: e.url('MCP_RESOURCE_URI', 'mcp://srv/scheduling', ['mcp:', 'http:', 'https:']),
      authorizationServers: e.urlList('MCP_AUTHORIZATION_SERVERS', []),
      jwksUri: e.url('MCP_JWKS_URI', undefined),
      issuer: e.optional('MCP_ISSUER'),
    },
    mfaScopes: e.list('MCP_MFA_SCOPES'),
    databaseUrl: e.url('DATABASE_URL', undefined, ['postgres:', 'postgresql:']),
    holdTtlSeconds: e.int('HOLD_TTL_S', 300, { min: 1 }),
  };
  e.done();
  return config;
}
