/**
 * OAuth 2.1 resource-server support (MCP Authorization spec, 2026-07-28).
 *
 * Each MCP server is an OAuth 2.1 *resource server*. It:
 *   - publishes Protected Resource Metadata (RFC 9728) so clients can discover
 *     the authorization server(s),
 *   - validates every token's signature, issuer, expiry, and — critically —
 *     that the token's `aud` names THIS server's canonical resource URI (RFC 8707),
 *   - never forwards the caller's token to any upstream API (no confused deputy).
 *
 * Token validation uses `jose` against the authorization server's JWKS. The
 * SDK's `requireBearerAuth` middleware consumes the verifier below and emits the
 * spec-required `WWW-Authenticate: Bearer ... resource_metadata="..."` challenge.
 */
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthProtectedResourceMetadata,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';

export interface ResourceServerConfig {
  /** Canonical URI identifying this MCP server (RFC 8707). The required token audience. */
  resourceUri: string;
  /** Issuer (authorization server) URLs advertised in Protected Resource Metadata. */
  authorizationServers: string[];
  /** JWKS URL used to verify token signatures. */
  jwksUri: string;
  /** Expected `iss` claim; defaults to the first authorization server. */
  issuer?: string;
  /** Scopes advertised in metadata (the minimal baseline). */
  scopesSupported?: string[];
}

/**
 * Build the Protected Resource Metadata document (RFC 9728) served at
 * /.well-known/oauth-protected-resource/mcp.
 */
export function buildProtectedResourceMetadata(config: ResourceServerConfig): OAuthProtectedResourceMetadata {
  return {
    resource: config.resourceUri,
    authorization_servers: config.authorizationServers,
    bearer_methods_supported: ['header'],
    // RFC 9449 §5.1: advertise the DPoP proof algorithms this server accepts.
    dpop_signing_alg_values_supported: ['ES256'],
    ...(config.scopesSupported?.length ? { scopes_supported: config.scopesSupported } : {}),
  };
}

const invalid = (message: string) => new OAuthError(OAuthErrorCode.InvalidToken, message);

/**
 * A token verifier that enforces signature, issuer, expiry, audience, and the
 * claims-contract shape.
 *
 * Audience binding is the load-bearing check: a token minted for a different
 * resource (another MCP server, or a different tier) MUST be rejected even if
 * it is otherwise valid and correctly signed by the same issuer.
 *
 * `keySet` is injectable so tests can verify against a local JWKS.
 */
export function createTokenVerifier(config: ResourceServerConfig, keySet?: JWTVerifyGetKey): OAuthTokenVerifier {
  const jwks = keySet ?? createRemoteJWKSet(new URL(config.jwksUri));
  const expectedIssuer = config.issuer ?? config.authorizationServers[0];

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      let payload: JWTPayload;
      try {
        ({ payload } = await jwtVerify(token, jwks, {
          issuer: expectedIssuer,
          audience: config.resourceUri, // RFC 8707 audience binding
          // Claims-contract §2: PS256 primary, ES256 permitted; RS256 and all
          // HMAC forbidden. Pinning here refuses a token signed with anything else.
          algorithms: ['PS256', 'ES256'],
          // Contract §3 mandatory claims (iss and aud are checked above).
          requiredClaims: ['sub', 'azp', 'exp', 'iat', 'jti'],
        }));
      } catch (err) {
        // Wrong signature/issuer/expiry/audience OR a forbidden alg land here.
        throw invalid(err instanceof Error ? err.message : 'token verification failed');
      }

      // Claims-contract shape checks (defense in depth; the DP validates too).
      if (payload.mcp_contract !== '1.0') {
        throw invalid('unsupported or missing mcp_contract');
      }
      const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
      if (aud.filter((a) => a.startsWith('mcp://tier/')).length !== 1) {
        throw invalid('token must carry exactly one tier audience');
      }
      // fhir_patient is a PII claim: mandatory on the Auth0 end-customer path,
      // FORBIDDEN on every other path (contract §3). Reject it anywhere else,
      // and reject an Auth0-origin token that lacks it (contract §8: absent on
      // a path that requires it is a rejection, not a workforce fallback).
      if (payload.fhir_patient !== undefined && payload.idp_origin !== 'auth0') {
        throw invalid('fhir_patient is forbidden on non-patient tokens');
      }
      if (
        payload.idp_origin === 'auth0' &&
        (typeof payload.fhir_patient !== 'string' || payload.fhir_patient.length === 0)
      ) {
        throw invalid('auth0-origin tokens must carry a non-empty string fhir_patient');
      }

      return {
        token,
        clientId: stringClaim(payload.azp) ?? stringClaim(payload.client_id) ?? '',
        scopes: scopesOf(payload.scope),
        expiresAt: payload.exp,
        resource: new URL(config.resourceUri),
        // The full validated claim set — servers read groups / fhir_patient /
        // idp_origin / amr etc. by name.
        extra: { ...payload },
      };
    },
  };
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function scopesOf(scope: unknown): string[] {
  if (typeof scope === 'string') return scope.split(' ').filter(Boolean);
  if (Array.isArray(scope)) return scope.filter((s): s is string => typeof s === 'string');
  return [];
}

/** Typed accessors over the validated claim set carried in AuthInfo.extra. */
export function claimsOf(auth?: AuthInfo): Record<string, unknown> {
  return (auth?.extra ?? {}) as Record<string, unknown>;
}

export function stringListClaim(auth: AuthInfo | undefined, name: string): string[] {
  const value = claimsOf(auth)[name];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return typeof value === 'string' ? [value] : [];
}
