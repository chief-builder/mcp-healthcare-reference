/**
 * OAuth 2.1 resource-server support (MCP Authorization spec, 2025-06-18+).
 *
 * This MCP server is an OAuth 2.1 *resource server*. It:
 *   - publishes Protected Resource Metadata (RFC 9728) so clients can discover
 *     the authorization server(s),
 *   - validates every bearer token's signature, issuer, expiry, and — critically —
 *     that the token's `aud` names THIS server's canonical resource URI (RFC 8707),
 *   - never forwards the caller's token to any upstream API (no confused deputy).
 *
 * Token validation uses `jose` against the authorization server's JWKS. The
 * SDK's `requireBearerAuth` middleware consumes the verifier below and emits the
 * spec-required `WWW-Authenticate: Bearer ... resource_metadata="..."` challenge.
 */
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthProtectedResourceMetadata } from '@modelcontextprotocol/sdk/shared/auth.js';

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
 * /.well-known/oauth-protected-resource.
 */
export function buildProtectedResourceMetadata(
  config: ResourceServerConfig,
): OAuthProtectedResourceMetadata {
  return {
    resource: config.resourceUri,
    authorization_servers: config.authorizationServers,
    bearer_methods_supported: ['header'],
    ...(config.scopesSupported ? { scopes_supported: config.scopesSupported } : {}),
  };
}

/**
 * A token verifier that enforces signature, issuer, expiry, and audience.
 *
 * Audience binding is the load-bearing check: a token minted for a different
 * resource (another MCP server, or a different tier) MUST be rejected even if
 * it is otherwise valid and correctly signed by the same issuer.
 */
export function createTokenVerifier(config: ResourceServerConfig): OAuthTokenVerifier {
  const jwks = createRemoteJWKSet(new URL(config.jwksUri));
  const expectedIssuer = config.issuer ?? config.authorizationServers[0];

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      let payload;
      try {
        ({ payload } = await jwtVerify(token, jwks, {
          issuer: expectedIssuer,
          audience: config.resourceUri, // RFC 8707 audience binding
          // Claims-contract §2: PS256 primary, ES256 permitted; RS256 and all
          // HMAC forbidden. Pinning here refuses a token signed with anything else.
          algorithms: ['PS256', 'ES256'],
        }));
      } catch (err) {
        // Wrong signature/issuer/expiry/audience OR a forbidden alg land here.
        throw new InvalidTokenError(
          err instanceof Error ? err.message : 'token verification failed',
        );
      }

      // Claims-contract shape checks (defense in depth; the DP validates too).
      if (payload.mcp_contract !== '1.0') {
        throw new InvalidTokenError('unsupported or missing mcp_contract');
      }
      const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
      if (aud.filter((a: unknown) => typeof a === 'string' && a.startsWith('mcp://tier/')).length !== 1) {
        throw new InvalidTokenError('token must carry exactly one tier audience');
      }
      // fhir_patient is a PII claim: mandatory on the Auth0 end-customer path,
      // FORBIDDEN on every other path (contract §3). Reject it anywhere else,
      // and reject an Auth0-origin token that lacks it (contract §8: absent on
      // a path that requires it is a rejection, not a workforce fallback).
      if (payload.fhir_patient !== undefined && payload.idp_origin !== 'auth0') {
        throw new InvalidTokenError('fhir_patient is forbidden on non-patient tokens');
      }
      if (
        payload.idp_origin === 'auth0' &&
        (typeof payload.fhir_patient !== 'string' || payload.fhir_patient.length === 0)
      ) {
        throw new InvalidTokenError('auth0-origin tokens must carry a non-empty string fhir_patient');
      }

      const scopes =
        typeof payload.scope === 'string'
          ? payload.scope.split(' ').filter(Boolean)
          : Array.isArray(payload.scope)
            ? (payload.scope as string[])
            : [];

      return {
        token,
        clientId: (payload.azp as string) ?? (payload.client_id as string) ?? '',
        scopes,
        expiresAt: payload.exp,
        resource: new URL(config.resourceUri),
        // The full validated claim set — servers read groups / fhir_patient /
        // idp_origin etc. by name (claim names are configurable per deployment).
        extra: { ...payload },
      };
    },
  };
}
