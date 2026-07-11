/**
 * DPoP (RFC 9449) sender-constraint enforcement — the authoritative re-check.
 *
 * The internal Kong DP runs a `dpop-check` plugin that rejects bad proofs early,
 * but per the repo doctrine (contract §8: servers re-validate, never trust the
 * gateway) this middleware is the binding check. It runs only when the access
 * token carries a `cnf.jkt` confirmation (RFC 9449 §6) — a plain bearer token
 * (e.g. from the `claude-code` client) passes straight through, so DPoP is
 * opt-in per token and never breaks the bearer path.
 *
 * A token that IS jkt-bound but arrives without a valid, matching proof is a
 * rejection, not a no-op — otherwise sender-constraint would be advisory.
 *
 * `requireBearerAuth` only parses the `Bearer` scheme, but RFC 9449 §7.1
 * mandates DPoP-bound tokens be presented as `Authorization: DPoP <token>`.
 * `dpopSchemeShim` runs BEFORE the bearer middleware, rewriting a `DPoP` header
 * to `Bearer` so the SDK still extracts the token, and flags `req.dpopScheme`
 * so `requireDpop` can reject a jkt token that arrived under the wrong scheme.
 */
import { createHash } from 'node:crypto';
import { jwtVerify, EmbeddedJWK, calculateJwkThumbprint } from 'jose';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { Request, Response, NextFunction } from 'express';

declare module 'express-serve-static-core' {
  interface Request {
    dpopScheme?: boolean;
  }
}

export interface DpopConfig {
  /** Absolute URL clients call for this endpoint (the `htu` they sign). */
  htu: string;
  /** Allowed |now - iat| skew in seconds (default 60). */
  iatWindowSec?: number;
  /** URL of this server's Protected Resource Metadata, for the challenge. */
  resourceMetadataUrl: string;
}

/** Rewrite `Authorization: DPoP <t>` to `Bearer <t>` so requireBearerAuth still parses it. */
export function dpopSchemeShim(req: Request, _res: Response, next: NextFunction): void {
  const auth = req.headers.authorization;
  if (auth && /^DPoP\s+/i.test(auth)) {
    req.dpopScheme = true;
    req.headers.authorization = auth.replace(/^DPoP\s+/i, 'Bearer ');
  }
  next();
}

function base64UrlSha256(input: string): string {
  return createHash('sha256').update(input).digest('base64url');
}

/**
 * Enforce a valid DPoP proof for any jkt-bound access token. Mount AFTER the
 * bearer middleware (so `req.auth` is populated) and before scope checks.
 */
export function requireDpop(config: DpopConfig) {
  const iatWindow = config.iatWindowSec ?? 60;

  return async function dpop(req: Request, res: Response, next: NextFunction): Promise<void> {
    const jkt = (req.auth?.extra as Record<string, any> | undefined)?.cnf?.jkt;
    // Not a sender-constrained token — the bearer path is untouched.
    if (typeof jkt !== 'string' || jkt.length === 0) return next();

    const reject = (error: string, description: string): void => {
      res
        .status(401)
        .set(
          'WWW-Authenticate',
          `DPoP algs="ES256", error="${error}", error_description="${description}", resource_metadata="${config.resourceMetadataUrl}"`,
        )
        .json({ error, error_description: description });
    };

    try {
      // A jkt-bound token MUST be presented under the DPoP scheme (RFC 9449 §7.1).
      if (!req.dpopScheme) {
        return reject('invalid_token', 'DPoP-bound token must use the DPoP authorization scheme');
      }

      // Exactly one DPoP proof header. Express folds repeats into a comma-joined
      // string; a comma (or array) means the client sent more than one.
      const raw = req.headers.dpop;
      if (raw === undefined) return reject('invalid_token', 'missing DPoP proof');
      if (Array.isArray(raw) || raw.includes(',')) {
        return reject('invalid_dpop_proof', 'exactly one DPoP proof is required');
      }

      // Verify the proof JWS against its own embedded public key (RFC 9449 §4.3).
      // EmbeddedJWK rejects a header JWK that carries private material.
      const { payload, protectedHeader } = await jwtVerify(raw, EmbeddedJWK, {
        typ: 'dpop+jwt',
        algorithms: ['ES256'],
      });

      // Bind the proof key to the token: its thumbprint MUST equal cnf.jkt.
      const proofJkt = await calculateJwkThumbprint(protectedHeader.jwk!, 'sha256');
      if (proofJkt !== jkt) {
        return reject('invalid_dpop_proof', 'proof key does not match the bound token');
      }

      if (payload.htm !== req.method) {
        return reject('invalid_dpop_proof', 'htm mismatch');
      }
      // htu is compared against the configured public URL, not a reconstructed
      // request URL — the server sits behind the DP and does not trust
      // forwarded headers. Query/fragment are ignored per RFC 9449 §4.3.
      const htu = typeof payload.htu === 'string' ? payload.htu.split(/[?#]/)[0] : '';
      if (htu !== config.htu) {
        return reject('invalid_dpop_proof', 'htu mismatch');
      }
      if (typeof payload.iat !== 'number' || Math.abs(Date.now() / 1000 - payload.iat) > iatWindow) {
        return reject('invalid_dpop_proof', 'proof iat outside the freshness window');
      }
      // ath binds the proof to THIS access token (RFC 9449 §4.3, §7).
      if (payload.ath !== base64UrlSha256(req.auth!.token)) {
        return reject('invalid_dpop_proof', 'ath does not match the presented token');
      }
      // jti must be present; single-use replay dedup is enforced authoritatively
      // at the single-entry DP (shared dict). Stateless server replicas cannot
      // dedupe honestly — production would use a shared cache (Redis SET NX EX,
      // key jkt:jti, TTL = freshness window).
      if (typeof payload.jti !== 'string' || payload.jti.length === 0) {
        return reject('invalid_dpop_proof', 'missing proof jti');
      }

      return next();
    } catch (err) {
      const description = err instanceof InvalidTokenError ? err.message : 'invalid DPoP proof';
      return reject('invalid_dpop_proof', description);
    }
  };
}
