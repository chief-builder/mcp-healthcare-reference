/**
 * The Express host every first-party MCP server shares.
 *
 * Request pipeline for POST /mcp:
 *   securityGuard   Host/Origin checks (DNS-rebinding defense)
 *   rate limit      per-client ceiling (defense in depth; Kong limits first)
 *   dpopSchemeShim  `DPoP <t>` → `Bearer <t>` so the SDK parses it
 *   bearer          signature/issuer/expiry/audience + contract shape
 *   dpop            proof-of-possession for cnf.jkt-bound tokens
 *   rejectBatch     JSON-RPC batch arrays are refused (see below)
 *   toolPolicy      per-tool step-up scope / patient scope / MFA challenge
 *   MCP handler     2026-07-28 per-request serving, stateless 2025 fallback
 *
 * Transport is the SDK v2 `createMcpHandler`: a fresh McpServer per request,
 * no sessions — the 2026-07-28 model, and what lets this run behind a plain
 * load balancer. 2025-era clients that still open with `initialize` are served
 * by the SDK's stateless legacy fallback from the same factory.
 */
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { createMcpHandler, type AuthInfo, type McpServer } from '@modelcontextprotocol/server';
import { requireBearerAuth } from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { rateLimit } from 'express-rate-limit';
import type { JWTVerifyGetKey } from 'jose';
import { dpopSchemeShim, requireDpop } from './dpop.js';
import { enforceToolPolicy, type ToolPolicy } from './tool-policy.js';
import { buildProtectedResourceMetadata, createTokenVerifier, type ResourceServerConfig } from './token-verifier.js';

export interface McpAppOptions {
  /** Bind host; a loopback bind turns on the Host-header rebinding check. */
  host: string;
  /** Absolute public URL of this server (what clients and DPoP proofs name). */
  publicBaseUrl: string;
  allowedOrigins: string[];
  resource: ResourceServerConfig;
  /** Scopes every request must carry (advertised in PRM). */
  requiredScopes?: string[];
  /** URL clients sign as DPoP `htu`; defaults to `${publicBaseUrl}/mcp`. */
  dpopHtu?: string;
  policyFor: (toolName: string) => ToolPolicy | undefined;
  mfaScopes: readonly string[];
  /** Audit a request refused before any tool ran. */
  onDeny: (auth: AuthInfo | undefined, tool: string, reason: string) => void;
  /** Builds the per-request MCP server for the authenticated caller. */
  buildServer: (auth: AuthInfo | undefined) => McpServer;
  /** Requests per minute per client address on /mcp; 0 disables. */
  rateLimitPerMinute: number;
  /** Test seam: verify tokens against a local key set instead of the JWKS URL. */
  keySet?: JWTVerifyGetKey;
}

const LOOPBACK_NAMES = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export function isLoopbackHost(hostHeader?: string): boolean {
  if (!hostHeader) return false;
  const name = hostHeader.startsWith('[') ? hostHeader.slice(0, hostHeader.indexOf(']') + 1) : hostHeader.split(':')[0];
  return LOOPBACK_NAMES.has(name);
}

export function securityGuard(host: string, allowedOrigins: string[]) {
  return function guard(req: Request, res: Response, next: NextFunction): void {
    // DNS-rebinding defense: on a loopback bind, reject unexpected Host headers.
    if (host === '127.0.0.1' && !isLoopbackHost(req.headers.host) && !allowedOrigins.length) {
      res.status(421).json({ error: 'misdirected_request', message: 'unexpected Host header' });
      return;
    }
    // Any browser Origin must be explicitly allowlisted (default: none).
    const origin = req.headers.origin;
    if (origin && !allowedOrigins.includes(origin)) {
      res.status(403).json({ error: 'forbidden_origin' });
      return;
    }
    next();
  };
}

/**
 * JSON-RPC batching was removed from MCP in 2025-06-18 and is absent from
 * 2026-07-28, but the SDK still routes an all-legacy batch array to its legacy
 * leg. Per-tool authorization is evaluated per request at the HTTP layer, so a
 * batch must never get that far: refuse it outright.
 */
export function rejectBatch(req: Request, res: Response, next: NextFunction): void {
  if (Array.isArray(req.body)) {
    res.status(400).json({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Invalid Request: JSON-RPC batches are not supported' },
    });
    return;
  }
  next();
}

export function createMcpApp(options: McpAppOptions): Express {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(securityGuard(options.host, options.allowedOrigins));

  // RFC 9728 path-insertion: the MCP endpoint is /mcp, so its metadata lives at
  // /.well-known/oauth-protected-resource/mcp. Challenges point here; the root
  // path is kept as a back-compat alias.
  const resourceMetadataUrl = `${options.publicBaseUrl}/.well-known/oauth-protected-resource/mcp`;
  const prm = buildProtectedResourceMetadata({ ...options.resource, scopesSupported: options.requiredScopes });
  const servePrm = (_req: Request, res: Response) => {
    res.set('Cache-Control', 'public, max-age=3600').json(prm);
  };
  app.get('/.well-known/oauth-protected-resource/mcp', servePrm);
  app.get('/.well-known/oauth-protected-resource', servePrm);

  const bearer = requireBearerAuth({
    verifier: createTokenVerifier(options.resource, options.keySet),
    requiredScopes: options.requiredScopes,
    resourceMetadataUrl,
  });
  const dpop = requireDpop({ htu: options.dpopHtu ?? `${options.publicBaseUrl}/mcp`, resourceMetadataUrl });
  const toolPolicy = enforceToolPolicy({
    policyFor: options.policyFor,
    mfaScopes: options.mfaScopes,
    resourceMetadataUrl,
    onDeny: options.onDeny,
  });

  const handler = toNodeHandler(createMcpHandler(({ authInfo }) => options.buildServer(authInfo)));
  const serve = (req: Request, res: Response) => handler(req, res, req.body);

  // Runs before token verification so a flood can't buy free signature checks.
  // Behind Kong every request shares the DP's address, so this is a per-DP
  // ceiling above the gateway's own per-route limits.
  const limiter = rateLimit({
    windowMs: 60_000,
    limit: options.rateLimitPerMinute,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skip: () => options.rateLimitPerMinute === 0,
    message: { error: 'rate_limited' },
  });

  app.post('/mcp', limiter, dpopSchemeShim, bearer, dpop, rejectBatch, toolPolicy, serve);
  // Stateless: no server-initiated GET stream and no session teardown — the
  // handler answers 405 for both after authentication.
  app.get('/mcp', limiter, dpopSchemeShim, bearer, dpop, serve);
  app.delete('/mcp', limiter, dpopSchemeShim, bearer, dpop, serve);

  return app;
}
