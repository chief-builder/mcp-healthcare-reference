/**
 * Test-only issuer: generates throwaway signing keys in memory (never written
 * anywhere) and mints claims-contract-shaped tokens and DPoP proofs.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Express } from 'express';
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

export const ISSUER = 'http://localhost:8080/realms/mcp-plane';

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;

export interface TestIssuer {
  keySet: JWTVerifyGetKey;
  /** Sign a token; `claims` override the defaults, `undefined` deletes a claim. */
  sign(claims?: Record<string, unknown>, opts?: { alg?: string; key?: KeyPair['privateKey'] }): Promise<string>;
  /** A key pair NOT in the key set (for wrong-signature tests). */
  rogue: KeyPair;
}

export async function createTestIssuer(audience: string): Promise<TestIssuer> {
  const ps = await generateKeyPair('PS256', { extractable: true });
  const es = await generateKeyPair('ES256', { extractable: true });
  const rogue = await generateKeyPair('PS256', { extractable: true });
  const keySet = createLocalJWKSet({
    keys: [
      { ...(await exportJWK(ps.publicKey)), kid: 'ps', alg: 'PS256' },
      { ...(await exportJWK(es.publicKey)), kid: 'es', alg: 'ES256' },
    ],
  });
  return {
    keySet,
    rogue,
    async sign(claims = {}, opts = {}) {
      const alg = opts.alg ?? 'PS256';
      const now = Math.floor(Date.now() / 1000);
      const payload: JWTPayload = {
        iss: ISSUER,
        sub: 'user-1',
        azp: 'claude-code',
        aud: [audience, 'mcp://tier/internal'],
        iat: now,
        exp: now + 300,
        jti: randomUUID(),
        mcp_contract: '1.0',
        mcp_tier: 'internal',
        idp_origin: 'ping',
        scope: 'openid',
        ...claims,
      };
      for (const [k, v] of Object.entries(payload)) if (v === undefined) delete payload[k];
      const key = opts.key ?? (alg === 'ES256' ? es.privateKey : ps.privateKey);
      return new SignJWT(payload).setProtectedHeader({ alg, kid: alg === 'ES256' ? 'es' : 'ps' }).sign(key);
    },
  };
}

/** A client-held DPoP key and a proof builder (RFC 9449). */
export async function createDpopKey() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = (await exportJWK(publicKey)) as JWK;
  const jkt = await calculateJwkThumbprint(jwk, 'sha256');
  return {
    jkt,
    async proof(opts: {
      htm?: string;
      htu: string;
      token: string;
      iat?: number;
      jti?: string;
      typ?: string;
      jwk?: JWK;
    }): Promise<string> {
      return new SignJWT({
        htm: opts.htm ?? 'POST',
        htu: opts.htu,
        iat: opts.iat ?? Math.floor(Date.now() / 1000),
        jti: opts.jti ?? randomUUID(),
        ath: createHash('sha256').update(opts.token).digest('base64url'),
      })
        .setProtectedHeader({ alg: 'ES256', typ: opts.typ ?? 'dpop+jwt', jwk: opts.jwk ?? jwk })
        .sign(privateKey);
    },
  };
}

/** Listen on an ephemeral loopback port; returns the base URL and a closer. */
export async function listen(app: Express): Promise<{ base: string; close: () => Promise<void> }> {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** A real MCP v2 client pinned to 2026-07-28, authenticated with `token`. */
export async function modernClient(base: string, token: string): Promise<Client> {
  const client = new Client({ name: 'test', version: '1' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
    }),
  );
  return client;
}

export const MODERN_HEADERS = {
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
  'mcp-protocol-version': '2026-07-28',
};

/** A raw 2026-07-28 request envelope (what a non-SDK client puts on the wire). */
export function modernBody(method: string, params: Record<string, unknown> = {}, id: number | string = 1) {
  return {
    jsonrpc: '2.0',
    id,
    method,
    params: {
      ...params,
      _meta: {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientInfo': { name: 'raw', version: '1' },
        'io.modelcontextprotocol/clientCapabilities': {},
      },
    },
  };
}

/** Capture audit lines written through the shared audit sink. */
export function captureAudit(setSink: (fn: (line: string) => void) => void): { lines: string[] } {
  const box = { lines: [] as string[] };
  setSink((line) => box.lines.push(line));
  return box;
}
