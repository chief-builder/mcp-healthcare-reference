import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import express, { type NextFunction, type Request, type Response } from 'express';
import { dpopSchemeShim, requireDpop } from '@mcp-lab/shared';
import { createDpopKey, listen } from './helpers.js';

// Stand-in for requireBearerAuth: the token's claims ride in a test header.
function fakeBearer(req: Request, _res: Response, next: NextFunction): void {
  const token = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
  const jkt = req.headers['x-test-jkt'];
  req.auth = { token, clientId: 'c', scopes: [], extra: jkt ? { cnf: { jkt } } : {} };
  next();
}

const TOKEN = 'header.payload.signature';
let key: Awaited<ReturnType<typeof createDpopKey>>;
let other: Awaited<ReturnType<typeof createDpopKey>>;
let server: Awaited<ReturnType<typeof listen>>;
let htu: string;

beforeAll(async () => {
  key = await createDpopKey();
  other = await createDpopKey();
  const app = express();
  // htu is fixed config (the public URL), filled in once the port is known.
  app.post('/mcp', dpopSchemeShim, fakeBearer, (req, res, next) =>
    requireDpop({ htu, resourceMetadataUrl: 'http://rs/prm' })(req, res, next),
  );
  app.post('/mcp', (_req, res) => {
    res.json({ ok: true });
  });
  server = await listen(app);
  htu = `${server.base}/mcp`;
});
afterAll(() => server.close());

async function call(headers: Record<string, string>) {
  return fetch(`${server.base}/mcp`, { method: 'POST', headers });
}

describe('requireDpop — positive', () => {
  it('passes a plain bearer token (no cnf.jkt) untouched', async () => {
    const r = await call({ authorization: `Bearer ${TOKEN}` });
    expect(r.status).toBe(200);
  });

  it('passes a jkt-bound token with a valid proof under the DPoP scheme', async () => {
    const r = await call({
      authorization: `DPoP ${TOKEN}`,
      'x-test-jkt': key.jkt,
      dpop: await key.proof({ htu, token: TOKEN }),
    });
    expect(r.status).toBe(200);
  });

  it('ignores query/fragment on htu (RFC 9449 §4.3)', async () => {
    const r = await call({
      authorization: `DPoP ${TOKEN}`,
      'x-test-jkt': key.jkt,
      dpop: await key.proof({ htu: `${htu}?x=1#y`, token: TOKEN }),
    });
    expect(r.status).toBe(200);
  });
});

describe('requireDpop — rejects a jkt-bound token', () => {
  const now = () => Math.floor(Date.now() / 1000);
  const cases: Array<[string, () => Promise<Record<string, string>>, RegExp]> = [
    ['under the Bearer scheme', async () => ({ authorization: `Bearer ${TOKEN}` }), /DPoP authorization scheme/],
    ['without a proof', async () => ({ authorization: `DPoP ${TOKEN}` }), /missing DPoP proof/],
    [
      'with two proofs',
      async () => {
        const p = await key.proof({ htu, token: TOKEN });
        return { authorization: `DPoP ${TOKEN}`, dpop: `${p}, ${p}` };
      },
      /exactly one/,
    ],
    [
      'with a proof from another key (thumbprint mismatch)',
      async () => ({ authorization: `DPoP ${TOKEN}`, dpop: await other.proof({ htu, token: TOKEN }) }),
      /does not match the bound token/,
    ],
    [
      'with the wrong htm',
      async () => ({ authorization: `DPoP ${TOKEN}`, dpop: await key.proof({ htm: 'GET', htu, token: TOKEN }) }),
      /htm mismatch/,
    ],
    [
      'with the wrong htu',
      async () => ({ authorization: `DPoP ${TOKEN}`, dpop: await key.proof({ htu: 'http://evil/mcp', token: TOKEN }) }),
      /htu mismatch/,
    ],
    [
      'with a stale iat',
      async () => ({ authorization: `DPoP ${TOKEN}`, dpop: await key.proof({ htu, token: TOKEN, iat: now() - 600 }) }),
      /freshness window/,
    ],
    [
      'with a proof bound to a different token (ath)',
      async () => ({ authorization: `DPoP ${TOKEN}`, dpop: await key.proof({ htu, token: 'another.token.here' }) }),
      /ath does not match/,
    ],
    [
      'with the wrong typ',
      async () => ({ authorization: `DPoP ${TOKEN}`, dpop: await key.proof({ htu, token: TOKEN, typ: 'JWT' }) }),
      /invalid DPoP proof/,
    ],
    [
      'with an empty jti',
      async () => ({ authorization: `DPoP ${TOKEN}`, dpop: await key.proof({ htu, token: TOKEN, jti: '' }) }),
      /missing proof jti/,
    ],
    [
      'with a tampered signature',
      async () => {
        const p = await key.proof({ htu, token: TOKEN });
        const sig = p.split('.')[2];
        const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
        return { authorization: `DPoP ${TOKEN}`, dpop: p.split('.').slice(0, 2).concat(flipped).join('.') };
      },
      /invalid DPoP proof/,
    ],
  ];

  for (const [name, headers, message] of cases) {
    it(name, async () => {
      const r = await call({ 'x-test-jkt': key.jkt, ...(await headers()) });
      expect(r.status).toBe(401);
      expect(r.headers.get('www-authenticate')).toMatch(/^DPoP algs="ES256"/);
      expect(r.headers.get('www-authenticate')).toContain('resource_metadata="http://rs/prm"');
      expect((await r.json()).error_description).toMatch(message);
    });
  }
});
