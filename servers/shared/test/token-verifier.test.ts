import { beforeAll, describe, expect, it } from 'vitest';
import { generateSecret, SignJWT } from 'jose';
import { buildProtectedResourceMetadata, createTokenVerifier, type ResourceServerConfig } from '@mcp-lab/shared';
import { createTestIssuer, ISSUER, type TestIssuer } from './helpers.js';

const RESOURCE = 'mcp://srv/fhir-clinical';
const config: ResourceServerConfig = {
  resourceUri: RESOURCE,
  authorizationServers: [ISSUER],
  jwksUri: 'http://unused.invalid/certs',
};

let issuer: TestIssuer;
let verify: (token: string) => Promise<unknown>;
beforeAll(async () => {
  issuer = await createTestIssuer(RESOURCE);
  const v = createTokenVerifier(config, issuer.keySet);
  verify = (t) => v.verifyAccessToken(t);
});

describe('createTokenVerifier — accepts contract-shaped tokens', () => {
  it('accepts PS256 and exposes scopes, client, expiry, and claims', async () => {
    const token = await issuer.sign({ scope: 'openid mcp:x', azp: 'claude-code' });
    const info = (await verify(token)) as {
      scopes: string[];
      clientId: string;
      expiresAt: number;
      extra: Record<string, unknown>;
    };
    expect(info.scopes).toEqual(['openid', 'mcp:x']);
    expect(info.clientId).toBe('claude-code');
    expect(info.expiresAt).toBeGreaterThan(Date.now() / 1000);
    expect(info.extra.mcp_contract).toBe('1.0');
  });

  it('accepts ES256', async () => {
    await expect(verify(await issuer.sign({}, { alg: 'ES256' }))).resolves.toBeDefined();
  });

  it('accepts an Auth0 patient token carrying fhir_patient', async () => {
    const token = await issuer.sign({
      idp_origin: 'auth0',
      fhir_patient: '123',
      aud: [RESOURCE, 'mcp://tier/external'],
    });
    await expect(verify(token)).resolves.toBeDefined();
  });
});

describe('createTokenVerifier — rejects', () => {
  const cases: Array<[string, Record<string, unknown>, RegExp]> = [
    ['a token for another server (audience binding)', { aud: ['mcp://srv/scheduling', 'mcp://tier/internal'] }, /aud/],
    ['a token from another issuer', { iss: 'http://evil.example/realms/x' }, /iss/],
    ['an expired token', { exp: Math.floor(Date.now() / 1000) - 60 }, /exp/],
    ['a token without mcp_contract', { mcp_contract: undefined }, /mcp_contract/],
    ['a token with the wrong mcp_contract', { mcp_contract: '2.0' }, /mcp_contract/],
    ['a token with no tier audience', { aud: [RESOURCE] }, /exactly one tier audience/],
    [
      'a token with two tier audiences',
      { aud: [RESOURCE, 'mcp://tier/internal', 'mcp://tier/external'] },
      /exactly one tier audience/,
    ],
    ['a workforce token carrying fhir_patient', { fhir_patient: '123' }, /forbidden on non-patient/],
    ['an Auth0 token without fhir_patient', { idp_origin: 'auth0' }, /must carry a non-empty string fhir_patient/],
    ['an Auth0 token with an empty fhir_patient', { idp_origin: 'auth0', fhir_patient: '' }, /fhir_patient/],
    ['a token without jti', { jti: undefined }, /jti/],
    ['a token without sub', { sub: undefined }, /sub/],
    ['a token without azp', { azp: undefined }, /azp/],
    ['a token without iat', { iat: undefined }, /iat/],
  ];
  for (const [name, claims, message] of cases) {
    it(name, async () => {
      await expect(verify(await issuer.sign(claims))).rejects.toThrow(message);
    });
  }

  it('a token signed by a key outside the JWKS', async () => {
    await expect(verify(await issuer.sign({}, { key: issuer.rogue.privateKey }))).rejects.toThrow();
  });

  it('an HS256 token (HMAC is forbidden by the contract)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const hs = await new SignJWT({ mcp_contract: '1.0', aud: [RESOURCE, 'mcp://tier/internal'] })
      .setProtectedHeader({ alg: 'HS256', kid: 'ps' })
      .setIssuer(ISSUER)
      .setSubject('u')
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .setJti('j')
      .sign(await generateSecret('HS256'));
    await expect(verify(hs)).rejects.toThrow();
  });

  it('an RS256 token (RS256 is forbidden by the contract)', async () => {
    // A PS256 key cannot sign RS256 in jose, so forge the header instead:
    // the alg allow-list must reject before any key lookup succeeds.
    const good = await issuer.sign();
    const [, payload, sig] = good.split('.');
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'ps' })).toString('base64url');
    await expect(verify(`${header}.${payload}.${sig}`)).rejects.toThrow();
  });

  it('garbage', async () => {
    await expect(verify('not-a-jwt')).rejects.toThrow();
  });
});

describe('buildProtectedResourceMetadata', () => {
  it('advertises the resource, its authorization servers, and DPoP algs', () => {
    const prm = buildProtectedResourceMetadata({ ...config, scopesSupported: ['openid'] });
    expect(prm).toMatchObject({
      resource: RESOURCE,
      authorization_servers: [ISSUER],
      bearer_methods_supported: ['header'],
      dpop_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['openid'],
    });
    expect(buildProtectedResourceMetadata(config)).not.toHaveProperty('scopes_supported');
  });
});
