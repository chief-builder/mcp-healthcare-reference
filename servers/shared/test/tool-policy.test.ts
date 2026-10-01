import { describe, expect, it } from 'vitest';
import type { AuthInfo } from '@modelcontextprotocol/server';
import { checkToolPolicy, evaluateToolPolicy } from '@mcp-lab/shared';

const STEP_UP = 'mcp:fhir-clinical:everything:read';
const auth = (scopes: string[], extra: Record<string, unknown> = {}): AuthInfo => ({
  token: 't',
  clientId: 'c',
  scopes,
  extra,
});

describe('evaluateToolPolicy', () => {
  it('passes tools with no policy or no required scope (floor tools)', () => {
    expect(evaluateToolPolicy(undefined, auth([]), [])).toEqual({ ok: true });
    expect(evaluateToolPolicy({}, auth([]), [])).toEqual({ ok: true });
  });

  it('requires the step-up scope', () => {
    expect(evaluateToolPolicy({ requiredScope: STEP_UP }, auth(['openid']), [])).toEqual({
      ok: false,
      kind: 'insufficient_scope',
      scope: STEP_UP,
    });
    expect(evaluateToolPolicy({ requiredScope: STEP_UP }, auth([STEP_UP]), [])).toEqual({ ok: true });
  });

  it('requires the per-resource scope of patient-origin tokens only', () => {
    const policy = { patientScope: 'patient/Observation.read' };
    expect(evaluateToolPolicy(policy, auth([], { fhir_patient: 'p1' }), [])).toMatchObject({
      ok: false,
      scope: 'patient/Observation.read',
    });
    expect(evaluateToolPolicy(policy, auth(['patient/Observation.read'], { fhir_patient: 'p1' }), [])).toEqual({
      ok: true,
    });
    // Workforce tokens keep floor read access (governed by group ACLs).
    expect(evaluateToolPolicy(policy, auth([]), [])).toEqual({ ok: true });
  });

  it('requires amr=mfa for MFA-gated scopes', () => {
    const policy = { requiredScope: STEP_UP };
    expect(evaluateToolPolicy(policy, auth([STEP_UP], { amr: ['pwd'] }), [STEP_UP])).toEqual({
      ok: false,
      kind: 'insufficient_user_authentication',
      scope: STEP_UP,
    });
    expect(evaluateToolPolicy(policy, auth([STEP_UP]), [STEP_UP])).toMatchObject({
      kind: 'insufficient_user_authentication',
    });
    expect(evaluateToolPolicy(policy, auth([STEP_UP], { amr: ['pwd', 'mfa'] }), [STEP_UP])).toEqual({ ok: true });
    // A single-string amr claim is accepted too.
    expect(evaluateToolPolicy(policy, auth([STEP_UP], { amr: 'mfa' }), [STEP_UP])).toEqual({ ok: true });
  });

  it('checks scope before MFA (the client fixes scope first)', () => {
    expect(evaluateToolPolicy({ requiredScope: STEP_UP }, auth([], { amr: ['pwd'] }), [STEP_UP])).toMatchObject({
      kind: 'insufficient_scope',
    });
  });

  it('fails closed without authentication', () => {
    expect(evaluateToolPolicy({ requiredScope: STEP_UP }, undefined, [])).toMatchObject({ ok: false });
  });
});

describe('checkToolPolicy', () => {
  it('returns an MCP error result naming the requirement', () => {
    const denied = checkToolPolicy({ requiredScope: STEP_UP }, auth([]), []);
    expect(denied).toMatchObject({ isError: true, reason: 'insufficient_scope' });
    expect(denied?.content[0].text).toContain(STEP_UP);
    expect(checkToolPolicy({ requiredScope: STEP_UP }, auth([STEP_UP]), [])).toBeUndefined();
  });
});
