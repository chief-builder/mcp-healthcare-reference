/**
 * Per-tool authorization policy, evaluated in two places from ONE definition:
 *
 *   1. HTTP layer (`enforceToolPolicy`), before the MCP handler runs, so an
 *      under-privileged `tools/call` gets the spec's single-shot challenge the
 *      client can act on (403 insufficient_scope → re-authorize with the named
 *      scope; 401 insufficient_user_authentication → re-authenticate with MFA).
 *   2. Inside every tool handler (`checkToolPolicy`), so no transport path —
 *      batched, legacy, or otherwise — can reach a tool without passing the
 *      same checks. The HTTP layer is the UX; the handler is the guarantee.
 *
 * Rules, in order:
 *   - the tool's `requiredScope` (step-up) must be held;
 *   - a patient-origin token (fhir_patient present) must hold the tool's
 *     per-resource `patientScope` (contract §3/§6.5);
 *   - when the required scope is MFA-gated, the token's `amr` must include
 *     `mfa` (contract §3 `amr`; arch §HIPAA "mfa required for clinical tool
 *     scopes"). Challenge per RFC 9470.
 */
import type { AuthInfo } from '@modelcontextprotocol/server';
import type { NextFunction, Request, Response } from 'express';
import { claimsOf, stringListClaim } from './token-verifier.js';

export interface ToolPolicy {
  /** Scope every caller must hold (step-up). */
  requiredScope?: string;
  /** Scope a patient-origin token must hold for this tool's resource type. */
  patientScope?: string;
}

export type PolicyResult =
  | { ok: true }
  | { ok: false; kind: 'insufficient_scope'; scope: string }
  | { ok: false; kind: 'insufficient_user_authentication'; scope: string };

export function evaluateToolPolicy(
  policy: ToolPolicy | undefined,
  auth: AuthInfo | undefined,
  mfaScopes: readonly string[],
): PolicyResult {
  if (!policy) return { ok: true };
  const isPatient = claimsOf(auth).fhir_patient !== undefined;
  const required = policy.requiredScope ?? (isPatient ? policy.patientScope : undefined);
  if (!required) return { ok: true };
  if (!(auth?.scopes ?? []).includes(required)) {
    return { ok: false, kind: 'insufficient_scope', scope: required };
  }
  if (mfaScopes.includes(required) && !stringListClaim(auth, 'amr').includes('mfa')) {
    return { ok: false, kind: 'insufficient_user_authentication', scope: required };
  }
  return { ok: true };
}

export interface ToolPolicyOptions {
  policyFor: (toolName: string) => ToolPolicy | undefined;
  mfaScopes: readonly string[];
  resourceMetadataUrl: string;
  /** Records the denial (audit line) before the challenge is sent. */
  onDeny: (auth: AuthInfo | undefined, tool: string, reason: string) => void;
}

/** Express middleware: the HTTP-layer challenge for a single tools/call. */
export function enforceToolPolicy(options: ToolPolicyOptions) {
  return function toolPolicy(req: Request, res: Response, next: NextFunction): void {
    const body = req.body as { method?: unknown; params?: { name?: unknown } } | undefined;
    if (body?.method !== 'tools/call' || typeof body.params?.name !== 'string') return next();
    const tool = body.params.name;
    const result = evaluateToolPolicy(options.policyFor(tool), req.auth, options.mfaScopes);
    if (result.ok) return next();
    options.onDeny(req.auth, tool, result.kind);
    if (result.kind === 'insufficient_scope') {
      res
        .status(403)
        .set(
          'WWW-Authenticate',
          `Bearer error="insufficient_scope", scope="${result.scope}", resource_metadata="${options.resourceMetadataUrl}"`,
        )
        .json({ error: 'insufficient_scope', scope: result.scope });
      return;
    }
    // RFC 9470 §3: the token is valid but the authentication event behind it
    // is too weak for this resource; the client re-authenticates (with MFA).
    res
      .status(401)
      .set(
        'WWW-Authenticate',
        `Bearer error="insufficient_user_authentication", error_description="multi-factor authentication required", resource_metadata="${options.resourceMetadataUrl}"`,
      )
      .json({ error: 'insufficient_user_authentication', scope: result.scope });
  };
}

/** Tool-handler guard: returns an MCP error result when the policy fails. */
export function checkToolPolicy(
  policy: ToolPolicy | undefined,
  auth: AuthInfo | undefined,
  mfaScopes: readonly string[],
): { content: { type: 'text'; text: string }[]; isError: true; reason: string } | undefined {
  const result = evaluateToolPolicy(policy, auth, mfaScopes);
  if (result.ok) return undefined;
  const text =
    result.kind === 'insufficient_scope'
      ? `insufficient_scope: requires ${result.scope}`
      : `insufficient_user_authentication: ${result.scope} requires multi-factor authentication`;
  return { content: [{ type: 'text', text }], isError: true, reason: result.kind };
}
