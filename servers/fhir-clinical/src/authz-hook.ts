/**
 * FHIR patient-compartment enforcement (claims contract §6.5).
 *
 * Hand-written hook the MCP server runs before every tool call. When the caller's token carries `fhir_patient` (the Auth0 end-customer
 * path), every FHIR interaction is HARD-filtered to that patient's compartment:
 *   - search tools: the `patient` parameter is forced to the token's patient,
 *     overriding anything the client supplied;
 *   - by-id reads ($everything, Patient read): the requested id MUST equal the
 *     token's patient, else 403.
 *
 * Workforce tokens (no `fhir_patient`) pass through unchanged — their access is
 * governed by group + scope, enforced by the server's tool policy.
 */
import type { AuthInfo } from '@modelcontextprotocol/server';
import { claimsOf } from '@mcp-lab/shared';

interface ToolLike {
  name: string;
  pathParams: string[];
  queryParams: string[];
}

interface AuthzContext {
  auth?: AuthInfo;
  tool: ToolLike;
  args: Record<string, unknown>;
}

class CompartmentError extends Error {
  status = 403;
  constructor(message: string) {
    super(message);
    this.name = 'CompartmentError';
  }
}

export async function authorize(ctx: AuthzContext): Promise<Record<string, unknown>> {
  const patient = claimsOf(ctx.auth).fhir_patient as string | undefined;
  if (!patient) {
    return ctx.args; // workforce / non-patient token: no compartment restriction
  }

  const args = { ...ctx.args };

  // by-id reads must target exactly the token's patient
  if (ctx.tool.pathParams.includes('id')) {
    if (String(args.id) !== String(patient)) {
      throw new CompartmentError(`patient-scoped token may only access Patient/${patient}, not ${args.id}`);
    }
  }

  // searches are hard-scoped to the token's patient (client value ignored)
  if (ctx.tool.queryParams.includes('patient')) {
    args.patient = patient;
  }

  return args;
}
