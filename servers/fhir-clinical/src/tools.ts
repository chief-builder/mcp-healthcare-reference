/**
 * Tool catalogue, generated from openapi.json by openapi-mcp-generator and
 * kept verbatim. `requiredScope` is the step-up scope every caller needs;
 * `requiredGroup` gates visibility (tools/list); `requiredPatientScope` is the
 * per-resource scope a patient-origin token must hold (contract §3/§6.5).
 */
import type { ToolPolicy } from '@mcp-lab/shared';

export interface ToolDescriptor {
  name: string;
  title?: string;
  description?: string;
  inputSchema: { type?: string; properties?: Record<string, unknown>; required?: string[] };
  annotations?: Record<string, unknown>;
  method: string;
  path: string;
  pathParams: string[];
  queryParams: string[];
  bodyParams: string[];
  requiredScope?: string;
  requiredGroup?: string;
  /** Scope a patient-origin token (fhir_patient present) must hold for this
   *  tool's resource type (contract §3/§6.5). Not required of workforce tokens. */
  requiredPatientScope?: string;
}
export const TOOLS: ToolDescriptor[] = [
  {
    name: 'getPatient',
    title: 'Get Patient',
    description: 'Read a single Patient resource. Patient-scoped callers may only read their own record.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'FHIR Patient logical id',
        },
      },
      required: ['id'],
    },
    annotations: {
      title: 'Get Patient',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    method: 'GET',
    path: '/Patient/{id}',
    pathParams: ['id'],
    queryParams: [],
    bodyParams: [],
    requiredPatientScope: 'patient/Patient.read',
  },
  {
    name: 'patientEverything',
    title: 'Patient Everything',
    description: 'Return the full patient compartment. Broad operation: clinical role + step-up scope required.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'FHIR Patient logical id',
        },
      },
      required: ['id'],
    },
    annotations: {
      title: 'Patient Everything',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    method: 'GET',
    path: '/Patient/{id}/$everything',
    pathParams: ['id'],
    queryParams: [],
    bodyParams: [],
    requiredScope: 'mcp:fhir-clinical:everything:read',
    requiredGroup: 'mcp-clinical-tools',
  },
  {
    name: 'searchObservation',
    title: 'Search Observation',
    description: 'Search Observations',
    inputSchema: {
      type: 'object',
      properties: {
        patient: {
          type: 'string',
          description: 'Patient reference (id)',
        },
        code: {
          type: 'string',
          description: 'Observation code (LOINC)',
        },
        _count: {
          type: 'integer',
          description: 'Max results',
        },
      },
    },
    annotations: {
      title: 'Search Observation',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    method: 'GET',
    path: '/Observation',
    pathParams: [],
    queryParams: ['patient', 'code', '_count'],
    bodyParams: [],
    requiredPatientScope: 'patient/Observation.read',
  },
  {
    name: 'searchCondition',
    title: 'Search Condition',
    description: 'Search Conditions',
    inputSchema: {
      type: 'object',
      properties: {
        patient: {
          type: 'string',
          description: 'Patient reference (id)',
        },
        _count: {
          type: 'integer',
          description: 'Max results',
        },
      },
    },
    annotations: {
      title: 'Search Condition',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    method: 'GET',
    path: '/Condition',
    pathParams: [],
    queryParams: ['patient', '_count'],
    bodyParams: [],
    requiredPatientScope: 'patient/Condition.read',
  },
  {
    name: 'searchMedicationRequest',
    title: 'Search Medication Request',
    description: 'Search MedicationRequests',
    inputSchema: {
      type: 'object',
      properties: {
        patient: {
          type: 'string',
          description: 'Patient reference (id)',
        },
        _count: {
          type: 'integer',
          description: 'Max results',
        },
      },
    },
    annotations: {
      title: 'Search Medication Request',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    method: 'GET',
    path: '/MedicationRequest',
    pathParams: [],
    queryParams: ['patient', '_count'],
    bodyParams: [],
    requiredPatientScope: 'patient/MedicationRequest.read',
  },
];
export const TOOLS_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

export function policyFor(toolName: string): ToolPolicy | undefined {
  const tool = TOOLS_BY_NAME.get(toolName);
  return tool && { requiredScope: tool.requiredScope, patientScope: tool.requiredPatientScope };
}
