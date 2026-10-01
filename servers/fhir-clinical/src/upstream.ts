/**
 * The upstream FHIR call. The caller's token is NEVER forwarded (no confused
 * deputy); if the upstream needs auth, the server presents its own credential
 * (UPSTREAM_API_KEY).
 */
import type { ToolDescriptor } from './tools.js';

export interface UpstreamConfig {
  upstreamBaseUrl: string;
  upstreamApiKey?: string;
  maxFhirCount: number;
  upstreamTimeoutMs: number;
  maxUpstreamBytes: number;
}

export interface UpstreamResult {
  ok: boolean;
  status: number;
  data: unknown;
}

export function buildUpstreamUrl(config: UpstreamConfig, tool: ToolDescriptor, args: Record<string, unknown>): string {
  let path = tool.path;
  for (const p of tool.pathParams) {
    if (args[p] === undefined) throw new Error(`missing required path parameter: ${p}`);
    path = path.replace(`{${p}}`, encodeURIComponent(String(args[p])));
  }
  const query = new URLSearchParams();
  for (const q of tool.queryParams) {
    if (args[q] === undefined) continue;
    // Clamp _count so a caller can't ask HAPI for an unbounded page.
    if (q === '_count') {
      const n = Math.trunc(Number(args[q]));
      if (!Number.isFinite(n) || n < 1) throw new Error('_count must be a positive integer');
      query.set(q, String(Math.min(n, config.maxFhirCount)));
    } else {
      query.set(q, String(args[q]));
    }
  }
  const qs = query.toString();
  return `${config.upstreamBaseUrl}${path}${qs ? `?${qs}` : ''}`;
}

export async function callUpstream(
  config: UpstreamConfig,
  tool: ToolDescriptor,
  args: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
): Promise<UpstreamResult> {
  const url = buildUpstreamUrl(config, tool, args);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (config.upstreamApiKey) headers.Authorization = `Bearer ${config.upstreamApiKey}`;
  let body: string | undefined;
  if (tool.method !== 'GET' && tool.bodyParams.length > 0) {
    const payload: Record<string, unknown> = {};
    for (const b of tool.bodyParams) if (args[b] !== undefined) payload[b] = args[b];
    body = JSON.stringify(payload);
    headers['Content-Type'] = 'application/json';
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.upstreamTimeoutMs);
  try {
    let res: Response;
    try {
      res = await fetchImpl(url, { method: tool.method, headers, body, signal: controller.signal });
    } catch (err) {
      if ((err as Error)?.name === 'AbortError') throw new Error('upstream request timed out', { cause: err });
      throw err;
    }
    const text = await readCapped(res, config.maxUpstreamBytes);
    let data: unknown = text;
    try {
      data = JSON.parse(text);
    } catch {
      /* non-JSON upstream body */
    }
    return { ok: res.ok, status: res.status, data };
  } finally {
    clearTimeout(timer);
  }
}

// Read the body but stop once the cap is exceeded, so an oversized upstream
// response can't blow up the server's memory.
export async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return res.text();
  const decoder = new TextDecoder();
  let out = '';
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`upstream response exceeded ${maxBytes} bytes`);
    }
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}
