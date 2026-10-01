/**
 * Environment configuration helpers. Each server declares its whole config in
 * one `loadConfig(env)` built from these readers; every problem is collected
 * and reported together at startup (fail fast, before the port is bound),
 * instead of surfacing as a 500 on the first request.
 */

export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`invalid configuration:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ConfigError';
  }
}

type Env = Record<string, string | undefined>;

export class EnvReader {
  private readonly problems: string[] = [];

  constructor(private readonly env: Env) {}

  /** A string; `fallback` undefined means the variable is required. */
  string(name: string, fallback?: string): string {
    const raw = this.env[name];
    if (raw !== undefined && raw !== '') return raw;
    if (fallback === undefined) {
      this.problems.push(`${name} is required`);
      return '';
    }
    return fallback;
  }

  optional(name: string): string | undefined {
    const raw = this.env[name];
    return raw === undefined || raw === '' ? undefined : raw;
  }

  int(name: string, fallback: number, { min = 0 }: { min?: number } = {}): number {
    const raw = this.env[name];
    if (raw === undefined || raw === '') return fallback;
    if (!/^-?\d+$/.test(raw.trim())) {
      this.problems.push(`${name} must be an integer (got "${raw}")`);
      return fallback;
    }
    const value = Number(raw);
    if (value < min) this.problems.push(`${name} must be >= ${min} (got ${value})`);
    return value;
  }

  /** Comma-separated list; empty entries dropped. */
  list(name: string, fallback: string[] = []): string[] {
    const raw = this.env[name];
    if (raw === undefined) return fallback;
    return raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  /** An absolute URL; `schemes` restricts the protocol (e.g. http/https). */
  url(name: string, fallback: string | undefined, schemes: string[] = ['http:', 'https:']): string {
    const value = this.string(name, fallback);
    if (value === '') return value;
    this.checkUrl(name, value, schemes);
    return value;
  }

  urlList(name: string, fallback: string[], schemes: string[] = ['http:', 'https:']): string[] {
    const values = this.list(name, fallback);
    if (values.length === 0) this.problems.push(`${name} must list at least one URL`);
    for (const v of values) this.checkUrl(name, v, schemes);
    return values;
  }

  /** Throw a ConfigError listing every problem found so far. */
  done(): void {
    if (this.problems.length) throw new ConfigError(this.problems);
  }

  private checkUrl(name: string, value: string, schemes: string[]): void {
    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      this.problems.push(`${name} must be an absolute URL (got "${value}")`);
      return;
    }
    if (!schemes.includes(parsed.protocol)) {
      this.problems.push(`${name} must use ${schemes.join(' or ')} (got "${value}")`);
    }
  }
}
