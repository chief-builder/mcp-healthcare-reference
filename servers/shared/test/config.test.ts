import { describe, expect, it } from 'vitest';
import { ConfigError, EnvReader } from '@mcp-lab/shared';

describe('EnvReader', () => {
  it('applies defaults and parses typed values', () => {
    const e = new EnvReader({ PORT: '8080', LIST: 'a, b,,c', URL: 'https://x.example/y' });
    expect(e.string('HOST', '127.0.0.1')).toBe('127.0.0.1');
    expect(e.int('PORT', 3000, { min: 1 })).toBe(8080);
    expect(e.list('LIST')).toEqual(['a', 'b', 'c']);
    expect(e.url('URL', undefined)).toBe('https://x.example/y');
    expect(e.optional('MISSING')).toBeUndefined();
    expect(() => e.done()).not.toThrow();
  });

  it('collects every problem and reports them together', () => {
    const e = new EnvReader({ PORT: 'eighty', MIN: '0', URL: 'not a url', SCHEME: 'ftp://x', DB: '' });
    e.int('PORT', 3000);
    e.int('MIN', 5, { min: 1 });
    e.url('URL', undefined);
    e.url('SCHEME', undefined);
    e.string('DB');
    e.urlList('SERVERS', []);
    try {
      e.done();
      expect.fail('expected ConfigError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      const problems = (err as ConfigError).problems;
      expect(problems).toHaveLength(6);
      expect(problems.join('\n')).toMatch(/PORT must be an integer/);
      expect(problems.join('\n')).toMatch(/MIN must be >= 1/);
      expect(problems.join('\n')).toMatch(/URL must be an absolute URL/);
      expect(problems.join('\n')).toMatch(/SCHEME must use http: or https:/);
      expect(problems.join('\n')).toMatch(/DB is required/);
      expect(problems.join('\n')).toMatch(/SERVERS must list at least one URL/);
    }
  });

  it('accepts custom URL schemes (mcp:// resource identifiers)', () => {
    const e = new EnvReader({ R: 'mcp://srv/x' });
    expect(e.url('R', undefined, ['mcp:'])).toBe('mcp://srv/x');
    expect(() => e.done()).not.toThrow();
  });
});
