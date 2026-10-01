import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    // Tests run against workspace sources; no build step needed first.
    alias: { '@mcp-lab/shared': fileURLToPath(new URL('./shared/src/index.ts', import.meta.url)) },
  },
  test: {
    include: ['*/test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['shared/src/**', 'fhir-clinical/src/**', 'scheduling/src/**'],
      exclude: ['**/index.ts'],
      reporter: ['text', 'json-summary'],
    },
  },
});
