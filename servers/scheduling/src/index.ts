/**
 * scheduling-mcp entry point: validate configuration, migrate the hold table,
 * then serve the stateless Streamable HTTP MCP endpoint.
 */
import pg from 'pg';
import { ConfigError } from '@mcp-lab/shared';
import { loadConfig, type SchedulingConfig } from './config.js';
import { initSchema } from './holds.js';
import { createApp } from './server.js';

let config: SchedulingConfig;
try {
  config = loadConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    console.error(`scheduling-mcp: ${err.message}`);
    process.exit(1);
  }
  throw err;
}

const pool = new pg.Pool({ connectionString: config.databaseUrl });
await initSchema(pool);
createApp(config, pool).listen(config.port, config.host, () => {
  console.error(`scheduling-mcp listening on http://${config.host}:${config.port}/mcp`);
});
