/**
 * fhir-clinical-mcp entry point: validate configuration, then serve the
 * stateless Streamable HTTP MCP endpoint. See mcp-server.ts for the security model.
 */
import { ConfigError } from '@mcp-lab/shared';
import { loadConfig, type FhirConfig } from './config.js';
import { createApp } from './mcp-server.js';

let config: FhirConfig;
try {
  config = loadConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    console.error(`fhir-clinical-mcp: ${err.message}`);
    process.exit(1);
  }
  throw err;
}

createApp(config).listen(config.port, config.host, () => {
  console.error(
    `fhir-clinical-mcp listening on http://${config.host}:${config.port}/mcp (resource ${config.resource.resourceUri})`,
  );
});
