import { createApp, initSchema } from './server.js';

const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT || '3000', 10);

await initSchema();
createApp().listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.error(`scheduling-mcp listening on http://${HOST}:${PORT}/mcp`);
});
