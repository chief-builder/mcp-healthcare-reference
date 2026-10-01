/** Adapts in-process PGlite (real Postgres, WASM) to the scheduling `Db` port. */
import { PGlite } from '@electric-sql/pglite';
import type { Db, QueryResult } from '../src/holds.js';

export async function createTestDb(): Promise<Db & { pg: PGlite }> {
  const pg = await PGlite.create();
  const query = async (text: string, params?: unknown[]): Promise<QueryResult> => {
    const r = await pg.query<Record<string, unknown>>(text, params as unknown[]);
    return { rows: r.rows, rowCount: r.affectedRows ?? r.rows.length };
  };
  // PGlite is a single connection, so a "client" is the same session.
  return { pg, query, connect: async () => ({ query, release: () => {} }) };
}
