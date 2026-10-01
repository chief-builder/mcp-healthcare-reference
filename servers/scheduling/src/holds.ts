/**
 * Slot-hold persistence. Continuity lives in explicit `slot_hold_id` HANDLES
 * and hold state lives in Postgres (shared), NOT in server memory — any
 * replica can serve any request.
 *
 * Every operation takes a `Db` (a pg Pool in production; tests inject an
 * in-process Postgres), and returns a plain outcome the tool layer turns into
 * an MCP result + audit decision.
 */
export interface QueryResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
}
export interface DbClient {
  query(text: string, params?: unknown[]): Promise<QueryResult>;
  release(): void;
}
export interface Db {
  query(text: string, params?: unknown[]): Promise<QueryResult>;
  connect(): Promise<DbClient>;
}

export async function initSchema(db: Db): Promise<void> {
  const client = await db.connect();
  try {
    // Serialize the migration across replicas: two replicas booting together
    // otherwise race on CREATE UNIQUE INDEX (one crashes on a duplicate relation).
    await client.query('SELECT pg_advisory_lock(hashtext($1))', ['scheduling_holds_init']);
    await client.query(`
      CREATE TABLE IF NOT EXISTS scheduling_holds (
        slot_hold_id UUID PRIMARY KEY,
        slot_id      TEXT NOT NULL,
        subject      TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'held',
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at   TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
    await client.query(
      'ALTER TABLE scheduling_holds ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT now()',
    );
    // Collapse any pre-constraint duplicate held rows (keep the newest per slot)
    // so the one-active-hold-per-slot unique index can be created safely. The
    // constraint covers 'held' only: it guards the concurrent-hold race, while a
    // terminal 'confirmed' row does not permanently occupy the slot (the lab's
    // deterministic catalogue is shared with a live workload).
    await client.query(`
      UPDATE scheduling_holds SET status='expired'
      WHERE status='held' AND slot_hold_id NOT IN (
        SELECT DISTINCT ON (slot_id) slot_hold_id FROM scheduling_holds
        WHERE status='held' ORDER BY slot_id, created_at DESC)`);
    // Drop first so a predicate change from an earlier revision takes effect
    // (CREATE ... IF NOT EXISTS would keep a stale predicate). Safe: we hold the
    // advisory lock and the server is not yet serving.
    await client.query('DROP INDEX IF EXISTS scheduling_holds_active_slot');
    await client.query(`
      CREATE UNIQUE INDEX scheduling_holds_active_slot
        ON scheduling_holds (slot_id) WHERE status='held'`);
  } finally {
    await client.query('SELECT pg_advisory_unlock(hashtext($1))', ['scheduling_holds_init']).catch(() => {});
    client.release();
  }
}

// Synthetic, deterministic slot catalogue (no state; a real server would query
// the practice-management system).
const SLOT_TIMES = ['09:00', '09:30', '10:00'];
const SLOT_SUFFIXES = SLOT_TIMES.map((t) => t.replace(':', ''));

export function findSlots(date: string, provider: string): Array<{ slot_id: string; start: string }> {
  const day = date || '2026-07-10';
  return SLOT_TIMES.map((t) => ({
    slot_id: `slot-${provider || 'dr-smith'}-${day}-${t.replace(':', '')}`,
    start: `${day}T${t}:00`,
  }));
}

// A slot_id is bookable only if it has the catalogue's shape: a provider, an
// ISO date, and one of the catalogue's time suffixes.
export function isCatalogueSlot(slotId: string): boolean {
  const m = /^slot-.+-\d{4}-\d{2}-\d{2}-(\d{4})$/.exec(slotId);
  return !!m && SLOT_SUFFIXES.includes(m[1]);
}

export type HoldOutcome =
  { ok: true; slot_hold_id: string; slot_id?: string; status: string } | { ok: false; reason: string; error: string };

export async function holdSlot(
  db: Db,
  slotId: string,
  subject: string,
  ttlSeconds: number,
  newId: () => string,
): Promise<HoldOutcome> {
  if (!isCatalogueSlot(slotId)) return { ok: false, reason: 'unknown_slot', error: 'unknown slot_id' };
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    // Free any expired hold on this slot before contending for it.
    await client.query(
      "UPDATE scheduling_holds SET status='expired' WHERE slot_id=$1 AND status='held' AND expires_at <= now()",
      [slotId],
    );
    const slotHoldId = newId();
    const ins = await client.query(
      `INSERT INTO scheduling_holds (slot_hold_id, slot_id, subject, status, expires_at)
         VALUES ($1,$2,$3,'held', now() + $4 * interval '1 second')
         ON CONFLICT (slot_id) WHERE status='held'
         DO NOTHING RETURNING slot_hold_id`,
      [slotHoldId, slotId, subject, ttlSeconds],
    );
    if (ins.rowCount === 1) {
      await client.query('COMMIT');
      return { ok: true, slot_hold_id: slotHoldId, slot_id: slotId, status: 'held' };
    }
    // Slot already actively held: the owner gets their existing handle back
    // (idempotent); anyone else is refused until it releases or expires.
    const cur = await client.query(
      "SELECT slot_hold_id, subject, status FROM scheduling_holds WHERE slot_id=$1 AND status='held'",
      [slotId],
    );
    await client.query('COMMIT');
    const row = cur.rows[0];
    if (row && row.subject === subject) {
      return { ok: true, slot_hold_id: String(row.slot_hold_id), slot_id: slotId, status: String(row.status) };
    }
    return { ok: false, reason: 'slot_taken', error: 'slot is already held' };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export async function confirmHold(db: Db, slotHoldId: string, subject: string): Promise<HoldOutcome> {
  const r = await db.query(
    'SELECT slot_id, subject, status, (expires_at <= now()) AS expired FROM scheduling_holds WHERE slot_hold_id=$1',
    [slotHoldId],
  );
  const row = r.rows[0];
  if (!row) return { ok: false, reason: 'unknown', error: 'unknown slot_hold_id' };
  if (row.subject !== subject)
    return { ok: false, reason: 'unowned', error: 'slot_hold_id belongs to another subject' };
  if (row.status === 'released') return { ok: false, reason: 'released', error: 'hold was released' };
  const slot_id = String(row.slot_id);
  if (row.status === 'confirmed') return { ok: true, slot_hold_id: slotHoldId, slot_id, status: 'confirmed' };
  if (row.status === 'expired' || row.expired) return { ok: false, reason: 'expired', error: 'hold expired' };
  const upd = await db.query(
    "UPDATE scheduling_holds SET status='confirmed' WHERE slot_hold_id=$1 AND subject=$2 AND status='held' AND expires_at > now()",
    [slotHoldId, subject],
  );
  // Lost a race with expiry/release between the read and the write.
  if (upd.rowCount !== 1) return { ok: false, reason: 'expired', error: 'hold expired' };
  return { ok: true, slot_hold_id: slotHoldId, slot_id, status: 'confirmed' };
}

export async function releaseHold(db: Db, slotHoldId: string, subject: string): Promise<HoldOutcome> {
  const r = await db.query('SELECT subject, status FROM scheduling_holds WHERE slot_hold_id=$1', [slotHoldId]);
  const row = r.rows[0];
  if (!row) return { ok: false, reason: 'unknown', error: 'unknown slot_hold_id' };
  if (row.subject !== subject)
    return { ok: false, reason: 'unowned', error: 'slot_hold_id belongs to another subject' };
  if (row.status !== 'released') {
    await db.query("UPDATE scheduling_holds SET status='released' WHERE slot_hold_id=$1 AND subject=$2", [
      slotHoldId,
      subject,
    ]);
  }
  return { ok: true, slot_hold_id: slotHoldId, status: 'released' };
}
