import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { confirmHold, findSlots, holdSlot, initSchema, isCatalogueSlot, releaseHold } from '../src/holds.js';
import { createTestDb } from './pglite-db.js';

let db: Awaited<ReturnType<typeof createTestDb>>;
const SLOT = 'slot-dr-smith-2026-07-10-0900';

beforeAll(async () => {
  db = await createTestDb();
  await initSchema(db);
});
beforeEach(async () => {
  await db.query('DELETE FROM scheduling_holds');
});

describe('catalogue', () => {
  it('lists three deterministic slots per provider/day', () => {
    expect(findSlots('2026-08-01', 'dr-x').map((s) => s.slot_id)).toEqual([
      'slot-dr-x-2026-08-01-0900',
      'slot-dr-x-2026-08-01-0930',
      'slot-dr-x-2026-08-01-1000',
    ]);
    expect(findSlots('', '')[0].slot_id).toBe(SLOT);
  });

  it('accepts only catalogue-shaped slot ids', () => {
    expect(isCatalogueSlot(SLOT)).toBe(true);
    expect(isCatalogueSlot('slot-dr-smith-2026-07-10-1100')).toBe(false);
    expect(isCatalogueSlot('slot-2026-07-10-0900')).toBe(false);
    expect(isCatalogueSlot("x'; DROP TABLE scheduling_holds; --")).toBe(false);
  });
});

describe('hold lifecycle', () => {
  it('migration is idempotent (replicas re-run it at boot)', async () => {
    await expect(initSchema(db)).resolves.toBeUndefined();
  });

  it('holds a slot and returns an explicit handle', async () => {
    const out = await holdSlot(db, SLOT, 'alice', 300, randomUUID);
    expect(out).toMatchObject({ ok: true, slot_id: SLOT, status: 'held' });
  });

  it('is idempotent for the owner and refuses everyone else', async () => {
    const first = await holdSlot(db, SLOT, 'alice', 300, randomUUID);
    const again = await holdSlot(db, SLOT, 'alice', 300, randomUUID);
    expect(again).toMatchObject({ ok: true, slot_hold_id: first.ok && first.slot_hold_id });
    expect(await holdSlot(db, SLOT, 'bob', 300, randomUUID)).toEqual({
      ok: false,
      reason: 'slot_taken',
      error: 'slot is already held',
    });
  });

  it('refuses unknown slots', async () => {
    expect(await holdSlot(db, 'slot-nope', 'alice', 300, randomUUID)).toMatchObject({ reason: 'unknown_slot' });
  });

  it('confirms only the owner, once, and idempotently', async () => {
    const held = await holdSlot(db, SLOT, 'alice', 300, randomUUID);
    if (!held.ok) throw new Error('setup');
    expect(await confirmHold(db, held.slot_hold_id, 'bob')).toMatchObject({ reason: 'unowned' });
    expect(await confirmHold(db, held.slot_hold_id, 'alice')).toMatchObject({ ok: true, status: 'confirmed' });
    expect(await confirmHold(db, held.slot_hold_id, 'alice')).toMatchObject({ ok: true, status: 'confirmed' });
    expect(await confirmHold(db, randomUUID(), 'alice')).toMatchObject({ reason: 'unknown' });
  });

  it('a confirmed slot no longer blocks a new hold (only active holds are unique)', async () => {
    const held = await holdSlot(db, SLOT, 'alice', 300, randomUUID);
    if (!held.ok) throw new Error('setup');
    await confirmHold(db, held.slot_hold_id, 'alice');
    expect(await holdSlot(db, SLOT, 'bob', 300, randomUUID)).toMatchObject({ ok: true });
  });

  it('expired holds cannot be confirmed and free the slot', async () => {
    const held = await holdSlot(db, SLOT, 'alice', 300, randomUUID);
    if (!held.ok) throw new Error('setup');
    await db.query("UPDATE scheduling_holds SET expires_at = now() - interval '1 second'");
    expect(await confirmHold(db, held.slot_hold_id, 'alice')).toMatchObject({ reason: 'expired' });
    expect(await holdSlot(db, SLOT, 'bob', 300, randomUUID)).toMatchObject({ ok: true });
  });

  it('release is owner-only and makes the handle unconfirmable', async () => {
    const held = await holdSlot(db, SLOT, 'alice', 300, randomUUID);
    if (!held.ok) throw new Error('setup');
    expect(await releaseHold(db, held.slot_hold_id, 'bob')).toMatchObject({ reason: 'unowned' });
    expect(await releaseHold(db, held.slot_hold_id, 'alice')).toMatchObject({ ok: true, status: 'released' });
    expect(await releaseHold(db, held.slot_hold_id, 'alice')).toMatchObject({ ok: true, status: 'released' });
    expect(await confirmHold(db, held.slot_hold_id, 'alice')).toMatchObject({ reason: 'released' });
    expect(await releaseHold(db, randomUUID(), 'alice')).toMatchObject({ reason: 'unknown' });
  });
});
