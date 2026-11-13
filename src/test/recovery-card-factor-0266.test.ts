// @vitest-environment node
/**
 * db/0266 (EXPAND): ROUT Card as fourth recovery shard.
 * Replays db/ on PGlite, applies 0266 and runs every function as rout_app with
 * a real transaction context. Checks: a 2-of-4 save stores the card shard as
 * version 2, the 0264-era reads never hand out a version 2 row, the 8-argument
 * save writes a clean version 1 row, the table stays closed to rout_app and
 * PUBLIC executes nothing, and every function is pinned to pg_catalog, pg_temp.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";
import { definerMigrationViolations } from "../../scripts/security-definer-policy";

const ROOT = join(__dirname, "..", "..");
const DB_DIR = join(ROOT, "db");
const FILE = join(ROOT, "db", "0266_recovery_card_factor.sql");
const SQL_0266 = readFileSync(FILE, "utf8");

const ALICE = "00000000-0000-4000-8000-0000000000e1";
const BOB = "00000000-0000-4000-8000-0000000000e2";
const shard = (c: string) => c.repeat(80);
const MASTER = "M".repeat(60);
const LOGIN = `${"L".repeat(43)}=`;
const CRED = "credential-id_1";
const CEREMONY = "a".repeat(32);

let db: PGlite;

async function asApp<T>(caller: string | null, query: string, params: unknown[] = []): Promise<T[]> {
  await db.exec("begin");
  try {
    await db.exec("set local role rout_app");
    await db.query("select set_config('rout.current_user_id', $1, true)", [caller ?? ""]);
    const r = await db.query<T>(query, params);
    await db.exec("commit");
    return r.rows;
  } catch (e) {
    await db.exec("rollback");
    throw e;
  }
}

const put9 = (who: string, card: string | null, device = shard("D")) =>
  asApp(who, "select public.rout_recovery_ceremony_put($1,$2,$3,$4,$5,$6,$7,$8,$9)", [CEREMONY, "key_id_1", MASTER, device, shard("P"), shard("S"), card, CRED, LOGIN]);
const put8 = (who: string) =>
  asApp(who, "select public.rout_recovery_ceremony_put($1,$2,$3,$4,$5,$6,$7,$8)", [CEREMONY, "key_id_1", MASTER, shard("D"), shard("P"), shard("S"), CRED, LOGIN]);

beforeAll(async () => {
  const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
  const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
  db = new PGlite({ extensions: { pgcrypto, btree_gist } });
  for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
    if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
  }
  await db.exec(`begin;\n${SQL_0266}\n;commit;`);
  await db.query("insert into public.users (id, email) values ($1, 'alice@example.test'), ($2, 'bob@example.test')", [ALICE, BOB]);
}, 300_000);

afterAll(async () => {
  await db?.close();
});

describe("0266: ROUT Card as fourth recovery shard", () => {
  it("passes the SECURITY DEFINER lint and pins every recovery function to pg_catalog, pg_temp", async () => {
    expect(definerMigrationViolations(SQL_0266, 266)).toEqual([]);
    const rows = (await db.query<{ sig: string; cfg: string[] | null }>(
      `select p.oid::regprocedure::text as sig, p.proconfig as cfg from pg_proc p
        where p.pronamespace = 'public'::regnamespace and p.proname like 'rout_recovery_ceremony_%' and p.prosecdef`,
    )).rows;
    expect(rows.length).toBeGreaterThanOrEqual(7);
    for (const r of rows) expect(r.cfg, r.sig).toEqual(["search_path=pg_catalog, pg_temp"]);
  });

  it("a 2-of-4 save stores the card shard as version 2; only the v2 reads return it", async () => {
    await put9(ALICE, shard("C"));
    const v2 = await asApp<{ card_shard: string; ceremony_version: number }>(ALICE, "select card_shard, ceremony_version from public.rout_recovery_ceremony_get_v2()");
    expect(v2).toEqual([{ card_shard: shard("C"), ceremony_version: 2 }]);
    const status = await asApp<{ ceremony_version: number }>(ALICE, "select ceremony_version from public.rout_recovery_ceremony_status_v2()");
    expect(status).toEqual([{ ceremony_version: 2 }]);
    // Code at schema 0264 must never receive a version 2 ceremony it would read as 2-of-3.
    expect(await asApp(ALICE, "select * from public.rout_recovery_ceremony_get()")).toEqual([]);
    expect(await asApp(ALICE, "select * from public.rout_recovery_ceremony_status()")).toEqual([]);
    // Another member sees nothing.
    expect(await asApp(BOB, "select * from public.rout_recovery_ceremony_get_v2()")).toEqual([]);
  });

  it("the 8-argument save writes a clean version 1 row (card shard cleared)", async () => {
    await put8(ALICE);
    const v = await asApp<{ card_shard: string | null; ceremony_version: number }>(ALICE, "select card_shard, ceremony_version from public.rout_recovery_ceremony_get_v2()");
    expect(v).toEqual([{ card_shard: null, ceremony_version: 1 }]);
    expect(await asApp(ALICE, "select ceremony_id from public.rout_recovery_ceremony_get()")).toEqual([{ ceremony_id: CEREMONY }]);
  });

  it("refuses a 9-argument save without card shard, with a duplicated shard, or without member context", async () => {
    await expect(put9(ALICE, null)).rejects.toThrow(/card shard required/);
    await expect(put9(ALICE, shard("D"))).rejects.toThrow(/recovery_ceremonies_card_distinct/);
    await expect(put9("", shard("C"))).rejects.toThrow(/no member context/);
    await expect(put9(ALICE, "not base64!")).rejects.toThrow();
  });

  it("the table stays closed to rout_app, and PUBLIC executes none of the functions", async () => {
    await expect(asApp(ALICE, "select * from public.recovery_ceremonies")).rejects.toThrow(/permission denied/);
    const r = (await db.query<{ sig: string; pub: boolean; app: boolean }>(
      `select p.oid::regprocedure::text as sig,
              has_function_privilege('public', p.oid, 'execute') as pub,
              has_function_privilege('rout_app', p.oid, 'execute') as app
         from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname like 'rout_recovery_ceremony_%'`,
    )).rows;
    for (const f of r) {
      expect(f.pub, f.sig).toBe(false);
      expect(f.app, f.sig).toBe(true);
    }
  });

  it("is idempotent: applying 0266 again changes nothing", async () => {
    await db.exec(`begin;\n${SQL_0266}\n;commit;`);
    await put9(BOB, shard("C"));
    expect(await asApp(BOB, "select ceremony_version from public.rout_recovery_ceremony_get_v2()")).toEqual([{ ceremony_version: 2 }]);
  });
});
