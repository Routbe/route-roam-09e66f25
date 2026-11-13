// @vitest-environment node
/**
 * db/0262 (live on Neon since 2026-11-13): rout_app keeps on the 17 tables, views and
 * sequences only the rights app code uses. Replays db/ up to 0261, recreates the extra
 * rights found on Neon on 2026-11-13, applies 0262 and checks every right;
 * card status changes must still work and card keys must not be writable.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";

const ROOT = join(__dirname, "..", "..");
const DB_DIR = join(ROOT, "db");
const CONTRACT_FILE = "0262_table_rights_least_privilege.sql";
const CONTRACT = readFileSync(join(DB_DIR, CONTRACT_FILE), "utf8");

/** What Neon had beyond db/ (table-level, as found in pg_class.relacl). */
const NEON_EXTRAS = [
  "grant insert, update, delete on public.agent_audit_logs to rout_app",
  "grant insert on public.app_issued_credentials to rout_app",
  "grant delete on public.auth_recovery_requests to rout_app",
  "grant insert, update, delete on public.grid_items to rout_app",
  "grant insert, update, delete on public.ingest_tokens to rout_app",
  "grant insert, update, delete on public.identity_relay_merge_archive to rout_app",
  "grant insert, update, delete on public.physical_key_events to rout_app",
  "grant update, delete on public.physical_keys to rout_app",
  "grant delete on public.platform_feature_switches to rout_app",
  "grant insert, update on public.profile_subscribers to rout_app",
  "grant select, insert, update, delete on public.qa_guest_trust to rout_app",
  "grant delete on public.rout_card_generations to rout_app",
  "grant insert, update, delete on public.wallet_passes to rout_app",
  "grant select, usage on sequence public.audit_logs_id_seq, public.forwarding_confirmation_sends_id_seq, public.physical_key_events_id_seq, public.qa_trust_charges_id_seq to rout_app",
];

const KEEP: Record<string, string[]> = {
  "public.agent_audit_logs": ["SELECT"],
  "public.app_issued_credentials": ["SELECT", "DELETE"],
  "public.auth_recovery_requests": ["SELECT", "INSERT", "UPDATE"],
  "public.grid_items": ["SELECT"],
  "public.ingest_tokens": ["SELECT"],
  "public.identity_relay_merge_archive": ["SELECT"],
  "public.physical_key_events": ["SELECT"],
  "public.physical_keys": ["SELECT"],
  "public.platform_feature_switches": ["SELECT", "INSERT", "UPDATE"],
  "public.profile_subscribers": ["SELECT", "DELETE"],
  "public.qa_guest_trust": [],
  "public.rout_card_generations": ["SELECT", "INSERT", "UPDATE"],
  "public.wallet_passes": ["SELECT"],
};

/** Replays db/ before 0262, so the extra Neon rights can be recreated first. */
async function replay() {
  const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
  const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
  const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
  // Strictly the files before 0262 (later ones, such as the 0264 contract, did not exist yet).
  const all = listMigrationFiles(DB_DIR);
  const before = all.slice(0, all.indexOf(CONTRACT_FILE));
  expect(before.length).toBeGreaterThan(0);
  for (const step of planMigrations(before, new Set())) {
    if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
  }
  return db;
}

async function tableRights(db: PGlite, tbl: string): Promise<string[]> {
  const out: string[] = [];
  for (const p of ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
    const r = await db.query<{ ok: boolean }>(`select has_table_privilege('rout_app', $1, $2) as ok`, [tbl, p]);
    if (r.rows[0]!.ok) out.push(p);
  }
  return out;
}

describe("0262 keeps rout_app to the table rights the app uses", () => {
  it("removes Neon's extra rights, keeps card status changes and closes card keys", async () => {
    const db = await replay();
    try {
      for (const g of NEON_EXTRAS) await db.exec(g);
      expect(await tableRights(db, "public.qa_guest_trust")).toEqual(["SELECT", "INSERT", "UPDATE", "DELETE"]);

      await db.exec(`begin;\n${CONTRACT}\n;commit;`);
      for (const [tbl, keep] of Object.entries(KEEP)) expect(await tableRights(db, tbl), tbl).toEqual(keep);
      for (const seq of ["audit_logs_id_seq", "forwarding_confirmation_sends_id_seq", "physical_key_events_id_seq", "qa_trust_charges_id_seq"]) {
        const r = await db.query<{ ok: boolean }>(`select has_sequence_privilege('rout_app', $1, 'USAGE') or has_sequence_privilege('rout_app', $1, 'SELECT') as ok`, [`public.${seq}`]);
        expect(r.rows[0]!.ok, seq).toBe(false);
      }

      // The freeze/block/replace paths in card-freeze.server.ts still pass the rights check.
      await expect(db.exec(`begin; set local role rout_app; update public.physical_keys set status = 'frozen' where false; commit;`)).resolves.toBeDefined();
      await expect(db.exec(`begin; set local role rout_app; update public.physical_keys set public_key = null where false; commit;`)).rejects.toThrow(/permission denied/);
      await db.exec("rollback").catch(() => undefined);
      await expect(db.exec(`begin; set local role rout_app; delete from public.wallet_passes where false; commit;`)).rejects.toThrow(/permission denied/);
      await db.exec("rollback").catch(() => undefined);

      // Running it again changes nothing and its own checks still pass.
      await expect(db.exec(`begin;\n${CONTRACT}\n;commit;`)).resolves.toBeDefined();
    } finally {
      await db.close();
    }
  }, 300_000);

  it("keeps the exact checksum Neon recorded", async () => {
    const { checksumOf } = await import("../../scripts/migration-plan");
    expect(checksumOf(CONTRACT)).toBe("a48f23389624a5062f805166964323de4208dfa168c1cdd07cd793be073131f4");
  });

  it("is safe on a fresh replay of db/ that never had the extra rights", async () => {
    const db = await replay();
    try {
      await expect(db.exec(`begin;\n${CONTRACT}\n;commit;`)).resolves.toBeDefined();
      for (const [tbl, keep] of Object.entries(KEEP)) expect(await tableRights(db, tbl), tbl).toEqual(keep);
    } finally {
      await db.close();
    }
  }, 300_000);
});
