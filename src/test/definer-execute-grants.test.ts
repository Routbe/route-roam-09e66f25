// @vitest-environment node
/**
 * 0259: internal SECURITY DEFINER helpers are callable only by their owner, and
 * execute_account_merge is not callable by PUBLIC. Replays db/, recreates the
 * grants Neon's default privileges had left (rout_app on every helper, PUBLIC
 * on the merge), applies 0259 and checks each grant per function.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";

const DB_DIR = join(__dirname, "..", "..", "db");
const FILE = "0259_definer_execute_least_privilege.sql";
const HELPERS = [
  "public.rout_audit_insert(uuid, text, text, uuid, text, text)",
  "public.rout_phone_mark_verified(public.phone_otp_codes)",
  "public.rout_psp_public_owner(uuid)",
  "public.rout_qa_owner(text, text)",
  "public.feedback_form_is_public(public.feedback_forms)",
  "public.profile_event_is_public(public.profile_events)",
  "public.rout_physical_key_audit()",
];
const MERGE = "public.execute_account_merge(text, text, text, text)";

describe("0259 removes direct execute on internal definer helpers", () => {
  it("leaves rout_app only its entry points and nobody else on the merge", async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
    const can = async (role: string, fn: string) =>
      (await db.query<{ ok: boolean }>(`select has_function_privilege($1, $2, 'execute') as ok`, [role, fn])).rows[0]!.ok;
    const publicOnMerge = async () =>
      (await db.query<{ n: number }>(
        `select count(*)::int as n from aclexplode((select proacl from pg_proc where oid = $1::regprocedure)) a where a.grantee = 0`,
        [MERGE],
      )).rows[0]!.n > 0;
    try {
      for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
        if (step.action === "run" && step.file !== FILE) await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
      }
      // The state found on Neon before 0259.
      for (const f of HELPERS) await db.exec(`grant execute on function ${f} to rout_app`);
      await db.exec(`grant execute on function public.workspace_may_drop_suffix(text, uuid) to rout_app`);
      await db.exec(`grant rout_merge_executor to current_user; grant execute on function ${MERGE} to public; revoke rout_merge_executor from current_user;`);
      for (const f of HELPERS) expect(await can("rout_app", f), f).toBe(true);
      expect(await publicOnMerge()).toBe(true);

      await db.exec(`begin;\n${readFileSync(join(DB_DIR, FILE), "utf8")}\n;commit;`);

      for (const f of HELPERS) expect(await can("rout_app", f), f).toBe(false);
      expect(await publicOnMerge()).toBe(false);
      expect(await can("rout_app", MERGE)).toBe(true);
      expect(await can("rout_app", "public.workspace_may_drop_suffix(text, uuid)")).toBe(true);
      const member = await db.query(`select 1 from pg_auth_members m join pg_roles r on r.oid = m.roleid where r.rolname = 'rout_merge_executor' and m.member = (select oid from pg_roles where rolname = current_user)`);
      expect(member.rows).toHaveLength(0);
      // Entry points that use the helpers still run them as the owner.
      await expect(db.exec(`begin;\n${readFileSync(join(DB_DIR, FILE), "utf8")}\n;commit;`)).resolves.toBeDefined();
    } finally {
      await db.close();
    }
  }, 300_000);
});

describe("a fresh replay of db/ has Neon's function rights (0260, 0261)", () => {
  it("keeps PUBLIC off owner-only functions, gives rout_app the helpers its policies and triggers call, and not the orphaned definers", async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
    const can = async (role: string, fn: string) =>
      (await db.query<{ ok: boolean }>(`select has_function_privilege($1, $2, 'execute') as ok`, [role, fn])).rows[0]!.ok;
    try {
      for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
        if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
      }
      await db.exec("create role rout_check_other nologin");
      // Money and account functions: never callable by an arbitrary role.
      for (const f of [
        "public.wallet_credit(uuid, integer, text, text, text)",
        "public.wallet_debit(uuid, integer, text, text)",
        "public.delete_account()",
        "public.signin_guard_record(text, boolean)",
        "public.save_profile_draft(uuid, text, jsonb, bigint)",
      ]) {
        expect(await can("rout_check_other", f), f).toBe(false);
        expect(await can("rout_app", f), f).toBe(true);
      }
      // Policy and invoker-trigger helpers the app role must reach.
      for (const f of [
        "public.rout_current_user_id()",
        "public.current_app_user_id()",
        "public.workspace_may_drop_suffix(text, uuid)",
        "public.assert_handle_namespace_free(text, uuid)",
      ]) expect(await can("rout_app", f), f).toBe(true);
      const seq = await db.query<{ ok: boolean }>(`select has_sequence_privilege('rout_app', 'public.calendar_events_id_seq', 'usage') as ok`);
      expect(seq.rows[0]!.ok).toBe(true);
      // Orphaned definers (0261).
      for (const f of ["public.seed_demo_content(uuid)", "public.grant_signup_badges(uuid)", "public.generate_unique_handle(text)"]) {
        expect(await can("rout_app", f), f).toBe(false);
        expect(await can("rout_check_other", f), f).toBe(false);
      }
    } finally {
      await db.close();
    }
  }, 300_000);
});
