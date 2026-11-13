// @vitest-environment node
/**
 * db/0263: account recovery requests only through rout_recovery_* functions.
 * Replays db/ on PGlite and runs every function as rout_app with a real
 * transaction context: filing never shows whether an account exists, only a
 * full admin with two-factor on can list, approve or deny (the deciding admin
 * comes from the context), the binding token is known to the database only by
 * its SHA-256 and works exactly once within 24 hours.
 */
import { PGlite } from "@electric-sql/pglite";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { listMigrationFiles, planMigrations } from "../../scripts/migration-plan";

const ROOT = join(__dirname, "..", "..");
const DB_DIR = join(ROOT, "db");
const CONTRACT_FILE = "0264_recovery_requests_contract.sql";

const ADMIN = "00000000-0000-4000-8000-0000000000a1";
const ADMIN_NO_2FA = "00000000-0000-4000-8000-0000000000a2";
const MEMBER = "00000000-0000-4000-8000-0000000000b1";
const AUTH_ADMIN = "10000000-0000-4000-8000-0000000000a1";
const AUTH_ADMIN_NO_2FA = "10000000-0000-4000-8000-0000000000a2";
const AUTH_MEMBER = "10000000-0000-4000-8000-0000000000b1";
const AUTH_LOCKED = "10000000-0000-4000-8000-0000000000c1"; // no passkey: quarantined
const AUTH_SAFE = "10000000-0000-4000-8000-0000000000c2"; // has a passkey

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const freshToken = () => randomBytes(32).toString("hex");

let db: PGlite;

/** One statement as rout_app, with the caller in the transaction context (as src/lib/neon.ts does). */
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

const requests = async () =>
  (await db.query<{ email: string; status: string; decided_by: string | null; token_hash: string | null }>(
    "select email, status, decided_by::text, token_hash from public.auth_recovery_requests order by created_at",
  )).rows;

beforeAll(async () => {
  const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
  const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
  db = new PGlite({ extensions: { pgcrypto, btree_gist } });
  // Up to 0263 only: the CONTRACT 0264 is applied in the last test, on top of this state.
  for (const step of planMigrations(listMigrationFiles(DB_DIR).filter((f) => f !== CONTRACT_FILE), new Set())) {
    if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
  }
  const authUser = 'insert into neon_auth."user"(id, name, email, "emailVerified", "createdAt", "updatedAt", "twoFactorEnabled") values ($1, $2, $3, true, now(), now(), $4)';
  await db.query(authUser, [AUTH_ADMIN, "Admin", "admin@example.test", true]);
  await db.query(authUser, [AUTH_ADMIN_NO_2FA, "Admin2", "admin2@example.test", false]);
  await db.query(authUser, [AUTH_MEMBER, "Member", "member@example.test", true]);
  await db.query(authUser, [AUTH_LOCKED, "Locked", "Locked@Example.test", false]);
  await db.query(authUser, [AUTH_SAFE, "Safe", "safe@example.test", false]);
  await db.query(
    `insert into neon_auth.passkey (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp") values ('pk1', 'k', $1, 'c', 0, 'singleDevice', false)`,
    [AUTH_SAFE],
  );
  const user = "insert into public.users (id, email, auth_user_id) values ($1, $2, $3)";
  await db.query(user, [ADMIN, "admin@example.test", AUTH_ADMIN]);
  await db.query(user, [ADMIN_NO_2FA, "admin2@example.test", AUTH_ADMIN_NO_2FA]);
  await db.query(user, [MEMBER, "member@example.test", AUTH_MEMBER]);
  await db.query("insert into public.user_roles (user_id, role) values ($1, 'admin'), ($2, 'admin')", [ADMIN, ADMIN_NO_2FA]);
}, 300_000);

afterAll(async () => {
  await db?.close();
});

describe("0263 recovery request entry points", () => {
  it("files only for an existing account without a passkey and answers every case the same way", async () => {
    const file = (email: string) => asApp<{ r: string | null }>(null, "select public.rout_recovery_request_file($1, $2)::text as r", [email, " please help "]);
    const answers = [
      await file("  locked@EXAMPLE.test "),
      await file("locked@example.test"), // second open request for the same account
      await file("nobody@example.test"),
      await file("safe@example.test"), // already has a passkey
      await file("not an email"),
    ];
    for (const a of answers) expect(a).toEqual([{ r: "" }]);
    const rows = await requests();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ email: "locked@example.test", status: "pending", decided_by: null, token_hash: null });
  });

  it("lets only a full admin with two-factor on see or decide requests", async () => {
    const [{ id }] = await asApp<{ id: string }>(ADMIN, "select id::text from public.rout_recovery_requests_list()");
    for (const caller of [null, MEMBER, ADMIN_NO_2FA]) {
      await expect(asApp(caller, "select * from public.rout_recovery_requests_list()")).rejects.toThrow(/forbidden/);
      await expect(asApp(caller, "select public.rout_recovery_request_approve($1, 'checked by phone', $2)", [id, sha(freshToken())])).rejects.toThrow(/forbidden/);
      await expect(asApp(caller, "select public.rout_recovery_request_deny($1, null)", [id])).rejects.toThrow(/forbidden/);
    }
    expect((await requests())[0]!.status).toBe("pending");
  });

  it("requires a verification note and a SHA-256, records the admin from the context and logs the decision", async () => {
    const [{ id }] = await asApp<{ id: string }>(ADMIN, "select id::text from public.rout_recovery_requests_list()");
    const approve = (note: string | null, hash: string) =>
      asApp<{ ok: boolean }>(ADMIN, "select public.rout_recovery_request_approve($1, $2, $3) as ok", [id, note, hash]);
    expect(await approve("   ", sha(freshToken()))).toEqual([{ ok: false }]);
    expect(await approve("checked by phone", "not-a-hash")).toEqual([{ ok: false }]);

    const token = freshToken();
    expect(await approve("checked by phone", sha(token))).toEqual([{ ok: true }]);
    expect(await approve("checked by phone", sha(freshToken()))).toEqual([{ ok: false }]); // no longer pending
    const [row] = await requests();
    expect(row).toMatchObject({ status: "approved", decided_by: ADMIN, token_hash: sha(token) });
    const log = await db.query<{ admin_id: string; action: string }>(
      "select admin_id::text, action from public.admin_audit_log where target_label = $1", [`recovery:${id}`]);
    expect(log.rows).toEqual([{ admin_id: ADMIN, action: "RECOVERY_REQUEST_APPROVED" }]);

    // The token works once: resolve does not use it, consume burns it.
    const resolve = (h: string) => asApp<{ auth_user_id: string; email: string }>(null, "select * from public.rout_recovery_token_resolve($1)", [h]);
    const consume = (h: string) => asApp<{ u: string | null }>(null, "select public.rout_recovery_token_consume($1) as u", [h]);
    expect(await resolve(sha(token))).toEqual([{ auth_user_id: AUTH_LOCKED, email: "locked@example.test" }]);
    expect(await resolve(sha(freshToken()))).toEqual([]);
    expect(await resolve(token)).toEqual([]); // the raw token is not a key
    expect(await consume(sha(token))).toEqual([{ u: AUTH_LOCKED }]);
    expect(await consume(sha(token))).toEqual([{ u: null }]);
    expect(await resolve(sha(token))).toEqual([]);
    expect((await requests())[0]).toMatchObject({ status: "bound", token_hash: null });
  });

  it("expires an approved token after 24 hours and lets an admin deny an approved request", async () => {
    await asApp(null, "select public.rout_recovery_request_file('locked@example.test', null)");
    const list = await asApp<{ id: string; status: string }>(ADMIN, "select id::text, status from public.rout_recovery_requests_list()");
    const open = list.find((r) => r.status === "pending")!;
    const token = freshToken();
    await asApp(ADMIN, "select public.rout_recovery_request_approve($1, 'video call', $2)", [open.id, sha(token)]);
    await db.query("update public.auth_recovery_requests set token_expires_at = now() - interval '1 minute' where id = $1", [open.id]);
    expect(await asApp(null, "select public.rout_recovery_token_consume($1) as u", [sha(token)])).toEqual([{ u: null }]);
    const after = await asApp<{ id: string; status: string }>(ADMIN, "select id::text, status from public.rout_recovery_requests_list()");
    expect(after.find((r) => r.id === open.id)!.status).toBe("expired");

    await asApp(null, "select public.rout_recovery_request_file('locked@example.test', null)");
    const again = (await asApp<{ id: string; status: string }>(ADMIN, "select id::text, status from public.rout_recovery_requests_list()")).find((r) => r.status === "pending")!;
    const t2 = freshToken();
    await asApp(ADMIN, "select public.rout_recovery_request_approve($1, 'in person', $2)", [again.id, sha(t2)]);
    expect(await asApp(ADMIN, "select public.rout_recovery_request_deny($1, 'wrong person') as ok", [again.id])).toEqual([{ ok: true }]);
    expect(await asApp(null, "select public.rout_recovery_token_consume($1) as u", [sha(t2)])).toEqual([{ u: null }]);
  });

  it("keeps the internal helper and the table closed to rout_app as far as this migration goes", async () => {
    const can = async (fn: string) =>
      (await db.query<{ ok: boolean }>("select has_function_privilege('rout_app', $1, 'execute') as ok", [fn])).rows[0]!.ok;
    expect(await can("public.rout_recovery_caller_admin()")).toBe(false);
    for (const fn of [
      "public.rout_recovery_request_file(text, text)", "public.rout_recovery_requests_list()",
      "public.rout_recovery_request_approve(uuid, text, text)", "public.rout_recovery_request_deny(uuid, text)",
      "public.rout_recovery_token_resolve(text)", "public.rout_recovery_token_consume(text)",
    ]) {
      expect(await can(fn), fn).toBe(true);
      const pub = await db.query<{ n: number }>(
        "select count(*)::int as n from aclexplode((select proacl from pg_proc where oid = $1::regprocedure)) a where a.grantee = 0", [fn]);
      expect(pub.rows[0]!.n, `${fn} PUBLIC`).toBe(0);
    }
    // Direct table access still finds nothing under RLS (why 0263 exists).
    expect(await asApp(ADMIN, "select count(*)::int as n from public.auth_recovery_requests")).toEqual([{ n: 0 }]);
  });

  it("0264 then removes every table right of rout_app and the functions keep working", async () => {
    const contract = readFileSync(join(DB_DIR, CONTRACT_FILE), "utf8");
    expect(createHash("sha256").update(contract).digest("hex")).toBe("2790c4fec5a42e94416cf86787836352fce510975f2197760ae9d814387b5ec5");
    await db.exec(`begin;\n${contract}\n;commit;`);
    for (const p of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
      const r = await db.query<{ ok: boolean }>("select has_table_privilege('rout_app', 'public.auth_recovery_requests', $1) as ok", [p]);
      expect(r.rows[0]!.ok, p).toBe(false);
    }
    await expect(asApp(ADMIN, "select count(*) from public.auth_recovery_requests")).rejects.toThrow(/permission denied/);
    await asApp(null, "select public.rout_recovery_request_file('locked@example.test', null)");
    const list = await asApp<{ status: string }>(ADMIN, "select status from public.rout_recovery_requests_list()");
    expect(list.some((r) => r.status === "pending")).toBe(true);
    await expect(db.exec(`begin;\n${contract}\n;commit;`)).resolves.toBeDefined();
  });
});
