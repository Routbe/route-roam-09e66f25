// @vitest-environment node
/**
 * App code for account recovery (quarantine.server.ts) against a full replay of
 * db/, including the CONTRACT 0264: every call runs as rout_app
 * inside the caller's transaction context, exactly as src/lib/neon.ts does, and
 * rout_app has no table rights left. Proves the app needs only the
 * rout_recovery_* functions and that the admin/2FA rule holds end to end.
 */
import { PGlite } from "@electric-sql/pglite";
import { AsyncLocalStorage } from "node:async_hooks";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { listMigrationFiles, planMigrations } from "../../../scripts/migration-plan";

const ROOT = join(__dirname, "..", "..", "..");
const DB_DIR = join(ROOT, "db");

const ADMIN = "00000000-0000-4000-8000-0000000000a1";
const ADMIN_NO_2FA = "00000000-0000-4000-8000-0000000000a2";
const MEMBER = "00000000-0000-4000-8000-0000000000b1";
const AUTH_ADMIN = "10000000-0000-4000-8000-0000000000a1";
const AUTH_ADMIN_NO_2FA = "10000000-0000-4000-8000-0000000000a2";
const AUTH_MEMBER = "10000000-0000-4000-8000-0000000000b1";
const AUTH_LOCKED = "10000000-0000-4000-8000-0000000000c1";
const AUTH_SAFE = "10000000-0000-4000-8000-0000000000c2";

let db: PGlite;
const ctx = new AsyncLocalStorage<{ userId: string }>();

vi.mock("@/lib/neon", () => {
  const run = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.reduce((acc, s, i) => acc + s + (i < values.length ? `$${i + 1}` : ""), "");
    await db.exec("begin");
    try {
      await db.exec("set local role rout_app");
      await db.query("select set_config('rout.current_user_id', $1, true)", [ctx.getStore()?.userId ?? ""]);
      const r = await db.query(text, values);
      await db.exec("commit");
      return r.rows;
    } catch (e) {
      await db.exec("rollback");
      throw e;
    }
  };
  return { sql: run, currentDbUserId: () => ctx.getStore()?.userId ?? null };
});

const as = <T>(userId: string, fn: () => Promise<T>) => ctx.run({ userId }, fn);
const q = await import("./quarantine.server");

beforeAll(async () => {
  const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
  const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
  db = new PGlite({ extensions: { pgcrypto, btree_gist } });
  for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
    if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
  }
  const authUser = 'insert into neon_auth."user"(id, name, email, "emailVerified", "createdAt", "updatedAt", "twoFactorEnabled") values ($1, $2, $3, true, now(), now(), $4)';
  await db.query(authUser, [AUTH_ADMIN, "Admin", "admin@example.test", true]);
  await db.query(authUser, [AUTH_ADMIN_NO_2FA, "Admin2", "admin2@example.test", false]);
  await db.query(authUser, [AUTH_MEMBER, "Member", "member@example.test", true]);
  await db.query(authUser, [AUTH_LOCKED, "Locked", "locked@example.test", false]);
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

describe("recovery app code after the 0264 contract", () => {
  it("rout_app has no table rights left on auth_recovery_requests", async () => {
    const r = await db.query<{ n: number }>(
      "select count(*)::int as n from information_schema.role_table_grants where grantee = 'rout_app' and table_schema = 'public' and table_name = 'auth_recovery_requests'",
    );
    expect(r.rows[0]?.n).toBe(0);
  });

  it("filing stores a request only for an account without a passkey and never throws", async () => {
    await q.fileRecoveryRequest("nobody@example.test", null);
    await q.fileRecoveryRequest("safe@example.test", "lost phone");
    await q.fileRecoveryRequest("not-an-email", null);
    await q.fileRecoveryRequest("  LOCKED@example.test ", "lost phone");
    await q.fileRecoveryRequest("locked@example.test", "again");
    const rows = (await db.query<{ email: string; status: string }>("select email, status from public.auth_recovery_requests")).rows;
    expect(rows).toEqual([{ email: "locked@example.test", status: "pending" }]);
  });

  it("only a full admin with two-factor on can list or decide", async () => {
    await expect(as(MEMBER, () => q.listRecoveryRequests(MEMBER))).rejects.toThrow(/forbidden/i);
    await expect(as(ADMIN_NO_2FA, () => q.listRecoveryRequests(ADMIN_NO_2FA))).rejects.toThrow(/forbidden/i);
    const [row] = await as(ADMIN, () => q.listRecoveryRequests(ADMIN));
    expect(row?.email).toBe("locked@example.test");
    await expect(as(ADMIN_NO_2FA, () => q.approveRecoveryRequest(row!.id, ADMIN_NO_2FA, "checked by phone"))).rejects.toThrow(/forbidden/i);
  });

  it("refuses to act for an admin id that is not the request's own caller", async () => {
    const [row] = await as(ADMIN, () => q.listRecoveryRequests(ADMIN));
    await expect(as(MEMBER, () => q.approveRecoveryRequest(row!.id, ADMIN, "checked"))).rejects.toThrow(/forbidden/i);
    await expect(q.denyRecoveryRequest(row!.id, ADMIN, null)).rejects.toThrow(/forbidden/i);
  });

  it("approve needs a verification note, stores only the hash and the token binds exactly once", async () => {
    const [row] = await as(ADMIN, () => q.listRecoveryRequests(ADMIN));
    expect(await as(ADMIN, () => q.approveRecoveryRequest(row!.id, ADMIN, null))).toBeNull();
    const token = await as(ADMIN, () => q.approveRecoveryRequest(row!.id, ADMIN, "checked by video call"));
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    const stored = (await db.query<{ token_hash: string; decided_by: string }>("select token_hash, decided_by::text from public.auth_recovery_requests")).rows[0];
    expect(stored?.token_hash).toBe(await q.sha256Hex(token!));
    expect(stored?.decided_by).toBe(ADMIN);
    expect(await q.resolveBindingToken(token!)).toEqual({ authUserId: AUTH_LOCKED, email: "locked@example.test" });
    expect(await q.consumeBindingToken(token!)).toBe(AUTH_LOCKED);
    expect(await q.consumeBindingToken(token!)).toBeNull();
    expect(await q.resolveBindingToken(token!)).toBeNull();
  });

  it("an admin can deny a pending request", async () => {
    await db.query("delete from public.auth_recovery_requests");
    await q.fileRecoveryRequest("locked@example.test", null);
    const [row] = await as(ADMIN, () => q.listRecoveryRequests(ADMIN));
    expect(await as(ADMIN, () => q.denyRecoveryRequest(row!.id, ADMIN, "could not verify"))).toBe(true);
    expect(await as(ADMIN, () => q.denyRecoveryRequest(row!.id, ADMIN, "again"))).toBe(false);
  });
});
