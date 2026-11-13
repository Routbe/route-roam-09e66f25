/**
 * Passkey-only cutover (db/0207). A Better Auth user WITHOUT a passkey is
 * quarantined: no session of theirs is honoured. Recovery is out-of-band:
 * the member files a request, an admin verifies them through a trusted channel
 * and approves, which mints a single-use binding token (SHA-256 stored, 24 h)
 * used to register the first passkey (`rq.<token>` WebAuthn context).
 *
 * public.auth_recovery_requests is reached ONLY through the rout_recovery_*
 * SECURITY DEFINER functions (db/0263). The database decides who may do what:
 * filing answers the same for every input, list/approve/deny need a full admin
 * with two-factor on taken from rout.current_user_id (the request context set
 * by the auth middleware), and the raw token never leaves this process.
 */
import { currentDbUserId, sql } from "@/lib/neon";

const enc = new TextEncoder();
const CACHE_MS = 30_000;
const TOKEN_RE = /^[0-9a-f]{64}$/;
const passkeyCache = new Map<string, { has: boolean; at: number }>();

export async function sha256Hex(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** True when the Better Auth user owns at least one passkey (briefly cached). */
export async function authUserHasPasskey(authUserId: string): Promise<boolean> {
  const hit = passkeyCache.get(authUserId);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.has;
  const rows = (await sql`select exists (select 1 from neon_auth.passkey where "userId"::text = ${authUserId}) as has`) as Array<{ has: boolean }>;
  const has = rows[0]?.has === true;
  passkeyCache.set(authUserId, { has, at: Date.now() });
  return has;
}

export function forgetPasskeyCache(authUserId: string) {
  passkeyCache.delete(authUserId);
}

/**
 * The deciding admin is taken by the database from the request context, never
 * from a parameter. Refuse when the caller's id and that context disagree, so
 * a call outside the admin's own request can never act in someone's name.
 */
function assertAdminContext(adminUserId: string) {
  if (currentDbUserId() !== adminUserId) throw Object.assign(new Error("Forbidden"), { statusCode: 403 });
}

/** Files a recovery request. Always resolves the same way (no account enumeration). */
export async function fileRecoveryRequest(email: string, note: string | null): Promise<void> {
  await sql`select public.rout_recovery_request_file(${email}, ${note})`;
}

export type RecoveryRequestRow = {
  id: string;
  email: string;
  note: string | null;
  status: string;
  created_at: string;
  token_expires_at: string | null;
};

export async function listRecoveryRequests(adminUserId: string): Promise<RecoveryRequestRow[]> {
  assertAdminContext(adminUserId);
  return (await sql`select id::text as id, email, note, status, created_at::text as created_at,
      token_expires_at::text as token_expires_at
    from public.rout_recovery_requests_list()`) as RecoveryRequestRow[];
}

/** Approves after out-of-band verification. Returns the raw token ONCE (only its hash reaches the database). */
export async function approveRecoveryRequest(id: string, adminUserId: string, decisionNote: string | null): Promise<string | null> {
  assertAdminContext(adminUserId);
  const raw = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
  const rows = (await sql`select public.rout_recovery_request_approve(${id}::uuid, ${decisionNote}, ${await sha256Hex(raw)}) as ok`) as Array<{ ok: boolean }>;
  return rows[0]?.ok === true ? raw : null;
}

export async function denyRecoveryRequest(id: string, adminUserId: string, decisionNote: string | null): Promise<boolean> {
  assertAdminContext(adminUserId);
  const rows = (await sql`select public.rout_recovery_request_deny(${id}::uuid, ${decisionNote}) as ok`) as Array<{ ok: boolean }>;
  return rows[0]?.ok === true;
}

/** Looks up an approved, unexpired binding token (no consumption). */
export async function resolveBindingToken(raw: string): Promise<{ authUserId: string; email: string } | null> {
  if (!TOKEN_RE.test(raw)) return null;
  const rows = (await sql`select auth_user_id, email from public.rout_recovery_token_resolve(${await sha256Hex(raw)})`) as Array<{
    auth_user_id: string;
    email: string;
  }>;
  const r = rows[0];
  return r ? { authUserId: r.auth_user_id, email: r.email } : null;
}

/** Atomically burns the token when the first passkey is bound. */
export async function consumeBindingToken(raw: string): Promise<string | null> {
  if (!TOKEN_RE.test(raw)) return null;
  const rows = (await sql`select public.rout_recovery_token_consume(${await sha256Hex(raw)}) as auth_user_id`) as Array<{
    auth_user_id: string | null;
  }>;
  const id = rows[0]?.auth_user_id ?? null;
  if (id) forgetPasskeyCache(id);
  return id;
}
