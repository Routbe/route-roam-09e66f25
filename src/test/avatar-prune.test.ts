// @vitest-environment node
/**
 * db/0252 over the real SQL (PGlite, as rout_app): uploads are pruned per member
 * and prefix to the newest 3, but a photo still used as a workspace logo, profile
 * photo or draft photo is never removed, and another member's uploads are never touched.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ALICE = "00000000-0000-4000-8000-00000000000a";
const BOB = "00000000-0000-4000-8000-00000000000b";
let db: PGlite;

const url = (path: string) => `/api/public/avatar?path=${encodeURIComponent(path)}`;

async function prune(user: string | null, prefix: string, keep = 3): Promise<number> {
  await db.query("select set_config('rout.current_user_id', $1, false)", [user ?? ""]);
  await db.exec("set role rout_app");
  try {
    return (await db.query<{ n: number }>("select public.rout_prune_avatar_uploads($1, $2) as n", [prefix, keep])).rows[0]!.n;
  } finally {
    await db.exec("reset role");
  }
}
async function upload(user: string, prefix: string, n: number): Promise<string> {
  const path = `${user}/${prefix}-${1_700_000_000_000 + n}.png`;
  await db.query(
    "insert into public.avatar_objects (path, user_id, content_type, data, created_at) values ($1, $2, 'image/png', 'x', now() + make_interval(secs => $3))",
    [path, user, n],
  );
  return path;
}
const paths = async (user: string) =>
  (await db.query<{ path: string }>("select path from public.avatar_objects where user_id = $1 order by path", [user])).rows.map((r) => r.path);

beforeAll(async () => {
  db = new PGlite();
  await db.exec(`create role rout_app;
    create function public.rout_current_user_id() returns uuid language sql stable
      as $$ select nullif(current_setting('rout.current_user_id', true), '')::uuid $$;
    create table public.avatar_objects (path text primary key, user_id uuid not null, content_type text not null, data text not null,
      created_at timestamptz not null default now());
    create table public.profiles (id uuid primary key, avatar_url text, favicon_url text);
    create table public.alias_profiles (user_id uuid primary key, avatar_url text, favicon_url text);
    create table public.profile_drafts (user_id uuid, space text, payload jsonb);
    create table public.workspaces (id uuid primary key default gen_random_uuid(), avatar_url text, public_profile jsonb not null default '{}');
    create table public.workspace_profile_drafts (workspace_id uuid primary key, payload jsonb);
    create table public.oauth_clients (id uuid primary key default gen_random_uuid(), logo_url text);
    alter table public.avatar_objects enable row level security;
    grant select, insert, update, delete on public.avatar_objects to rout_app;
    create policy rout_scope on public.avatar_objects to rout_app using (user_id = public.rout_current_user_id())
      with check (user_id = public.rout_current_user_id());`);
  await db.exec(readFileSync(new URL("../../db/0252_avatar_prune_in_use.sql", import.meta.url), "utf8"));
}, 30_000);
afterAll(async () => db?.close());

describe("photo cleanup keeps photos in use (db/0252)", () => {
  it("removes unused uploads beyond the newest 3", async () => {
    const all: string[] = [];
    for (let i = 1; i <= 5; i++) all.push(await upload(ALICE, "avatar", i));
    expect(await prune(ALICE, "avatar")).toBe(2);
    expect(await paths(ALICE)).toEqual(all.slice(2));
  });

  it("keeps the logo of workspace A when the member uploads logos for other workspaces", async () => {
    const logoA = await upload(ALICE, "workspace-logo", 10);
    await db.query("insert into public.workspaces (avatar_url) values ($1)", [url(logoA)]);
    const draftLogo = await upload(ALICE, "workspace-logo", 11);
    await db.query("insert into public.workspace_profile_drafts (workspace_id, payload) values (gen_random_uuid(), $1)", [
      JSON.stringify({ avatarUrl: url(draftLogo) }),
    ]);
    const unused = await upload(ALICE, "workspace-logo", 12);
    for (let i = 13; i <= 15; i++) await upload(ALICE, "workspace-logo", i);
    expect(await prune(ALICE, "workspace-logo")).toBe(1);
    const left = await paths(ALICE);
    expect(left).toContain(logoA);
    expect(left).toContain(draftLogo);
    expect(left).not.toContain(unused);
  });

  it("keeps an older photo that a profile still shows", async () => {
    const shown = await upload(BOB, "avatar", 20);
    await db.query("insert into public.profiles (id, avatar_url) values ($1, $2)", [BOB, url(shown)]);
    for (let i = 21; i <= 24; i++) await upload(BOB, "avatar", i);
    await prune(BOB, "avatar");
    expect(await paths(BOB)).toContain(shown);
  });

  it("never removes another member's uploads", async () => {
    const before = await paths(BOB);
    expect(await prune(ALICE, "avatar", 1)).toBeGreaterThanOrEqual(0);
    expect(await paths(BOB)).toEqual(before);
  });

  it("does nothing without a signed-in member or with an unknown prefix", async () => {
    for (let i = 30; i <= 34; i++) await upload(ALICE, "avatar", i);
    const before = await paths(ALICE);
    expect(await prune(null, "avatar")).toBe(0);
    expect(await prune(ALICE, "other")).toBe(0);
    expect(await paths(ALICE)).toEqual(before);
  });
});
