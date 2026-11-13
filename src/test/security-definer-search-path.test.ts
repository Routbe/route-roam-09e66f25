// @vitest-environment node
/**
 * Every SECURITY DEFINER function runs with search_path = pg_catalog, except
 * the shrinking list in scripts/security-definer-legacy.ts. Checked on the
 * committed schema snapshot (replayed from db/), on every migration file from
 * 0255 on, and on the guard both runners run inside each migration.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { listMigrationFiles, migrationNumber } from "../../scripts/migration-plan";
import { HARDENED_BY_MIGRATION, LEGACY_DEFINER_SEARCH_PATH, legacyAllowedAfter } from "../../scripts/security-definer-legacy";
import {
  definerFindings,
  definerGuardSql,
  definerKey,
  definerMigrationViolations,
  migrationDefinerViolations,
  pinnedAfter,
  guardedMigration,
  isSecurityDefinerDef,
  searchPathFromConfig,
  searchPathFromDef,
} from "../../scripts/security-definer-policy";

const DB_DIR = join(__dirname, "..", "..", "db");
type SnapshotFn = { schema: string; name: string; args: string; def: string };
const snapshot = JSON.parse(readFileSync(join(DB_DIR, "schema.snapshot.json"), "utf8")) as { functions: SnapshotFn[] };
const definers = snapshot.functions
  .filter((f) => isSecurityDefinerDef(f.def))
  .map((f) => ({ key: definerKey(f.schema, f.name, f.args), searchPath: searchPathFromDef(f.def) }));

/** Top-level argument count of a "(...)" list starting at `open` (nested parentheses and quotes skipped). */
function arityAt(src: string, open: number): number | null {
  let depth = 0;
  let commas = 0;
  let any = false;
  let quoted = false;
  for (let i = open; i < src.length; i++) {
    const c = src[i]!;
    if (c === "'") quoted = !quoted;
    if (quoted) continue;
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return any ? commas + 1 : 0;
    } else if (depth === 1) {
      if (c === ",") commas++;
      else if (!/\s/.test(c)) any = true;
    }
  }
  return null;
}
const argCount = (args: string) => (args.trim() === "" ? 0 : arityAt(`(${args})`, 0)!);

/** "schema.name/arity" of every function a set of migrations creates. */
function createdIn(files: string[]): Set<string> {
  const out = new Set<string>();
  for (const f of files) {
    const src = readFileSync(join(DB_DIR, f), "utf8");
    for (const m of src.matchAll(/create\s+(?:or\s+replace\s+)?function\s+(\w+)\.(\w+)\s*\(/gi)) {
      const n = arityAt(src, m.index! + m[0].length - 1);
      if (n !== null) out.add(`${m[1]}.${m[2]}/${n}`);
    }
  }
  return out;
}

/**
 * Functions first created after 0258 (born pinned, so 0258 never names them),
 * by name and argument count: a later migration that replaces a function 0258
 * already pinned (or adds a new overload next to it) must not move it out of,
 * or into, the 0258 set.
 */
const files = listMigrationFiles(DB_DIR);
const createdUpTo0258 = createdIn(files.filter((f) => migrationNumber(f) <= 258));
const bornAfter0258 = new Set([...createdIn(files.filter((f) => migrationNumber(f) > 258))].filter((k) => !createdUpTo0258.has(k)));
const definersUpTo0258 = snapshot.functions
  .filter((f) => isSecurityDefinerDef(f.def))
  .filter((f) => !bornAfter0258.has(`${f.schema}.${f.name}/${argCount(f.args)}`))
  .map((f) => ({ key: definerKey(f.schema, f.name, f.args), searchPath: searchPathFromDef(f.def) }));

const BATCH_1 = [
  "public.rout_card_design(s text)",
  "public.rout_card_frozen(s text)",
  "public.rout_card_generation(u uuid)",
  "public.rout_card_status_by_serial(s text)",
  "public.rout_card_status_by_hardware(hid uuid)",
  "public.rout_card_token_use(n text, exp timestamp with time zone)",
  "public.rout_hw_issue_challenge(hid uuid, nh text)",
  "public.rout_hw_consume_challenge(hid uuid, nh text)",
  "public.rout_hw_record_scan(hid uuid, ok boolean)",
  "public.rout_pair_factory_card(hid uuid, proof_hash text, serial text)",
  "public.rout_physical_key_audit()",
  "public.rout_ephemeral_vault_create(p_vault_id uuid, p_key_hash text, p_vault_hash text, p_payload text)",
  "public.rout_ephemeral_vault_read(p_vault_id uuid)",
  "public.rout_ephemeral_vault_commit(p_vault_id uuid, p_vault_hash text, p_name text, p_slug text, p_blob text, p_key_id text)",
  "public.rout_purge_expired_ephemeral_vaults()",
  "public.signin_guard_status(_identity_hash text)",
  "public.signin_guard_record(_identity_hash text, _success boolean)",
  "public.rout_resolve_account(p_identifier text)",
  "public.email_freeze_owner(token_hash text)",
  "public.delete_account()",
  "public.handle_new_user()",
];

const BATCH_2 = [
  "public.rout_is_workspace_member(ws uuid)",
  "public.rout_workspace_role(ws uuid)",
  "public.rout_workspace_team(p_ws uuid)",
  "public.rout_accept_workspace_invites(p_email text)",
  "public.rout_transfer_by_token(p_hash text)",
  "public.rout_transfers_for_email(p_email text)",
  "public.workspace_may_drop_suffix(ws_plan text, ws uuid)",
  "public.rout_public_workspace(p_slug text)",
  "public.rout_public_workspace_relme(p_slug text)",
  "public.rout_workspace_atproto_did(p_slug text, p_domain text)",
  "public.rout_workspace_slug_for_domain(p_domain text)",
  "public.rout_workspace_slug_taken(p_slug text)",
  "public.workspace_slug_for_root_alias(h text)",
  "public.rout_migrated_workspace_for_handle(p_handle text, p_space text)",
  "public.rout_record_signup_age(p_email text, p_dob date, p_parent_email text, p_token_hash text)",
  "public.rout_user_is_minor(p_user_id uuid)",
  "public.rout_parent_lookup(p_token_hash text)",
  "public.rout_parent_approve_consent(p_token_hash text)",
  "public.rout_parent_set_qa_level(p_token_hash text, p_level qa_permission_level)",
  "public.rout_parent_request_payment(p_user_id uuid, p_token_hash text, p_details jsonb)",
  "public.rout_parent_mark_payment(p_token_hash text)",
  "public.rout_agent_sandbox_register(p_key_hash text, p_pow_hash text, p_ip_bucket text, p_agent_name text)",
  "public.rout_agent_sandbox_context(p_key_hash text)",
  "public.rout_agent_sandbox_provision(p_key_hash text, p_name text, p_slug text, p_description text, p_token_hash text, p_code_hash text, p_draft jsonb)",
  "public.rout_agent_sandbox_patch_draft(p_key_hash text, p_fields jsonb, p_prefs jsonb)",
  "public.rout_agent_sandbox_set_apps(p_key_hash text, p_apps jsonb)",
  "public.rout_agent_sandbox_state(p_key_hash text)",
  "public.rout_purge_expired_agent_sandboxes()",
  "public.rout_agent_provision_workspace(p_client_id text, p_name text, p_slug text, p_description text, p_token_hash text)",
  "public.rout_agent_claim_preview(p_token_hash text)",
  "public.rout_claim_agent_workspace(p_token_hash text)",
  "public.rout_claim_agent_workspace_v2(p_hash text)",
  "public.rout_agent_audit_log(p_workspace_id uuid, p_user_id uuid, p_client_id text, p_action text, p_target_table text, p_target_id text, p_previous jsonb, p_new jsonb)",
  "public.rout_agent_audit_mark_reverted(p_log_id uuid)",
  "public.rout_agent_audit_revert_workspace(p_workspace_id uuid)",
  "public.rout_purge_unclaimed_agent_workspaces()",
];

const BATCH_3 = [
  "public.rout_booking_adjacent_ok(p_host uuid, p_block_start timestamp with time zone, p_block_end timestamp with time zone)",
  "public.rout_booking_cache_free(p_host uuid, p_from timestamp with time zone, p_to timestamp with time zone)",
  "public.rout_booking_confirm_paid(p_booking uuid, p_session text)",
  "public.rout_booking_create(p_event_type uuid, p_start timestamp with time zone, p_guest_name text, p_guest_email text, p_guest_timezone text, p_guest_note text, p_intake jsonb)",
  "public.rout_booking_create(p_event_type uuid, p_start timestamp with time zone, p_guest_name text, p_guest_email text, p_guest_timezone text, p_guest_note text, p_intake jsonb, p_hold uuid, p_hold_secret text)",
  "public.rout_booking_due_calendars(p_limit integer)",
  "public.rout_booking_edge_busy(p_host uuid, p_from timestamp with time zone, p_to timestamp with time zone)",
  "public.rout_booking_group_ids(p_booking uuid)",
  "public.rout_booking_guest_view(p_booking uuid, p_token text)",
  "public.rout_booking_hold(p_event_type uuid, p_start timestamp with time zone, p_client text, p_replace uuid, p_replace_secret text)",
  "public.rout_booking_hold_release(p_hold uuid, p_secret text)",
  "public.rout_booking_horizon_end(p_business_days integer, p_max_days integer, p_zone text, p_now timestamp with time zone)",
  "public.rout_booking_host_free(p_host uuid, p_event_type uuid, p_start timestamp with time zone, p_block_start timestamp with time zone, p_block_end timestamp with time zone, p_capacity integer)",
  "public.rout_booking_host_free_held(p_host uuid, p_event_type uuid, p_start timestamp with time zone, p_block_start timestamp with time zone, p_block_end timestamp with time zone, p_capacity integer, p_hold uuid)",
  "public.rout_booking_lock_hosts(p_hosts uuid[], p_from timestamp with time zone, p_to timestamp with time zone)",
  "public.rout_booking_lock_type(p_event_type uuid, p_start timestamp with time zone)",
  "public.rout_booking_pick_hosts(p_event_type uuid, p_start timestamp with time zone, p_hold uuid)",
  "public.rout_booking_public_constraints(p_id uuid, p_from timestamp with time zone, p_to timestamp with time zone, p_hold uuid)",
  "public.rout_booking_public_days(p_id uuid, p_from date, p_to date)",
  "public.rout_booking_public_event_type(p_id uuid)",
  "public.rout_booking_public_sessions(p_id uuid, p_from timestamp with time zone, p_to timestamp with time zone, p_hold uuid)",
  "public.rout_booking_public_type_for_handle(p_handle text, p_type uuid)",
  "public.rout_booking_release_expired(p_limit integer)",
  "public.rout_booking_release_hold(p_booking uuid)",
  "public.rout_booking_set_checkout(p_booking uuid, p_session text)",
  "public.rout_booking_stale_hosts(p_id uuid, p_max_age interval)",
  "public.rout_booking_start_problem(p_event_type uuid, p_start timestamp with time zone)",
  "public.rout_booking_type_public(p_id uuid)",
  "public.rout_booking_type_zone(p_event_type uuid)",
  "public.rout_booking_within_limits(p_event_type uuid, p_host uuid, p_start timestamp with time zone, p_hold uuid)",
  "public.rout_booking_zone(p_zone text, p_host uuid)",
];

describe("SECURITY DEFINER functions in the schema snapshot", () => {
  it("are all pinned to pg_catalog, pg_temp and the legacy list is empty", () => {
    expect(definers.length).toBeGreaterThan(300);
    expect(definerFindings(definers, LEGACY_DEFINER_SEARCH_PATH)).toEqual([]);
  });

  it("batches 1 (cards, vault, sign-in), 2 (workspaces, parents, agents), 3 (bookings) and 4 (the rest) are pinned; none remain", () => {
    expect(BATCH_1).toHaveLength(21);
    expect(BATCH_2).toHaveLength(36);
    expect(BATCH_3).toHaveLength(31);
    for (const key of [...BATCH_1, ...BATCH_2, ...BATCH_3]) {
      expect(definers.find((f) => f.key === key)?.searchPath, key).toEqual(["pg_catalog", "pg_temp"]);
      expect(LEGACY_DEFINER_SEARCH_PATH, key).not.toContain(key);
    }
    expect(HARDENED_BY_MIGRATION[258]).toHaveLength(48);
    expect(new Set(HARDENED_BY_MIGRATION[258]).size).toBe(48);
    expect(LEGACY_DEFINER_SEARCH_PATH).toEqual([]);
    for (const f of definers) expect(f.searchPath, f.key).toEqual(["pg_catalog", "pg_temp"]);
  });

  it("records each hardened batch under its migration, so a fresh replay allows it only until then", () => {
    expect([...HARDENED_BY_MIGRATION[255]!].sort()).toEqual([...BATCH_1].sort());
    expect([...HARDENED_BY_MIGRATION[256]!].sort()).toEqual([...BATCH_2].sort());
    expect([...HARDENED_BY_MIGRATION[257]!].sort()).toEqual([...BATCH_3].sort());
    const hardened = Object.values(HARDENED_BY_MIGRATION).flat();
    for (const key of hardened) expect(LEGACY_DEFINER_SEARCH_PATH, key).not.toContain(key);
    const after255 = legacyAllowedAfter(255);
    for (const key of BATCH_2) expect(after255, key).toContain(key);
    for (const key of BATCH_1) expect(after255, key).not.toContain(key);
    const after256 = legacyAllowedAfter(256);
    for (const key of BATCH_3) expect(after256, key).toContain(key);
    for (const key of BATCH_2) expect(after256, key).not.toContain(key);
    expect([...legacyAllowedAfter(257)].sort()).toEqual([...HARDENED_BY_MIGRATION[258]!].sort());
    expect(legacyAllowedAfter(258)).toEqual([]);
    const files = listMigrationFiles(DB_DIR);
    for (const n of Object.keys(HARDENED_BY_MIGRATION)) {
      const file = files.find((f) => f.startsWith(`0${n}_`));
      expect(file, n).toBeDefined();
      // 0258 also names pg_temp on the 300 already-pinned definers; its batch is the first section.
      const text = readFileSync(join(DB_DIR, file!), "utf8").split("-- Already pinned to pg_catalog")[0]!;
      const altered = [...text.matchAll(/^(?:alter|create or replace) function public\.(\w+)\(/gim)].map((m) => m[1]).sort();
      expect(altered, file).toEqual(HARDENED_BY_MIGRATION[Number(n)]!.map((k) => k.match(/^public\.(\w+)\(/)?.[1]).sort());
    }
  });

  it("vault_enclave has no exception at all", () => {
    expect(LEGACY_DEFINER_SEARCH_PATH.filter((k) => k.startsWith("vault_enclave."))).toEqual([]);
    expect(definers.filter((f) => f.key.startsWith("vault_enclave.")).every((f) => f.searchPath?.join() === "pg_catalog,pg_temp")).toBe(true);
  });

  it("flags an unpinned function that is not listed, and a listed function that is already pinned", () => {
    expect(definerFindings([{ key: "public.x()", searchPath: ["public"] }], [])).toEqual([
      { problem: "not_pinned", key: "public.x()", searchPath: ["public"] },
    ]);
    expect(definerFindings([{ key: "public.x()", searchPath: ["pg_catalog", "public"] }], [])[0]?.problem).toBe("not_pinned");
    expect(definerFindings([{ key: "public.x()", searchPath: null }], [])[0]?.problem).toBe("not_pinned");
    expect(definerFindings([{ key: "public.x()", searchPath: ["pg_catalog"] }], [])[0]?.problem).toBe("not_pinned");
    expect(definerFindings([{ key: "public.x()", searchPath: ["pg_temp", "pg_catalog"] }], [])[0]?.problem).toBe("not_pinned");
    expect(definerFindings([{ key: "public.x()", searchPath: ["pg_catalog"] }], [], pinnedAfter(257))).toEqual([]);
    expect(definerFindings([{ key: "public.x()", searchPath: ["pg_catalog", "pg_temp"] }], ["public.x()"])).toEqual([
      { problem: "stale_legacy_entry", key: "public.x()" },
    ]);
  });

  it("reads search_path the same way from proconfig and from the function definition", () => {
    expect(searchPathFromConfig(["search_path=public, pg_temp"])).toEqual(["public", "pg_temp"]);
    expect(searchPathFromConfig(["search_path=pg_catalog"])).toEqual(["pg_catalog"]);
    expect(searchPathFromConfig(null)).toBeNull();
    expect(searchPathFromDef(" SECURITY DEFINER\n SET search_path TO 'public', 'pg_temp'\nAS $function$")).toEqual(["public", "pg_temp"]);
    expect(searchPathFromDef(" SECURITY DEFINER\n SET search_path TO 'pg_catalog'\nAS $function$")).toEqual(["pg_catalog"]);
  });
});

describe("migration files from 0255 on", () => {
  const guarded = listMigrationFiles(DB_DIR).filter(guardedMigration);

  it("include 0255-0258; each is linted by the rule in force at its number", () => {
    expect(guarded).toContain("0255_definer_search_path_cards_vault_auth.sql");
    expect(guarded).toContain("0256_definer_search_path_workspaces_parents_agents.sql");
    expect(guarded).toContain("0257_definer_search_path_bookings.sql");
    expect(guarded).toContain("0258_definer_search_path_rest_and_pg_temp.sql");
    for (const file of guarded) expect(migrationDefinerViolations(file, readFileSync(join(DB_DIR, file), "utf8")), file).toEqual([]);
    // From 0258 on the bare pg_catalog form is rejected.
    expect(migrationDefinerViolations("0259_x.sql", "alter function public.a() set search_path = pg_catalog;")).toHaveLength(1);
    expect(migrationDefinerViolations("0257_x.sql", "alter function public.a() set search_path = pg_catalog;")).toEqual([]);
  });

  it("0258 only sets search_path = pg_catalog, pg_temp, once for every SECURITY DEFINER function in the snapshot", () => {
    const sql = readFileSync(join(DB_DIR, "0258_definer_search_path_rest_and_pg_temp.sql"), "utf8").replace(/--[^\n]*/g, "");
    const OWN = /^do \$own\$ begin execute format\('(grant rout_merge_executor to %I with inherit true, set true|revoke rout_merge_executor from %I)', current_user\); end \$own\$$/;
    const all = sql.split(/;\n/).map((s) => s.trim().replace(/;$/, "")).filter(Boolean);
    // Only the borrowed owner role around execute_account_merge, as in 0215/0242.
    expect(all.filter((s) => OWN.test(s))).toHaveLength(2);
    const statements = all.filter((s) => !OWN.test(s));
    expect(definersUpTo0258).toHaveLength(348);
    expect(statements).toHaveLength(definersUpTo0258.length);
    const keys = statements.map((s) => s.match(/^alter function (.+) set search_path = pg_catalog, pg_temp$/)?.[1]);
    expect(keys.every(Boolean)).toBe(true);
    expect([...keys].sort()).toEqual(definersUpTo0258.map((f) => f.key).sort());
  });

  it("0255 only changes search_path settings and one PUBLIC grant", () => {
    const sql = readFileSync(join(DB_DIR, "0255_definer_search_path_cards_vault_auth.sql"), "utf8").replace(/--[^\n]*/g, "");
    const statements = sql.split(";").map((s) => s.trim()).filter(Boolean);
    expect(statements).toHaveLength(22);
    for (const s of statements) expect(s).toMatch(/^(alter function public\.\w+\([^)]*\) set search_path = pg_catalog|revoke execute on function public\.rout_physical_key_audit\(\) from public)$/);
  });

  it("0256 only changes search_path settings, one statement per batch 2 function", () => {
    const sql = readFileSync(join(DB_DIR, "0256_definer_search_path_workspaces_parents_agents.sql"), "utf8").replace(/--[^\n]*/g, "");
    const statements = sql.split(";").map((s) => s.trim()).filter(Boolean);
    expect(statements).toHaveLength(36);
    for (const s of statements) expect(s).toMatch(/^alter function public\.\w+\([^)]*\) set search_path = pg_catalog$/);
    const names = statements.map((s) => s.match(/^alter function public\.(\w+)\(/)?.[1]).sort();
    expect(names).toEqual(BATCH_2.map((k) => k.match(/^public\.(\w+)\(/)?.[1]).sort());
  });

  it("0257 pins all 31 booking functions; only rout_booking_zone and rout_booking_hold are rewritten", () => {
    const sql = readFileSync(join(DB_DIR, "0257_definer_search_path_bookings.sql"), "utf8").replace(/^--[^\n]*/gm, "");
    const alters = [...sql.matchAll(/^alter function public\.(\w+)\([^)]*\) set search_path = pg_catalog;$/gm)].map((m) => m[1]);
    const creates = [...sql.matchAll(/^CREATE OR REPLACE FUNCTION public\.(\w+)\(/gm)].map((m) => m[1]);
    expect(alters).toHaveLength(29);
    expect(creates).toEqual(["rout_booking_zone", "rout_booking_hold"]);
    expect([...alters, ...creates].sort()).toEqual(BATCH_3.map((k) => k.match(/^public\.(\w+)\(/)?.[1]).sort());
    // Outside the two function bodies the file changes nothing else: no drop, grant, revoke or data change.
    expect(sql.replace(/\$function\$[\s\S]*?\$function\$/g, "")).not.toMatch(/\b(drop|grant|revoke|insert|update|delete|truncate|alter table)\b/i);
    expect(sql).toContain("encode(public.gen_random_bytes(32), 'hex')");
    expect(sql.match(/pg_catalog\.pg_timezone_names/g)).toHaveLength(2);
  });

  it("the lint rejects a definer without pg_catalog and accepts a pinned one", () => {
    expect(definerMigrationViolations("create function public.a() returns int language sql security definer as $$ select 1 $$;")).toHaveLength(1);
    expect(definerMigrationViolations("create or replace function public.a() returns int language sql security definer set search_path = public as $$ select 1 $$;").length).toBeGreaterThan(0);
    expect(definerMigrationViolations("alter function public.a() set search_path = public, pg_temp;")).toHaveLength(1);
    expect(definerMigrationViolations("create function public.a() returns int language plpgsql as $$ begin set local search_path to public; return 1; end $$;")).toHaveLength(1);
    expect(definerMigrationViolations("create function public.a() returns int language sql security definer set search_path = pg_catalog, pg_temp as $$ select 1 $$;")).toEqual([]);
    expect(definerMigrationViolations("create function public.a() returns int language sql set search_path = pg_catalog, pg_temp security definer as $$ select 1 $$;")).toEqual([]);
    expect(definerMigrationViolations("alter function public.a() set search_path = pg_catalog, pg_temp;")).toEqual([]);
    expect(definerMigrationViolations("alter function public.a() set search_path = pg_catalog;")).toHaveLength(1);
    expect(definerMigrationViolations("alter function public.a() set search_path = pg_catalog;", 257)).toEqual([]);
  });
});

describe("the runner guard inside a migration transaction", () => {
  it("raises for an unlisted unpinned definer and passes for pinned or listed ones", async () => {
    const db = new PGlite();
    try {
      await db.exec(`create function public.pinned() returns int language sql security definer set search_path = pg_catalog, pg_temp as $$ select 1 $$;
        create function public.listed(p int) returns int language sql security definer set search_path = public as $$ select p $$;
        create function public.invoker() returns int language sql set search_path = public as $$ select 1 $$;`);
      await expect(db.exec(definerGuardSql(["public.listed(p integer)"]))).resolves.toBeDefined();
      await expect(db.exec(definerGuardSql([]))).rejects.toThrow(/public\.listed\(p integer\)/);
      await db.exec("create function public.sneaky() returns int language sql security definer set search_path = public, pg_temp as $$ select 1 $$;");
      await expect(db.exec(definerGuardSql(["public.listed(p integer)"]))).rejects.toThrow(/SECURITY DEFINER without search_path = pg_catalog, pg_temp: public\.sneaky\(\)/);
      await db.exec("drop function public.sneaky(); create function public.bare() returns int language sql security definer set search_path = pg_catalog as $$ select 1 $$;");
      // The bare form of 0255-0257 passes only the guard that runs before 0258.
      await expect(db.exec(definerGuardSql(["public.listed(p integer)"], false))).resolves.toBeDefined();
      await expect(db.exec(definerGuardSql(["public.listed(p integer)"]))).rejects.toThrow(/public\.bare\(\)/);
    } finally {
      await db.close();
    }
  }, 60_000);
});

describe("batch 1 functions still run with search_path = pg_catalog (all migrations replayed)", () => {
  it("resolve every table and helper they touch", async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    const { planMigrations } = await import("../../scripts/migration-plan");
    const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
    try {
      for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
        if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
      }
      // Lookups that a misplaced search_path would break: undefined table, function, type, column or schema.
      const unresolved = /^42(P01|883|704|703|3F)$/;
      const id = "00000000-0000-4000-8000-0000000000c1";
      const calls = [
        ["select public.rout_card_design('S1')"],
        ["select public.rout_card_frozen('S1')"],
        ["select public.rout_card_generation($1::uuid)", id],
        ["select public.rout_card_status_by_serial('S1')"],
        ["select public.rout_card_status_by_hardware($1::uuid)", id],
        ["select public.rout_card_token_use('AAAAAAAAAAAAAAAAAAAAAA', now() + interval '30 seconds')"],
        ["select public.rout_card_token_use('bad', now())"],
        ["select public.rout_hw_issue_challenge($1::uuid, repeat('a', 64))", id],
        ["select * from public.rout_hw_consume_challenge($1::uuid, repeat('a', 64))", id],
        ["select public.rout_hw_record_scan($1::uuid, true)", id],
        ["select public.rout_pair_factory_card($1::uuid, repeat('a', 64), 'S1')", id],
        ["select public.rout_ephemeral_vault_create($1::uuid, 'k', 'h', 'p')", id],
        ["select * from public.rout_ephemeral_vault_read($1::uuid)", id],
        ["select * from public.rout_ephemeral_vault_commit($1::uuid, 'h', 'n', 's', 'b', 'k')", id],
        ["select public.rout_purge_expired_ephemeral_vaults()"],
        ["select public.signin_guard_status(repeat('b', 32))"],
        ["select public.signin_guard_record(repeat('b', 32), false)"],
        ["select public.signin_guard_record(repeat('b', 32), true)"],
        ["select * from public.rout_resolve_account('@nobody')"],
        ["select public.email_freeze_owner('x')"],
        ["select public.delete_account()"],
      ] as const;
      const failures: string[] = [];
      for (const [sql, ...params] of calls) {
        await db.exec("begin");
        try {
          await db.query(sql, [...params]);
        } catch (error) {
          const code = (error as { code?: string }).code ?? "";
          if (unresolved.test(code)) failures.push(`${sql}: ${code} ${(error as Error).message}`);
        } finally {
          await db.exec("rollback");
        }
      }
      expect(failures).toEqual([]);
      expect(calls).toHaveLength(21);
    } finally {
      await db.close();
    }
  }, 120_000);

  it("would catch an unqualified table under the same setting", async () => {
    const db = new PGlite();
    try {
      await db.exec(`create table public.t (x int);
        create function public.bad() returns bigint language sql security definer set search_path = pg_catalog as $$ select count(*) from public.t $$;`);
      await expect(db.query("select public.bad()")).resolves.toBeDefined();
      await db.exec("create or replace function public.bad2() returns bigint language plpgsql security definer set search_path = pg_catalog as $$ begin return (select count(*) from t); end $$;");
      await expect(db.query("select public.bad2()")).rejects.toMatchObject({ code: "42P01" });
    } finally {
      await db.close();
    }
  }, 60_000);
});

describe("batch 2 functions run their normal paths with search_path = pg_catalog (all migrations replayed)", () => {
  it("sandbox, agent workspace, invites, public lookups and parental consent all succeed", async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    const { planMigrations } = await import("../../scripts/migration-plan");
    const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
    try {
      for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
        if (step.action === "run") await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
      }
      const owner = "00000000-0000-4000-8000-0000000000a1";
      const kid = "00000000-0000-4000-8000-0000000000a2";
      const h = (c: string) => c.repeat(64);
      const ws = (prefix: string) => `(select id from public.workspaces where slug like '${prefix}%')`;
      const slug = (prefix: string) => `(select slug from public.workspaces where slug like '${prefix}%')`;
      const as = (uid: string) => [`select set_config('rout.current_user_id', $1, true)`, uid] as const;
      const steps: (readonly [string, ...unknown[]])[] = [
        ["insert into public.users (id, email) values ($1, 'owner@example.test'), ($2, 'kid@example.test')", owner, kid],
        as(""),
        [`select * from public.rout_agent_sandbox_register('${h("a")}', '${h("b")}', 'ip1', 'Agent One')`],
        [`select * from public.rout_agent_sandbox_context('${h("a")}')`],
        [`select * from public.rout_agent_sandbox_provision('${h("a")}', 'Agent Space', 'agent-space-x7', 'desc', '${h("c")}', '${h("d")}', '{}'::jsonb)`],
        [`select * from public.rout_agent_sandbox_patch_draft('${h("a")}', '{"bio":"hi"}'::jsonb, '{"theme":"x"}'::jsonb)`],
        [`select public.rout_agent_sandbox_set_apps('${h("a")}', '[]'::jsonb)`],
        [`select * from public.rout_agent_sandbox_state('${h("a")}')`],
        as(owner),
        [`select * from public.rout_agent_claim_preview('${h("c")}')`],
        [`select * from public.rout_claim_agent_workspace_v2('${h("d")}')`],
        [`select public.rout_is_workspace_member(${ws("agent-space-x7")}) as v`],
        [`select public.rout_workspace_role(${ws("agent-space-x7")}) as v`],
        [`select * from public.rout_workspace_team(${ws("agent-space-x7")})`],
        [`select public.rout_agent_audit_log(${ws("agent-space-x7")}, $1, 'client', 'update', 'profiles', 'p1', '{}'::jsonb, '{}'::jsonb)`, owner],
        ["select public.rout_agent_audit_mark_reverted((select id from public.agent_audit_logs limit 1))"],
        [`select * from public.rout_agent_provision_workspace('client-a', 'Second', 'second-space-x7', '', '${h("e")}')`],
        [`select * from public.rout_claim_agent_workspace('${h("e")}')`],
        [`select * from public.rout_agent_provision_workspace('client-a', 'Third', 'third-space-x7', '', '${h("f")}')`],
        [`select public.rout_agent_audit_revert_workspace(${ws("third-space-x7")})`],
        [`select * from public.rout_agent_provision_workspace('client-a', 'Fourth', 'fourth-space-x7', '', '${h("9")}')`],
        [`update public.agent_workspace_claims set created_at = created_at - interval '25 hours', expires_at = expires_at - interval '25 hours' where token_hash = '${h("9")}'`],
        ["select public.rout_purge_unclaimed_agent_workspaces() as v"],
        ["select public.rout_purge_expired_agent_sandboxes()"],
        [`insert into public.workspace_invites (workspace_id, email, role, status, invited_by) select id, 'kid@example.test', 'editor', 'pending', $1 from public.workspaces where slug like 'agent-space-x7%'`, owner],
        as(kid),
        ["select public.rout_accept_workspace_invites('kid@example.test') as v"],
        ["select * from public.rout_transfer_by_token('nope')"],
        ["select * from public.rout_transfers_for_email('kid@example.test')"],
        [`select public.workspace_may_drop_suffix('free', ${ws("agent-space-x7")})`],
        [`select * from public.rout_public_workspace(${slug("agent-space-x7")})`],
        [`select * from public.rout_public_workspace_relme(${slug("agent-space-x7")})`],
        ["select public.rout_workspace_atproto_did('agent-space-x7', 'example.test')"],
        ["select public.rout_workspace_slug_for_domain('example.test')"],
        [`select public.rout_workspace_slug_taken(${slug("agent-space-x7")}) as v`],
        ["select public.workspace_slug_for_root_alias('agent')"],
        ["select public.rout_migrated_workspace_for_handle('someone', 'alias')"],
        ["select public.rout_migrated_workspace_for_handle('someone', 'profile')"],
        [`select public.rout_record_signup_age('kid@example.test', (current_date - interval '10 years')::date, 'parent@example.test', '${h("8")}') as v`],
        [`select * from public.rout_parent_lookup('${h("8")}')`],
        [`select public.rout_parent_set_qa_level('${h("8")}', 'verified_only') as v`],
        [`select public.rout_parent_approve_consent('${h("8")}') as v`],
        ["select public.rout_user_is_minor($1) as v", kid],
        [`select public.rout_parent_request_payment($1, '${h("7")}', '{"item":"pro"}'::jsonb) as v`, kid],
        [`select public.rout_parent_mark_payment('${h("7")}') as v`],
      ];
      const results: Record<string, unknown>[][] = [];
      await db.exec("begin");
      try {
        for (const [sql, ...params] of steps) {
          const r = await db.query<Record<string, unknown>>(sql, params).catch((error: Error & { code?: string }) => {
            throw new Error(`${sql}: ${error.code ?? ""} ${error.message}`);
          });
          results.push(r.rows);
        }
      } finally {
        await db.exec("rollback");
      }
      const v = (fragment: string) => results[steps.findIndex(([sql]) => sql.includes(fragment))]?.[0]?.v;
      expect(v("rout_is_workspace_member(")).toBe(true);
      expect(v("rout_workspace_role(")).toBe("owner");
      expect(v("rout_purge_unclaimed_agent_workspaces(")).toBe(1);
      expect(v("rout_accept_workspace_invites(")).toBe(1);
      expect(v("rout_workspace_slug_taken(")).toBe(true);
      expect(v("rout_record_signup_age(")).toBe(kid);
      expect(v("rout_parent_set_qa_level(")).toBe(true);
      expect(v("rout_parent_approve_consent(")).toBe(true);
      expect(v("rout_user_is_minor(")).toBe(true);
      expect(v("rout_parent_request_payment(")).toBe("parent@example.test");
      expect(v("rout_parent_mark_payment(")).toBe(kid);
      const called = new Set(steps.flatMap(([sql]) => [...sql.matchAll(/public\.(\w+)\(/g)].map((m) => m[1])));
      for (const key of BATCH_2) expect(called, key).toContain(key.match(/^public\.(\w+)\(/)?.[1]);
    } finally {
      await db.close();
    }
  }, 180_000);
});

describe("batch 3 booking functions after 0257 (all migrations replayed)", () => {
  it("keep their bodies apart from two qualified names, and a full booking runs with search_path = pg_catalog", async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    const { planMigrations } = await import("../../scripts/migration-plan");
    const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
    const BOOKINGS = "0257_definer_search_path_bookings.sql";
    try {
      for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
        if (step.action === "run" && step.file !== BOOKINGS) await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
      }
      const defs = async () =>
        new Map(
          (await db.query<{ k: string; d: string }>(
            "select p.oid::regprocedure::text as k, pg_get_functiondef(p.oid) as d from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname like 'rout_booking_%'",
          )).rows.map((r) => [r.k, r.d]),
        );
      const before = await defs();
      await db.exec(`begin;\n${readFileSync(join(DB_DIR, BOOKINGS), "utf8")}\n;commit;`);
      const after = await defs();
      const norm = (d: string) =>
        d.replace(/^ SET search_path TO .*$/m, "").replace("public.gen_random_bytes(", "gen_random_bytes(").replaceAll("pg_catalog.pg_timezone_names", "pg_timezone_names");
      expect(after.size).toBe(before.size);
      for (const [k, d] of before) expect(norm(after.get(k)!), k).toBe(norm(d));

      const host = "00000000-0000-4000-8000-0000000000b1";
      const free = "00000000-0000-4000-8000-0000000000b2";
      const paid = "00000000-0000-4000-8000-0000000000b3";
      const day = new Date(Date.now() + 3 * 86400000).toISOString().slice(0, 10);
      const bits = "0".repeat(32) + "1".repeat(40) + "0".repeat(24);
      type J = Record<string, unknown>;
      const one = async (sql: string, params: unknown[] = []) => {
        const r = await db.query<{ v: J }>(sql, params).catch((error: Error & { code?: string }) => {
          throw new Error(`${sql}: ${error.code ?? ""} ${error.message}`);
        });
        return r.rows[0]?.v;
      };
      await db.exec("begin");
      try {
        await one("insert into public.users (id, email) values ($1, 'host@example.test')", [host]);
        await one("insert into public.profiles (id, username, display_name) values ($1, 'hosty', 'Host') on conflict (id) do update set username = 'hosty'", [host]);
        await one("insert into public.booking_event_types (id, user_id, slug, title, duration_minutes, minimum_notice_hours, max_days_ahead) values ($1, $2, 'intro', 'Intro', 30, 0, 30)", [free, host]);
        await one("insert into public.booking_event_types (id, user_id, slug, title, duration_minutes, minimum_notice_hours, max_days_ahead, price_cents, currency) values ($1, $2, 'paid', 'Paid', 30, 0, 30, 1000, 'eur')", [paid, host]);
        await one("insert into public.booking_event_type_hosts (event_type_id, user_id) values ($1, $3), ($2, $3)", [free, paid, host]);
        await one("insert into public.availability_cache (user_id, day, free_bits) values ($1, $2::date, $3::bit(96))", [host, day, bits]);

        expect((await one("select public.rout_booking_public_event_type($1) as v", [free]))?.["title"]).toBe("Intro");
        await one("select public.rout_booking_public_type_for_handle('hosty', null)::text as v");
        await one("select count(*) as v from public.rout_booking_public_days($1, current_date, current_date + 10)", [free]);
        await one("select count(*) as v from public.rout_booking_public_sessions($1, now(), now() + interval '7 days', null)", [free]);
        await one("select count(*) as v from public.rout_booking_public_constraints($1, now(), now() + interval '7 days', null)", [free]);
        await one("select public.rout_booking_stale_hosts($1, interval '1 hour')::text as v", [free]);

        const held = (await one(`select public.rout_booking_hold($1, '${day}T10:00:00Z', repeat('a', 64), null, null) as v`, [free]))!;
        expect(held["ok"]).toBe(true);
        expect(String(held["secret"])).toMatch(/^[a-f0-9]{64}$/);
        const booked = (await one(`select public.rout_booking_create($1, '${day}T10:00:00Z', 'Ann', 'ann@example.test', 'Europe/Brussels', null, null, $2::uuid, $3) as v`, [free, held["holdId"], held["secret"]]))!;
        expect(booked["ok"]).toBe(true);
        const legacy = (await one(`select public.rout_booking_create($1, '${day}T12:00:00Z', 'Bo', 'bo@example.test', 'Europe/Brussels', null, null) as v`, [free]))!;
        expect(legacy["status"]).toBe("confirmed");
        const pending = (await one(`select public.rout_booking_create($1, '${day}T14:00:00Z', 'Cy', 'cy@example.test', 'Europe/Brussels', null, null) as v`, [paid]))!;
        expect(pending["status"]).toBe("pending_payment");
        const pendingId = (pending["bookingIds"] as string[])[0];
        expect(await one("select public.rout_booking_set_checkout($1, 'cs_test_12345678') as v", [pendingId])).toBe(true);
        expect((await one("select public.rout_booking_confirm_paid($1, 'cs_test_12345678') as v", [pendingId]))?.["status"]).toBe("confirmed");
        expect((await one("select public.rout_booking_guest_view(b.id, b.booking_token) as v from public.bookings b where b.guest_name = 'Bo'"))?.["masked"]).toBe(false);
        const second = (await one(`select public.rout_booking_hold($1, '${day}T16:00:00Z', repeat('b', 64), null, null) as v`, [free]))!;
        expect(await one("select public.rout_booking_hold_release($1::uuid, $2) as v", [second["holdId"], second["secret"]])).toBe(true);
        await one("select public.rout_booking_release_hold($1) as v", [pendingId]);
        await one("select public.rout_booking_release_expired(10) as v");
        await one("select count(*) as v from public.rout_booking_due_calendars(10)");
        expect(await one("select public.rout_booking_zone('Europe/Brussels', $1) as v", [host])).toBe("Europe/Brussels");
        expect(await one("select public.rout_booking_zone('Not/AZone', $1) as v", [host])).toBe("UTC");
      } finally {
        await db.exec("rollback");
      }
    } finally {
      await db.close();
    }
  }, 180_000);
});

describe("batch 4 and pg_temp after 0258 (all migrations replayed)", () => {
  it("0258 changes only the search_path line, every definer ends on pg_catalog, pg_temp, and the last 48 resolve every name they reach", async () => {
    const { btree_gist } = await import("@electric-sql/pglite/contrib/btree_gist");
    const { pgcrypto } = await import("@electric-sql/pglite/contrib/pgcrypto");
    const { planMigrations } = await import("../../scripts/migration-plan");
    const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
    const REST = "0258_definer_search_path_rest_and_pg_temp.sql";
    const definerDefs = async () =>
      new Map(
        (await db.query<{ k: string; d: string }>(
          `select n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' as k, pg_get_functiondef(p.oid) as d
             from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where p.prosecdef and n.nspname not in ('pg_catalog', 'information_schema')
              and not exists (select 1 from pg_depend x where x.classid = 'pg_proc'::regclass and x.objid = p.oid and x.deptype = 'e')`,
        )).rows.map((r) => [r.k, r.d]),
      );
    try {
      for (const step of planMigrations(listMigrationFiles(DB_DIR), new Set())) {
        if (step.action === "run" && step.file !== REST) await db.exec(`begin;\n${readFileSync(join(DB_DIR, step.file), "utf8")}\n;commit;`);
      }
      const before = await definerDefs();
      await db.exec(`begin;\n${readFileSync(join(DB_DIR, REST), "utf8")}\n;commit;`);
      const after = await definerDefs();
      expect(after.size).toBe(before.size);
      const strip = (d: string) => d.replace(/^ SET search_path TO .*$/m, "");
      for (const [k, d] of before) {
        expect(strip(after.get(k)!), k).toBe(strip(d));
        expect(searchPathFromDef(after.get(k)!), k).toEqual(["pg_catalog", "pg_temp"]);
      }
      await expect(db.exec(definerGuardSql([]))).resolves.toBeDefined();

      // Call every batch 4 function (triggers excepted) with empty and with sample
      // arguments. Business errors are fine; an unresolved table, function, type,
      // column or schema is not.
      const UNRESOLVED = new Set(["42P01", "42883", "42704", "42703", "3F000"]);
      const sample: Record<string, string> = {
        text: "'x'", uuid: "'00000000-0000-4000-8000-0000000000c1'::uuid", integer: "1", bigint: "1", boolean: "true",
        "timestamp with time zone": "now() + interval '1 hour'", jsonb: "'{}'::jsonb", "text[]": "'{}'::text[]",
      };
      const fns = (
        await db.query<{ k: string; fn: string; types: string[]; trig: boolean }>(
          `select p.oid::regprocedure::text as k, p.oid::regproc::text as fn,
                  coalesce(array(select pg_catalog.format_type(t, null) from unnest(p.proargtypes) t), '{}') as types,
                  p.prorettype = 'trigger'::regtype as trig
             from pg_proc p where p.pronamespace = 'public'::regnamespace and p.prosecdef`,
        )
      ).rows;
      const batch4 = new Set(HARDENED_BY_MIGRATION[258]!.map((k) => k.match(/^public\.(\w+)\(/)![1]));
      const called: string[] = [];
      const problems: string[] = [];
      await db.exec("begin");
      try {
        for (const f of fns) {
          const name = f.fn.replace(/^public\./, "");
          if (!batch4.has(name) || f.trig) continue;
          called.push(name);
          for (const variant of ["null", "sample"]) {
            const args = f.types.map((t) => (variant === "null" ? `null::${t}` : sample[t] ?? `null::${t}`)).join(", ");
            await db.exec("savepoint s");
            try {
              await db.query(`select * from public.${name}(${args})`);
            } catch (error) {
              const code = (error as { code?: string }).code ?? "";
              if (UNRESOLVED.has(code)) problems.push(`${f.k} [${variant}]: ${code} ${(error as Error).message}`);
            }
            await db.exec("rollback to savepoint s");
          }
        }
      } finally {
        await db.exec("rollback");
      }
      expect(problems).toEqual([]);
      // enforce_short_link_limits and rout_shadow_mute_trust are triggers; the other 46 are called.
      expect(new Set(called).size).toBe(batch4.size - 2);
    } finally {
      await db.close();
    }
  }, 240_000);
});
