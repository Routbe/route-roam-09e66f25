-- 0263 — EXPAND: account recovery requests (db/0207) only through database functions.
--
-- Found on Neon on 2026-11-13 (docs/HANDOVER.md, appendix J): RLS is on for
-- public.auth_recovery_requests and the table has no policy, so every read and
-- write rout_app makes there is refused or returns nothing. A member asking to
-- get back in sees "received" while nothing is stored, and the admin queue stays
-- empty. Instead of opening the table with policies, these SECURITY DEFINER
-- functions are its only way in. Each one decides for itself what the caller
-- may do:
--   * filing: no session; the database looks the account up itself and always
--     answers the same way, so the answer never shows whether an account exists;
--   * list / approve / deny: only for a full admin with two-factor sign-in on,
--     checked in the database from the transaction context (rout.current_user_id).
--     The deciding admin comes from that context, never from a parameter;
--   * resolve / consume of the single-use binding token: the database receives
--     only the token's SHA-256, never the token itself.
-- Only adds functions: no table, column, row or table right changes. The CONTRACT
-- step that removes rout_app's table rights waits in db-pending/0264 until
-- production runs the code that calls these functions.

-- ------------------------------------------------------------------ internal helper
-- Full admin (role 'admin', as assertAdminRole in src/lib/admin.server.ts) whose
-- sign-in account has two-factor on (as memberTwoFactorEnabled).
create or replace function public.rout_recovery_caller_admin()
returns uuid language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select u.id
    from public.users u
    join neon_auth."user" au on au.id::text = coalesce(u.auth_user_id::text, u.user_metadata ->> 'neon_auth_id')
   where u.id = public.rout_current_user_id()
     and public.rout_has_role(u.id, 'admin')
     and au."twoFactorEnabled" is true
$$;

-- ------------------------------------------------------------------ filing (no session)
-- Always returns nothing and never raises for unknown, invalid or already
-- protected input. Only an existing account without a passkey and without an
-- open request gets a new 'pending' row (one open request per account, 0207).
create or replace function public.rout_recovery_request_file(p_email text, p_note text)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_email text := pg_catalog.lower(pg_catalog.btrim(coalesce(p_email, '')));
  v_note  text := pg_catalog.left(nullif(pg_catalog.btrim(coalesce(p_note, '')), ''), 1000);
  v_user  text;
begin
  if pg_catalog.char_length(v_email) not between 3 and 254 or v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then
    return;
  end if;
  select au.id::text into v_user from neon_auth."user" au where pg_catalog.lower(au.email) = v_email limit 1;
  if v_user is null or exists (select 1 from neon_auth.passkey k where k."userId" = v_user) then
    return;
  end if;
  insert into public.auth_recovery_requests (auth_user_id, email, note)
  values (v_user, v_email, v_note)
  on conflict do nothing;
end $$;

-- ------------------------------------------------------------------ admin queue
-- Approved tokens past their deadline fall back to 'expired' first (as before).
create or replace function public.rout_recovery_requests_list()
returns table (id uuid, email text, note text, status text, created_at timestamptz, token_expires_at timestamptz)
language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
begin
  if public.rout_recovery_caller_admin() is null then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  update public.auth_recovery_requests r set status = 'expired', token_hash = null
   where r.status = 'approved' and r.token_expires_at < pg_catalog.now();
  return query
    select r.id, r.email, r.note, r.status, r.created_at, r.token_expires_at
      from public.auth_recovery_requests r
     order by (r.status = 'pending') desc, r.created_at desc
     limit 100;
end $$;

-- Approve AFTER out-of-band identity verification. The app generates the token
-- and passes only its SHA-256; the database never sees the token. A note on how
-- the person was verified is required. The token is valid for 24 hours.
create or replace function public.rout_recovery_request_approve(p_id uuid, p_note text, p_token_hash text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_admin uuid := public.rout_recovery_caller_admin();
  v_note  text := pg_catalog.left(nullif(pg_catalog.btrim(coalesce(p_note, '')), ''), 1000);
begin
  if v_admin is null then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if p_id is null or v_note is null or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
    return false;
  end if;
  update public.auth_recovery_requests r
     set status = 'approved', decided_at = pg_catalog.now(), decided_by = v_admin, decision_note = v_note,
         token_hash = p_token_hash, token_expires_at = pg_catalog.now() + pg_catalog.make_interval(hours => 24)
   where r.id = p_id and r.status = 'pending';
  if not found then
    return false;
  end if;
  perform public.rout_audit_insert(v_admin, (select u.email from public.users u where u.id = v_admin),
    'RECOVERY_REQUEST_APPROVED', null, 'recovery:' || p_id::text, null);
  return true;
end $$;

create or replace function public.rout_recovery_request_deny(p_id uuid, p_note text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_admin uuid := public.rout_recovery_caller_admin();
  v_note  text := pg_catalog.left(nullif(pg_catalog.btrim(coalesce(p_note, '')), ''), 1000);
begin
  if v_admin is null then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if p_id is null then
    return false;
  end if;
  update public.auth_recovery_requests r
     set status = 'denied', decided_at = pg_catalog.now(), decided_by = v_admin, decision_note = v_note, token_hash = null
   where r.id = p_id and r.status in ('pending', 'approved');
  if not found then
    return false;
  end if;
  perform public.rout_audit_insert(v_admin, (select u.email from public.users u where u.id = v_admin),
    'RECOVERY_REQUEST_DENIED', null, 'recovery:' || p_id::text, null);
  return true;
end $$;

-- ------------------------------------------------------------------ binding token (no session)
-- Looks up an approved, unexpired token by its SHA-256 without using it.
create or replace function public.rout_recovery_token_resolve(p_token_hash text)
returns table (auth_user_id text, email text)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select r.auth_user_id, r.email
    from public.auth_recovery_requests r
   where p_token_hash ~ '^[0-9a-f]{64}$'
     and r.token_hash = p_token_hash and r.status = 'approved' and r.token_expires_at > pg_catalog.now()
   limit 1
$$;

-- Burns the token when the first passkey is bound: one caller wins, every later
-- call (and every expired or unknown token) gets null.
create or replace function public.rout_recovery_token_consume(p_token_hash text)
returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_user text;
begin
  if p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
    return null;
  end if;
  update public.auth_recovery_requests r
     set status = 'bound', bound_at = pg_catalog.now(), token_hash = null
   where r.token_hash = p_token_hash and r.status = 'approved' and r.token_expires_at > pg_catalog.now()
  returning r.auth_user_id into v_user;
  return v_user;
end $$;

-- ------------------------------------------------------------------ privileges
-- Stated explicitly: Neon's default privileges give rout_app EXECUTE on every
-- new function, so the internal helper is revoked from rout_app as well.
revoke all on function public.rout_recovery_caller_admin() from public;
do $$
declare f text;
begin
  if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
    revoke all on function public.rout_recovery_caller_admin() from rout_app;
  end if;
  foreach f in array array[
    'public.rout_recovery_request_file(text, text)',
    'public.rout_recovery_requests_list()',
    'public.rout_recovery_request_approve(uuid, text, text)',
    'public.rout_recovery_request_deny(uuid, text)',
    'public.rout_recovery_token_resolve(text)',
    'public.rout_recovery_token_consume(text)'
  ] loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
      execute pg_catalog.format('grant execute on function %s to rout_app', f);
    end if;
  end loop;
  if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app')
     and pg_catalog.has_function_privilege('rout_app', 'public.rout_recovery_caller_admin()', 'execute') then
    raise exception 'rout_app can still execute public.rout_recovery_caller_admin()';
  end if;
end $$;
