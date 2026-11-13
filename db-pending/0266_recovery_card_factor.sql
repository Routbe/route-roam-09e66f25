-- 0266 — EXPAND: ROUT Card as fourth recovery factor (2-of-4, ceremony version 2).
--
-- Owner decision (2026-11-13): recovery = any 2 of 4 shards — passkey (WebAuthn
-- PRF), ROUT Card (NXP NTAG 424 DNA), ROUT's server shard, 24 paper words.
--
-- The card shard is an RVE1 'mpc' envelope like the others, sealed in the
-- browser to a key derived from the 32-byte secret in the card's tap-URL
-- fragment (src/lib/crypto-enclave/card-factor.ts). Browsers never send a URL
-- fragment, so neither this database nor the server can derive that key: ROUT's
-- own shard plus anything ROUT holds stays one share, never two.
--
-- Only adds: a nullable card_shard column, a version column (1 = 2-of-3,
-- 2 = 2-of-4) tied to it by a check, a 9-argument save function, and *_v2 read
-- functions. The existing 8-argument save keeps working and now explicitly
-- writes a version 1 row (clearing a card shard), and the existing reads show
-- version 1 rows only, so code at schema 0264 never receives a version 2
-- ceremony it would mis-read as 2-of-3. rout_app still has no table rights;
-- every function takes the member from rout_current_user_id().

alter table public.recovery_ceremonies
  add column if not exists card_shard text
    check (card_shard is null or (char_length(card_shard) between 64 and 6000 and card_shard ~ '^[A-Za-z0-9+/]+={0,2}$')),
  add column if not exists ceremony_version smallint not null default 1;

alter table public.recovery_ceremonies drop constraint if exists recovery_ceremonies_version_card;
alter table public.recovery_ceremonies add constraint recovery_ceremonies_version_card
  check ((ceremony_version = 1 and card_shard is null) or (ceremony_version = 2 and card_shard is not null));

-- Five distinct shards: the same envelope stored twice would turn 2-of-4 into less.
alter table public.recovery_ceremonies drop constraint if exists recovery_ceremonies_card_distinct;
alter table public.recovery_ceremonies add constraint recovery_ceremonies_card_distinct
  check (card_shard is null or (card_shard <> device_shard and card_shard <> paper_shard and card_shard <> server_shard));

-- Existing 8-argument save (0244): same signature, same rights; now writes version 1 explicitly.
create or replace function public.rout_recovery_ceremony_put(
  p_ceremony_id text, p_key_id text, p_sealed_master text,
  p_device_shard text, p_paper_shard text, p_server_shard text, p_device_credential text, p_login_key text)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null then raise exception 'no member context' using errcode = '42501'; end if;
  if p_login_key is null then raise exception 'login key required' using errcode = '22023'; end if;
  insert into public.recovery_ceremonies as c
    (user_id, ceremony_id, key_id, sealed_master, device_shard, paper_shard, server_shard, card_shard, ceremony_version,
     device_credential, login_key, created_at)
  values (v_user, p_ceremony_id, p_key_id, p_sealed_master, p_device_shard, p_paper_shard, p_server_shard, null, 1,
          p_device_credential, p_login_key, pg_catalog.now())
  on conflict (user_id) do update set
    ceremony_id = excluded.ceremony_id, key_id = excluded.key_id, sealed_master = excluded.sealed_master,
    device_shard = excluded.device_shard, paper_shard = excluded.paper_shard, server_shard = excluded.server_shard,
    card_shard = null, ceremony_version = 1,
    device_credential = excluded.device_credential, login_key = excluded.login_key, created_at = excluded.created_at;
end $$;

-- Version 2 save: the card shard is required (a 2-of-3 save uses the 8-argument form).
create or replace function public.rout_recovery_ceremony_put(
  p_ceremony_id text, p_key_id text, p_sealed_master text,
  p_device_shard text, p_paper_shard text, p_server_shard text, p_card_shard text,
  p_device_credential text, p_login_key text)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null then raise exception 'no member context' using errcode = '42501'; end if;
  if p_login_key is null then raise exception 'login key required' using errcode = '22023'; end if;
  if p_card_shard is null then raise exception 'card shard required' using errcode = '22023'; end if;
  insert into public.recovery_ceremonies as c
    (user_id, ceremony_id, key_id, sealed_master, device_shard, paper_shard, server_shard, card_shard, ceremony_version,
     device_credential, login_key, created_at)
  values (v_user, p_ceremony_id, p_key_id, p_sealed_master, p_device_shard, p_paper_shard, p_server_shard, p_card_shard, 2,
          p_device_credential, p_login_key, pg_catalog.now())
  on conflict (user_id) do update set
    ceremony_id = excluded.ceremony_id, key_id = excluded.key_id, sealed_master = excluded.sealed_master,
    device_shard = excluded.device_shard, paper_shard = excluded.paper_shard, server_shard = excluded.server_shard,
    card_shard = excluded.card_shard, ceremony_version = 2,
    device_credential = excluded.device_credential, login_key = excluded.login_key, created_at = excluded.created_at;
end $$;

-- Existing reads (0242): same signatures and rights, version 1 rows only.
create or replace function public.rout_recovery_ceremony_status()
returns table (ceremony_id text, key_id text, created_at timestamptz)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select c.ceremony_id, c.key_id, c.created_at from public.recovery_ceremonies c
   where c.user_id = public.rout_current_user_id() and c.ceremony_version = 1;
$$;

create or replace function public.rout_recovery_ceremony_get()
returns table (ceremony_id text, key_id text, sealed_master text, device_shard text, paper_shard text, server_shard text, device_credential text)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select c.ceremony_id, c.key_id, c.sealed_master, c.device_shard, c.paper_shard, c.server_shard, c.device_credential
    from public.recovery_ceremonies c
   where c.user_id = public.rout_current_user_id() and c.ceremony_version = 1;
$$;

-- Version-aware reads for code at 0266 and later.
create or replace function public.rout_recovery_ceremony_status_v2()
returns table (ceremony_id text, key_id text, created_at timestamptz, ceremony_version smallint)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select c.ceremony_id, c.key_id, c.created_at, c.ceremony_version from public.recovery_ceremonies c
   where c.user_id = public.rout_current_user_id();
$$;

create or replace function public.rout_recovery_ceremony_get_v2()
returns table (ceremony_id text, key_id text, sealed_master text, device_shard text, paper_shard text, server_shard text,
               card_shard text, ceremony_version smallint, device_credential text)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select c.ceremony_id, c.key_id, c.sealed_master, c.device_shard, c.paper_shard, c.server_shard,
         c.card_shard, c.ceremony_version, c.device_credential
    from public.recovery_ceremonies c
   where c.user_id = public.rout_current_user_id();
$$;

do $$
declare f text;
begin
  foreach f in array array[
    'public.rout_recovery_ceremony_put(text,text,text,text,text,text,text,text)',
    'public.rout_recovery_ceremony_put(text,text,text,text,text,text,text,text,text)',
    'public.rout_recovery_ceremony_status()',
    'public.rout_recovery_ceremony_get()',
    'public.rout_recovery_ceremony_status_v2()',
    'public.rout_recovery_ceremony_get_v2()'] loop
    execute format('revoke all on function %s from public', f);
    execute format('grant execute on function %s to rout_app', f);
  end loop;
end $$;

-- In-transaction proof: rout_app still has no table rights, PUBLIC executes nothing new.
do $$
begin
  if has_table_privilege('rout_app', 'public.recovery_ceremonies', 'select, insert, update, delete') then
    raise exception '0266: rout_app must not have table rights on recovery_ceremonies';
  end if;
  if has_function_privilege('public', 'public.rout_recovery_ceremony_put(text,text,text,text,text,text,text,text,text)', 'execute')
     or has_function_privilege('public', 'public.rout_recovery_ceremony_get_v2()', 'execute')
     or has_function_privilege('public', 'public.rout_recovery_ceremony_status_v2()', 'execute') then
    raise exception '0266: PUBLIC must not execute the version 2 recovery functions';
  end if;
end $$;
