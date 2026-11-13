-- 0250 (EXPAND): a ROUT Card tap as a step-up factor.
--  * member_card_factor(): whether the caller owns an activated, unrevoked card.
--  * Cross-device / iOS path: the dialog opens a single-use intent (csu_ ref, kept
--    only as a SHA-256 digest; the browser holds it in an HttpOnly cookie). A tap on
--    /t by the same signed-in member spends the tap_ grant for 'step_up' (owner
--    check in consume_sdm_tap) and completes the intent in the same transaction.
--    The dialog then claims the intent exactly once and receives a step-up proof.
--  * The caller always comes from the transaction context; nothing is trusted
--    from arguments. Every denial lands on the hash-chained audit log.
-- Additive only: new table (deny-all RLS, no rights for rout_app) and new functions.

create table vault_enclave.card_step_up_intents (
  intent_digest bytea primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  scope text not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  expires_at timestamptz not null,
  completed_at timestamptz,
  claimed_at timestamptz,
  constraint card_step_up_intents_digest_len check (octet_length(intent_digest) = 32),
  constraint card_step_up_intents_scope check (scope in ('*', 'card_reveal', 'card_lifecycle')),
  constraint card_step_up_intents_order check (claimed_at is null or completed_at is not null)
);
create index card_step_up_intents_open_idx on vault_enclave.card_step_up_intents (user_id, created_at desc)
  where completed_at is null;
alter table vault_enclave.card_step_up_intents enable row level security;
create policy deny_all on vault_enclave.card_step_up_intents as restrictive for all to public using (false) with check (false);
revoke all on vault_enclave.card_step_up_intents from public, rout_app;

create function vault_enclave.member_card_factor()
returns boolean language plpgsql stable security definer set search_path = pg_catalog as $$
declare v_caller uuid := vault_enclave.caller_user_id();
begin
  if v_caller is null then return false; end if;
  return exists (select 1 from vault_enclave.sdm_batch_cards c
                  where c.owner_user_id = v_caller and c.activated_at is not null and c.revoked_at is null);
end $$;

-- Opens the caller's one open intent (older open ones expire at once); 300 s.
create function vault_enclave.begin_card_step_up(p_scope text)
returns text language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_caller uuid := vault_enclave.caller_user_id();
  v_ref text;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'card_step_up_begin', 'denied', 'no_caller', null); return null;
  end if;
  if p_scope is null or p_scope not in ('*', 'card_reveal', 'card_lifecycle') then
    perform vault_enclave.append_audit(v_caller, 'card_step_up_begin', 'denied', 'bad_request', null); return null;
  end if;
  if not exists (select 1 from vault_enclave.sdm_batch_cards c
                  where c.owner_user_id = v_caller and c.activated_at is not null and c.revoked_at is null) then
    perform vault_enclave.append_audit(v_caller, 'card_step_up_begin', 'denied', 'no_card', null); return null;
  end if;
  update vault_enclave.card_step_up_intents set expires_at = v_now
   where user_id = v_caller and completed_at is null and expires_at > v_now;
  v_ref := 'csu_' || pg_catalog.encode(public.gen_random_bytes(32), 'hex');
  insert into vault_enclave.card_step_up_intents (intent_digest, user_id, scope, created_at, expires_at)
  values (pg_catalog.sha256(pg_catalog.convert_to(v_ref, 'UTF8')), v_caller, p_scope, v_now, v_now + interval '300 seconds');
  perform vault_enclave.append_audit(v_caller, 'card_step_up_begin', 'granted', p_scope, null);
  return v_ref;
end $$;

-- Whether the caller has an open intent (so /t confirms a step-up instead of a public check).
create function vault_enclave.pending_card_step_up()
returns boolean language plpgsql stable security definer set search_path = pg_catalog as $$
declare v_caller uuid := vault_enclave.caller_user_id();
begin
  if v_caller is null then return false; end if;
  return exists (select 1 from vault_enclave.card_step_up_intents i
                  where i.user_id = v_caller and i.completed_at is null and i.expires_at > pg_catalog.clock_timestamp());
end $$;

-- Spends a tap_ grant for 'step_up' (owner-checked) and completes the caller's open intent, atomically.
create function vault_enclave.complete_card_step_up(p_tap_ref text)
returns boolean language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_caller uuid := vault_enclave.caller_user_id();
  v_intent vault_enclave.card_step_up_intents%rowtype;
  v_ok boolean;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'card_step_up_complete', 'denied', 'no_caller', null); return false;
  end if;
  select * into v_intent from vault_enclave.card_step_up_intents i
   where i.user_id = v_caller and i.completed_at is null and i.expires_at > v_now
   order by i.created_at desc limit 1 for update;
  if not found then
    perform vault_enclave.append_audit(v_caller, 'card_step_up_complete', 'denied', 'no_intent', null); return false;
  end if;
  select c.granted into v_ok from vault_enclave.consume_sdm_tap(p_tap_ref, 'step_up') c;
  if v_ok is not true then
    perform vault_enclave.append_audit(v_caller, 'card_step_up_complete', 'denied', 'tap_refused', null); return false;
  end if;
  update vault_enclave.card_step_up_intents set completed_at = v_now where intent_digest = v_intent.intent_digest;
  perform vault_enclave.append_audit(v_caller, 'card_step_up_complete', 'granted', v_intent.scope, null);
  return true;
end $$;

-- Claims a completed intent once, for the caller who opened it; returns its scope.
-- Not yet completed: null without an audit row (the dialog polls).
create function vault_enclave.claim_card_step_up(p_intent_ref text)
returns text language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_caller uuid := vault_enclave.caller_user_id();
  v_intent vault_enclave.card_step_up_intents%rowtype;
begin
  if v_caller is null or p_intent_ref is null or p_intent_ref !~ '^csu_[0-9a-f]{64}$' then
    perform vault_enclave.append_audit(v_caller, 'card_step_up_claim', 'denied', 'bad_request', null); return null;
  end if;
  select * into v_intent from vault_enclave.card_step_up_intents i
   where i.intent_digest = pg_catalog.sha256(pg_catalog.convert_to(p_intent_ref, 'UTF8')) for update;
  if not found or v_intent.user_id is distinct from v_caller then
    perform vault_enclave.append_audit(v_caller, 'card_step_up_claim', 'denied', 'unknown_intent', null); return null;
  end if;
  if v_intent.claimed_at is not null then
    perform vault_enclave.append_audit(v_caller, 'card_step_up_claim', 'denied', 'intent_spent', null); return null;
  end if;
  if v_intent.expires_at <= v_now then
    perform vault_enclave.append_audit(v_caller, 'card_step_up_claim', 'denied', 'intent_expired', null); return null;
  end if;
  if v_intent.completed_at is null then return null; end if;
  update vault_enclave.card_step_up_intents set claimed_at = v_now where intent_digest = v_intent.intent_digest;
  perform vault_enclave.append_audit(v_caller, 'card_step_up_claim', 'granted', v_intent.scope, null);
  return v_intent.scope;
end $$;

revoke all on function vault_enclave.member_card_factor() from public, rout_app;
revoke all on function vault_enclave.begin_card_step_up(text) from public, rout_app;
revoke all on function vault_enclave.pending_card_step_up() from public, rout_app;
revoke all on function vault_enclave.complete_card_step_up(text) from public, rout_app;
revoke all on function vault_enclave.claim_card_step_up(text) from public, rout_app;
grant execute on function vault_enclave.member_card_factor() to rout_app;
grant execute on function vault_enclave.begin_card_step_up(text) to rout_app;
grant execute on function vault_enclave.pending_card_step_up() to rout_app;
grant execute on function vault_enclave.complete_card_step_up(text) to rout_app;
grant execute on function vault_enclave.claim_card_step_up(text) to rout_app;
