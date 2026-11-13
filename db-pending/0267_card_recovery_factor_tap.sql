-- 0267 — EXPAND: a live ROUT Card tap can confirm "this is my own card" for the
-- recovery vault (2-of-4, db/0266), without completing any step-up.
--
-- Why: before the browser seals a recovery shard to a card's fragment secret
-- (src/lib/crypto-enclave/card-factor.ts), the tap that carried that fragment
-- must be a genuine, unrevoked ROUT Card owned by the signed-in member. Without
-- this, a crafted /t#rk1=… link opened during setup could make a member seal
-- a share to a secret someone else knows.
--
-- Only adds the purpose 'recovery_factor' to consume_sdm_tap: same single-use
-- grant, same owner rule as 'step_up' (caller from the transaction context,
-- never a parameter), its own audit reason. Signature, owner and rights stay.

alter table vault_enclave.sdm_tap_grants drop constraint if exists sdm_tap_grants_purpose;
alter table vault_enclave.sdm_tap_grants add constraint sdm_tap_grants_purpose
  check (consumed_for is null or consumed_for in ('public_proof', 'step_up', 'recovery_factor'));

-- Spends a tap_ grant once, for one purpose. public_proof needs no session and
-- reveals only whether the card is activated; step_up and recovery_factor only
-- work for the card's own owner (the caller from the transaction context).
create or replace function vault_enclave.consume_sdm_tap(p_tap_ref text, p_purpose text)
returns table (granted boolean, card_state text)
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_caller uuid := vault_enclave.caller_user_id();
  v_grant vault_enclave.sdm_tap_grants%rowtype;
  v_card vault_enclave.sdm_batch_cards%rowtype;
  v_owned_only boolean := p_purpose in ('step_up', 'recovery_factor');
begin
  if p_tap_ref is null or p_tap_ref !~ '^tap_[0-9a-f]{64}$' or p_purpose is null
     or p_purpose not in ('public_proof', 'step_up', 'recovery_factor') then
    perform vault_enclave.append_audit(v_caller, 'sdm_tap_consume', 'denied', 'bad_request', null);
    return query select false, null::text; return;
  end if;
  select * into v_grant from vault_enclave.sdm_tap_grants g
   where g.grant_digest = pg_catalog.sha256(pg_catalog.convert_to(p_tap_ref, 'UTF8')) for update;
  if not found or v_grant.consumed_at is not null or v_grant.expires_at < v_now then
    perform vault_enclave.append_audit(v_caller, 'sdm_tap_consume', 'denied',
      case when not found then 'unknown_grant' when v_grant.consumed_at is not null then 'grant_spent' else 'grant_expired' end, null);
    return query select false, null::text; return;
  end if;
  select * into v_card from vault_enclave.sdm_batch_cards c where c.card_id = v_grant.card_id;
  if v_card.revoked_at is not null or (v_owned_only and (v_caller is null or v_card.owner_user_id is distinct from v_caller)) then
    update vault_enclave.sdm_tap_grants set consumed_at = v_now, consumed_for = p_purpose where grant_digest = v_grant.grant_digest;
    perform vault_enclave.append_audit(v_caller, 'sdm_tap_consume', 'denied',
      case when v_card.revoked_at is not null then 'card_revoked' else 'not_card_owner' end, null);
    return query select false, null::text; return;
  end if;
  update vault_enclave.sdm_tap_grants set consumed_at = v_now, consumed_for = p_purpose where grant_digest = v_grant.grant_digest;
  perform vault_enclave.append_audit(v_caller, 'sdm_tap_consume', 'granted', p_purpose, null);
  return query select true, case when v_card.owner_user_id is null then 'unactivated' else 'active' end;
end $$;

revoke all on function vault_enclave.consume_sdm_tap(text, text) from public;
grant execute on function vault_enclave.consume_sdm_tap(text, text) to rout_app;

-- In-transaction proof: PUBLIC executes nothing here, rout_app still has no table rights.
do $$
begin
  if has_function_privilege('public', 'vault_enclave.consume_sdm_tap(text, text)', 'execute') then
    raise exception '0267: PUBLIC must not execute consume_sdm_tap';
  end if;
  if has_table_privilege('rout_app', 'vault_enclave.sdm_tap_grants', 'select, insert, update, delete')
     or has_table_privilege('rout_app', 'vault_enclave.sdm_batch_cards', 'select, insert, update, delete') then
    raise exception '0267: rout_app must not have table rights in vault_enclave';
  end if;
end $$;
