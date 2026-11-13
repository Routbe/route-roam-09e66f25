-- 0246 (EXPAND): ROUT Card activation with the first physical tap, plus the
-- admin batch overview. Additive only: no existing function changes.
--
-- The tap is verified exactly as in 0245 (server: PICCData + AN10922 CMAC,
-- then confirm_sdm_tap mints a single-use tap_ grant). activate_member_card
-- spends that grant for the new purpose 'activation' and links the card to the
-- signed-in caller (taken from the transaction context, never a parameter).
-- Only a card without owner, not revoked and never activated can be claimed;
-- when the manifest carried an activation code, its hash must match.
-- Every outcome is written to the hash-chained vault audit log; every
-- failure answers false (fail closed) so the audit row commits.

alter table vault_enclave.sdm_batch_cards add column initial_counter integer;
alter table vault_enclave.sdm_batch_cards add constraint sdm_batch_cards_initial_counter_range
  check (initial_counter is null or initial_counter between 0 and 16777214);

alter table vault_enclave.sdm_tap_grants drop constraint sdm_tap_grants_purpose;
alter table vault_enclave.sdm_tap_grants add constraint sdm_tap_grants_purpose
  check (consumed_for is null or consumed_for in ('public_proof', 'step_up', 'activation'));

alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                    'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export'));

create function vault_enclave.activate_member_card(p_tap_ref text, p_activation_hash bytea)
returns boolean language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_caller uuid := vault_enclave.caller_user_id();
  v_grant vault_enclave.sdm_tap_grants%rowtype;
  v_card vault_enclave.sdm_batch_cards%rowtype;
begin
  if v_caller is null then
    perform vault_enclave.append_audit(null, 'sdm_card_activate', 'denied', 'no_caller', null); return false;
  end if;
  if p_tap_ref is null or p_tap_ref !~ '^tap_[0-9a-f]{64}$'
     or (p_activation_hash is not null and octet_length(p_activation_hash) <> 32) then
    perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'denied', 'bad_request', null); return false;
  end if;
  select * into v_grant from vault_enclave.sdm_tap_grants g
   where g.grant_digest = pg_catalog.sha256(pg_catalog.convert_to(p_tap_ref, 'UTF8')) for update;
  if not found or v_grant.consumed_at is not null or v_grant.expires_at < v_now then
    perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'denied',
      case when not found then 'unknown_grant' when v_grant.consumed_at is not null then 'grant_spent' else 'grant_expired' end, null);
    return false;
  end if;
  -- The grant is spent whatever happens next: one tap, one answer.
  update vault_enclave.sdm_tap_grants set consumed_at = v_now, consumed_for = 'activation' where grant_digest = v_grant.grant_digest;
  select * into v_card from vault_enclave.sdm_batch_cards c where c.card_id = v_grant.card_id for update;
  if v_card.revoked_at is not null then
    perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'denied', 'card_revoked', null); return false;
  end if;
  if v_card.owner_user_id is not null or v_card.activated_at is not null then
    perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'denied', 'card_claimed', null); return false;
  end if;
  if v_card.activation_hash is not null and (p_activation_hash is null or p_activation_hash <> v_card.activation_hash) then
    perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'denied', 'activation_code_mismatch', null); return false;
  end if;
  update vault_enclave.sdm_batch_cards
     set owner_user_id = v_caller, activated_at = v_now, initial_counter = last_counter
   where card_id = v_card.card_id;
  perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'granted', 'ok', null);
  return true;
end $$;

-- Admin overview: batches with card counts. No keys, refs or hashes leave.
create function vault_enclave.list_sdm_batches()
returns table (batch_id uuid, fleet_id uuid, label text, created_at timestamptz, exported_at timestamptz,
               retired_at timestamptz, cards integer, active_cards integer)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
begin
  if v_caller is null or not public.rout_is_admin_member(v_caller) then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_list', 'denied', 'not_admin', null); return;
  end if;
  return query
    select b.batch_id, b.fleet_id, b.label, b.created_at, b.exported_at, b.retired_at,
           (select count(*)::int from vault_enclave.sdm_batch_cards c where c.batch_id = b.batch_id),
           (select count(*)::int from vault_enclave.sdm_batch_cards c where c.batch_id = b.batch_id and c.owner_user_id is not null and c.revoked_at is null)
      from vault_enclave.sdm_batches b
     order by b.created_at desc
     limit 200;
end $$;

-- Admin: records that the station configuration was exported once.
create function vault_enclave.mark_sdm_batch_exported(p_batch_id uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_rows int;
begin
  if v_caller is null or not public.rout_is_admin_member(v_caller) then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_export', 'denied', 'not_admin', null); return false;
  end if;
  update vault_enclave.sdm_batches set exported_at = coalesce(exported_at, pg_catalog.clock_timestamp())
   where batch_id = p_batch_id and retired_at is null;
  get diagnostics v_rows = row_count;
  perform vault_enclave.append_audit(v_caller, 'sdm_batch_export', case when v_rows = 1 then 'granted' else 'denied' end,
    case when v_rows = 1 then 'ok' else 'unknown_batch' end, null);
  return v_rows = 1;
end $$;

revoke all on function vault_enclave.activate_member_card(text, bytea) from public, rout_app;
revoke all on function vault_enclave.list_sdm_batches() from public, rout_app;
revoke all on function vault_enclave.mark_sdm_batch_exported(uuid) from public, rout_app;
grant execute on function vault_enclave.activate_member_card(text, bytea) to rout_app;
grant execute on function vault_enclave.list_sdm_batches() to rout_app;
grant execute on function vault_enclave.mark_sdm_batch_exported(uuid) to rout_app;
