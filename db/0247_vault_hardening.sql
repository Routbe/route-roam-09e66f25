-- 0247 (EXPAND): defense in depth for the vault enclave.
--  1. Activation codes are compared with a fixed 32-step XOR accumulation, never `=`/`<>`.
--  2. Explicit restrictive deny-all RLS policies on every vault_enclave table, so a future
--     accidental GRANT or permissive policy still returns no rows. The tables are owned by the
--     migration owner without FORCE, so the SECURITY DEFINER functions (same owner) keep working.
-- Additive only; activate_member_card keeps its signature and grants.

create function vault_enclave.ct_equal_32(p_a bytea, p_b bytea)
returns boolean language plpgsql immutable security invoker set search_path = pg_catalog as $$
declare
  v_zero constant bytea := pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex');
  v_bad integer := 0;
  v_a bytea := p_a;
  v_b bytea := p_b;
  v_diff integer := 0;
begin
  -- Wrong length or null still walks all 32 bytes, against a zero buffer.
  if v_a is null or pg_catalog.octet_length(v_a) <> 32 then v_a := v_zero; v_bad := 1; end if;
  if v_b is null or pg_catalog.octet_length(v_b) <> 32 then v_b := v_zero; v_bad := 1; end if;
  for i in 0..31 loop
    v_diff := v_diff | (pg_catalog.get_byte(v_a, i) # pg_catalog.get_byte(v_b, i));
  end loop;
  return (v_diff | v_bad) = 0;
end $$;
revoke all on function vault_enclave.ct_equal_32(bytea, bytea) from public, rout_app;

create or replace function vault_enclave.activate_member_card(p_tap_ref text, p_activation_hash bytea)
returns boolean language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_caller uuid := vault_enclave.caller_user_id();
  v_grant vault_enclave.sdm_tap_grants%rowtype;
  v_card vault_enclave.sdm_batch_cards%rowtype;
  v_code_ok boolean;
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
  -- Always run the full constant-time comparison, also when no code is required.
  v_code_ok := vault_enclave.ct_equal_32(p_activation_hash, v_card.activation_hash);
  if v_card.revoked_at is not null then
    perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'denied', 'card_revoked', null); return false;
  end if;
  if v_card.owner_user_id is not null or v_card.activated_at is not null then
    perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'denied', 'card_claimed', null); return false;
  end if;
  if v_card.activation_hash is not null and not v_code_ok then
    perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'denied', 'activation_code_mismatch', null); return false;
  end if;
  update vault_enclave.sdm_batch_cards
     set owner_user_id = v_caller, activated_at = v_now, initial_counter = last_counter
   where card_id = v_card.card_id;
  perform vault_enclave.append_audit(v_caller, 'sdm_card_activate', 'granted', 'ok', null);
  return true;
end $$;

alter table vault_enclave.audit_logs enable row level security;
alter table vault_enclave.opaque_tokens enable row level security;
alter table vault_enclave.sdm_batch_cards enable row level security;
alter table vault_enclave.sdm_batches enable row level security;
alter table vault_enclave.sdm_cards enable row level security;
alter table vault_enclave.sdm_fleet_keys enable row level security;
alter table vault_enclave.sdm_recovery_attempts enable row level security;
alter table vault_enclave.sdm_tap_attempts enable row level security;
alter table vault_enclave.sdm_tap_grants enable row level security;
alter table vault_enclave.server_keys enable row level security;
alter table vault_enclave.step_up_proofs enable row level security;

create policy deny_all on vault_enclave.audit_logs as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.opaque_tokens as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.sdm_batch_cards as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.sdm_batches as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.sdm_cards as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.sdm_fleet_keys as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.sdm_recovery_attempts as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.sdm_tap_attempts as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.sdm_tap_grants as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.server_keys as restrictive for all to public using (false) with check (false);
create policy deny_all on vault_enclave.step_up_proofs as restrictive for all to public using (false) with check (false);
