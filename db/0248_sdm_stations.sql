-- 0248 (EXPAND): registered personalisation stations and the key export.
-- A station is pinned by its P-256 public key (raw 65-byte point). The batch keys
-- leave ROUT only HPKE-sealed to a registered, non-retired station; the vault hands
-- the still RVE1-sealed envelopes to the app only inside mark_sdm_batch_exported,
-- whose audit row commits in the same transaction (no envelope without a log line).

create table vault_enclave.sdm_stations (
  station_id uuid primary key default gen_random_uuid(),
  label text not null,
  public_key bytea not null unique,
  fingerprint bytea not null unique,
  registered_by uuid not null references public.users(id) on delete restrict,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  retired_at timestamptz,
  constraint sdm_stations_label check (char_length(label) between 1 and 80),
  constraint sdm_stations_key check (octet_length(public_key) = 65 and pg_catalog.get_byte(public_key, 0) = 4),
  constraint sdm_stations_fingerprint check (fingerprint = pg_catalog.sha256(public_key))
);
revoke all on table vault_enclave.sdm_stations from public, rout_app;
alter table vault_enclave.sdm_stations enable row level security;
create policy deny_all on vault_enclave.sdm_stations as restrictive for all to public using (false) with check (false);

alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                    'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export',
                    'sdm_station_register', 'sdm_station_list', 'sdm_station_retire'));

-- Admin: pins a station key. The app validates the point is on the curve first.
create function vault_enclave.register_sdm_station(p_label text, p_public_key bytea)
returns uuid language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_label text := pg_catalog.btrim(coalesce(p_label, ''));
  v_id uuid;
begin
  if v_caller is null or not public.rout_is_admin_member(v_caller) then
    perform vault_enclave.append_audit(v_caller, 'sdm_station_register', 'denied', 'not_admin', null); return null;
  end if;
  if char_length(v_label) not between 1 and 80 or p_public_key is null
     or octet_length(p_public_key) <> 65 or pg_catalog.get_byte(p_public_key, 0) <> 4 then
    perform vault_enclave.append_audit(v_caller, 'sdm_station_register', 'denied', 'bad_request', null); return null;
  end if;
  if exists (select 1 from vault_enclave.sdm_stations s where s.public_key = p_public_key) then
    perform vault_enclave.append_audit(v_caller, 'sdm_station_register', 'denied', 'duplicate_key', null); return null;
  end if;
  insert into vault_enclave.sdm_stations (label, public_key, fingerprint, registered_by)
  values (v_label, p_public_key, pg_catalog.sha256(p_public_key), v_caller) returning station_id into v_id;
  perform vault_enclave.append_audit(v_caller, 'sdm_station_register', 'granted',
    'fp_' || pg_catalog.encode(pg_catalog.sha256(p_public_key), 'hex'), null);
  return v_id;
end $$;

-- Admin: stations with their fingerprint (public data, but only admins need it).
create function vault_enclave.list_sdm_stations()
returns table (station_id uuid, label text, fingerprint bytea, created_at timestamptz, retired_at timestamptz)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
begin
  if v_caller is null or not public.rout_is_admin_member(v_caller) then
    perform vault_enclave.append_audit(v_caller, 'sdm_station_list', 'denied', 'not_admin', null); return;
  end if;
  return query
    select s.station_id, s.label, s.fingerprint, s.created_at, s.retired_at
      from vault_enclave.sdm_stations s
     order by s.retired_at nulls first, s.created_at desc
     limit 50;
end $$;

-- Admin: a retired station never receives keys again (irreversible).
create function vault_enclave.retire_sdm_station(p_station_id uuid)
returns boolean language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_rows int;
begin
  if v_caller is null or not public.rout_is_admin_member(v_caller) then
    perform vault_enclave.append_audit(v_caller, 'sdm_station_retire', 'denied', 'not_admin', null); return false;
  end if;
  update vault_enclave.sdm_stations set retired_at = pg_catalog.clock_timestamp()
   where station_id = p_station_id and retired_at is null;
  get diagnostics v_rows = row_count;
  perform vault_enclave.append_audit(v_caller, 'sdm_station_retire', case when v_rows = 1 then 'granted' else 'denied' end,
    case when v_rows = 1 then 'ok' else 'unknown_station' end, null);
  return v_rows = 1;
end $$;

-- Admin: the export. Marks the batch exported, logs batch + station fingerprint on the
-- hash chain and, in the same transaction, returns the station key and the batch and
-- fleet envelopes still sealed under the server vault key. Every denial returns
-- granted = false and still commits its audit row.
create function vault_enclave.mark_sdm_batch_exported(p_batch_id uuid, p_station_id uuid)
returns table (granted boolean, station_public_key bytea, batch_owner uuid, batch_payload bytea,
               fleet_owner uuid, fleet_payload bytea)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_batch vault_enclave.sdm_batches%rowtype;
  v_fleet vault_enclave.sdm_fleet_keys%rowtype;
  v_station vault_enclave.sdm_stations%rowtype;
  v_batch_payload bytea;
  v_fleet_payload bytea;
begin
  if v_caller is null or not public.rout_is_admin_member(v_caller) then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_export', 'denied', 'not_admin', null);
    return query select false, null::bytea, null::uuid, null::bytea, null::uuid, null::bytea; return;
  end if;
  select * into v_station from vault_enclave.sdm_stations s where s.station_id = p_station_id for share;
  if not found or v_station.retired_at is not null then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_export', 'denied', 'unknown_station', null);
    return query select false, null::bytea, null::uuid, null::bytea, null::uuid, null::bytea; return;
  end if;
  select * into v_batch from vault_enclave.sdm_batches b where b.batch_id = p_batch_id for update;
  if not found or v_batch.retired_at is not null then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_export', 'denied', 'unknown_batch', null);
    return query select false, null::bytea, null::uuid, null::bytea, null::uuid, null::bytea; return;
  end if;
  select * into v_fleet from vault_enclave.sdm_fleet_keys f where f.fleet_id = v_batch.fleet_id;
  select t.encrypted_payload into v_batch_payload from vault_enclave.opaque_tokens t
   where t.token_ref = v_batch.sdm_ref and t.owner_user_id = v_batch.owner_user_id and t.token_type = 'sdm';
  select t.encrypted_payload into v_fleet_payload from vault_enclave.opaque_tokens t
   where t.token_ref = v_fleet.sdm_ref and t.owner_user_id = v_fleet.owner_user_id and t.token_type = 'sdm';
  if v_fleet.fleet_id is null or v_fleet.retired_at is not null or v_batch_payload is null or v_fleet_payload is null then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_export', 'denied', 'keys_unavailable', v_batch.sdm_ref);
    return query select false, null::bytea, null::uuid, null::bytea, null::uuid, null::bytea; return;
  end if;
  update vault_enclave.sdm_batches set exported_at = coalesce(exported_at, pg_catalog.clock_timestamp())
   where batch_id = v_batch.batch_id;
  perform vault_enclave.append_audit(v_caller, 'sdm_batch_export', 'granted',
    'fp_' || pg_catalog.encode(v_station.fingerprint, 'hex'), v_batch.sdm_ref);
  return query select true, v_station.public_key, v_batch.owner_user_id, v_batch_payload, v_fleet.owner_user_id, v_fleet_payload;
end $$;

revoke all on function vault_enclave.register_sdm_station(text, bytea) from public, rout_app;
revoke all on function vault_enclave.list_sdm_stations() from public, rout_app;
revoke all on function vault_enclave.retire_sdm_station(uuid) from public, rout_app;
revoke all on function vault_enclave.mark_sdm_batch_exported(uuid, uuid) from public, rout_app;
grant execute on function vault_enclave.register_sdm_station(text, bytea) to rout_app;
grant execute on function vault_enclave.list_sdm_stations() to rout_app;
grant execute on function vault_enclave.retire_sdm_station(uuid) to rout_app;
grant execute on function vault_enclave.mark_sdm_batch_exported(uuid, uuid) to rout_app;
