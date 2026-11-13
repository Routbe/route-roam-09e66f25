-- 0257: SECURITY DEFINER search_path, batch 3 of the legacy functions (bookings).
--  * Every SECURITY DEFINER function must pin search_path to pg_catalog, so
--    nothing on the caller's path can be resolved inside it. These 31
--    rout_booking_* functions were created with search_path = public, pg_temp.
--  * Reviewed against Neon on 2026-11-13: the live definitions, owner
--    (neondb_owner) and grants were byte-identical to db/schema.snapshot.json
--    before this file. Every body names its tables, types and helper functions
--    with their schema (public.) except two, rewritten below:
--      - rout_booking_hold calls gen_random_bytes(), which comes from pgcrypto
--        and lives in the public schema; it is now public.gen_random_bytes().
--      - rout_booking_zone reads pg_timezone_names; it is now
--        pg_catalog.pg_timezone_names, because with search_path = pg_catalog a
--        session's temporary schema would be searched first for an
--        unqualified relation.
--    Their CREATE OR REPLACE keeps the signature, return type, language,
--    volatility, owner and grants; the body changes only in those names.
--  * Everything else they use (now(), sha256(), convert_to(), encode(),
--    decode(), gen_random_uuid(), tstzrange(), make_interval(), date_trunc(),
--    hashtextextended(), pg_advisory_xact_lock(), jsonb functions) lives in
--    pg_catalog. Exclusion constraints and column defaults are stored by OID.
--  * ALTER FUNCTION ... SET only replaces the search_path setting.
--    No table, column or data change.


-- Availability, limits and host selection (internal helpers)
alter function public.rout_booking_adjacent_ok(uuid, timestamptz, timestamptz) set search_path = pg_catalog;
alter function public.rout_booking_cache_free(uuid, timestamptz, timestamptz) set search_path = pg_catalog;
alter function public.rout_booking_edge_busy(uuid, timestamptz, timestamptz) set search_path = pg_catalog;
alter function public.rout_booking_host_free(uuid, uuid, timestamptz, timestamptz, timestamptz, integer) set search_path = pg_catalog;
alter function public.rout_booking_host_free_held(uuid, uuid, timestamptz, timestamptz, timestamptz, integer, uuid) set search_path = pg_catalog;
alter function public.rout_booking_within_limits(uuid, uuid, timestamptz, uuid) set search_path = pg_catalog;
alter function public.rout_booking_pick_hosts(uuid, timestamptz, uuid) set search_path = pg_catalog;
alter function public.rout_booking_lock_hosts(uuid[], timestamptz, timestamptz) set search_path = pg_catalog;
alter function public.rout_booking_lock_type(uuid, timestamptz) set search_path = pg_catalog;
alter function public.rout_booking_start_problem(uuid, timestamptz) set search_path = pg_catalog;
alter function public.rout_booking_horizon_end(integer, integer, text, timestamptz) set search_path = pg_catalog;
alter function public.rout_booking_type_zone(uuid) set search_path = pg_catalog;

-- Time zone lookup: pg_timezone_names qualified with pg_catalog.
CREATE OR REPLACE FUNCTION public.rout_booking_zone(p_zone text, p_host uuid)
 RETURNS text
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
  select coalesce(
    (select p_zone where p_zone is not null and exists (select 1 from pg_catalog.pg_timezone_names z where z.name = p_zone)),
    (select r.timezone from public.availability_rules r
      where r.user_id = p_host and exists (select 1 from pg_catalog.pg_timezone_names z where z.name = r.timezone)
      order by r.weekday, r.start_minute, r.id limit 1),
    'UTC')
$function$;

alter function public.rout_booking_stale_hosts(uuid, interval) set search_path = pg_catalog;

-- Public booking page
alter function public.rout_booking_type_public(uuid) set search_path = pg_catalog;
alter function public.rout_booking_public_event_type(uuid) set search_path = pg_catalog;
alter function public.rout_booking_public_type_for_handle(text, uuid) set search_path = pg_catalog;
alter function public.rout_booking_public_days(uuid, date, date) set search_path = pg_catalog;
alter function public.rout_booking_public_sessions(uuid, timestamptz, timestamptz, uuid) set search_path = pg_catalog;
alter function public.rout_booking_public_constraints(uuid, timestamptz, timestamptz, uuid) set search_path = pg_catalog;

-- Holds, bookings, payment and maintenance
alter function public.rout_booking_create(uuid, timestamptz, text, text, text, text, jsonb) set search_path = pg_catalog;
alter function public.rout_booking_create(uuid, timestamptz, text, text, text, text, jsonb, uuid, text) set search_path = pg_catalog;

-- Soft-lock: gen_random_bytes() qualified with public (pgcrypto).
CREATE OR REPLACE FUNCTION public.rout_booking_hold(p_event_type uuid, p_start timestamp with time zone, p_client text, p_replace uuid, p_replace_secret text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
declare
  t public.booking_event_types%rowtype; problem text; chosen uuid[]; h uuid;
  secret text := encode(public.gen_random_bytes(32), 'hex'); hid uuid := gen_random_uuid();
  exp timestamptz := now() + interval '5 minutes'; client bytea; bs timestamptz; be timestamptz;
begin
  if not public.rout_booking_type_public(p_event_type) then return jsonb_build_object('ok', false, 'reason', 'inactive'); end if;
  if p_client is null or p_client !~ '^[a-f0-9]{64}$' then return jsonb_build_object('ok', false, 'reason', 'invalid_input'); end if;
  client := decode(p_client, 'hex');
  select * into t from public.booking_event_types where id = p_event_type;
  if p_replace is not null and p_replace_secret ~ '^[a-f0-9]{64}$' then
    delete from public.booking_holds where hold_id = p_replace and secret_digest = sha256(convert_to(p_replace_secret, 'UTF8'));
  end if;
  problem := public.rout_booking_start_problem(t.id, p_start);
  if problem is not null then return jsonb_build_object('ok', false, 'reason', problem); end if;
  if (select count(distinct hold_id) from public.booking_holds where client_digest = client and expires_at > now()) >= 3 then
    return jsonb_build_object('ok', false, 'reason', 'too_many_holds');
  end if;
  perform public.rout_booking_lock_type(t.id, p_start);
  chosen := public.rout_booking_pick_hosts(t.id, p_start, null);
  if chosen is null then return jsonb_build_object('ok', false, 'reason', 'slot_taken'); end if;
  bs := p_start - make_interval(mins => t.buffer_before_minutes);
  be := p_start + make_interval(mins => t.duration_minutes + t.buffer_after_minutes);
  begin
    foreach h in array chosen loop
      insert into public.booking_holds (hold_id, host_user_id, event_type_id, start_utc, block_start_utc, block_end_utc,
        shared_slot, secret_digest, client_digest, expires_at)
      values (hid, h, t.id, p_start, bs, be, greatest(1, t.resource_capacity) > 1,
        sha256(convert_to(secret, 'UTF8')), client, exp);
    end loop;
  exception when exclusion_violation then
    return jsonb_build_object('ok', false, 'reason', 'slot_taken');
  end;
  return jsonb_build_object('ok', true, 'holdId', hid, 'secret', secret, 'expiresAt', exp, 'startUtc', p_start);
end $function$;

alter function public.rout_booking_hold_release(uuid, text) set search_path = pg_catalog;
alter function public.rout_booking_group_ids(uuid) set search_path = pg_catalog;
alter function public.rout_booking_guest_view(uuid, text) set search_path = pg_catalog;
alter function public.rout_booking_set_checkout(uuid, text) set search_path = pg_catalog;
alter function public.rout_booking_confirm_paid(uuid, text) set search_path = pg_catalog;
alter function public.rout_booking_release_hold(uuid) set search_path = pg_catalog;
alter function public.rout_booking_release_expired(integer) set search_path = pg_catalog;
alter function public.rout_booking_due_calendars(integer) set search_path = pg_catalog;
