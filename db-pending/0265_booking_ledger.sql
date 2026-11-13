-- 0265 — EXPAND: immutable, hash-chained and server-signed booking ledger.
--
-- Every change to public.bookings is written by the database itself into
-- public.booking_events: no caller can add, skip, edit or remove an event.
--   * One chain per host. Each event's entry_hash = SHA-256(prev_hash ||
--     UTF-8(preimage)); the first prev_hash is SHA-256 of a genesis string
--     naming the host, so a chain can never be spliced into another host's.
--     (host_user_id, prev_hash) is unique: a chain cannot fork.
--   * The preimage is a length-prefixed encoding ("v<len>:<value>" or "n" for
--     null) of every field, so no value can be crafted to shift a boundary.
--   * Guest name, e-mail, note, intake answers and payment references never
--     enter the ledger. The event carries detail_commit = SHA-256(salt ||
--     those fields) with a 256-bit salt per booking in booking_ledger_salts.
--     Deleting a booking deletes its salt (crypto-shredding): the immutable
--     ledger then no longer links to the personal data, which keeps erasure
--     possible.
--   * Ed25519 signatures come from the server (ROUT_BOOKING_LEDGER_SIGNING_KEY),
--     never from the database: booking_event_attestations only stores them.
--     The signer extends only from a predecessor it has itself signed, so a
--     history rewritten after signing can never be signed again; trusted public
--     keys are configured out of band, never read from this database.
--   * UPDATE, DELETE and TRUNCATE on the ledger tables are refused by triggers.
--   * The chain is appended under a per-host advisory lock inside the same
--     transaction as the booking write.
-- rout_app gets no table rights at all, only the owner-scoped functions below
-- (host = rout.current_user_id) and one session-less function that returns
-- nothing but host ids with unsigned events. Existing bookings are imported
-- as 'imported' events. Only adds objects: nothing existing is changed.

-- ------------------------------------------------------------------ tables
create table if not exists public.booking_events (
  host_user_id     uuid        not null,
  host_seq         bigint      not null check (host_seq >= 1),
  occurred_at      timestamptz not null,
  booking_id       uuid        not null,
  group_id         uuid,
  event_type_id    uuid        not null,
  workspace_id     uuid,
  kind             text        not null check (kind in ('imported', 'created', 'status_changed', 'rescheduled', 'updated',
                                                         'transferred_in', 'transferred_out', 'deleted')),
  status           text        not null,
  start_utc        timestamptz not null,
  end_utc          timestamptz not null,
  block_start_utc  timestamptz not null,
  block_end_utc    timestamptz not null,
  ics_sequence     integer     not null,
  detail_commit    bytea       check (detail_commit is null or octet_length(detail_commit) = 32),
  actor_user_id    uuid,
  prev_hash        bytea       not null check (octet_length(prev_hash) = 32),
  entry_hash       bytea       not null unique check (octet_length(entry_hash) = 32),
  primary key (host_user_id, host_seq),
  unique (host_user_id, prev_hash),
  check ((kind in ('deleted', 'transferred_out')) = (detail_commit is null))
);
create index if not exists booking_events_booking_idx on public.booking_events (host_user_id, booking_id, host_seq desc);

create table if not exists public.booking_event_attestations (
  host_user_id uuid        not null,
  host_seq     bigint      not null,
  key_id       text        not null check (key_id ~ '^[0-9a-f]{32}$'),
  signature    bytea       not null check (octet_length(signature) = 64),
  signed_at    timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (host_user_id, host_seq, key_id),
  foreign key (host_user_id, host_seq) references public.booking_events (host_user_id, host_seq)
);

create table if not exists public.booking_ledger_salts (
  booking_id uuid  primary key references public.bookings (id) on delete cascade,
  salt       bytea not null check (octet_length(salt) = 32)
);

revoke all on table public.booking_events, public.booking_event_attestations, public.booking_ledger_salts from public;
do $$ begin
  if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
    revoke all on table public.booking_events, public.booking_event_attestations, public.booking_ledger_salts from rout_app;
  end if;
end $$;
alter table public.booking_events enable row level security;
alter table public.booking_event_attestations enable row level security;
alter table public.booking_ledger_salts enable row level security;

-- ------------------------------------------------------------------ immutability
create or replace function public.rout_booking_ledger_immutable() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
  raise exception 'booking_ledger_immutable' using errcode = '42501';
end $$;

drop trigger if exists booking_events_no_update on public.booking_events;
create trigger booking_events_no_update before update or delete on public.booking_events
  for each row execute function public.rout_booking_ledger_immutable();
drop trigger if exists booking_events_no_truncate on public.booking_events;
create trigger booking_events_no_truncate before truncate on public.booking_events
  for each statement execute function public.rout_booking_ledger_immutable();
drop trigger if exists booking_event_attestations_no_update on public.booking_event_attestations;
create trigger booking_event_attestations_no_update before update or delete on public.booking_event_attestations
  for each row execute function public.rout_booking_ledger_immutable();
drop trigger if exists booking_event_attestations_no_truncate on public.booking_event_attestations;
create trigger booking_event_attestations_no_truncate before truncate on public.booking_event_attestations
  for each statement execute function public.rout_booking_ledger_immutable();

-- ------------------------------------------------------------------ encoding
-- "n" for null, otherwise "v" || character count || ":" || value.
create or replace function public.rout_ledger_field(p text) returns text
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select case when p is null then 'n' else 'v' || pg_catalog.char_length(p)::text || ':' || p end
$$;

create or replace function public.rout_ledger_ts(p timestamptz) returns text
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.to_char(p at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;

create or replace function public.rout_booking_ledger_genesis(p_host uuid) returns bytea
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.sha256(pg_catalog.convert_to('rout.booking-ledger.v1|genesis|' || p_host::text, 'UTF8'))
$$;

-- The exact bytes that are hashed (and that the TypeScript verifier parses).
create or replace function public.rout_booking_ledger_preimage(e public.booking_events) returns text
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select 'rout.booking-ledger.v1'
    || public.rout_ledger_field(e.host_user_id::text)
    || public.rout_ledger_field(e.host_seq::text)
    || public.rout_ledger_field(public.rout_ledger_ts(e.occurred_at))
    || public.rout_ledger_field(e.booking_id::text)
    || public.rout_ledger_field(e.group_id::text)
    || public.rout_ledger_field(e.event_type_id::text)
    || public.rout_ledger_field(e.workspace_id::text)
    || public.rout_ledger_field(e.kind)
    || public.rout_ledger_field(e.status)
    || public.rout_ledger_field(public.rout_ledger_ts(e.start_utc))
    || public.rout_ledger_field(public.rout_ledger_ts(e.end_utc))
    || public.rout_ledger_field(public.rout_ledger_ts(e.block_start_utc))
    || public.rout_ledger_field(public.rout_ledger_ts(e.block_end_utc))
    || public.rout_ledger_field(e.ics_sequence::text)
    || public.rout_ledger_field(pg_catalog.encode(e.detail_commit, 'hex'))
    || public.rout_ledger_field(e.actor_user_id::text)
$$;

create or replace function public.rout_booking_ledger_hash(e public.booking_events) returns bytea
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.sha256(e.prev_hash || pg_catalog.convert_to(public.rout_booking_ledger_preimage(e), 'UTF8'))
$$;

-- Commitment to the private fields of a booking row (never stored in the ledger).
create or replace function public.rout_booking_detail_commit(b public.bookings, p_salt bytea) returns bytea
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.sha256(p_salt || pg_catalog.convert_to('rout.booking-detail.v1'
    || public.rout_ledger_field(b.guest_name)
    || public.rout_ledger_field(b.guest_email)
    || public.rout_ledger_field(b.guest_timezone)
    || public.rout_ledger_field(b.guest_note)
    || public.rout_ledger_field(b.intake_answers::text)
    || public.rout_ledger_field(b.stripe_checkout_session_id)
    || public.rout_ledger_field(public.rout_ledger_ts(b.hold_expires_at))
    || public.rout_ledger_field(b.shared_slot::text)
    || public.rout_ledger_field(b.ics_uid), 'UTF8'))
$$;

-- ------------------------------------------------------------------ append (internal)
create or replace function public.rout_booking_ledger_append(b public.bookings, p_kind text, p_commit bytea)
returns void language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_last public.booking_events;
  v_ctx text := pg_catalog.current_setting('rout.current_user_id', true);
  e public.booking_events;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('booking-ledger:' || b.host_user_id::text, 0));
  select * into v_last from public.booking_events x
   where x.host_user_id = b.host_user_id order by x.host_seq desc limit 1;
  e.host_user_id := b.host_user_id;
  e.host_seq := coalesce(v_last.host_seq, 0) + 1;
  e.prev_hash := coalesce(v_last.entry_hash, public.rout_booking_ledger_genesis(b.host_user_id));
  -- Never earlier than the previous event: the chain's clock only moves forward.
  e.occurred_at := greatest(pg_catalog.clock_timestamp(), coalesce(v_last.occurred_at, '-infinity'::timestamptz));
  e.booking_id := b.id;
  e.group_id := b.group_id;
  e.event_type_id := b.event_type_id;
  e.workspace_id := b.workspace_id;
  e.kind := p_kind;
  e.status := b.status;
  e.start_utc := b.start_utc;
  e.end_utc := b.end_utc;
  e.block_start_utc := b.block_start_utc;
  e.block_end_utc := b.block_end_utc;
  e.ics_sequence := b.sequence;
  e.detail_commit := p_commit;
  e.actor_user_id := case when v_ctx ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then v_ctx::uuid end;
  e.entry_hash := public.rout_booking_ledger_hash(e);
  insert into public.booking_events values (e.*);
end $$;

create or replace function public.rout_booking_ledger_salt(p_booking uuid) returns bytea
language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v bytea;
begin
  select s.salt into v from public.booking_ledger_salts s where s.booking_id = p_booking;
  if v is null then
    v := pg_catalog.decode(pg_catalog.replace(pg_catalog.gen_random_uuid()::text || pg_catalog.gen_random_uuid()::text, '-', ''), 'hex');
    v := pg_catalog.sha256(v || pg_catalog.convert_to(pg_catalog.clock_timestamp()::text || p_booking::text, 'UTF8'));
    insert into public.booking_ledger_salts (booking_id, salt) values (p_booking, v);
  end if;
  return v;
end $$;

-- ------------------------------------------------------------------ capture trigger
-- SECURITY DEFINER: the trigger runs for whoever writes bookings (rout_app
-- included), and that caller has no rights on the ledger tables.
create or replace function public.rout_booking_ledger_capture() returns trigger
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_salt bytea;
  v_old bytea;
  v_new bytea;
begin
  if tg_op = 'INSERT' then
    v_salt := public.rout_booking_ledger_salt(new.id);
    perform public.rout_booking_ledger_append(new, 'created', public.rout_booking_detail_commit(new, v_salt));
  elsif tg_op = 'DELETE' then
    perform public.rout_booking_ledger_append(old, 'deleted', null);
  else
    v_salt := public.rout_booking_ledger_salt(new.id);
    if new.id <> old.id then
      raise exception 'booking_id_immutable' using errcode = '42501';
    end if;
    v_new := public.rout_booking_detail_commit(new, v_salt);
    if new.host_user_id <> old.host_user_id then
      perform public.rout_booking_ledger_append(old, 'transferred_out', null);
      perform public.rout_booking_ledger_append(new, 'transferred_in', v_new);
      return null;
    end if;
    v_old := public.rout_booking_detail_commit(old, v_salt);
    if new.status is distinct from old.status then
      perform public.rout_booking_ledger_append(new, 'status_changed', v_new);
    elsif (new.start_utc, new.end_utc, new.block_start_utc, new.block_end_utc)
          is distinct from (old.start_utc, old.end_utc, old.block_start_utc, old.block_end_utc) then
      perform public.rout_booking_ledger_append(new, 'rescheduled', v_new);
    elsif v_new <> v_old or (new.sequence, new.event_type_id, new.group_id, new.workspace_id)
          is distinct from (old.sequence, old.event_type_id, old.group_id, old.workspace_id) then
      perform public.rout_booking_ledger_append(new, 'updated', v_new);
    end if;
  end if;
  return null;
end $$;

drop trigger if exists bookings_ledger_capture on public.bookings;
create trigger bookings_ledger_capture after insert or update or delete on public.bookings
  for each row execute function public.rout_booking_ledger_capture();

-- ------------------------------------------------------------------ owner-scoped reads
create or replace function public.rout_booking_ledger_caller() returns uuid
language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
declare v text := pg_catalog.current_setting('rout.current_user_id', true);
begin
  if v is null or v !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then return null; end if;
  return v::uuid;
end $$;

-- The caller's own chain, after p_after, with the exact preimage and hashes.
create or replace function public.rout_booking_ledger_entries(p_after bigint, p_limit integer)
returns table (host_seq bigint, preimage text, prev_hash text, entry_hash text)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select e.host_seq, public.rout_booking_ledger_preimage(e), pg_catalog.encode(e.prev_hash, 'hex'), pg_catalog.encode(e.entry_hash, 'hex')
    from public.booking_events e
   where e.host_user_id = public.rout_booking_ledger_caller()
     and e.host_seq > coalesce(p_after, 0)
   order by e.host_seq
   limit least(greatest(coalesce(p_limit, 500), 1), 1000)
$$;

create or replace function public.rout_booking_ledger_attestations(p_after bigint, p_limit integer)
returns table (host_seq bigint, key_id text, signature text)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select a.host_seq, a.key_id, pg_catalog.encode(a.signature, 'hex')
    from public.booking_event_attestations a
   where a.host_user_id = public.rout_booking_ledger_caller()
     and a.host_seq > coalesce(p_after, 0)
   order by a.host_seq, a.key_id
   limit least(greatest(coalesce(p_limit, 500), 1), 4000)
$$;

-- Recomputes every link of the caller's chain in the database.
create or replace function public.rout_booking_ledger_verify()
returns table (ok boolean, entries bigint, first_broken_seq bigint, head_hash text)
language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_host uuid := public.rout_booking_ledger_caller();
  r public.booking_events;
  v_prev bytea;
  v_n bigint := 0;
  v_at timestamptz := '-infinity';
begin
  if v_host is null then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  v_prev := public.rout_booking_ledger_genesis(v_host);
  for r in select * from public.booking_events e where e.host_user_id = v_host order by e.host_seq loop
    v_n := v_n + 1;
    if r.host_seq <> v_n or r.prev_hash <> v_prev or r.occurred_at < v_at or r.entry_hash <> public.rout_booking_ledger_hash(r) then
      return query select false, v_n, r.host_seq, pg_catalog.encode(v_prev, 'hex');
      return;
    end if;
    v_prev := r.entry_hash;
    v_at := r.occurred_at;
  end loop;
  return query select true, v_n, null::bigint, pg_catalog.encode(v_prev, 'hex');
end $$;

-- Overview vs ledger: replaying the caller's chain must give exactly the
-- bookings rows the caller hosts. Any row changed around the trigger shows up.
create or replace function public.rout_booking_ledger_drift()
returns table (booking_id uuid, problem text)
language plpgsql stable security definer set search_path = pg_catalog, pg_temp as $$
declare v_host uuid := public.rout_booking_ledger_caller();
begin
  if v_host is null then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query
  with last_event as (
    select distinct on (e.booking_id) e.*
      from public.booking_events e
     where e.host_user_id = v_host
     order by e.booking_id, e.host_seq desc
  )
  select coalesce(b.id, l.booking_id),
         case
           when l.booking_id is null then 'missing_from_ledger'
           when b.id is null and l.kind not in ('deleted', 'transferred_out') then 'missing_from_bookings'
           when b.id is not null and l.kind in ('deleted', 'transferred_out') then 'resurrected'
           when b.id is not null and (
                  (b.status, b.start_utc, b.end_utc, b.block_start_utc, b.block_end_utc, b.sequence, b.event_type_id, b.group_id, b.workspace_id)
                  is distinct from
                  (l.status, l.start_utc, l.end_utc, l.block_start_utc, l.block_end_utc, l.ics_sequence, l.event_type_id, l.group_id, l.workspace_id)
                  or s.salt is null
                  or public.rout_booking_detail_commit(b, s.salt) <> l.detail_commit) then 'mismatch'
         end
    from (select x.* from public.bookings x where x.host_user_id = v_host) b
    full join last_event l on l.booking_id = b.id
    left join public.booking_ledger_salts s on s.booking_id = b.id
   where l.booking_id is null
      or (b.id is null and l.kind not in ('deleted', 'transferred_out'))
      or (b.id is not null and l.kind in ('deleted', 'transferred_out'))
      or (b.id is not null and (
            (b.status, b.start_utc, b.end_utc, b.block_start_utc, b.block_end_utc, b.sequence, b.event_type_id, b.group_id, b.workspace_id)
            is distinct from
            (l.status, l.start_utc, l.end_utc, l.block_start_utc, l.block_end_utc, l.ics_sequence, l.event_type_id, l.group_id, l.workspace_id)
            or s.salt is null
            or public.rout_booking_detail_commit(b, s.salt) <> l.detail_commit));
end $$;

-- ------------------------------------------------------------------ signing
-- Session-less: only host ids that still miss a signature from this key.
create or replace function public.rout_booking_ledger_pending_hosts(p_key_id text, p_limit integer)
returns table (host_user_id uuid)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select distinct e.host_user_id
    from public.booking_events e
   where p_key_id ~ '^[0-9a-f]{32}$'
     and not exists (select 1 from public.booking_event_attestations a
                      where a.host_user_id = e.host_user_id and a.host_seq = e.host_seq and a.key_id = p_key_id)
   limit least(greatest(coalesce(p_limit, 50), 1), 500)
$$;

-- The caller's unsigned events (for this key), each with the signature this
-- key gave its predecessor, so the signer can refuse to extend a broken chain.
create or replace function public.rout_booking_ledger_unsigned(p_key_id text, p_limit integer)
returns table (host_seq bigint, preimage text, prev_hash text, entry_hash text, prev_signature text)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select e.host_seq, public.rout_booking_ledger_preimage(e), pg_catalog.encode(e.prev_hash, 'hex'), pg_catalog.encode(e.entry_hash, 'hex'),
         (select pg_catalog.encode(p.signature, 'hex') from public.booking_event_attestations p
           where p.host_user_id = e.host_user_id and p.host_seq = e.host_seq - 1 and p.key_id = p_key_id)
    from public.booking_events e
   where e.host_user_id = public.rout_booking_ledger_caller()
     and p_key_id ~ '^[0-9a-f]{32}$'
     and not exists (select 1 from public.booking_event_attestations a
                      where a.host_user_id = e.host_user_id and a.host_seq = e.host_seq and a.key_id = p_key_id)
   order by e.host_seq
   limit least(greatest(coalesce(p_limit, 200), 1), 1000)
$$;

-- Stores a signature for one of the caller's own events. The database cannot
-- check Ed25519; verifiers check it against keys configured outside it.
create or replace function public.rout_booking_ledger_attest(p_seq bigint, p_key_id text, p_signature text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_host uuid := public.rout_booking_ledger_caller();
  v_n integer;
begin
  if v_host is null or p_key_id is null or p_key_id !~ '^[0-9a-f]{32}$'
     or p_signature is null or p_signature !~ '^[0-9a-f]{128}$' then
    return false;
  end if;
  insert into public.booking_event_attestations (host_user_id, host_seq, key_id, signature)
  select e.host_user_id, e.host_seq, p_key_id, pg_catalog.decode(p_signature, 'hex')
    from public.booking_events e
   where e.host_user_id = v_host and e.host_seq = p_seq
  on conflict do nothing;
  get diagnostics v_n = row_count;
  return v_n = 1;
end $$;

-- ------------------------------------------------------------------ import existing bookings
do $$
declare b public.bookings;
begin
  for b in select * from public.bookings x
            where not exists (select 1 from public.booking_events e where e.booking_id = x.id)
            order by x.created_at, x.id loop
    perform public.rout_booking_ledger_append(b, 'imported', public.rout_booking_detail_commit(b, public.rout_booking_ledger_salt(b.id)));
  end loop;
end $$;

-- ------------------------------------------------------------------ privileges
-- Internal helpers: nobody but the owner and other definers.
do $$
declare f text;
begin
  foreach f in array array[
    'public.rout_booking_ledger_immutable()',
    'public.rout_booking_ledger_append(public.bookings, text, bytea)',
    'public.rout_booking_ledger_salt(uuid)',
    'public.rout_booking_ledger_capture()',
    'public.rout_booking_ledger_caller()',
    'public.rout_booking_detail_commit(public.bookings, bytea)',
    'public.rout_ledger_field(text)',
    'public.rout_ledger_ts(timestamptz)',
    'public.rout_booking_ledger_genesis(uuid)',
    'public.rout_booking_ledger_preimage(public.booking_events)',
    'public.rout_booking_ledger_hash(public.booking_events)'
  ] loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
      execute pg_catalog.format('revoke all on function %s from rout_app', f);
    end if;
  end loop;
  foreach f in array array[
    'public.rout_booking_ledger_entries(bigint, integer)',
    'public.rout_booking_ledger_attestations(bigint, integer)',
    'public.rout_booking_ledger_verify()',
    'public.rout_booking_ledger_drift()',
    'public.rout_booking_ledger_pending_hosts(text, integer)',
    'public.rout_booking_ledger_unsigned(text, integer)',
    'public.rout_booking_ledger_attest(bigint, text, text)'
  ] loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
      execute pg_catalog.format('grant execute on function %s to rout_app', f);
    end if;
  end loop;
  if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') and (
       pg_catalog.has_function_privilege('rout_app', 'public.rout_booking_ledger_append(public.bookings, text, bytea)', 'execute')
    or pg_catalog.has_table_privilege('rout_app', 'public.booking_events', 'select')
    or pg_catalog.has_table_privilege('rout_app', 'public.booking_ledger_salts', 'select')) then
    raise exception 'rout_app can still reach the booking ledger directly';
  end if;
end $$;
