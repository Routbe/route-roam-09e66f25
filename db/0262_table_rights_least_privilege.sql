-- 0262 — CONTRACT (held back, not applied): rout_app keeps on 13 tables/views
-- and 4 number sequences only the rights the app code uses. Neon's default
-- privileges had given it more than db/ grants; this brings Neon back to db/,
-- and on physical_keys a little below it (see there). Only REVOKE, plus the two
-- column grants a table-level revoke on physical_keys would otherwise remove.
-- Every revoked right is unused: no app code writes there (src/, checked
-- 2026-11-13), writes go through SECURITY DEFINER functions that run as the
-- owner, and cascades from public.users run as the table owner. All 13 tables
-- were empty on Neon on 2026-11-13.
do $$
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
    return;
  end if;

  -- Read only for the app; rows come from rout_agent_audit_log / _mark_reverted.
  revoke insert, update, delete on public.agent_audit_logs from rout_app;
  -- Issued by definer code; members read, accept (column grant) and delete.
  revoke insert on public.app_issued_credentials from rout_app;
  -- quarantine.server.ts inserts and updates, never deletes.
  revoke delete on public.auth_recovery_requests from rout_app;
  -- Read-only compatibility views over omni_matrix_items / omni_ingest_tokens.
  revoke insert, update, delete on public.grid_items from rout_app;
  revoke insert, update, delete on public.ingest_tokens from rout_app;
  -- Written only by execute_account_merge (rout_merge_executor).
  revoke insert, update, delete on public.identity_relay_merge_archive from rout_app;
  -- Written only by the definer trigger rout_physical_key_audit and rout_hw_record_scan.
  revoke insert, update, delete on public.physical_key_events from rout_app;
  -- card-freeze.server.ts changes only status; label stays editable as in db/0199.
  -- A table-level UPDATE also let rout_app overwrite public_key/key_alg, which
  -- db/0200 meant to close. Revoking table UPDATE drops the column grants too,
  -- so they are granted again right after.
  revoke update, delete on public.physical_keys from rout_app;
  grant update (status, label) on public.physical_keys to rout_app;
  -- Admin switch: insert ... on conflict update; never deleted.
  revoke delete on public.platform_feature_switches from rout_app;
  -- Rows come from the rout_subscriber_* definers; the app reads and purges.
  revoke insert, update on public.profile_subscribers from rout_app;
  -- Only the rout_qa_* / rout_shadow_mute_trust definers touch it.
  revoke all on public.qa_guest_trust from rout_app;
  -- replaceCardAtomically inserts/updates the generation, never deletes.
  revoke delete on public.rout_card_generations from rout_app;
  -- Members only read their passes; written by definer code and the merge.
  revoke insert, update, delete on public.wallet_passes from rout_app;
  -- Their tables are closed to rout_app; defaults fire inside definers as the owner.
  revoke all on sequence public.audit_logs_id_seq, public.forwarding_confirmation_sends_id_seq,
    public.physical_key_events_id_seq, public.qa_trust_charges_id_seq from rout_app;
end $$;

-- Postconditions: the exact table-level rights rout_app keeps.
do $$
declare
  r record;
  want text[];
  have text[];
  p text;
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
    return;
  end if;
  for r in
    select * from (values
      ('public.agent_audit_logs', array['SELECT']),
      ('public.app_issued_credentials', array['SELECT', 'DELETE']),
      ('public.auth_recovery_requests', array['SELECT', 'INSERT', 'UPDATE']),
      ('public.grid_items', array['SELECT']),
      ('public.ingest_tokens', array['SELECT']),
      ('public.identity_relay_merge_archive', array['SELECT']),
      ('public.physical_key_events', array['SELECT']),
      ('public.physical_keys', array['SELECT']),
      ('public.platform_feature_switches', array['SELECT', 'INSERT', 'UPDATE']),
      ('public.profile_subscribers', array['SELECT', 'DELETE']),
      ('public.qa_guest_trust', array[]::text[]),
      ('public.rout_card_generations', array['SELECT', 'INSERT', 'UPDATE']),
      ('public.wallet_passes', array['SELECT'])
    ) as t(tbl, privs)
  loop
    want := r.privs;
    have := array[]::text[];
    foreach p in array array['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'] loop
      if pg_catalog.has_table_privilege('rout_app', r.tbl, p) then
        have := have || p;
      end if;
    end loop;
    if not (have @> want and want @> have) then
      raise exception '0262: rout_app on % has %, expected %', r.tbl, have, want;
    end if;
  end loop;
  if not pg_catalog.has_column_privilege('rout_app', 'public.physical_keys', 'status', 'UPDATE')
     or not pg_catalog.has_column_privilege('rout_app', 'public.physical_keys', 'label', 'UPDATE')
     or pg_catalog.has_column_privilege('rout_app', 'public.physical_keys', 'public_key', 'UPDATE')
     or pg_catalog.has_column_privilege('rout_app', 'public.physical_keys', 'key_alg', 'UPDATE')
     or pg_catalog.has_column_privilege('rout_app', 'public.physical_keys', 'user_id', 'UPDATE') then
    raise exception '0262: physical_keys column rights for rout_app are not status + label only';
  end if;
  if not pg_catalog.has_column_privilege('rout_app', 'public.app_issued_credentials', 'accepted_at', 'UPDATE')
     or not pg_catalog.has_column_privilege('rout_app', 'public.app_issued_credentials', 'show_on_name', 'UPDATE') then
    raise exception '0262: app_issued_credentials lost its accept column rights';
  end if;
  foreach p in array array['public.audit_logs_id_seq', 'public.forwarding_confirmation_sends_id_seq',
                           'public.physical_key_events_id_seq', 'public.qa_trust_charges_id_seq'] loop
    if pg_catalog.has_sequence_privilege('rout_app', p, 'USAGE') or pg_catalog.has_sequence_privilege('rout_app', p, 'SELECT')
       or pg_catalog.has_sequence_privilege('rout_app', p, 'UPDATE') then
      raise exception '0262: rout_app still has rights on %', p;
    end if;
  end loop;
end $$;
