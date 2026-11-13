-- 0259 — Internal SECURITY DEFINER helpers are callable only by their owner.
-- Found in the live check after 0258 (2026-11-13): Neon's default privileges
-- (db/53, section 5) gave rout_app EXECUTE on every new function, so helpers
-- whose migrations only revoked PUBLIC are still directly callable by the app
-- role on Neon, while a replay of db/ leaves them owner-only. Directly callable,
-- rout_audit_insert writes admin audit rows for any admin id and
-- rout_phone_mark_verified marks any member's number verified without a code.
-- Each helper is reached only from SECURITY DEFINER entry points (they run as
-- the owner) or as a trigger; no app code calls them (checked in src/ and in
-- the code production runs, schema level 0253). workspace_may_drop_suffix stays:
-- invoker triggers call it with the caller's rights.
-- execute_account_merge (owner rout_merge_executor) keeps rout_app but loses the
-- PUBLIC grant that 0152 revoked; on Neon it was back.
-- Only REVOKE: bodies, owners, search paths and rout_app's entry points stay.
do $$
declare f text;
begin
  if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
    foreach f in array array[
      'public.rout_audit_insert(uuid, text, text, uuid, text, text)',
      'public.rout_phone_mark_verified(public.phone_otp_codes)',
      'public.rout_psp_public_owner(uuid)',
      'public.rout_qa_owner(text, text)',
      'public.feedback_form_is_public(public.feedback_forms)',
      'public.profile_event_is_public(public.profile_events)',
      'public.rout_physical_key_audit()'
    ] loop
      execute pg_catalog.format('revoke all on function %s from public, rout_app', f);
    end loop;
  end if;
end $$;

-- execute_account_merge belongs to rout_merge_executor; borrow that role only
-- for this statement, as 0215, 0242 and 0258 do, then give it back.
do $own$ begin execute format('grant rout_merge_executor to %I with inherit true, set true', current_user); end $own$;
revoke all on function public.execute_account_merge(text, text, text, text) from public;
do $own$ begin execute format('revoke rout_merge_executor from %I', current_user); end $own$;

do $check$
declare bad text;
begin
  if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
    select string_agg(f, ', ') into bad from unnest(array[
      'public.rout_audit_insert(uuid, text, text, uuid, text, text)',
      'public.rout_phone_mark_verified(public.phone_otp_codes)',
      'public.rout_psp_public_owner(uuid)',
      'public.rout_qa_owner(text, text)',
      'public.feedback_form_is_public(public.feedback_forms)',
      'public.profile_event_is_public(public.profile_events)',
      'public.rout_physical_key_audit()'
    ]) f where pg_catalog.has_function_privilege('rout_app', f, 'execute');
    if bad is not null then raise exception 'rout_app can still execute: %', bad; end if;
    if not pg_catalog.has_function_privilege('rout_app', 'public.execute_account_merge(text, text, text, text)', 'execute') then
      raise exception 'rout_app lost execute_account_merge';
    end if;
  end if;
  if exists (select 1 from pg_catalog.aclexplode((select proacl from pg_catalog.pg_proc
              where oid = 'public.execute_account_merge(text, text, text, text)'::pg_catalog.regprocedure)) a
              where a.grantee = 0) then
    raise exception 'execute_account_merge is still executable by PUBLIC';
  end if;
end $check$;
