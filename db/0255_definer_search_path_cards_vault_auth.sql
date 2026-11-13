-- 0255: SECURITY DEFINER search_path, batch 1 of the legacy functions
--       (ROUT Card / hardware keys, ephemeral vault, sign-in and account).
--  * Every SECURITY DEFINER function must pin search_path to pg_catalog, so
--    nothing on the caller's path can be resolved inside it. These 21 were
--    created pinned to the public schema.
--  * Reviewed against Neon on 2026-11-13: every body already names its tables
--    and helper functions with their schema (public., auth.); everything else
--    they use (now(), count(), jsonb_build_object(), pg_advisory_xact_lock(),
--    text and enum operators) lives in pg_catalog. The live definitions were
--    byte-identical to db/schema.snapshot.json before this file.
--  * ALTER FUNCTION ... SET only replaces the search_path setting: body,
--    owner and grants stay exactly as they are. No table, column or data change.
--  * rout_physical_key_audit (a trigger function) also loses its PUBLIC
--    execute grant; firing a trigger never checks it.

-- ROUT Card and hardware keys
alter function public.rout_card_design(text) set search_path = pg_catalog;
alter function public.rout_card_frozen(text) set search_path = pg_catalog;
alter function public.rout_card_generation(uuid) set search_path = pg_catalog;
alter function public.rout_card_status_by_serial(text) set search_path = pg_catalog;
alter function public.rout_card_status_by_hardware(uuid) set search_path = pg_catalog;
alter function public.rout_card_token_use(text, timestamptz) set search_path = pg_catalog;
alter function public.rout_hw_issue_challenge(uuid, text) set search_path = pg_catalog;
alter function public.rout_hw_consume_challenge(uuid, text) set search_path = pg_catalog;
alter function public.rout_hw_record_scan(uuid, boolean) set search_path = pg_catalog;
alter function public.rout_pair_factory_card(uuid, text, text) set search_path = pg_catalog;
alter function public.rout_physical_key_audit() set search_path = pg_catalog;
revoke execute on function public.rout_physical_key_audit() from public;

-- Ephemeral vault
alter function public.rout_ephemeral_vault_create(uuid, text, text, text) set search_path = pg_catalog;
alter function public.rout_ephemeral_vault_read(uuid) set search_path = pg_catalog;
alter function public.rout_ephemeral_vault_commit(uuid, text, text, text, text, text) set search_path = pg_catalog;
alter function public.rout_purge_expired_ephemeral_vaults() set search_path = pg_catalog;

-- Sign-in and account
alter function public.signin_guard_status(text) set search_path = pg_catalog;
alter function public.signin_guard_record(text, boolean) set search_path = pg_catalog;
alter function public.rout_resolve_account(text) set search_path = pg_catalog;
alter function public.email_freeze_owner(text) set search_path = pg_catalog;
alter function public.delete_account() set search_path = pg_catalog;
alter function public.handle_new_user() set search_path = pg_catalog;
