-- 0256: SECURITY DEFINER search_path, batch 2 of the legacy functions
--       (workspaces, parental consent, agent sandbox and agent workspaces).
--  * Every SECURITY DEFINER function must pin search_path to pg_catalog, so
--    nothing on the caller's path can be resolved inside it. These 36 were
--    created pinned to the public schema.
--  * Reviewed against Neon on 2026-11-13: the live definitions, owner
--    (neondb_owner) and grants (EXECUTE for rout_app only) were byte-identical
--    to db/schema.snapshot.json before this file. Every body already names its
--    tables, types and helper functions with their schema (public.); everything
--    else they use (now(), current_date, count(), lower(), hashtext(),
--    pg_advisory_xact_lock(), jsonb functions and operators) lives in pg_catalog.
--  * Triggers that fire from these writes were checked as well: the ones
--    without their own search_path (touch_updated_at, reserve_recovery_email,
--    the handle-namespace guards) also qualify every table with public.
--  * ALTER FUNCTION ... SET only replaces the search_path setting: body,
--    owner and grants stay exactly as they are. No table, column or data change.

-- Workspaces: membership, roles, team, invites and transfers
alter function public.rout_is_workspace_member(uuid) set search_path = pg_catalog;
alter function public.rout_workspace_role(uuid) set search_path = pg_catalog;
alter function public.rout_workspace_team(uuid) set search_path = pg_catalog;
alter function public.rout_accept_workspace_invites(text) set search_path = pg_catalog;
alter function public.rout_transfer_by_token(text) set search_path = pg_catalog;
alter function public.rout_transfers_for_email(text) set search_path = pg_catalog;
alter function public.workspace_may_drop_suffix(text, uuid) set search_path = pg_catalog;

-- Workspaces: public lookups by slug, domain and alias
alter function public.rout_public_workspace(text) set search_path = pg_catalog;
alter function public.rout_public_workspace_relme(text) set search_path = pg_catalog;
alter function public.rout_workspace_atproto_did(text, text) set search_path = pg_catalog;
alter function public.rout_workspace_slug_for_domain(text) set search_path = pg_catalog;
alter function public.rout_workspace_slug_taken(text) set search_path = pg_catalog;
alter function public.workspace_slug_for_root_alias(text) set search_path = pg_catalog;
alter function public.rout_migrated_workspace_for_handle(text, text) set search_path = pg_catalog;

-- Parental consent and minors
alter function public.rout_record_signup_age(text, date, text, text) set search_path = pg_catalog;
alter function public.rout_user_is_minor(uuid) set search_path = pg_catalog;
alter function public.rout_parent_lookup(text) set search_path = pg_catalog;
alter function public.rout_parent_approve_consent(text) set search_path = pg_catalog;
alter function public.rout_parent_set_qa_level(text, public.qa_permission_level) set search_path = pg_catalog;
alter function public.rout_parent_request_payment(uuid, text, jsonb) set search_path = pg_catalog;
alter function public.rout_parent_mark_payment(text) set search_path = pg_catalog;

-- Agent sandbox
alter function public.rout_agent_sandbox_register(text, text, text, text) set search_path = pg_catalog;
alter function public.rout_agent_sandbox_context(text) set search_path = pg_catalog;
alter function public.rout_agent_sandbox_provision(text, text, text, text, text, text, jsonb) set search_path = pg_catalog;
alter function public.rout_agent_sandbox_patch_draft(text, jsonb, jsonb) set search_path = pg_catalog;
alter function public.rout_agent_sandbox_set_apps(text, jsonb) set search_path = pg_catalog;
alter function public.rout_agent_sandbox_state(text) set search_path = pg_catalog;
alter function public.rout_purge_expired_agent_sandboxes() set search_path = pg_catalog;

-- Agent workspaces: provisioning, claims and audit log
alter function public.rout_agent_provision_workspace(text, text, text, text, text) set search_path = pg_catalog;
alter function public.rout_agent_claim_preview(text) set search_path = pg_catalog;
alter function public.rout_claim_agent_workspace(text) set search_path = pg_catalog;
alter function public.rout_claim_agent_workspace_v2(text) set search_path = pg_catalog;
alter function public.rout_agent_audit_log(uuid, uuid, text, text, text, text, jsonb, jsonb) set search_path = pg_catalog;
alter function public.rout_agent_audit_mark_reverted(uuid) set search_path = pg_catalog;
alter function public.rout_agent_audit_revert_workspace(uuid) set search_path = pg_catalog;
alter function public.rout_purge_unclaimed_agent_workspaces() set search_path = pg_catalog;
