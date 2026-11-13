/**
 * SECURITY DEFINER functions that still run without search_path = pg_catalog.
 * This list only shrinks: each hardening batch removes its functions here in
 * the same change as its migration. Adding an entry is never the fix for a new
 * function; pin it to pg_catalog instead.
 *
 * Checked by src/test/security-definer-search-path.test.ts (against
 * db/schema.snapshot.json), by both migration runners inside every migration
 * transaction from 0255 on, and live by `bun scripts/security-definer-check.ts`.
 *
 * Remaining after 0255 (batch 1: cards, vault, sign-in): 115.
 * Remaining after 0256 (batch 2: workspaces, parental consent, agents): 79.
 * Remaining after 0257 (batch 3: bookings): 48.
 * Remaining after 0258 (batch 4: everything else, plus pg_temp named last on all): 0.
 *
 * A function leaves this list in the same change as the migration that pins
 * it, and is recorded under that migration in HARDENED_BY_MIGRATION. A fresh
 * database replays the older migrations before the pinning one, so the runner
 * guard after migration N also allows what a later migration still pins.
 */
export const LEGACY_DEFINER_SEARCH_PATH: readonly string[] = [];

/** Functions removed from the list above, keyed by the migration that pins them. */
export const HARDENED_BY_MIGRATION: Readonly<Record<number, readonly string[]>> = {
  255: [
    "public.rout_card_design(s text)",
    "public.rout_card_frozen(s text)",
    "public.rout_card_generation(u uuid)",
    "public.rout_card_status_by_serial(s text)",
    "public.rout_card_status_by_hardware(hid uuid)",
    "public.rout_card_token_use(n text, exp timestamp with time zone)",
    "public.rout_hw_issue_challenge(hid uuid, nh text)",
    "public.rout_hw_consume_challenge(hid uuid, nh text)",
    "public.rout_hw_record_scan(hid uuid, ok boolean)",
    "public.rout_pair_factory_card(hid uuid, proof_hash text, serial text)",
    "public.rout_physical_key_audit()",
    "public.rout_ephemeral_vault_create(p_vault_id uuid, p_key_hash text, p_vault_hash text, p_payload text)",
    "public.rout_ephemeral_vault_read(p_vault_id uuid)",
    "public.rout_ephemeral_vault_commit(p_vault_id uuid, p_vault_hash text, p_name text, p_slug text, p_blob text, p_key_id text)",
    "public.rout_purge_expired_ephemeral_vaults()",
    "public.signin_guard_status(_identity_hash text)",
    "public.signin_guard_record(_identity_hash text, _success boolean)",
    "public.rout_resolve_account(p_identifier text)",
    "public.email_freeze_owner(token_hash text)",
    "public.delete_account()",
    "public.handle_new_user()",
  ],
  256: [
    "public.rout_is_workspace_member(ws uuid)",
    "public.rout_workspace_role(ws uuid)",
    "public.rout_workspace_team(p_ws uuid)",
    "public.rout_accept_workspace_invites(p_email text)",
    "public.rout_transfer_by_token(p_hash text)",
    "public.rout_transfers_for_email(p_email text)",
    "public.workspace_may_drop_suffix(ws_plan text, ws uuid)",
    "public.rout_public_workspace(p_slug text)",
    "public.rout_public_workspace_relme(p_slug text)",
    "public.rout_workspace_atproto_did(p_slug text, p_domain text)",
    "public.rout_workspace_slug_for_domain(p_domain text)",
    "public.rout_workspace_slug_taken(p_slug text)",
    "public.workspace_slug_for_root_alias(h text)",
    "public.rout_migrated_workspace_for_handle(p_handle text, p_space text)",
    "public.rout_record_signup_age(p_email text, p_dob date, p_parent_email text, p_token_hash text)",
    "public.rout_user_is_minor(p_user_id uuid)",
    "public.rout_parent_lookup(p_token_hash text)",
    "public.rout_parent_approve_consent(p_token_hash text)",
    "public.rout_parent_set_qa_level(p_token_hash text, p_level qa_permission_level)",
    "public.rout_parent_request_payment(p_user_id uuid, p_token_hash text, p_details jsonb)",
    "public.rout_parent_mark_payment(p_token_hash text)",
    "public.rout_agent_sandbox_register(p_key_hash text, p_pow_hash text, p_ip_bucket text, p_agent_name text)",
    "public.rout_agent_sandbox_context(p_key_hash text)",
    "public.rout_agent_sandbox_provision(p_key_hash text, p_name text, p_slug text, p_description text, p_token_hash text, p_code_hash text, p_draft jsonb)",
    "public.rout_agent_sandbox_patch_draft(p_key_hash text, p_fields jsonb, p_prefs jsonb)",
    "public.rout_agent_sandbox_set_apps(p_key_hash text, p_apps jsonb)",
    "public.rout_agent_sandbox_state(p_key_hash text)",
    "public.rout_purge_expired_agent_sandboxes()",
    "public.rout_agent_provision_workspace(p_client_id text, p_name text, p_slug text, p_description text, p_token_hash text)",
    "public.rout_agent_claim_preview(p_token_hash text)",
    "public.rout_claim_agent_workspace(p_token_hash text)",
    "public.rout_claim_agent_workspace_v2(p_hash text)",
    "public.rout_agent_audit_log(p_workspace_id uuid, p_user_id uuid, p_client_id text, p_action text, p_target_table text, p_target_id text, p_previous jsonb, p_new jsonb)",
    "public.rout_agent_audit_mark_reverted(p_log_id uuid)",
    "public.rout_agent_audit_revert_workspace(p_workspace_id uuid)",
    "public.rout_purge_unclaimed_agent_workspaces()",
  ],
  257: [
    "public.rout_booking_adjacent_ok(p_host uuid, p_block_start timestamp with time zone, p_block_end timestamp with time zone)",
    "public.rout_booking_cache_free(p_host uuid, p_from timestamp with time zone, p_to timestamp with time zone)",
    "public.rout_booking_confirm_paid(p_booking uuid, p_session text)",
    "public.rout_booking_create(p_event_type uuid, p_start timestamp with time zone, p_guest_name text, p_guest_email text, p_guest_timezone text, p_guest_note text, p_intake jsonb)",
    "public.rout_booking_create(p_event_type uuid, p_start timestamp with time zone, p_guest_name text, p_guest_email text, p_guest_timezone text, p_guest_note text, p_intake jsonb, p_hold uuid, p_hold_secret text)",
    "public.rout_booking_due_calendars(p_limit integer)",
    "public.rout_booking_edge_busy(p_host uuid, p_from timestamp with time zone, p_to timestamp with time zone)",
    "public.rout_booking_group_ids(p_booking uuid)",
    "public.rout_booking_guest_view(p_booking uuid, p_token text)",
    "public.rout_booking_hold(p_event_type uuid, p_start timestamp with time zone, p_client text, p_replace uuid, p_replace_secret text)",
    "public.rout_booking_hold_release(p_hold uuid, p_secret text)",
    "public.rout_booking_horizon_end(p_business_days integer, p_max_days integer, p_zone text, p_now timestamp with time zone)",
    "public.rout_booking_host_free(p_host uuid, p_event_type uuid, p_start timestamp with time zone, p_block_start timestamp with time zone, p_block_end timestamp with time zone, p_capacity integer)",
    "public.rout_booking_host_free_held(p_host uuid, p_event_type uuid, p_start timestamp with time zone, p_block_start timestamp with time zone, p_block_end timestamp with time zone, p_capacity integer, p_hold uuid)",
    "public.rout_booking_lock_hosts(p_hosts uuid[], p_from timestamp with time zone, p_to timestamp with time zone)",
    "public.rout_booking_lock_type(p_event_type uuid, p_start timestamp with time zone)",
    "public.rout_booking_pick_hosts(p_event_type uuid, p_start timestamp with time zone, p_hold uuid)",
    "public.rout_booking_public_constraints(p_id uuid, p_from timestamp with time zone, p_to timestamp with time zone, p_hold uuid)",
    "public.rout_booking_public_days(p_id uuid, p_from date, p_to date)",
    "public.rout_booking_public_event_type(p_id uuid)",
    "public.rout_booking_public_sessions(p_id uuid, p_from timestamp with time zone, p_to timestamp with time zone, p_hold uuid)",
    "public.rout_booking_public_type_for_handle(p_handle text, p_type uuid)",
    "public.rout_booking_release_expired(p_limit integer)",
    "public.rout_booking_release_hold(p_booking uuid)",
    "public.rout_booking_set_checkout(p_booking uuid, p_session text)",
    "public.rout_booking_stale_hosts(p_id uuid, p_max_age interval)",
    "public.rout_booking_start_problem(p_event_type uuid, p_start timestamp with time zone)",
    "public.rout_booking_type_public(p_id uuid)",
    "public.rout_booking_type_zone(p_event_type uuid)",
    "public.rout_booking_within_limits(p_event_type uuid, p_host uuid, p_start timestamp with time zone, p_hold uuid)",
    "public.rout_booking_zone(p_zone text, p_host uuid)",
  ],
  258: [
    "public.claim_referral(p_referrer text)",
    "public.contact_submissions_recent_count(_sender_hash text, _window_minutes integer)",
    "public.enforce_short_link_limits()",
    "public.feedback_form_is_public(f feedback_forms)",
    "public.generate_unique_handle(_seed text)",
    "public.get_public_profile(_username text)",
    "public.grant_signup_badges(_user_id uuid)",
    "public.is_handle_available(_username text)",
    "public.log_qr_scan(_tracked_qr_id uuid, _device text, _country text, _browser text, _os text)",
    "public.manage_short_link(_token text, _action text, _target_url text, _is_active boolean, _expires_at timestamp with time zone, _slug text)",
    "public.profile_event_is_public(e profile_events)",
    "public.read_public_events(p_slug text, p_space text, p_handle text)",
    "public.read_public_fediverse(p_user uuid)",
    "public.read_public_feedback(p_slug text, p_space text, p_handle text)",
    "public.resolve_short_link(_slug text)",
    "public.rout_broadcast_event_allowed(p_owner uuid, p_event uuid, p_space text)",
    "public.rout_due_sunset_accounts()",
    "public.rout_ingest_token_owner(p_hash text)",
    "public.rout_omni_media(p_path text, p_viewer uuid)",
    "public.rout_pow_spend(p_hash text, p_scope text, p_expires_at timestamp with time zone)",
    "public.rout_presence_public(p_handle text, p_space text)",
    "public.rout_profile_qa_level(p_handle text)",
    "public.rout_protocol_append(p_stream text, p_seq bigint, p_prev text, p_hash text, p_author text, p_kind text, p_cap_id text, p_event jsonb)",
    "public.rout_protocol_dpop_spend(p_jkt text, p_jti text, p_expires_at timestamp with time zone)",
    "public.rout_protocol_head(p_stream text)",
    "public.rout_protocol_read(p_stream text, p_after bigint, p_limit integer)",
    "public.rout_protocol_revoked(p_stream text, p_ids text[])",
    "public.rout_public_calendar(p_public_id text)",
    "public.rout_qa_charge(p_recipient uuid, p_abuse_key text, p_net text)",
    "public.rout_qa_maintenance()",
    "public.rout_qa_mute_by_message(p_message_id uuid, p_muter_net text)",
    "public.rout_qa_my_mutes()",
    "public.rout_qa_owner(p_handle text, p_space text)",
    "public.rout_qa_public(p_handle text, p_space text)",
    "public.rout_qa_submit(p_handle text, p_space text, p_body text, p_device_base text, p_acct_base text, p_abuse_now text, p_abuse_prev text, p_masked boolean)",
    "public.rout_qa_unmute(p_action_id uuid)",
    "public.rout_shadow_mute_trust()",
    "public.rout_subscriber_confirm(p_token_hash text)",
    "public.rout_subscriber_join(p_handle text, p_hash text, p_ciphertext text, p_iv text, p_confirm_hash text, p_unsubscribe_hash text, p_locale text)",
    "public.rout_subscriber_platform_counts()",
    "public.rout_subscriber_sync_result(p_id uuid, p_ok boolean, p_error text)",
    "public.rout_subscriber_unsubscribe(p_token_hash text)",
    "public.rout_visit_seen_recently(p_hash text, p_handle text, p_space text)",
    "public.seed_demo_content(_user_id uuid)",
    "public.short_link_stats(_token text)",
    "public.submit_public_feedback(p_form uuid, p_rating integer, p_comment text, p_name text, p_consent boolean)",
    "public.wallet_credit(_user_id uuid, _amount_cents integer, _kind text, _description text, _reference text)",
    "public.wallet_debit(_user_id uuid, _amount_cents integer, _description text, _reference text)",
  ],
};

/** What may still be unpinned once migration `migration` has run: the list above plus what later migrations pin. */
export function legacyAllowedAfter(migration: number): readonly string[] {
  const later = Object.entries(HARDENED_BY_MIGRATION)
    .filter(([n]) => Number(n) > migration)
    .flatMap(([, keys]) => keys);
  return [...LEGACY_DEFINER_SEARCH_PATH, ...later];
}
