-- 0260 — A fresh replay of db/ ends with the same function rights as Neon.
-- Found 2026-11-13 by comparing every function and table ACL on Neon with a
-- replay of db/ (after 0259): the replay left EXECUTE for PUBLIC on functions
-- whose PUBLIC grant Neon no longer has, and left rout_app without EXECUTE on
-- functions Neon grants it (RLS helpers such as rout_current_user_id, invoker
-- triggers and the helpers they call), so a rebuilt database was looser for
-- PUBLIC and broken for the app role. Each statement states Neon's current
-- right; on Neon the whole file changes nothing. The calendar_events id
-- sequence gets the usage rout_app already has on Neon and needs for its insert
-- right. Table rights where Neon is looser than db/ are not touched here.

-- PUBLIC loses EXECUTE it no longer has on Neon (30 functions)
revoke execute on function public.alias_profiles_handle_namespace_guard() from public;
revoke execute on function public.assert_handle_namespace_free(_handle text, _user_id uuid) from public;
revoke execute on function public.assign_badge_serial_number() from public;
revoke execute on function public.claim_referral(p_referrer text) from public;
revoke execute on function public.contact_submissions_recent_count(_sender_hash text, _window_minutes integer) from public;
revoke execute on function public.current_app_user_id() from public;
revoke execute on function public.delete_account() from public;
revoke execute on function public.enforce_short_link_limits() from public;
revoke execute on function public.generate_unique_handle(_seed text) from public;
revoke execute on function public.get_my_account() from public;
revoke execute on function public.get_my_profile() from public;
revoke execute on function public.get_public_profile(_username text) from public;
revoke execute on function public.grant_signup_badges(_user_id uuid) from public;
revoke execute on function public.handle_new_user() from public;
revoke execute on function public.has_role(_user_id uuid, _role app_role) from public;
revoke execute on function public.is_handle_available(_username text) from public;
revoke execute on function public.log_qr_scan(_tracked_qr_id uuid, _device text, _country text, _browser text, _os text) from public;
revoke execute on function public.manage_short_link(_token text, _action text, _target_url text, _is_active boolean, _expires_at timestamp with time zone, _slug text) from public;
revoke execute on function public.profiles_handle_namespace_guard() from public;
revoke execute on function public.publish_profile_draft(p_user_id uuid, p_space text, p_expected_revision bigint) from public;
revoke execute on function public.resolve_short_link(_slug text) from public;
revoke execute on function public.save_profile_draft(p_user_id uuid, p_space text, p_payload jsonb, p_expected_revision bigint) from public;
revoke execute on function public.seed_demo_content(_user_id uuid) from public;
revoke execute on function public.short_link_stats(_token text) from public;
revoke execute on function public.signin_guard_record(_identity_hash text, _success boolean) from public;
revoke execute on function public.signin_guard_status(_identity_hash text) from public;
revoke execute on function public.social_links_touch() from public;
revoke execute on function public.touch_updated_at() from public;
revoke execute on function public.wallet_credit(_user_id uuid, _amount_cents integer, _kind text, _description text, _reference text) from public;
revoke execute on function public.wallet_debit(_user_id uuid, _amount_cents integer, _description text, _reference text) from public;

-- rout_app keeps or gets EXECUTE it has on Neon (56 functions). Not granted
-- here: seed_demo_content, grant_signup_badges and generate_unique_handle,
-- SECURITY DEFINER functions nothing calls; 0261 takes them from rout_app on Neon.
grant execute on function auth.jwt() to rout_app;
grant execute on function auth.role() to rout_app;
grant execute on function auth.uid() to rout_app;
grant execute on function public.account_deletion_audit_append_only() to rout_app;
grant execute on function public.alias_profiles_handle_namespace_guard() to rout_app;
grant execute on function public.assert_handle_namespace_free(_handle text, _user_id uuid) to rout_app;
grant execute on function public.assign_badge_serial_number() to rout_app;
grant execute on function public.claim_referral(p_referrer text) to rout_app;
grant execute on function public.contact_submissions_recent_count(_sender_hash text, _window_minutes integer) to rout_app;
grant execute on function public.current_app_user_id() to rout_app;
grant execute on function public.delete_account() to rout_app;
grant execute on function public.disclosure_hash(prev text, uid uuid, cid text, scopes text[], ts timestamp with time zone) to rout_app;
grant execute on function public.disclosure_no_rewrite() to rout_app;
grant execute on function public.enforce_short_link_limits() to rout_app;
grant execute on function public.enforce_workspace_root_alias() to rout_app;
grant execute on function public.enforce_workspace_slug_suffix() to rout_app;
grant execute on function public.get_my_account() to rout_app;
grant execute on function public.get_my_profile() to rout_app;
grant execute on function public.get_public_profile(_username text) to rout_app;
grant execute on function public.grant_early_verified_promo() to rout_app;
grant execute on function public.handle_new_user() to rout_app;
grant execute on function public.has_role(_user_id uuid, _role app_role) to rout_app;
grant execute on function public.identity_event_chain() to rout_app;
grant execute on function public.identity_owner_immutable() to rout_app;
grant execute on function public.identity_verifications_immutable() to rout_app;
grant execute on function public.is_handle_available(_username text) to rout_app;
grant execute on function public.log_qr_scan(_tracked_qr_id uuid, _device text, _country text, _browser text, _os text) to rout_app;
grant execute on function public.manage_short_link(_token text, _action text, _target_url text, _is_active boolean, _expires_at timestamp with time zone, _slug text) to rout_app;
grant execute on function public.profiles_handle_namespace_guard() to rout_app;
grant execute on function public.publish_profile_draft(p_user_id uuid, p_space text, p_expected_revision bigint) to rout_app;
grant execute on function public.queue_presence_broadcast() to rout_app;
grant execute on function public.reserve_recovery_email() to rout_app;
grant execute on function public.resolve_short_link(_slug text) to rout_app;
grant execute on function public.rout_current_user_id() to rout_app;
grant execute on function public.rout_like_literal(p text) to rout_app;
grant execute on function public.rout_notify_omni_job() to rout_app;
grant execute on function public.rout_oauth_b64url_sha256(p text) to rout_app;
grant execute on function public.rout_protocol_events_immutable() to rout_app;
grant execute on function public.rout_shadow_mute_trust() to rout_app;
grant execute on function public.rout_users_minor_sync() to rout_app;
grant execute on function public.rout_vp_json(v verification_payments) to rout_app;
grant execute on function public.save_profile_draft(p_user_id uuid, p_space text, p_payload jsonb, p_expected_revision bigint) to rout_app;
grant execute on function public.security_audit_chain() to rout_app;
grant execute on function public.security_audit_refuse() to rout_app;
grant execute on function public.short_link_stats(_token text) to rout_app;
grant execute on function public.signin_guard_record(_identity_hash text, _success boolean) to rout_app;
grant execute on function public.signin_guard_status(_identity_hash text) to rout_app;
grant execute on function public.social_links_touch() to rout_app;
grant execute on function public.sync_omni_semantic_draft() to rout_app;
grant execute on function public.sync_social_grid_draft() to rout_app;
grant execute on function public.touch_updated_at() to rout_app;
grant execute on function public.validate_ephemeral_presence() to rout_app;
grant execute on function public.wallet_credit(_user_id uuid, _amount_cents integer, _kind text, _description text, _reference text) to rout_app;
grant execute on function public.wallet_debit(_user_id uuid, _amount_cents integer, _description text, _reference text) to rout_app;
grant execute on function public.workspace_may_drop_suffix(ws_plan text, ws uuid) to rout_app;
grant execute on function public.wt_assert(ok boolean, msg text) to rout_app;

grant usage, select on sequence public.calendar_events_id_seq to rout_app;
