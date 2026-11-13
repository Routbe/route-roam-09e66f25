-- 0252 (EXPAND): prune uploaded photos without deleting one that is still in use.
--  * The upload handler kept the newest 3 uploads per member and prefix, so a
--    member with several workspaces lost the logo of one workspace by uploading
--    logos for others, and an older photo still shown on a profile could vanish.
--  * rout_prune_avatar_uploads(prefix, keep) removes only the caller's own
--    uploads with that prefix beyond the newest `keep` that no profile, alias,
--    draft, workspace, workspace draft or app logo references any more.
--    References are checked across all rows (definer), deletes stay limited to
--    rows owned by the caller taken from the transaction context.
-- Additive only: one new function, executable by rout_app.

create function public.rout_prune_avatar_uploads(p_prefix text, p_keep integer)
returns integer
language plpgsql volatile security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := public.rout_current_user_id();
  v_deleted integer := 0;
begin
  if v_caller is null or p_prefix is null or p_prefix not in ('avatar', 'workspace-logo')
     or p_keep is null or p_keep < 1 or p_keep > 20 then
    return 0;
  end if;

  with mine as (
    select a.path, row_number() over (order by a.created_at desc, a.path desc) as rn
      from public.avatar_objects a
     where a.user_id = v_caller
       and pg_catalog.starts_with(a.path, v_caller::text || '/' || p_prefix || '-')
  ), doomed as (
    select m.path, pg_catalog.replace(m.path, '/', '%2F') as enc
      from mine m
     where m.rn > p_keep
  ), unused as (
    select d.path from doomed d
     where not exists (select 1 from public.profiles p
             where pg_catalog.strpos(coalesce(p.avatar_url, '') || ' ' || coalesce(p.favicon_url, ''), d.path) > 0
                or pg_catalog.strpos(coalesce(p.avatar_url, '') || ' ' || coalesce(p.favicon_url, ''), d.enc) > 0)
       and not exists (select 1 from public.alias_profiles ap
             where pg_catalog.strpos(coalesce(ap.avatar_url, '') || ' ' || coalesce(ap.favicon_url, ''), d.path) > 0
                or pg_catalog.strpos(coalesce(ap.avatar_url, '') || ' ' || coalesce(ap.favicon_url, ''), d.enc) > 0)
       and not exists (select 1 from public.profile_drafts pd
             where pg_catalog.strpos(pd.payload::text, d.path) > 0 or pg_catalog.strpos(pd.payload::text, d.enc) > 0)
       and not exists (select 1 from public.workspaces w
             where pg_catalog.strpos(coalesce(w.avatar_url, '') || ' ' || coalesce(w.public_profile::text, ''), d.path) > 0
                or pg_catalog.strpos(coalesce(w.avatar_url, '') || ' ' || coalesce(w.public_profile::text, ''), d.enc) > 0)
       and not exists (select 1 from public.workspace_profile_drafts wd
             where pg_catalog.strpos(wd.payload::text, d.path) > 0 or pg_catalog.strpos(wd.payload::text, d.enc) > 0)
       and not exists (select 1 from public.oauth_clients oc
             where pg_catalog.strpos(coalesce(oc.logo_url, ''), d.path) > 0 or pg_catalog.strpos(coalesce(oc.logo_url, ''), d.enc) > 0)
  ), gone as (
    delete from public.avatar_objects a
     using unused u
     where a.path = u.path and a.user_id = v_caller
    returning 1
  )
  select count(*)::integer into v_deleted from gone;
  return v_deleted;
end $$;
revoke all on function public.rout_prune_avatar_uploads(text, integer) from public;
grant execute on function public.rout_prune_avatar_uploads(text, integer) to rout_app;
