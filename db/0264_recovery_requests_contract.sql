-- 0264 — CONTRACT (held back, not applied): rout_app loses its table rights on
-- public.auth_recovery_requests. Since 0263 the functions rout_recovery_* are the
-- only way in. Move this file into db/ only after production runs the code that
-- calls them (the health probe reports schema >= 0263). Nothing breaks: under
-- RLS without a policy the direct access never worked (appendix J).
do $$
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
    return;
  end if;
  revoke all on public.auth_recovery_requests from rout_app;
  if pg_catalog.has_table_privilege('rout_app', 'public.auth_recovery_requests', 'select')
     or pg_catalog.has_table_privilege('rout_app', 'public.auth_recovery_requests', 'insert')
     or pg_catalog.has_table_privilege('rout_app', 'public.auth_recovery_requests', 'update')
     or pg_catalog.has_table_privilege('rout_app', 'public.auth_recovery_requests', 'delete') then
    raise exception 'rout_app still has rights on public.auth_recovery_requests';
  end if;
end $$;
