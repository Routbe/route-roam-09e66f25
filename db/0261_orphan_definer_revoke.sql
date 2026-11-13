-- 0261 — Three orphaned SECURITY DEFINER functions leave rout_app, and the account merge executor may run the handle check.
-- callable by the app role. seed_demo_content(_user_id) and
-- grant_signup_badges(_user_id) write demo content and badges for any member id
-- they are given; generate_unique_handle reads every handle. No app code calls
-- them (src/ and the code production runs, schema level 0253), and no policy,
-- view, trigger or other function does (checked on Neon 2026-11-13). Neon's
-- default privileges had given rout_app EXECUTE on them. Only REVOKE.
do $$
declare f text;
begin
  foreach f in array array[
    'public.seed_demo_content(uuid)',
    'public.grant_signup_badges(uuid)',
    'public.generate_unique_handle(text)'
  ] loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    if exists (select 1 from pg_catalog.pg_roles where rolname = 'rout_app') then
      execute pg_catalog.format('revoke all on function %s from rout_app', f);
      if pg_catalog.has_function_privilege('rout_app', f, 'execute') then
        raise exception 'rout_app can still execute %', f;
      end if;
    end if;
  end loop;
end $$;

-- execute_account_merge runs as rout_merge_executor. Keeping the secondary
-- handle updates profiles.username, whose invoker trigger
-- profiles_handle_namespace_guard calls assert_handle_namespace_free with that
-- role's rights. On Neon that function has no PUBLIC grant (and since 0260 a
-- replay has none either), so the merge failed with "permission denied";
-- found by account-merge-postgres.test.ts. The executor gets exactly this one.
grant execute on function public.assert_handle_namespace_free(text, uuid) to rout_merge_executor;
