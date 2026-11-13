-- 0254: rout_pairwise_register runs with search_path = pg_catalog.
--  * 0209 created it as SECURITY DEFINER pinned to the public schema. Every
--    SECURITY DEFINER function must pin search_path to pg_catalog, so nothing
--    the caller can place on the path is ever resolved inside it.
--  * Same signature, body and behaviour: first registration wins, a subject
--    never moves to another key or sector. Every object is schema-qualified.
--  * CREATE OR REPLACE keeps owner and grants; they are re-asserted below
--    (EXECUTE for rout_app only, never PUBLIC).
-- Hardening only: no table, column or data change.

create or replace function public.rout_pairwise_register(p_sub text, p_sector_hash text, p_public_key text)
returns boolean language plpgsql security definer set search_path = pg_catalog as $$
begin
  insert into public.pairwise_subjects (sub, sector_hash, public_key) values (p_sub, p_sector_hash, p_public_key)
  on conflict (sub) do nothing;
  return exists (
    select 1 from public.pairwise_subjects
     where sub = p_sub and sector_hash = p_sector_hash and public_key = p_public_key
  );
end $$;

revoke execute on function public.rout_pairwise_register(text, text, text) from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'rout_app') then
    grant execute on function public.rout_pairwise_register(text, text, text) to rout_app;
  end if;
end $$;
