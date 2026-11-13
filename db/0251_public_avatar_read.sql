-- 0251 (EXPAND): public read of uploaded profile photos and workspace logos.
--  * avatar_objects rows are owner-scoped (rout_scope: user_id = caller), so the
--    anonymous /api/public/avatar proxy could never read them and every photo
--    stored through the Neon fallback answered 404 ("photo does not save").
--  * rout_public_avatar(path) returns only content_type + data of exactly one
--    row whose path has the upload shape; no listing, no owner id, no writes.
--  * Writes stay owner-only through the existing rout_scope policy.
-- Additive only: one new function, executable by rout_app.

create function public.rout_public_avatar(p_path text)
returns table (content_type text, data text)
language sql stable security definer set search_path = pg_catalog as $$
  select a.content_type, a.data
    from public.avatar_objects a
   where p_path ~ '^[0-9a-f-]{36}/[A-Za-z0-9._-]{1,120}$'
     and a.path = p_path
   limit 1
$$;
revoke all on function public.rout_public_avatar(text) from public;
grant execute on function public.rout_public_avatar(text) to rout_app;
