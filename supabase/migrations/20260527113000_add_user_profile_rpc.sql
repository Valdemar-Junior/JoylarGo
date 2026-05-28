create or replace function public.get_current_user_profile()
returns table (
  id uuid,
  email text,
  name text,
  role text,
  phone text,
  must_change_password boolean,
  created_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select
    u.id,
    u.email,
    u.name,
    u.role,
    u.phone,
    u.must_change_password,
    u.created_at
  from public.users u
  where u.id = auth.uid()
  limit 1;
$$;

revoke all on function public.get_current_user_profile() from public;
grant execute on function public.get_current_user_profile() to authenticated;
