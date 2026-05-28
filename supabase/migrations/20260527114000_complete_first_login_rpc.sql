create or replace function public.complete_first_login()
returns table (
  id uuid,
  email text,
  name text,
  role text,
  phone text,
  must_change_password boolean,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.users
  set must_change_password = false
  where id = auth.uid();

  return query
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
end;
$$;

revoke all on function public.complete_first_login() from public;
grant execute on function public.complete_first_login() to authenticated;
