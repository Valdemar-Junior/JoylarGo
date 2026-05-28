create or replace function public.admin_list_users()
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
  if not public.is_current_user_admin() then
    raise exception 'Not authorized';
  end if;

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
  order by u.name;
end;
$$;

revoke all on function public.admin_list_users() from public;
grant execute on function public.admin_list_users() to authenticated;
