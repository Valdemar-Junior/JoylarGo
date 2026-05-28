create or replace function public.admin_list_teams()
returns table (
  id uuid,
  name text,
  created_at timestamptz,
  driver_name text,
  helper_name text
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
    t.id,
    t.name,
    t.created_at,
    du.name as driver_name,
    hu.name as helper_name
  from public.teams_user t
  left join public.users du on du.id = t.driver_user_id
  left join public.users hu on hu.id = t.helper_user_id
  order by t.created_at desc;
end;
$$;

revoke all on function public.admin_list_teams() from public;
grant execute on function public.admin_list_teams() to authenticated;
