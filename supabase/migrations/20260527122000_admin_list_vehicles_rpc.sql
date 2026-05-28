create or replace function public.admin_list_vehicles()
returns table (
  id uuid,
  model text,
  plate text,
  active boolean
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
    v.id,
    v.model,
    v.plate,
    v.active
  from public.vehicles v
  order by v.model;
end;
$$;

revoke all on function public.admin_list_vehicles() from public;
grant execute on function public.admin_list_vehicles() to authenticated;
