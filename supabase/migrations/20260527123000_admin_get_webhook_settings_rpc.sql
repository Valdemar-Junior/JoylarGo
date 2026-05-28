create or replace function public.admin_get_webhook_settings()
returns table (
  key text,
  url text,
  active boolean,
  updated_at timestamptz
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
    w.key,
    w.url,
    w.active,
    w.updated_at
  from public.webhook_settings w
  order by w.key;
end;
$$;

revoke all on function public.admin_get_webhook_settings() from public;
grant execute on function public.admin_get_webhook_settings() to authenticated;
