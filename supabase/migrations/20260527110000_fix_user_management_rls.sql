create or replace function public.is_current_user_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.users u
    where u.id = auth.uid()
      and u.role = 'admin'
  );
$$;

revoke all on function public.is_current_user_admin() from public;
grant execute on function public.is_current_user_admin() to authenticated;

create or replace function public.can_access_driver_row(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select auth.uid() = p_user_id or public.is_current_user_admin();
$$;

revoke all on function public.can_access_driver_row(uuid) from public;
grant execute on function public.can_access_driver_row(uuid) to authenticated;

alter table public.users enable row level security;
alter table public.drivers enable row level security;

drop policy if exists users_select_admin_or_self on public.users;
drop policy if exists users_insert_admin on public.users;
drop policy if exists users_update_admin_or_self on public.users;
drop policy if exists users_delete_admin on public.users;
drop policy if exists "Users can view their own profile" on public.users;
drop policy if exists "Admins can view all users" on public.users;
drop policy if exists "Users can update their own profile" on public.users;
drop policy if exists "Admins can update all users" on public.users;

create policy users_select_admin_or_self
  on public.users
  for select
  to authenticated
  using (id = auth.uid() or public.is_current_user_admin());

create policy users_insert_self_or_admin
  on public.users
  for insert
  to authenticated
  with check (id = auth.uid() or public.is_current_user_admin());

create policy users_update_admin_or_self
  on public.users
  for update
  to authenticated
  using (id = auth.uid() or public.is_current_user_admin())
  with check (id = auth.uid() or public.is_current_user_admin());

create policy users_delete_admin
  on public.users
  for delete
  to authenticated
  using (public.is_current_user_admin());

drop policy if exists "Drivers can view their own record" on public.drivers;
drop policy if exists "Admins can view all drivers" on public.drivers;
drop policy if exists "Admins can manage drivers" on public.drivers;

create policy drivers_select_own_or_admin
  on public.drivers
  for select
  to authenticated
  using (public.can_access_driver_row(user_id));

create policy drivers_insert_admin
  on public.drivers
  for insert
  to authenticated
  with check (public.is_current_user_admin());

create policy drivers_update_own_or_admin
  on public.drivers
  for update
  to authenticated
  using (public.can_access_driver_row(user_id))
  with check (public.can_access_driver_row(user_id));

create policy drivers_delete_admin
  on public.drivers
  for delete
  to authenticated
  using (public.is_current_user_admin());
