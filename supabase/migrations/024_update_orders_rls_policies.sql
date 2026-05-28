-- Refresh orders RLS using the security-definer admin helper.
-- This avoids recursive policy evaluation against public.users.

alter table public.orders enable row level security;

drop policy if exists "Users can view their own data" on public.orders;
drop policy if exists "Admins can insert orders" on public.orders;
drop policy if exists "Admins can update orders" on public.orders;
drop policy if exists "Admins can delete orders" on public.orders;
drop policy if exists orders_select_authenticated on public.orders;
drop policy if exists orders_insert_admin_safe on public.orders;
drop policy if exists orders_update_admin_safe on public.orders;
drop policy if exists orders_delete_admin_safe on public.orders;

create policy orders_select_authenticated
  on public.orders
  for select
  to authenticated
  using (true);

create policy orders_insert_admin_safe
  on public.orders
  for insert
  to authenticated
  with check (public.is_current_user_admin());

create policy orders_update_admin_safe
  on public.orders
  for update
  to authenticated
  using (public.is_current_user_admin())
  with check (public.is_current_user_admin());

create policy orders_delete_admin_safe
  on public.orders
  for delete
  to authenticated
  using (public.is_current_user_admin());

grant select, insert, update, delete on public.orders to authenticated;
