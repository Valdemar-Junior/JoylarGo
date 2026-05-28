-- Policies for users table to allow admin manage users without switching session
alter table if exists public.users enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'users'
      and policyname = 'users_select_admin_or_self'
  ) then
    create policy users_select_admin_or_self on public.users
      for select to authenticated
      using (
        id = auth.uid() or exists(select 1 from public.users u where u.id = auth.uid() and u.role = 'admin')
      );
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'users'
      and policyname = 'users_insert_admin'
  ) then
    create policy users_insert_admin on public.users
      for insert to authenticated
      with check (
        exists(select 1 from public.users u where u.id = auth.uid() and u.role = 'admin')
      );
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'users'
      and policyname = 'users_update_admin_or_self'
  ) then
    create policy users_update_admin_or_self on public.users
      for update to authenticated
      using (
        id = auth.uid() or exists(select 1 from public.users u where u.id = auth.uid() and u.role = 'admin')
      )
      with check (
        id = auth.uid() or exists(select 1 from public.users u where u.id = auth.uid() and u.role = 'admin')
      );
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'users'
      and policyname = 'users_delete_admin'
  ) then
    create policy users_delete_admin on public.users
      for delete to authenticated
      using (
        exists(select 1 from public.users u where u.id = auth.uid() and u.role = 'admin')
      );
  end if;
end $$;
