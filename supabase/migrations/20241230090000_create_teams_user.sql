create table if not exists public.teams_user (
  id uuid primary key default gen_random_uuid(),
  driver_user_id uuid not null references public.users(id) on delete cascade,
  helper_user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists teams_user_driver_user_id_idx
  on public.teams_user (driver_user_id);

create index if not exists teams_user_helper_user_id_idx
  on public.teams_user (helper_user_id);

create unique index if not exists teams_user_driver_helper_unique_idx
  on public.teams_user (driver_user_id, helper_user_id);

alter table public.teams_user enable row level security;

do $$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'teams_user'
      and policyname = 'teams_user_select_authenticated'
  ) then
    create policy teams_user_select_authenticated
      on public.teams_user
      for select
      using (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'teams_user'
      and policyname = 'teams_user_insert_authenticated'
  ) then
    create policy teams_user_insert_authenticated
      on public.teams_user
      for insert
      with check (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'teams_user'
      and policyname = 'teams_user_update_authenticated'
  ) then
    create policy teams_user_update_authenticated
      on public.teams_user
      for update
      using (auth.role() = 'authenticated')
      with check (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'teams_user'
      and policyname = 'teams_user_delete_authenticated'
  ) then
    create policy teams_user_delete_authenticated
      on public.teams_user
      for delete
      using (auth.role() = 'authenticated');
  end if;
end $$;
