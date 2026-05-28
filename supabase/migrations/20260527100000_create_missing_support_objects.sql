create extension if not exists pgcrypto;

create table if not exists public.user_preferences (
  user_id uuid not null references public.users(id) on delete cascade,
  pref_key text not null,
  pref_value jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default timezone('utc', now()),
  primary key (user_id, pref_key)
);

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  entity_type text not null,
  entity_id uuid not null,
  action text not null,
  details jsonb,
  user_id uuid references public.users(id) on delete set null,
  created_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.company_holidays (
  date date primary key,
  description text,
  created_at timestamptz not null default timezone('utc', now()),
  created_by uuid references public.users(id) on delete set null
);

create table if not exists public.delivery_city_rules (
  id uuid primary key default gen_random_uuid(),
  city_name text not null,
  delivery_days integer not null default 15,
  assembly_days integer not null default 15,
  rural_delivery_days integer not null default 25,
  rural_assembly_days integer not null default 20,
  full_delivery_days integer not null default 2,
  full_assembly_days integer not null default 5,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  constraint delivery_city_rules_city_name_unique unique (city_name),
  constraint delivery_city_rules_delivery_days_non_negative check (delivery_days >= 0),
  constraint delivery_city_rules_assembly_days_non_negative check (assembly_days >= 0),
  constraint delivery_city_rules_rural_delivery_days_non_negative check (rural_delivery_days >= 0),
  constraint delivery_city_rules_rural_assembly_days_non_negative check (rural_assembly_days >= 0),
  constraint delivery_city_rules_full_delivery_days_non_negative check (full_delivery_days >= 0),
  constraint delivery_city_rules_full_assembly_days_non_negative check (full_assembly_days >= 0)
);

create table if not exists public.operational_diary (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default timezone('utc', now()),
  date date not null,
  type text not null,
  order_ref text not null default '',
  responsible_staff text not null default '',
  content text not null,
  tags text[] not null default '{}'::text[],
  constraint operational_diary_type_check check (type in ('Entrega', 'Montagem', 'Geral'))
);

create table if not exists public.order_audit_log (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  user_id uuid references public.users(id) on delete set null,
  user_name text,
  field_changed text not null,
  old_value text,
  new_value text,
  created_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.route_conferences (
  id uuid primary key default gen_random_uuid(),
  route_id uuid not null references public.routes(id) on delete cascade,
  status text not null default 'in_progress',
  result_ok boolean,
  started_at timestamptz default timezone('utc', now()),
  finished_at timestamptz,
  user_id uuid references public.users(id) on delete set null,
  summary jsonb,
  created_at timestamptz default timezone('utc', now()),
  resolved_at timestamptz,
  resolved_by uuid references public.users(id) on delete set null,
  resolution jsonb,
  constraint route_conferences_status_check check (status in ('in_progress', 'completed'))
);

create table if not exists public.route_conference_scans (
  id uuid primary key default gen_random_uuid(),
  route_conference_id uuid not null references public.route_conferences(id) on delete cascade,
  normalized_code text not null,
  order_id uuid references public.orders(id) on delete set null,
  product_code text,
  volume_index integer,
  volume_total integer,
  matched boolean default true,
  timestamp timestamptz default timezone('utc', now()),
  created_at timestamptz default timezone('utc', now())
);

create index if not exists audit_logs_entity_type_entity_id_idx
  on public.audit_logs (entity_type, entity_id, created_at desc);

create index if not exists delivery_city_rules_city_name_idx
  on public.delivery_city_rules (city_name);

create index if not exists operational_diary_date_idx
  on public.operational_diary (date desc, created_at desc);

create index if not exists operational_diary_type_idx
  on public.operational_diary (type, date desc);

create index if not exists operational_diary_responsible_staff_idx
  on public.operational_diary (responsible_staff);

create index if not exists order_audit_log_order_id_idx
  on public.order_audit_log (order_id, created_at desc);

create or replace function public.set_delivery_city_rules_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = timezone('utc', now());
  return new;
end;
$$;

drop trigger if exists trg_delivery_city_rules_updated_at on public.delivery_city_rules;

create trigger trg_delivery_city_rules_updated_at
before update on public.delivery_city_rules
for each row
execute function public.set_delivery_city_rules_updated_at();

alter table public.route_conferences
  add column if not exists result_ok boolean,
  add column if not exists started_at timestamptz default timezone('utc', now()),
  add column if not exists finished_at timestamptz,
  add column if not exists resolved_at timestamptz,
  add column if not exists resolved_by uuid references public.users(id) on delete set null,
  add column if not exists resolution jsonb;

create or replace view public.latest_route_conferences as
select distinct on (route_id)
  id,
  route_id,
  status,
  result_ok,
  started_at,
  finished_at,
  created_at,
  user_id,
  summary,
  resolved_at,
  resolved_by,
  resolution
from public.route_conferences
order by route_id, created_at desc;

grant select on public.latest_route_conferences to authenticated;

alter table public.user_preferences enable row level security;
alter table public.audit_logs enable row level security;
alter table public.company_holidays enable row level security;
alter table public.delivery_city_rules enable row level security;
alter table public.operational_diary enable row level security;
alter table public.order_audit_log enable row level security;
alter table public.route_conferences enable row level security;
alter table public.route_conference_scans enable row level security;

do $$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'user_preferences'
      and policyname = 'user_preferences_select_own'
  ) then
    create policy user_preferences_select_own
      on public.user_preferences
      for select
      using (auth.uid() = user_id);
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'user_preferences'
      and policyname = 'user_preferences_upsert_own'
  ) then
    create policy user_preferences_upsert_own
      on public.user_preferences
      for all
      using (auth.uid() = user_id)
      with check (auth.uid() = user_id);
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'audit_logs'
      and policyname = 'audit_logs_select_authenticated'
  ) then
    create policy audit_logs_select_authenticated
      on public.audit_logs
      for select
      using (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'audit_logs'
      and policyname = 'audit_logs_insert_authenticated'
  ) then
    create policy audit_logs_insert_authenticated
      on public.audit_logs
      for insert
      with check (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'company_holidays'
      and policyname = 'company_holidays_rw_authenticated'
  ) then
    create policy company_holidays_rw_authenticated
      on public.company_holidays
      for all
      using (auth.role() = 'authenticated')
      with check (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'delivery_city_rules'
      and policyname = 'delivery_city_rules_rw_authenticated'
  ) then
    create policy delivery_city_rules_rw_authenticated
      on public.delivery_city_rules
      for all
      using (auth.role() = 'authenticated')
      with check (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'operational_diary'
      and policyname = 'operational_diary_rw_authenticated'
  ) then
    create policy operational_diary_rw_authenticated
      on public.operational_diary
      for all
      using (auth.role() = 'authenticated')
      with check (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'order_audit_log'
      and policyname = 'order_audit_log_select_authenticated'
  ) then
    create policy order_audit_log_select_authenticated
      on public.order_audit_log
      for select
      using (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'order_audit_log'
      and policyname = 'order_audit_log_insert_authenticated'
  ) then
    create policy order_audit_log_insert_authenticated
      on public.order_audit_log
      for insert
      with check (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'route_conferences'
      and policyname = 'route_conferences_select_authenticated'
  ) then
    create policy route_conferences_select_authenticated
      on public.route_conferences
      for select
      using (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'route_conferences'
      and policyname = 'route_conferences_insert_authenticated'
  ) then
    create policy route_conferences_insert_authenticated
      on public.route_conferences
      for insert
      with check (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'route_conferences'
      and policyname = 'route_conferences_update_own'
  ) then
    create policy route_conferences_update_own
      on public.route_conferences
      for update
      using (auth.role() = 'authenticated' and user_id = auth.uid())
      with check (auth.role() = 'authenticated' and user_id = auth.uid());
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'route_conferences'
      and policyname = 'route_conferences_update_admin'
  ) then
    create policy route_conferences_update_admin
      on public.route_conferences
      for update
      using (
        exists (
          select 1
          from public.users u
          where u.id = auth.uid()
            and u.role = 'admin'
        )
      )
      with check (
        exists (
          select 1
          from public.users u
          where u.id = auth.uid()
            and u.role = 'admin'
        )
      );
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'route_conference_scans'
      and policyname = 'route_conference_scans_select_authenticated'
  ) then
    create policy route_conference_scans_select_authenticated
      on public.route_conference_scans
      for select
      using (auth.role() = 'authenticated');
  end if;

  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'route_conference_scans'
      and policyname = 'route_conference_scans_insert_authenticated'
  ) then
    create policy route_conference_scans_insert_authenticated
      on public.route_conference_scans
      for insert
      with check (auth.role() = 'authenticated');
  end if;
end $$;
