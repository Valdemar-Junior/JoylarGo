-- Broaden vehicles policies: allow any authenticated user to insert/update/read

alter table public.vehicles enable row level security;

drop policy if exists "vehicles_select_authenticated" on public.vehicles;
create policy "vehicles_select_authenticated"
on public.vehicles
for select
to authenticated
using ( true );

drop policy if exists "vehicles_insert_authenticated" on public.vehicles;
create policy "vehicles_insert_authenticated"
on public.vehicles
for insert
to authenticated
with check ( true );

drop policy if exists "vehicles_update_authenticated" on public.vehicles;
create policy "vehicles_update_authenticated"
on public.vehicles
for update
to authenticated
using ( true )
with check ( true );
