alter table public.orders
  add column if not exists manifest_id text,
  add column if not exists import_source text;

create index if not exists idx_orders_manifest_id
  on public.orders (manifest_id);

create index if not exists idx_orders_import_source
  on public.orders (import_source);
