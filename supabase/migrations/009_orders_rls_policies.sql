-- Ensure RLS and permissions for orders table so admin can write
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;

-- Cleanup existing conflicting policies
DROP POLICY IF EXISTS "All authenticated users can view orders" ON public.orders;
DROP POLICY IF EXISTS "Admins can manage orders" ON public.orders;
DROP POLICY IF EXISTS "Admins can insert orders" ON public.orders;
DROP POLICY IF EXISTS "Admins can update orders" ON public.orders;
DROP POLICY IF EXISTS "Admins can delete orders" ON public.orders;
DROP POLICY IF EXISTS orders_select_authenticated ON public.orders;
DROP POLICY IF EXISTS orders_insert_admin_safe ON public.orders;
DROP POLICY IF EXISTS orders_update_admin_safe ON public.orders;
DROP POLICY IF EXISTS orders_delete_admin_safe ON public.orders;

-- Read for any authenticated user
CREATE POLICY orders_select_authenticated
  ON public.orders FOR SELECT
  TO authenticated
  USING (true);

-- Admin write policies
CREATE POLICY orders_insert_admin_safe
  ON public.orders FOR INSERT
  TO authenticated
  WITH CHECK (public.is_current_user_admin());

CREATE POLICY orders_update_admin_safe
  ON public.orders FOR UPDATE
  TO authenticated
  USING (public.is_current_user_admin())
  WITH CHECK (public.is_current_user_admin());

CREATE POLICY orders_delete_admin_safe
  ON public.orders FOR DELETE
  TO authenticated
  USING (public.is_current_user_admin());

-- Grants for authenticated role
GRANT SELECT, INSERT, UPDATE, DELETE ON public.orders TO authenticated;
