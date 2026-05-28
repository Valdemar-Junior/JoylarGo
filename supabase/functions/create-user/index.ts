import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

type CreateUserPayload = {
  email?: string;
  password?: string;
  name?: string;
  role?: string;
  phone?: string;
  cpf?: string;
  auth_token?: string;
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const allowedRoles = new Set([
  "admin",
  "driver",
  "helper",
  "montador",
  "conferente",
  "consultor",
]);

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

function asText(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function extractBearerToken(headerValue: string | null) {
  const raw = asText(headerValue);
  if (!raw) return "";
  const match = raw.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json(405, { error: "Method not allowed" });
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

  if (!supabaseUrl || !serviceRoleKey) {
    return json(500, { error: "Supabase function secrets are not configured." });
  }

  let payload: CreateUserPayload;
  try {
    payload = await req.json();
  } catch {
    return json(400, { error: "Invalid JSON body." });
  }

  const email = asText(payload.email).toLowerCase();
  const password = asText(payload.password);
  const name = asText(payload.name);
  const phone = asText(payload.phone);
  const cpf = asText(payload.cpf);
  const role = asText(payload.role || "driver").toLowerCase();
  const authToken = asText(payload.auth_token) || extractBearerToken(req.headers.get("Authorization"));

  if (!email || !password || !name) {
    return json(400, { error: "Missing required fields: email, password, name." });
  }

  if (!allowedRoles.has(role)) {
    return json(400, { error: `Invalid role: ${role}` });
  }

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  if (role !== "driver") {
    if (!authToken) {
      return json(401, { error: "Admin authentication is required for this role." });
    }

    const { data: requesterUser, error: requesterUserError } = await admin.auth.getUser(authToken);
    if (requesterUserError || !requesterUser.user) {
      return json(401, { error: "Invalid admin session." });
    }

    const { data: requesterProfile, error: requesterProfileError } = await admin
      .from("users")
      .select("id, role")
      .eq("id", requesterUser.user.id)
      .single();

    if (requesterProfileError || requesterProfile?.role !== "admin") {
      return json(403, { error: "Only admins can create this type of user." });
    }
  }

  const { data: existingAuthUsers, error: listError } = await admin.auth.admin.listUsers({
    page: 1,
    perPage: 1000,
  });

  if (listError) {
    return json(500, { error: listError.message || "Failed to verify existing users." });
  }

  const existingAuth = existingAuthUsers.users.find((user) => user.email?.toLowerCase() === email);
  if (existingAuth) {
    return json(409, { error: "User with this email already exists." });
  }

  const { data: createdAuth, error: createAuthError } = await admin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: {
      name,
      role,
      phone: phone || null,
      cpf: cpf || null,
    },
  });

  if (createAuthError || !createdAuth.user) {
    return json(500, { error: createAuthError?.message || "Failed to create auth user." });
  }

  const userId = createdAuth.user.id;

  const { error: upsertProfileError } = await admin.from("users").upsert({
    id: userId,
    email,
    name,
    role,
    phone: phone || null,
    must_change_password: true,
  }, {
    onConflict: "id",
  });

  if (upsertProfileError) {
    await admin.auth.admin.deleteUser(userId);
    return json(500, { error: upsertProfileError.message || "Failed to create user profile." });
  }

  if (role === "driver") {
    const { error: driverError } = await admin.from("drivers").insert({
      user_id: userId,
      cpf: cpf || null,
      vehicle_id: null,
      active: true,
    });

    if (driverError) {
      await admin.from("users").delete().eq("id", userId);
      await admin.auth.admin.deleteUser(userId);
      return json(500, { error: driverError.message || "Failed to create driver profile." });
    }
  }

  return json(200, {
    ok: true,
    id: userId,
    email,
    role,
    must_change_password: true,
  });
});
