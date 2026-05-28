import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

type DeleteUserPayload = {
  userId?: string;
  auth_token?: string;
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

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

  let payload: DeleteUserPayload;
  try {
    payload = await req.json();
  } catch {
    return json(400, { error: "Invalid JSON body." });
  }

  const userId = asText(payload.userId);
  const authToken = asText(payload.auth_token) || extractBearerToken(req.headers.get("Authorization"));

  if (!userId) {
    return json(400, { error: "Missing userId." });
  }
  if (!authToken) {
    return json(401, { error: "Admin authentication is required." });
  }

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: requesterUser, error: requesterUserError } = await admin.auth.getUser(authToken);
  if (requesterUserError || !requesterUser.user) {
    return json(401, { error: "Invalid admin session." });
  }

  if (requesterUser.user.id === userId) {
    return json(400, { error: "You cannot delete your own admin user." });
  }

  const { data: requesterProfile, error: requesterProfileError } = await admin
    .from("users")
    .select("id, role")
    .eq("id", requesterUser.user.id)
    .single();

  if (requesterProfileError || requesterProfile?.role !== "admin") {
    return json(403, { error: "Only admins can delete users." });
  }

  const { data: targetProfile } = await admin
    .from("users")
    .select("id, role")
    .eq("id", userId)
    .single();

  if (targetProfile?.role === "admin") {
    return json(403, { error: "Deleting admin users is blocked." });
  }

  await admin.from("drivers").delete().eq("user_id", userId);
  await admin.from("teams_user").delete().or(`driver_user_id.eq.${userId},helper_user_id.eq.${userId}`);
  await admin.from("users").delete().eq("id", userId);

  const { error: authDeleteError } = await admin.auth.admin.deleteUser(userId);
  if (authDeleteError) {
    return json(500, { error: authDeleteError.message || "Failed to delete auth user." });
  }

  return json(200, { ok: true });
});
