import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

type ResetPasswordPayload = {
  userId?: string;
  newPassword?: string;
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

  let payload: ResetPasswordPayload;
  try {
    payload = await req.json();
  } catch {
    return json(400, { error: "Invalid JSON body." });
  }

  const userId = asText(payload.userId);
  const newPassword = asText(payload.newPassword);
  const authToken = asText(payload.auth_token) || extractBearerToken(req.headers.get("Authorization"));

  if (!userId || !newPassword) {
    return json(400, { error: "Missing userId or newPassword." });
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

  const { data: requesterProfile, error: requesterProfileError } = await admin
    .from("users")
    .select("id, role")
    .eq("id", requesterUser.user.id)
    .single();

  if (requesterProfileError || requesterProfile?.role !== "admin") {
    return json(403, { error: "Only admins can reset passwords." });
  }

  const { error: updateError } = await admin.auth.admin.updateUserById(userId, {
    password: newPassword,
  });

  if (updateError) {
    return json(500, { error: updateError.message || "Failed to reset password." });
  }

  const { error: profileError } = await admin
    .from("users")
    .update({ must_change_password: true })
    .eq("id", userId);

  if (profileError) {
    return json(500, { error: profileError.message || "Password updated, but failed to mark first-login flag." });
  }

  return json(200, { ok: true });
});
