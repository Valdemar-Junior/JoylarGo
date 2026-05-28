import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

type CompleteFirstLoginPayload = {
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

  let payload: CompleteFirstLoginPayload = {};
  try {
    payload = await req.json();
  } catch {
    payload = {};
  }

  const authToken = asText(payload.auth_token) || extractBearerToken(req.headers.get("Authorization"));
  if (!authToken) {
    return json(401, { error: "Authentication is required." });
  }

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: requesterUser, error: requesterUserError } = await admin.auth.getUser(authToken);
  if (requesterUserError || !requesterUser.user) {
    return json(401, { error: "Invalid session." });
  }

  const userId = requesterUser.user.id;

  const { error: updateError } = await admin
    .from("users")
    .update({ must_change_password: false })
    .eq("id", userId);

  if (updateError) {
    return json(500, { error: updateError.message || "Failed to update profile." });
  }

  const { data: profile, error: profileError } = await admin
    .from("users")
    .select("id,email,name,role,phone,must_change_password,created_at")
    .eq("id", userId)
    .single();

  if (profileError || !profile) {
    return json(500, { error: profileError?.message || "Failed to load profile." });
  }

  return json(200, { ok: true, profile });
});
