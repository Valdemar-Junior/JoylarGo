import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

type Payload = {
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
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "Method not allowed" });

  const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  if (!supabaseUrl || !serviceRoleKey) {
    return json(500, { error: "Supabase function secrets are not configured." });
  }

  let payload: Payload = {};
  try { payload = await req.json(); } catch { payload = {}; }

  const authToken = asText(payload.auth_token) || extractBearerToken(req.headers.get("Authorization"));
  if (!authToken) return json(401, { error: "Admin authentication is required." });

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
    return json(403, { error: "Only admins can read settings." });
  }

  const [webhookRes, appSettingsRes] = await Promise.all([
    admin.from("webhook_settings").select("key,url,active,updated_at").order("key"),
    admin.from("app_settings").select("key,value,updated_at").order("key"),
  ]);

  if (webhookRes.error) {
    return json(500, { error: webhookRes.error.message || "Failed to load webhook settings." });
  }
  if (appSettingsRes.error) {
    return json(500, { error: appSettingsRes.error.message || "Failed to load app settings." });
  }

  return json(200, {
    ok: true,
    webhooks: webhookRes.data || [],
    app_settings: appSettingsRes.data || [],
  });
});
