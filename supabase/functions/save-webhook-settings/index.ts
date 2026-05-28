import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

type WebhookRow = {
  key: string;
  url: string;
  active?: boolean;
};

type SaveWebhookSettingsPayload = {
  auth_token?: string;
  rows?: WebhookRow[];
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

  let payload: SaveWebhookSettingsPayload;
  try {
    payload = await req.json();
  } catch {
    return json(400, { error: "Invalid JSON body." });
  }

  const authToken = asText(payload.auth_token) || extractBearerToken(req.headers.get("Authorization"));
  if (!authToken) {
    return json(401, { error: "Admin authentication is required." });
  }

  const rows = Array.isArray(payload.rows) ? payload.rows : [];
  const normalizedRows = rows
    .map((row) => ({
      key: asText(row?.key),
      url: asText(row?.url),
      active: row?.active !== false,
    }))
    .filter((row) => row.key);

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
    return json(403, { error: "Only admins can save webhook settings." });
  }

  const { error } = await admin.from("webhook_settings").upsert(normalizedRows, { onConflict: "key" });
  if (error) {
    return json(500, { error: error.message || "Failed to save webhook settings." });
  }

  return json(200, { ok: true });
});
