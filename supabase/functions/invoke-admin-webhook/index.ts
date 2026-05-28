import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

type Payload = {
  auth_token?: string;
  key?: string;
  body?: unknown;
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const allowedKeys = new Set([
  "envia_pedidos",
  "gera_nf",
  "gera_nf_devolucao",
  "envia_mensagem",
  "envia_grupo",
  "consulta_lancamento",
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
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "Method not allowed" });

  const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  if (!supabaseUrl || !serviceRoleKey) {
    return json(500, { error: "Supabase function secrets are not configured." });
  }

  let payload: Payload = {};
  try {
    payload = await req.json();
  } catch {
    return json(400, { error: "Invalid JSON body." });
  }

  const authToken = asText(payload.auth_token) || extractBearerToken(req.headers.get("Authorization"));
  const key = asText(payload.key);

  if (!authToken) return json(401, { error: "Admin authentication is required." });
  if (!key || !allowedKeys.has(key)) return json(400, { error: "Invalid webhook key." });

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
    return json(403, { error: "Only admins can invoke configured webhooks." });
  }

  const { data: setting, error: settingError } = await admin
    .from("webhook_settings")
    .select("url, active")
    .eq("key", key)
    .eq("active", true)
    .single();

  if (settingError || !setting?.url) {
    return json(404, { error: `Webhook not configured for key: ${key}` });
  }

  try {
    const upstream = await fetch(setting.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload.body ?? {}),
    });

    const text = await upstream.text();
    let data: unknown = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }

    return json(upstream.status, {
      ok: upstream.ok,
      status: upstream.status,
      data,
    });
  } catch (error) {
    return json(502, { error: error instanceof Error ? error.message : "Failed to call webhook." });
  }
});
