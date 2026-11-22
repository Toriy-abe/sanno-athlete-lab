import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigin = "https://toriy-abe.github.io";

const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });

function generatePassword(length = 16): string {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZ" +
    "abcdefghijkmnopqrstuvwxyz" +
    "23456789" +
    "!@#$%*-_";

  const random = new Uint32Array(length);
  crypto.getRandomValues(random);

  return Array.from(random, (value) =>
    chars[value % chars.length]
  ).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  try {
    const authHeader = req.headers.get("Authorization");

    if (!authHeader?.startsWith("Bearer ")) {
      return json({ error: "Unauthorized" }, 401);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !anonKey || !serviceKey) {
      return json({ error: "Server configuration error" }, 500);
    }

    const authClient = createClient(supabaseUrl, anonKey);
    const adminClient = createClient(supabaseUrl, serviceKey);

    const token = authHeader.replace("Bearer ", "");

    const { data: userData, error: userError } =
      await authClient.auth.getUser(token);

    if (userError || !userData.user) {
      return json({ error: "Unauthorized" }, 401);
    }

    const adminId = userData.user.id;

    const { data: admin, error: adminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", adminId)
        .maybeSingle();

    if (adminError) {
      return json({ error: "Admin verification failed" }, 500);
    }

    if (!admin) {
      return json({ error: "Forbidden" }, 403);
    }

    // テスト段階ではパスワード自体を返さない
    const password = generatePassword();

    return json({
      success: true,
      mode: "password_generation_test",
      admin_verified: true,
      password_length: password.length,
      has_uppercase: /[A-Z]/.test(password),
      has_lowercase: /[a-z]/.test(password),
      has_number: /[0-9]/.test(password),
      has_symbol: /[^A-Za-z0-9]/.test(password),
      password_changed: false,
      message: "仮パスワード生成テストが完了しました。",
    });

  } catch {
    return json({ error: "Internal server error" }, 500);
  }
});
