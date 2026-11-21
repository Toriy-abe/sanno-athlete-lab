import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (req.method !== "POST") return respond({ error: "POSTのみ対応しています" }, 405);

  try {
    const authorization = req.headers.get("Authorization");
    if (!authorization?.startsWith("Bearer ")) return respond({ error: "ログインが必要です" }, 401);

    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !anonKey || !serviceRoleKey) return respond({ error: "サーバー設定が不足しています" }, 500);

    const authClient = createClient(url, anonKey);
    const { data: authData, error: authError } = await authClient.auth.getUser(authorization.slice(7));
    if (authError || !authData.user) return respond({ error: "認証に失敗しました" }, 401);

    const adminClient = createClient(url, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: admin, error: adminError } = await adminClient
      .from("app_admins").select("user_id").eq("user_id", authData.user.id).maybeSingle();
    if (adminError) return respond({ error: "ADMIN権限の確認に失敗しました" }, 500);
    if (!admin) return respond({ error: "ADMIN専用機能です" }, 403);

    return respond({
      success: true,
      mode: "preview_only",
      message: "ADMIN認証に成功しました。パスワードは変更していません。",
    });
  } catch {
    return respond({ error: "処理中にエラーが発生しました" }, 500);
  }
});
