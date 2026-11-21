import { createClient } from "npm:@supabase/supabase-js@2";

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};

function reply(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  if (req.method !== "POST") {
    return reply({ error: "POSTのみ対応しています" }, 405);
  }

  try {
    const authorization = req.headers.get("Authorization");

    if (!authorization?.startsWith("Bearer ")) {
      return reply({ error: "ログインが必要です" }, 401);
    }

    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!url || !anonKey || !serviceRoleKey) {
      return reply({ error: "サーバー設定が不足しています" }, 500);
    }

    const authClient = createClient(url, anonKey);

    const { data: authData, error: authError } =
      await authClient.auth.getUser(authorization.slice(7));

    if (authError || !authData.user) {
      return reply({ error: "認証に失敗しました" }, 401);
    }

    const adminClient = createClient(url, serviceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data: admin, error: adminError } = await adminClient
      .from("app_admins")
      .select("user_id")
      .eq("user_id", authData.user.id)
      .maybeSingle();

    if (adminError) {
      return reply({ error: "ADMIN権限の確認に失敗しました" }, 500);
    }

    if (!admin) {
      return reply({ error: "ADMIN専用機能です" }, 403);
    }

    let body: unknown;

    try {
      body = await req.json();
    } catch {
      return reply({ error: "JSON形式で送信してください" }, 400);
    }

    const targetUserId =
      typeof body === "object" &&
      body !== null &&
      "target_user_id" in body
        ? (body as Record<string, unknown>).target_user_id
        : undefined;

    if (
      typeof targetUserId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(targetUserId)
    ) {
      return reply({
        error: "正しいtarget_user_idを指定してください",
      }, 400);
    }

    if (targetUserId === authData.user.id) {
      return reply({
        error: "自分自身は対象にできません",
      }, 403);
    }

    const { data: targetAdmin, error: targetAdminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", targetUserId)
        .maybeSingle();

    if (targetAdminError) {
      return reply({
        error: "対象の権限確認に失敗しました",
      }, 500);
    }

    if (targetAdmin) {
      return reply({
        error: "ADMINアカウントは対象にできません",
      }, 403);
    }

    const { data: allowed, error: allowedError } =
      await adminClient
        .from("sanno_password_reset_test_targets")
        .select("user_id")
        .eq("user_id", targetUserId)
        .maybeSingle();

    if (allowedError) {
      return reply({
        error: "テスト対象の確認に失敗しました",
      }, 500);
    }

    if (!allowed) {
      return reply({
        error: "登録されたテスト対象ではありません",
      }, 403);
    }

    const { data: target, error: targetError } =
      await adminClient.auth.admin.getUserById(targetUserId);

    if (targetError || !target.user) {
      return reply({
        error: "対象アカウントが存在しません",
      }, 404);
    }

    return reply({
      success: true,
      mode: "preview_only",
      target_verified: true,
      message:
        "ADMIN認証とテスト対象の確認に成功しました。パスワードは変更していません。",
    });
  } catch {
    return reply({
      error: "処理中にエラーが発生しました",
    }, 500);
  }
});
