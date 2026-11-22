import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "https://toriy-abe.github.io",
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};

function reply(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: cors,
  });
}

function generatePassword(): string {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZ" +
    "abcdefghijkmnopqrstuvwxyz" +
    "23456789" +
    "!@#$%";

  const password: string[] = [];
  const limit = Math.floor(256 / chars.length) * chars.length;

  while (password.length < 16) {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);

    for (const byte of bytes) {
      if (byte >= limit) continue;
      password.push(chars[byte % chars.length]);
      if (password.length === 16) break;
    }
  }

  return password.join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: cors,
    });
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
    const anon = Deno.env.get("SUPABASE_ANON_KEY");
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!url || !anon || !service) {
      return reply({ error: "サーバー設定エラー" }, 500);
    }

    const authClient = createClient(url, anon);
    const adminClient = createClient(url, service, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data: authData, error: authError } =
      await authClient.auth.getUser(
        authorization.slice(7)
      );

    if (authError || !authData.user) {
      return reply({ error: "認証に失敗しました" }, 401);
    }

    const adminId = authData.user.id;

    const { data: admin, error: adminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", adminId)
        .maybeSingle();

    if (adminError) {
      return reply({ error: "ADMIN確認エラー" }, 500);
    }

    if (!admin) {
      return reply({ error: "ADMIN専用機能です" }, 403);
    }

    let body: unknown;

    try {
      body = await req.json();
    } catch {
      return reply({ error: "JSON形式が不正です" }, 400);
    }

    if (
      typeof body !== "object" ||
      body === null ||
      Array.isArray(body)
    ) {
      return reply({ error: "入力形式が不正です" }, 400);
    }

    const input = body as Record<string, unknown>;
    const targetId = input.target_user_id;

    const uuidPattern =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    if (
      typeof targetId !== "string" ||
      !uuidPattern.test(targetId)
    ) {
      return reply({ error: "対象UIDが不正です" }, 400);
    }

    if (targetId === adminId) {
      return reply({ error: "自分自身は対象外です" }, 403);
    }

    const { data: targetAdmin, error: targetAdminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", targetId)
        .maybeSingle();

    if (targetAdminError) {
      return reply({ error: "対象権限確認エラー" }, 500);
    }

    if (targetAdmin) {
      return reply({ error: "ADMINは対象外です" }, 403);
    }

    const { data: allowed, error: allowedError } =
      await adminClient
        .from("sanno_password_reset_test_targets")
        .select("user_id")
        .eq("user_id", targetId)
        .maybeSingle();

    if (allowedError) {
      return reply({ error: "テスト対象確認エラー" }, 500);
    }

    if (!allowed) {
      return reply({
        error: "登録済みテストアカウント以外は対象外です",
      }, 403);
    }

    const { data: target, error: targetError } =
      await adminClient.auth.admin.getUserById(targetId);

    if (targetError || !target.user) {
      return reply({ error: "対象ユーザーが存在しません" }, 404);
    }

    // 安全確認段階：
    // パスワード変更は意図的に無効化。
    // 発行処理はデータベース側の
    // 二重実行防止機構を実装後に追加する。

    return reply({
      success: true,
      mode: "preview_only",
      target_verified: true,
      password_changed: false,
      message:
        "ADMIN認証とテスト対象の確認に成功しました。パスワードは変更していません。",
    });

  } catch {
    return reply({
      error: "処理中にエラーが発生しました",
    }, 500);
  }
});
