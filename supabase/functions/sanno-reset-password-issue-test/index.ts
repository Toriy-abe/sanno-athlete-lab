import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "https://toriy-abe.github.io",
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};

function reply(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: cors,
  });
}

function makePassword(): string {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZ" +
    "abcdefghijkmnopqrstuvwxyz" +
    "23456789" +
    "!@#$%";

  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  return Array.from(bytes, (n) => chars[n % chars.length]).join("");
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
    const auth = req.headers.get("Authorization");

    if (!auth?.startsWith("Bearer ")) {
      return reply({ error: "ログインが必要です" }, 401);
    }

    const url = Deno.env.get("SUPABASE_URL");
    const anon = Deno.env.get("SUPABASE_ANON_KEY");
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!url || !anon || !service) {
      return reply({ error: "サーバー設定エラー" }, 500);
    }

    const userClient = createClient(url, anon);
    const adminClient = createClient(url, service, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data: authData, error: authError } =
      await userClient.auth.getUser(auth.slice(7));

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

    let body: Record<string, unknown>;

    try {
      body = await req.json();
    } catch {
      return reply({ error: "JSON形式が不正です" }, 400);
    }

    const targetId = body.target_user_id;
    const confirm = body.confirm;

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
      return reply({ error: "対象権限の確認エラー" }, 500);
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
        error: "登録済みテストアカウント以外は変更できません",
      }, 403);
    }

    const { data: target, error: targetError } =
      await adminClient.auth.admin.getUserById(targetId);

    if (targetError || !target.user) {
      return reply({ error: "対象ユーザーが存在しません" }, 404);
    }

    if (confirm !== "ISSUE_TEST_PASSWORD") {
      return reply({
        success: true,
        mode: "preview_only",
        target_verified: true,
        message:
          "対象確認に成功しました。パスワードは変更していません。",
      });
    }

    // 実際の発行処理。
    // テスト対象登録とADMIN権限を確認した場合のみ実行。

    const password = makePassword();
    const now = new Date().toISOString();

    const { error: stateError } = await adminClient
      .from("sanno_password_reset_states")
      .upsert(
        {
          user_id: targetId,
          must_change_password: true,
          reset_requested_at: now,
          reset_requested_by: adminId,
          password_changed_at: null,
          updated_at: now,
        },
        { onConflict: "user_id" },
      );

    if (stateError) {
      return reply({
        error: "変更必須状態の記録に失敗しました",
      }, 500);
    }

    const { error: updateError } =
      await adminClient.auth.admin.updateUserById(
        targetId,
        { password },
      );

    if (updateError) {
      return reply({
        error:
          "パスワード更新に失敗しました。変更必須状態を確認してください。",
      }, 500);
    }

    const { error: logError } = await adminClient
      .from("sanno_password_reset_logs")
      .insert({
        target_user_id: targetId,
        reset_by: adminId,
        reset_at: now,
        action: "test_password_issued",
        details: {
          test_only: true,
          password_stored: false,
        },
      });

    if (logError) {
      // Authの変更は成功済み。
      // ログ記録失敗を隠さず通知する。
      return reply({
        success: true,
        warning:
          "パスワードは更新されましたが、履歴の記録に失敗しました。",
        temporary_password: password,
      });
    }

    return reply({
      success: true,
      mode: "test_password_issued",
      temporary_password: password,
      must_change_password: true,
      message:
        "テストアカウントの仮パスワードを発行しました。",
    });
  } catch {
    return reply({ error: "処理中にエラーが発生しました" }, 500);
  }
});
