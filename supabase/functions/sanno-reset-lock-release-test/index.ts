import { createClient } from "npm:@supabase/supabase-js@2";

const headers = {
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
    headers,
  });
}

const TEST_TARGET_ID =
  "aa59925f-9f62-46ef-8d50-455da104ef15";

const TEST_REQUEST_ID =
  "e4659dd1-424e-42a2-85d0-b0106b7e060c";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers,
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

    // ログインユーザーの本人確認
    const { data: authData, error: authError } =
      await authClient.auth.getUser(
        authorization.slice(7),
      );

    if (authError || !authData.user) {
      return reply({ error: "認証に失敗しました" }, 401);
    }

    const adminId = authData.user.id;

    // ADMIN権限確認
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

    // テスト対象の確認
    const { data: allowed, error: allowedError } =
      await adminClient
        .from("sanno_password_reset_test_targets")
        .select("user_id")
        .eq("user_id", TEST_TARGET_ID)
        .maybeSingle();

    if (allowedError) {
      return reply({ error: "テスト対象確認エラー" }, 500);
    }

    if (!allowed) {
      return reply({
        error: "登録済みテスト対象ではありません",
      }, 403);
    }

    // 対象がADMINでないことを確認
    const { data: targetAdmin, error: targetAdminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", TEST_TARGET_ID)
        .maybeSingle();

    if (targetAdminError) {
      return reply({ error: "対象権限確認エラー" }, 500);
    }

    if (targetAdmin || TEST_TARGET_ID === adminId) {
      return reply({ error: "ADMINは対象外です" }, 403);
    }

    // ロック状態・取得者を確認
    const { data: lock, error: lockError } =
      await adminClient
        .from("sanno_password_reset_locks")
        .select("request_id,status,locked_by")
        .eq("user_id", TEST_TARGET_ID)
        .maybeSingle();

    if (lockError) {
      return reply({ error: "ロック確認エラー" }, 500);
    }

    if (
      !lock ||
      lock.request_id !== TEST_REQUEST_ID ||
      lock.status !== "completed" ||
      lock.locked_by !== adminId
    ) {
      return reply({
        success: false,
        error: "対象ロックの状態または実行者が一致しません",
      }, 409);
    }

    // ロック解除と履歴記録を実行
    const { data: released, error: releaseError } =
      await adminClient.rpc(
        "sanno_release_test_reset_lock",
        {
          p_user_id: TEST_TARGET_ID,
          p_request_id: TEST_REQUEST_ID,
          p_admin_id: adminId,
        },
      );

    if (releaseError) {
      return reply({
        success: false,
        error: "ロック解除処理に失敗しました",
      }, 500);
    }

    if (released !== true) {
      return reply({
        success: false,
        error: "ロックを解除できませんでした",
      }, 409);
    }

    return reply({
      success: true,
      mode: "lock_release_test",
      admin_verified: true,
      target_verified: true,
      request_id: TEST_REQUEST_ID,
      previous_status: "completed",
      lock_released: true,
      audit_log_written: true,
      password_changed: false,
      message:
        "テスト用ロックを解除し、操作履歴を記録しました。パスワードは変更していません。",
    });

  } catch {
    return reply({
      error: "処理中にエラーが発生しました",
    }, 500);
  }
});
