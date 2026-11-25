import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://toriy-abe.github.io",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function generatePassword(): string {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  return Array.from(
    bytes,
    (byte) => chars[byte % chars.length]
  ).join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  if (req.method !== "POST") {
    return respond({ error: "POSTのみ対応しています" }, 405);
  }

  try {
    const authorization = req.headers.get("Authorization");

    if (!authorization?.startsWith("Bearer ")) {
      return respond({ error: "ログインが必要です" }, 401);
    }

    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!url || !anonKey || !serviceKey) {
      return respond({ error: "サーバー設定エラー" }, 500);
    }

    const authClient = createClient(url, anonKey);

    const { data: authData, error: authError } =
      await authClient.auth.getUser(authorization.slice(7));

    if (authError || !authData.user) {
      return respond({ error: "認証に失敗しました" }, 401);
    }
    const sessionClient = createClient(
      url,
      anonKey,
      {
        global: {
          headers: {
            Authorization: authorization,
          },
        },
        auth: {
          persistSession: false,
          autoRefreshToken: false,
        },
      },
    );

    const {
      data: sessionAllowed,
      error: sessionError,
    } = await sessionClient.rpc(
      "sanno_session_allowed"
    );

    if (sessionError || sessionAllowed !== true) {
      return respond({
        error: "セッションが無効です。再ログインしてください",
      }, 403);
    }
    const adminId = authData.user.id;

    const adminClient = createClient(url, serviceKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });

    const { data: admin, error: adminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", adminId)
        .maybeSingle();

    if (adminError) {
      return respond({ error: "権限確認エラー" }, 500);
    }

    if (!admin) {
      return respond({ error: "ADMIN専用機能です" }, 403);
    }

    const body = await req.json();

    const targetId = body.target_user_id;

    if (
      targetId !==
      "b1fc45aa-7721-476e-8994-ca552d772e75"
    ) {
      return respond({
        error: "現在は検証用アカウントのみ対応しています",
      }, 403);
    }

    if (targetId === adminId) {
      return respond({ error: "自身は再設定できません" }, 403);
    }

    const { data: targetAdmin, error: targetAdminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", targetId)
        .maybeSingle();

    if (targetAdminError) {
      return respond({ error: "対象者の権限確認エラー" }, 500);
    }

    if (targetAdmin) {
      return respond({ error: "ADMINは再設定対象外です" }, 403);
    }

    const { data: target, error: targetError } =
      await adminClient
        .from("profiles")
        .select("id, display_name, role")
        .eq("id", targetId)
        .maybeSingle();

    if (targetError || !target) {
      return respond({ error: "対象者が見つかりません" }, 404);
    }

    if (target.role !== "player") {
      return respond({ error: "選手のみ再設定可能です" }, 403);
    }

    if (
      body.confirm !== true ||
      body.confirm_display_name !== target.display_name
    ) {
      return respond({ error: "氏名確認が一致しません" }, 400);
    }

    const requestId = crypto.randomUUID();

    const { data: acquired, error: lockError } =
      await adminClient.rpc(
        "sanno_acquire_password_reset_lock",
        {
          p_user_id: targetId,
          p_request_id: requestId,
          p_admin_id: adminId,
        }
      );

    if (lockError || acquired !== true) {
      return respond({
        error: "再設定ロックを取得できません",
      }, 409);
    }

    async function finish(status: string) {
      const { data, error } = await adminClient.rpc(
        "sanno_finish_password_reset_lock",
        {
          p_user_id: targetId,
          p_request_id: requestId,
          p_status: status,
        }
      );

      return !error && data === true;
    }

    try {
      const temporaryPassword = generatePassword();
      const now = new Date().toISOString();

      const { error: stateError } =
        await adminClient
          .from("sanno_password_reset_states")
          .upsert({
            user_id: targetId,
            must_change_password: true,
            reset_requested_at: now,
            reset_requested_by: adminId,
            password_changed_at: null,
            updated_at: now,
          });

      if (stateError) {
        await finish("failed");

        return respond({
          error: "再設定状態の保存に失敗しました",
        }, 500);
      }

      const { error: passwordError } =
        await adminClient.auth.admin.updateUserById(
          targetId,
          { password: temporaryPassword }
        );

      if (passwordError) {
        await finish("needs_review");

        return respond({
          error: "パスワード変更結果の確認が必要です",
          request_id: requestId,
        }, 500);
      }

      const { error: logError } =
        await adminClient
          .from("sanno_password_reset_logs")
          .insert({
            target_user_id: targetId,
            reset_by: adminId,
            action: "temporary_password_issued",
            details: {
              request_id: requestId,
              test_mode: true,
            },
          });

      if (logError) {
        await finish("needs_review");

        return respond({
          error: "パスワード変更済み・監査ログ要確認",
          request_id: requestId,
        }, 500);
      }

      const completed = await finish("completed");

      if (!completed) {
        return respond({
          error: "パスワード変更済み・ロック状態要確認",
          request_id: requestId,
        }, 500);
      }

      return respond({
        success: true,
        mode: "test_only",
        target_user_id: targetId,
        target_display_name: target.display_name,
        temporary_password: temporaryPassword,
        must_change_password: true,
        request_id: requestId,
      });

    } catch {
      await finish("needs_review");

      return respond({
        error: "再設定処理の確認が必要です",
        request_id: requestId,
      }, 500);
    }

  } catch {
    return respond({
      error: "処理中にエラーが発生しました",
    }, 500);
  }
});
