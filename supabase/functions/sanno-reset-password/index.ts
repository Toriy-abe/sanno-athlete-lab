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

    const recovery = body.mode === "recovery";
    if (body.mode !== undefined && body.mode !== "recovery") {
      return respond({ error: "Invalid mode" }, 400);
    }
    const requestId = crypto.randomUUID();
    let recoveryArgs = {};
    if (recovery) {
      if (typeof body.recovery_reason !== "string" || !body.recovery_reason.trim() || body.recovery_reason.length > 500) {
        return respond({ error: "復旧理由を入力してください" }, 400);
      }
      const { data: lock, error } = await adminClient.from("sanno_password_reset_locks").select("request_id,status").eq("user_id",targetId).maybeSingle();
      if (error || lock?.status !== "failed") return respond({ error: "復旧可能な状態ではありません" },409);
      recoveryArgs = { p_old_request_id: lock.request_id, p_new_request_id: requestId, p_reason: body.recovery_reason.trim() };
    }
    const { data: acquired, error: lockError } = await adminClient.rpc(
      recovery ? "sanno_prepare_password_recovery_v2" : "sanno_prepare_password_reset_v2",
      { p_user_id: targetId, p_admin_id: adminId, ...(recovery ? recoveryArgs : { p_request_id: requestId }) }
    );
    if (lockError || acquired !== true) {
      return respond({ error: "再設定を開始できません。状態を確認してください", request_id: requestId }, 409);
    }

    async function finish(status: string) {
      const { data, error } = await adminClient.rpc(
        "sanno_fail_password_operation_v2", {
          p_user_id: targetId,
          p_request_id: requestId,
          p_operation: "issue",
          p_status: status,
        });
      return !error && data === true;
    }

    try {
      const temporaryPassword = generatePassword();
      const { error: passwordError } =
        await adminClient.auth.admin.updateUserById(targetId, {
          password: temporaryPassword,
        });
      if (passwordError) {
        await finish("needs_review");
        return respond({ error: "パスワード変更結果の確認が必要です", request_id: requestId }, 500);
      }
      const { data: count, error: countError } = await adminClient.rpc(
        "sanno_count_reset_sessions_v2", { p_user_id: targetId });
      if (countError || count !== 0) {
        await finish("needs_review");
        return respond({ error: "残存セッションの確認が必要です", request_id: requestId }, 500);
      }
      const { data: completed, error: completeError } = await adminClient.rpc(
        "sanno_complete_password_reset_v2", {
          p_user_id: targetId,
          p_request_id: requestId,
        });
      if (completeError || completed !== true) {
        await finish("needs_review");
        return respond({ error: "発行完了状態の確認が必要です", request_id: requestId }, 500);
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
