import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

Deno.serve(async (req) => {
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
    const authHeader = req.headers.get("Authorization");

    if (!authHeader?.startsWith("Bearer ")) {
      return respond({ error: "ログインが必要です" }, 401);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
      return respond({ error: "サーバー設定が不足しています" }, 500);
    }

    const token = authHeader.slice(7);

    const authClient = createClient(supabaseUrl, anonKey);

    const { data: authData, error: authError } =
      await authClient.auth.getUser(token);

    if (authError || !authData.user) {
      return respond({ error: "認証に失敗しました" }, 401);
    }

    const adminClient = createClient(
      supabaseUrl,
      serviceRoleKey,
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false,
        },
      },
    );

    const adminId = authData.user.id;

    const { data: adminRecord, error: adminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", adminId)
        .maybeSingle();

    if (adminError) {
      return respond({ error: "ADMIN権限の確認に失敗しました" }, 500);
    }

    if (!adminRecord) {
      return respond({ error: "ADMIN専用機能です" }, 403);
    }

    const body = await req.json().catch(() => null);
    const targetUserId = body?.target_user_id;

    if (
      typeof targetUserId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        targetUserId,
      )
    ) {
      return respond({ error: "正しい選手IDを指定してください" }, 400);
    }

    if (targetUserId === adminId) {
      return respond({ error: "自分自身は削除できません" }, 403);
    }

    const { data: targetAdmin, error: targetAdminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", targetUserId)
        .maybeSingle();

    if (targetAdminError) {
      return respond({ error: "対象者の権限確認に失敗しました" }, 500);
    }

    if (targetAdmin) {
      return respond({ error: "ADMINは削除できません" }, 403);
    }

    const { data: profile, error: profileError } =
      await adminClient
        .from("profiles")
        .select("*")
        .eq("id", targetUserId)
        .maybeSingle();

    if (profileError) {
      return respond({ error: "選手情報の取得に失敗しました" }, 500);
    }

    if (!profile) {
      return respond({ error: "対象アカウントが存在しません" }, 404);
    }

    // 本番削除は二段階操作。初回は確認情報のみ返す。
    if (profile.role !== "player") {
      return respond({ error: "選手アカウント以外は削除できません" }, 403);
    }

    const displayName = String(profile.display_name ?? "").trim();
    if (!displayName) {
      return respond({ error: "表示名が未登録のため削除できません" }, 409);
    }

    if (body?.confirm !== true) {
      return respond({
        success: true,
        mode: "confirmation_required",
        target_user_id: targetUserId,
        target_display_name: displayName,
      });
    }

    if (body?.confirm_display_name !== displayName) {
      return respond({ error: "確認用の選手氏名が一致しません" }, 400);
    }

    // 同じ対象の未完了処理があれば停止（並行実行の完全な排他制御ではない）。
    const { data: pendingRows, error: pendingError } = await adminClient
      .from("sanno_account_deletion_logs")
      .select("id")
      .eq("target_user_id", targetUserId)
      .eq("status", "pending")
      .limit(1);
    if (pendingError) return respond({ error: "削除履歴の確認に失敗しました" }, 500);
    if (pendingRows?.length) return respond({ error: "この選手の削除処理が未完了です。管理者が履歴を確認してください" }, 409);

    // 事前チェック専用RPC。ここでは記録を削除しない。
    const { error: preDeleteError } = await adminClient.rpc(
      "sanno_delete_player_records", { p_player_id: targetUserId },
    );
    if (preDeleteError) return respond({
      success: false, mode: "blocked",
      error: "削除前チェックで停止しました。データは削除していません。",
      details: preDeleteError.message,
    }, 409);

    // 監査ログの作成に失敗した場合は絶対に削除しない。
    const { data: logRow, error: logInsertError } = await adminClient
      .from("sanno_account_deletion_logs")
      .insert({
        deleted_by: adminId,
        target_user_id: targetUserId,
        target_display_name: displayName,
        target_group: profile.training_group ?? null,
        status: "pending",
        details: { stage: "before_auth_delete" },
      })
      .select("id")
      .single();
    if (logInsertError?.code === "23505") return respond({
      error: "この選手の削除処理が既に進行中です",
      mode: "already_pending",
    }, 409);
    if (logInsertError || !logRow) return respond({
      error: "削除履歴を作成できなかったため、削除を中止しました",
      details: logInsertError?.message,
    }, 500);

    // auth.users -> profiles -> 対象選手の記録をDBのFK CASCADEで一括削除。
    // 共有履歴のFK制約が残る場合はDB側で削除を拒否する。
    const { error: deleteAuthError } = await adminClient.auth.admin.deleteUser(targetUserId);
    const success = !deleteAuthError;
    const { error: logUpdateError } = await adminClient
      .from("sanno_account_deletion_logs")
      .update({
        status: success ? "success" : "pending",
        details: {
          stage: success ? "auth_deleted" : "auth_delete_uncertain_manual_review",
          error: deleteAuthError?.message ?? null,
        },
      })
      .eq("id", logRow.id);

    if (deleteAuthError) return respond({
      success: false,
      mode: "blocked",
      error: "Auth削除の結果が不明です。自動再試行せず、Authと削除履歴を確認してください。",
      details: deleteAuthError.message,
      log_saved: !logUpdateError,
    }, 500);

    return respond({
      success: true,
      mode: "deleted",
      target_user_id: targetUserId,
      target_display_name: displayName,
      log_saved: !logUpdateError,
      warning: logUpdateError ? "削除は成功しましたが、履歴がpendingのままです。管理者が確認してください。" : undefined,
    });
  } catch {
    return respond({ error: "処理中にエラーが発生しました" }, 500);
  }
});
