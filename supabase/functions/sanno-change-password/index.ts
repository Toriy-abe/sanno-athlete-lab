import { createClient } from "npm:@supabase/supabase-js@2";

const TEST_USER_ID =
  "b1fc45aa-7721-476e-8994-ca552d772e75";

const corsHeaders = {
  "Access-Control-Allow-Origin":
    "https://toriy-abe.github.io",
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Cache-Control": "no-store",
};

function respond(
  body: Record<string, unknown>,
  status = 200
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: corsHeaders,
    });
  }

  if (req.method !== "POST") {
    return respond({
      error: "Method not allowed",
    }, 405);
  }

  const url = Deno.env.get("SUPABASE_URL")!;
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceKey =
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  const options = {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  };

  const client = createClient(
    url, anonKey, options
  );

  const admin = createClient(
    url, serviceKey, options
  );

  let userId: string | null = null;
  let requestId: string | null = null;
  let acquired = false;

  async function markForReview() {
    if (!acquired || !userId || !requestId) {
      return;
    }

    await admin.rpc(
      "sanno_finish_password_reset_lock",
      {
        p_user_id: userId,
        p_request_id: requestId,
        p_status: "needs_review",
      }
    );
  }

  try {
    const authorization =
      req.headers.get("Authorization") || "";

    if (!authorization.startsWith("Bearer ")) {
      return respond({
        error: "Unauthorized",
      }, 401);
    }

    const token = authorization.slice(7);

    const { data: authData, error: authError } =
      await client.auth.getUser(token);

    if (authError || !authData.user) {
      return respond({
        error: "Unauthorized",
      }, 401);
    }

    const user = authData.user;
    userId = user.id;

    if (userId !== TEST_USER_ID) {
      return respond({
        error: "Test account only",
      }, 403);
    }

    const {
      temporary_password,
      new_password,
    } = await req.json();

    if (
      typeof temporary_password !== "string" ||
      typeof new_password !== "string" ||
      new_password.length < 8 ||
      new TextEncoder().encode(new_password).length > 72 ||
      temporary_password === new_password
    ) {
      return respond({
        error: "Invalid password",
      }, 400);
    }

    const { data: state, error: stateError } =
      await admin
        .from("sanno_password_reset_states")
        .select("must_change_password")
        .eq("user_id", userId)
        .single();

    if (
      stateError ||
      !state?.must_change_password
    ) {
      return respond({
        error: "Password reset not required",
      }, 403);
    }

    const { data: lock, error: lockError } =
      await admin
        .from("sanno_password_reset_locks")
        .select("request_id, status")
        .eq("user_id", userId)
        .single();

    if (
      lockError ||
      lock?.status !== "completed"
    ) {
      return respond({
        error: "Reset not ready",
      }, 409);
    }

    requestId = lock.request_id;

    if (!user.email) {
      return respond({
        error: "Email unavailable",
      }, 400);
    }

    const { data: verified, error: verifyError } =
      await client.auth.signInWithPassword({
        email: user.email,
        password: temporary_password,
      });

    if (
      verifyError ||
      verified.user?.id !== userId ||
      !verified.session
    ) {
      return respond({
        error: "Password verification failed",
      }, 401);
    }

    // 二重実行防止
    const {
      data: beginResult,
      error: beginError,
    } = await admin.rpc(
      "sanno_begin_password_change",
      {
        p_user_id: userId,
        p_request_id: requestId,
      }
    );

    if (beginError || beginResult !== true) {
      await client.auth.signOut({
        scope: "local",
      });

      return respond({
        error: "Password change already processing",
      }, 409);
    }

    acquired = true;

    // 新しいパスワードへ更新
    const { error: updateError } =
      await admin.auth.admin.updateUserById(
        userId,
        {
          password: new_password,
        }
      );

    if (updateError) {
      await markForReview();

      return respond({
        error: "Password update requires review",
      }, 500);
    }

    // 既存セッションの失効
    const {data:sessionCount,error:sessionCountError}
  = await admin.rpc("sanno_count_reset_sessions",{
    p_user_id:userId
  });

if(sessionCountError || sessionCount===null){
  await markForReview();
  return respond({
    error:"Session check requires review"
  },500);
}

if(Number(sessionCount)>0){
  await admin.auth.admin.signOut(
    verified.session.access_token,"global"
  );
}

const {data:remainingSessions,error:remainingError}
  = await admin.rpc("sanno_count_reset_sessions",{
    p_user_id:userId
  });

if(remainingError || remainingSessions===null || Number(remainingSessions)!==0){
  await markForReview();
  return respond({
    error:"Session revocation requires review"
  },500);
}

    // 利用制限解除・監査ログ保存
    const {
      data: completeResult,
      error: completeError,
    } = await admin.rpc(
      "sanno_complete_password_change",
      {
        p_user_id: userId,
        p_request_id: requestId,
      }
    );

    if (
      completeError ||
      completeResult !== true
    ) {
      await markForReview();

      return respond({
        error: "Completion requires review",
      }, 500);
    }

    acquired = false;

    return respond({
      success: true,
      mode: "test_only",
      password_changed: true,
      must_change_password: false,
      login_required: true,
    });

  } catch {
    try {
      await markForReview();
    } catch {
      // 利用制限を維持
    }

    return respond({
      error: "Internal server error",
    }, 500);
  }
});
