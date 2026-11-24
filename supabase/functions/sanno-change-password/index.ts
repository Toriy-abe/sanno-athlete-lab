import { createClient } from "npm:@supabase/supabase-js@2";

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

  try {
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

    // 検証用アカウント限定
    if (
      user.id !==
      "b1fc45aa-7721-476e-8994-ca552d772e75"
    ) {
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
      new_password.length > 72 ||
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
        .eq("user_id", user.id)
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
        .eq("user_id", user.id)
        .single();

    if (
      lockError ||
      lock?.status !== "completed"
    ) {
      return respond({
        error: "Reset not ready",
      }, 409);
    }

    if (!user.email) {
      return respond({
        error: "Email unavailable",
      }, 400);
    }

    // 現在のパスワードで本人確認
    const { data: verified, error: verifyError } =
      await client.auth.signInWithPassword({
        email: user.email,
        password: temporary_password,
      });

    if (
      verifyError ||
      verified.user?.id !== user.id
    ) {
      return respond({
        error: "Password verification failed",
      }, 401);
    }

    // 現段階では本人確認まで実施
    // 更新・解除処理は次のSTEPで追加
    return respond({
      success: true,
      mode: "verification_only",
      password_verified: true,
      must_change_password: true,
    });

  } catch {
    return respond({
      error: "Internal server error",
    }, 500);
  }
});
