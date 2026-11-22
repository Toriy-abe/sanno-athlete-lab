import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigin = "https://toriy-abe.github.io";

const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });

// 暗号学的に安全で、偏りのない乱数
function secureRandomInt(max: number): number {
  if (!Number.isSafeInteger(max) || max <= 0 || max > 256) {
    throw new Error("Invalid random range");
  }

  const limit = 256 - (256 % max);
  const random = new Uint8Array(1);

  while (true) {
    crypto.getRandomValues(random);

    if (random[0] < limit) {
      return random[0] % max;
    }
  }
}

// 4種類の文字を必ず含む仮パスワードを生成
function generatePassword(length = 16): string {
  const groups = [
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "abcdefghijkmnopqrstuvwxyz",
    "23456789",
    "!@#$%*-_",
  ];

  if (!Number.isInteger(length) || length < groups.length) {
    throw new Error("Invalid password length");
  }

  const allChars = groups.join("");

  // 各文字種から最低1文字ずつ選択
  const password: string[] = groups.map(
    (group) => group[secureRandomInt(group.length)]
  );

  // 残りの文字を生成
  while (password.length < length) {
    password.push(
      allChars[secureRandomInt(allChars.length)]
    );
  }

  // 並び順をランダムに変更
  for (let i = password.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);

    [password[i], password[j]] = [
      password[j],
      password[i],
    ];
  }

  return password.join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  try {
    const authHeader = req.headers.get("Authorization");

    if (!authHeader?.startsWith("Bearer ")) {
      return json({ error: "Unauthorized" }, 401);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !anonKey || !serviceKey) {
      return json({ error: "Server configuration error" }, 500);
    }

    const authClient = createClient(supabaseUrl, anonKey);
    const adminClient = createClient(supabaseUrl, serviceKey);

    const token = authHeader.replace("Bearer ", "");

    const { data: userData, error: userError } =
      await authClient.auth.getUser(token);

    if (userError || !userData.user) {
      return json({ error: "Unauthorized" }, 401);
    }

    const adminId = userData.user.id;

    const { data: admin, error: adminError } =
      await adminClient
        .from("app_admins")
        .select("user_id")
        .eq("user_id", adminId)
        .maybeSingle();

    if (adminError) {
      return json({ error: "Admin verification failed" }, 500);
    }

    if (!admin) {
      return json({ error: "Forbidden" }, 403);
    }

    // テスト用：生成したパスワード自体は返さない
    const password = generatePassword();

    return json({
      success: true,
      mode: "password_generation_test",
      admin_verified: true,
      password_length: password.length,
      has_uppercase: /[A-Z]/.test(password),
      has_lowercase: /[a-z]/.test(password),
      has_number: /[0-9]/.test(password),
      has_symbol: /[^A-Za-z0-9]/.test(password),
      password_changed: false,
      message: "仮パスワード生成テストが完了しました。",
    });

  } catch {
    return json({ error: "Internal server error" }, 500);
  }
});
