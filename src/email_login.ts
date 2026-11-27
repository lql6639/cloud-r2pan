/**
 * 管理员「邮箱验证码」登录
 * ─────────────────────────────────────────────────────────────
 * 流程：
 *   POST /api/admin/email/send   { email }           → 发 6 位验证码
 *   POST /api/admin/email/login  { email, code, totp? } → 校验并下发会话
 *
 * 设计约束（单管理员后台，安全优先）：
 *   1. 邮箱白名单：只有 env.ADMIN_EMAIL 能收码，其余一律拒发（防被当短信/邮件轰炸器）
 *   2. 验证码只存 HMAC(env.admin, email:code) —— 数据库泄露也反推不出验证码
 *   3. 10 分钟过期、5 次尝试上限、用后即焚、重发即作废旧码
 *   4. 双限流：同邮箱 60 秒一条；同 IP 每小时 10 条（内存计数，isolate 重启清零，只作第一道闸）
 *   5. 若已开启 TOTP，邮箱验证码通过后仍需 6 位动态码（返回 need_2fa）
 */
import type { Env } from "./types";
import { clientIp, createSession, passwordFingerprint } from "./auth";
import { getSettings } from "./settings";
import { decryptSecret, hmacHex, safeEqual, totpVerify } from "./crypto";
import { parseUA } from "./ua";
import { json } from "./pages";

const CODE_TTL_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const EMAIL_GAP_MS = 60 * 1000;
const IP_WINDOW_MS = 60 * 60 * 1000;
const IP_MAX_PER_HOUR = 10;
const RESEND_ENDPOINT = "https://api.resend.com/emails";

/** 内存限流桶：key → 最近命中的时间戳数组 */
const buckets = new Map<string, number[]>();

function takeSlot(key: string, max: number, windowMs: number): { ok: boolean; retryAfter: number } {
  const now = Date.now();
  const arr = (buckets.get(key) ?? []).filter((t) => now - t < windowMs);
  if (arr.length >= max) {
    const retryAfter = Math.max(1, Math.ceil((windowMs - (now - arr[0])) / 1000));
    buckets.set(key, arr);
    return { ok: false, retryAfter };
  }
  arr.push(now);
  buckets.set(key, arr);
  // 顺手清理陈旧 key，避免 Map 无限增长
  if (buckets.size > 500) {
    for (const [k, v] of buckets) {
      if (!v.length || now - v[v.length - 1] > IP_WINDOW_MS) buckets.delete(k);
    }
  }
  return { ok: true, retryAfter: 0 };
}

function normalizeEmail(v: unknown): string {
  return typeof v === "string" ? v.trim().toLowerCase() : "";
}

function randomCode(): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return String(buf[0] % 1_000_000).padStart(6, "0");
}

async function hashCode(env: Env, email: string, code: string): Promise<string> {
  return hmacHex(env.admin, `email-otp:${email}:${code}`);
}

/** 是否已具备邮箱登录条件 */
export function emailLoginEnabled(env: Env): boolean {
  return !!(env.ADMIN_EMAIL && env.RESEND_API_KEY);
}

function codeMailHtml(code: string, ttlMin: number): string {
  return `<!doctype html><html><body style="margin:0;padding:32px;background:#f5f6f8;font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',sans-serif">
  <div style="max-width:460px;margin:0 auto;background:#fff;border-radius:16px;padding:32px 28px;box-shadow:0 6px 24px rgba(0,0,0,.06)">
    <div style="font-size:15px;color:#111;font-weight:700;letter-spacing:-.01em">R2网盘 管理后台</div>
    <div style="font-size:13px;color:#666;margin-top:6px">登录验证码，请勿转发给任何人</div>
    <div style="margin:22px 0;text-align:center;font-size:34px;font-weight:800;letter-spacing:10px;color:#0a7cff;font-family:ui-monospace,Menlo,monospace">${code}</div>
    <div style="font-size:12.5px;color:#8a8f99;line-height:1.7">${ttlMin} 分钟内有效，仅可使用一次。<br>如果不是你本人操作，请忽略本邮件，并检查管理员密码是否泄露。</div>
  </div>
  <div style="max-width:460px;margin:14px auto 0;text-align:center;font-size:11.5px;color:#a8adb8">Powered by R2网盘</div>
</body></html>`;
}

async function sendViaResend(env: Env, to: string, code: string): Promise<{ ok: boolean; detail?: string }> {
  const from = env.MAIL_FROM?.trim() || "cloud-r2pan <onboarding@resend.dev>";
  try {
    const res = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.RESEND_API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [to],
        subject: `R2网盘登录验证码 ${code}`,
        html: codeMailHtml(code, CODE_TTL_MS / 60000),
      }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { ok: false, detail: `resend ${res.status}: ${text.slice(0, 300)}` };
    }
    return { ok: true };
  } catch (err: any) {
    return { ok: false, detail: String(err?.message ?? err).slice(0, 300) };
  }
}

async function writeLoginLog(env: Env, req: Request, result: string, reason: string | null): Promise<void> {
  try {
    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    await env.db
      .prepare(
        `INSERT INTO login_logs(action, ip, browser, os, country, result, reason, created_at)
         VALUES('login', ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        clientIp(req),
        browser,
        os,
        req.headers.get("cf-ipcountry") ?? null,
        result,
        reason,
        Date.now()
      )
      .run();
  } catch {
    /* 日志失败不影响登录 */
  }
}

/** POST /api/admin/email/send —— 发送登录验证码 */
export async function handleEmailCodeSend(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (!emailLoginEnabled(env)) {
    return json(
      {
        error: "not_configured",
        message: "邮箱验证码登录未配置：需要 ADMIN_EMAIL 变量与 RESEND_API_KEY 密钥",
      },
      { status: 503 }
    );
  }

  let body: { email?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: "bad_request", message: "请求体不是合法 JSON" }, { status: 400 });
  }

  const email = normalizeEmail(body.email);
  const allowed = normalizeEmail(env.ADMIN_EMAIL);
  if (!email) return json({ error: "missing_email", message: "请填写邮箱" }, { status: 400 });
  if (email !== allowed) {
    return json({ error: "email_not_allowed", message: "该邮箱未配置为该后台的管理员邮箱" }, { status: 400 });
  }

  const ip = clientIp(req);
  const emailSlot = takeSlot(`e:${email}`, 1, EMAIL_GAP_MS);
  if (!emailSlot.ok) {
    return json(
      { error: "too_frequent", message: `请求过于频繁，请 ${emailSlot.retryAfter} 秒后再试` },
      { status: 429, headers: { "Retry-After": String(emailSlot.retryAfter) } }
    );
  }
  const ipSlot = takeSlot(`i:${ip}`, IP_MAX_PER_HOUR, IP_WINDOW_MS);
  if (!ipSlot.ok) {
    return json(
      { error: "rate_limited", message: "该 IP 请求次数过多，请稍后再试" },
      { status: 429, headers: { "Retry-After": String(ipSlot.retryAfter) } }
    );
  }

  const code = randomCode();
  const codeHash = await hashCode(env, email, code);
  const now = Date.now();

  // 旧码立即作废（同邮箱只允许一条有效码）
  await env.db.prepare("UPDATE email_login_codes SET used = 1 WHERE email = ?1 AND used = 0").bind(email).run();
  await env.db
    .prepare(
      `INSERT INTO email_login_codes(email, code_hash, expires_at, attempts, used, ip, created_at)
       VALUES(?1, ?2, ?3, 0, 0, ?4, ?5)`
    )
    .bind(email, codeHash, now + CODE_TTL_MS, ip, now)
    .run();

  const sent = await sendViaResend(env, email, code);
  if (!sent.ok) {
    // 发信失败就让这条码失效，避免占用用户的尝试次数
    await env.db.prepare("UPDATE email_login_codes SET used = 1 WHERE code_hash = ?1").bind(codeHash).run();
    ctx.waitUntil(writeLoginLog(env, req, "fail", "email_send_failed"));
    console.error("[email-otp] send failed:", sent.detail);
    return json(
      { error: "send_failed", message: "验证码发送失败，请稍后重试或检查发信服务配置" },
      { status: 502 }
    );
  }

  return json({ ok: true, ttl: Math.floor(CODE_TTL_MS / 1000), message: "验证码已发送，请查收邮件" });
}

/** POST /api/admin/email/login —— 校验验证码并下发会话 */
export async function handleEmailCodeLogin(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (!emailLoginEnabled(env)) {
    return json(
      { error: "not_configured", message: "邮箱验证码登录未配置" },
      { status: 503 }
    );
  }

  let body: { email?: string; code?: string; totp?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: "bad_request", message: "请求体不是合法 JSON" }, { status: 400 });
  }

  const email = normalizeEmail(body.email);
  const code = (body.code ?? "").trim();
  if (email !== normalizeEmail(env.ADMIN_EMAIL)) {
    return json({ error: "invalid", message: "邮箱或验证码错误" }, { status: 401 });
  }
  if (!/^\d{6}$/.test(code)) {
    return json({ error: "invalid_code_format", message: "请输入 6 位数字验证码" }, { status: 400 });
  }

  const row: any = await env.db
    .prepare(
      `SELECT id, code_hash, expires_at, attempts, used
       FROM email_login_codes WHERE email = ?1 ORDER BY created_at DESC LIMIT 1`
    )
    .bind(email)
    .first();

  if (!row || row.used) {
    return json({ error: "no_code", message: "验证码不存在或已使用，请重新获取" }, { status: 401 });
  }
  if (Number(row.expires_at) < Date.now()) {
    return json({ error: "expired", message: "验证码已过期，请重新获取" }, { status: 401 });
  }
  if (Number(row.attempts) >= MAX_ATTEMPTS) {
    return json({ error: "too_many_attempts", message: "尝试次数过多，请重新获取验证码" }, { status: 429 });
  }

  await env.db.prepare("UPDATE email_login_codes SET attempts = attempts + 1 WHERE id = ?1").bind(row.id).run();

  const expected = await hashCode(env, email, code);
  if (!safeEqual(expected, String(row.code_hash))) {
    await writeLoginLog(env, req, "fail", "email_code_invalid");
    return json({ error: "invalid", message: "邮箱或验证码错误" }, { status: 401 });
  }

  const url = new URL(req.url);
  const s = await getSettings(env);

  // 已开启 TOTP → 还差一步动态码
  if (s.totpEnabled && s.totpSecretCipher) {
    const totp = (body.totp ?? "").trim();
    if (!totp) return json({ need_2fa: true });
    const secret = await decryptSecret(s.totpSecretCipher, env.admin);
    const ok = secret ? await totpVerify(secret, totp) : false;
    if (!ok) {
      await writeLoginLog(env, req, "fail", "email_2fa_invalid");
      return json({ error: "invalid_2fa", message: "动态码错误" }, { status: 401 });
    }
  }

  // 用后即焚
  await env.db.prepare("UPDATE email_login_codes SET used = 1 WHERE email = ?1").bind(email).run();
  await writeLoginLog(env, req, "success", "email_otp");

  const cookie = await createSession(env, url.protocol === "https:", await passwordFingerprint(s));
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json;charset=utf-8",
      "set-cookie": cookie,
      "cache-control": "no-store",
    },
  });
}
