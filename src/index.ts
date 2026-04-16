import { Hono } from 'hono';
import { cors } from 'hono/cors';
import Stripe from 'stripe';

export interface Env {
  LICENSE_DB: D1Database;
  LICENSE_ARCHIVE?: R2Bucket;
  SECURITY_COORDINATOR: DurableObjectNamespace;
  INTERNAL_API_TOKEN: string;
  LEGACY_VERIFY_URL?: string;
  LEGACY_VERIFY_TOKEN?: string;
  LICENSE_PEPPER: string;
  HWID_PEPPER: string;
  RESPONSE_PROOF_SECRET: string;
  MAINTENANCE_DEFAULT_MESSAGE: string;
  PROOF_VERSION?: string;

  // New Secrets for Payment Migration
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  STRIPE_PRICE_MONTHLY: string;
  STRIPE_PRICE_LIFETIME: string;
  DISCORD_CLIENT_ID: string;
  DISCORD_CLIENT_SECRET: string;
  DISCORD_BOT_TOKEN: string;
  ADMIN_SESSION_SECRET: string;
  FRONTEND_URL: string;
  REDIRECT_URI: string;
}

// --- Types ---
type VerifyRequest = {
  licenseKey?: string;
  hwid?: string;
  nonce?: string;
  clientTime?: number;
};

type VerifyResponse = {
  valid: boolean;
  premiumAllowed?: boolean;
  status: string;
  reason: string;
  licenseType: string;
  tier: string;
  expiresAt: number;
  issuedAt?: number;
  deviceHash?: string;
  message: string;
  serverTime: number;
  proof?: string;
  proofVersion?: string;
};

type SecurityCheckResult = {
  ok: boolean;
  reason?: "rate_limited" | "replay_nonce";
};

type LegacyVerifyResult = {
  valid: boolean;
  status?: string;
  reason?: string;
  tier?: string;
  licenseType?: string;
  expiresAt?: number;
  deviceBound?: boolean;
  source?: string;
};

// --- Constants ---
const MAX_NONCE_AGE_MS = 2 * 60 * 1000;
const RATE_LIMIT_MAX = 40;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const PREMIUM_SESSION_TTL_MS = 15 * 60 * 1000;

// SECRET ADMIN PATH
const SECRET_ADMIN_PREFIX = "Hiimkleslwrtodayimjustheretosaywhykfdlajsfklsadjfklajsdfkczimagineifididthesametoubrothatskindalikehmmitwouldhurtrightfkajskasdjfkasjdfkasjdfklasjf242532";
const GUILD_ID = "1457759928247914598";

// --- Utils ---
const nowMs = (): number => Date.now();

function randomId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return prefix ? `${prefix}_${hex}` : hex;
}

function normalizeTier(raw: string): { tier: string; licenseType: string } {
  const t = (raw || "").toLowerCase();
  if (t === "trial" || t === "free") return { tier: "Trial", licenseType: "free" };
  if (t === "monthly") return { tier: "Monthly", licenseType: "premium" };
  if (t === "lifetime") return { tier: "Lifetime", licenseType: "premium" };
  return { tier: raw || "Monthly", licenseType: "premium" };
}

async function get_keygen_config(env: Env, provider: 'lootlabs' | 'workink'): Promise<any | null> {
  const row = await env.LICENSE_DB.prepare(`SELECT config_value FROM app_config WHERE config_key = ?1 LIMIT 1`).bind(provider).first<{ config_value: string }>();
  if (row?.config_value) {
    try {
      return JSON.parse(row.config_value);
    } catch {
      return null;
    }
  }
  // Fallback for legacy LootLabs key
  if (provider === 'lootlabs') {
    const directRow = await env.LICENSE_DB.prepare(`SELECT config_value FROM app_config WHERE config_key = 'lootlabs_keygen_id' LIMIT 1`).first<{ config_value: string }>();
    if (directRow?.config_value) return { keygen: directRow.config_value };
  }
  return null;
}

function keyMask(input: string): { prefix: string; last4: string } {
  const clean = input.trim().toUpperCase();
  const prefix = clean.slice(0, 4) || "KLES";
  const last4 = clean.slice(-4).padStart(4, "X");
  return { prefix, last4 };
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function normalizeIp(req: Request): string {
  const cfIp = req.headers.get("CF-Connecting-IP");
  return cfIp?.trim() || "0.0.0.0";
}

// --- Hono App ---
const app = new Hono<{ Bindings: Env }>();

import { getCookie, setCookie, deleteCookie } from 'hono/cookie';

// Enable CORS for frontend and trial requests
const ALLOWED_ORIGINS = ['https://kleslwr.com', 'https://www.kleslwr.com'];

app.use('*', cors({
  origin: (origin) => {
    if (ALLOWED_ORIGINS.includes(origin)) return origin;
    // Allow for preview/development origins if they match the domain pattern
    if (origin.endsWith('.kleslwr.com')) return origin;
    return ALLOWED_ORIGINS[0];
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Admin-UUID', 'X-Requested-With'],
  exposeHeaders: ['Content-Length'],
  credentials: true,
}))

// Admin Middleware
app.use(`/${SECRET_ADMIN_PREFIX}/*`, async (c, next) => {
  const path = c.req.path;
  if (path === `/${SECRET_ADMIN_PREFIX}/auth/login` || path === `/${SECRET_ADMIN_PREFIX}/auth/logout`) return next();
  
  const session = getCookie(c, 'kles_admin_session');
  if (!session) return c.json({ ok: false, message: 'No session' }, 401);
  
  const verified = await verifyAdminSession(c.env, session);
  if (!verified) return c.json({ ok: false, message: 'Invalid session' }, 401);
  
  await next();
});

// OAuth State Token Utils
const base64url = (input: string) => {
  const bytes = new TextEncoder().encode(input);
  let base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

async function createStateToken(env: Env, plan: string) {
  const payload = base64url(JSON.stringify({ plan, ts: Date.now() }));
  const sig = await hmacHex(env.ADMIN_SESSION_SECRET, payload);
  return `${payload}.${sig}`;
}

async function verifyStateToken(env: Env, state: string) {
  if (!state || !state.includes('.')) return null;
  const [payload, sig] = state.split('.');
  const expected = await hmacHex(env.ADMIN_SESSION_SECRET, payload);
  if (sig !== expected) return null;
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const parsed = JSON.parse(json);
    if (!parsed.plan || !parsed.ts) return null;
    if (Date.now() - Number(parsed.ts) > 15 * 60 * 1000) return null; // 15 min expiry
    return parsed;
  } catch {
    return null;
  }
}

// Admin Session Utils
async function signAdminSession(env: Env, discordId: string): Promise<string> {
  const payload = base64url(JSON.stringify({ sub: discordId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 })); // 7 days
  const sig = await hmacHex(env.ADMIN_SESSION_SECRET, payload);
  return `${payload}.${sig}`;
}

async function verifyAdminSession(env: Env, session: string): Promise<any | null> {
  if (!session || !session.includes('.')) return null;
  const [payload, sig] = session.split('.');
  const expected = await hmacHex(env.ADMIN_SESSION_SECRET, payload);
  if (sig !== expected) return null;
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const parsed = JSON.parse(json);
    if (Date.now() > parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

// User Session Utils (for "Login Once" — customers)
async function signUserSession(env: Env, userData: any): Promise<string> {
  const avatarUrl = userData.avatar 
    ? `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png` 
    : `https://cdn.discordapp.com/embed/avatars/${parseInt(userData.discriminator || "0") % 5}.png`;

  const payload = base64url(JSON.stringify({ 
    sub: userData.id, 
    username: userData.username, 
    avatar: avatarUrl,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000 
  })); // 30 days
  const sig = await hmacHex(env.ADMIN_SESSION_SECRET, payload);
  return `${payload}.${sig}`;
}

async function verifyUserSession(env: Env, session: string): Promise<any | null> {
  if (!session || !session.includes('.')) return null;
  const [payload, sig] = session.split('.');
  const expected = await hmacHex(env.ADMIN_SESSION_SECRET, payload);
  if (sig !== expected) return null;
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const parsed = JSON.parse(json);
    if (Date.now() > parsed.exp) return null;
    return parsed; // Returns the full user payload { sub, username, avatar }
  } catch {
    return null;
  }
}

// Shared purchase logic (used by both cookie-path and OAuth-path)
async function handlePurchaseFlow(c: any, plan: string, discordId: string) {
  const tierInfo = normalizeTier(plan === 'trial' ? 'Trial' : plan);
  
  // Pre-purchase check: Prevent duplicate active licenses for the same tier
  try {
    const existing = await c.env.LICENSE_DB.prepare(
      "SELECT 1 FROM licenses WHERE discord_id = ?1 AND tier = ?2 AND status = 'active' LIMIT 1"
    ).bind(discordId, tierInfo.tier).first();

    if (existing) {
      console.log(`[Buy] User ${discordId} already has an active ${tierInfo.tier} license. Redirecting to success page.`);
      return c.redirect(`${c.env.FRONTEND_URL}/success`);
    }
  } catch (err) {
    console.error(`[Buy] DB pre-check failed:`, err);
  }

  if (plan === 'trial') {
    // 1. Check for Workink (Secure Key System)
    const workink = await get_keygen_config(c.env, 'workink');
    if (workink && workink.link_id && workink.api_key) {
      try {
        // Build the dynamic destination with the {TOKEN} placeholder for security
        // Use our public API URL for the webhook
        const webhookUrl = `https://api.kleslwr.com/webhook/workink?unique_id=${discordId}&token={TOKEN}`;
        const customDest = encodeURIComponent(webhookUrl);
        
        console.log(`[Workink] Requesting override for user ${discordId}`);
        const overrideRes = await fetch(`https://work.ink/_api/v2/override?destination=${customDest}`, {
          headers: { 'X-Api-Key': workink.api_key }
        });
        
        if (overrideRes.ok) {
          const { sr } = await overrideRes.json<{ sr: string }>();
          const finalUrl = `https://work.ink/${workink.link_id}?sr=${sr}`;
          console.log(`[Buy] Redirecting to Secure Workink: ${finalUrl}`);
          return c.redirect(finalUrl);
        } else {
          console.error(`[Workink] Override API failed: ${overrideRes.status}`);
        }
      } catch (err: any) {
        console.error(`[Workink] Override Error: ${err.message}`);
      }
    }

    // 2. Fallback to LootLabs (Legacy)
    const lootlabs = await get_keygen_config(c.env, 'lootlabs');
    if (lootlabs && lootlabs.keygen) {
      const lootLabsUrl = `https://loot-link.com/s?${lootlabs.keygen}&unique_id=${discordId}`;
      console.log(`[Buy] Redirecting to LootLabs fallback: ${lootLabsUrl}`);
      return c.redirect(lootLabsUrl);
    }

    // 3. Instant fulfillment if no provider configured
    console.warn("No Trial monetization provider configured. Bypassing to instant fulfillment.");
    const trialSessionId = `trial_${discordId}_${Date.now()}`;
    await fulfillOrder(c.env, {
      discordId,
      tier: 'Trial',
      stripeSessionId: trialSessionId,
      stripeCustomerId: 'free_tier'
    });
    return c.redirect(`${c.env.FRONTEND_URL}/success?session_id=${trialSessionId}`);
  }

  // Paid tiers
  const stripe = new Stripe(c.env.STRIPE_SECRET_KEY, { apiVersion: '2024-12-18.acacia' as any });
  const priceId = plan === 'monthly' ? c.env.STRIPE_PRICE_MONTHLY : c.env.STRIPE_PRICE_LIFETIME;
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{ price: priceId, quantity: 1 }],
    mode: plan === 'monthly' ? 'subscription' : 'payment',
    success_url: `${c.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${c.env.FRONTEND_URL}/#pricing`,
    client_reference_id: discordId,
    metadata: { discord_id: discordId, plan },
  });
  return c.redirect(session.url!);
}

// ─── 1. License Verification Routines (Original logic) ───────────────────────

app.post('/api/license/verify', async (c) => {
  const env = c.env;
  let body: VerifyRequest;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ valid: false, reason: "invalid_payload", message: "Invalid JSON." }, 400);
  }

  const { licenseKey, hwid, nonce, clientTime } = {
    licenseKey: (body.licenseKey ?? "").trim().toUpperCase(),
    hwid: (body.hwid ?? "").trim(),
    nonce: (body.nonce ?? "").trim(),
    clientTime: Number(body.clientTime ?? 0)
  };

  if (!licenseKey || !hwid || !nonce || !clientTime) {
    return c.json({ valid: false, reason: "missing_fields", message: "licenseKey, hwid, nonce, clientTime are required." }, 400);
  }

  if (Math.abs(nowMs() - clientTime) > MAX_NONCE_AGE_MS) {
    return c.json({ valid: false, reason: "stale_request", message: "Request timestamp is too old." }, 400);
  }

  const ip = normalizeIp(c.req.raw);
  const licenseKeyHash = await sha256Hex(`${env.LICENSE_PEPPER}:${licenseKey}`);
  const hwidHash = await sha256Hex(`${env.HWID_PEPPER}:${hwid}`);
  const ipHash = await sha256Hex(ip);

  // Security Check via Durable Object
  const secId = env.SECURITY_COORDINATOR.idFromName("global");
  const secRes = await env.SECURITY_COORDINATOR.get(secId).fetch("https://security/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      nonce,
      key: licenseKeyHash.slice(0, 24),
      hwid: hwidHash.slice(0, 24),
      ip: ipHash.slice(0, 24),
      now: nowMs(),
      windowMs: RATE_LIMIT_WINDOW_MS,
      max: RATE_LIMIT_MAX,
    }),
  });
  const sec = (await secRes.json<SecurityCheckResult>()) ?? { ok: false, reason: "rate_limited" };
  
  if (!sec.ok) {
    await logEvent(env, { eventType: "verify", outcome: "blocked", reason: sec.reason, ipHash, hwidHash });
    return c.json({ valid: false, reason: sec.reason, message: "Request blocked." }, 429);
  }

  // DB Query
  const row = await env.LICENSE_DB.prepare(
    `SELECT id, tier, license_type, status, expires_at, device_limit
     FROM licenses WHERE key_hash = ?1 LIMIT 1`
  ).bind(licenseKeyHash).first<{
    id: string; tier: string; license_type: string; status: string; expires_at: number | null; device_limit: number;
  }>();

  const serverTime = nowMs();
  
  if (!row) {
    // Legacy Check (Fallback to existing Render legacy endpoint if configured)
    const legacy = await verifyAgainstLegacyStore(env, { licenseKey, hwid });
    if (legacy?.valid) {
      const resp: VerifyResponse = {
        valid: true, premiumAllowed: legacy.licenseType === "premium", status: legacy.status || "active",
        reason: "ok_legacy", licenseType: legacy.licenseType || "free", tier: legacy.tier || "Trial",
        expiresAt: legacy.expiresAt || 0, issuedAt: serverTime, deviceHash: hwidHash,
        message: "License verified (legacy).", serverTime
      };
      resp.proof = await makeProof(env, resp, nonce);
      resp.proofVersion = env.PROOF_VERSION || "v1";
      await logEvent(env, { eventType: "verify", outcome: "allowed", reason: "ok_legacy", ipHash, hwidHash, details: { source: "legacy" } });
      return c.json(resp);
    }
    return c.json({ valid: false, reason: "invalid_key", message: "Invalid key." });
  }

  let status = row.status;
  const expiresAt = row.expires_at ?? 0;
  if (expiresAt > 0 && expiresAt < serverTime && status === "active") {
    status = "expired";
    await env.LICENSE_DB.prepare("UPDATE licenses SET status = 'expired', updated_at = ?1 WHERE id = ?2").bind(serverTime, row.id).run();
  }

  if (status !== "active") {
    return c.json({ valid: false, status, reason: status === "banned" ? "key_banned" : "key_expired", message: "License not active." });
  }

  // Device Binding
  const existingDevice = await env.LICENSE_DB.prepare(
    `SELECT id FROM license_devices WHERE license_id = ?1 AND hwid_hash = ?2 LIMIT 1`
  ).bind(row.id, hwidHash).first();

  if (!existingDevice) {
    const countRow = await env.LICENSE_DB.prepare(`SELECT COUNT(*) as c FROM license_devices WHERE license_id = ?1`).bind(row.id).first<{ c: number }>();
    if ((countRow?.c ?? 0) >= (row.device_limit || 1)) {
      return c.json({ valid: false, reason: "hwid_mismatch", message: "Device limit reached." });
    }
    await env.LICENSE_DB.prepare(`INSERT INTO license_devices (license_id, hwid_hash, first_seen_at, last_seen_at) VALUES (?1, ?2, ?3, ?4)`).bind(row.id, hwidHash, serverTime, serverTime).run();
  } else {
    await env.LICENSE_DB.prepare(`UPDATE license_devices SET last_seen_at = ?1 WHERE license_id = ?2 AND hwid_hash = ?3`).bind(serverTime, row.id, hwidHash).run();
  }

  const result: VerifyResponse = {
    valid: true, premiumAllowed: row.license_type === "premium", status: "active", reason: "ok",
    licenseType: row.license_type, tier: row.tier, expiresAt, issuedAt: serverTime, deviceHash: hwidHash,
    message: "Verified.", serverTime
  };
  result.proof = await makeProof(env, result, nonce);
  return c.json(result);
});

// ─── 2. Payment Flow (Migrated from Render) ──────────────────────────────────

// Step 1: Buy Link -> Check cookie OR Discord Redirect
app.get('/buy/:plan', async (c) => {
  const plan = c.req.param('plan');
  if (plan !== 'monthly' && plan !== 'lifetime' && plan !== 'trial' && plan !== 'login') return c.text('Invalid plan', 400);

  // Check if user already has a valid session ("Login Once")
  const userSession = getCookie(c, 'kles_user_session');
  if (userSession) {
    const userData = await verifyUserSession(c.env, userSession);
    if (userData && userData.sub) {
      console.log(`[Buy] Returning user ${userData.sub} — skipping OAuth for ${plan}`);
      if (plan === 'login') return c.redirect(c.env.FRONTEND_URL);
      return handlePurchaseFlow(c, plan, userData.sub);
    }
  }

  // No valid session — send to Discord OAuth
  const state = await createStateToken(c.env, plan);
  const discordUrl = `https://discord.com/api/oauth2/authorize?client_id=${c.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(c.env.REDIRECT_URI)}&response_type=code&scope=identify&state=${state}`;
  
  return c.redirect(discordUrl);
});

// Step 2: Discord Callback -> Stripe Checkout
app.get('/callback', async (c) => {
  const { code, state, error } = c.req.query();
  if (error) return c.text(`Auth error: ${error}`, 400);
  
  const parsedState = await verifyStateToken(c.env, state);
  if (!parsedState) return c.text('Invalid or expired session. Please try again.', 401);

  // Exchange Code for Token
  const tokenParams = new URLSearchParams({
    client_id: c.env.DISCORD_CLIENT_ID,
    client_secret: c.env.DISCORD_CLIENT_SECRET,
    grant_type: 'authorization_code',
    code,
    redirect_uri: c.env.REDIRECT_URI,
  });

  const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    body: tokenParams,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  if (!tokenRes.ok) return c.text('Failed to authenticate with Discord.', 500);
  const tokenData: any = await tokenRes.json();

  // Get User Info
  const userRes = await fetch('https://discord.com/api/users/@me', {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  const userData: any = await userRes.json();

  // Save user session cookie so they don't need to re-authorize ("Login Once")
  const userSessionToken = await signUserSession(c.env, userData);
  setCookie(c, 'kles_user_session', userSessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'None',
    maxAge: 30 * 24 * 60 * 60, // 30 days
    path: '/',
    domain: '.kleslwr.com' // Share across api., www., and root
  });
  console.log(`[Callback] Saved user session for Discord ID: ${userData.id}`);

  // Check if they are a completely new user (no previous licenses)
  try {
    const dbCheck = await c.env.LICENSE_DB.prepare(
      `SELECT 1 FROM licenses WHERE discord_id = ? LIMIT 1`
    ).bind(userData.id).first();

    if (!dbCheck) {
      await sendDiscordWelcomeDM(c.env, userData.id, userData.username);
    }
  } catch (err) {
    console.error(`[Callback] DB Check for Welcome DM failed:`, err);
  }

  // If this was just a login, redirect home
  if (parsedState.plan === 'login') {
    return c.redirect(c.env.FRONTEND_URL);
  }

  // Use shared purchase flow
  return handlePurchaseFlow(c, parsedState.plan, userData.id);
});

// User Info endpoint for the front-end header
app.get('/api/user/me', async (c) => {
  const userSession = getCookie(c, 'kles_user_session');
  if (!userSession) return c.json({ loggedIn: false });
  
  const userData = await verifyUserSession(c.env, userSession);
  if (!userData) return c.json({ loggedIn: false });

  return c.json({
    loggedIn: true,
    id: userData.sub,
    username: userData.username,
    avatar: userData.avatar
  });
});

// Endpoint for success.html to grab the user's generated license key without needing S2S session_id
app.get('/api/user/latest-key', async (c) => {
  const userSession = getCookie(c, 'kles_user_session');
  if (!userSession) return c.json({ found: false });
  
  const userData = await verifyUserSession(c.env, userSession);
  if (!userData || !userData.sub) return c.json({ found: false });

  const dbRes = await c.env.LICENSE_DB.prepare(
    `SELECT plain_key, tier FROM licenses WHERE discord_id = ? AND status = 'active' AND plain_key IS NOT NULL ORDER BY created_at DESC LIMIT 1`
  ).bind(userData.sub).first();
  
  if (!dbRes || !dbRes.plain_key) return c.json({ found: false });
  return c.json({ found: true, key: dbRes.plain_key, tier: dbRes.tier });
});


// Step 2.5: LootLabs Postback Webhook
app.get('/webhook/lootlabs', async (c) => {
  const puid = String(c.req.query('unique_id') || c.req.query('puid') || "");
  if (!puid) return c.text('Missing unique_id or puid', 400);

  console.log(`[LootLabs] Received postback for user: ${puid}`);

  try {
    const trialSessionId = `loot_${puid}_${Date.now()}`;
      await fulfillOrder(c.env, {
        discordId: puid,
        tier: 'Trial',
        stripeSessionId: trialSessionId,
        stripeCustomerId: 'lootlabs'
      }, "LootLabs");
    return c.json({ ok: true, message: 'Fulfillment triggered.' });
  } catch (err: any) {
    console.error(`[LootLabs] Fulfillment Error: ${err.message}`);
    return c.json({ ok: false, message: err.message }, 500);
  }
});

// Step 2.6: Work.ink Postback Webhook (Secure)
app.get('/webhook/workink', async (c) => {
  const { token, unique_id } = c.req.query();
  const secret = c.req.query('secret');

  if (!unique_id) return c.text('Missing unique_id', 400);

  // Admin Bypass for Testing
  if (secret && secret === c.env.ADMIN_SESSION_SECRET) {
    console.log(`[Workink] Admin Bypass triggered for user: ${unique_id}`);
    try {
      await fulfillOrder(c.env, {
        discordId: unique_id,
        tier: 'Trial',
        stripeSessionId: `bypass_${unique_id}_${Date.now()}`,
        stripeCustomerId: 'admin_bypass'
      }, "Work.ink (Bypass)");
      return c.json({ ok: true, message: 'Fulfillment bypassed correctly.' });
    } catch (err: any) {
      return c.json({ ok: false, message: err.message }, 500);
    }
  }

  if (!token) return c.text('Missing token', 400);

  console.log(`[Workink] Verifying token for user: ${unique_id}`);

  try {
    const workink = await get_keygen_config(c.env, 'workink');
    if (!workink?.api_key) throw new Error('Work.ink API key not configured');

    const verifyRes = await fetch(`https://work.ink/_api/v2/token/isValid/${token}`, {
      headers: { 'X-Api-Key': workink.api_key }
    });

    const verifyData = await verifyRes.json<{ valid: boolean }>();
    if (!verifyData.valid) {
      console.warn(`[Workink] Invalid token attempt for user ${unique_id}`);
      return c.text('Invalid or expired token', 403);
    }

    const trialSessionId = `workink_${unique_id}_${Date.now()}`;
    await fulfillOrder(c.env, {
      discordId: unique_id,
      tier: 'Trial',
      stripeSessionId: trialSessionId,
      stripeCustomerId: 'workink'
    }, "Work.ink");

    console.log(`[Workink] Token verified. Fulfillment triggered.`);
    return c.redirect(`${c.env.FRONTEND_URL}/success?session_id=${trialSessionId}`);
  } catch (err: any) {
    console.error(`[Workink] Verification Error: ${err.message}`);
    return c.json({ ok: false, message: err.message }, 500);
  }
});

// Step 3: Webhook -> License Generation
app.post('/webhook/stripe', async (c) => {
  const sig = c.req.header('stripe-signature');
  const body = await c.req.text();
  const stripe = new Stripe(c.env.STRIPE_SECRET_KEY, { apiVersion: '2024-12-18.acacia' as any });

  console.log(`[Webhook] Received request. Signature present: ${!!sig}`);

  let event;
  try {
    event = await stripe.webhooks.constructEventAsync(body, sig!, c.env.STRIPE_WEBHOOK_SECRET);
  } catch (err: any) {
    console.error(`[Webhook] Signature Verification Failed: ${err.message}`);
    return c.text(`Webhook Error: ${err.message}`, 400);
  }

  console.log(`[Webhook] Processing event type: ${event.type}`);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as any;
    const discordId = session.client_reference_id || session.metadata?.discord_id;
    const plan = session.metadata?.plan || 'unknown';
    const tier = plan === 'monthly' ? 'Monthly' : (plan === 'trial' ? 'Trial' : 'Lifetime');

    console.log(`[Webhook] Checkout Completed. Session: ${session.id}, User: ${discordId}, Plan: ${plan}`);

    if (discordId) {
      try {
        await fulfillOrder(c.env, {
          discordId,
          tier,
          stripeSessionId: session.id,
          stripeCustomerId: session.customer,
        }, "Stripe");
        console.log(`[Webhook] Order Fulfilled successfully.`);
      } catch (err: any) {
        console.error(`[Webhook] Fulfillment Failed: ${err.message}`);
        // Log to D1 error table if possible (skipped for simplicity but crash caught)
      }
    } else {
      console.warn(`[Webhook] No Discord ID found in session metadata or client_reference_id.`);
    }
  }

  return c.json({ received: true });
});

// ─── 3. Internal Functions ───────────────────────────────────────────────────

async function fulfillOrder(env: Env, body: { discordId: string, tier: string, stripeSessionId: string, stripeCustomerId: string }, createdBy: string = "System") {
  const tierInfo = normalizeTier(body.tier);
  const createdAt = nowMs();
  
  // Prevent duplicate key generation for the same user and tier if a key is already active
  const existing = await env.LICENSE_DB.prepare(
    "SELECT id FROM licenses WHERE discord_id = ?1 AND tier = ?2 AND status = 'active' LIMIT 1"
  ).bind(body.discordId, tierInfo.tier).first();

  if (existing) {
    console.log(`[Fulfill] User ${body.discordId} already has an active ${tierInfo.tier} license. Skipping generation.`);
    return;
  }

  
  // Trial = 24 hours, others = 30 days or null
  let expiresAt: number | null = null;
  if (tierInfo.tier === "Trial") {
    expiresAt = createdAt + 1 * 24 * 60 * 60 * 1000; // 24 Hours
  } else if (tierInfo.tier === "Monthly") {
    expiresAt = createdAt + 30 * 24 * 60 * 60 * 1000;
  }
  let plainKey = "";
  if (tierInfo.tier === "Trial") {
    // Generate clean 4-4 blocks: KLESF-XXXX-XXXX
    const r1 = randomId("").slice(0, 4).toUpperCase();
    const r2 = randomId("").slice(0, 4).toUpperCase();
    plainKey = `KLESF-${r1}-${r2}`;
  } else {
    // Generate clean 4-4-4-4 blocks: KLESP-XXXX-XXXX-XXXX-XXXX
    const r1 = randomId("").slice(0, 4).toUpperCase();
    const r2 = randomId("").slice(0, 4).toUpperCase();
    const r3 = randomId("").slice(0, 4).toUpperCase();
    const r4 = randomId("").slice(0, 4).toUpperCase();
    plainKey = `KLESP-${r1}-${r2}-${r3}-${r4}`;
  }
  const masks = keyMask(plainKey);
  const keyHash = await sha256Hex(`${env.LICENSE_PEPPER}:${plainKey}`);
  const licenseId = randomId("lic");

  await env.LICENSE_DB.prepare(
    `INSERT INTO licenses (id, key_hash, key_prefix, key_last4, tier, license_type, status, discord_id, stripe_session_id, stripe_customer_id, device_limit, issued_at, expires_at, created_at, updated_at, created_by, plain_key)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?8, ?9, 1, ?10, ?11, ?12, ?13, ?14, ?15)`
  ).bind(licenseId, keyHash, masks.prefix, masks.last4, tierInfo.tier, tierInfo.licenseType, body.discordId, body.stripeSessionId, body.stripeCustomerId, createdAt, expiresAt, createdAt, createdAt, createdBy, plainKey).run();

  // Send Discord DM ONLY for Premium (Trial skips DM)
  if (tierInfo.tier !== "Trial") {
    await sendDiscordDM(env, body.discordId, plainKey, tierInfo.tier, expiresAt);
  }
}

async function sendDiscordWelcomeDM(env: Env, discordId: string, username: string) {
  const token = env.DISCORD_BOT_TOKEN;
  if (!token) return;

  try {
    const dmRes = await fetch('https://discord.com/api/v10/users/@me/channels', {
      method: 'POST',
      headers: { Authorization: `Bot ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipient_id: discordId }),
    });

    if (!dmRes.ok) return;
    const dmChannel: any = await dmRes.json();
    if (!dmChannel.id) return;

    await fetch(`https://discord.com/api/v10/channels/${dmChannel.id}/messages`, {
      method: 'POST',
      headers: { Authorization: `Bot ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: '🎉 Welcome to KlesLwR!',
          description: `Hello **${username}**, your Discord account is now linked to the KlesLwR dashboard.\n\nReady to get started? Head to the website to grab your macro keys!`,
          color: 0x00c853,
          timestamp: new Date().toISOString()
        }]
      })
    });
  } catch (err) {
    console.error(`[Discord] Welcome DM error:`, err);
  }
}

async function sendDiscordDM(env: Env, discordId: string, key: string, tier: string, expiresAt: number | null) {
  const token = env.DISCORD_BOT_TOKEN;
  if (!token) {
    console.error(`[Discord] Bot token missing.`);
    return;
  }

  const expiryLine = expiresAt ? `**Expires:** ${new Date(expiresAt).toLocaleDateString()}` : '**Expires:** Never (Lifetime)';
  
  try {
    const dmRes = await fetch('https://discord.com/api/v10/users/@me/channels', {
      method: 'POST',
      headers: { Authorization: `Bot ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipient_id: discordId }),
    });

    if (!dmRes.ok) {
      const errTxt = await dmRes.text();
      console.error(`[Discord] Error creating DM channel: ${errTxt}`);
      return;
    }

    const dmChannel: any = await dmRes.json();
    if (!dmChannel.id) {
      console.error(`[Discord] No DM channel ID returned.`);
      return;
    }
    
    const msgRes = await fetch(`https://discord.com/api/v10/channels/${dmChannel.id}/messages`, {
      method: 'POST',
      headers: { Authorization: `Bot ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: `**Payment Success!**\n\nThank you for choosing KlesLwR. Your license has been activated.\n\n**Tier:** ${tier}\n**License Key:** \`${key}\`\n${expiryLine}\n\n**Download Dashboard:** [Click Here](https://kleslwr.com/download)`
      }),
    });

    if (!msgRes.ok) {
      const errTxt = await msgRes.text();
      console.error(`[Discord] Error sending message: ${errTxt}`);
    } else {
      console.log(`[Discord] DM sent successfully to ${discordId}.`);
    }
  } catch (err: any) {
    console.error(`[Discord] Exception: ${err.message}`);
  }
}

// Helper: Logging
async function logEvent(env: Env, input: any) {
  const createdAt = nowMs();
  await env.LICENSE_DB.prepare(
    `INSERT INTO license_events (license_id, event_type, outcome, reason, ip_hash, hwid_hash, created_at, details_json)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
  ).bind(input.licenseId ?? null, input.eventType, input.outcome, input.reason ?? null, input.ipHash, input.hwidHash, createdAt, input.details ? JSON.stringify(input.details) : null).run();
}

// Admin / Internal Routes (Migrated)
app.get('/api/status', async (c) => {
  const rows = await c.env.LICENSE_DB.prepare(`SELECT config_key, config_value FROM app_config`).all<{ config_key: string, config_value: string }>();
  const configMap: Record<string, string> = {};
  for (const r of (rows.results || [])) {
    configMap[r.config_key] = r.config_value;
  }
  
  // Parse structured configs
  let lootlabs = { keygen: '', download: '' };
  let workink = { link: '' };
  try {
     if (configMap['lootlabs']) lootlabs = JSON.parse(configMap['lootlabs']);
     if (configMap['workink']) workink = JSON.parse(configMap['workink']);
  } catch (e) {}

  return c.json({ 
    maintenance: {
      enabled: configMap['maintenance_enabled'] === 'true' || (configMap['maintenance'] && JSON.parse(configMap['maintenance']).enabled), 
      message: configMap['maintenance_message'] || (configMap['maintenance'] && JSON.parse(configMap['maintenance']).message) || c.env.MAINTENANCE_DEFAULT_MESSAGE 
    },
    lootlabs: lootlabs,
    workink: workink
  });
});

// Admin API Routes (Restored)
app.post(`/${SECRET_ADMIN_PREFIX}/auth/login`, async (c) => {
  const { token } = await c.req.json<{ token: string }>();
  // Use ADMIN_SESSION_SECRET as the primary password for now
  if (token !== c.env.ADMIN_SESSION_SECRET) {
    return c.json({ ok: false, message: 'Invalid admin token' }, 403);
  }
  
  const session = await signAdminSession(c.env, 'admin_user');
  setCookie(c, 'kles_admin_session', session, {
    httpOnly: true,
    secure: true,
    sameSite: 'None', // Needed for cross-domain dashboard if on different subdomain
    maxAge: 7 * 24 * 60 * 60, // 7 days
    path: '/'
  });
  
  return c.json({ ok: true });
});

app.get(`/${SECRET_ADMIN_PREFIX}/auth/status`, async (c) => {
  return c.json({ ok: true, user: 'admin' });
});

app.post(`/${SECRET_ADMIN_PREFIX}/auth/logout`, async (c) => {
  deleteCookie(c, 'kles_admin_session', { path: '/', secure: true, sameSite: 'None' });
  return c.json({ ok: true });
});

app.get(`/${SECRET_ADMIN_PREFIX}/stats`, async (c) => {
  const trials = await c.env.LICENSE_DB.prepare("SELECT COUNT(*) as c FROM licenses WHERE tier = 'Trial'").first<{c:number}>();
  const monthly = await c.env.LICENSE_DB.prepare("SELECT COUNT(*) as c FROM licenses WHERE tier = 'Monthly'").first<{c:number}>();
  const lifetime = await c.env.LICENSE_DB.prepare("SELECT COUNT(*) as c FROM licenses WHERE tier = 'Lifetime'").first<{c:number}>();
  
  // Basic growth data (last 7 days)
  const growth = await c.env.LICENSE_DB.prepare(`
    SELECT date(created_at/1000, 'unixepoch') as d, COUNT(*) as count 
    FROM licenses 
    WHERE created_at > ?1 
    GROUP BY d 
    ORDER BY d ASC
  `).bind(Date.now() - 7*24*60*60*1000).all<{d:string, count:number}>();

  return c.json({
    free_count: trials?.c || 0,
    premium_count: (monthly?.c || 0) + (lifetime?.c || 0),
    growth_data: growth.results.map(r => ({ date: r.d, count: r.count }))
  });
});

app.get(`/${SECRET_ADMIN_PREFIX}/keys`, async (c) => {
  const search = c.req.query('search') || '';
  let query = "SELECT * FROM licenses";
  let params: any[] = [];
  if (search) {
    query += " WHERE id LIKE ?1 OR discord_id LIKE ?1 OR key_prefix LIKE ?1";
    params.push(`%${search}%`);
  }
  query += " ORDER BY created_at DESC LIMIT 100";
  
  const rows = await c.env.LICENSE_DB.prepare(query).bind(...params).all();
  
  // Map rows to dashboard format
  const keys = (rows.results || []).map((r: any) => ({
    key: r.plain_key || `${r.key_prefix || 'KLES-****'}-****-****-${r.key_last4 || '****'}`,
    owner: r.discord_id || r.stripe_customer_id || 'System',
    email: r.stripe_customer_id?.includes('@') ? r.stripe_customer_id : null,
    type: r.license_type || 'premium',
    tier: r.tier || 'Monthly',
    generatedAt: r.created_at || Date.now(),
    expiresAt: r.expires_at || 'PERMANENT',
    source: r.stripe_session_id === 'manual' ? 'admin' : (r.stripe_session_id?.startsWith('cs_') ? 'kofi' : 'web'),
    createdBy: r.created_by
  }));

  return c.json({ keys });
});

app.get(`/${SECRET_ADMIN_PREFIX}/discord-user/:id`, async (c) => {
  const userId = c.req.param('id');
  
  try {
    // Try Guild Member first for Server Nickname/PFP
    let res = await fetch(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`, {
      headers: { 'Authorization': `Bot ${c.env.DISCORD_BOT_TOKEN}` }
    });

    if (res.ok) {
      const member: any = await res.json();
      const user = member.user;
      
      const avatar = member.avatar || user.avatar;
      const avatarUrl = avatar 
        ? (member.avatar 
            ? `https://cdn.discordapp.com/guilds/${GUILD_ID}/users/${userId}/avatars/${member.avatar}.png`
            : `https://cdn.discordapp.com/avatars/${userId}/${user.avatar}.png`)
        : `https://cdn.discordapp.com/embed/avatars/${parseInt(user.discriminator || "0") % 5}.png`;

      return c.json({
        id: userId,
        username: user.username,
        display_name: member.nick || user.global_name || user.username,
        avatar: avatarUrl,
        roles: member.roles,
        joined_at: member.joined_at,
        in_guild: true
      });
    }

    // Fallback to Global User Profile
    res = await fetch(`https://discord.com/api/v10/users/${userId}`, {
      headers: { 'Authorization': `Bot ${c.env.DISCORD_BOT_TOKEN}` }
    });

    if (res.ok) {
      const user: any = await res.json();
      const avatarUrl = user.avatar 
        ? `https://cdn.discordapp.com/avatars/${userId}/${user.avatar}.png`
        : `https://cdn.discordapp.com/embed/avatars/${parseInt(user.discriminator || "0") % 5}.png`;

      return c.json({
        id: userId,
        username: user.username,
        display_name: user.global_name || user.username,
        avatar: avatarUrl,
        in_guild: false
      });
    }

    return c.json({ error: 'User not found' }, 404);
  } catch (err) {
    return c.json({ error: 'Discord API Error' }, 500);
  }
});

app.post(`/${SECRET_ADMIN_PREFIX}/key-details`, async (c) => {
  const { key } = await c.req.json<{ key: string }>();
  const keyHash = await sha256Hex(`${c.env.LICENSE_PEPPER}:${key}`);
  const row = await c.env.LICENSE_DB.prepare("SELECT * FROM licenses WHERE key_hash = ?1").bind(keyHash).first();
  return c.json({ found: !!row, ...row });
});

app.post(`/${SECRET_ADMIN_PREFIX}/bulk-revoke`, async (c) => {
  const { target } = await c.req.json<{ target: 'trial' | 'all' }>();
  let query = "UPDATE licenses SET status = 'revoked', updated_at = ?1 WHERE status = 'active'";
  if (target === 'trial') {
    query += " AND tier = 'Trial'";
  }
  
  const now = Date.now();
  await c.env.LICENSE_DB.prepare(query).bind(now).run();
  
  return c.json({ ok: true, message: `Bulk revoke (${target}) completed successfully.` });
});

app.get(`/${SECRET_ADMIN_PREFIX}/users`, async (c) => {
  const search = c.req.query('search') || '';
  let query = "SELECT discord_id as email, tier, status, created_at FROM licenses"; // Using discord_id as 'email' for compatibility
  let params: any[] = [];
  if (search) {
    query += " WHERE discord_id LIKE ?1";
    params.push(`%${search}%`);
  }
  query += " GROUP BY discord_id ORDER BY created_at DESC LIMIT 50";
  const rows = await c.env.LICENSE_DB.prepare(query).bind(...params).all();
  
  // Map users to dashboard format
  const users = (rows.results || []).map((r: any) => ({
    username: r.email || r.discord_id || 'Member',
    email: r.email || r.discord_id || 'unknown',
    tier: r.tier || 'Baseline',
    status: r.status || 'active',
    created_at: r.created_at || Date.now()
  }));

  return c.json({ users });
});

app.post(`/${SECRET_ADMIN_PREFIX}/revoke`, async (c) => {
  const { key } = await c.req.json<{ key: string }>();
  const keyHash = await sha256Hex(`${c.env.LICENSE_PEPPER}:${key}`);
  await c.env.LICENSE_DB.prepare("UPDATE licenses SET status = 'revoked', updated_at = ?1 WHERE key_hash = ?2").bind(Date.now(), keyHash).run();
  return c.json({ ok: true });
});

app.post(`/${SECRET_ADMIN_PREFIX}/system-config`, async (c) => {
  const body = await c.req.json<any>();
  const queries = [];
  const now = Date.now();
  
  for (const [key, value] of Object.entries(body)) {
    queries.push(
      c.env.LICENSE_DB.prepare(
        "INSERT INTO app_config (config_key, config_value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(config_key) DO UPDATE SET config_value=?2, updated_at=?3"
      ).bind(key, JSON.stringify(value), now)
    );
  }
  
  if (queries.length > 0) {
    await c.env.LICENSE_DB.batch(queries);
  }
  
  return c.json({ ok: true });
});

app.get(`/${SECRET_ADMIN_PREFIX}/system-config`, async (c) => {
  const rows = await c.env.LICENSE_DB.prepare("SELECT config_key, config_value FROM app_config").all<{config_key:string, config_value:string}>();
  // We need to return the structure the frontend expects: { maintenance, news, lootlabs }
  const config: any = {
    maintenance: { enabled: false, message: '' },
    news: { title: '', content: '' },
    lootlabs: { keygen: '', download: '' },
  };

  for (const r of (rows.results || [])) {
    try {
       config[r.config_key] = JSON.parse(r.config_value);
    } catch {
       config[r.config_key] = r.config_value;
    }
  }
  return c.json(config);
});

app.post(`/${SECRET_ADMIN_PREFIX}/generate-key`, async (c) => {
  const { tier, discordId, durationDays, generator } = await c.req.json<{ tier: string, discordId?: string, durationDays?: number, generator?: string }>();
  
  // Extract real admin identity from session if available
  const session = getCookie(c, 'kles_admin_session');
  let adminId = generator;
  if (session) {
    const payload = await verifyAdminSession(c.env, session);
    if (payload && payload.sub) {
      adminId = payload.sub; // This is the Discord ID
    }
  }
  
  const createdAt = nowMs();
  const tInfo = normalizeTier(tier);
  let expiresAt: number | null = null;

  if (durationDays) {
     expiresAt = createdAt + durationDays * 24 * 60 * 60 * 1000;
  } else if (tInfo.tier === "Trial") {
     expiresAt = createdAt + 24 * 60 * 60 * 1000;
  } else if (tInfo.tier === "Monthly") {
     expiresAt = createdAt + 30 * 24 * 60 * 60 * 1000;
  }

  let plainKey = "";
  if (tInfo.tier === "Trial") {
    plainKey = `KLESF-${randomId("").slice(0, 4)}-${randomId("").slice(0, 4)}`.toUpperCase();
  } else {
    plainKey = `KLESP-${randomId("").slice(0, 4)}-${randomId("").slice(0, 4)}-${randomId("").slice(0, 4)}-${randomId("").slice(0, 4)}`.toUpperCase();
  }
  const masks = keyMask(plainKey);
  const keyHash = await sha256Hex(`${c.env.LICENSE_PEPPER}:${plainKey}`);
  const licenseId = randomId("lic");

  await c.env.LICENSE_DB.prepare(
    `INSERT INTO licenses (id, key_hash, key_prefix, key_last4, tier, license_type, status, discord_id, stripe_session_id, stripe_customer_id, device_limit, issued_at, expires_at, created_at, updated_at, created_by, plain_key)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, 'manual', 'admin', 1, ?8, ?9, ?10, ?11, ?12, ?13)`
  ).bind(licenseId, keyHash, masks.prefix, masks.last4, tInfo.tier, tInfo.licenseType, discordId || null, createdAt, expiresAt, createdAt, createdAt, adminId || "Admin", plainKey).run();

  if (discordId) {
    await sendDiscordDM(c.env, discordId, plainKey, tInfo.tier, expiresAt);
  }

  return c.json({ ok: true, key: plainKey });
});

// Legacy search logic for Polling (Success Page)
app.get('/api/internal/check-key-by-session', async (c) => {
  const sessionId = c.req.query('session_id');
  if (!sessionId) return c.json({ ok: false }, 400);

  const row = await c.env.LICENSE_DB.prepare(`SELECT key_prefix, key_last4 FROM licenses WHERE stripe_session_id = ?1 LIMIT 1`).bind(sessionId).first();
  if (row) return c.json({ ok: true, found: true });
  return c.json({ ok: true, found: false });
});

// Original Export Handler Logic
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return app.fetch(request, env, ctx);
  },
};

// Original Durable Object must be exported
export class SecurityCoordinator {
  state: DurableObjectState;
  constructor(state: DurableObjectState) { this.state = state; }
  async fetch(request: Request): Promise<Response> {
    const body: any = await request.json();
    const now = body.now;
    const rateKey = `rate:${body.ip}:${body.key}`;
    const nonceKey = `nonce:${body.nonce}`;

    const nonceSeen = await this.state.storage.get(nonceKey);
    if (nonceSeen) return new Response(JSON.stringify({ ok: false, reason: "replay_nonce" }));
    await this.state.storage.put(nonceKey, now);

    let current: any = await this.state.storage.get(rateKey) || { count: 0, windowStart: now };
    if (now - current.windowStart > body.windowMs) {
      current = { count: 1, windowStart: now };
    } else {
      current.count++;
    }
    await this.state.storage.put(rateKey, current);

    return new Response(JSON.stringify({ ok: current.count <= body.max }));
  }
}

// Missing function from original file needed for legacy support
async function verifyAgainstLegacyStore(env: Env, payload: any): Promise<LegacyVerifyResult | null> {
  if (!env.LEGACY_VERIFY_URL) return null;
  try {
    const res = await fetch(env.LEGACY_VERIFY_URL, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${env.INTERNAL_API_TOKEN}` },
      body: JSON.stringify(payload),
    });
    return res.ok ? (await res.json() as any) : null;
  } catch { return null; }
}

async function makeProof(env: Env, response: VerifyResponse, nonce: string): Promise<string> {
  const payload = [nonce, response.valid ? "1" : "0", response.premiumAllowed ? "1" : "0", response.status, response.reason, String(response.expiresAt), "0", String(response.serverTime), response.deviceHash ?? "", response.tier].join("|");
  return hmacHex(env.RESPONSE_PROOF_SECRET, payload);
}
