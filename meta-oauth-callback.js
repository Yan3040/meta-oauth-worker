// meta-oauth-callback - multi-provider OAuth callback Worker for oauth.mash.org.il
// Independent of Growth OS: the old connection stays available unchanged; nothing
// here removes a registered redirect or revokes a grant on either side.
//
// Providers (isolated signed state per provider - separate keys, routes, cookies):
//   /meta/facebook/*   - IIAI page token (existing flow)
//   /meta/instagram/*  - IG business account 27505601549079393 (app 1770271414146078)
//   /meta/threads/*    - Threads account 27854165164221388 (app 1527327988427406)
//   /google/youtube/*  - YouTube channel UCH9pcf1_jXNQH5rYVqiyfsA (existing verified
//                        Google Web client 216606794484-...; its NEW redirect URI
//                        https://oauth.mash.org.il/google/youtube/callback must be
//                        ADDED to the client - existing redirects stay registered)
//
// Every token is rendered exactly once to the owner's browser; never logged,
// stored, or sent anywhere else. Do not enable Workers tail/body logs.
// Provider error bodies/messages are NEVER echoed to the browser (fixed texts only).
//
// Secrets (Settings -> Variables -> Secrets):
//   META_APP_SECRET, STATE_SIGNING_KEY                  (facebook)
//   IG_APP_SECRET, STATE_SIGNING_KEY_IG                 (instagram)
//   THREADS_APP_SECRET, STATE_SIGNING_KEY_THREADS       (threads)
//   YOUTUBE_CLIENT_SECRET, STATE_SIGNING_KEY_YT         (youtube)

const GRAPH = "https://graph.facebook.com/v21.0";
const THREADS_GRAPH = "https://graph.threads.net/v1.0";
const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const YT_CHANNELS = "https://www.googleapis.com/youtube/v3/channels?part=id,snippet&mine=true";
const STATE_TTL_MS = 10 * 60 * 1000;
const FUTURE_SKEW_MS = 60 * 1000;

const FB_SCOPES = "pages_show_list,pages_read_engagement,pages_manage_posts,pages_read_user_content,pages_manage_engagement";
const IG_SCOPES = "instagram_business_basic,instagram_business_content_publish,instagram_business_manage_comments";
const THREADS_SCOPES = "threads_basic,threads_content_publish,threads_read_replies,threads_manage_replies";
const YT_SCOPES = [
  "https://www.googleapis.com/auth/youtube.upload",
  "https://www.googleapis.com/auth/youtube.readonly",
].join(" ");

const BIND_COOKIE = { facebook: "bind_facebook", instagram: "bind_instagram", threads: "bind_threads", youtube: "bind_youtube" };

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Every HTML response: no-store, no-referrer, no framing (token pages included).
function html(title, body, status = 200) {
  return new Response(
    `<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">` +
    `<meta name="robots" content="noindex"><title>${esc(title)}</title></head>` +
    `<body style="font-family:sans-serif;max-width:640px;margin:2rem auto">${body}</body></html>`,
    { status, headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "content-security-policy": "frame-ancestors 'none'",
    } });
}

// Response.redirect()'s headers are IMMUTABLE (TypeError on .set in Workers/undici):
// build the 302 explicitly so cache/referrer headers and Set-Cookie actually land.
function noStoreRedirect(location) {
  return new Response(null, { status: 302, headers: {
    "location": location,
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
  } });
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function constEq(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function bindCookie(provider, nonce) {
  return `${BIND_COOKIE[provider]}=${nonce}; Max-Age=600; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookies(...providers) {
  return providers.map(p =>
    `${BIND_COOKIE[p]}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

function readBindCookie(cookieHeader, provider) {
  const m = String(cookieHeader || "").match(new RegExp("(?:^|;\\s*)" + BIND_COOKIE[provider] + "=([0-9a-f]{32})"));
  return m ? m[1] : null;
}

// State is provider-bound (HMAC over provider.ts.nonce) AND browser-bound: the
// nonce also lives in a Secure/HttpOnly/SameSite=Lax cookie set at /start, so a
// state is consumable only by the browser that began the flow, exactly once (the
// cookie is cleared on every terminal callback response). A state minted for one
// provider never validates on another's route or cookie. Timestamps that are
// malformed, expired, or in the future are rejected.
export async function mintState(secret, provider) {
  const ts = Date.now().toString(36);
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, "0")).join("");
  const sig = await hmacHex(secret, provider + "." + ts + "." + nonce);
  return { state: ts + "." + nonce + "." + sig, nonce };
}

export async function checkState(secret, provider, state, cookieHeader) {
  const parts = String(state || "").split(".");
  if (parts.length !== 3) return false;
  const [ts, nonce, sig] = parts;
  if (!/^[0-9a-z]{1,16}$/.test(ts) || !/^[0-9a-f]{32}$/.test(nonce) || !/^[0-9a-f]{64}$/.test(sig)) return false;
  const tsMs = parseInt(ts, 36);
  if (!Number.isFinite(tsMs)) return false;
  const now = Date.now();
  if (tsMs > now + FUTURE_SKEW_MS) return false;          // future timestamp
  if (now - tsMs > STATE_TTL_MS) return false;            // expired
  const expect = await hmacHex(secret, provider + "." + ts + "." + nonce);
  if (!constEq(expect, sig)) return false;
  const bound = readBindCookie(cookieHeader, provider);
  return bound !== null && constEq(bound, nonce);
}

// Sanitized provider-failure diagnostics. Carries ONLY: our own stage label, the
// HTTP status, and the provider's NUMERIC error code/subcode. Never values,
// messages, key names, error-type strings, auth codes, tokens, app secrets, or URLs.
class ProviderStageError extends Error {
  constructor(stage, info) {
    super("provider-stage-" + stage);
    this.stage = stage;
    this.info = info;
  }
}

// Numeric codes only. Nothing provider-controlled and string-shaped is reflected:
// no key names, no error types, no messages, no cardinality - those channels were
// shown injectable in review. Only integers pass (res.status is client-side; the
// provider-controlled code/subcode are admitted solely as Number.isInteger).
function httpInfo(status, body) {
  const info = { status };
  const e = body && typeof body === "object" ? (body.error && typeof body.error === "object" ? body.error : body) : null;
  if (e) {
    if (Number.isInteger(e.code)) info.code = e.code;
    else if (Number.isInteger(e.error_code)) info.code = e.error_code;
    if (Number.isInteger(e.error_subcode)) info.subcode = e.error_subcode;
  }
  return info;
}

async function getJSON(url, stage) {
  const res = await fetch(url);
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new ProviderStageError(stage || "get", httpInfo(res.status, body));
  return body;
}

async function postForm(url, fields, stage) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields) });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new ProviderStageError(stage || "post", httpInfo(res.status, body));
  return body;
}

// Meta ids can exceed Number.MAX_SAFE_INTEGER (e.g. 27505601549079393 > 2^53):
// res.json() silently rounds them and strict string compares then fail on real accounts.
// These variants keep the raw text so id fields are extracted losslessly.
async function getJSONRaw(url, stage) {
  const res = await fetch(url);
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch {}
  if (!res.ok) throw new ProviderStageError(stage || "get", httpInfo(res.status, body));
  return { data: body, text };
}

async function postFormRaw(url, fields, stage) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields) });
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch {}
  if (!res.ok) throw new ProviderStageError(stage || "post", httpInfo(res.status, body));
  return { data: body, text };
}

// Extracts "<key>" as an exact string from raw JSON text (string or numeric literal),
// before any float rounding can occur. Returns null when absent.
function losslessField(text, key) {
  if (typeof text !== "string") return null;
  const str = text.match(new RegExp('"' + key + '"\\s*:\\s*"([^"]*)"'));
  if (str) return str[1];
  const num = text.match(new RegExp('"' + key + '"\\s*:\\s*(\\d+)'));
  return num ? num[1] : null;
}

// Safe mismatch diagnostics: stage, value TYPE and safe-integer status only. Never the value.
function idDiagnostics(stage, parsedValue, losslessValue) {
  return esc(JSON.stringify({
    stage, parsed_type: typeof parsedValue,
    parsed_is_safe_integer: typeof parsedValue === "number" ? Number.isSafeInteger(parsedValue) : null,
    lossless_used: losslessValue != null }, null, 2));
}

// Rendered on the error page instead of the generic carrier when a stage error
// reaches terminal(): stage + HTTP status + error code + field structure only.
function providerDiagnostic(err) {
  const d = {
    stage: err.stage,
    http_status: err.info.status ?? null,
    error_code: err.info.code ?? null,
    error_subcode: err.info.subcode ?? null,
  };
  return html("שגיאת ספק - אבחון",
    "<p>הספק החזיר שגיאה. אבחון מסונן (שלב + סטטוס HTTP + קוד שגיאה נומרי בלבד; בלי קוד הרשאה, טוקן, סוד אפליקציה, שמות שדות או כתובת) - צלמו ושלחו ל-Instinct:</p><pre>" +
    esc(JSON.stringify(d, null, 2)) + "</pre>", 502);
}

function oneTimeTokenPage(title, verifyLine, vaultNote, tokenLabel, tokenValue) {
  return html(title, `
    <p>${esc(verifyLine)}</p>
    <p><b>${esc(vaultNote)}</b></p>
    <p>${esc(tokenLabel)}:</p>
    <textarea style="width:100%;height:6rem" readonly onclick="this.select()">${esc(tokenValue)}</textarea>
    <p>אחרי השמירה - עדכנו את Instinct להשלמת השרשרת.</p>`);
}

function badState(providerPath) {
  return html("state לא תקין", `<p>ה-state חסר, פג, שובש, שייך לדפדפן אחר או כבר נוצל. התחילו מחדש מ-${esc(providerPath)}/start.</p>`, 400);
}

function cancelled() {
  return html("ההסכמה בוטלה או נכשלה", "<p>הספק דיווח על ביטול או כשל בהסכמה. ניתן להתחיל מחדש מקישור ה-/start של הספק.</p>", 400);
}

function providerError() {
  return html("שגיאת ספק", "<p>אירעה שגיאה זמנית מול הספק. נסו שוב מקישור ה-/start של הספק.</p>", 502);
}

function providerNotConfigured() {
  return html("הספק אינו מוגדר", "<p>הגדרות הספק חסרות ב-worker. פנו למנהל.</p>", 500);
}

// Runs a callback and clears the provider's binding cookie (plus any extra flow
// cookies such as yt_pkce) on every terminal response.
async function terminal(provider, extraCookieClears, fn) {
  let res;
  try {
    res = await fn();
  } catch (e) {
    res = e instanceof ProviderStageError ? providerDiagnostic(e) : providerError();
  }
  for (const c of [...clearCookies(provider), ...extraCookieClears]) res.headers.append("set-cookie", c);
  return res;
}

const CLEAR_YT_PKCE = "yt_pkce=; Max-Age=0; Path=/google/youtube; HttpOnly; Secure; SameSite=Lax";

// --- Meta (facebook + instagram share the Graph dialog/exchange shape) ---

async function metaStart(env, provider, appId, redirectUri, scopes, stateKey) {
  const { state, nonce } = await mintState(env[stateKey], provider);
  const res = noStoreRedirect("https://www.facebook.com/dialog/oauth?" + new URLSearchParams({
    client_id: appId, redirect_uri: redirectUri, scope: scopes, response_type: "code", state }));
  res.headers.append("set-cookie", bindCookie(provider, nonce));
  return res;
}

async function metaLongLivedUserToken(appId, appSecret, redirectUri, code) {
  const t1 = await getJSON(`${GRAPH}/oauth/access_token?` + new URLSearchParams({
    client_id: appId, redirect_uri: redirectUri, client_secret: appSecret, code }), "fb-code-exchange");
  const t2 = await getJSON(`${GRAPH}/oauth/access_token?` + new URLSearchParams({
    grant_type: "fb_exchange_token", client_id: appId,
    client_secret: appSecret, fb_exchange_token: t1.access_token }), "fb-exchange-long");
  return t2.access_token;
}

async function debugToken(appId, appSecret, inputToken) {
  const dbg = await getJSON(`${GRAPH}/debug_token?` + new URLSearchParams({
    input_token: inputToken, access_token: `${appId}|${appSecret}` }), "fb-debug-token");
  return dbg.data || {};
}

async function facebookCallback(env, url, cookieHeader) {
  if (url.searchParams.get("error")) return cancelled();
  const code = url.searchParams.get("code");
  if (!code || !(await checkState(env.STATE_SIGNING_KEY, "facebook", url.searchParams.get("state"), cookieHeader)))
    return badState("/meta/facebook");
  const userToken = await metaLongLivedUserToken(env.META_APP_ID, env.META_APP_SECRET, env.REDIRECT_URI, code);
  const accounts = await getJSON(`${GRAPH}/me/accounts?` + new URLSearchParams({
    fields: "id,name,access_token", limit: "100", access_token: userToken }), "fb-me-accounts");
  const page = (accounts.data || []).find(p => p.id === env.TARGET_PAGE_ID);
  if (!page) return html("העמוד לא נבחר",
    "<p>עמוד IIAI (826210657231623) לא נמצא בין העמודים שהוענקו. הריצו שוב את הקישור וסמנו את העמוד.</p>", 400);
  const d = await debugToken(env.META_APP_ID, env.META_APP_SECRET, page.access_token);
  const missing = FB_SCOPES.split(",").filter(s => !(d.scopes || []).includes(s));
  const ok = d.is_valid === true && String(d.app_id) === String(env.META_APP_ID)
    && String(d.profile_id) === String(env.TARGET_PAGE_ID) && d.type === "PAGE" && missing.length === 0;
  if (!ok) return html("אימות הטוקן נכשל", "<pre>" + esc(JSON.stringify({
    is_valid: d.is_valid, app_id: d.app_id, profile_id: d.profile_id, type: d.type,
    expires_at: d.expires_at, data_access_expires_at: d.data_access_expires_at,
    scopes: d.scopes, missing_scopes: missing }, null, 2)) + "</p>", 502);
  return oneTimeTokenPage("IIAI - טוקן עמוד חדש מוכן",
    `הטוקן אומת (app ${d.app_id}, page ${d.profile_id}, valid, 5 scopes, expires_at=${d.expires_at ?? "never"}, data_access_expires_at=${d.data_access_expires_at}).`,
    'העתיקו עכשיו ל-vault, לרשומה הקיימת "Meta Page Token - iiai" (שדה password). הדף מוצג פעם אחת ולא נשמר.',
    "Page token", page.access_token);
}

// Instagram API with Instagram Login (Business Login), per the official docs:
//   authorize:  https://www.instagram.com/oauth/authorize
//   code->short: POST https://api.instagram.com/oauth/access_token
//                (response carries access_token, user_id and the GRANTED permissions)
//   short->long: GET https://graph.instagram.com/access_token?grant_type=ig_exchange_token
//   identity:    GET https://graph.instagram.com/me?fields=user_id,username
async function instagramCallback(env, url, cookieHeader) {
  if (url.searchParams.get("error")) return cancelled();
  const code = url.searchParams.get("code");
  if (!code || !(await checkState(env.STATE_SIGNING_KEY_IG, "instagram", url.searchParams.get("state"), cookieHeader)))
    return badState("/meta/instagram");
  // Documented response: top-level {"access_token", "user_id",
  // "permissions": "comma,separated,string"}. A legacy envelope {"data": [entry]}
  // is accepted only when that is the actual shape. Live diagnosis 28.9:
  // the real response is top-level; the envelope-only assumption was wrong.
  const ex = await postFormRaw("https://api.instagram.com/oauth/access_token", {
    client_id: env.IG_APP_ID, client_secret: env.IG_APP_SECRET,
    grant_type: "authorization_code", redirect_uri: env.IG_REDIRECT_URI, code }, "ig-code-exchange");
  const raw = ex.data;
  const entry = raw && typeof raw.access_token === "string" ? raw
    : raw && Array.isArray(raw.data) && raw.data.length === 1 ? raw.data[0] : null;
  if (!entry || typeof entry.access_token !== "string" || !entry.access_token || entry.user_id == null)
    throw new ProviderStageError("ig-code-exchange-shape", {});
  // Lossless id: raw text wins over the float-rounded JSON value.
  const exchUserId = losslessField(ex.text, "user_id") ?? String(entry.user_id);
  const granted = new Set(String(entry.permissions || "").split(",").map(x => x.trim()).filter(Boolean));
  const missing = IG_SCOPES.split(",").filter(s => !granted.has(s));
  if (missing.length) return html("scopes חסרים", "<pre>" + esc(JSON.stringify({
    granted_scopes: [...granted], missing_scopes: missing }, null, 2)) + "</p>", 502);
  if (exchUserId !== String(env.IG_TARGET_ID))
    return html("חשבון Instagram לא תואם", "<p>החשבון שאומת אינו החשבון הממופה. הריצו שוב עם החשבון הנכון.</p><pre>" + idDiagnostics("ig-code-exchange", entry.user_id, losslessField(ex.text, "user_id")) + "</pre>", 502);
  const long = await getJSON("https://graph.instagram.com/access_token?" + new URLSearchParams({
    grant_type: "ig_exchange_token", client_secret: env.IG_APP_SECRET, access_token: entry.access_token }), "ig-exchange-long");
  const meRes = await getJSONRaw("https://graph.instagram.com/me?" + new URLSearchParams({
    fields: "user_id,username", access_token: long.access_token }), "ig-me-readback");
  const me = meRes.data || {};
  const meUserId = losslessField(meRes.text, "user_id") ?? String(me.user_id);
  if (meUserId !== String(env.IG_TARGET_ID))
    return html("חשבון Instagram לא תואם", "<p>החשבון שאומת אינו החשבון הממופה. הריצו שוב עם החשבון הנכון.</p><pre>" + idDiagnostics("ig-me-readback", me.user_id, losslessField(meRes.text, "user_id")) + "</pre>", 502);
  return oneTimeTokenPage("Instagram - טוקן חדש מוכן",
    `הטוקן אומת (IG @${me.username} user_id ${me.user_id}; readback permissions: ${[...granted].join(", ")}; expires_in=${long.expires_in ?? "?"}s).`,
    'העתיקו עכשיו ל-vault. הדף מוצג פעם אחת ולא נשמר.',
    "Long-lived Instagram token", long.access_token);
}

// --- Threads (graph.threads.net) ---

async function threadsCallback(env, url, cookieHeader) {
  if (url.searchParams.get("error")) return cancelled();
  const code = url.searchParams.get("code");
  if (!code || !(await checkState(env.STATE_SIGNING_KEY_THREADS, "threads", url.searchParams.get("state"), cookieHeader)))
    return badState("/meta/threads");
  const t1 = await postForm(`${THREADS_GRAPH}/oauth/access_token`, {
    client_id: env.THREADS_APP_ID, redirect_uri: env.THREADS_REDIRECT_URI,
    client_secret: env.THREADS_APP_SECRET, code, grant_type: "authorization_code" }, "th-code-exchange");
  const t2 = await getJSON(`${THREADS_GRAPH.replace("/v1.0", "")}/access_token?` + new URLSearchParams({
    grant_type: "th_exchange_token", client_secret: env.THREADS_APP_SECRET, access_token: t1.access_token }), "th-exchange-long");
  // Scope readback on the granted token itself (not the consent request).
  // Official Threads debug endpoint: graph.threads.com/v1.0/debug_token, called with
  // the app access token in the documented Threads format TH|<APP_ID>|<APP_SECRET>
  // (or a tester token). App binding is
  // enforced BY THE ENDPOINT: it only inspects tokens belonging to the calling app
  // ("The App_id in the input_token did not match the Viewing App" otherwise), and
  // its response carries application/user_id/is_valid/scopes - no app_id field.
  const dbgRes = await getJSONRaw("https://graph.threads.com/v1.0/debug_token?" + new URLSearchParams({
    input_token: t2.access_token, access_token: `TH|${env.THREADS_APP_ID}|${env.THREADS_APP_SECRET}` }), "th-debug-token");
  const d = (dbgRes.data || {}).data || {};
  // Same MAX_SAFE_INTEGER defect class as IG: the target id exceeds 2^53, read it losslessly.
  const dbgUserId = losslessField(dbgRes.text, "user_id") ?? String(d.user_id || "");
  const missing = THREADS_SCOPES.split(",").filter(s => !(d.scopes || []).includes(s));
  if (d.is_valid !== true || dbgUserId !== String(env.THREADS_TARGET_ID) || missing.length)
    return html("אימות הטוקן נכשל", "<pre>" + esc(JSON.stringify({
      is_valid: d.is_valid, user_id_matches: String(d.user_id || "") === String(env.THREADS_TARGET_ID),
      granted_scopes: d.scopes, missing_scopes: missing }, null, 2)) + "</p>", 502);
  const me = await getJSON(`${THREADS_GRAPH}/me?` + new URLSearchParams({
    fields: "id,username", access_token: t2.access_token }), "th-me-readback");
  if (String(me.id) !== String(env.THREADS_TARGET_ID))
    return html("חשבון Threads לא תואם", "<p>החשבון שאומת אינו החשבון הממופה. הריצו שוב עם החשבון הנכון.</p>", 502);
  return oneTimeTokenPage("Threads - טוקן חדש מוכן",
    `הטוקן אומת (@${me.username} id ${me.id}; readback scopes: ${(d.scopes || []).join(", ")}; expires_in=${t2.expires_in ?? "?"}s).`,
    'העתיקו עכשיו ל-vault. הדף מוצג פעם אחת ולא נשמר.',
    "Long-lived token", t2.access_token);
}

// --- YouTube (Google OAuth, PKCE S256, existing verified Web client) ---

async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function youtubeStart(env) {
  const { state, nonce } = await mintState(env.STATE_SIGNING_KEY_YT, "youtube");
  const verifier = [...crypto.getRandomValues(new Uint8Array(48))].map(b => b.toString(16).padStart(2, "0")).join("");
  const challenge = await pkceChallenge(verifier);
  const res = noStoreRedirect(GOOGLE_AUTH + "?" + new URLSearchParams({
    client_id: env.YOUTUBE_CLIENT_ID, redirect_uri: env.YOUTUBE_REDIRECT_URI,
    response_type: "code", scope: YT_SCOPES, access_type: "offline", prompt: "consent",
    state, code_challenge: challenge, code_challenge_method: "S256" }));
  res.headers.append("set-cookie", bindCookie("youtube", nonce));
  res.headers.append("set-cookie",
    `yt_pkce=${verifier}; Max-Age=600; Path=/google/youtube; HttpOnly; Secure; SameSite=Lax`);
  return res;
}

async function youtubeCallback(env, url, request, cookieHeader) {
  if (url.searchParams.get("error")) return cancelled();
  const code = url.searchParams.get("code");
  if (!code || !(await checkState(env.STATE_SIGNING_KEY_YT, "youtube", url.searchParams.get("state"), cookieHeader)))
    return badState("/google/youtube");
  const verifier = (String(cookieHeader).match(/(?:^|;\s*)yt_pkce=([0-9a-f]+)/) || [])[1];
  if (!verifier) return html("PKCE חסר", "<p>עוגיית ה-PKCE חסרה או פגה. התחילו מחדש מ-/google/youtube/start.</p>", 400);
  const tok = await postForm(GOOGLE_TOKEN, {
    client_id: env.YOUTUBE_CLIENT_ID, client_secret: env.YOUTUBE_CLIENT_SECRET, code,
    code_verifier: verifier, grant_type: "authorization_code", redirect_uri: env.YOUTUBE_REDIRECT_URI }, "yt-code-exchange");
  if (!tok.refresh_token || !tok.access_token)
    return html("Google לא החזיר refresh token", "<p>יש להריץ שוב את /google/youtube/start (prompt=consent).</p>", 502);
  const granted = new Set(String(tok.scope || "").split(" "));
  const missing = YT_SCOPES.split(" ").filter(s => !granted.has(s));
  if (missing.length) return html("scopes חסרים", "<p>חסרים scopes שהוסכם עליהם. הריצו שוב ואשרו את כולם.</p>", 502);
  const channels = await getJSON(YT_CHANNELS + "&access_token=" + encodeURIComponent(tok.access_token)).catch(() => null);
  const ids = channels && Array.isArray(channels.items) ? channels.items.map(x => x.id) : [];
  if (ids.length !== 1 || ids[0] !== env.YOUTUBE_CHANNEL_ID)
    return html("ערוץ לא תואם", "<p>הערוץ שאומת אינו הערוץ הממופה.</p>", 502);
  return oneTimeTokenPage("YouTube - refresh token מוכן",
    `הטוקן אומת (channel ${ids[0]}, readback scopes: upload+readonly).`,
    'העתיקו עכשיו ל-vault. הדף מוצג פעם אחת ולא נשמר.',
    "Refresh token", tok.refresh_token);
}

// Required env per route; missing config -> fixed 500 page, never a thrown edge error.
const ROUTE_ENV = {
  "/meta/facebook/start": ["META_APP_ID", "REDIRECT_URI", "STATE_SIGNING_KEY"],
  "/meta/facebook/callback": ["META_APP_ID", "META_APP_SECRET", "REDIRECT_URI", "TARGET_PAGE_ID", "STATE_SIGNING_KEY"],
  "/meta/instagram/start": ["IG_APP_ID", "IG_REDIRECT_URI", "STATE_SIGNING_KEY_IG"],
  "/meta/instagram/callback": ["IG_APP_ID", "IG_APP_SECRET", "IG_REDIRECT_URI", "IG_TARGET_ID", "STATE_SIGNING_KEY_IG"],
  "/meta/threads/start": ["THREADS_APP_ID", "THREADS_REDIRECT_URI", "STATE_SIGNING_KEY_THREADS"],
  "/meta/threads/callback": ["THREADS_APP_ID", "THREADS_APP_SECRET", "THREADS_REDIRECT_URI", "THREADS_TARGET_ID", "STATE_SIGNING_KEY_THREADS"],
  "/google/youtube/start": ["YOUTUBE_CLIENT_ID", "YOUTUBE_REDIRECT_URI", "STATE_SIGNING_KEY_YT"],
  "/google/youtube/callback": ["YOUTUBE_CLIENT_ID", "YOUTUBE_CLIENT_SECRET", "YOUTUBE_REDIRECT_URI", "YOUTUBE_CHANNEL_ID", "STATE_SIGNING_KEY_YT"],
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cookieHeader = request.headers.get("cookie") || "";
    const required = ROUTE_ENV[path];
    if (!required) return new Response("not found", { status: 404, headers: { "cache-control": "no-store" } });
    if (required.some(k => !env || typeof env[k] !== "string" || !env[k])) return providerNotConfigured();
    try {
      if (path === "/meta/facebook/start")
        return metaStart(env, "facebook", env.META_APP_ID, env.REDIRECT_URI, FB_SCOPES, "STATE_SIGNING_KEY");
      if (path === "/meta/facebook/callback")
        return await terminal("facebook", [], () => facebookCallback(env, url, cookieHeader));

      if (path === "/meta/instagram/start") {
        const { state, nonce } = await mintState(env.STATE_SIGNING_KEY_IG, "instagram");
        const res = noStoreRedirect("https://www.instagram.com/oauth/authorize?" + new URLSearchParams({
          client_id: env.IG_APP_ID, redirect_uri: env.IG_REDIRECT_URI,
          response_type: "code", scope: IG_SCOPES, state }));
        res.headers.append("set-cookie", bindCookie("instagram", nonce));
        return res;
      }
      if (path === "/meta/instagram/callback")
        return await terminal("instagram", [], () => instagramCallback(env, url, cookieHeader));

      if (path === "/meta/threads/start") {
        const { state, nonce } = await mintState(env.STATE_SIGNING_KEY_THREADS, "threads");
        const res = noStoreRedirect("https://www.threads.net/oauth/authorize?" + new URLSearchParams({
          client_id: env.THREADS_APP_ID, redirect_uri: env.THREADS_REDIRECT_URI,
          scope: THREADS_SCOPES, response_type: "code", state }));
        res.headers.append("set-cookie", bindCookie("threads", nonce));
        return res;
      }
      if (path === "/meta/threads/callback")
        return await terminal("threads", [], () => threadsCallback(env, url, cookieHeader));

      if (path === "/google/youtube/start") return await youtubeStart(env);
      if (path === "/google/youtube/callback")
        return await terminal("youtube", [CLEAR_YT_PKCE], () => youtubeCallback(env, url, request, cookieHeader));

      return new Response("not found", { status: 404, headers: { "cache-control": "no-store" } });
    } catch (e) {
      return providerError();
    }
  },
};

export { mintState as _mintState, checkState as _checkState, httpInfo as _httpInfo, ProviderStageError as _ProviderStageError, providerDiagnostic as _providerDiagnostic };
