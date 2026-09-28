// meta-oauth-callback — single-purpose Cloudflare Worker for oauth.mash.org.il
// Completes the Meta Facebook Login consent for the IIAI page (826210657231623)
// on the independent domain and hands the resulting long-lived page token ONCE
// to the owner for vault storage (entry "Meta Page Token - iiai").
//
// Secrets (Settings -> Variables -> Secrets): META_APP_SECRET, STATE_SIGNING_KEY
// Vars:    META_APP_ID=4606276736317443
//          TARGET_PAGE_ID=826210657231623
//          REDIRECT_URI=https://oauth.mash.org.il/meta/facebook/callback
//
// Entry point for the owner: https://oauth.mash.org.il/meta/facebook/start
// The token is rendered exactly once to the owner's browser; it is never
// logged, stored, or sent anywhere else. Do not enable Workers tail/body logs.

const GRAPH = "https://graph.facebook.com/v21.0";
const SCOPES = "pages_show_list,pages_read_engagement,pages_manage_posts,pages_read_user_content,pages_manage_engagement";
const STATE_TTL_MS = 10 * 60 * 1000;

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function html(title, body, status = 200) {
  return new Response(
    `<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">` +
    `<meta name="robots" content="noindex"><title>${esc(title)}</title></head>` +
    `<body style="font-family:sans-serif;max-width:640px;margin:2rem auto">${body}</body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function mintState(env) {
  const ts = Date.now().toString(36);
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, "0")).join("");
  const sig = await hmacHex(env.STATE_SIGNING_KEY, ts + "." + nonce);
  return ts + "." + nonce + "." + sig;
}

async function checkState(env, state) {
  const parts = String(state || "").split(".");
  if (parts.length !== 3) return false;
  const [ts, nonce, sig] = parts;
  if (Date.now() - parseInt(ts, 36) > STATE_TTL_MS) return false;
  const expect = await hmacHex(env.STATE_SIGNING_KEY, ts + "." + nonce);
  if (expect.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expect.length; i++) diff |= expect.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}

async function getJSON(url) {
  const res = await fetch(url);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = body && body.error && typeof body.error.message === "string" ? body.error.message.slice(0, 200) : ("HTTP " + res.status);
    throw new Error(msg.replace(/EAA\w+/g, "[REDACTED]"));
  }
  return body;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/meta/facebook/start") {
      const state = await mintState(env);
      const dialog = "https://www.facebook.com/dialog/oauth?" + new URLSearchParams({
        client_id: env.META_APP_ID, redirect_uri: env.REDIRECT_URI,
        scope: SCOPES, response_type: "code", state });
      return Response.redirect(dialog, 302);
    }

    if (url.pathname !== "/meta/facebook/callback") return new Response("not found", { status: 404 });

    const err = url.searchParams.get("error");
    if (err) return html("ההסכמה בוטלה או נכשלה", `<p>${esc(err)}: ${esc(url.searchParams.get("error_description") || "")}</p>`, 400);

    const code = url.searchParams.get("code");
    if (!code || !(await checkState(env, url.searchParams.get("state"))))
      return html("state לא תקין", "<p>ה-state חסר, פג או לא תקין. התחילו מחדש מ-/meta/facebook/start.</p>", 400);

    try {
      // code -> short-lived user token -> long-lived user token
      const t1 = await getJSON(`${GRAPH}/oauth/access_token?` + new URLSearchParams({
        client_id: env.META_APP_ID, redirect_uri: env.REDIRECT_URI, client_secret: env.META_APP_SECRET, code }));
      const t2 = await getJSON(`${GRAPH}/oauth/access_token?` + new URLSearchParams({
        grant_type: "fb_exchange_token", client_id: env.META_APP_ID,
        client_secret: env.META_APP_SECRET, fb_exchange_token: t1.access_token }));

      // page token for the fixed target page (never from a query parameter)
      const accounts = await getJSON(`${GRAPH}/me/accounts?` + new URLSearchParams({
        fields: "id,name,access_token", limit: "100", access_token: t2.access_token }));
      const page = (accounts.data || []).find(p => p.id === env.TARGET_PAGE_ID);
      if (!page) return html("העמוד לא נבחר",
        "<p>עמוד IIAI (826210657231623) לא נמצא בין העמודים שהוענקו. הריצו שוב את הקישור וסמנו את העמוד.</p>", 400);

      // verify: app binding, validity, page identity, scopes
      const dbg = await getJSON(`${GRAPH}/debug_token?` + new URLSearchParams({
        input_token: page.access_token, access_token: `${env.META_APP_ID}|${env.META_APP_SECRET}` }));
      const d = dbg.data || {};
      const missing = SCOPES.split(",").filter(s => !(d.scopes || []).includes(s));
      const ok = d.is_valid === true && String(d.app_id) === String(env.META_APP_ID)
        && String(d.profile_id) === String(env.TARGET_PAGE_ID) && d.type === "PAGE" && missing.length === 0;
      if (!ok) return html("אימות הטוקן נכשל", "<pre>" + esc(JSON.stringify({
        is_valid: d.is_valid, app_id: d.app_id, profile_id: d.profile_id, type: d.type,
        expires_at: d.expires_at, data_access_expires_at: d.data_access_expires_at,
        scopes: d.scopes, missing_scopes: missing }, null, 2)) + "</p>", 502);

      return html("IIAI - טוקן עמוד חדש מוכן", `
        <p>הטוקן אומת (app ${esc(d.app_id)}, page ${esc(d.profile_id)}, valid, 5 scopes, expires_at=${esc(d.expires_at ?? "never")}, data_access_expires_at=${esc(d.data_access_expires_at)}).</p>
        <p><b>העתיקו עכשיו ל-vault, לרשומה הקיימת "Meta Page Token - iiai" (שדה password). הדף הזה מוצג פעם אחת ולא נשמר בשום מקום.</b></p>
        <textarea style="width:100%;height:6rem" readonly onclick="this.select()">${esc(page.access_token)}</textarea>
        <p>אחרי השמירה - עדכנו את Instinct להשלמת השרשרת (secret ← probe ← grant ← דגל).</p>`);
    } catch (e) {
      return html("שגיאת ספק", "<p>" + esc(e.message) + "</p>", 502);
    }
  },
};
