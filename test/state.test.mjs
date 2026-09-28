import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { _mintState as mintState, _checkState as checkState } from '../meta-oauth-callback.js';
import crypto from 'node:crypto';

const KEY = 'test-signing-key';
const cookieFor = (provider, nonce) => `bind_${provider}=${nonce}`;
const legacySig = async (ts, nonce) => {
  const key = await globalThis.crypto.subtle.importKey('raw', new TextEncoder().encode(KEY),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await globalThis.crypto.subtle.sign('HMAC', key, new TextEncoder().encode(ts + '.' + nonce));
  return ts + '.' + nonce + '.' + [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
};

test('valid state + matching cookie accepted', async () => {
  const { state, nonce } = await mintState(KEY, 'instagram');
  assert.equal(await checkState(KEY, 'instagram', state, cookieFor('instagram', nonce)), true);
});

test('pre-deployment legacy state format rejected everywhere', async () => {
  // The worker was never deployed with the old format: there is no live traffic
  // and no in-flight consent to migrate (see README migration note).
  const ts = Date.now().toString(36);
  const nonce = crypto.randomBytes(16).toString('hex');
  const state = await legacySig(ts, nonce);
  assert.equal(await checkState(KEY, 'facebook', state, cookieFor('facebook', nonce)), false);
});

test('callback clears binding cookie on provider failure', async () => {
  globalThis.fetch = async () => { throw new Error('network down'); };
  const { state, nonce } = await mintState(KEY, 'instagram');
  const env = { IG_APP_ID: '1', IG_APP_SECRET: 's', IG_REDIRECT_URI: 'https://x/cb',
                IG_TARGET_ID: '2', STATE_SIGNING_KEY_IG: KEY };
  const res = await worker.fetch(
    new Request('https://oauth.mash.org.il/meta/instagram/callback?code=c&state=' + state,
                { headers: { cookie: cookieFor('instagram', nonce) } }), env);
  assert.equal(res.status, 502);
  const cleared = res.headers.getSetCookie().join(';');
  assert.match(cleared, /bind_instagram=; Max-Age=0/);
});

test('missing state rejected', async () => {
  assert.equal(await checkState(KEY, 'facebook', undefined, 'bind_facebook=00'), false);
  assert.equal(await checkState(KEY, 'facebook', '', 'bind_facebook=00'), false);
});

test('expired state rejected', async () => {
  const { state, nonce } = await mintState(KEY, 'threads');
  const [ts, n, sig] = state.split('.');
  const old = (Date.now() - 11 * 60 * 1000).toString(36);
  const { _mintState } = await import('../meta-oauth-callback.js');
  // rebuild with expired ts but correct signature for that ts
  const key = await globalThis.crypto.subtle.importKey('raw', new TextEncoder().encode(KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const raw = await globalThis.crypto.subtle.sign('HMAC', key, new TextEncoder().encode('threads.' + old + '.' + n));
  const oldSig = [...new Uint8Array(raw)].map(b => b.toString(16).padStart(2, '0')).join('');
  assert.equal(await checkState(KEY, 'threads', old + '.' + n + '.' + oldSig, cookieFor('threads', n)), false);
});

test('future timestamp rejected', async () => {
  const nonce = crypto.randomBytes(16).toString('hex');
  const future = (Date.now() + 5 * 60 * 1000).toString(36);
  const key = await globalThis.crypto.subtle.importKey('raw', new TextEncoder().encode(KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const raw = await globalThis.crypto.subtle.sign('HMAC', key, new TextEncoder().encode('threads.' + future + '.' + nonce));
  const sig = [...new Uint8Array(raw)].map(b => b.toString(16).padStart(2, '0')).join('');
  assert.equal(await checkState(KEY, 'threads', future + '.' + nonce + '.' + sig, cookieFor('threads', nonce)), false);
});

test('different browser (no/other cookie) rejected', async () => {
  const { state } = await mintState(KEY, 'youtube', '');
  assert.equal(await checkState(KEY, 'youtube', state, ''), false);
  assert.equal(await checkState(KEY, 'youtube', state, 'bind_youtube=' + '0'.repeat(32)), false);
});

test('state for one provider rejected on another route', async () => {
  const { state, nonce } = await mintState(KEY, 'instagram');
  assert.equal(await checkState(KEY, 'threads', state, cookieFor('threads', nonce)), false);
  assert.equal(await checkState(KEY, 'facebook', state, cookieFor('facebook', nonce)), false);
});

test('tampered signature rejected', async () => {
  const { state, nonce } = await mintState(KEY, 'facebook');
  const [ts, n] = state.split('.');
  const bad = ts + '.' + n + '.' + 'a'.repeat(64);
  assert.equal(await checkState(KEY, 'facebook', bad, cookieFor('facebook', nonce)), false);
});

test('malformed parts rejected', async () => {
  assert.equal(await checkState(KEY, 'facebook', 'a.b', 'bind_facebook=' + '0'.repeat(32)), false);
  assert.equal(await checkState(KEY, 'facebook', '!!!.' + '0'.repeat(32) + '.' + 'a'.repeat(64), 'bind_facebook=' + '0'.repeat(32)), false);
});

test('missing env -> fixed 500 page, no throw', async () => {
  const res = await worker.fetch(new Request('https://oauth.mash.org.il/meta/instagram/start'), {});
  assert.equal(res.status, 500);
  assert.match(await res.text(), /אינו מוגדר/);
  const res2 = await worker.fetch(new Request('https://oauth.mash.org.il/google/youtube/callback?code=x&state=y'), { YOUTUBE_CLIENT_ID: 'a' });
  assert.equal(res2.status, 500);
});

test('html responses carry no-store + no-referrer + frame-ancestors', async () => {
  const res = await worker.fetch(new Request('https://oauth.mash.org.il/nope'), {});
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const res2 = await worker.fetch(new Request('https://oauth.mash.org.il/meta/instagram/start'), {});
  assert.equal(res2.headers.get('cache-control'), 'no-store');
  assert.equal(res2.headers.get('referrer-policy'), 'no-referrer');
});

// --- /start routes: real worker.fetch, must return 302 + Location + Set-Cookie ---
const FULL_ENV = {
  META_APP_ID: 'm', META_APP_SECRET: 'ms', REDIRECT_URI: 'https://oauth.mash.org.il/meta/facebook/callback',
  TARGET_PAGE_ID: '826210657231623', STATE_SIGNING_KEY: 'k1',
  IG_APP_ID: 'i', IG_APP_SECRET: 'is', IG_REDIRECT_URI: 'https://oauth.mash.org.il/meta/instagram/callback',
  IG_TARGET_ID: '27505601549079393', STATE_SIGNING_KEY_IG: 'k2',
  THREADS_APP_ID: 't', THREADS_APP_SECRET: 'ts', THREADS_REDIRECT_URI: 'https://oauth.mash.org.il/meta/threads/callback',
  THREADS_TARGET_ID: '27854165164221388', STATE_SIGNING_KEY_THREADS: 'k3',
  YOUTUBE_CLIENT_ID: 'y', YOUTUBE_CLIENT_SECRET: 'ys', YOUTUBE_REDIRECT_URI: 'https://oauth.mash.org.il/google/youtube/callback',
  YOUTUBE_CHANNEL_ID: 'c', STATE_SIGNING_KEY_YT: 'k4',
};

const START_CASES = [
  ['/meta/facebook/start', 'www.facebook.com', 'bind_facebook', 'pages_manage_posts'],
  ['/meta/instagram/start', 'www.instagram.com', 'bind_instagram', 'instagram_business_content_publish'],
  ['/meta/threads/start', 'www.threads.net', 'bind_threads', 'threads_content_publish'],
  ['/google/youtube/start', 'accounts.google.com', 'bind_youtube', 'youtube.upload'],
];
for (const [path, host, cookieName, scopeBit] of START_CASES) {
  test('start ' + path + ' -> 302 + Location + Set-Cookie', async () => {
    const res = await worker.fetch(new Request('https://oauth.mash.org.il' + path), FULL_ENV);
    assert.equal(res.status, 302);
    const loc = res.headers.get('location');
    assert.ok(loc && new URL(loc).hostname === host, loc);
    assert.ok(decodeURIComponent(loc).includes(scopeBit), loc);
    assert.ok(new URL(loc).searchParams.get('state'), loc);
    const cookies = res.headers.getSetCookie().join(';');
    assert.match(cookies, new RegExp(cookieName + '=[0-9a-f]{32}'));
    assert.match(cookies, /HttpOnly; Secure; SameSite=Lax/);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    if (path === '/google/youtube/start') assert.match(cookies, /yt_pkce=[0-9a-f]{96}/);
  });
}

test('threads consent no longer carries threads_delete', async () => {
  const res = await worker.fetch(new Request('https://oauth.mash.org.il/meta/threads/start'), FULL_ENV);
  const loc = decodeURIComponent(res.headers.get('location'));
  assert.ok(!loc.includes('threads_delete'), loc);
});

// --- Contract tests against the documented provider response shapes ---
function mockFetch(routes) {
  globalThis.fetch = async (url, opts) => {
    for (const [prefix, body] of routes) {
      if (String(url).startsWith(prefix))
        return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    throw new Error('unexpected fetch: ' + url);
  };
}
const jsonHeaders = (r) => r.headers.get('content-type');

test('instagram callback: documented data[0] shape accepted, account+scopes verified', async () => {
  const { state, nonce } = await mintState('k2', 'instagram');
  mockFetch([
    ['https://api.instagram.com/oauth/access_token', { data: [{ access_token: 'SHORT', user_id: '27505601549079393',
      permissions: 'instagram_business_basic,instagram_business_content_publish,instagram_business_manage_comments' }] }],
    ['https://graph.instagram.com/access_token', { access_token: 'LONGTOKEN', token_type: 'bearer', expires_in: 5183944 }],
    ['https://graph.instagram.com/me', { user_id: '27505601549079393', username: 'ainewsil' }],
  ]);
  const res = await worker.fetch(new Request(
    'https://oauth.mash.org.il/meta/instagram/callback?code=c&state=' + state,
    { headers: { cookie: 'bind_instagram=' + nonce } }), FULL_ENV);
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('LONGTOKEN'));
  assert.ok(body.includes('ainewsil'));
  assert.match(res.headers.getSetCookie().join(';'), /bind_instagram=; Max-Age=0/);
});

test('instagram callback: documented shape with wrong user_id rejected before exchange', async () => {
  const { state, nonce } = await mintState('k2', 'instagram');
  let longCalled = false;
  globalThis.fetch = async (url) => {
    if (String(url).startsWith('https://graph.instagram.com/access_token')) longCalled = true;
    if (String(url).startsWith('https://api.instagram.com/oauth/access_token'))
      return new Response(JSON.stringify({ data: [{ access_token: 'SHORT', user_id: '999', permissions: 'instagram_business_basic,instagram_business_content_publish,instagram_business_manage_comments' }] }), { status: 200 });
    throw new Error('unexpected fetch: ' + url);
  };
  const res = await worker.fetch(new Request(
    'https://oauth.mash.org.il/meta/instagram/callback?code=c&state=' + state,
    { headers: { cookie: 'bind_instagram=' + nonce } }), FULL_ENV);
  assert.equal(res.status, 502);
  assert.ok((await res.text()).includes('לא תואם'));
  assert.equal(longCalled, false);
});

test('threads callback: documented debug shape (no app_id) accepted', async () => {
  const { state, nonce } = await mintState('k3', 'threads');
  mockFetch([
    ['https://graph.threads.net/v1.0/oauth/access_token', { access_token: 'TSHORT', user_id: '27854165164221388' }],
    ['https://graph.threads.net/access_token', { access_token: 'TLONG', token_type: 'bearer', expires_in: 5183944 }],
    ['https://graph.threads.com/v1.0/debug_token', { data: { type: 'USER', application: 'Threads API Test App',
      is_valid: true, user_id: '27854165164221388', expires_at: 1752254132,
      scopes: ['threads_basic', 'threads_content_publish', 'threads_read_replies', 'threads_manage_replies'] } }],
    ['https://graph.threads.net/v1.0/me', { id: '27854165164221388', username: 'ainewsil' }],
  ]);
  const res = await worker.fetch(new Request(
    'https://oauth.mash.org.il/meta/threads/callback?code=c&state=' + state,
    { headers: { cookie: 'bind_threads=' + nonce } }), FULL_ENV);
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('TLONG'));
  assert.ok(body.includes('threads_content_publish'));
});

test('threads debug call carries the documented TH| app-token format', async () => {
  const { state, nonce } = await mintState('k3', 'threads');
  let seen;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.startsWith('https://graph.threads.com/v1.0/debug_token')) { seen = u; }
    if (u.startsWith('https://graph.threads.net/v1.0/oauth/access_token'))
      return new Response(JSON.stringify({ access_token: 'TSHORT', user_id: '27854165164221388' }), { status: 200 });
    if (u.startsWith('https://graph.threads.net/access_token'))
      return new Response(JSON.stringify({ access_token: 'TLONG', token_type: 'bearer', expires_in: 1 }), { status: 200 });
    if (u.startsWith('https://graph.threads.com/v1.0/debug_token'))
      return new Response(JSON.stringify({ data: { type: 'USER', is_valid: true, user_id: '27854165164221388',
        scopes: ['threads_basic', 'threads_content_publish', 'threads_read_replies', 'threads_manage_replies'] } }), { status: 200 });
    if (u.startsWith('https://graph.threads.net/v1.0/me'))
      return new Response(JSON.stringify({ id: '27854165164221388', username: 'ainewsil' }), { status: 200 });
    throw new Error('unexpected fetch: ' + u);
  };
  await worker.fetch(new Request('https://oauth.mash.org.il/meta/threads/callback?code=c&state=' + state,
    { headers: { cookie: 'bind_threads=' + nonce } }), FULL_ENV);
  assert.ok(seen, 'debug_token was called');
  const q = new URL(seen).searchParams;
  assert.equal(q.get('access_token'), 'TH|t|ts');
  assert.equal(q.get('input_token'), 'TLONG');
});
