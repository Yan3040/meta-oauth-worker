import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { _mintState as mintState } from '../meta-oauth-callback.js';

const KEY = 'test-signing-key';
const SCOPES = 'instagram_business_basic,instagram_business_content_publish,instagram_business_manage_comments';
const env = { IG_APP_ID: '1', IG_APP_SECRET: 's', IG_REDIRECT_URI: 'https://x/cb',
              IG_TARGET_ID: '42', STATE_SIGNING_KEY_IG: KEY };

const jsonRes = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { 'content-type': 'application/json' } });

function stubFetch(exchangeBody) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const u = String(url); calls.push(u);
    if (u.startsWith('https://api.instagram.com/oauth/access_token')) return jsonRes(exchangeBody);
    if (u.startsWith('https://graph.instagram.com/access_token')) return jsonRes({ access_token: 'long', expires_in: 5184000 });
    if (u.startsWith('https://graph.instagram.com/v26.0/me')) return jsonRes({ user_id: '42', username: 'dr.shenhav' });
    throw new Error('unexpected fetch ' + u);
  };
  return calls;
}

async function run() {
  const { state, nonce } = await mintState(KEY, 'instagram');
  return worker.fetch(new Request(
    'https://oauth.mash.org.il/meta/instagram/callback?code=c&state=' + state,
    { headers: { cookie: `bind_instagram=${nonce}` } }), env);
}

test('documented top-level {access_token,user_id,permissions} accepted', async () => {
  stubFetch({ access_token: 'short', user_id: '42', permissions: SCOPES });
  const res = await run();
  assert.equal(res.status, 200);
  assert.match(await res.text(), /טוקן חדש מוכן/);
});

test('legacy data envelope accepted only when it is the actual shape', async () => {
  stubFetch({ data: [{ access_token: 'short', user_id: '42', permissions: SCOPES }] });
  const res = await run();
  assert.equal(res.status, 200);
});

test('empty data envelope rejected as ig-code-exchange-shape', async () => {
  stubFetch({ data: [] });
  const res = await run();
  assert.equal(res.status, 502);
  assert.match(await res.text(), /ig-code-exchange-shape/);
});

test('user mismatch rejected after both exchange shapes agree', async () => {
  stubFetch({ access_token: 'short', user_id: '99', permissions: SCOPES });
  const res = await run();
  assert.equal(res.status, 502);
  assert.match(await res.text(), /חשבון Instagram לא תואם/);
});

test('missing granted scopes rejected with no token page', async () => {
  stubFetch({ access_token: 'short', user_id: '42',
              permissions: 'instagram_business_basic,instagram_business_content_publish' });
  const res = await run();
  assert.equal(res.status, 502);
  assert.match(await res.text(), /scopes חסרים/);
});
