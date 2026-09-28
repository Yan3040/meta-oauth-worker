import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { _mintState as mintState } from '../meta-oauth-callback.js';

const KEY = 'test-signing-key';
const TID = '27854165164221388'; // Threads target, > Number.MAX_SAFE_INTEGER
assert.ok(BigInt(TID) > BigInt(Number.MAX_SAFE_INTEGER));
const SCOPES_ARR = '["threads_basic","threads_content_publish","threads_read_replies","threads_manage_replies"]';
const env = { THREADS_APP_ID: '1', THREADS_APP_SECRET: 's', THREADS_REDIRECT_URI: 'https://x/cb',
              THREADS_TARGET_ID: TID, STATE_SIGNING_KEY_THREADS: KEY };

const rawRes = (text, status = 200) => new Response(text, {
  status, headers: { 'content-type': 'application/json' } });

function stubFetch(debugText, meText = `{"id":${TID},"username":"dr.shenhav"}`) {
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith('https://graph.threads.net/v1.0/oauth/access_token')) return rawRes('{"access_token":"short"}');
    if (u.startsWith('https://graph.threads.net/access_token')) return rawRes('{"access_token":"long","expires_in":5184000}');
    if (u.startsWith('https://graph.threads.com/v1.0/debug_token')) return rawRes(debugText);
    if (u.startsWith('https://graph.threads.net/v1.0/me')) return rawRes(meText);
    throw new Error('unexpected fetch ' + u);
  };
}

async function run() {
  const { state, nonce } = await mintState(KEY, 'threads');
  return worker.fetch(new Request(
    'https://oauth.mash.org.il/meta/threads/callback?code=c&state=' + state,
    { headers: { cookie: `bind_threads=${nonce}` } }), env);
}

test('debug_token + /me with id > 2^53 as numeric literals: accepted (lossless)', async () => {
  stubFetch(`{"data":{"user_id":${TID},"is_valid":true,"scopes":${SCOPES_ARR}}}`);
  const res = await run();
  assert.equal(res.status, 200);
  assert.match(await res.text(), /טוקן חדש מוכן/);
});

test('HOSTILE: decoy user_id outside data does not bypass the debug_token check', async () => {
  stubFetch(`{"app_data":{"user_id":${TID}},"data":{"user_id":27854165164220001,"is_valid":true,"scopes":${SCOPES_ARR}}}`);
  const res = await run();
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.match(text, /user_id_matches&quot;: false/);
  assert.ok(!text.includes('27854165164220001'), 'mismatched id value must not leak');
});

test('HOSTILE: duplicate user_id in debug_token data fails closed', async () => {
  stubFetch(`{"data":{"user_id":${TID},"user_id":27854165164220001,"is_valid":true,"scopes":${SCOPES_ARR}}}`);
  const res = await run();
  assert.equal(res.status, 502);
});

test('HOSTILE: decoy id nested in threads /me readback does not bypass it', async () => {
  stubFetch(`{"data":{"user_id":${TID},"is_valid":true,"scopes":${SCOPES_ARR}}}`,
            `{"meta":{"id":${TID}},"id":27854165164220002,"username":"other"}`);
  const res = await run();
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.match(text, /threads-me-readback/);
  assert.ok(!text.includes('27854165164220002'));
});
