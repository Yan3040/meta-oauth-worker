import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { _mintState as mintState } from '../meta-oauth-callback.js';

const KEY = 'test-signing-key';
const SCOPES = 'instagram_business_basic,instagram_business_content_publish,instagram_business_manage_comments';
const BIG = '27505601549079393'; // > Number.MAX_SAFE_INTEGER (9007199254740992)
assert.ok(BigInt(BIG) > BigInt(Number.MAX_SAFE_INTEGER));
const env = { IG_APP_ID: '1', IG_APP_SECRET: 's', IG_REDIRECT_URI: 'https://x/cb',
              IG_TARGET_ID: BIG, STATE_SIGNING_KEY_IG: KEY };

// Raw-text bodies: the 17-digit id must survive intact until the worker parses it.
const rawRes = (text, status = 200) => new Response(text, {
  status, headers: { 'content-type': 'application/json' } });

function stubFetch(exchangeText, meText = `{"user_id":${BIG},"username":"dr.shenhav"}`) {
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.startsWith('https://api.instagram.com/oauth/access_token')) return rawRes(exchangeText);
    if (u.startsWith('https://graph.instagram.com/access_token')) return rawRes('{"access_token":"long","expires_in":5184000}');
    if (u.startsWith('https://graph.instagram.com/me')) return rawRes(meText);
    throw new Error('unexpected fetch ' + u);
  };
}

async function run() {
  const { state, nonce } = await mintState(KEY, 'instagram');
  return worker.fetch(new Request(
    'https://oauth.mash.org.il/meta/instagram/callback?code=c&state=' + state,
    { headers: { cookie: `bind_instagram=${nonce}` } }), env);
}

test('id > 2^53 as numeric literal: top-level shape accepted (lossless)', async () => {
  stubFetch(`{"access_token":"short","user_id":${BIG},"permissions":"${SCOPES}"}`);
  const res = await run();
  assert.equal(res.status, 200);
  assert.match(await res.text(), /טוקן חדש מוכן/);
});

test('id > 2^53 inside legacy envelope accepted (lossless)', async () => {
  stubFetch(`{"data":[{"access_token":"short","user_id":${BIG},"permissions":"${SCOPES}"}]}`);
  const res = await run();
  assert.equal(res.status, 200);
});

test('id > 2^53 as string literal accepted', async () => {
  stubFetch(`{"access_token":"short","user_id":"${BIG}","permissions":"${SCOPES}"}`);
  const res = await run();
  assert.equal(res.status, 200);
});

test('a genuinely different big id is still rejected, with safe diagnostics and no value leak', async () => {
  stubFetch(`{"access_token":"short","user_id":27505601549070001,"permissions":"${SCOPES}"}`);
  const res = await run();
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.match(text, /חשבון Instagram לא תואם/);
  assert.match(text, /ig-code-exchange/);
  assert.match(text, /parsed_is_safe_integer/);
  assert.ok(!text.includes('27505601549070001'), 'mismatched id value must not leak');
  assert.ok(!text.includes(BIG), 'target id value must not leak');
});

test('/me readback mismatch is diagnosed at its own stage', async () => {
  stubFetch(`{"access_token":"short","user_id":${BIG},"permissions":"${SCOPES}"}`,
            `{"user_id":27505601549070002,"username":"other"}`);
  const res = await run();
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.match(text, /ig-me-readback/);
  assert.ok(!text.includes('27505601549070002'));
});

// --- Round 2: hostile shapes. Extraction is scoped to the exact object path;
// a decoy user_id elsewhere or a duplicate key must fail closed (502), never 200.

test('HOSTILE: decoy user_id earlier in the document does not bypass the exchange check', async () => {
  stubFetch(`{"metadata":{"user_id":${BIG}},"data":[{"access_token":"short","user_id":27505601549070001,"permissions":"${SCOPES}"}]}`);
  const res = await run();
  assert.equal(res.status, 502);
  assert.match(await res.text(), /ig-code-exchange/);
});

test('HOSTILE: duplicate user_id key at the entry fails closed', async () => {
  stubFetch(`{"access_token":"short","user_id":${BIG},"user_id":27505601549070001,"permissions":"${SCOPES}"}`);
  const res = await run();
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.match(text, /ig-code-exchange/);
  assert.ok(!text.includes(BIG));
});

test('HOSTILE: decoy user_id nested in the /me readback does not bypass it', async () => {
  stubFetch(`{"access_token":"short","user_id":${BIG},"permissions":"${SCOPES}"}`,
            `{"note":{"user_id":${BIG}},"user_id":27505601549070002,"username":"other"}`);
  const res = await run();
  assert.equal(res.status, 502);
  assert.match(await res.text(), /ig-me-readback/);
});

test('HOSTILE: duplicate user_id at the /me readback fails closed', async () => {
  stubFetch(`{"access_token":"short","user_id":${BIG},"permissions":"${SCOPES}"}`,
            `{"user_id":${BIG},"user_id":27505601549070002,"username":"other"}`);
  const res = await run();
  assert.equal(res.status, 502);
  assert.match(await res.text(), /ig-me-readback/);
});
