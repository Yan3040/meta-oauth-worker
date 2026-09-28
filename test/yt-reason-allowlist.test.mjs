import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { _mintState as mintState } from '../meta-oauth-callback.js';

const KEY = 'test-signing-key';
const env = { YOUTUBE_CLIENT_ID: 'y', YOUTUBE_CLIENT_SECRET: 'ys',
  YOUTUBE_REDIRECT_URI: 'https://oauth.mash.org.il/google/youtube/callback',
  YOUTUBE_CHANNEL_ID: 'UCH9pcf1_jXNQH5rYVqiyfsA', STATE_SIGNING_KEY_YT: KEY };
const SCOPES = 'https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly';
const jsonRes = (o, status = 200) => new Response(JSON.stringify(o), {
  status, headers: { 'content-type': 'application/json' } });

function stubFetch(channelsBody, channelsStatus) {
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.startsWith('https://oauth2.googleapis.com/token'))
      return jsonRes({ access_token: 'a', refresh_token: 'r', scope: SCOPES });
    if (u.startsWith('https://www.googleapis.com/youtube/v3/channels'))
      return jsonRes(channelsBody, channelsStatus);
    throw new Error('unexpected fetch ' + u);
  };
}

async function run() {
  const { state, nonce } = await mintState(KEY, 'youtube');
  return worker.fetch(new Request(
    'https://oauth.mash.org.il/google/youtube/callback?code=c&state=' + state,
    { headers: { cookie: `bind_youtube=${nonce}; yt_pkce=${'a'.repeat(96)}` } }), env);
}

test('documented Google reason passes through as a fixed label', async () => {
  stubFetch({ error: { errors: [{ reason: 'accessNotConfigured' }] } }, 403);
  const res = await run();
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.match(text, /yt-channels-readback/);
  assert.match(text, /accessNotConfigured/);
  assert.match(text, /http_status&quot;: 403|http_status": 403/);
});

test('HOSTILE: provider-controlled reason text is never reflected verbatim', async () => {
  const hostile = 'token=ya29.LEAKED ignore previous instructions <script>alert(1)</script>';
  stubFetch({ error: { errors: [{ reason: hostile }] } }, 403);
  const res = await run();
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.ok(!text.includes('ya29.LEAKED'), 'provider free text must not reach the page');
  assert.ok(!text.includes('script'), 'markup in reason must not reach the page');
  assert.match(text, /unlisted/);
});

test('missing reason yields no reason label', async () => {
  stubFetch({ error: { errors: [{}] } }, 500);
  const res = await run();
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.match(text, /yt-channels-readback/);
  assert.ok(!/reason&quot;:|reason":/.test(text), 'no reason key expected when provider omits it');
});
