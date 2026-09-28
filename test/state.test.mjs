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
