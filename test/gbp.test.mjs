import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { _mintState as mintState } from '../meta-oauth-callback.js';
const KEY = 'gbp-fixture-key';
const CLIENT = '216606794484-pptm2u9sru96oero7qo9i6flglatr46d.apps.googleusercontent.com';
const REDIRECT = 'https://oauth.mash.org.il/google/gbp/callback';
const RESOURCE = 'accounts/113236961009268126526/locations/5514155164283068581/localPosts/3696915744151409203';
const SCOPE = 'https://www.googleapis.com/auth/business.manage';
const env = {GBP_CLIENT_ID:CLIENT, GBP_CLIENT_SECRET:'SECRET_SENTINEL', GBP_REDIRECT_URI:REDIRECT, STATE_SIGNING_KEY_GBP:KEY};
const json = (o, status=200) => new Response(JSON.stringify(o), {status});
const token = () => ({access_token:'ACCESS_SENTINEL', refresh_token:'REFRESH_SENTINEL', scope:SCOPE});
async function callback({cookie=true, pkce='a'.repeat(96), provider='gbp', query='', method='GET'}={}) {
  const {state,nonce} = await mintState(KEY,provider);
  const headers = cookie ? {cookie:`bind_gbp=${nonce}; gbp_pkce=${pkce}`} : {};
  return worker.fetch(new Request(REDIRECT+'?code=CODE_SENTINEL&state='+state+query,{headers,method}),env);
}
function stub(tok=token(), body={name:RESOURCE}, status=200) {
  const calls=[];
  globalThis.fetch = async (url,opts) => {
    calls.push([String(url),opts]);
    if (String(url)==='https://oauth2.googleapis.com/token') return json(tok);
    if (String(url)==='https://mybusiness.googleapis.com/v4/'+RESOURCE) return json(body,status);
    throw new Error('unexpected fetch');
  };
  return calls;
}

test('GBP start isolates state/cookies, pins client and exact scope, uses S256', async()=>{
  const res=await worker.fetch(new Request('https://oauth.mash.org.il/google/gbp/start'),env);
  assert.equal(res.status,302);
  const u=new URL(res.headers.get('location'));
  assert.equal(u.origin,'https://accounts.google.com');
  for (const [k,v] of Object.entries({client_id:CLIENT,redirect_uri:REDIRECT,scope:SCOPE,prompt:'consent',access_type:'offline',code_challenge_method:'S256'})) assert.equal(u.searchParams.get(k),v);
  assert.ok(!u.searchParams.has('include_granted_scopes'));
  assert.match(res.headers.get('set-cookie'),/bind_gbp=[0-9a-f]{32}/);
  assert.match(res.headers.get('set-cookie'),/gbp_pkce=[0-9a-f]{96}; Max-Age=600; Path=\/google\/gbp; HttpOnly; Secure; SameSite=Lax/);
  assert.equal(res.headers.get('cache-control'),'no-store');
});

test('exact iLEAD GET precedes token page; no provider writes or external secret sink', async()=>{
  const calls=stub(); const res=await callback(); const text=await res.text();
  assert.equal(res.status,200); assert.equal(calls.length,2);
  assert.equal(calls[0][1].method,'POST'); assert.equal(calls[0][1].redirect,'error');
  assert.equal(calls[0][1].body.get('client_secret'),'SECRET_SENTINEL');
  assert.equal(calls[0][1].body.get('redirect_uri'),REDIRECT);
  assert.equal(calls[1][1].method,'GET'); assert.equal(calls[1][1].redirect,'error');
  assert.equal(calls[1][1].headers.authorization,'Bearer ACCESS_SENTINEL');
  assert.ok(!calls[1][0].includes('ACCESS_SENTINEL'));
  assert.ok(text.includes('REFRESH_SENTINEL'));
  for(const value of ['ACCESS_SENTINEL','SECRET_SENTINEL','CODE_SENTINEL']) assert.ok(!text.includes(value));
  assert.equal(res.headers.get('cache-control'),'no-store');
  assert.equal(res.headers.get('referrer-policy'),'no-referrer');
  assert.match(res.headers.get('set-cookie'),/bind_gbp=; Max-Age=0/);
  assert.match(res.headers.get('set-cookie'),/gbp_pkce=; Max-Age=0/);
});

test('wrong state/provider/browser/PKCE fail before exchange', async()=>{
  for(const options of [{cookie:false},{provider:'youtube'},{pkce:'a'.repeat(95)},{pkce:'a'.repeat(97)},{pkce:'x'.repeat(96)}]){
    const calls=stub(); const res=await callback(options);
    assert.equal(res.status,400); assert.equal(calls.length,0);
    assert.match(res.headers.get('set-cookie'),/gbp_pkce=; Max-Age=0/);
  }
});

test('missing token/scope or wrong resource never renders refresh', async()=>{
  for(const tok of [{access_token:'ACCESS_SENTINEL',scope:SCOPE}, {refresh_token:'REFRESH_SENTINEL',scope:SCOPE}, {...token(),scope:'other'}, {...token(),refresh_token:{secret:'REFRESH_SENTINEL'}}]){
    const calls=stub(tok); const res=await callback();
    assert.equal(res.status,502); assert.equal(calls.length,1);
    assert.ok(!(await res.text()).includes('REFRESH_SENTINEL'));
  }
  for(const body of [{name:'wrong'}, {}, []]){
    stub(token(),body); const res=await callback(); assert.equal(res.status,502);
    assert.ok(!(await res.text()).includes('REFRESH_SENTINEL'));
  }
});

test('hostile error body never reaches response; numeric HTTP status only', async()=>{
  stub(token(),{error:{message:'LEAK_SENTINEL <script>do something</script>'}},403);
  const res=await callback(); const text=await res.text();
  assert.equal(res.status,502); assert.match(text,/gbp-ilead-readback/);
  assert.ok(!text.includes('LEAK_SENTINEL')); assert.ok(!text.includes('REFRESH_SENTINEL'));
});

test('bounded response, malformed JSON, denied flow and method fail closed', async()=>{
  stub(); const denied=await callback({query:'&error=denied'}); assert.equal(denied.status,400);
  stub(); const badMethod=await callback({method:'POST'}); assert.equal(badMethod.status,405);
  for(const content of ['not json','x'.repeat(65537)]){
    globalThis.fetch=async()=>new Response(content);
    const res=await callback(); assert.equal(res.status,502); assert.ok(!(await res.text()).includes('REFRESH_SENTINEL'));
  }
});

test('wrong client, redirect, absent config, alternate origin and unknown route fail closed', async()=>{
  for(const changes of [{GBP_CLIENT_ID:'other'},{GBP_REDIRECT_URI:'https://attacker.invalid/callback'},{GBP_CLIENT_SECRET:''},{STATE_SIGNING_KEY_GBP:''}]){
    const res=await worker.fetch(new Request('https://oauth.mash.org.il/google/gbp/start'),{...env,...changes});
    assert.equal(res.status,500);
  }
  assert.equal((await worker.fetch(new Request('https://attacker.invalid/google/gbp/start'),env)).status,500);
  assert.equal((await worker.fetch(new Request('https://oauth.mash.org.il/google/gbp'),env)).status,404);
});
