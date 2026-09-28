import test from 'node:test';
import assert from 'node:assert/strict';
import { _structureOf as structureOf, _httpInfo as httpInfo, _ProviderStageError as ProviderStageError } from '../meta-oauth-callback.js';

test('structureOf reports key names and shapes, never values', () => {
  const body = { access_token: 'SECRET-TOKEN-VALUE', user_id: 27505601549079393, permissions: 'a,b' };
  const s = structureOf(body);
  const flat = JSON.stringify(s);
  assert.deepEqual(s, { access_token: 'string', user_id: 'number', permissions: 'string' });
  assert.ok(!flat.includes('SECRET-TOKEN-VALUE'));
  assert.ok(!flat.includes('27505601549079393'));
  assert.ok(!flat.includes('a,b'));
});

test('structureOf unwraps the IG data envelope structurally', () => {
  const s = structureOf({ data: [{ access_token: 'x'.repeat(40), user_id: 1 }] });
  assert.equal(s.data.arrayLength, 1);
  assert.deepEqual(s.data.entry, { access_token: 'string', user_id: 'number' });
});

test('httpInfo keeps status, numeric codes, type; drops messages and secrets', () => {
  const body = { error: { message: 'Invalid OAuth access token SECRET', type: 'OAuthException', code: 190, error_subcode: 463 } };
  const info = httpInfo(400, body);
  assert.equal(info.status, 400);
  assert.equal(info.code, 190);
  assert.equal(info.subcode, 463);
  assert.equal(info.type, 'OAuthException');
  assert.ok(!JSON.stringify(info).includes('SECRET'));
  assert.ok(!('message' in info));
});

test('httpInfo handles legacy IG error shape and non-json bodies', () => {
  const legacy = httpInfo(400, { error_type: 'OAuthException', code: 400, error_message: 'bad SECRET' });
  assert.equal(legacy.type, 'OAuthException');
  assert.equal(legacy.code, 400);
  assert.ok(!JSON.stringify(legacy).includes('SECRET'));
  const nonJson = httpInfo(502, null);
  assert.equal(nonJson.structure, 'non-json');
});

test('ProviderStageError carries stage + info only', () => {
  const e = new ProviderStageError('ig-code-exchange', { status: 400, code: 190 });
  assert.equal(e.stage, 'ig-code-exchange');
  assert.equal(e.info.code, 190);
});
