import test from 'node:test';
import assert from 'node:assert/strict';
import { _httpInfo as httpInfo, _ProviderStageError as ProviderStageError, _providerDiagnostic as providerDiagnostic } from '../meta-oauth-callback.js';

const SECRETISH = 'sk-live-SECRET-VALUE-12345';

test('httpInfo keeps status + numeric codes only', () => {
  const info = httpInfo(400, { error: { message: SECRETISH, type: SECRETISH, code: 190, error_subcode: 463 } });
  assert.deepEqual(info, { status: 400, code: 190, subcode: 463 });
  assert.ok(!JSON.stringify(info).includes(SECRETISH));
});

test('httpInfo drops secret-looking keys, string types, and cardinality', () => {
  const body = { [SECRETISH]: 'x', error: { code: '190', type: SECRETISH, status: SECRETISH, data: [1, 2, 3] } };
  const info = httpInfo(400, body);
  assert.deepEqual(info, { status: 400 }); // string "190" rejected: integers only
  assert.ok(!JSON.stringify(info).includes(SECRETISH));
  assert.ok(!JSON.stringify(info).includes('data'));
});

test('httpInfo handles legacy IG shape and non-json bodies without reflection', () => {
  const legacy = httpInfo(400, { error_type: SECRETISH, code: 400, error_message: SECRETISH });
  assert.deepEqual(legacy, { status: 400, code: 400 });
  assert.deepEqual(httpInfo(502, null), { status: 502 });
});

test('diagnostic page renders stage + numeric codes and nothing injectable', async () => {
  const e = new ProviderStageError('ig-code-exchange', { status: 400, code: 190, subcode: 463 });
  const res = providerDiagnostic(e);
  assert.equal(res.status, 502);
  const text = await res.text();
  assert.ok(text.includes('ig-code-exchange'));
  assert.ok(text.includes('400') && text.includes('190') && text.includes('463'));
  // An attacker-controlled body that reached httpInfo must not appear
  const evil = new ProviderStageError('ig-code-exchange', httpInfo(400, { error: { message: SECRETISH, type: SECRETISH, code: 190 } }));
  const page2 = await providerDiagnostic(evil).text();
  assert.ok(!page2.includes(SECRETISH));
});

test('ProviderStageError carries stage + info only', () => {
  const e = new ProviderStageError('ig-code-exchange-shape', {});
  assert.equal(e.stage, 'ig-code-exchange-shape');
  assert.deepEqual(e.info, {});
});
