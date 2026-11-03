const assert = require('node:assert/strict');
const { test } = require('node:test');
const extract = require('./extract-fixture.cjs');
const { scoreEvidence } = require('../../src/shared/model-policy.js');

test('explicit verification-code prompts remain sensitive when email is mentioned', () => {
  for (const prompt of ['Email verification code', 'Email one-time code', 'Authenticator code', 'Two-factor authentication code']) {
    const features = extract(`<title>PayPal sign in</title><form method="post" action="https://collector.invalid/collect"><label>${prompt}<input type="text"></label></form>`, 'https://members.example/verify');
    assert.equal(features.sensitive_credential_field_count, 1, prompt);
    assert.equal(scoreEvidence(features).outcome, 'HIGH_RISK', prompt);
  }
});

test('recovery email and generic code prompts do not become sensitive credentials', () => {
  for (const prompt of ['Email address to reset your password', 'Coupon code', 'Postal code', 'Product code']) {
    const features = extract(`<title>Member portal</title><form method="post"><label>${prompt}<input type="text"></label></form>`, 'https://members.example/login');
    assert.equal(features.sensitive_credential_field_count, 0, prompt);
    assert.equal(scoreEvidence(features).outcome, 'SAFE', prompt);
  }
});

test('a same-origin lookalike requesting an email verification code retains sensitive context', () => {
  const features = extract('<title>Member portal</title><h1>PayPal sign in</h1><form method="post" action="/session"><label>Email verification code<input type="text"></label></form>', 'https://paypa1.test/verify');
  assert.equal(features.sensitive_credential_field_count, 1);
  assert.equal(features.credential_contexts[0].credential_brand_address_match, 1);
  assert.equal(scoreEvidence(features).outcome, 'HIGH_RISK');
  assert.equal(scoreEvidence(features).categories.destination, 0, 'no external destination is invented');
});

test('GET transport evidence requires a sensitive control included in native submission', () => {
  for (const input of ['<input type="password">', '<input type="password" name="">', '<input type="password"><input type="email" name="email">']) {
    const features = extract(`<title>PayPal sign in</title><form method="get">${input}<button>Sign in</button></form>`, 'https://members.example/login');
    assert.equal(scoreEvidence(features).categories.transport, 0, input);
    assert.equal(scoreEvidence(features).outcome, 'CAUTION', input);
  }
  const named = extract('<title>PayPal sign in</title><form method="get"><input type="password" name="password"><button>Sign in</button></form>', 'https://members.example/login');
  assert.equal(scoreEvidence(named).outcome, 'HIGH_RISK', 'a named password still creates query exposure evidence');
});

test('GET exposure cannot leak between alternative submission flows', () => {
  const features = extract('<title>Member portal</title><form method="post" action="https://identity.example.org/session"><input type="password" name="password"><button formmethod="get" formaction="/lookup">Fallback</button></form>', 'https://members.example/login');
  assert.equal(scoreEvidence(features).outcome, 'CAUTION');
  assert.equal(scoreEvidence(features).warning, false);
});

test('new credential observations never read field values', () => {
  const features = extract('<title>Account</title><form method="get"><input type="password" name="password"><input placeholder="Email verification code" name="otp"><button>Continue</button></form>', 'https://members.example/login', (window) => {
    for (const input of window.document.querySelectorAll('input')) {
      Object.defineProperty(input, 'value', { get() { throw new Error('Field values must never be inspected'); } });
    }
  });
  assert.equal(features.sensitive_credential_field_count, 2);
  assert.equal(features.credential_contexts[0].credential_form_get_exposes_sensitive, 1);
});
