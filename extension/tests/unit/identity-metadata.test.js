const assert = require('node:assert/strict');
const { test } = require('node:test');
const extract = require('./extract-fixture.cjs');
const { scoreEvidence } = require('../../src/shared/model-policy.js');
const fixtures = require('../../../ml/tests/fixtures/identity-metadata-golden.json');

for (const fixture of fixtures) {
  test(`reviewed identity/metadata: ${fixture.name}`, () => {
    const features = extract(fixture.html, fixture.url);
    assert.equal(scoreEvidence(features).outcome, fixture.outcome);
    for (const [name, value] of Object.entries(fixture.expected)) assert.equal(features[name], value, name);
  });
}

test('all native heading levels and valid ARIA headings bind to the sensitive form', () => {
  for (const [opening, closing] of [...[1, 2, 3, 4, 5, 6].map((level) => [`<h${level}>`, `</h${level}>`]),
    ['<div role="heading" aria-level="3">', '</div>'], ['<div role="heading">', '</div>']]) {
    const features = extract(`<title>Member login</title>${opening}PayPal sign in${closing}<form method="post"><input type="password"></form>`, 'https://paypa1.test/login');
    assert.equal(scoreEvidence(features).outcome, 'HIGH_RISK', opening);
    assert.equal(features.credential_contexts[0].credential_brand_address_match, 1, opening);
  }
});

test('heading and accessible logo evidence cannot cross submission contexts', () => {
  for (const identity of ['<h2>PayPal sign in</h2>', '<img alt="PayPal logo">']) {
    const features = extract(`<title>Member login</title>${identity}<form method="post"><input type="password"></form>` +
      '<section><h2>Organization login</h2><form method="post" action="https://identity.other.test/session"><input type="password"></form></section>', 'https://members.example/login');
    assert.equal(features.credential_contexts[0].brand_domain_mismatch, 1);
    assert.equal(features.credential_contexts[1].brand_domain_mismatch, 0);
    assert.equal(scoreEvidence(features).outcome, 'CAUTION');
  }
});

test('finite normalized multilingual password prompts remain structural metadata', () => {
  for (const prompt of ['पासवर्ड', 'कूटशब्द', 'Mot de passe', 'Contraseña', 'contrasen\u0303a', 'Passwort', 'Senha', 'Пароль', 'كلمة المرور', '密码', 'パスワード', 'Ｐａｓｓｗｏｒｄ', 'Pass\u200bword']) {
    const features = extract(`<title>Member login</title><form method="post"><label>${prompt}<input name="x"></label></form>`, 'https://members.example/login', (window) => {
      Object.defineProperty(window.document.querySelector('input'), 'value', { get() { throw new Error('A field value was read'); } });
    });
    assert.equal(features.has_password_input, 1, prompt);
    assert.equal(features.sensitive_credential_field_count, 1, prompt);
  }
});

test('logo names referenced from editors never read user-authored text', () => {
  const features = extract('<title>Member login</title><div contenteditable><span id="name">PayPal</span></div>' +
    '<img aria-labelledby="name"><form method="post"><input type="password"></form>', 'https://paypa1.test/login', (window) => {
    Object.defineProperty(window.document.getElementById('name').firstChild, 'nodeValue', { get() { throw new Error('Editor contents were read'); } });
  });
  assert.equal(features.body_brand_identity_claim, 0);
  assert.equal(scoreEvidence(features).outcome, 'SAFE');
});
