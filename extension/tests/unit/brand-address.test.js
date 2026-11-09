const assert = require('node:assert/strict');
const extract = require('./extract-fixture.cjs');
const policy = require('../../src/shared/model-policy.js');
const login = (brand = 'PayPal') => `<h1>${brand} sign in</h1><form method="post" action="/session"><input type="password"><button>Sign in</button></form>`;
for (const [url, brand] of [
  ['https://paypa1.com/', 'PayPal'], ['https://micros0ft.com/', 'Microsoft'],
  ['https://\u0430pple.com/', 'Apple'], ['https://paypal.com.attacker.example/', 'PayPal'],
  ['https://paypal.com.example/', 'PayPal'], ['https://paypa1.github.io/', 'PayPal'],
  ['https://login.paypa1.github.io/', 'PayPal']
]) {
  const features = extract(login(brand), url);
  const verdict = policy.scoreEvidence(features);
  assert.equal(features.brand_address_deception, 1, url);
  assert.equal(features.credential_contexts[0].credential_brand_address_match, 1, url);
  assert.equal(verdict.outcome, 'HIGH_RISK', url);
  assert.equal(verdict.categories.identity, 45, url);
  assert.equal(verdict.categories.address, 35, url);
  assert.equal(verdict.score, 80, url);
  assert(verdict.evidence.some(item => item.key === 'credential_brand_address_match'), url);
}
for (const [name, html, url] of [
  ['official site', login(), 'https://www.paypal.com/'],
  ['official regional site', login('Google'), 'https://accounts.google.co.in/'],
  ['arbitrary edit distance', login(), 'https://paypall.com/'],
  ['ordinary IDN', login('Apple'), 'https://b\u00fccher.de/'],
  ['shared hosting alone', login(), 'https://tenant.github.io/'],
  ['lookalike only below another tenant boundary', login(), 'https://paypa1.tenant.github.io/'],
  ['provider phrase', '<h1>Sign in with PayPal</h1><form method=post><input type=password></form>', 'https://paypa1.com/'],
  ['footer form', `<footer>${login()}</footer>`, 'https://paypa1.com/'],
  ['different form brand', login('Microsoft'), 'https://paypa1.com/'],
  ['title alone', '<title>PayPal sign in</title><form method=post><input type=password></form>', 'https://paypa1.com/'],
  ['body repetitions', '<title>PayPal</title><p>PayPal PayPal</p><form method=post><input type=password></form>', 'https://paypa1.com/'],
  ['identity fields alone', '<h1>PayPal sign in</h1><form method=post><input type=email></form>', 'https://paypa1.com/'],
  ['hidden heading', '<h1 hidden>PayPal sign in</h1><form method=post><input type=password></form>', 'https://paypa1.com/'],
  ['editor heading', '<div contenteditable><h1>PayPal sign in</h1></div><form method=post><input type=password></form>', 'https://paypa1.com/'],
  ['distant unrelated login', '<h1>PayPal sign in</h1><p>one</p><p>two</p><p>three</p><form method=post><input type=password></form>', 'https://paypa1.com/'],
  ['lookalike without credentials', '<h1>PayPal sign in</h1>', 'https://paypa1.com/']
]) {
  const features = extract(html, url);
  assert.notEqual(policy.scoreEvidence(features).outcome, 'HIGH_RISK', name);
  assert(features.credential_contexts.every(context => context.credential_brand_address_match === 0), name);
}
const separate = extract('<form method=post><h1>PayPal sign in</h1><input type=email></form>' +
  '<form method=post><h1>Member sign in</h1><input type=password></form>', 'https://paypa1.com/');
assert.notEqual(policy.scoreEvidence(separate).outcome, 'HIGH_RISK', 'identity-only form cannot corroborate a different password form');
const hostileAggregate = { ...separate, credential_brand_identity_claim: 1, credential_brand_address_match: 1 };
assert.notEqual(policy.scoreEvidence(hostileAggregate).outcome, 'HIGH_RISK', 'per-context defaults prevent aggregate leakage');
const noClaim = policy.scoreEvidence({credential_context:1, has_password_input:1, brand_address_deception:1});
assert.equal(noClaim.outcome, 'SAFE', 'address resemblance alone remains inconclusive');
for (const context of ['footer', 'nav', 'aside']) {
  const features = extract(`<${context}><div id="component"></div></${context}>`, 'https://paypa1.com/', (window) => {
    window.document.getElementById('component').attachShadow({mode:'open'}).innerHTML = '<form method="post"><h1>PayPal sign in</h1><input type="password"></form>';
  });
  assert.notEqual(policy.scoreEvidence(features).outcome, 'HIGH_RISK', `${context} exclusion crosses shadow roots`);
}
for (const wrapper of ['article', 'div role="article"']) {
  const tag = wrapper.split(' ')[0];
  const features = extract(`<${wrapper}>${login()}</${tag}>`, 'https://paypa1.com/');
  assert.equal(policy.scoreEvidence(features).outcome, 'HIGH_RISK', 'an article wrapper does not neutralize active credential UI');
}
const shadowArticle = extract('<article><div id="component"></div></article>', 'https://paypa1.com/', (window) => {
  window.document.getElementById('component').attachShadow({mode:'open'}).innerHTML = '<form method="post"><h2>PayPal sign in</h2><input type="password"></form>';
});
assert.equal(policy.scoreEvidence(shadowArticle).outcome, 'HIGH_RISK', 'active article identity crosses an open shadow boundary');
const slottedArticle = extract('<div id="component"><div slot="example">' + login() + '</div></div>', 'https://paypa1.com/', (window) => {
  window.document.getElementById('component').attachShadow({mode:'open'}).innerHTML = '<article><slot name="example"></slot></article>';
});
assert.equal(policy.scoreEvidence(slottedArticle).outcome, 'HIGH_RISK', 'a slotted active form retains identity through its article wrapper');
console.log('Reviewed address deception and contextual identity regressions passed.');
