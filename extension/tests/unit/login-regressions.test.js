const assert = require('node:assert/strict');
const extract = require('./extract-fixture.cjs');
const { scoreEvidence } = require('../../src/shared/model-policy.js');
const login = '<form action="/auth" method="post"><input type="password"></form>';
const validation = '<script>document.querySelector("input").addEventListener("input", () => {});</script>';
const benign = [
  ['ordinary college login', 'https://college.example/login', '<title>College Portal</title>' + login],
  ['ordinary validation', 'https://college.example/login', '<title>College Portal</title>' + login + validation],
  ['ordinary Ajax default form', 'https://college.example/login', '<title>College Portal</title><form><input type="password"></form>' + validation],
  ['ordinary JavaScript action', 'https://college.example/login', '<title>College Portal</title><form action="javascript:void(0)" method="post"><input type="password"></form>' + validation],
  ['ordinary accessible labels', 'https://college.example/login', '<title>College Portal</title><form action="/session" method="post"><label>Password <input type="text"></label></form>'],
  ['ordinary dialog password', 'https://college.example/login', '<title>College Portal</title><form method="dialog"><input type="password"></form>'],
  ['official Google root', 'https://accounts.google.com/', '<title>Google Account</title><p>Sign in to Google</p>' + login],
  ['official Google login path', 'https://accounts.google.com/login', '<title>Google Account</title><p>Sign in to Google</p>' + login],
  ['Pineapple substring', 'https://college.example/login', '<title>Pineapple Club</title>' + login],
  ['query brand', 'https://github.com/login?return_to=%2Ftopics%2Fpaypal', '<title>Sign in to GitHub</title>' + login],
  ['two providers', 'https://login.microsoftonline.com/', '<title>Microsoft - sign in using Google</title>' + login],
  ['visible iframe', 'https://accounts.google.com/', '<title>Google</title><p>Google sign in</p>' + login + validation + '<iframe src="/help"></iframe>'],
  ['neutral CSRF inputs', 'https://accounts.google.com/', '<title>Google</title><p>Google sign in</p>' + login + '<iframe src="/help"></iframe><input type="hidden"><input type="hidden"><input type="hidden">']
];
for (const [name, url, html] of benign) {
  const verdict = scoreEvidence(extract(html, url));
  assert.equal(verdict.outcome, 'SAFE', name);
  assert.equal(verdict.warning, false, name);
  assert(verdict.score < 35, name);
}
const ipLogin = scoreEvidence(extract('<title>Member Portal</title>' + login,
  'https://192.0.2.1/login?next=%2Faccount%2Fsignin&padding=' + 'a'.repeat(180)));
assert.equal(ipLogin.outcome, 'CAUTION', 'IP-address credential destination requires contextual review');
assert.equal(ipLogin.warning, false, 'one strong evidence category cannot display a high-risk warning');
for (const [name, url, html] of [
  ['destination named in text', 'https://phish.example/login', '<title>Member Portal</title><p>credentials-stolen.test</p><form action="https://credentials-stolen.test/collect" method="post"><input type="password"></form>'],
  ['different private tenants', 'https://victim.github.io/login', '<title>Member Portal</title><form action="https://attacker.github.io/collect" method="post"><input type="password"></form>']
]) {
  const features = extract(html, url);
  assert.equal(features.cross_domain_form_action, 1, name);
  assert.equal(scoreEvidence(features).outcome, 'CAUTION', name + ' requires contextual review');
}
for (const [name, html] of [
  ['brand and destination', '<title>PayPal Login</title><form action="https://destination.example.org/collect" method="post"><input type="password"></form>'],
  ['accessible password and destination', '<title>PayPal Login</title><form action="https://destination.example.org/collect" method="post"><input aria-label="Password"></form>'],
  ['cross-site downgrade', '<title>Member Login</title><form action="http://destination.example.org/collect" method="post"><input type="password"></form>']
]) {
  const verdict = scoreEvidence(extract(html, 'https://members.example/login'));
  assert.equal(verdict.outcome, 'HIGH_RISK', name);
  assert.equal(verdict.warning, true, name);
  assert.equal(verdict.activeCategories.length, 2, name + ' is corroborated by independent observations');
}
const passwordPost = '<form method="post" action="/session"><input type="password" name="password"></form>';
const usernameGet = '<form method="get" action="/lookup"><input autocomplete="username"></form>';
assert.equal(scoreEvidence(extract('<title>Account</title>' + passwordPost + usernameGet,
  'https://college.example/login')).outcome, 'SAFE', 'an identity GET cannot become a different password form\'s transport evidence');
const emailSso = '<form method="post" action="https://id.example.org/authorize"><input type="email" autocomplete="username"></form>';
for (const localForm of [
  '<form method="get" action="/lookup"><input type="password" name="password"></form>',
  '<form method="post" action="http://college.example/session"><input type="password" name="password"></form>'
]) {
  const verdict = scoreEvidence(extract('<title>Account</title>' + emailSso + localForm, 'https://college.example/login'));
  assert.equal(verdict.outcome, 'CAUTION', 'independent form destinations and transport cannot corroborate each other');
  assert.equal(verdict.warning, false);
}
const alternatives = scoreEvidence(extract('<title>Account</title><form method="post" action="https://id.example.org/authorize">' +
  '<input type="password" name="password"><button formaction="/lookup" formmethod="get">Local fallback</button></form>',
  'https://college.example/login'));
assert.equal(alternatives.outcome, 'CAUTION', 'alternative submitter flows are evaluated individually');
assert.equal(alternatives.warning, false);
const deceptiveDialog = scoreEvidence(extract('<title>PayPal Login</title><form method="dialog" action="http://destination.example.org/collect">' +
  '<input type="password"></form>', 'https://college.example/login'));
assert.equal(deceptiveDialog.outcome, 'CAUTION', 'dialog semantics do not erase the credential identity mismatch');
assert.equal(deceptiveDialog.score, 45);
assert.equal(deceptiveDialog.categories.destination, 0, 'dialog actions do not establish a network destination');
assert.equal(deceptiveDialog.categories.transport, 0);
console.log('Audit login and suspicious-destination policy regressions passed (offline fixtures only).');
