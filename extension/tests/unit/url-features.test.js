const assert = require('node:assert/strict');
const extract = require('./extract-fixture.cjs');
const login = '<form action="/auth" method="post"><input type="password"></form>';
for (const [name, url, title] of [
  ['Pineapple substring', 'https://college.example/login', 'Pineapple Club'],
  ['brand only in query', 'https://github.com/login?return_to=%2Ftopics%2Fpaypal', 'Sign in to GitHub'],
  ['multiple providers', 'https://login.microsoftonline.com/', 'Microsoft - sign in using Google'],
  ['provider mention', 'https://college.example/login', 'College - Sign in with Google'],
  ['official subdomain', 'https://accounts.google.com/', 'Google Account']
]) {
  const result = extract('<title>' + title + '</title>' + login, url);
  assert.equal(result.brand_domain_mismatch, 0, name);
  assert.equal(result.page_title_mismatch, 0, name);
}
const query = extract('<title>Sign in to GitHub</title>' + login, 'https://github.com/login?paypal=1');
assert.equal(query.brand_name_in_url, 0);
assert.equal(query.brand_identity_claim, 0);
const deceptive = extract('<title>PayPal - Sign In</title>' + login, 'https://members.example/login');
assert.equal(deceptive.brand_identity_claim, 1);
assert.equal(deceptive.brand_domain_mismatch, 1);
const hostClaim = extract('<title>Member Portal</title>' + login, 'https://paypal-login.example/');
assert.equal(hostClaim.brand_domain_mismatch, 1);
assert.equal(hostClaim.brand_name_in_url, 1);
const suffixAttack = extract('<title>PayPal</title>' + login, 'https://paypal.com.attacker.example/');
assert.equal(suffixAttack.is_official_brand_domain, 0);
assert.equal(suffixAttack.brand_domain_mismatch, 1);
const repeatedProvider = extract('<title>Sign in with Google - Google Accounts</title>' + login, 'https://members.example/');
assert.equal(repeatedProvider.brand_domain_mismatch, 1);
const counts = extract('', 'https://auth7.college.example/login?ref=12');
assert.equal(counts.digit_count, 3, 'hostname digits are not counted twice');
assert.equal(counts.dot_count, 2);
assert.equal(counts.subdomain_count, 1);
const privateSite = extract('', 'https://auth.victim.github.io/');
assert.equal(privateSite.subdomain_count, 1, 'private hosting tenant is registrable boundary');
const ip = extract('', 'https://192.0.2.1/');
assert.equal(ip.has_ip_address, 1);
assert.equal(ip.subdomain_count, 0);
const loopback = extract('', 'http://127.0.0.2:8123/');
assert.equal(loopback.uses_http, 0);
assert.equal(loopback.has_unusual_port, 0);

console.log('URL feature extraction regression tests passed.');
