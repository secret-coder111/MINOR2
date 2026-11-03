const assert = require('node:assert/strict');
const domain = require('../../src/shared/domain-utils.js');
const tldts = require('tldts');
const cases = [
  ['accounts.example.co.uk', 'example.co.uk'], ['a.ac.in', 'a.ac.in'],
  ['victim.github.io', 'victim.github.io'], ['attacker.pages.dev', 'attacker.pages.dev'],
  ['foo.bar.ck', 'foo.bar.ck'], ['www.ck', 'www.ck'], ['a.www.ck', 'www.ck'],
  ['city.kawasaki.jp', 'city.kawasaki.jp'], ['a.city.kawasaki.jp', 'city.kawasaki.jp'],
  ['127.0.0.1', '127.0.0.1'], ['[::1]', '[::1]'], ['localhost', 'localhost'],
  ['co.uk', ''], ['com', ''], ['shop.example.COM.', 'example.com'],
  ['a.example.test', 'example.test'], ['bücher.de', 'xn--bcher-kva.de']
];
for (const [hostname, expected] of cases) {
  assert.equal(domain.getRegistrableDomain(hostname), expected, hostname);
  if (!domain.isIpAddress(hostname) && hostname !== 'localhost') {
    assert.equal(expected, tldts.getDomain(domain.normalizeHostname(hostname), {
      allowPrivateDomains: true
    }) || '', `Pinned PSL parity: ${hostname}`);
  }
}
assert.equal(domain.sameSite('login.example.com', 'api.example.com'), true);
assert.equal(domain.sameSite('victim.github.io', 'attacker.github.io'), false);
assert.equal(domain.sameSite('co.uk', 'example.co.uk'), false);
assert.equal(domain.sameSite('127.0.0.1', '10.0.0.1'), false);
assert.equal(domain.sameSite('', ''), false);
assert.equal(domain.isLoopback('127.1.2.3'), true);
assert.equal(domain.isLoopback('[::1]'), true);
assert.equal(domain.normalizeHostname('example.com/attacker'), '');
// Exercise every pinned rule, including exception and wildcard paths.
for (const rule of require('../../src/shared/public-suffix-rules.json').rules) {
  const host = 'audit.' + rule.replace(/^!/, '').replace(/^\*\./, 'wildcard.');
  assert.equal(domain.getRegistrableDomain(host), tldts.getDomain(host, {
    allowPrivateDomains: true
  }) || '', `Full PSL parity: ${rule}`);
}
console.log('Offline public-suffix domain validation passed.');
