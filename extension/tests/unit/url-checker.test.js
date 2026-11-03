const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const root = path.resolve(__dirname, '../../demo');
function load() {
  const dom = new JSDOM(fs.readFileSync(path.join(root, 'url-checker.html'), 'utf8'), { url: 'https://lab.example/url-checker.html', runScripts: 'outside-only' });
  dom.window.fetch = () => { throw new Error('Checking a URL must not send a request'); };
  for (const file of ['url-core.js', 'url-model.js', 'url-analysis.js', 'url-checker.js']) dom.window.eval(fs.readFileSync(path.join(root, file), 'utf8'));
  return dom;
}
test('URL-only model uses canonical explicit addresses without borrowing the page identity', () => {
  const dom = load();
  const { URLChecker } = dom.window.PhishGuard;
  const value = URLChecker.analyze('github.com/login');
  assert.equal(value.url, 'https://github.com/login');
  assert.equal(value.host, 'github.com');
  assert.equal(value.site, 'github.com');
  assert.equal(value.band, 'low', 'Research-model false positives must not become a primary phishing accusation');
  assert.equal(value.score, 0);
  assert.equal(URLChecker.analyze('http://http-password.badssl.com/').band, 'caution');
  const reported = URLChecker.analyze('http://banamxr.com/1/mexico/');
  assert.equal(reported.score, 15, 'An HTTP transport caution must explain a nonzero URL-only score');
  assert.equal(reported.band, 'caution');
  assert.equal(reported.scoreComponents[0].points, 15);
  assert.equal(URLChecker.analyze('https://example.com/').score, 0, 'Do not invent evidence to avoid a zero');
  assert.equal(URLChecker.analyze('http://127.0.0.1:8080/').scoreComponents.some(c => c.category === 'URL HTTP transport'), false, 'Local fixtures are not public transport destinations');
  assert.equal(URLChecker.analyze('https://paypal.com.security-check.example.invalid/verify').band, 'caution');
  assert(Number.isFinite(value.score));
  assert(value.score >= 0 && value.score <= 100);
  dom.window.document.title = 'PayPal Security Update';
  const again = URLChecker.analyze('github.com/login');
  assert.equal(again.probability, value.probability);
  assert.equal(again.features.brand_domain_mismatch, value.features.brand_domain_mismatch);
  assert.equal(URLChecker.normalize('example.com:8080/path').href, 'https://example.com:8080/path');
  for (const invalid of ['', 'javascript:alert(1)', 'data:text/html,<script>bad</script>', 'file:///C:/secret',
    'ftp://example.com/', 'https://user:password@example.com/', 'https://good.test\n@bad.test', 'https://[invalid', 'x'.repeat(4097)]) {
    assert.throws(() => URLChecker.analyze(invalid), undefined, invalid);
  }
  dom.window.close();
});
test('checker displays the exact measured model metrics and clears stale results on invalid input or missing model', () => {
  const dom = load();
  const doc = dom.window.document;
  assert.equal(doc.querySelector('meta[http-equiv="Content-Security-Policy"]').content.includes("connect-src 'none'"), true);
  assert.equal(doc.querySelector('input').id, 'urlInput');
  assert.equal(doc.querySelectorAll('input').length, 1, 'No sign-in details are requested');
  assert.equal(doc.getElementById('modelMetrics').children.length, 4);
  const model = dom.window.PHISHGUARD_URL_PREVIEW;
  assert.equal(model.deployment_eligible, false);
  assert.equal(model.mode, 'research_preview');
  assert.match(model.model_version, /^url-checker-research-[0-9-]+(?:-expanded)?$/);
  // Published compact results keep clean-checkout tests independent of the
  // large local training manifests and Python estimators.
  const metadata = JSON.parse(fs.readFileSync(path.resolve(root, '../../docs/audit', model.model_version + '-comparison.json'), 'utf8'));
  assert.equal(model.model_version, metadata.model_version);
  for (const key of ['accuracy', 'precision', 'recall', 'f1', 'false_positive_rate']) {
    assert.equal(model.metrics[key], metadata.test[key]);
  }
  doc.querySelector('[data-url-example]').click();
  assert.equal(doc.getElementById('urlResult').hidden, false);
  assert.equal(doc.getElementById('openCheckedUrl').href, 'https://github.com/login');
  const input = doc.getElementById('urlInput');
  input.dispatchEvent(new dom.window.Event('input'));
  assert.equal(doc.getElementById('urlResult').hidden, true, 'Editing the address clears an older result');
  assert.equal(doc.getElementById('openCheckedUrl').hasAttribute('href'), false);
  input.value = 'javascript:alert(1)';
  doc.getElementById('checkUrl').click();
  assert.equal(doc.getElementById('urlResult').hidden, true);
  assert.equal(doc.getElementById('openCheckedUrl').hasAttribute('href'), false);
  assert.equal(doc.getElementById('inputError').hidden, false);
  input.value = 'https://example.com';
  delete dom.window.PHISHGUARD_URL_PREVIEW;
  doc.getElementById('checkUrl').click();
  assert.match(doc.getElementById('modelDiagnostic').textContent, /model unavailable/);
  assert.equal(doc.getElementById('urlResult').hidden, false, 'The independent evidence policy remains available');
  input.value = 'http://banamxr.com/1/mexico/';
  doc.getElementById('checkUrl').click();
  assert.equal(doc.getElementById('urlScore').textContent, '15');
  assert.match(doc.getElementById('scoreBreakdown').textContent, /HTTP transport: \+15/);
  dom.window.close();
});
test('official AMTSO feature entry stays distinct from statistical URL classification', () => {
  const dom = load();
  const doc = dom.window.document;
  doc.querySelector('[data-url-example*="amtso"]').click();
  assert.equal(doc.getElementById('securityTestNote').hidden, false);
  assert.match(doc.getElementById('securityTestNote').textContent, /harmless AMTSO/);
  const value = dom.window.PhishGuard.URLChecker.analyze('https://www.amtso.org/check-desktop-phishing-page/');
  assert.equal(Number(doc.getElementById('urlScore').textContent), value.score);
  assert.equal(dom.window.PhishGuard.URLChecker.analyze('https://amtso.org.evil.test/check-desktop-phishing-page/').securityTest, false);
  dom.window.close();
});
