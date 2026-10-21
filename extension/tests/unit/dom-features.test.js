const assert = require('assert');
const fs = require('fs');
const { JSDOM } = require('jsdom');

const source = fs.readFileSync('extension/src/content/dom-features.js', 'utf8');

function extract(html, url) {
  const dom = new JSDOM(html, { url, runScripts: 'outside-only' });
  dom.window.eval(source);
  return dom.window.PhishGuard.extractDomFeatures();
}

const result = extract(`
  <title>Example Login</title>
  <div hidden>PayPal hidden text</div>
  <div>Welcome to the account</div>
  <iframe hidden></iframe>
  <iframe style="display: none"></iframe>
  <meta http-equiv="refresh" content="0;url=https://example.test">
  <script>eval(atob("encoded"))</script>
`, 'https://example.test/login');

assert.strictEqual(result.brand_name_in_visible_text, 0);
assert.strictEqual(result.hidden_iframe_count, 2);
assert.strictEqual(result.meta_refresh_count, 1);
assert(result.obfuscated_script_score >= 0.5);
assert.strictEqual(result.frontpage_is_landing_page, 0);
assert.strictEqual(result.frontpage_has_credential_form, 0);

const frontpage = extract(`
  <title>PayPal Sign In</title>
  <form><input type="password"></form>
  <iframe hidden></iframe>
  <meta http-equiv="refresh" content="0;url=https://example.test">
  <script>eval(atob("encoded"))</script>
`, 'https://paypal-security.example/');

assert.strictEqual(frontpage.frontpage_is_landing_page, 1);
assert.strictEqual(frontpage.frontpage_has_credential_form, 1);
assert(frontpage.frontpage_suspicious_signal_count >= 4);
console.log('DOM feature extraction validation passed.');
