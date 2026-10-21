const assert = require('assert');
const fs = require('fs');
const { JSDOM } = require('jsdom');

const source = fs.readFileSync('extension/src/content/form-features.js', 'utf8');

function extract(html, url) {
  const dom = new JSDOM(html, { url, runScripts: 'outside-only' });
  dom.window.eval(source);
  return dom.window.PhishGuard.extractFormFeatures();
}

const legitimateLogin = extract(
  '<form action="/session"><input type="email"><input type="password"></form>',
  'https://business.amazon.com/login'
);
assert.strictEqual(legitimateLogin.has_password_input, 1);
assert.strictEqual(legitimateLogin.cross_domain_form_action, 0);
assert.strictEqual(legitimateLogin.credential_submission_script, 0);

const scriptedCredentialPage = extract(
  '<input name="password"><script>document.addEventListener("input", send); fetch("/collect")</script>',
  'https://login.example.test/'
);
assert.strictEqual(scriptedCredentialPage.form_count, 0);
assert.strictEqual(scriptedCredentialPage.has_password_input, 1);
assert.strictEqual(scriptedCredentialPage.credential_submission_script, 1);

console.log('Form feature extraction validation passed.');
