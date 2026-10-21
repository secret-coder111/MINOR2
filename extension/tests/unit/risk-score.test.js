const assert = require('assert');
const { scoreFeatures, getRiskLevel } = require('../../src/shared/risk-score.js');
const { JSDOM } = require('jsdom');

function loadDemo(url, htmlPath) {
  const dom = new JSDOM(require('fs').readFileSync(htmlPath, 'utf8'), { url });
  const { window } = dom;

  global.window = window;
  global.document = window.document;
  global.location = window.location;
  global.navigator = window.navigator;

  require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'shared', 'feature-schema.js'), 'utf8');
  require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'shared', 'constants.js'), 'utf8');
  require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'shared', 'browser-api.js'), 'utf8');
  require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'shared', 'risk-score.js'), 'utf8');
  require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'content', 'url-features.js'), 'utf8');

  window.eval(require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'shared', 'feature-schema.js'), 'utf8'));
  window.eval(require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'shared', 'constants.js'), 'utf8'));
  window.eval(require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'shared', 'browser-api.js'), 'utf8'));
  window.eval(require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'shared', 'risk-score.js'), 'utf8'));
  window.eval(require('fs').readFileSync(require('path').join(process.cwd(), 'extension', 'src', 'content', 'url-features.js'), 'utf8'));

  return window;
}

const legitimate = {
  url_length: 90,
  hostname_length: 18,
  subdomain_count: 0,
  dot_count: 1,
  digit_count: 0,
  suspicious_char_count: 0,
  has_ip_address: 0,
  uses_http: 0,
  has_punycode: 0,
  suspicious_keyword_count: 0,
  hostname_entropy: 1.2,
  brand_domain_mismatch: 0,
  page_title_mismatch: 0,
  form_count: 1,
  has_password_input: 0,
  credential_field_count: 0,
  cross_domain_form_action: 0,
  hidden_field_count: 0,
  form_action_is_empty: 0,
  obfuscated_script_score: 0,
  hidden_iframe_count: 0,
  external_script_count: 0,
  meta_refresh_count: 0,
  brand_name_in_title: 0,
  brand_name_in_visible_text: 0,
  brand_name_in_url: 0,
  has_unusual_port: 0,
  domain_registration_age_days: 365
};

const phishing = {
  url_length: 180,
  hostname_length: 45,
  subdomain_count: 3,
  dot_count: 5,
  digit_count: 6,
  suspicious_char_count: 4,
  has_ip_address: 0,
  uses_http: 1,
  has_punycode: 1,
  suspicious_keyword_count: 3,
  hostname_entropy: 4.8,
  brand_domain_mismatch: 1,
  page_title_mismatch: 1,
  form_count: 2,
  has_password_input: 1,
  credential_field_count: 4,
  cross_domain_form_action: 1,
  hidden_field_count: 1,
  form_action_is_empty: 0,
  obfuscated_script_score: 0.8,
  hidden_iframe_count: 1,
  external_script_count: 2,
  meta_refresh_count: 1,
  brand_name_in_title: 1,
  brand_name_in_visible_text: 1,
  brand_name_in_url: 1,
  has_unusual_port: 1,
  domain_registration_age_days: 12
};

const score = scoreFeatures(phishing);

const benignWindow = loadDemo('https://www.contoso.com/login', require('path').join(process.cwd(), 'extension', 'demo', 'legitimate-demo.html'));
const benignUrlFeatures = benignWindow.PhishGuard.extractUrlFeatures();

assert.strictEqual(benignUrlFeatures.brand_domain_mismatch, 0, 'Generic words like "bank" should not trigger a brand mismatch on a legitimate page');
assert.strictEqual(benignUrlFeatures.page_title_mismatch, 0, 'Title and hostname should not be considered mismatched when the hostname is a normal www brand subdomain');
assert.strictEqual(benignWindow.PhishGuard.normalizeFeatureVector({ domain_registration_age_days: 365 }).domain_registration_age_days, 1, 'A one-year-old domain should not be treated as newly registered');

const spoofedWindow = loadDemo('https://paypal-security.example/login', require('path').join(process.cwd(), 'extension', 'demo', 'phishing-demo.html'));
assert.strictEqual(spoofedWindow.PhishGuard.extractUrlFeatures().brand_domain_mismatch, 1, 'A brand-like lookalike domain should be flagged');

const trustedWindow = loadDemo('https://login.paypal.com/account', require('path').join(process.cwd(), 'extension', 'demo', 'legitimate-demo.html'));
assert.strictEqual(trustedWindow.PhishGuard.extractUrlFeatures().brand_domain_mismatch, 0, 'A trusted brand subdomain should not be flagged');

const amazonBusinessWindow = loadDemo('https://business.amazon.com/', require('path').join(process.cwd(), 'extension', 'demo', 'legitimate-demo.html'));
const amazonBusinessFeatures = amazonBusinessWindow.PhishGuard.extractUrlFeatures();
assert.strictEqual(amazonBusinessFeatures.brand_domain_mismatch, 0, 'Amazon Business should be recognized as an official Amazon domain');
assert.strictEqual(amazonBusinessFeatures.is_official_brand_domain, 1, 'Official Amazon domains should be marked trusted');

assert.ok(score >= 65, `Expected a high phishing score, got ${score}`);
assert.strictEqual(getRiskLevel(score), 'likely_phishing');
assert.ok(scoreFeatures(legitimate) <= 34, `Expected legitimate page to stay low risk, got ${scoreFeatures(legitimate)}`);
console.log('Risk scoring validation passed.');
