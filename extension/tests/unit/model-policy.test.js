const assert = require('assert');

global.self = global;
global.PhishGuard = {};
require('../../src/shared/model-policy.js');

const normalLoginPage = {
  suspicious_keyword_count: 2,
  subdomain_count: 1,
  hostname_entropy: 3.2,
  has_password_input: 1,
  cross_domain_form_action: 0,
  obfuscated_script_score: 0,
  hidden_iframe_count: 0,
  credential_submission_script: 0,
  has_ip_address: 0,
  has_punycode: 0,
  has_unusual_port: 0
};

assert.strictEqual(
  global.PhishGuard.hasStrongModelEvidence(normalLoginPage),
  false,
  'ordinary same-origin login pages must not activate the ML score'
);

assert.strictEqual(
  global.PhishGuard.hasStrongModelEvidence({
    ...normalLoginPage,
    brand_domain_mismatch: 1
  }),
  true,
  'brand impersonation must remain strong model evidence'
);

assert.strictEqual(
  global.PhishGuard.hasStrongModelEvidence({
    ...normalLoginPage,
    cross_domain_form_action: 1
  }),
  true,
  'cross-domain credential submission must remain strong model evidence'
);

assert.strictEqual(
  global.PhishGuard.isOrdinarySecureLoginPage(normalLoginPage),
  true,
  'secure same-origin login pages without strong evidence must be protected'
);

assert.strictEqual(
  global.PhishGuard.isOrdinarySecureLoginPage({
    ...normalLoginPage,
    uses_http: 1
  }),
  false,
  'HTTP login pages must not receive the legitimate-login safeguard'
);

assert.strictEqual(
  global.PhishGuard.shouldApplyModel(normalLoginPage),
  false,
  'URL-model probabilities must not override an ordinary secure login page'
);

assert.strictEqual(
  global.PhishGuard.shouldApplyModel({
    ...normalLoginPage,
    cross_domain_form_action: 1
  }),
  true,
  'strong cross-domain evidence may activate the model'
);

console.log('Model evidence policy validation passed.');
