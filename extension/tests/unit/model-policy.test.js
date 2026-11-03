const assert = require('node:assert/strict');
const policy = require('../../src/shared/model-policy.js');
const base = { has_password_input: 1, credential_field_count: 2, credential_context: 1 };
for (const extras of [{}, { suspicious_keyword_count: 8, url_length: 800 },
  { hidden_iframe_count: 10 }, { credential_submission_script: 1 },
  { frontpage_suspicious_signal_count: 6 }, { has_punycode: 1 },
  { hidden_iframe_count: 4, obfuscated_script_score: 1, has_ip_address: 1,
    has_punycode: 1, has_unusual_port: 1, subdomain_count: 4, suspicious_char_count: 5 }]) {
  const verdict = policy.scoreEvidence({ ...base, ...extras });
  assert.equal(verdict.outcome, 'SAFE', JSON.stringify(extras));
  assert.equal(verdict.warning, false);
}
assert.equal(policy.scoreEvidence({ brand_domain_mismatch: 1 }).outcome, 'SAFE');
const identity = policy.scoreEvidence({ ...base, brand_domain_mismatch: 1,
  brand_name_in_title: 1, brand_name_in_visible_text: 1, page_title_mismatch: 1 });
assert.equal(identity.score, 45, 'Repeated brand facts contribute once');
assert.deepEqual(identity.activeCategories, ['identity']);
assert.equal(identity.outcome, 'CAUTION');
assert.equal(policy.scoreEvidence({ ...base, cross_domain_form_action: 1 }).outcome, 'CAUTION');
const phishing = { ...base, brand_domain_mismatch: 1, cross_domain_form_action: 1 };
const verdict = policy.scoreEvidence(phishing);
assert.equal(verdict.score, 80);
assert.equal(verdict.outcome, 'HIGH_RISK');
assert.equal(verdict.warning, true);
assert.equal(verdict.reasons.length, 2);
assert.equal(verdict.evidence.length, 2);
assert.equal(policy.scoreEvidence(phishing, { warningThreshold: 90 }).outcome, 'CAUTION');
assert.equal(policy.scoreEvidence(phishing, { warningThreshold: 35 }).outcome, 'HIGH_RISK');
assert.equal(policy.scoreEvidence({ ...base, credential_transport_downgrade: 1,
  cross_domain_form_action: 1 }).outcome, 'HIGH_RISK');
assert.equal(policy.scoreEvidence({ ...base, uses_http: 1 }).outcome, 'CAUTION');
assert.equal(policy.scoreEvidence({ uses_http: 1 }).outcome, 'SAFE');
assert.equal(policy.scoreEvidence({ ...base, credential_form_method_get: 1 }).outcome, 'CAUTION');
assert.equal(policy.shouldApplyModel(phishing), false, 'Legacy models never change verdicts');
assert.equal(policy.hasHighConfidencePageEvidence({ ...base, hidden_iframe_count: 1 }), false);
assert.equal(policy.hasHighConfidencePageEvidence(phishing), true);
assert.equal(policy.isOrdinarySecureLoginPage(base), true);
assert.equal(policy.isOrdinarySecureLoginPage({ ...base, credential_target_ip: 1 }), false);
assert.equal(policy.validateWarningThreshold(Infinity), 65);
assert.equal(policy.validateWarningThreshold(-100), 35);
assert.equal(policy.validateWarningThreshold(1000), 90);
assert.equal(policy.scoreEvidence(null).outcome, 'SAFE');
assert.equal(policy.scoreEvidence({ ...base, has_password_input: 0,
  sensitive_credential_field_count: 1, credential_form_method_get: 1 }).outcome, 'CAUTION');
console.log('Independent evidence and canonical verdict policy validation passed.');
