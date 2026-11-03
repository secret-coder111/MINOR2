(function (global) {
  'use strict';
  const moduleSchema = typeof require === 'function' ? require('./feature-schema.js').PHISH_GUARD_FEATURES : [];
  function policy() {
    const api = global.PhishGuard || {};
    if (api.scoreEvidence) return api;
    if (typeof require === 'function') return require('./model-policy.js');
    throw new Error('The canonical evidence policy must be loaded before scoring');
  }
  function normalizeFeatureVector(featureSet = {}) {
    const ranges = { url_length: 200, hostname_length: 75, subdomain_count: 4,
      dot_count: 6, digit_count: 10, suspicious_char_count: 5, suspicious_keyword_count: 4,
      hostname_entropy: 5, form_count: 4, credential_field_count: 5, hidden_field_count: 3,
      hidden_iframe_count: 3, external_script_count: 3, meta_refresh_count: 3,
      domain_registration_age_days: 365 };
    return Object.fromEntries((global.PHISH_GUARD_FEATURES || moduleSchema).map((feature) => {
      const value = Number(featureSet && featureSet[feature.name]);
      return [feature.name, Number.isFinite(value) ? Math.max(0, Math.min(1, value / (ranges[feature.name] || 1))) : 0];
    }));
  }
  // Retained API for old callers; all decisions use the same policy now.
  function scoreFeatures(featureSet, options) { return policy().scoreEvidence(featureSet, options).score; }
  function getRiskLevel(score, options = {}) {
    const threshold = policy().validateWarningThreshold(options.warningThreshold === undefined ? 65 : options.warningThreshold);
    return score >= threshold ? 'likely_phishing' : score >= 35 ? 'suspicious' : 'legitimate';
  }
  const api = { normalizeFeatureVector, scoreFeatures, getRiskLevel };
  global.PhishGuard = global.PhishGuard || {};
  Object.assign(global.PhishGuard, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
