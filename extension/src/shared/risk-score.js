(function (global) {
  const featureSchemaFromModule = (() => {
    try {
      if (typeof require === 'function') {
        const mod = require('./feature-schema.js');
        return mod.PHISH_GUARD_FEATURES || [];
      }
    } catch (error) {
      return [];
    }
    return [];
  })();

  const DEFAULT_WEIGHTS = {
    url_length: 0.12,
    hostname_length: 0.18,
    subdomain_count: 0.1,
    dot_count: 0.08,
    digit_count: 0.08,
    suspicious_char_count: 0.15,
    has_ip_address: 0.14,
    uses_http: 0.23,
    has_punycode: 0.22,
    suspicious_keyword_count: 0.16,
    hostname_entropy: 0.12,
    brand_domain_mismatch: 0.2,
    page_title_mismatch: 0.14,
    form_count: 0.03,
    has_password_input: 0.18,
    credential_field_count: 0.13,
    cross_domain_form_action: 0.25,
    hidden_field_count: 0.06,
    form_action_is_empty: 0.15,
    obfuscated_script_score: 0.22,
    hidden_iframe_count: 0.12,
    external_script_count: 0.09,
    meta_refresh_count: 0.08,
    brand_name_in_title: 0.1,
    brand_name_in_visible_text: 0.12,
    brand_name_in_url: 0.11,
    has_unusual_port: 0.1,
    domain_registration_age_days: 0.08,
    credential_submission_script: 0.2
  };

  function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
  }

  function normalizeSingleValue(key, rawValue) {
    const value = Number(rawValue) || 0;

    const ranges = {
      url_length: 200,
      hostname_length: 75,
      subdomain_count: 4,
      dot_count: 6,
      digit_count: 10,
      suspicious_char_count: 5,
      suspicious_keyword_count: 4,
      hostname_entropy: 5,
      form_count: 4,
      credential_field_count: 5,
      hidden_field_count: 3,
      hidden_iframe_count: 3,
      external_script_count: 3,
      meta_refresh_count: 3,
      domain_registration_age_days: 365
    };

    if (Object.prototype.hasOwnProperty.call(ranges, key)) {
      return clamp(value / ranges[key], 0, 1);
    }

    if (['has_ip_address', 'uses_http', 'has_punycode', 'brand_domain_mismatch', 'page_title_mismatch', 'has_password_input', 'cross_domain_form_action', 'form_action_is_empty', 'brand_name_in_title', 'brand_name_in_visible_text', 'brand_name_in_url', 'has_unusual_port', 'credential_submission_script'].includes(key)) {
      return clamp(value, 0, 1);
    }

    if (key === 'obfuscated_script_score') {
      return clamp(value, 0, 1);
    }

    return 0;
  }

  function normalizeFeatureVector(featureSet) {
    const featureSchema = global.PHISH_GUARD_FEATURES || featureSchemaFromModule || [];
    const normalized = {};

    featureSchema.forEach((feature) => {
      const rawValue = featureSet && Object.prototype.hasOwnProperty.call(featureSet, feature.name)
        ? featureSet[feature.name]
        : feature.missing;
      normalized[feature.name] = normalizeSingleValue(feature.name, rawValue);
    });

    return normalized;
  }

  function scoreFeatures(featureSet) {
    const featureSchema = global.PHISH_GUARD_FEATURES || featureSchemaFromModule || [];
    const weights = (global.PHISH_GUARD_CONSTANTS && global.PHISH_GUARD_CONSTANTS.MODEL_WEIGHTS) || DEFAULT_WEIGHTS;
    const normalized = normalizeFeatureVector(featureSet);

    let rawScore = 0;
    let totalWeight = 0;
    featureSchema.forEach((feature) => {
      const key = feature.name;
      const weight = weights[key] || 0;
      totalWeight += weight;
      rawScore += weight * Number(normalized[key] || 0);
    });

    if (totalWeight === 0) return 0;

    const score = (rawScore / totalWeight) * 100;
    return Math.min(100, Math.max(0, Math.round(score)));
  }

  function getRiskLevel(score) {
    if (score <= 34) return 'legitimate';
    if (score <= 64) return 'suspicious';
    return 'likely_phishing';
  }

  global.PhishGuard = global.PhishGuard || {};
  global.PhishGuard.normalizeFeatureVector = normalizeFeatureVector;
  global.PhishGuard.scoreFeatures = scoreFeatures;
  global.PhishGuard.getRiskLevel = getRiskLevel;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { normalizeFeatureVector, scoreFeatures, getRiskLevel };
  }
})(typeof window !== 'undefined' ? window : globalThis);
