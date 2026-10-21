(function (global) {
  function hasHighConfidencePageEvidence(features) {
    return Number(features.has_ip_address) === 1
      || Number(features.uses_http) === 1
      || Number(features.has_punycode) === 1
      || Number(features.has_unusual_port) === 1
      || Number(features.brand_domain_mismatch) === 1
      || Number(features.cross_domain_form_action) === 1
      || Number(features.hidden_iframe_count) >= 1
      || Number(features.obfuscated_script_score) >= 0.75
      || Number(features.credential_submission_script) === 1
      || Number(features.suspicious_hosting) === 1
      || Number(features.frontpage_suspicious_signal_count) >= 3;
  }

  function hasStrongModelEvidence(features) {
    if (hasHighConfidencePageEvidence(features)) return true;

    const urlSignals = [
      Number(features.suspicious_char_count) >= 2,
      Number(features.redirect_count) >= 2,
      Number(features.subdomain_count) >= 3,
      Number(features.hostname_entropy) >= 4
    ];
    return urlSignals.filter(Boolean).length >= 2;
  }

  function isOrdinarySecureLoginPage(features) {
    return Number(features.uses_http) !== 1
      && (
        Number(features.has_password_input) === 1
        || Number(features.credential_field_count) > 0
        || Number(features.form_count) > 0
      )
      && Number(features.cross_domain_form_action) !== 1
      && Number(features.brand_domain_mismatch) !== 1
      && !hasHighConfidencePageEvidence(features);
  }

  function shouldApplyModel(features) {
    return !isOrdinarySecureLoginPage(features)
      && hasStrongModelEvidence(features)
      && (
        Number(features.is_official_brand_domain) !== 1
        || hasHighConfidencePageEvidence(features)
      );
  }

  global.PhishGuard = global.PhishGuard || {};
  global.PhishGuard.hasHighConfidencePageEvidence = hasHighConfidencePageEvidence;
  global.PhishGuard.hasStrongModelEvidence = hasStrongModelEvidence;
  global.PhishGuard.isOrdinarySecureLoginPage = isOrdinarySecureLoginPage;
  global.PhishGuard.shouldApplyModel = shouldApplyModel;
})(typeof self !== 'undefined' ? self : globalThis);
