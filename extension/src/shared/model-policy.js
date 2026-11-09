(function (global) {
  'use strict';
  const POLICY_VERSION = '0.6.0';
  const flag = (features, key) => Number(features[key]) === 1;
  const count = (features, key) => {
    const value = Number(features[key]);
    return Number.isFinite(value) ? Math.max(0, value) : 0;
  };
  function validateWarningThreshold(value) {
    const number = Number(value);
    return Number.isFinite(number) ? Math.max(35, Math.min(90, Math.round(number))) : 65;
  }
  function scoreSingleContext(input, options = {}) {
    const features = input && typeof input === 'object' ? input : {};
    const hasCredentialContext = Object.prototype.hasOwnProperty.call(features, 'credential_context')
      ? flag(features, 'credential_context')
      : flag(features, 'has_password_input') || count(features, 'credential_field_count') > 0;
    const sensitive = flag(features, 'has_password_input')
      || count(features, 'sensitive_credential_field_count') > 0;
    const crossSite = hasCredentialContext && flag(features, 'cross_domain_form_action');
    const mismatch = flag(features, 'brand_domain_mismatch');
    const downgrade = hasCredentialContext && flag(features, 'credential_transport_downgrade');
    const insecure = hasCredentialContext && (flag(features, 'credential_insecure_transport')
      || (sensitive && flag(features, 'uses_http')));
    const invalidDestination = hasCredentialContext && flag(features, 'invalid_credential_action');
    const declaredGet = Object.prototype.hasOwnProperty.call(features, 'credential_form_explicit_get')
      ? flag(features, 'credential_form_explicit_get') : flag(features, 'credential_form_method_get');
    const getExposesSensitive = !Object.prototype.hasOwnProperty.call(features, 'credential_form_get_exposes_sensitive')
      || flag(features, 'credential_form_get_exposes_sensitive');
    const queryCredentials = hasCredentialContext && sensitive && getExposesSensitive && (declaredGet || flag(features, 'credential_form_native_get'))
      && !flag(features, 'credential_script_action');
    const warningThreshold = validateWarningThreshold(options.warningThreshold === undefined ? 65 : options.warningThreshold);
    const evidence = [];
    const categories = { identity: 0, destination: 0, transport: 0, address: 0, page: 0 };
    function add(key, category, points, reason) {
      categories[category] = Math.max(categories[category], points);
      evidence.push({ key, category, points, reason });
    }
    // Repeated brand/title/text flags belong to one evidence group.
    if (mismatch) add('brand_domain_mismatch', 'identity', hasCredentialContext ? 45 : 20,
      hasCredentialContext
        ? 'This page asks for credentials while claiming a brand whose recognized domain does not match.'
        : 'A claimed brand does not match its recognized domain; a brand mention alone is inconclusive.');
    if (crossSite) add('cross_domain_form_action', 'destination', 35,
      'A credential form sends information to another site. Verify the destination; some sign-in providers use this legitimately.');
    if (hasCredentialContext && flag(features, 'credential_target_ip')) add('credential_target_ip', 'destination', 45,
      'A credential form targets an IP address rather than an identified website.');
    if (invalidDestination) add('invalid_credential_action', 'destination', 35,
      'A credential form has an invalid or non-web submission destination.');
    if (downgrade) add('credential_transport_downgrade', 'transport', 45,
      'This HTTPS page sends credentials to an unencrypted HTTP destination.');
    else if (insecure) add('credential_insecure_transport', 'transport', 35,
      'The page or credential submission uses unencrypted HTTP, which can expose sign-in information.');
    if (queryCredentials) add('credential_form_method_get', 'transport', 35,
      'A sensitive form has a native GET submission path, which can put credentials into a URL if submitted.');

    const contextualAddressDeception = hasCredentialContext && sensitive && mismatch
      && flag(features, 'credential_brand_identity_claim') && flag(features, 'credential_brand_address_match');
    if (contextualAddressDeception) add('credential_brand_address_match', 'address', 35,
      'This credential form claims a brand whose address uses a reviewed visual lookalike or embeds its official domain inside an unrelated site.');

    // URL shape and static DOM clues stay weak, including on a login page.
    const addressPoints = Math.min(18,
      (flag(features, 'has_ip_address') ? 8 : 0)
      + (flag(features, 'has_punycode') ? 4 : 0)
      + (flag(features, 'has_unusual_port') ? 2 : 0)
      + (count(features, 'suspicious_char_count') >= 2 && count(features, 'subdomain_count') >= 3 ? 4 : 0));
    if (addressPoints) add('unusual_address', 'address', addressPoints,
      'The address has unusual structural characteristics; this alone does not establish phishing.');
    const pagePoints = Math.min(8,
      (count(features, 'hidden_iframe_count') > 0 ? 2 : 0)
      + (count(features, 'obfuscated_script_score') >= 0.75 ? 4 : 0)
      + (count(features, 'meta_refresh_count') > 0 ? 2 : 0));
    if (pagePoints) add('static_page_patterns', 'page', pagePoints,
      'Static page patterns were observed that also occur on legitimate websites.');

    const activeCategories = ['identity', 'destination', 'transport', 'address']
      .filter((key) => categories[key] >= 25);
    const corroborated = hasCredentialContext && activeCategories.length >= 2;
    const rawScore = Math.min(100, Object.values(categories).reduce((sum, value) => sum + value, 0));
    const score = Math.round(corroborated ? rawScore : Math.min(64, rawScore));
    const outcome = corroborated && score >= warningThreshold
      ? 'HIGH_RISK' : score >= 35 ? 'CAUTION' : 'SAFE';
    const normalFirstPartyLogin = hasCredentialContext && !crossSite && !mismatch
      && !downgrade && !insecure && !invalidDestination && !queryCredentials
      && !flag(features, 'credential_target_ip');
    const reasons = evidence.filter((item, index) =>
      item.points === categories[item.category]
      && evidence.findIndex((other) => other.category === item.category && other.points === item.points) === index)
      .sort((a, b) => b.points - a.points).map((item) => item.reason).slice(0, 5);
    if (!reasons.length) reasons.push('No strong phishing indicators found. The website\'s identity has not been independently verified.');
    return { score, outcome, warning: outcome === 'HIGH_RISK', categories,
      activeCategories, hasCredentialContext, normalFirstPartyLogin, evidence,
      reasons, warningThreshold, policyVersion: POLICY_VERSION };
  }
  function scoreEvidence(input, options = {}) {
    const features = input && typeof input === 'object' ? input : {};
    const settings = options && typeof options === 'object' ? options : {};
    if (!Array.isArray(features.credential_contexts)) return scoreSingleContext(features, settings);
    // Destination and transport clues must refer to the same submission flow.
    // Never combine an email SSO form's destination with a different form's GET.
    const empty = { credential_context: 0, has_password_input: 0,
      credential_field_count: 0, sensitive_credential_field_count: 0,
      cross_domain_form_action: 0, credential_target_ip: 0,
      credential_transport_downgrade: 0, credential_insecure_transport: 0,
      credential_form_method_get: 0, credential_form_explicit_get: 0,
      credential_form_native_get: 0,
      credential_brand_identity_claim: 0, credential_brand_address_match: 0,
      credential_script_action: 0, invalid_credential_action: 0 };
    const contexts = features.credential_contexts.length ? features.credential_contexts : [empty];
    const severity = { SAFE: 0, CAUTION: 1, HIGH_RISK: 2 };
    let selected;
    contexts.forEach((context, index) => {
      const scoped = { ...features, ...empty, ...context, credential_contexts: undefined };
      // A flat aggregate must never override a particular flow's GET exposure.
      // Older inputs without this observation keep the conservative fallback.
      if (!Object.prototype.hasOwnProperty.call(context, 'credential_form_get_exposes_sensitive')) delete scoped.credential_form_get_exposes_sensitive;
      const result = scoreSingleContext(scoped, settings);
      result.credentialContextIndex = index;
      if (!selected || severity[result.outcome] > severity[selected.outcome]
        || (result.outcome === selected.outcome && result.score > selected.score)) selected = result;
    });
    selected.credentialContextsChecked = features.credential_contexts.length;
    return selected;
  }
  function hasHighConfidencePageEvidence(features) {
    const evidence = scoreEvidence(features);
    return evidence.activeCategories.length >= 2 && evidence.hasCredentialContext;
  }
  function hasStrongModelEvidence(features) { return hasHighConfidencePageEvidence(features); }
  function isOrdinarySecureLoginPage(features) { return scoreEvidence(features).normalFirstPartyLogin; }
  // Legacy learned artifacts are incompatible with the changed extraction contract.
  function shouldApplyModel() { return false; }
  const api = { scoreEvidence, hasHighConfidencePageEvidence, hasStrongModelEvidence,
    isOrdinarySecureLoginPage, shouldApplyModel, validateWarningThreshold, POLICY_VERSION };
  global.PhishGuard = global.PhishGuard || {};
  Object.assign(global.PhishGuard, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis);
