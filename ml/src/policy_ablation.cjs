// Development-only evidence ablations. Never used by the browser verdict path.
const variants = Object.freeze(['url_only', 'without_identity', 'without_destination',
  'without_transport', 'without_address', 'without_page_patterns']);
const disabled = {
  without_identity: ['brand_domain_mismatch', 'credential_brand_identity_claim'],
  without_destination: ['cross_domain_form_action', 'credential_target_ip', 'invalid_credential_action'],
  without_transport: ['uses_http', 'credential_transport_downgrade', 'credential_insecure_transport',
    'credential_form_method_get', 'credential_form_explicit_get', 'credential_form_native_get'],
  without_address: ['has_ip_address', 'has_punycode', 'has_unusual_port', 'suspicious_char_count',
    'credential_brand_address_match'],
  without_page_patterns: ['hidden_iframe_count', 'obfuscated_script_score', 'meta_refresh_count']
};
const urlKeys = ['url_length', 'hostname_length', 'subdomain_count', 'dot_count', 'digit_count',
  'suspicious_char_count', 'has_ip_address', 'uses_http', 'has_punycode',
  'suspicious_keyword_count', 'hostname_entropy', 'brand_name_in_url', 'has_unusual_port'];
function project(features, variant) {
  if (!variants.includes(variant)) throw new Error('Unknown policy ablation');
  if (variant === 'url_only') return Object.fromEntries(urlKeys.map(key => [key, features[key] || 0]));
  const remove = value => ({ ...value, ...Object.fromEntries(disabled[variant].map(key => [key, 0])) });
  const result = remove(features);
  if (Array.isArray(features.credential_contexts)) result.credential_contexts = features.credential_contexts.map(remove);
  return result;
}
module.exports = { variants, project };
