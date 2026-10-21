var phishGuardGlobal = typeof window !== 'undefined' ? window : self;

phishGuardGlobal.PHISH_GUARD_CONSTANTS = {
  RISK_LEVELS: {
    legitimate: { label: 'Legitimate', min: 0, max: 34 },
    suspicious: { label: 'Suspicious', min: 35, max: 64 },
    likely_phishing: { label: 'Likely phishing', min: 65, max: 100 }
  },
  MODEL_WEIGHTS: {
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
  },
  SUSPICIOUS_KEYWORDS: [
    'login',
    'verify',
    'secure',
    'account',
    'update',
    'wallet',
    'bank',
    'signin',
    'payment',
    'confirm'
  ]
};
