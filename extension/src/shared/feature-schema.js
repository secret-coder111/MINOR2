const PHISH_GUARD_FEATURES = [
  {
    name: 'url_length',
    type: 'number',
    missing: 0,
    description: 'Length of the full URL including query string.'
  },
  {
    name: 'hostname_length',
    type: 'number',
    missing: 0,
    description: 'Length of the hostname without the scheme or path.'
  },
  {
    name: 'subdomain_count',
    type: 'number',
    missing: 0,
    description: 'Number of subdomains in the hostname.'
  },
  {
    name: 'dot_count',
    type: 'number',
    missing: 0,
    description: 'Number of dots in the canonical full URL, counted once.'
  },
  {
    name: 'digit_count',
    type: 'number',
    missing: 0,
    description: 'Number of ASCII digits in the canonical full URL, counted once.'
  },
  {
    name: 'suspicious_char_count',
    type: 'number',
    missing: 0,
    description: 'Number of suspicious separators and special characters such as @, %, repeated dashes or dots.'
  },
  {
    name: 'has_ip_address',
    type: 'number',
    missing: 0,
    description: 'Whether the canonical hostname is an IPv4 or IPv6 literal; no DNS lookup is performed.'
  },
  {
    name: 'uses_http',
    type: 'number',
    missing: 0,
    description: 'Whether the page uses HTTP instead of HTTPS.'
  },
  {
    name: 'has_punycode',
    type: 'number',
    missing: 0,
    description: 'Whether the hostname contains punycode or Unicode spoofing markers.'
  },
  {
    name: 'suspicious_keyword_count',
    type: 'number',
    missing: 0,
    description: 'Count of suspicious terms such as login, account, verify, update, secure, wallet, bank, and signin.'
  },
  {
    name: 'hostname_entropy',
    type: 'number',
    missing: 0,
    description: 'Approximate entropy score for the hostname.'
  },
  {
    name: 'brand_domain_mismatch',
    type: 'number',
    missing: 0,
    description: 'Whether a deliberate title or hostname brand claim mismatches recognized domain ownership; query mentions are excluded.'
  },
  {
    name: 'page_title_mismatch',
    type: 'number',
    missing: 0,
    description: 'Whether the title makes a recognized brand claim inconsistent with domain ownership.'
  },
  {
    name: 'form_count',
    type: 'number',
    missing: 0,
    description: 'Total number of forms in the document.'
  },
  {
    name: 'has_password_input',
    type: 'number',
    missing: 0,
    description: 'Whether a password field exists in the page.'
  },
  {
    name: 'credential_field_count',
    type: 'number',
    missing: 0,
    description: 'Number of credential-like form fields such as password, card, OTP, email, PAN, Aadhaar, or wallet phrase.'
  },
  {
    name: 'cross_domain_form_action',
    type: 'number',
    missing: 0,
    description: 'Whether an active credential-bearing form targets a different registrable site, including private suffix boundaries.'
  },
  {
    name: 'hidden_field_count',
    type: 'number',
    missing: 0,
    description: 'Count of hidden fields in forms.'
  },
  {
    name: 'form_action_is_empty',
    type: 'number',
    missing: 0,
    description: 'Whether the form action is empty or malformed.'
  },
  {
    name: 'obfuscated_script_score',
    type: 'number',
    missing: 0,
    description: 'Heuristic score based on eval, atob, obfuscation patterns, or encoded script content.'
  },
  {
    name: 'hidden_iframe_count',
    type: 'number',
    missing: 0,
    description: 'Number of hidden or offscreen iframes.'
  },
  {
    name: 'external_script_count',
    type: 'number',
    missing: 0,
    description: 'Number of external scripts from domains not matching the page host.'
  },
  {
    name: 'meta_refresh_count',
    type: 'number',
    missing: 0,
    description: 'Number of meta-refresh redirects or timed jumps.'
  },
  {
    name: 'brand_name_in_title',
    type: 'number',
    missing: 0,
    description: 'Whether a known brand appears in the title.'
  },
  {
    name: 'brand_name_in_visible_text',
    type: 'number',
    missing: 0,
    description: 'Whether a known brand appears in visible text on the page.'
  },
  {
    name: 'brand_name_in_url',
    type: 'number',
    missing: 0,
    description: 'Whether a known brand appears in the URL.'
  },
  {
    name: 'has_unusual_port',
    type: 'number',
    missing: 0,
    description: 'Whether the URL uses a non-standard port.'
  },
  {
    name: 'domain_registration_age_days',
    type: 'number',
    missing: 0,
    description: 'Optional domain age in days, if enabled by the user and a lookup returns a result.'
  },
  {
    name: 'credential_submission_script',
    type: 'number',
    missing: 0,
    description: 'Reserved for independently established credential submission behavior; static scans return 0 and do not infer theft from script words.'
  }
];

const FEATURE_SCHEMA_VERSION = '0.2.0';
const PHISH_GUARD_MODEL_VERSION = 'rules-0.4.0';
const PHISH_GUARD_DEFAULT_THRESHOLDS = {
  low: 34,
  medium: 64,
  high: 65
};

if (typeof globalThis !== 'undefined') {
  globalThis.PHISH_GUARD_FEATURES = PHISH_GUARD_FEATURES;
  globalThis.FEATURE_SCHEMA_VERSION = FEATURE_SCHEMA_VERSION;
  globalThis.PHISH_GUARD_MODEL_VERSION = PHISH_GUARD_MODEL_VERSION;
  globalThis.PHISH_GUARD_DEFAULT_THRESHOLDS = PHISH_GUARD_DEFAULT_THRESHOLDS;
}

if (typeof window !== 'undefined') {
  window.PHISH_GUARD_FEATURES = PHISH_GUARD_FEATURES;
  window.FEATURE_SCHEMA_VERSION = FEATURE_SCHEMA_VERSION;
  window.PHISH_GUARD_MODEL_VERSION = PHISH_GUARD_MODEL_VERSION;
  window.PHISH_GUARD_DEFAULT_THRESHOLDS = PHISH_GUARD_DEFAULT_THRESHOLDS;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    PHISH_GUARD_FEATURES,
    FEATURE_SCHEMA_VERSION,
    PHISH_GUARD_MODEL_VERSION,
    PHISH_GUARD_DEFAULT_THRESHOLDS
  };
}
