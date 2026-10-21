var phishGuardGlobal = typeof window !== 'undefined' ? window : self;

phishGuardGlobal.PhishGuard = phishGuardGlobal.PhishGuard || {};

phishGuardGlobal.PhishGuard.explanationMap = {
  cross_domain_form_action: 'The form sends data to a different domain than the page you are viewing.',
  has_password_input: 'This page requests a password or login credential.',
  uses_http: 'This page is using HTTP instead of HTTPS.',
  has_punycode: 'This address contains a lookalike or punycode-style hostname.',
  brand_domain_mismatch: 'The page claims to be a trusted brand, but the website address does not match the brand domain.',
  suspicious_keyword_count: 'The address contains multiple suspicious security-related terms such as login or verify.',
  obfuscated_script_score: 'The page contains script patterns that look obfuscated or disguised.',
  meta_refresh_count: 'This page uses timed redirects or refresh behavior that is common in phishing flows.',
  hidden_iframe_count: 'The page contains hidden iframe elements that may be used to obscure a malicious flow.',
  page_title_mismatch: 'The page title is inconsistent with the hostname or brand being claimed.',
  frontpage_suspicious_signal_count: 'The site front page combines several suspicious page-level signals.',
  credential_submission_script: 'Credential-like fields coexist with scripts that may observe or submit input events.'
};
