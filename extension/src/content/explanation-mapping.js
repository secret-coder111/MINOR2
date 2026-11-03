var phishGuardGlobal = typeof window !== 'undefined' ? window : self;
phishGuardGlobal.PhishGuard = phishGuardGlobal.PhishGuard || {};
// Retained for research tools. Product explanations come from the exact scored
// evidence in shared/model-policy.js, so labels cannot diverge from the verdict.
phishGuardGlobal.PhishGuard.explanationMap = {
  cross_domain_form_action: 'A credential form targets another site; verify the destination.',
  has_password_input: 'A password field is present; this is ordinary login context.',
  uses_http: 'The document uses unencrypted HTTP.',
  has_punycode: 'The hostname is internationalized; this alone is not evidence of phishing.',
  brand_domain_mismatch: 'A deliberate brand claim differs from recognized domain ownership.',
  suspicious_keyword_count: 'The URL contains sign-in or account-related words.',
  obfuscated_script_score: 'Static script patterns were observed that also occur in legitimate software.',
  meta_refresh_count: 'An HTML refresh redirect is present.',
  hidden_iframe_count: 'An explicitly hidden or zero-sized iframe is present.',
  page_title_mismatch: 'The title makes a brand claim inconsistent with recognized domain ownership.',
  credential_submission_script: 'Static scanning does not establish credential theft.'
};
