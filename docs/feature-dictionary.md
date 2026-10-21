# Feature dictionary

This file defines the exact browser and training feature names for PhishGuard.

## Feature schema

The browser extension and the Python training pipeline must agree on the names, types, missing value handling, and explanation text.

- `url_length`: number, missing = 0
- `hostname_length`: number, missing = 0
- `subdomain_count`: number, missing = 0
- `dot_count`: number, missing = 0
- `digit_count`: number, missing = 0
- `suspicious_char_count`: number, missing = 0
- `has_ip_address`: number, missing = 0
- `uses_http`: number, missing = 0
- `has_punycode`: number, missing = 0
- `suspicious_keyword_count`: number, missing = 0
- `hostname_entropy`: number, missing = 0
- `brand_domain_mismatch`: number, missing = 0
- `page_title_mismatch`: number, missing = 0
- `form_count`: number, missing = 0
- `has_password_input`: number, missing = 0
- `credential_field_count`: number, missing = 0
- `cross_domain_form_action`: number, missing = 0
- `hidden_field_count`: number, missing = 0
- `form_action_is_empty`: number, missing = 0
- `obfuscated_script_score`: number, missing = 0
- `hidden_iframe_count`: number, missing = 0
- `external_script_count`: number, missing = 0
- `meta_refresh_count`: number, missing = 0
- `brand_name_in_title`: number, missing = 0
- `brand_name_in_visible_text`: number, missing = 0
- `brand_name_in_url`: number, missing = 0
- `has_unusual_port`: number, missing = 0
- `domain_registration_age_days`: number, missing = 0
- `credential_submission_script`: number, missing = 0; credential-like inputs coexist with script patterns that may observe or submit input events

## Explanation mapping

The following explanation labels map to the strongest signals for the popup and warning banner:

- `cross_domain_form_action` → "The form sends data to a different domain than the page you are viewing."
- `has_password_input` → "This page requests a password or login credential."
- `uses_http` → "This page is using HTTP instead of HTTPS."
- `has_punycode` → "This address contains a lookalike or punycode-style hostname."
- `brand_domain_mismatch` → "The page claims to be a trusted brand, but the website address does not match the brand domain."
- `suspicious_keyword_count` → "The address contains multiple suspicious security-related terms such as login or verify."
- `obfuscated_script_score` → "The page contains script patterns that look obfuscated or disguised."
- `meta_refresh_count` → "This page uses timed redirects or refresh behavior that is common in phishing flows."
- `hidden_iframe_count` → "The page contains hidden iframe elements that may be used to obscure a malicious flow."
- `page_title_mismatch` → "The page title is inconsistent with the hostname or brand being claimed."
- `credential_submission_script` → "Credential-like fields coexist with scripts that may observe or submit input events."
