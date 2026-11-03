# Feature dictionary

Numeric schema version: **0.2.0** (29 names/order unchanged); policy version:
**0.5.0**. Exact extractor hashes change with semantics, including the document
context helper; older captures/models cannot silently qualify for this policy.

The 29 numeric names and order below are the browser research contract. Missing
numeric values use 0 only within an observed feature record. URL-only model
training uses an explicit URL subset; missing HTML must not become observed zero DOM.

| Position | Feature | Definition |
|---:|---|---|
| 0 | `url_length` | Length of the full URL including query string. |
| 1 | `hostname_length` | Length of the hostname without the scheme or path. |
| 2 | `subdomain_count` | Number of subdomains in the hostname. |
| 3 | `dot_count` | Number of dots in the canonical full URL, counted once. |
| 4 | `digit_count` | Number of ASCII digits in the canonical full URL, counted once. |
| 5 | `suspicious_char_count` | Number of suspicious separators and special characters such as @, %, repeated dashes or dots. |
| 6 | `has_ip_address` | Whether the canonical hostname is an IPv4 or IPv6 literal; no DNS lookup is performed. |
| 7 | `uses_http` | Whether the page uses HTTP instead of HTTPS. |
| 8 | `has_punycode` | Whether the hostname contains punycode or Unicode spoofing markers. |
| 9 | `suspicious_keyword_count` | Count of suspicious terms such as login, account, verify, update, secure, wallet, bank, and signin. |
| 10 | `hostname_entropy` | Approximate entropy score for the hostname. |
| 11 | `brand_domain_mismatch` | Whether a deliberate title or hostname brand claim mismatches recognized domain ownership; query mentions are excluded. |
| 12 | `page_title_mismatch` | Whether the title makes a recognized brand claim inconsistent with domain ownership. |
| 13 | `form_count` | Total number of forms in the document. |
| 14 | `has_password_input` | Whether an active visible password-like field is identified by type, name, autocomplete, accessible label or placeholder. |
| 15 | `credential_field_count` | Number of active visible credential-like fields, identified from metadata without reading values. Includes password, card, OTP, email, PAN, Aadhaar and recovery phrase prompts. |
| 16 | `cross_domain_form_action` | Whether an active credential-bearing form targets a different registrable site, including private suffix boundaries. |
| 17 | `hidden_field_count` | Count of hidden fields in forms. |
| 18 | `form_action_is_empty` | Whether the form action is empty or malformed. |
| 19 | `obfuscated_script_score` | Heuristic score based on eval, atob, obfuscation patterns, or encoded script content. |
| 20 | `hidden_iframe_count` | Number of hidden or offscreen iframes. |
| 21 | `external_script_count` | Number of external scripts from domains not matching the page host. |
| 22 | `meta_refresh_count` | Number of meta-refresh redirects or timed jumps. |
| 23 | `brand_name_in_title` | Whether a known brand appears in the title. |
| 24 | `brand_name_in_visible_text` | Whether a known brand appears in visible text on the page. |
| 25 | `brand_name_in_url` | Whether a known brand appears in the URL. |
| 26 | `has_unusual_port` | Whether the URL uses a non-standard port. |
| 27 | `domain_registration_age_days` | Reserved compatibility slot; current extraction returns 0. Domain-age lookup is not implemented. |
| 28 | `credential_submission_script` | Reserved for independently established credential submission behavior; static scans return 0 and do not infer theft from script words. |

**Policy-only context**

Form extraction also returns `credential_contexts`: one metadata-only object per
credential submission target, including submit-button overrides and orphan fields.
Each contains field counts and explicit destination/transport flags. Contexts
never contain typed values or full destination URLs. Each is scored separately;
flags from unrelated targets must not corroborate one another.

Relevant flags include `credential_context`, `sensitive_credential_field_count`,
`credential_transport_downgrade`, `credential_insecure_transport`,
`credential_target_ip`, `credential_form_method_get`, `credential_form_explicit_get`,
`credential_script_action`, `credential_form_native_get`,
`credential_destination_unknown` and `invalid_credential_action`. Sensitive GET
contributes transport evidence when explicitly declared, or when a cross-site
named sensitive control has a detectable native submission path without static
indications of interception. This fallback is deliberately conservative; scripts
may alter actual behavior. JavaScript actions do not establish a network destination
or credential theft. Inherited documents with empty actions retain credential
context but mark the actual destination unknown.
Dialog-method forms retain credential context but do not add a network destination.
Dynamic label text, placeholder and ARIA naming edits trigger rescanning.
`credential_form_cross_origin` and `credential_target_unusual_port` are diagnostic.

`body_brand_identity_claim` and `body_brand_domain_mismatch` describe a narrowly
scoped, visible primary authentication heading near credential UI. Incidental
paragraph/provider/article mentions do not become identity claims. Each brand is
matched independently; ownership of a hosting platform cannot cancel a different
claimed identity. No recognized owner bypasses destination/transport checks.

Policy 0.4.0 adds `brand_address_deception` as a diagnostic flag and per-submission
`credential_brand_identity_claim` / `credential_brand_address_match`. The former
records finite reviewed visual hostname substitutions or embedded official-domain
labels. The latter require a short rendered primary brand heading attached to
that same sensitive form and a matching deceptive address. A top-level aggregate
cannot leak these flags into a different submission context. Only this combined
context can supply strong address evidence; generic punycode and hostname
similarity do not. The numeric research vector remains 29 fields at schema 0.2.0.
Extractor and policy hashes bind captures/artifacts to the changed semantics.
Python helpers mirror address/identity matching for already-bound contexts;
static HTML rows do not infer live context flags or replace browser captures.

Visible custom editable textboxes and card/security-code/expiry metadata are
recognized without reading editable contents. Rendering checks account for
collapsed details, closed dialogs, content-visibility, hosts and slots. Related
HTTP(S)-origin documents use a validated inherited origin; an HTML base URL never
establishes ownership. Opaque documents remain incomplete coverage.

The legacy flat numeric features remain aggregate research observations; they
do not replace structured submission contexts in browser policy decisions.

`credential_submission_script` is 0 in static extraction. Mere script tokens
cannot establish credential theft. `credential_script_activity` is diagnostic
and does not increase risk. Front-page counts exclude ordinary login branding.

**Parity and versioning**

Use the shared offline PSL rules (including PRIVATE, wildcard and exception rules).
The URL canonicalization bridge uses Node WHATWG URL, matching browser parsing.
Static HTML extraction cannot reproduce arbitrary CSS/layout or live JavaScript;
DOM training requires captured browser feature rows and a matching extractor hash.

Run `npm.cmd test` and Python feature-golden tests after changing semantics.
Update feature/extractor versions, documentation, artifacts and calibration together.
Product reasons are generated from canonical scored evidence in `model-policy.js`.
See `docs/architecture.md` for policy group weights and limits.

## Policy observation added in 0.5.0

`credential_form_get_exposes_sensitive` is a per-submission structural flag. It
is one only when a GET flow contains a rendered sensitive input or textarea with
a nonempty submission name. Native form submission omits unnamed controls. The
policy does not infer a credential value in a query merely from an unnamed
password field. Other identity, destination and transport indicators still apply.
This is a policy extra, not a change to the historical 29-column research vector.
New captures retain it; extractor/policy hashes reject stale captures as before.
