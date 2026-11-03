**PhishGuard audit — 24 October 2026**

> Historical baseline before implementation. See [the implemented changes and
> current verification](improvements-2026-10-24.md) and
> [updated fixture results](login-probe-results-after.json) for version 0.2.0.

The current extension can assign 100/100 to harmless login pages because ordinary page features are promoted into strong evidence and counted repeatedly. Its learned URL model has additional data and deployment problems. Increasing the warning threshold alone will leave these causes in place and can hide phishing pages.

This audit examined the current working tree, including the existing uncommitted changes. Application and training source files were left unchanged. The only additions are this report, an offline diagnostic script, and its results. The actual installed browser extension was not inspected, and no live login or phishing pages were visited.

**What was verified**

- `npm.cmd test`: all six existing JavaScript suites passed.
- `node docs/audit/diagnose-login.cjs`: twelve synthetic HTML fixtures went through the real URL/form/DOM extractors and background scoring code, using the actual exported model. Inline page scripts were inspected as text but never executed; network access was not enabled.
- Results are saved in [login-probe-results.json](login-probe-results.json). These are diagnostic cases, not a representative accuracy benchmark.
- The deployed tree artifact is `url-multidataset-hard-negatives-v0.6.0`, threshold 0.36, with 32 trees. The matching Python estimator has 250 trees.

| Offline synthetic fixture | Final score | Result |
|---|---:|---|
| Ordinary college password login | 12 | SAFE |
| Same login with ordinary input validation | 50 | CAUTION |
| Official Google-style plain login at `/` | 42 | CAUTION |
| Same Google-style HTML at `/login` | 20 | SAFE |
| College login titled “Pineapple Club” | 100 | HIGH_RISK |
| GitHub-style login with `paypal` only in its return query | 100 | HIGH_RISK |
| Microsoft-domain fixture titled “Microsoft - sign in using Google” | 100 | HIGH_RISK |
| Google-style root login, ordinary validation and an iframe | 93 | HIGH_RISK |
| Google-style root login, iframe and three hidden CSRF fields | 68 | HIGH_RISK; explanation incorrectly says normal login |
| External password destination mentioned in page text | 12 | SAFE; external destination missed |
| Password post from one `github.io` tenant to another | 12 | SAFE; external destination missed |
| Long encoded IP-host login with one active evidence category | 90 | Metadata CAUTION, popup high risk, warning disabled |

The first row means the current files do not assign 100 simply because a password exists. The later rows reproduce concrete ways ordinary login pages can reach 100. Confirm which unpacked folder/version the browser loaded when comparing these results with the reported symptom.

**1. Brand detection creates false impersonation, then counts it several times — highest priority**

In `extension/src/content/url-features.js:82`, the first brand substring found anywhere in the title or complete URL determines the purported brand. There are no word boundaries or distinction between a site's own identity and a mention of another service.

Consequences include `apple` matching `Pineapple`, `paypal` in a return URL becoming an impersonation claim, and Google winning the match before Microsoft on a Microsoft-domain page that mentions both providers.

In `extension/src/shared/model-policy.js:54`, the mismatch contributes 50 URL points. The same mismatch adds 35 brand points at line 86. Related title/text flags and the credential bonus can then saturate the result at 100. Requiring two active categories does not establish independent evidence when the same observation activates both categories.

Improve this by separating a deliberate identity claim from incidental mentions, matching whole names, checking the current hostname against the claimed identity, and handling multiple providers. Query parameters and “sign in with Google” text should not by themselves establish impersonation. Put each underlying observation in one evidence group so it cannot satisfy multiple independent-evidence requirements. Do not replace this with a blanket trusted-site list.

**2. Ordinary JavaScript is treated as evidence of credential theft — highest priority**

`extension/src/content/form-features.js:89` scans inline script text. If any credential-like input exists, the words `input`, `keydown`, `submit`, `fetch`, `XMLHttpRequest`, or `sendBeacon` can set `credential_submission_script=1`. Even comments or unrelated application logic can match.

The policy treats this flag as high-confidence evidence, adds 30 form points, and may add a credential-context bonus. The harmless validation fixture therefore becomes CAUTION at 50.

Keep this as weak static evidence, with an explanation that states what was actually observed. Ordinary validation and same-origin requests should not independently trigger caution. Stronger analysis must connect a particular credential form to a concerning destination or corroborated deceptive behavior. Continue avoiding typed values, cookies and passwords. Also document that this scanner does not inspect the bodies of external script bundles and cannot prove exfiltration.

**3. Normal root logins and visible iframes look suspicious — highest priority**

`extension/src/content/dom-features.js:30` converts absent iframe dimensions to zero. Thus a normal `<iframe src="/help"></iframe>` is counted as hidden. Missing size attributes mean default/unknown dimensions, not zero-size.

At line 72, the front-page counter independently counts a password form, a brand in its title, and short branded text beside the form. These are three correlated facts about an ordinary branded login. At `/` they switch off the ordinary-login safeguard and add 30 brand points; the same page at `/login` behaves differently.

Fix iframe measurement using explicit attributes, computed visibility and rendered bounds where available. Keep hidden-frame presence weak because authentication and anti-abuse systems can use hidden frames legitimately. Remove ordinary login/branding facts from the front-page suspicious-signal count; path `/` is not evidence of deception.

**4. Cross-domain form handling can miss phishing — highest priority**

`extension/src/content/form-features.js:21` extracts domain hints from page-controlled text. `isLikelyBrandedDomain` then uses them to suppress cross-domain detection at line 71. The external-post fixture becomes SAFE merely by mentioning the destination in its own text. A page cannot establish the trustworthiness of its destination this way.

The handwritten domain-suffix logic at line 30 also considers `victim.github.io` and `attacker.github.io` the same site. Shared hosting tenants need distinct boundaries. Country suffixes are incomplete too.

Remove page-text-based destination trust. Use a maintained local Public Suffix List implementation, including private suffixes, consistently in browser and Python. Assess the actual credential-bearing form and its resolved destination, including scheme and port. Cross-site submission can be legitimate SSO, so treat it as context requiring corroboration rather than an automatic phishing verdict. Page-controlled words must not override it.

Other extraction corrections: detect `type="email"` without relying on `name`; avoid `name="company"` matching the substring `pan`; keep unrelated search/newsletter forms separate from password-form destinations; handle `<base>` and submit-button destination overrides deliberately.

The [Public Suffix List](https://publicsuffix.org/learn/) explains why a short last-two-label algorithm cannot correctly identify all registration boundaries.

**5. Score, explanation and warning state disagree — high priority**

`extension/src/background/service-worker.js:184` calls `generateReasons(normalized)` even though that function expects raw counts and policy-only flags. Two suspicious keywords become 0.5, one hidden iframe becomes 0.333, and `frontpage_suspicious_signal_count` disappears because it is outside the numeric feature schema. The explanation function therefore makes a different evidence decision from the scorer.

The Google-style root/iframe/CSRF fixture gives 68 HIGH_RISK while explaining “Normal first-party login form; no phishing warning.” This is a confirmed contradiction.

The service worker and popup also derive a high-risk label from score alone, while the warning requires two active categories. The last diagnostic fixture produces score 90, metadata CAUTION and no banner, while the popup's score band says high risk.

Create one canonical verdict object containing score, outcome, evidence and reasons. Use raw typed features for evidence decisions, and normalization only where a model needs it. Generate reasons from the actual contributions used. Have popup and banner render the same outcome. A risk index of 100 must not be described as 100% certainty.

**6. The deployed ML model has not learned login-page DOM behavior — high priority**

The current local training CSVs contain URLs rather than captured login-page HTML. DOM feature means in v0.6 metadata are zero, and no deployed tree split uses DOM/form features. The browser's DOM evidence currently comes from rules, not learned DOM discrimination.

A fresh diagnostic on the 32 curated official login URLs found 23 above the exported model's 0.36 threshold. These are curated inputs used in the training pipeline, not a held-out test or final browser verdict, but they contradict the README claim that the small hard-negative list prevents login-shaped URL false positives.

The current integration at `service-worker.js:180` only lets model scores raise a page that rules already classify HIGH_RISK; `Math.max` cannot correct a false positive by lowering it. Conversely, a high learned probability cannot promote a rule-CAUTION page. `trained_model_applied` can be true even when the final-score branch ignores it. Distinguish model eligibility, evaluation and actual influence in diagnostics.

Improve the rule evidence first. For ML, collect representative legitimate login/SSO/banking/college/payment pages and controlled phishing snapshots, then train and validate a separate DOM model or a deliberately designed fusion model. Keep URL-only training separate when DOM is unobserved; missing DOM is not an observed harmless page.

**7. Training evaluation differs from the deployed predictor — high priority**

`ml/src/export_browser_model.py:63` takes only the first 32 trees by default, while retaining the full ensemble's threshold/version. Current Python v0.6 has 250 trees. On the 32 curated login URLs, truncation changed one threshold classification and changed probabilities by up to 0.077873. Serialized browser inference agrees with the first 32 sklearn trees to floating-point precision: the problem is evaluating a different predictor, not faulty tree serialization.

Evaluate the exact exported predictor. Either train a compact ensemble directly or treat a truncated ensemble as a new artifact requiring calibration and evaluation. Save its tree count, feature/extractor version, dataset manifest and file hash beside its metrics. The full v0.6 metadata test accuracy of 79.03% does not establish the accuracy of the deployed extension.

`ml/src/train_model.py:153` selects thresholds by validation F1. Choose a warning operating point using an explicit false-positive budget on a separate representative calibration set instead. A proposed initial target such as at most 1% FPR is an engineering goal, not an achieved result; measure phishing recall at the selected target and report uncertainty.

Stored older reports record 43.45% FPR for v0.4 and 82.63% for v0.5. These are existing report values, not fresh measurements of v0.6 plus current browser policy. The v0.5 data provenance also prevents calling its report an established untouched future test.

`ml/src/future_test_protocol.py` checks overlap between classes inside evaluation, but does not prove separation from training URLs, domains, sources or dates. README training commands reuse feeds later described as future-test inputs. Preserve training/calibration/test manifests and reject prohibited overlap; freeze the final test before training and evaluate it once. Report the full extension policy as well as individual model metrics. Keep mixed-label domains together in one partition where labels are valid; cross-class domain overlap is not automatically a labeling error.

**8. Problems in the active `ml/src/dom_dataset.py` pipeline — high priority before DOM training**

- `dom_dataset.py:57` groups only the original URL. Two snapshots starting on different domains but redirecting to the same final page pass its overlap check. Validate `final_url` and group connected original/final domains together to prevent related pages crossing splits.
- `train_model.py:109` combines the original URL with HTML captured after redirects. Use the URL of the captured document for its DOM/form features and retain original URL/redirect metadata separately.
- `train_model.py:115` shares the incomplete handwritten domain grouping. IP addresses such as `127.0.0.1` become the key `0.1`; private-hosting tenants and some country domains collapse together. Replace this with the same public-suffix contract as the extension, with explicit IP handling.
- `dom_dataset.py:35` deduplicates using the entire lowercased URL plus label. Paths and queries can be case-sensitive, and opposite labels are not resolved at this stage. Normalize only components whose semantics allow it and handle conflicting labels explicitly.
- Whitespace-only HTML passes its nonempty-HTML coverage check. Capture HTTP status, final URL, date and capture success; exclude failed captures and detect error/challenge pages. Add content/template hashes where appropriate to avoid near-duplicate leakage.
- `train_model.py:74` can resurrect a conflicted URL: good, bad, good leaves a retained good record. Once a URL is marked conflicted, keep it quarantined until resolved.
- Despite its description, `dom_dataset.py` currently validates records; its `write_split` helper is not called. Splitting happens later in the trainer and is not an enforced time/source-separated dataset release.

Browser and Python feature semantics also differ: brand ownership checks, digit counts, cross-domain decisions, external-script counts and credential-script patterns. The Python HTML parser mishandles boolean `hidden` attributes. Build shared golden URL+HTML fixtures and assert identical named features before retraining. Version the extractor contract when semantics change. Preserve source labels: malware/defacement currently become the same positive class as phishing, so results need to state that scope or use phishing-specific labels.

**9. Runtime and UI gaps — next priority**

- `content-script.js:86` observes only selected newly added elements. Action/type/src changes, removed forms and new meta refreshes can leave verdicts stale. A local observer probe confirmed these omissions. Watch relevant attributes/removals/text, debounce scans and exclude extension UI.
- `content-script.js:103` replaces history methods in the isolated extension world. It does not reliably intercept the website's own SPA navigation. Use browser navigation events or a minimal navigation-only bridge. Chrome documents [isolated content-script environments](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts).
- `service-worker.js:132` accepts delayed reputation responses without checking the current document/scan. An offline two-request probe confirmed that an old malicious response can overwrite the newer page's verdict and display risk 90 in the current tab. Carry URL/document/scan identity through the request, storage and display, and discard obsolete results. This race requires reputation enrichment to be enabled.
- `manifest.json` sets `all_frames:false`; credential forms inside frames are uninspected. Add deliberate frame-aware analysis and aggregation while retaining frame origin, rather than blindly summing all frame signals.
- The warning threshold and domain-age controls are saved in options but do not affect runtime. Implement them with validated behavior or remove the controls.
- Tab results and feedback persist complete URLs, potentially including login query strings/fragments. Prefer session storage for ephemeral results, clean up closed tabs, redact feedback URLs and describe retention. Typed field values are not collected by the inspected extractors.
- The popup reads storage once and can remain stale while open. Subscribe to matching-document result changes. Feedback records “wrong_result” without an expected verdict; collect an explicit correction if feedback will become evaluation data.

**Recommended implementation order and completion criteria**

1. Turn the twelve diagnostics into meaningful regression assertions and add a few real-browser integration tests for navigation, frames and delayed messages. Keep ordinary login and actual suspicious-destination fixtures on both sides of the boundary.
2. Fix brand matching, duplicate evidence, front-page counting, script evidence, iframe visibility and page-text destination trust. Correct raw-feature explanations and use one canonical verdict for every UI surface.
3. Fix scan identity and dynamic-page coverage. Validate the unpacked extension in Chromium, reloading it and refreshing existing tabs after changes.
4. Establish browser/Python feature parity, correct snapshot final-URL handling, fix conflict handling and freeze grouped source/time-separated dataset manifests.
5. Train/calibrate the exact compact deployed model using representative legitimate hard negatives and real labeled DOM where appropriate. Select a threshold under a stated FPR budget; evaluate the exported model plus final policy on untouched data.
6. Deliver a report with confusion matrix, legitimate-login FPR, phishing recall, per-source/per-page-type breakdowns, uncertainty, runtime cost and artifact identity. Report what was actually measured; do not promise an accuracy gain before this evaluation.

Run the diagnostic again after fixes with:

```powershell
node docs/audit/diagnose-login.cjs
npm.cmd test
```

The diagnostic script prints observations rather than enforcing desired outcomes. It is a starting point for regression coverage and does not certify a page or the detector as safe.
