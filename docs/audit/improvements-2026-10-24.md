# PhishGuard improvements - 24 October 2026

Implemented version **0.2.0** in the existing working tree. Existing user model
artifacts and historical reports were retained. No commit, push or publication
was performed.

**Scoring and extraction**

- Replaced substring/query brand matching with deliberate title/hostname claims,
  whole names, recognized ownership and provider-phrase handling.
- Removed repeated scoring of one brand fact and high-confidence treatment of
  ordinary password fields, validation code, login words and homepage branding.
- Each credential submission is now a separate context, including external
  form associations, base URLs and submitter overrides. Unrelated forms and
  alternative targets cannot manufacture corroboration.
- Corrected visible/hidden iframes, disabled/hidden credential fields, field-name
  boundaries, email/autocomplete metadata and textarea recovery phrases.
- Removed page-controlled destination trust. Browser and Python share 10,334
  pinned offline PSL rules, including private hosting, wildcards and exceptions.
- Added contextual destination/IP/downgrade/HTTP/explicit-password-GET checks. Default
  GET on an Ajax form and JavaScript-only actions do not independently warn. Cross-site
  submission alone produces Caution rather than an automatic phishing claim.
- One verdict supplies score, outcome, warning and exact contributing reasons.

**Runtime, UI and privacy**

- Document/frame identity and scan sequencing reject old results and reputation
  responses. Normal HTTP(S) frames are evaluated independently, without summing
  their scores; removed-frame evidence is pruned.
- Browser navigation events handle SPA routes. Relevant attributes, added/removed
  nodes and text trigger bounded, debounced rescans without banner feedback loops.
- The popup updates live and displays the canonical outcome. The threshold
  control works; the unimplemented domain-age control was removed.
- Tab results use session storage without URL paths/queries/fragments and are
  removed on tab close. Legacy persistent tab records are migrated away.
- Corrections require an expected verdict and retain the origin only. Optional
  reputation remains disabled by default, omits credentials, rejects redirects,
  times out and rejects obsolete responses.
- Demo pages use read-only fields, prevent submission and use a reserved invalid
  destination. See [loading and local demonstrations](../load-extension.md).

**ML and dataset integrity**

- Legacy URL/character models do not influence browser verdicts. They were not
  redeployed under changed feature semantics and have not been replaced by a
  fictitious accuracy claim. The default worker avoids loading their large assets.
- Schema/extractor version is 0.2.0. URL-only training has an explicit feature
  subset; DOM training requires actual browser-captured features and source hash.
- Offline WHATWG URL canonicalization matches the browser's parsing, including
  numeric IP forms, Unicode/IDNA and escaping. Case-sensitive path/query data is
  preserved. Conflicting URL labels remain quarantined.
- Original/final domains and duplicate content form connected split groups.
  Valid mixed-label sites remain together rather than being deleted.
- Captures validate final URL, date, HTTP success, bounded HTML and quality.
  Capture blocks non-GET/HEAD requests, uses clean contexts and redacts values.
- Compact predictors are fitted before independent FPR-budget calibration.
  Exact export replaces silent tree truncation; sklearn and JS use float32 input
  parity. Feature/extractor/model identities and dataset manifests are recorded.
- Frozen future evaluation checks development-versus-test identity, source and
  time, labels reports honestly, reports uncertainty/breakdowns and prevents CLI
  reuse of the holdout for subsequent model decisions. Export requires qualifying
  independent evidence before a future artifact can be marked deployment eligible.
- `ml/src/evaluate_policy.py` evaluates the actual shipped JavaScript policy on
  versioned captured submission contexts. It reports high-risk warning and
  caution-or-high rates separately, confidence intervals and source/page-type
  breakdowns; exploratory results cannot masquerade as frozen independent tests.

**Verified offline**

```powershell
npm.cmd test
.\.venv\Scripts\python.exe -m unittest discover -s ml/tests -v
node docs/audit/diagnose-login.cjs
```

The JavaScript suite passes 12 test files. The Python suite passes 10 tests,
including 18 golden HTML/URL fixtures across all 29 features, grouped-data and
capture checks, independent calibration, provenance gates and exact compact
model export through the actual JavaScript predictor and full-policy outcome
evaluation. The model-training cases
are synthetic machinery tests, not a phishing benchmark.

| Offline diagnostic | Before | After |
|---|---:|---|
| Ordinary login with validation | 50 Caution | 0, no strong indicators |
| Pineapple title | 100 High risk | 0, no strong indicators |
| Brand only in return URL | 100 High risk | 0, no strong indicators |
| Multiple providers on official-domain fixture | 100 High risk | 0, no strong indicators |
| Ordinary branded login with iframe | 93 High risk | 0, no strong indicators |
| Text-trusted external credential target | 12 Safe | 35 Caution |
| Different private-hosting tenants | 12 Safe | 35 Caution |
| Controlled identity mismatch + external target | Not in baseline | 80 High risk |
| Controlled external transport downgrade | Not in baseline | 80 High risk |

Full observations: [before](login-probe-results.json),
[after](login-probe-results-after.json). Fixtures are local synthetic documents;
these results do not describe the live websites whose domains they imitate.

The installed Edge 156 browser smoke test passed in an isolated test profile:
ordinary local login (8, SAFE), SPA/action changes (88, HIGH_RISK), corrected
warning removal, an embedded phishing-like frame warning on the top document,
and removal of that frame clearing the warning. See
[browser smoke results](browser-smoke-results.json). No existing user browser
profile was modified. Worker/popup/DOM integration tests also pass separately.

**Research work that still requires data**

No representative untouched login/SSO and phishing corpus is available here to
establish real-world FPR/recall or approve a new learned model. Follow
[the ML workflow](../../ml/README.md) before making accuracy claims or enabling ML
influence. Frozen-data checks cannot prove honest human labels or that an analyst
never viewed a dataset.

The identity mapping is finite. Compromised/unknown domains, visual deception,
external-script data flow, closed shadow roots and inherited about:blank/srcdoc
frames remain coverage limits. The project warns about observable evidence; it
does not certify websites as safe.
