# Tester audit of the current PhishGuard checkout — 25 October 2026

**27 October follow-up:** See the [source-based methods comparison](competitive-methods-2026-10-27.md)
and [0.4.0 implementation, trained research candidates and current verification](improvements-2026-10-27.md).
The original observations below remain historical evidence.

**Repair status — PhishGuard 0.3.0:** Corrective code and regression coverage now
address B01–B14. All ten additional limitations have an explicit improvement and
residual-boundary entry in the [implementation follow-up](tester-repairs-2026-10-25.md).
Generic same-site deception, arbitrary script data flow, closed/opaque UI and
unmeasured real-world accuracy remain limitations; they are not claimed solved.
The original observations below are preserved as historical evidence.

This review found **14 reproducible implementation/release-workflow issues and 10 additional design/evaluation limitations**. The count separates root causes, rather than counting every fixture as a new bug. Severity is an audit judgment based on impact, not a measured incidence rate.

The browser currently uses the local rules policy. Historical learned models do not affect its verdicts (`extension/src/shared/model-release.js:4` and `extension/src/shared/model-policy.js:120`). ML findings below affect future data, evaluation, and releases; they do not describe a currently active learned predictor.

During the original audit phase, no product source was changed. The subsequent
user-authorized repair phase changed the product and tests as recorded in the
linked follow-up. Existing working-tree changes and historical probe results were
preserved; maintained regression/browser reports reflect their latest run.

## How to interpret the evidence

- **Real browser:** actual installed unpacked extension in an isolated Edge 156.0.4314.42 profile, using harmless local HTML. No credentials entered and no fixture form submitted.
- **Extractor fixture:** actual URL/form/DOM extraction and scoring in jsdom, using synthetic HTML/URLs. Page scripts are inspected as text and are not executed. These demonstrate decision behavior, not that a particular public site currently serves that HTML.
- **Worker/UI harness:** actual production worker/UI with mocked browser APIs, controlled network responses and, for runtime sequencing probes, a stub scorer. These isolate lifecycle/integration behavior, not the rule classifier's accuracy.
- **ML synthetic/mock:** actual pipeline functions on synthetic data; the navigation-status reproduction explicitly mocks browser navigation. This last case has not been exercised with live Playwright.

`SAFE` is the internal outcome displayed as Low risk/No strong indicators. `CAUTION` is a warning band but does not show the High risk banner. Neither is proof of legitimacy. All numeric scores below use default settings.

## Reproducible implementation and workflow issues

### B01 — High: a worker restart loses a risky iframe's verdict

**Evidence:** Worker harness starts with a SAFE top document and HIGH_RISK child. After recreating the worker while retaining session storage, only the top document rescans. The aggregate becomes **SAFE**, with one uninspected frame. Opening the popup returns that SAFE result and requests **no recovery scan**.

**Cause:** Per-frame state lives only in `const tabs = new Map()` (`extension/src/background/service-worker.js:7`). Session output is written but never used to recover frame state. Missing frames discovered by inventory are counted, but not requested to rescan when a valid top result exists (`:120`, `:253`). Chrome documents that worker globals are lost on shutdown: [official lifecycle documentation](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).

**Impact/fix direction:** A static risky child can lose its warning after an ordinary background-worker restart until it independently rescans. Recover by requesting all live, covered documents on cold-start reconstruction; retain Unknown/partial status until reconciliation completes. Do not blindly restore stale verdicts. Lifecycle reproduction is controlled/harness-based, not a forced shutdown in Edge.

### B02 — High: CSS-only reveal leaves an obsolete low-risk result

**Evidence:** In real Edge, a hidden password field on a PayPal-titled page produces **28 SAFE**. Revealing it through `CSSStyleSheet.insertRule()` makes it visibly available, but after **4.5 seconds** the scan ID and result remain unchanged. An explicit rescan produces **88 HIGH_RISK**.

**Cause:** `extension/src/content/content-script.js:100` observes selected DOM attributes/mutations. CSSOM edits do not generate those mutations. Root polling at `:120` only schedules analysis when the root list changes.

**Impact/fix direction:** Visibility can change without fresh analysis. Add bounded detection of relevant rendering changes and a pre-interaction check; cover CSSOM, stylesheet-load/media changes and relevant state attributes with targeted regression cases. The additional possibilities are coverage targets, not separately browser-reproduced cases.

### B03 — High when optional reputation is enabled: a new scan erases a known malicious verdict

**Evidence:** Controlled response `malicious` produces HIGH_RISK. A second scan of the **same hostname** immediately produces **SAFE** before its new reputation request resolves. If that request returns unknown, the downgrade remains.

**Cause:** `extension/src/background/service-worker.js:216` replaces the result with a fresh local score; reputation is applied later at `:219` without retaining a still-valid prior report.

**Impact/fix direction:** Ordinary DOM changes can remove a reputation-derived warning; a busy page can continually supersede delayed responses. Preserve a validated report with a defined TTL and configuration identity, and make pending/failed reputation state explicit. Harness verified; no external reputation service contacted.

### B04 — High false positive: a harmless SSO wording change creates impersonation evidence

**Evidence:** An email-only form POSTing to `accounts.google.com`, titled **“Sign in with a Google Account”**, scores **80 HIGH_RISK**. Replacing `a` with `your` gives **35 CAUTION**.

**Cause:** The provider-mention expression at `extension/src/content/url-features.js:34` accepts optional `your`, but not ordinary variants such as `a`. The title is then treated as an ownership claim and combined with cross-site SSO submission.

**Fix direction:** Interpret an authentication-provider phrase semantically/conservatively; expand legitimate phrase regressions without creating a blanket brand/domain exemption.

### B05 — High false positive: email recovery instructions are mistaken for a password field

**Evidence:** An `<input type="email">` labeled **“Enter your email to reset your password”** is assigned `has_password_input=1` and a sensitive-field count of one. A cross-site GET recovery form becomes **70 HIGH_RISK**. The same input labeled “Email address” gives **35 CAUTION**.

**Cause:** Accessible metadata regexes identify any mention of password as a password prompt (`extension/src/content/form-features.js:68`, `:79`, `:112`, `:122`).

**Fix direction:** Resolve metadata against the control's actual requested information and recovery context. Do not equate explanatory prose mentioning a password with collecting one.

### B06 — High false-negative exposure: one owned brand suppresses another brand's mismatch

**Evidence:** A synthetic PayPal-titled password form POSTing to an external HTTPS collector scores **80 HIGH_RISK** at `host.example`, but **35 CAUTION** at `sites.google.com`.

**Cause:** Host recognition adds Google to claimed brands. `claimedBrands.some(ownsHost)` makes any owned claim erase the unrelated PayPal mismatch (`extension/src/content/url-features.js:38`, `:45`).

**Fix direction:** Evaluate each identity claim independently and distinguish platform ownership from hosted-content identity. This is an extractor fixture, not proof that Google Sites permits that exact HTML or a live exploit there.

### B07 — Medium false positive: official-domain mappings are incomplete

**Evidence:** A synthetic `www.google.ch` page titled Google with a password POST to `accounts.google.com` scores **80 HIGH_RISK**. Google lists `.google.ch` in its [official domain list](https://www.google.com/supported_domains); the project omits it.

**Cause:** `extension/src/content/url-features.js:6` enumerates a small set of Google domains. Other brand mappings are similarly manually maintained.

**Fix direction:** Maintain reviewed ownership data with tests and provenance; unfamiliar domains should not automatically become proof of impersonation. No live country-domain login flow was tested.

### B08 — Medium false positive: collapsed/unrendered credential controls are counted as active

**Evidence:** In real Edge, a password field inside closed `<details>` has `checkVisibility(...) === false`, yet its archived cross-site HTTP form makes the current page **78 HIGH_RISK**. HTTPS fixture equivalents score 80. A `content-visibility:hidden` fixture also contributes full evidence. A closed `<dialog>` control was correctly excluded.

**Cause:** Visibility logic at `extension/src/content/form-features.js:82` checks display/opacity/visibility/hidden/inert, but misses other rendering states. Submitter override inspection at `:179` also ignores submitter visibility.

**Fix direction:** Use browser rendering information carefully, account for collapsed containers, and refresh on relevant state changes. Hidden submission targets warrant separate reasoning because they can still be invoked programmatically; not every latent target is necessarily harmless.

### B09 — High evaluation-integrity bug: CSV round-tripping upgrades untrusted provenance

**Evidence:** The same data originally fails source separation with `source_provenance=filename_fallback`. Writing it as CSV and reading it again changes provenance to `explicit`, after which the source/time separation check passes.

**Cause:** `ml/src/train_model.py:61` replaces provenance based only on a nonempty source column. `ml/src/capture_dom_snapshots.py:224` repeats this rule.

**Fix direction:** Preserve explicit provenance classifications across formats and reject automatic upgrades. A filename-derived string becoming a CSV column does not establish an independent source. This does not bypass every overlap/timestamp check; it specifically defeats the provenance gate.

### B10 — High release-gate bug: a model with zero phishing recall can be exported as validated

**Evidence:** A synthetic model evaluated on 800 independent synthetic sites yields **TN=400, FP=0, FN=400, TP=0**. Recall is **0%** and the false-positive upper confidence bound is **0.9512%**, within the 1% budget. Actual export accepts it with `deployment_eligible=true`, `deployment_status=validated`.

**Cause:** `ml/src/export_browser_model.py:97` checks the FPR bound but imposes no minimum recall requirement. Threshold selection can choose 1.0 (`ml/src/train_model.py:167`). The required representative-login review assertion was deliberately supplied to exercise this gate; synthetic data is not claimed representative.

**Fix direction:** Predefine recall/detection requirements and adequate independent positive coverage alongside the FPR budget. The current rules-only browser does not load this probe model.

### B11 — Medium dataset bug: a completed script navigation can retain the previous HTTP status

**Evidence:** Mocked navigation from an initial **200** page to a final **404** page completes before extraction. The collector stores final-page URL/title with **status=200**, marks quality okay, and `dom_dataset.load_snapshots()` accepts it.

**Cause:** `ml/src/capture_dom_snapshots.py:241` saves `goto()`'s response, waits at `:242`, then captures the current document but reads the original response status at `:249` and bases capture success on it at `:258`.

**Fix direction:** Bind navigation response/status and redirect provenance to the exact captured document. The final-URL consistency check only catches navigation during the extraction window. **Mock reproduction only; full Playwright/live redirect capture was not performed.**

### B12 — Medium: unusable reputation endpoints are accepted without a visible failure

**Evidence:** Options accepts and saves `https://username:password@rep.test/check`. Fetch rejects constructing requests from URLs containing embedded credentials. The worker swallows the failure.

**Cause:** `extension/src/options/options.js:20` validates protocol but not URL userinfo; `extension/src/background/service-worker.js:173` reduces failures to no report.

**Fix direction:** Reject unsupported endpoint forms and expose request/response failures separately from a benign or unknown report. Probe verified request construction without sending a network request.

### B13 — Medium: reputation requests are not coordinated across repeated scans

**Evidence:** The worker harness accepts 100 same-host scans and issues **100 requests**; **99 superseded requests remain unaborted**.

**Cause:** `extension/src/background/service-worker.js:149` creates a new request per scan (`:219`), with no per-host cache/inflight sharing or cancellation of superseded requests. Settings changes do correctly abort requests.

**Impact/fix direction:** Busy pages/multiple frames can waste requests, repeatedly disclose hosts to the configured service and hit rate limits. Real content scans are debounced: 100 requests is a harness count, not a measured production request rate. Add bounded caching, inflight sharing and request budgets.

### B14 — Low: failed storage writes/deletions report success

**Evidence:** Mocked failures still display “Settings saved” and “Saved corrections cleared.” The correction popup announces success without awaiting its write.

**Cause:** `extension/src/options/options.js:30`, `:35` omit `runtime.lastError` checks; `extension/src/popup/popup.js:75` does not await confirmed storage completion.

**Fix direction:** Report success only after confirmed storage completion, and retain an actionable failure message. This particularly matters when a user believes feedback has been deleted.

## Additional design and evaluation limitations

1. **Same-origin HTTPS harvesting can look normal.** A synthetic generic-title password POST to `/collect` scores **0 SAFE**. A PayPal title raises it only to **45 CAUTION** because High risk requires two strong categories (`extension/src/shared/model-policy.js:70`). This conservative tradeoff reduces false positives while leaving substantial recall exposure. HTTPS and same-site posting do not establish legitimate ownership.

2. **Body-only branding does not contribute to the identity decision.** Generic title plus visible `<h1>PayPal</h1>` and same-origin password POST still scores **0 SAFE**, even with `brand_name_in_visible_text=1`. Identity matching uses title/hostname (`extension/src/content/url-features.js:97`); the body flag is descriptive. Visual/image-only impersonation is also outside these rules. Raising risk for every incidental body mention would reintroduce false positives.

3. **Declared form destination is not runtime data flow.** A form declaring same-origin action while an inline submit handler uses cross-site `fetch(FormData(...))` scores **0 SAFE**. The static extractor records activity but deliberately does not claim proven credential submission (`extension/src/content/form-features.js:252`, `:278`). External scripts, changing destinations and compromised-site behavior require different evidence; a `fetch` token alone is not proof of theft.

4. **An omitted method gets weaker treatment than equivalent explicit GET.** Cross-site password form with `method=get` gives **70 HIGH_RISK**; missing method gives **35 CAUTION**, although effective native GET is observed. The explicit-only rule avoids incorrectly condemning Ajax forms but misses native default-GET exposure (`extension/src/content/form-features.js:198`, `extension/src/shared/model-policy.js:26`).

5. **Some input surfaces/documents remain uninspected.** Closed shadow roots, inherited-origin `about:blank`/`srcdoc` frames and browser-protected pages have gaps. A closed-shadow fixture gives **20 SAFE**, no detected credential context. Custom `contenteditable` textbox fixtures also give **20 SAFE** because extraction queries `input, textarea` (`extension/src/content/form-features.js:5`, `:36`). Known omitted frames are disclosed; inaccessible closed trees are not comprehensively discoverable.

6. **Brand and sensitive-field vocabulary is narrow.** Only nine brand names have ownership mappings. A plausible card form labeled “Credit card”, “Expiration”, “Security code” with arbitrary names produces sensitive count zero in the probe. Locale/language variations, image/canvas prompts and unknown brands need representative coverage. Naming/metadata heuristics cannot fully establish user intent.

7. **No representative current-policy accuracy benchmark is present.** No DOM JSONL corpus was found under `ml/data`; the legitimate-login hard-negative list has only 32 URL seeds. Historical unreviewed popularity-list negatives are correctly rejected by the current reader. Existing URL datasets and historical model reports cannot measure this release's URL+DOM+runtime behavior. No credible production FPR, recall or overall accuracy percentage follows from these fixtures.

8. **Current scores and thresholds are an uncalibrated risk index.** Hand-chosen evidence weights, category requirements and an adjustable threshold determine outcomes. A high numeric score requires corroboration for High risk. Zero means no selected evidence, not zero probability. Raising/lowering the threshold cannot repair missing observations or semantic errors; it changes the tradeoff.

9. **Saving a correction does not train or correct the detector.** Feedback is a local, capped log (`extension/src/popup/popup.js:67`); no trainer or scoring path consumes it. It records top origin plus aggregate result, so a risky third-party frame's warning is attached to the top origin without frame/context evidence. These privacy-limited, unverified records cannot safely become site-level labels without further review.

10. **Warnings are asynchronous advice, not guaranteed prevention.** Injection occurs at `document_idle`; ordinary mutations are debounced, and late open roots are discovered periodically. Content submission is not blocked by the detector. A page also owns the DOM containing the banner despite repair logic; the popup is the independent extension surface. The browser collector executes page JavaScript and its URL guards are not an OS/network malware sandbox. These boundaries need explicit product expectations and deployment testing.

## Validation and evidence

- Existing JavaScript regression suite: **12/12 test files passed**.
- Existing Python regression suite: **20/20 tests passed**.
- Demo validator: **passed**.
- Maintained real Edge smoke test: **passed**, including SPA/hash updates, iframe removal, late open shadow roots, banner repair, coverage reporting and isolated collector extraction.
- Additional real Edge audit: **passed its bug-reproduction assertions** for CSSOM stale results and unrendered closed-details controls.
- Detection fixtures: **23 synthetic cases**.
- Extra worker probes: **3 assertions/scenarios** covering restart/frame state, reputation reset and CSSOM.
- ML probes: **3 confirmed scenarios**, with navigation status explicitly browser-mocked.
- UI probes: **3 confirmed scenarios**, including a 100-scan request-coordination check.
- `git diff --check`: passed. No production code fixes were made during this audit.

The first sandboxed Edge attempt crashed in its GPU/process initialization. The isolated rerun outside that sandbox passed; this environment failure is not counted as a detector bug. Its diagnostic output is retained separately. A preliminary additional probe used rectangle-count as a visibility assertion; Edge's closed-details layout still returned a rectangle. The final probe uses the browser's visibility check and passes. Passing bug-reproduction assertions means the documented wrong behavior was observed; it does not mean those bugs are fixed.

Original supplemental probes (historical; some assert faulty behavior and will
intentionally fail after the repair; use follow-up verification commands now):

```powershell
node docs/audit/detection-probe-2026-10-25.cjs
node docs/audit/tester-runtime-probes-2026-10-25.cjs
node docs/audit/tester-ui-probe-2026-10-25.cjs
.\.venv\Scripts\python.exe docs/audit/tester-ml-probes.py --output docs/audit/tester-ml-results.json
node docs/audit/tester-browser-probes-2026-10-25.cjs
```

Results: `detection-probe-results-2026-10-25.json`, `tester-runtime-probes-2026-10-25.json`, `tester-ui-results-2026-10-25.json`, `tester-ml-results.json`, `tester-browser-probe-results-2026-10-25.json`, and `browser-smoke-results.json` in this directory. Browser probes require installed Edge and may need a runtime that permits its subprocesses.

## Suggested repair order

1. Recover per-frame results after worker restarts; retain valid malicious reputation across rescans; address CSS-only stale analysis.
2. Correct SSO phrase handling, password-recovery metadata, per-brand matching and rendered-control visibility. Add exact counterexample regressions while preserving ordinary-login protections.
3. Fix provenance preservation, bind capture metadata to the captured document and require minimum detection performance before any learned-model deployment.
4. Coordinate reputation requests and expose service/storage failures.
5. Build a reviewed, representative, untouched policy+browser benchmark spanning login/SSO, banks/colleges/payments, compromised sites, dynamic/embedded UI and independent phishing campaigns. Measure FPR and recall before making performance claims or changing thresholds.
