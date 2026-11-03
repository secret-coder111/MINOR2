# Warning dismissal, restored demos and URL checker

Date: 2 November 2026. Browser page policy remains 0.5.0.

## Delivered behavior

- A keyboard-accessible **Close ×** button dismisses the same warning in the
  current document. The verdict remains in the popup. Automatic rescans respect
  dismissal; explicit **Check again**, changed warning evidence or a new page
  can show a warning. Synthetic page-script clicks cannot dismiss it.
- The credential-entry demonstration, loopback collector/server, live-demo
  command and active links are removed. Original read-only fixtures stay intact.
- The overview restores three owned demonstrations with live comparisons:
  GitHub sign-in, BadSSL HTTP password, and AMTSO's harmless phishing test.
- A browser-local URL input validates HTTP(S), rejects embedded credentials,
  control characters and unsupported schemes, and never visits the target just
  to compute address evidence. Invalid/edited input clears stale results/links.
- The checker opened through the extension popup can explicitly **Load page and
  inspect with PhishGuard**. It uses a temporary inactive tab, the final redirected
  URL, worker document binding, a two-second post-load settling interval and a
  15-second inspection budget. Missing/stale/blocked results do not become SAFE.
  Cleanup closes only its owned inactive tab; a tab the user selects remains.
  The public website opens the requested address for a separate toolbar check.
- The address index reuses the canonical evidence policy. It is an incomplete
  URL assessment, not a manufactured full-page score or a safety certificate.

## Model experiment and false-positive finding

All six local CSVs were audited (1,838,548 rows), leaving 762,086 unique eligible
URLs after scope/review filtering and duplicate/conflict checks. A deterministic
120,000-record source/class sample compared 23 numeric, character and blended
candidates with separate registrable-site groups across fit/tuning/calibration/test.

The tuning-selected character model measured **90.12% accuracy, 98.31% precision,
80.42% recall, 88.47% F1 and 1.23% FPR** on 22,358 internal held-out URLs.
This is exploratory, not a reviewed source/time-separated production benchmark.
The internal test was not used to select the winner or its threshold.

A real negative control exposed a high model score for GitHub's genuine login.
The release gate also remains unmet. The model therefore stays in a separate,
collapsed **experimental diagnostic** and does not decide primary URL or loaded
page outcomes. The corrected primary GitHub result is limited address inspection,
0 URL-evidence points, with no verified-safe claim or special hostname exemption.
No accuracy gain over earlier experiments on different splits is claimed.

The standalone diagnostic predictor matches sklearn within 3.34e-16 over 1,010
cases. All 13 numeric URL features also match Python, including the checked
Unicode/canonicalisation boundaries. The extension verdict worker does not load
the new model. Raw datasets/estimators are not copied to the public Site.

## Verification

- **41 JavaScript tests passed**, including dismissal tampering, URL validation,
  stale-result clearing, model separation, redirects, unavailable page results,
  cancellation and owned-tab cleanup.
- **37 Python tests passed**, including browser/Python feature and policy parity,
  capture provenance, grouped splits, threshold selection and release checks.
- `npm.cmd run test:demo`: passed; existing fixtures send no submitted data.
- `npm.cmd run build:classroom`: passed; **19 explicitly selected assets**,
  **119 local references**; only the URL input is editable, submission and page
  connections remain blocked by CSP. Extension-only page loads use browser APIs
  after the user explicitly chooses the action.
- Isolated **Edge 156.0.4314.58** browser suite passed, including trusted close,
  rejected synthetic dismissal, retained verdict, automatic/manual rescan behavior,
  URL-checker screenshots at 1440px/390px and the packaged extension CSP.
- The loaded-page checker returned **SAFE 8** for the ordinary local fixture and
  **HIGH_RISK 88** for the combined brand/external fixture. These are controlled
  demonstrations, not production performance measurements.
- An initial new-test readiness check raced navigation; its unbound-variable
  expression was corrected before the successful complete browser run.

Evidence: [browser report](browser-smoke-results.json),
[model/parity report](url-checker-model-2026-11-02.json),
[data audit](../../ml/reports/url-checker-data-audit-2026-11-02.json),
[user guide](../url-checker.md).

## Publication and final web check

Site **version 6** deployed successfully. The final isolated Edge rehearsal
loaded the published URL checker, waited for the actual input handlers/metrics
to be ready, and verified a GitHub URL produced the primary 0-point limited
address assessment with all four separate research metrics visible. Hosted
ordinary / caution / combined fixtures produced **0 / 35 / 80**.

The readiness check uncovered a click-before-handler race during public loading.
The final UI disables its buttons while preparing, then explicitly enables them;
the hosted check waits for that ready state. A failure of this owned checker now
fails the browser suite instead of being silently treated as an observation.
The final targeted URL tests passed after the loading-state change.

Exact release: [deployment record](url-checker-deployment-2026-11-02.json).
Live results: [published-page rehearsal](classroom-web-results-2026-11-02.json).
Visual records: [desktop checker](url-checker-visuals/checker-desktop.png),
[narrow checker](url-checker-visuals/checker-narrow.png),
[close button](url-checker-visuals/close-warning-narrow.png).
