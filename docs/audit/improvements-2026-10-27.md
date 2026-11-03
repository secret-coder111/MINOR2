# PhishGuard 0.4.0: implementation and measured results

Date: 27 October 2026. This update follows source-based research of PhishLang,
PhishDetect, Netcraft, Malwarebytes Browser Guard and Bitdefender Web Sage.
The detailed research is in `competitive-methods-2026-10-27.md`.

## What changed in the working project

The installed-extension source is `C:\Users\wwwvi\Desktop\MINOR2\extension`.
Existing uncommitted changes and historical audit evidence were preserved.
Package, manifest and active rules-policy versions now identify 0.4.0.
The numeric research feature schema remains 0.2.0 with the same 29 ordered fields;
extractor/policy hashes distinguish changed capture semantics.

### Contextual lookalike-address protection

The detector now recognizes finite reviewed visual hostname substitutions such
as `paypa1`, `micros0ft` and a single Cyrillic homograph character. It can also
recognize a full official domain embedded before an unrelated domain boundary.
The offline Public Suffix List, including PRIVATE entries, selects the actual
registrable site or hosted tenant. It performs no registration or network lookup.

This evidence can raise risk only when a short rendered primary login heading
claims that same brand next to the same sensitive credential form. A matching
identity concern contributes 45 points; the contextual address evidence contributes
35. The resulting 80-point High risk verdict can therefore cover certain HTTPS
forms submitting to their own origin, where external-destination checks do not help.

Address resemblance, internationalized text, provider phrases, shared hosting,
title/body repetitions and ordinary credential requests cannot activate this new
escalation alone. Arbitrary one-edit spellings are deliberately outside the finite
matching contract. Article/footer/navigation/aside/comment examples are excluded
through composed ancestors, including open shadow roots and assigned slots.
Different forms cannot lend one another their identity/address evidence.

New policy flags are numeric structural observations, never typed values or page
text. Matching Python helpers and browser fixtures preserve the capture contract;
static HTML research rows do not manufacture browser-observed submission contexts.
This is an independently implemented concept, not copied third-party model code.

Changed detection files: `extension/src/content/url-features.js`,
`extension/src/content/dom-features.js`, `extension/src/shared/model-policy.js`,
and `ml/src/feature_engineering.py`.

### Frontend improvements

The existing extension is the frontend. No separate website, React installation,
account, API key or Python server is needed for the deployed local detector.

The popup now shows the browser-derived ASCII website origin, identifies the
embedded-page origin when relevant, gives practical next steps, opens Settings,
and provides **Check again**. It never displays private URL paths/queries in those
origin labels. A manual scan checks the exact current URL against browser frame
inventory, requests accessible frames again, and confirms completion only after
a newer scan/document identity arrives. Local-file scans retain existing browser
permission requirements. Keyboard focus and narrow-width layout were checked.

Changed frontend/runtime files: `extension/src/popup/popup.html`, `popup.css`,
`popup.js`, and `extension/src/background/service-worker.js`.

### Model development improvements

Tree and character trainers now compare candidates by phishing recall within the
declared empirical tuning false-positive budget. Overall ROC AUC alone no longer
selects the winner. Ties prefer fewer false positives, then average precision and
AUC. Infeasible candidates produce explicit diagnostics. The final fitted model
still receives its threshold from a separate calibration partition.

The new `ml/src/train_hybrid_model.py` compares 23 predeclared candidates:
32-tree Random Forest/ExtraTrees models over 13 URL features, character TF-IDF
3–5-grams with logistic regression at three regularization settings, and 18
probability blends. Vocabulary and estimators fit only development partitions;
tuning selects candidates before separate calibration and test scoring.
The numerical and character predictions are correlated and are not treated as
independent evidence groups in the browser policy.

Hybrid bundles are explicitly research-only and have a separate Python prediction
function. Existing browser exporters reject this unsupported representation.
No historical or newly trained learned model changes the browser verdict.

## Actual training experiment

The run sampled 4,000 rows per class deterministically from the existing local
EdgePhish CSV. Canonicalization, conflict quarantine and deduplication retained
7,995 rows. Grouped partitions contained 3,629 fit, 1,209 tuning, 1,597 calibration
and 1,560 internal-test rows. The sampling seed was 20261027; source/sample/model
hashes and partition manifests were saved for reproducibility.

Unreviewed popularity seeds, the mixed-threat good/bad corpus and frozen future
tests were excluded. The input labels were supplied by the dataset and were not
newly verified. Source timestamps, reviewers and representative login/SSO/DOM
coverage are absent. The balanced sample does not represent browsing prevalence.
This is a previously available, exploratory internal dataset, not an untouched
source/time-separated deployment benchmark.

| Research candidate | Phishing recall | Legitimate-page false-positive rate | Accuracy |
|---|---:|---:|---:|
| Numeric Random Forest | 63.38% | 1.24% | 81.73% |
| Character TF-IDF/logistic | 87.48% | 2.35% | 92.76% |
| Tuning-selected hybrid | 87.35% | 2.35% | 92.69% |

All rows use the same 1,560 internal-test observations and separately calibrated
family models. Family/global winners were selected on tuning data, not these test
values. The initial old-AUC versus new-budget comparison chose the same Random
Forest on this sample, so changing the selection criterion alone showed no
measured gain here.

The hybrid selected by tuning used equal numeric ExtraTrees and character-C=2
weights. Its internal confusion matrix was TN=790, FP=19, FN=95, TP=656.
Recall's descriptive 95% interval was 84.78–89.54%; the false-positive interval
was 1.51–3.64%. The character-only family happened to detect one more phishing
row at the same false-positive count. The hybrid is not an established improvement
over that component; it improves observed recall over the numeric baseline while
increasing false warnings.

The 1% false-positive upper-bound release target fails, and the required independent
reviewed benchmark and hybrid browser inference are missing. Both trained artifacts
remain `research_only` with `deployment_eligible=false`. Strong AUC or over 92%
sample accuracy does not justify activating them.

Saved artifacts in `ml/models`:

- `research-url-0.4.0.json` and `.joblib`: numeric research run. Its extractor hash
  records the earlier training snapshot; subsequent contextual-exclusion changes
  correctly prevent treating it as a current compatible deployment artifact.
- `research-hybrid-url-0.4.0.json` and `.joblib`: new numeric/character research
  bundle with the final frozen extractor hash. No browser integration is claimed.

`model-research-2026-10-27.json` contains aggregate comparisons, dataset limitations,
reproducibility hashes and failed release checks. Model metadata retains internal
identity manifests; the aggregate report does not export raw example URLs.

## Verification completed

| Check | Observed result |
|---|---|
| `npm.cmd test` | 23 tests passed across 15 JavaScript test files |
| Python unittest discovery in `ml/tests` | 37 tests passed |
| `npm.cmd run test:demo` | Passed; controlled verdicts and submission prevention |
| `npm.cmd run test:browser` | Passed in isolated Edge 156.0.4314.42 |
| Final popup/runtime targeted regressions | 10 tests passed |
| Browser/Python features | Existing 46 named-feature fixtures and 15 new address/context fixtures passed |
| Independent finite-alias cross-check | All 121 generated alias labels matched between browser and Python |
| Source syntax, manifest assets, version alignment and diff whitespace | Passed |

The real browser loaded the unpacked extension. A reserved HTTPS `.test` address
was fulfilled from harmless fixture HTML before page networking; no malicious site
was visited. Its same-origin lookalike login scored **80 High risk**, with zero
external-destination evidence. A provider-phrase control remained Low risk.
The real popup displayed that origin/verdict and completed a manual rescan.
The saved popup screenshot was visually inspected and its normal width checked.

The maintained browser suite also passed SPA/mutation updates, embedded-frame
warnings/removal, shadow-root discovery, CSS-only control reveals, warning repairs,
worker-restart recovery, inherited-document coverage, options and feedback storage.
The standard demo still produced 43 Caution, 88 High risk, then 8 Low risk, with
submission cancellation and browser CSP blocking verified; zero POSTs were sent.

The first browser launch was limited by the execution environment; the isolated
test passed with its local debugging connection available. Python temporary files
were placed in the working folder because Windows restricted the default temporary
directory. These were verification-environment issues, not detector fixes.

## Use the update

1. Open `chrome://extensions` or `edge://extensions`.
2. Reload PhishGuard; confirm version **0.4.0** and refresh the website tab.
3. Open the popup to see the current origin, evidence and **Check again**.
4. For the local presentation, run `npm.cmd run demo` from the project directory
   and open `http://127.0.0.1:8080/`. Keep threshold 65 and reputation disabled.
5. Show the actual popup result, then stop the demo server with Ctrl+C.

## Remaining improvement needed for a deployable learned model

Collect and independently review a representative, source/time-separated captured
benchmark covering legitimate login, SSO, banking, education, payment, non-login,
and phishing pages. Maintain campaign/site separation before any text chunking.
Measure whole-policy false warnings, recall, latency and memory on a fresh holdout.
Only then choose a model/runtime and implement matching browser inference if the
candidate passes the predefined gates. A larger transformer is a candidate to test,
not evidence of better accuracy by itself.

The current finite detector still cannot establish arbitrary JavaScript data flow,
generic same-origin HTTPS theft, visual/QR-only deception, unknown brands/languages,
closed shadow content or every compromised official-domain scenario. No claim of
best-in-market accuracy or elimination of all phishing is made.
