# URL score consistency and wider extension UI

Date: 3 November 2026. Loaded-page evidence policy remains 0.5.0.

## Score repair

The URL-only checker previously gave HTTP an independent Caution label but
used a loaded-page score that assigns transport points only when credential
fields are observed. With no page loaded, this produced Caution / 0.

The address-only preview now adds 15 points for public HTTP transport and
lists each score component. The user's example,
`http://banamxr.com/1/mexico/`, yields Caution / 15. No target request was made.
This explains HTTP exposure; it does not claim the historical dataset entry is
currently online, credential-stealing or confirmed by live reputation.
An ordinary HTTPS address can still have zero observed indicators. This means
limited evidence, not verified safety. Main loaded-page scoring is unchanged.

## Layout and scope

- The action popup's root and body have an intrinsic width of 540px. This avoids
  shrinking to the browser's small provisional popup viewport through `100vw`.
- Verdict and guidance sit side by side; the three main actions share one row.
- The popup identifies the current browser tab and explains that pasted URLs
  are checked separately. A zero for the classroom page is not the pasted
  site's result.
- On-page warnings extend to 640px on desktop, keep the responsive mobile width,
  and retain the Close / Leave actions and protected text-only explanations.
- Browser QA exposed a settings initialization race: the HTML Save button is
  now initially disabled until storage initialization completes.

Actual extension HTML and APIs were exercised in isolated Edge
156.0.4314.58. The popup test checks that its body stays 540px even with a 240px
provisional viewport, then verifies the intended 540x600 rendering without
horizontal overflow. This is an extension-target rendering check, not a
screenshot of the user's native toolbar window.

Evidence: [popup](ui-fixes-2026-11-03/popup-540.png),
[desktop warning](ui-fixes-2026-11-03/warning-desktop.png),
[mobile warning](ui-fixes-2026-11-03/warning-mobile.png),
[full local browser result](ui-fixes-2026-11-03/browser-smoke-results.json).
The final checker also has [desktop](ui-fixes-2026-11-03/checker-desktop.png)
and [mobile](ui-fixes-2026-11-03/checker-mobile.png) previews with the updated
research metrics.

## Model experiments

The baseline is reproduced on exactly the same 22,358 internal test URLs before
comparison. These corpora and the internal test were previously inspected;
results are exploratory and cannot establish production accuracy. Candidate
selection uses tuning only; final thresholds use separate calibration. No new
test metric selects a candidate or changes the threshold.

The scheme-ablation experiment compared the existing full-URL character model
with four scheme-free alternatives (C=2, 4, 8, 16). Tuning selected scheme-free
C=2. On the reused test, precision rose from 98.31% to 98.37%, but accuracy fell
from 90.12% to 89.47%, recall from 80.42% to 78.97%, and F1 from 88.47% to
87.61%. It still falsely scored genuine GitHub and PayPal controls highly.
This experiment is rejected for integration. Its estimator/metadata remain
offline for reproducibility; the browser diagnostic is unchanged by this run.

Full scheme-ablation metadata remains local at
`ml/models/url-checker-research-2026-11-03.json`; its measured results are recorded
above. Large per-record training manifests and Python estimators are excluded
from new Git commits; the compact comparison and browser export are published.

The expanded-data experiment retained the original tuning/calibration/test
partitions and excluded all their registrable sites from additional fitting.
It added 190,947 fitting rows: 240,000 fitting, 18,595 tuning, 29,994 calibration
and 22,358 test URLs. The baseline confusion matrix was reproduced exactly.
Three predeclared full-URL candidates (C=1, 2, 4) were compared on tuning;
C=4 won and the refitted estimator was calibrated separately.

| Metric | Baseline | Expanded C=4 |
| --- | ---: | ---: |
| Accuracy | 90.12% | 92.57% |
| Precision | 98.31% | 98.21% |
| Recall | 80.42% | 85.79% |
| F1 | 88.47% | 91.58% |
| False-positive rate | 1.23% | 1.40% |

The expanded model fixes 677 previous test errors but introduces 130. Its test
confusion matrix is TN=11,658, FP=165, FN=1,497, TP=9,038. All metrics did not
improve. It still falsely scores genuine GitHub and PayPal controls highly,
exceeds the release FPR budget, and lacks a fresh reviewed source/time test.
It is exported **only as the separate collapsed research diagnostic**, never
as the primary URL result or extension page verdict. `deployment_eligible`
remains false. Scores are not calibrated theft probabilities.

The diagnostic export matches sklearn over 1,010 cases to maximum absolute
error 3.34e-16; all 13 URL features match between browser and Python. See the
[compact comparison](url-checker-research-2026-11-03-expanded-comparison.json)
and [export/parity report](url-checker-model-2026-11-03.json).

## Verification and publication

- JavaScript suite: 41 passed, 0 failed.
- Python suite: 37 passed, 0 failed.
- Controlled demonstration and no-submit checks: passed.
- Full isolated Edge smoke test: passed, including warning dismissal, popup
  width, actual loaded-page checks and the HTTP URL-only score regression.
- Public classroom checks: passed. Owned HTTPS scenarios score 0 / 35 / 80;
  the published checker returns 15 with the HTTP transport component for the
  user's address. The target itself was never visited by that check.
- Static packaging: 19 selected files, 119 local references; no raw CSVs,
  estimators, browser profiles or credentials copied into the public Site.

The [published checker](https://phishguard-classroom-visual-lab.www-vikramsahu001.chatgpt.site/url-checker.html)
was updated as version 8. See the [deployment record](url-checker-deployment-2026-11-03.json)
and [hosted browser results](classroom-web-results-2026-11-03.json).
Local extension UI changes require Reload in chrome://extensions (or
edge://extensions) followed by refreshing existing website tabs.

## Reported real phishing example

The first entry in the [OpenPhish Community Feed](https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt)
was checked on 3 November 2026:

```text
hxxps://www[.]roblox[.]com[.]et/users/7280036217/profile
```

This is a reported phishing address, defanged to avoid accidental navigation.
The destination was not opened and current reachability was not independently
verified. A feed listing is external evidence, not a successful PhishGuard
detection or a permanent statement about a domain. The entry was not added to
the training data or hardcoded into verdicts. For classroom navigation use the
owned non-submitting fixtures or the separate harmless AMTSO feature test.
