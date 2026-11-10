# URL checker and restored demonstrations

## Run and use

1. Reload the unpacked `extension` folder in `chrome://extensions` or
   `edge://extensions`, then refresh the demo tabs.
2. From the project folder run `npm.cmd run demo`.
3. Open http://127.0.0.1:8080/. Each of the three cards offers our own read-only
   demo and an independent public comparison: [GitHub login](https://github.com/login),
   [BadSSL's HTTP password test](http://http-password.badssl.com/), and the
   [official AMTSO phishing test](https://www.amtso.org/check-desktop-phishing-page/).
   AMTSO is a harmless feature check, not a criminal credential-stealing site.
4. Choose **Check a URL**, open http://127.0.0.1:8080/url-checker.html directly,
   or choose **Check another URL** in the extension popup.
5. Paste an HTTP(S) address and select **Check URL** or press Enter. A bare
   hostname assumes HTTPS. The result shows the observed URL-evidence index/review band,
   actual hostname/registrable site, transport and address observations.

The address is processed in the browser. Checking it does not visit the site,
upload the address or save checking history. **Open page for an extension check**
is a separate explicit action. In the checker opened from the extension popup,
it loads a temporary background tab and displays the actual worker verdict
for the loaded page. It waits briefly after load, uses the final redirected
address, and reports unavailable/blocked/timed-out inspections without inventing
a low-risk result. It closes only its own inactive scan tab. A scan tab selected
by the user remains open. On the public website the action instead opens the
address for a separate toolbar inspection. Another security product may block
navigation first; do not bypass that block or credit it to PhishGuard.

The URL-only index adds **15 transport points for public HTTP addresses**,
independently of unobserved form fields. The result displays the contributing
categories. For example, `http://banamxr.com/1/mexico/` now shows **Caution,
15/100**, because it uses HTTP. This is a transport concern, not proof that the
address is currently phishing. A plain HTTPS address can still show zero observed
indicators; zero does not verify its owner, page content or live reputation.

The toolbar popup is **540 pixels wide**, with the verdict and next step side by
side. The on-page warning expands to **640 pixels** on desktop and still fits a
mobile viewport. The popup explicitly scores the **current browser tab**; a URL
pasted into the checker is a separate assessment. Reload the unpacked extension
and refresh existing tabs to use the updated popup and warning.

The credential-entry lab, second recipient, server, npm command and editable
sign-in forms are removed. The only new editable input is a URL. The original
fixtures retain read-only fields and CSP/JavaScript submission blocking.

## Close the warning

Use **Close ×** at the notification's top right. It dismisses the same warning
for this document without changing its score or toolbar verdict. Automatic
rescans do not immediately reopen it. **Check again** restores it; a changed
warning reason, new address or new document can show another warning.
This is not a persistent hostname exemption. Page-script `.click()` and
synthetic events cannot dismiss it. **Leave this page** remains available.

## Training and measured results

All **six local CSV files** were audited: **1,838,548 rows**, with **762,086
unique eligible URLs** after canonicalization, duplicate/conflict checks and
label filtering. Generic `bad` labels were not silently treated as phishing;
one million unreviewed popularity seeds were not promoted to verified legitimate
examples. No new feed URLs were downloaded for this experiment.

The 2 November experiment selected 120,000 records across source/class strata.
On 3 November, scheme removal was tested and rejected because recall and F1
fell. The larger experiment then added **190,947 fitting records** from the
remaining eligible local pool, excluding every tuning/calibration/test site.
It used **240,000 fitting URLs**, **18,595 tuning**, **29,994 calibration** and
**22,358 internal test URLs**: **310,947 records** in total.

Three full-URL character candidates (C=1, 2, 4) were declared before new test
scoring. Tuning selected **C=4** at the empirical 1% false-positive budget.
The winner was refitted on fitting plus tuning, then calibrated independently
at threshold **0.7668868036**. Test results did not select the candidate or its
threshold. Its browser export remains a separate **research diagnostic**.

| Metric | Previous C=2 | Expanded C=4 |
| --- | ---: | ---: |
| Accuracy | 90.12% | 92.57% |
| Precision | 98.31% | 98.21% |
| Recall | 80.42% | 85.79% |
| F1 | 88.47% | 91.58% |
| False-positive rate | 1.23% | 1.40% |
| True negatives / false positives | 11,677 / 146 | 11,658 / 165 |
| False negatives / true positives | 2,063 / 8,472 | 1,497 / 9,038 |

This is a **paired exploratory comparison on the same previously used internal
test**, not an untouched source/time-separated production evaluation. Accuracy,
recall and F1 improved; precision declined slightly and false positives increased.
The new model fixed 677 previous errors and introduced 130 errors on this set.
It is not an improvement to every metric and does not meet the release budget.

These percentages describe only the research model's high-risk threshold.
Its intermediate research band begins at 35/100 and does not count as a
positive phishing prediction in the table. Model estimates are ranking values,
not calibrated probabilities that credentials will be stolen.

The primary URL evidence and extension loaded-page verdicts **do not use this
model** or inherit these percentages. It still falsely scores genuine GitHub
and PayPal controls highly. Its output stays inside a separate collapsed
experimental diagnostic, with `deployment_eligible=false`. No domain is
hardcoded as safe and no criminal test URL is hardcoded as phishing.

The updated browser predictor matched sklearn within **3.34e-16** over **1,010**
cases, including Unicode/canonicalization boundaries. All 13 browser/Python
numeric URL features matched. This validates inference mechanics, not real-world
accuracy. Historical experiment artifacts are retained separately.

## 6 November research follow-up

The login-boundary candidate recorded 93.29% accuracy, 98.42% precision,
87.01% recall, 92.36% F1 and 1.22% false-positive rate on a reused internal test
after excluding known login development sites. It remains an offline research
experiment. The checker continues to show the 3 November expanded diagnostic
described above. Live page warnings use the 0.6.0 evidence policy.
[6 November comparison](audit/url-checker-research-2026-11-06-login-boundaries-comparison.json)

## Limits and next quality work

A URL-only model cannot inspect redirects, page content, form destinations or
JavaScript behavior. A trusted domain can be compromised, and a new phishing
address can look ordinary. The address-only preview therefore shows **Limited inspection** or **Caution**,
never a verified-safe certificate or a definitive phishing accusation based
only on a statistical score. The explicitly loaded-page inspection can display
the extension's SAFE/CAUTION/HIGH_RISK result with its evidence and coverage.

Further release work needs reviewed legitimate login/SSO examples and phishing
captures, representative campaigns, fresh source/time-separated tests and a
whole-policy evaluation. Re-labelling malware as phishing or popularity seeds
as verified legitimate pages would not establish better detection.

## Evidence and rebuilds

- [Data audit](../ml/reports/url-checker-data-audit-2026-11-03-expanded.json)
- [Compact model comparison](audit/url-checker-research-2026-11-03-expanded-comparison.json)
- [Browser parity/model metrics](audit/url-checker-model-2026-11-03.json)
- [Implementation audit](audit/score-popup-model-2026-11-03.md)

`scripts/train-url-checker.py` preserves completed experiments; future training
needs fresh output/version identities. `scripts/export-url-checker.py` verifies
estimator/extractor identities, exports the diagnostic predictor and checks
parity. `npm.cmd run build:url-checker` regenerates the shared URL extractor
from canonical extension sources. The Site packages only selected static assets
and this diagnostic predictor, excluding raw training URLs, Python estimators,
correction records, profiles and private configuration.

Full Python estimators and per-record training manifests stay local under
`ml/models/` and are excluded from new Git commits. The browser-ready research
diagnostic and compact measured reports are included, so using the extension
or running its regression tests does not require those local artifacts.

Published checker: https://phishguard-classroom-visual-lab.www-vikramsahu001.chatgpt.site/url-checker.html

For the loaded-page inspection action, open **Check another URL** from the
reloaded PhishGuard popup. The public page provides the address-only check.
