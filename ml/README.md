# PhishGuard ML baseline

This directory contains the Python feature contract and the first reproducible URL-only model.

## Dataset

The training script downloads the public `Using-machine-learning-to-detect-malicious-URLs` CSV from GitHub. It contains raw URLs with `good` and `bad` labels. The downloaded file is stored locally at `ml/data/malicious_urls.csv` and should be treated as an external dataset, not as user browsing data.

## Train

From the repository root:

```powershell
python -m pip install -r ml/requirements.txt
python ml/src/train_model.py --balanced --limit 100000 --output ml/models/url-tuned-ensemble-v0.3.0.json
python ml/src/train_model.py --include-edgephish --balanced --limit 100000 --model-version url-multidataset-tuned-v0.4.0 --output ml/models/url-multidataset-tuned-v0.4.0.json
python ml/src/export_browser_model.py --metadata ml/models/url-multidataset-tuned-v0.4.0.json --model ml/models/url-multidataset-tuned-v0.4.0.joblib --output extension/src/shared/trained-model-data.js
python ml/src/fetch_feeds.py --openphish --phishtank --output ml/data/recent_phishing_feeds.csv
python ml/src/fetch_feeds.py --umbrella --output ml/data/recent_legitimate_feed.csv
python ml/src/train_model.py --include-edgephish --additional-dataset ml/data/recent_phishing_feeds.csv --additional-dataset ml/data/phishtank_recent.csv --balanced --limit 100000 --model-version url-multidataset-feeds-tuned-v0.5.0 --output ml/models/url-multidataset-feeds-tuned-v0.5.0.json
python ml/src/train_char_model.py --include-edgephish --additional-dataset ml/data/recent_phishing_feeds.csv --additional-dataset ml/data/phishtank_recent.csv --balanced --limit 100000 --model-version char-url-tfidf-feeds-v0.2.0 --output ml/models/char-url-tfidf-feeds-v0.2.0.json
python ml/src/export_browser_model.py --metadata ml/models/url-tuned-ensemble-v0.3.0.json --model ml/models/url-tuned-ensemble-v0.3.0.joblib --output extension/src/shared/trained-model-data.js
python ml/src/export_browser_char_model.py --metadata ml/models/char-url-tfidf-feeds-v0.2.0.json --model ml/models/char-url-tfidf-feeds-v0.2.0.joblib --output extension/src/shared/trained-char-model-data.js
```

The `--balanced` option samples the same number of legitimate and malicious URLs. `--include-edgephish` adds the MIT-licensed EdgePhish-5G URL corpus. URLs are normalized, deduplicated, and conflicting labels are removed before sampling. The trainer compares logistic regression with multiple random forest and extra trees configurations, tunes hyperparameters and the F1 threshold on a validation split, and evaluates the winner once on an untouched test split.

## Current selected model

The multi-dataset tuned run used 100,000 deduplicated balanced rows and selected `random_forest_tuned_2`. Final untouched-test results:

- Accuracy: 0.8739
- Precision: 0.8982
- Recall: 0.8434
- F1: 0.8699
- ROC-AUC: 0.9451

These results are a held-out benchmark, not a production security claim. The next step is evaluating on a separate source or time-based test set before replacing the deterministic browser scorer.

## Current-feed evaluation

Evaluate a historical model against current phishing and legitimate snapshots:

```powershell
python ml/src/evaluate_time_split.py --model ml/models/url-multidataset-tuned-v0.4.0.joblib --metadata ml/models/url-multidataset-tuned-v0.4.0.json --dataset ml/data/recent_phishing_feeds.csv --dataset ml/data/phishtank_recent.csv --dataset ml/data/recent_legitimate_feed.csv --limit 100000
```

The old evaluator balanced the future data and only supported the numeric estimator artifact. The replacement `future_test_protocol.py` retains every phishing row, caps legitimate rows only, supports both numeric and character-model bundles, checks cross-class domain overlap, reports confusion-matrix/FPR/FNR/MCC/PR-AUC metrics, and reports whether DOM features are present. The current feed is a future/source-separated test set and must not be added to training before evaluation.

Run a future test without dropping phishing URLs:

```powershell
python ml/src/future_test_protocol.py --model ml/models/url-multidataset-tuned-v0.4.0.joblib --metadata ml/models/url-multidataset-tuned-v0.4.0.json --phishing-dataset ml/data/recent_phishing_feeds.csv --phishing-dataset ml/data/phishtank_recent.csv --legitimate-dataset ml/data/recent_legitimate_feed.csv --legitimate-limit 100000 --output ml/reports/future-handcrafted.json
python ml/src/future_test_protocol.py --model ml/models/char-url-tfidf-feeds-v0.2.0.joblib --metadata ml/models/char-url-tfidf-feeds-v0.2.0.json --phishing-dataset ml/data/recent_phishing_feeds.csv --phishing-dataset ml/data/phishtank_recent.csv --legitimate-dataset ml/data/recent_legitimate_feed.csv --legitimate-limit 100000 --output ml/reports/future-character.json
```

The DOM report is intentionally part of every future evaluation. URL feeds without HTML should show zero DOM coverage rather than silently suggesting that DOM signals were tested. DOM work must therefore use a separately captured, labeled HTML/screenshot corpus and an untouched future page set.

## DOM capture and training

DOM generalization must be measured on captured pages, not manufactured by filling URL-only rows with zero DOM values. The capture format is JSONL with `url`, `label`, `title`, `html`, `final_url`, `redirect_count`, and `source` fields. Keep collection, training, and future-test sources separate by registrable domain.

The optional Playwright collector runs in a fresh headless context. It does not submit forms, accept permissions, enable downloads, reuse cookies, or visit private/loopback IP addresses. Review the URL list before collection and run it in an isolated environment:

```powershell
python -m pip install playwright
playwright install chromium
python ml/src/capture_dom_snapshots.py reviewed_urls.csv ml/data/dom_snapshots.jsonl --limit 500
python ml/src/dom_dataset.py ml/data/dom_snapshots.jsonl --report ml/reports/dom-dataset.json
python ml/src/train_dom_model.py ml/data/dom_snapshots.jsonl --model-version dom-aware-v0.1.0 --output ml/models/dom-aware-v0.1.0.json
python ml/src/export_browser_model.py --metadata ml/models/dom-aware-v0.1.0.json --model ml/models/dom-aware-v0.1.0.joblib --output extension/src/shared/trained-model-data.js
```

The validator rejects missing HTML, invalid labels, oversized snapshots, and cross-class registrable-domain overlap. Do not train on live-feed pages and then reuse those same pages as a future test. A useful first DOM corpus should contain separate legitimate and phishing examples for login forms, empty and same-origin form actions, cross-origin exfiltration actions, hidden iframes, external scripts, meta refreshes, obfuscated scripts, branded titles, non-login pages, HTTPS pages, redirects, and JavaScript-rendered forms.

## Browser integration

The generated model data is loaded by the service worker. The worker combines the trained URL score with the existing rule score and keeps the higher score. A high trained probability is only applied when at least two strong phishing signals agree, which prevents a generic login page from being escalated by the URL-only model alone.

The browser also contains the exported character n-gram model. It is used only at a high-confidence probability of 0.99, because the future-feed evaluation shows that lower thresholds create unacceptable legitimate-page false positives. It is a high-recall secondary signal, not a standalone verdict.

Future evaluation reports include operating points across thresholds. Use those
points to choose a warning threshold from an explicit false-positive budget; do
not select a production threshold from F1 on a balanced historical split.

The extension also performs a conservative front-page analysis. Root and landing paths
are checked for combinations of credential forms, hidden iframes, timed redirects,
obfuscated scripts, and tightly constrained brand claims. Ordinary homepage text,
normal external assets, or a legitimate login form alone do not trigger this signal.
Official brand domains are allowed through this layer unless high-confidence page
evidence is present. This page analysis is rule-based until a labeled HTML snapshot
corpus is available; URL-feed rows must not be used as fake DOM training examples.

Chrome does not expose its Safe Browsing verdict to ordinary extensions. PhishGuard therefore treats a Chrome interstitial as unavailable and never reuses a stale result for that tab. The extension can still use its own local URL, DOM, form, hosting, redirect, IP-like-host, and brand-impersonation rules on pages that Chrome allows to load.
