# PhishGuard model research and release checks

New Python estimators and full training manifests are local research artifacts
under `ml/models/`, excluded from Git. The extension includes its selected
browser diagnostic in `extension/demo/url-model.js`; compact results live in
`docs/audit/` and `ml/reports/`. Tests generate their own small estimators and do
not require large local experiment files. Historical files already tracked in
Git retain their existing storage configuration, including Git LFS where used.

## Release and research status

PhishGuard **0.6.0** uses the local evidence policy for live page verdicts. The
URL checker's experimental panel runs the **3 November expanded** character
TF-IDF and logistic regression model separately. Historical estimator names,
including `url-multidataset-hard-negatives-v0.6.0`, refer to research artifacts.
[Packaged diagnostic results](../docs/audit/url-checker-research-2026-11-03-expanded-comparison.json)

The **6 November login-boundary** experiment compared character text transforms,
regularization and official-login sample weights. Known official-login sites
were reserved for development and excluded from evaluation. Tuning selected
the host/path-boundary transform with C=4 and login weight 1. A separate
calibration set supplied the threshold. These comparisons used the same 22,095
previously inspected internal URLs after excluding those sites.

| Candidate and threshold | Accuracy | Precision | Recall | F1 | False-positive rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| 3 November model, original threshold | 93.12% | 98.24% | 86.79% | 92.16% | 1.36% |
| 3 November model, recalibrated at the same budget | 92.65% | 98.45% | 85.59% | 91.57% | 1.18% |
| 6 November login-boundary candidate | 93.29% | 98.42% | 87.01% | 92.36% | 1.22% |

The new candidate's counts were 11,650 true negatives, 144 false positives,
1,338 false negatives and 8,963 true positives. Its internal-test false-positive
rate had a 95% Wilson upper bound of 1.44%. The experiment remains offline with
`browser_inference_supported=false` and `deployment_eligible=false`.
[6 November comparison](../docs/audit/url-checker-research-2026-11-06-login-boundaries-comparison.json) ·
[Data audit](reports/url-checker-research-2026-11-06-login-boundaries-data-audit.json)

The offline regression suite checks dataset integrity, the 29 named browser/Python
features, exact estimator serialization, browser inference and release gates.
Representative live-extension performance still requires a reviewed, independent
benchmark.

## Environment and verification

Run from the repository root with Node.js 22+ and Python. Node's offline WHATWG URL parser canonicalizes dataset URLs in batches, including unusual IP notation, Unicode paths and modern IDNA. It never visits the URLs. Case-sensitive paths, queries and fragments are preserved.

```powershell
python -m pip install -r ml/requirements.txt
python -m unittest discover -s ml/tests -v
```

`ml/requirements.txt` pins the estimator environment used for the checks. Joblib artifacts are executable Python objects: load only locally trusted training outputs. Changing the library versions or extractor sources requires a fresh artifact identity, calibration and evaluation.

## Dataset rules

- CSV inputs require `url` and `label`/`type`. Default positives mean phishing (`1`, `phishing`); negatives include `0`, `benign`, `legitimate`, `good`, `safe`. Broad `bad`/`malicious`/`malware`/`defacement` labels are excluded unless `--include-other-threats` explicitly changes the scope to mixed threats. Such a model cannot qualify as a phishing-specific release.
- Umbrella popularity imports are sampling seeds with an empty `label` and `label_status=unreviewed_popularity_seed`. Popularity does not establish a safe site/page. Review each intended sample, supply its actual label and set `label_status=reviewed` before capture/training. Existing `umbrella-top-1m` rows also require that explicit review marker; their historical automatically generated legitimate labels are not accepted as ground truth. Other explicitly unreviewed rows are excluded by CSV readers and rejected by snapshot validation.
- Conflicting labels for the same normalized URL are quarantined permanently within the load, including good/bad/good sequences. DOM snapshots reject conflicts and different captures for one normalized URL for review; identical repeated observations are counted once. Future evaluation also deduplicates identical inputs before sampling/counting, and rejects ambiguous observations. URL paths are never lowercased for deduplication.
- Grouping uses the pinned complete ICANN and PRIVATE Public Suffix List shared with the browser. Original and redirected final sites form connected groups. Exact duplicate HTML connects groups too. Mixed-label sites can be valid; all their records stay in the same partition. Template/near-duplicate and labeling review are still needed for a real corpus.
- Optional reviewed `campaign_id` and `template_group` annotations connect related examples across sites. Keep connected records together when splitting. Unannotated campaigns still require review.
- Preserve actual provenance in `source` and timezone-aware ISO `observed_at`. Renaming a file does not establish an independent source. The shared attribution reader preserves `source_provenance=filename_fallback`, `missing` and unknown classifications through CSV, feed-export and JSONL round trips. A nonempty source column cannot overwrite an existing weaker classification. These samples can be used for exploratory research but cannot pass source/time release checks. Version 3 manifests hash review evidence and document-response identity as well as labels/features, count explicitly identified sources and compare source names without casing/whitespace differences. Old frozen manifests need a new reviewed collection/release; do not rewrite them to qualify. Do not reuse feeds from old training as an untouched future test.
- Current URL CSVs do not observe DOM. A URL-only model has an explicit 13-feature subset of the stable 29-feature browser contract; absent page data is never supplied as observed harmless DOM zeros.

## Train a research URL model

No dataset is downloaded unless `--refresh` is explicitly supplied. A representative phishing-specific labeled CSV is required; the old good/bad corpus needs the mixed-threat flag and remains unsuitable for phishing-specific deployment.

```powershell
python ml/src/train_model.py --dataset reviewed-training.csv --additional-dataset reviewed-legitimate-logins.csv --fpr-budget 0.01 --model-version url-compact-v1 --output ml/models/url-compact-v1.json
```

The trainer reserves four site/content-disjoint partitions: fit, tuning, calibration and internal test. It compares compact 32-tree candidates by **phishing recall at the declared empirical FPR budget on tuning data**, rather than global ROC AUC. A candidate with attractive overall AUC may still miss every phishing page at the low-FPR operating point. Ties prefer fewer false positives, then average precision and ROC AUC. A candidate that cannot meet the tuning budget at any threshold in [0, 1] is reported as infeasible; malformed probabilities fail validation, and if every candidate is infeasible, training stops. The selected model is fitted on fit+tuning, and a **fresh threshold** is selected using only the independent calibration partition. Tuning thresholds are recorded for comparison and never reused as the final threshold. No refitting happens after calibration.

Reports retain each candidate's operating-point metrics and its separate default-0.5 metrics, plus the selection contract, confusion matrices, recall/FPR Wilson 95% intervals, average precision and positive-class prevalence. Average precision depends on class prevalence, so balanced research samples must not be presented as deployment precision. The tuning intervals describe sampling uncertainty and are not adjusted for searching models/thresholds. An internal grouped test is not a source/time-separated future test, and the empirical budget is not a statistical guarantee. Small calibration/test sets can have wide intervals even with zero observed false positives. This selection change aligns training with the intended warning budget; it does not itself establish improved real-world accuracy.

The saved metadata includes feature scope/version/hash, actual extractor source hash, exact joblib hash, full ensemble size and identity manifests for every partition. All research outputs start with `deployment_eligible=false`.

## Captured DOM data

Only collect a reviewed list in an isolated environment. No live criminal URLs are needed for regression tests. The optional Playwright collector does not click or submit forms, reuse prior-page cookies/storage, or grant permissions. Its URL/DNS guard rejects non-global addresses, including private, loopback and shared CGNAT space. It blocks all non-GET/HEAD requests and WebSockets and marks affected captures partial for review. WebSocket blocking requires [Playwright 1.48 or later](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route-web-socket). It runs website JavaScript, which can initiate GET requests; external resource loading and public network contact are intrinsic to capture. DNS checks alone cannot prevent DNS rebinding, and browser networking is not an OS-level egress firewall: isolate the collector and restrict local-network access outside the browser too. This is not a malware sandbox. Input values and textarea contents are redacted from stored HTML. Install Playwright separately only when capture is intended.

```powershell
python -m pip install "playwright>=1.48"
playwright install chromium
python ml/src/capture_dom_snapshots.py reviewed_urls.csv ml/data/new-dom-capture.jsonl --limit 500
python ml/src/dom_dataset.py ml/data/new-dom-capture.jsonl --report ml/reports/new-dom-dataset.json
python ml/src/dom_dataset.py ml/data/new-dom-capture.jsonl --split-dir ml/data/new-dom-release
python ml/src/train_dom_model.py ml/data/new-dom-capture.jsonl --fpr-budget 0.01 --model-version dom-research-v1 --output ml/models/dom-research-v1.json
```

Snapshots require valid original/final HTTP(S) URLs, nonempty bounded HTML, successful 2xx status, `capture_success=true`, a timezone-aware capture date and `capture_quality=ok`. Common challenge titles are marked for review, but automatic checks cannot establish that captured content has the source URL's intended label. Review challenge/error pages, redirects and labels manually. The validator does not silently treat capture failures as clean pages.

The collector records the actual browser's numeric `feature_row`, schema version and source hash. Extraction runs in a fresh Chromium CDP isolated world, observing the same live DOM with separate JavaScript globals/prototypes. A page replacing its main-world DOM APIs cannot forge the collector's feature values through those replacements. Features, HTML, title and final URL are read in one synchronous document snapshot; a navigation during capture invalidates the sample. `capture_execution_world=isolated` records this execution context. This protects extraction integrity; it does not isolate network access or stop a page changing its own visible content.

HTTP status now comes from a `Network.responseReceived` document response observed before navigation and matched to the snapshot's exact CDP `(frameId, loaderId)`. The collector checks the loader before and after extraction, records `navigation_response` plus `capture_document_status=bound_to_loader`, and rejects missing identity. A completed JavaScript redirect to a 404 is recorded as 404 and rejected as a training sample; an old 200 response from `goto()` cannot bless it. Reloading the same URL also changes loader identity. Same-document `history.pushState` retains the document's actual navigation response. `redirect_count` describes the HTTP redirect chain for that captured document. Legacy snapshots without binding can still be inspected/explored, but cannot enter new DOM training or a release benchmark; recapture them.

Snapshot validation rejects stale extractor/policy identities, nonnumeric values (including booleans), inconsistent numeric/policy rows and negative/noninteger redirect counts before releasing splits. DOM training requires these captured features and uses the final document URL; original URL/redirect metadata remain for grouping. Character models also train and evaluate the final document URL to match browser inference after redirects. The static Python HTML extractor has shared golden tests and correct void/hidden/form/accessible-label handling, but cannot reconstruct external CSS, layout, JavaScript state or all HTML5 repair rules. It is a fixture/research fallback, not a substitute for observed rendered features. Shadow DOM and frame composition require separate representative coverage.

`--split-dir` writes fit/tuning/calibration/test JSONL files and SHA-256 identity manifests into a new empty release directory. The trainer also records its deterministic split manifests. Preserve the initial release and seed; changing or repeatedly inspecting the test makes it development data.

## Freeze and evaluate an independent test

Collect independently sourced, later-observed, site/content-disjoint data. Include substantial legitimate login, SSO, bank, college, payment and non-login coverage with reviewed labels. Freeze its identity before training/model selection and reserve the same manifest in the trainer. Use separate CSVs (or validated JSONL snapshots) for each class.

```powershell
python ml/src/future_test_protocol.py --phishing-dataset reviewed-future-phishing.csv --legitimate-dataset reviewed-future-legitimate.csv --freeze-manifest ml/reports/reserved-test.json
python ml/src/train_model.py --dataset reviewed-training.csv --reserved-test-manifest ml/reports/reserved-test.json --fpr-budget 0.01 --output ml/models/url-compact-v1.json
python ml/src/future_test_protocol.py --model ml/models/url-compact-v1.joblib --metadata ml/models/url-compact-v1.json --phishing-dataset reviewed-future-phishing.csv --legitimate-dataset reviewed-future-legitimate.csv --test-manifest ml/reports/reserved-test.json --output ml/reports/reserved-test-result.json
```

Evaluation verifies the frozen record/label/feature identity, exact model and metadata hashes, original reserved freeze timestamp, and development-versus-test URL/site/content/source/date separation. Freeze/training dates must have timezones and cannot be in the future; test observations must already exist when their manifest is frozen. It keeps valid mixed-label domains rather than deleting legitimate examples to improve a metric. A receipt prevents the CLI from reusing the same frozen holdout for later model decisions. Previously viewed or reused data is exploratory; `--exploratory` labels its report accordingly and cannot qualify a release. A protocol cannot prove that human source labels are honest or that an analyst has never inspected a test: maintain collection and experiment records too.

Use `--representative-login-reviewed` only after independently reviewing that the test composition actually covers representative legitimate login/SSO pages and labels. This is a human provenance assertion, not an automatic claim. Evaluate the final extension policy separately as well as the model before presenting system-level results.

## Reviewed benchmark and release targets

There is still no representative captured benchmark in this checkout. The tests demonstrate repairs to the machinery; they do not measure deployed precision, recall, FPR or an accuracy improvement. No historical learned model has been activated by these changes.

The predeclared targets in `ml/src/release_contract.py` are saved in metadata before training. Decision-eligible export requires both page and conservative independent-group FPR upper Wilson 95% bounds at or below the calibration budget, which may not exceed **1%**, and recall lower Wilson 95% bounds of at least **80%**. It also requires at least **400 independent legitimate groups**, **100 independent phishing groups**, two reviewed sources per class, and at least 20 reviewed legitimate records in each of `login`, `sso`, `banking`, `education`, `payment`, `non_login`. These are acceptance targets chosen for this project, not measured performance or a universal security standard. Passing minimum counts alone does not guarantee passing the confidence bounds.

An independent group connects original/final registrable sites and exact HTML copies. Any warned legitimate page is a group false positive; any missed phishing page makes that group's phishing outcome a miss. This prevents 400 paths on one site from pretending to be 400 independent trials. Reviewers must also identify shared campaigns and near-duplicate templates that exact grouping cannot detect.

For every benchmark row, retain `label_status=reviewed`, `reviewed_by`, timezone-aware `reviewed_at` after the observation, `label_evidence` explaining the label, explicit source attribution, and `page_type`. Review the actual captured document after capture; a seed URL reviewed before capture is insufficient. Complete reviews before freezing: verified evaluations reject review timestamps later than the frozen manifest. DOM release checks validate the response/loader evidence and captured numeric features, not only a binding marker, including for direct Python callers. Keep evidence brief and exclude credentials or personal page contents. Include independent phishing campaigns, same-site harvesting, hosted content, brand impersonation, JavaScript/dynamic forms and embedded flows. Locale, device and browser coverage must reflect the intended users. Quotas and a check box cannot establish that sampling is representative.

```powershell
# Checks composition and review records without fitting or scoring a model.
python ml/src/review_benchmark.py reviewed-policy-captures.jsonl --require-dom --output ml/reports/policy-composition.json

# Only a complete reviewed collection can be frozen by this command.
python ml/src/review_benchmark.py reviewed-future-phishing.jsonl reviewed-future-legitimate.jsonl --require-dom --output ml/reports/future-composition.json --freeze-manifest ml/reports/reserved-test.json
```

The tool reports missing evidence/coverage rather than inventing labels or data. Use new output paths. Preserve the frozen files and hashes, reserve that manifest before training, and evaluate once. Subsequent model/policy decisions require a fresh untouched test. Release reports now include `benchmark_review`, `independent_group_metrics` and `release_gate`; the exporter recalculates confidence bounds from confusion counts rather than trusting copied interval fields. A constant all-safe classifier fails the recall gate even with zero false positives and a supplied representative-login assertion. Diagnostic export remains available for research.

## Evaluate the local extension verdict policy

The collector also saves whitelisted numeric `policy_features`, including each actual credential submission context, plus the policy version/source hash. These richer features are necessary: combining an SSO form's external destination with another form's GET method would manufacture corroboration. Snapshot record hashes cover these features and labels.

```powershell
python ml/src/evaluate_policy.py reviewed-policy-captures.jsonl --warning-threshold 65 --output ml/reports/policy-exploratory.json
```

This executes the actual shipped JavaScript policy offline and evaluates canonical `HIGH_RISK` warnings rather than assigning labels from score bands. It reports warning FPR/recall and 95% intervals, separate CAUTION-or-HIGH rates, and source/page-type breakdowns. It requires valid successful reviewed captures with current numeric/rich feature and extractor/policy identities. Its scope is the local document verdict; reputation services, frame aggregation, browser lifecycle and UI delivery need integration tests.

Results are explicitly exploratory by default. A source/time-separated claim additionally requires `--frozen-manifest`, `--development-manifest` and `--policy-lock`. The frozen test identity must match, exclude every development URL/site/content/source and have later capture dates. The policy lock JSON contains the actual `policy_sha256`, `extractor_sha256`, `warning_threshold` and timezone-aware `locked_at`; freeze the unseen test before policy selection is locked. Evaluation rejects a threshold different from the locked setting. The CLI writes a receipt and refuses reuse. Preserve collection/selection records: manually writing a lock or changing source names cannot establish that a test was unseen. No accuracy claim follows from the synthetic regression fixtures.

To assess policy release readiness, also include `fpr_budget` (at most `.01`) and the exact `release_requirements()` object in the policy lock before evaluation. Reports without this predeclared contract remain usable for analysis but their release gate fails. The policy evaluator reports the same conservative independent-group metrics and review composition as the model evaluator. Policy scores remain an uncalibrated evidence index, never a phishing probability. Runtime frame aggregation, reputation, interaction timing and warning delivery still require separate browser tests.

For development captures, `--ablations` reports the effect of removing evidence
families from the JavaScript policy. The evaluator rejects ablations on a
frozen release holdout. [Policy evaluation code](src/evaluate_policy.py)

## Export the exact predictor

```powershell
# Offline diagnostics only; runtime must not use it for verdicts.
python ml/src/export_browser_model.py --metadata ml/models/url-compact-v1.json --model ml/models/url-compact-v1.joblib --output ml/models/url-compact-v1.diagnostic.js --diagnostic-only

# Only after the independent release evaluation and login review pass:
python ml/src/export_browser_model.py --metadata ml/models/url-compact-v1.json --model ml/models/url-compact-v1.joblib --evaluation-report ml/reports/reserved-test-result.json --output extension/src/shared/trained-model-data.js
```

The exporter never truncates trees. `--max-trees`, if supplied, asserts the trained count. If an artifact exceeds the byte budget, train a smaller ensemble and calibrate it anew. Export verifies schema/extractor/estimator identities, independent calibration and exact serialized inference against sklearn with float32 input casting. It writes the predictor hash, tree count, calibration and deployment status into the browser artifact. The regression suite additionally verifies the exported model through the real browser inference JavaScript.

Decision-eligible export requires the frozen separated report for that exact metadata/model, phishing scope, reviewed legitimate-login composition, the predeclared recall/coverage contract above, and page/group FPR 95% upper bounds within the configured budget. A missing/failed check is a reason to improve data/model evaluation, not to change metadata flags manually. The updated runtime does not load a diagnostic model automatically; integrating any qualified release also requires explicit runtime loading and full-policy validation.

The optional character n-gram trainer uses the same connected partitions, tuning recall-at-FPR selection for its regularization candidates, and independent final FPR calibration. Character export is explicitly diagnostic-only until browser Unicode/tokenization parity and representative evaluation are established. The historical hardcoded 0.99 decision threshold is no longer a release justification.

## Optional numeric and character ensemble research

`train_hybrid_model.py` compares complementary URL representations without a transformer or remote service: the 13 numeric URL features with 32-tree Random Forest/ExtraTrees models, and character TF-IDF 3–5-grams with balanced logistic regression. It predeclares 23 candidates: two numeric estimators, three character regularization values (`C=0.5,1,2`), and 18 convex probability blends with numeric weights `0.25,0.5,0.75`. Every candidate and each family winner is selected only on tuning recall within the empirical FPR budget. Numeric/character scores are correlated; their blend must never be treated as independent phishing evidence.

The chosen family models are refitted on fit+tuning; the character vocabulary is also learned only from those partitions. Each receives a fresh threshold from the separate calibration partition, then reports a grouped internal-test comparison and conservative independent-group metrics. No internal-test result selects or refits the winner. The same final redirected document URL is used by both numeric and character components. An unavailable operating point is reported rather than silently relaxing the budget. Reports cannot turn a previously inspected dataset into an untouched release evaluation.

```powershell
python ml/src/train_hybrid_model.py --dataset reviewed-training.csv --seed 42 --fpr-budget 0.01 --model-version hybrid-url-research-v1 --output ml/models/hybrid-url-research-v1.json
```

Outputs are always `research_only`, with `deployment_eligible=false`. The dictionary joblib bundle is predicted only through `train_hybrid_model.predict_bundle(bundle, records)` using locally trusted artifacts. Existing browser exporters deliberately reject this representation; the general frozen-test evaluator is not yet an inference path for it. There is no browser runtime integration, model activation, or claimed browser-tokenization parity. It needs an independently reviewed representative benchmark, verified browser inference and whole-policy evaluation before any deployment. A blend is a candidate to measure, not an assurance of improvement over either component.
