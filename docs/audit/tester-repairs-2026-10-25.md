# Tester audit repairs — PhishGuard 0.3.0 — 25 October 2026

This is the implementation follow-up to `tester-audit-2026-10-25.md`. All fourteen
reproduced implementation/workflow defects have corrective code and regression
coverage. The ten additional limitations were addressed through expanded
inspection, honest coverage, safer evaluation and feedback workflows; some remain
fundamental detection boundaries and are listed individually below. This is not a
claim that every possible bug or phishing technique has been eliminated.

Existing unrelated working-tree changes and historical model/audit artifacts were
preserved. No model was activated, no live malicious URL was needed, and no
production accuracy improvement percentage is claimed.

## Fourteen defect repairs

| Audit ID | Implemented correction | Verification |
|---|---|---|
| B01 | The worker inventories live documents and requests missing frame results on cold reconstruction and popup access. Pending/unknown coverage is explicit; stored tab summaries are not blindly restored as current verdicts. | Worker regression and **actual Edge worker termination** followed by a top-only mutation; the static risky child is recovered. |
| B02 | A visible-page rendering watch detects CSSOM-only control reveals. Stylesheet/frame loads, details toggles, resize, slot/open/metadata changes and normal credential interaction trigger rescans. Periodic layout work is capped at 512 controls and truncation is disclosed. | Real Edge hidden password → stylesheet `insertRule` reveal → automatic **HIGH_RISK 88**, with no forced rescan. |
| B03 | Unexpired hostname reputation is applied before publishing each fresh local scan. Valid available reports survive worker restarts in session storage. A threshold-only settings change retains same-service reports. | Same-host rescan and worker restart retain malicious High risk; opt-out still aborts requests and ignores late responses. |
| B04 | Provider phrases recognize common articles/pronouns (`a`, `an`, `the`, `your`, `my`) without treating provider mentions as page ownership. Independent ownership claims remain visible. | Original `Sign in with a Google Account` fixture changes **80 HIGH_RISK → 35 CAUTION**; provider/article variants and a separate PayPal claim are covered. |
| B05 | Credential metadata distinguishes an identity/email request from explanatory password-recovery prose, while concrete password type/autocomplete evidence remains decisive for field recognition. | Original recovery-email fixture changes **70 HIGH_RISK → 35 CAUTION**; email, named reset fields, labels and text-type password prompts are covered. |
| B06 | Brand ownership is checked per claim; a platform's legitimate brand cannot cancel another claimed identity. New body claims are additionally scoped to their credential flow. | Original hosted PayPal fixture changes **35 CAUTION → 80 HIGH_RISK**. Unrelated forms cannot borrow another form's body identity claim. |
| B07 | Ownership mappings include the reviewed Google supported-domain list and verified ICICI/HDFC/SBI/Axis `.bank.in` migrations, mirrored in Python. Domain suffix boundaries remain exact; these are ownership facts, not safety exemptions. | Country-domain and bank-domain regressions pass; lookalike suffixes and suspicious actions on an owned domain still contribute evidence. |
| B08 | Shared rendered-control checks handle native browser visibility, collapsed details, closed dialogs, content-visibility, composed hosts/slots, hidden/inert ancestry and submitter visibility. | Real Edge closed details **SAFE**, opening it **HIGH_RISK**, closing it **SAFE**. Related extractor regressions pass. |
| B09 | Shared source identity logic preserves filename-derived/unknown provenance across CSV, JSONL, feeds and capture. Manifest identity includes review and captured-document evidence. | CSV round-trip retains weak provenance and cannot upgrade it into verified source separation. |
| B10 | Training records a predefined release contract. Export independently requires page and independent-group FPR/recall confidence bounds, sufficient independent classes, and reviewed composition. | Actual constant/all-negative model export is rejected despite zero false positives and a supplied review assertion. |
| B11 | Capture observes document network responses before navigation and binds status to exact frame/loader identity. Navigation during extraction, missing binding and legacy unbound DOM training captures are rejected. | Mocked final-404/same-URL-reload regressions and **real Edge 200 → script navigation → 404 network events** fed to the actual collector binder return final status **404**. |
| B12 | Options and worker reject credential-bearing, fragmented or unsupported reputation endpoints. The popup displays pending/error coverage instead of silently implying a remote verdict. | UI failure regressions plus real Edge unusable-endpoint rejection and valid local-settings save. |
| B13 | Identical endpoint/hostname requests share in-flight work. Bounded TTL caching, four concurrent requests and thirty new requests per minute per worker lifetime limit repeat traffic. The in-memory rate counter restarts with the worker; available session-cache verdicts still avoid repeat requests. Late old generations cannot delete newer requests. | One hundred same-host worker scans produce **one** request. Cache/revision/opt-out regressions pass. |
| B14 | Storage helpers check callback `runtime.lastError` and Promise rejection. Saves, review state, deletion and export report success only after the relevant operation completes. | Failure mocks never announce success; real Edge settings/review/deletion flows pass. |

Relevant implementation: `extension/src/background/service-worker.js`,
`extension/src/content/content-script.js`, the three feature extractors,
`extension/src/shared/{document-context,model-policy,browser-api,feedback}.js`,
popup/options, and `ml/src/{dataset_contract,capture_dom_snapshots,dom_dataset,
train_model,future_test_protocol,release_contract,export_browser_model}.py`.

## Work on each additional limitation

| Limitation | Change made | Remaining boundary |
|---|---|---|
| L1: same-origin HTTPS harvesting | Preserve explicit unverified identity wording, avoid a safety guarantee, make optional reputation reliable, and require this attack class in reviewed evaluation. | A generic first-party HTTPS password form can still score 0: its structure alone does not reveal whether its owner is dishonest. Treating every unfamiliar login as phishing would manufacture false positives. |
| L2: body-only identity | Short rendered primary brand/authentication headings near sensitive UI now contribute identity evidence; article/nav/footer/comment/provider mentions are excluded. Evidence is scoped per credential flow. | The original body-only PayPal fixture now gives **45 CAUTION**. A single identity category deliberately does not establish High risk. Logos/images/canvas and arbitrary prose remain outside reliable ownership inference. |
| L3: JavaScript destinations | Pre-interaction scans and live form/DOM/render observation reduce stale observation. Static script activity stays diagnostic; declared destinations are never presented as proven runtime data flow. | Arbitrary inline/external script exfiltration, compromised websites and destinations constructed at runtime are not solved by static metadata. A `fetch` token is not proof of theft. |
| L4: default GET | Added conservative native GET evidence for cross-site, named sensitive controls with a native submit path and no static signs of interception. | The original native missing-method case now gives **70 HIGH_RISK**. Ambiguous Ajax/default forms remain conservative; scripts can alter behavior and an attacker can suppress a static heuristic. |
| L5: inaccessible/custom UI | Added inherited HTTP(S)-origin about:blank/srcdoc/blob inspection with browser-supplied sender-origin validation. Added editable textbox metadata recognition without reading contents. Missing documents and unknown inherited destinations are disclosed. | Opaque sandbox/data documents, closed shadow roots and protected browser pages can remain uninspected. Custom editors establish a prompt, not a proven submission target. |
| L6: vocabulary | Expanded reviewed owner domains and card/security-code/expiry metadata. Provider prose and field intent are checked to limit newly introduced false positives. | Unknown brands, languages, visual prompts and uncommon widgets need representative coverage. Nine brand names still form a bounded ownership vocabulary. |
| L7: absent benchmark | Added `review_benchmark.py`, reviewed composition requirements, capture/review/freeze timeline checks, independent-group metrics and a readiness report on existing seeds. | Existing 32 URL seeds yield 29 legitimate groups and zero phishing groups; they are not a representative captured-policy benchmark. No production FPR/recall is established. |
| L8: uncalibrated score | Versioned the policy; kept the score explicitly a risk index. Model/policy release reports now enforce predefined confidence and composition criteria rather than letting a low FPR hide zero recall. | Rule weights remain uncalibrated. Release targets are engineering acceptance criteria, not achieved performance or a universal security standard. Historical models remain disabled. |
| L9: inert feedback | Corrections now retain sanitized top/evidence origins and coarse context. Options supports explicit review and export of checked candidates, confirms storage outcomes and marks exports unverified/no automatic learning. | Corrections intentionally do not auto-train or allowlist sites. User annotation needs independent ownership/label verification; privacy-limited origins cannot reconstruct the exact page later. |
| L10: asynchronous advisory warnings | Injection starts at document start; analysis runs on available initial DOM, normal credential interaction, native submit events, relevant mutations/render changes and restored pages. Popup coverage and remote status are explicit. | The detector does not guarantee prevention or block arbitrary script submission. The page owns the banner's DOM, while the popup is an extension surface. The collector is not an OS/network malware sandbox. |

## Runtime behavior and privacy details

- Numeric schema names/order remain **0.2.0**; policy/runtime/package are
  **0.3.0**. Extractor hashes include the context helper and invalidate older
  incompatible captures even when the numeric vector order is unchanged.
- Inherited-document browser identity remains the actual document URL. Only a
  matching trusted `MessageSender.origin` can establish its effective HTTP(S)
  security origin. HTML `<base>` never establishes ownership. Opaque documents
  are not assigned invented owners.
- Per-document scores are not added together. Recovery leaves a local low result
  visibly incomplete until pending frames answer. An existing child warning is
  not cleared merely because the recovering top document is low risk.
- Reputation is opt-in. Available malicious reports can be reused for ten
  minutes, safe/benign for five minutes and unknown for thirty seconds. Brief
  errors are cached in worker memory for fifteen seconds. Session cache holds at
  most 256 hostnames with timestamps and an endpoint digest, never endpoint API
  keys or browsing URL paths. TTL bounds reuse; physical expired records are
  pruned on cache load/write/clear and can otherwise last until session end.
  Disabling reputation clears the cache. Settings changes abort obsolete work.
- Reputation status is aggregated across frames, so a completed top lookup
  cannot hide pending/failed child lookups. A malicious report in one frame
  still warns even if another frame's lookup fails.
- No field values, editable user text, passwords or cookies are collected.
  Feedback exports contain origins and fixed coarse metadata, and require an
  explicit action. Storage/network errors do not become invented benign verdicts.

## Verification

The maintained regressions and the added audit counterexamples check behavior;
they do not measure deployment accuracy. Current verification commands are:

```powershell
npm.cmd test
.\.venv\Scripts\python.exe -m unittest discover -s ml/tests -v
npm.cmd run test:demo
npm.cmd run test:browser
git diff --check
```

The final verification summary is recorded in
`repair-verification-2026-10-25.json`. Browser evidence is
`browser-smoke-results.json`; benchmark readiness is
`repair-ml-benchmark-readiness-2026-10-25.json`.

New JavaScript regressions include `detection-repairs.test.js`,
`ui-feedback.test.js`, and expanded `runtime-integration.test.js`.
Python coverage includes `test_release_contract.py`, expanded capture/pipeline
contracts and **46 named browser/Python parity fixtures**. The real Edge suite
also exercises options/review storage and collector-world isolation. The
navigation check uses live browser events and the actual response binder; the
complete Playwright collection CLI/network routing is not installed or run here.

Historical `tester-*-probe` scripts assert or record the original faulty
behavior. They and their original JSON are preserved as dated evidence, not
current pass/fail checks. Use the maintained test commands above for this release.

## Use the updated extension

1. Open `chrome://extensions` or `edge://extensions`.
2. Click **Reload** on PhishGuard, or load
   `C:\Users\wwwvi\Desktop\MINOR2\extension` unpacked.
3. Confirm version **0.3.0** and refresh existing website tabs.
4. Keep the default threshold **65** for the controlled demonstration.
5. Run `npm.cmd run demo`, open `http://127.0.0.1:8080/`, and use the extension
   popup to see ordinary → caution → high risk → corrected ordinary behavior.

No Python/model service or build is required to load the extension. Review the
remaining boundaries before describing it as a production security detector.

## Ownership and platform sources

These sources support the domain/context implementation choices; spot-checking
them does not establish detection accuracy:

- [Google supported domains](https://www.google.com/supported_domains).
- [ICICI official website](https://www.icicibank.com/) and its bank.in destination.
- [Axis official website](https://www.axisbank.com/) and its bank.in destination.
- [SBI official redirect information](https://bank.sbi/redirect/).
- [HDFC website migration information](https://www.hdfc.bank.in/important-messages/all-new-website).
- [Chrome related-frame content-script injection](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts).
- [Chrome extension worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).
