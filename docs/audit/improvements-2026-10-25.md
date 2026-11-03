# PhishGuard follow-up review - 25 October 2026

Reviewed the current working tree, including the previous day's uncommitted
improvements. This follow-up fixes additional reproducible issues; it does not
certify that every possible flaw has been eliminated.

## Additional findings and fixes

| Area | Verified flaw | Result |
|---|---|---|
| Credential recognition | Arbitrary input IDs and text-type password/OTP prompts could evade extraction; numbered names were missed. | Associated labels, ARIA names and placeholders are inspected without reading field values. Numbered names are recognized. Search help and generic prose regressions remain neutral. |
| Dialog forms | `method=dialog` erased credential context. | Visible requests for credentials are retained, without inventing a network destination. |
| DOM rescanning | A page could reuse the warning banner ID to suppress observation or have its own node overwritten. | The content script tracks extension-owned nodes instead of trusting IDs. Credential nodes inserted inside the warning still trigger inspection. |
| Reputation opt-out | Pending responses could outlive a setting change. | Setting changes abort requests immediately and stale responses are ignored. |
| Reputation parsing | A nonempty string such as `"false"` could become a malicious verdict. | Only the expected boolean malicious value is accepted. |
| Popup | Overlapping active-tab lookups could display an older tab. | Sequence checks preserve the latest result; missing tabs display Unknown. |
| Capture integrity | Stale extractor/policy identities, boolean features, invalid redirect counts and different observations of one URL could enter the dataset. | Explicit validation rejects these inputs before training or release. |
| Evaluation | Repeated inputs could inflate reported metrics; probabilities and class coverage needed validation. | Identical input observations are deduplicated; ambiguous repeats, invalid probabilities and incomplete class coverage are rejected. |
| Evaluation lock | A policy threshold could change after locking policy code; future lock times could be accepted. | Verified evaluation requires the locked threshold and valid timezone-aware provenance without future freeze/lock dates. |
| Redirect consistency | Character models used original URLs while browser/tree inference used final document URLs. | Character training and evaluation now use final document URLs. |
| Collection isolation | WebSocket traffic and shared/private address ranges needed stricter handling. | Capture explicitly blocks WebSockets and non-global addresses; external network isolation remains necessary. |
| Demo reliability | Old `validate-demo.js` duplicated stale extraction logic; fixtures had only a script-level submission guard. | The validator uses current tests/extraction. Fixtures now have browser CSP, a presentation guide and interactive rescan/reset scenarios. |

## Validation

- `npm.cmd test`: all **12 JavaScript test files passed** after the integrated changes.
- `.\.venv\Scripts\python.exe -m unittest discover -s ml/tests -v`: all **13 Python tests passed**, including **24 browser/Python golden fixture comparisons**.
- `node validate-demo.js`: ordinary login, external destination, brand + external destination, reset, selection state and submit cancellation passed.
- Local Node demo server: fixture GET/HEAD works; POST and traversal requests are rejected.
- Isolated Edge **156.0.4314.42** smoke test passed: SPA changes, attribute
  corrections, frame warnings/removal, and the actual interactive demo all
  updated correctly. Demo sequence: **8 SAFE -> 43 CAUTION -> 88 HIGH_RISK ->
  8 SAFE**. Direct `form.submit()` was blocked by browser CSP; zero POST
  requests reached the fixture server. A placeholder-only change from a generic
  text field to a password prompt triggered high risk, and correcting it cleared
  the warning. See [browser smoke report](browser-smoke-results.json).

Tests use controlled HTML and synthetic machinery data. They measure regressions,
not production phishing accuracy. Historical reports remain dated evidence of
their earlier versions. Source hash changes invalidate older captures as intended.

## Remaining limits

- A representative unseen phishing and legitimate login/SSO dataset is still
  needed for real-world recall, FPR and model deployment. No new production model
  was trained and no accuracy improvement percentage is claimed.
- Static inspection cannot establish external-script credential exfiltration,
  visual deception, unknown/compromised brand ownership or behavior behind closed
  shadow roots and inherited `about:blank`/`srcdoc` documents.
- A webpage can alter its own DOM, including an in-page warning. Use the extension
  popup as the independent verdict surface.
- The optional Playwright collector is not installed here. Route protections
  were regression tested with mocks; live capture was not verified. DNS rebinding
  and other network channels require an isolated machine/container and external
  egress controls for untrusted collection.

See [presentation steps](../presentation-demo.md) for a repeatable classroom demo.
