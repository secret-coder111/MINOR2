# PhishGuard 0.5.0

A college research project: a privacy-first Chromium extension that inspects URL,
DOM and credential-form structure locally and explains possible phishing indicators.

Version 0.5.0 adds recognition of explicit email/authenticator verification-code
prompts, more precise GET credential-exposure evidence, and redesigned popup,
warning and settings screens. See the [detailed review, changes and remaining
priorities](docs/audit/improvements-2026-11-02.md). These fixes address controlled
regressions; they do not establish a real-world accuracy percentage.

The [3 November score/UI repair and model comparison](docs/audit/score-popup-model-2026-11-03.md)
adds a wider popup and warning, explains HTTP URL-only score contributions, and
records expanded-data research results with their precision/recall tradeoff.

**Load the `extension` folder, not the project root.** No server, Python model
service or build step is needed to run the extension.

1. Open `chrome://extensions` in Chrome (`edge://extensions` in Edge).
2. Enable **Developer mode** and click **Load unpacked**.
3. Select `C:\Users\wwwvi\Desktop\MINOR2\extension`.
4. Pin PhishGuard from the toolbar Extensions menu and refresh the website tab.
5. Disable older PhishGuard copies loaded from other folders.

After source changes, click **Reload** on its extension card and refresh existing
website tabs. See [loading, demos and troubleshooting](docs/load-extension.md).

For a classroom presentation, run `npm.cmd run demo` in this project folder and
open **http://127.0.0.1:8080/**. The guide includes a normal login, a suspicious
destination, a combined high-risk example and a reset that demonstrates rescanning.
See [presentation steps and wording](docs/presentation-demo.md).
Each comparison now includes an animated, non-submitting credential journey
and an inspectable real title/form destination. The [professor guide](docs/professor-demonstration.md)
adds a five-minute script, examiner-controlled changes and independent public-test limits.
The **Public website comparisons** page includes external links, observed results,
local comparisons for all three bands, and a progress checklist. Browser/security
blocklist tests are labelled separately from PhishGuard's structural verdict.

The 0.4.0 update adds narrowly scoped lookalike-address protection for same-origin
HTTPS credential forms, clearer site/frame origins and next steps in the popup,
and a **Check again** button. A short, visible primary brand heading must match
the deceptive address and the same sensitive form before this new evidence can
raise a warning. Internationalized domains, provider buttons, shared hosting and
ordinary login forms do not activate it alone.

See the [source-based comparison of PhishLang, PhishDetect and commercial tools](docs/audit/competitive-methods-2026-10-27.md)
and the [implementation and verification report](docs/audit/improvements-2026-10-27.md).

## Detection behavior

The popup and banner share one canonical verdict:

- **No strong indicators:** ordinary login fields, CSRF inputs, validation code,
  incidental brand mentions and normal iframes do not independently warn.
- **Caution:** review a concern such as an external credential destination,
  insecure credential transport, or inconsistent brand identity.
- **High risk:** corroborating identity, destination and transport evidence, or
  an explicitly enabled reputation service's malicious verdict.

A score is a risk index, not a probability or guarantee. The default high-risk
threshold is 65; options can adjust it from 35 to 90. HTTP(S) frames are inspected
separately, with the most severe verdict used without summing unrelated frame
scores. SPA navigation and DOM changes trigger rescans; old results are rejected.

The 0.3.0 hardening release repairs the [tester audit](docs/audit/tester-audit-2026-10-25.md).
It recovers missing frames after background-worker restarts, detects CSS-only
credential reveals, inspects inherited HTTP(S) `about:blank`/`srcdoc` and blob
documents, and reports incomplete coverage explicitly. Visible-control checks
exclude collapsed legacy forms. Provider phrases, email recovery prompts and
individual brand claims have dedicated false-positive regressions. Reviewed
Google country domains and Indian-bank domain migrations are included as ownership
data, never as an exemption from other evidence.

Inspection starts at document start and analyzes available DOM on initial load,
before normal credential interaction, after mutations and on relevant rendering
changes. A visible-page poll checks up to 512 controls every three seconds;
truncation is disclosed. Arbitrary page scripts can still submit between checks.
See [repairs, verification and remaining limits](docs/audit/tester-repairs-2026-10-25.md).

## Machine-learning status

Historical URL tree and character models remain for research. They **do not
change browser verdicts in this release**: their training/calibration does not
match the corrected feature semantics or establish independent deployment accuracy.

The updated [ML workflow](ml/README.md) supports explicit URL-only/DOM modes,
connected-domain/content grouping, independent false-positive-budget calibration,
frozen future-test provenance checks and exact ensemble export. A representative
unseen login/SSO and phishing corpus is still needed before deploying a learned
model. Passing regression fixtures is not a real-world accuracy measurement.

Tree and character model selection now compares recall at the declared tuning
false-positive budget, rather than choosing only by overall ROC AUC. Independent
calibration remains separate from fitting and tuning. Any newly trained research
candidate remains disabled in the extension until the independent release gates pass.

New release gates require predefined recall and false-positive confidence bounds,
independent site/content groups, preserved source provenance and reviewed benchmark
composition. DOM captures bind HTTP status to the exact captured browser document.
`ml/src/review_benchmark.py` reports missing coverage before freezing a benchmark;
it does not manufacture labels or establish representative accuracy.

## Development checks

Use Node.js 22 or newer. The checkout already has installed test dependencies.

```powershell
npm.cmd ci
npm.cmd test
npm.cmd run audit:login
npm.cmd run test:demo
npm.cmd run test:browser
.\.venv\Scripts\python.exe -m unittest discover -s ml/tests -v
```

For a fresh setup, install `ml/requirements.txt` inside a Python virtual
environment. Python and npm are not needed merely to load the extension.

The pinned ICANN + PRIVATE domain list is bundled offline. See
[third-party notices](THIRD_PARTY_NOTICES.md) and `npm.cmd run vendor:psl`.

## Privacy and practical limits

Typed field values, passwords and cookies are not inspected. Optional reputation
is disabled by default and sends inspected hostnames only. Session tab results
omit URL paths/queries and are cleared when tabs close. Optional reputation shares
in-flight requests and retains bounded, expiring hostname verdicts in session
storage; disabling it clears those verdicts. Failed lookups are disclosed.
Corrections retain origins and coarse evidence/coverage context. Options supports
explicit review/export for independent verification; corrections never automatically
change predictions. See [privacy details](docs/privacy-policy.md).

Current coverage limits include unknown/compromised brand domains, visual-only
deception, arbitrary script data flow, closed shadow roots and opaque sandbox/data
documents. Inherited-origin blank/srcdoc documents are inspected when a trusted
HTTP(S) origin is available. Internal/protected browser pages may disallow injection.

See [architecture](docs/architecture.md),
[the original audit](docs/audit/phishguard-audit-2026-10-24.md), and
[implementation and verification](docs/audit/improvements-2026-10-24.md).
The [25 October follow-up review](docs/audit/improvements-2026-10-25.md) records
additional fixes, validation and remaining limitations.
See also [the second review and public-demo verification](docs/audit/remaining-flaws-2026-10-25.md).
