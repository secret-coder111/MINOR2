# Classroom walkthrough and professor verification

Date: 2 November 2026. Detection policy remains PhishGuard 0.5.0.

Published read-only walkthrough:
https://phishguard-classroom-visual-lab.www-vikramsahu001.chatgpt.site
See [deployment evidence](classroom-deployment-2026-11-02.json).
The subsequent [hands-on demo update](hands-on-demo-2026-11-02.md) adds a
separate fixed-dummy local request lab and explicit AMTSO test recognition.
Its results supersede earlier AMTSO behavior described below.

## What changed

The ordinary, external-destination and brand-plus-external pages now contain an
interactive four-stage explanation. The same component follows scenario changes
on the existing interactive page.

1. Inspect the real browser origin and title.
2. Introduce fixed fictional email/secret tokens.
3. Follow the actual resolved form destination in an illustrative animation.
4. Explain the possible consequence and which evidence should be inspected.

Play/pause, previous/next and reset controls support a spoken presentation.
Recipients and addresses are visible. A recipient view shows only fictional
tokens. No input value is read, copied, transmitted, authenticated or stored.

The page-facts disclosure reads the real document title, origin and form action.
Its code preview is rendered as text. If a professor edits facts outside a preset
scenario, the narrative changes to a neutral Professor-edited page; it does not
invent the extension's result. The toolbar popup remains the verdict source.

All four pages retain read-only fields, submit-event cancellation, CSP
`form-action 'none'` and `connect-src 'none'`. The loopback server still rejects
POST. The animation never disables, hides or changes the extension warning.

The public comparison page adds a professor-controlled protocol. The new
`professor-guide.html` provides a short web presentation script and Q&A;
`docs/professor-demonstration.md` contains the detailed spoken version.

## The important conceptual distinctions

- A first-party form is ordinary context, not proof of legitimate ownership.
- A different destination can be authorized SSO/payment infrastructure or an
  unauthorized collector. Cross-site movement alone is inconclusive.
- A brand/address conflict combined with credential collection at another site
  supplies corroborating risk evidence in the demonstrated rule policy.
- HTTPS encrypts transport to the selected recipient; it does not establish the
  recipient's honesty. No attack success is asserted without actual evidence.
- A controlled fixture isolates a mechanism. A hosted copy remains a controlled
  fixture. Independent generalisation claims need a reviewed unseen benchmark.

## Independent public observations

Observed in an isolated Edge 156.0.4314.58 profile on 2 November 2026, with local
rules and optional reputation disabled. No credentials entered, forms submitted
or browser interstitials bypassed. Full details: [public results](public-demo-results.json).

| Public page | Actual PhishGuard observation | Interpretation |
|---|---|---|
| `https://example.com/` | 0 / Low risk | Neutral page; no identity guarantee. |
| `http://http-password.badssl.com/` | 35 / Caution | The rendered password context uses unencrypted HTTP. |
| `https://mixed-form.badssl.com/` | 0 / Low risk | No strong credential-theft evidence found in that document; not an accuracy test. |
| AMTSO desktop phishing test | 0 / Low risk | A harmless participating-product/blocklist check is distinct from structural detection. |
| Google Safe Browsing phishing test | 0 / Low risk | No strong local structural indicators in this particular Edge run. This is not proof that browser phishing protection works or fails generally. |

AMTSO explicitly describes its test as harmless and blocked by agreement among
participating products: [official explanation](https://www.amtso.org/feature-settings-check-phishing-page/).
Google lists its test pages in the [official test directory](https://testsafebrowsing.appspot.com/).
BadSSL lists intentional transport fixtures in its [official directory](https://badssl.com/).
Its [HTTP login source](https://github.com/chromium/badssl.com/blob/master/domains/http/http-login/index.html)
can be inspected independently. Do not describe BadSSL as a credential-stealing
operator or its insecure-input example as a proven phishing incident.

## Verification

- Full JavaScript suite: 34 tests passed after the initial integration.
- Targeted visual/demo tests passed after final content edits. They exercise
  all three structural verdicts, step/reset/play/pause behavior, real fact
  updates, and throwing field-value/network/submission guards.
- Real Edge smoke test exercises all three visual pages against the installed
  extension, preserving Low risk/Caution/High risk outcomes after stepping.
  Screenshots at 1440 and 390 pixels and reduced-motion checks are included.
- Page scripts submit zero credentials; the browser's independent form CSP is
  still exercised. Existing dynamic, worker, warning and feedback checks remain.
- Browser startup-file reading now tolerates Edge's brief Windows EBUSY lock;
  missing or permanently unreadable ports still fail the test.
- The public bundle allowlist contains twelve teaching assets and validates
  local references, fragment targets, read-only controls, restrictive CSP and
  route-arrow encoding. Extension internals, models, corrections and credentials
  are excluded from that bundle.

See [browser results](browser-smoke-results.json) for the latest completed run.
Screenshots are development evidence, not production accuracy measurements.
