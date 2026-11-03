# Hands-on demo and official test recognition — 2 November 2026

The reported screenshots exposed a presentation mismatch and missing support
for a known security feature-check URL. Example Domain was loaded correctly,
but is not a login example. AMTSO was previously scored only for structural
evidence; its harmless test address was not recognised. Bitdefender's separate
block was not a PhishGuard result.

## Changes

- Exact, browser-address-based AMTSO test recognition. A separate warning and
  popup label disclose that recognition is a built-in test entry. Rule score,
  canonical structural outcome and evidence remain unchanged. No broad domain
  block, ML claim or accuracy claim is introduced.
- Test checks cannot be recorded as ordinary phishing/safe correction labels.
- A separate live local experiment accepts only `student@demo.invalid` and
  `Demo-Only-123!`. Same-recipient and external-recipient requests go to distinct
  loopback hosts. The brand scenario adds an identity/address mismatch.
- Typed input is checked locally, then a fixed constant pair is sent. Server
  validation rejects other credentials, extra keys, oversized requests, wrong
  origins, unexpected host headers and mismatched scenario routes. No arbitrary
  collector URL, real account login, disk credential log or public collector.
- The UI confirms a receipt by a separate server lookup and exposes actual
  form facts and request details for professor inspection. Reset and scenario
  switches clear the visible receipt and guard against stale asynchronous UI.
- Public comparison labels explain the documentation page, historical AMTSO
  result and updated feature-check behavior. The public Site remains read-only.

## Observed verification

- `npm.cmd test`: **37 tests passed**.
- `npm.cmd run test:demo`: passed; existing read-only fixtures still block
  native and script submissions.
- `npm.cmd run build:classroom`: passed; 12 explicitly selected assets,
  97 local references, read-only controls, no private project data copied.
- `npm.cmd run test:browser`: passed in isolated Edge **156.0.4314.58**.
  Hands-on ordinary / external / brand outcomes were **SAFE 8 / CAUTION 43 /
  HIGH_RISK 88**. All three actual dummy requests reached the expected recipient
  and were independently confirmed from server memory.
- Desktop 1440px and narrow 390px screenshots captured; no horizontal overflow.
  The external desktop and brand narrow captures were visually inspected.
- The first sandboxed Edge attempt crashed in its GPU process. The isolated
  browser verification then passed outside the sandbox through approved execution.
- Python scoring was not changed in this task; no new Python test result claimed.

Official AMTSO match, nonmatching paths/hosts, frame isolation, warning removal,
popup labelling and exclusion from correction labels are covered by current JS
tests.

## Live public verification

The isolated Edge rehearsal also visited the real public pages without entering
credentials or bypassing any browser block. Recorded at 15:46 UTC:

| Public document | PhishGuard observation |
| --- | --- |
| Example Domain | Loaded; structural score 0, no warning. |
| AMTSO official phishing test | Known test entry recognised; warning visible; structural score remains 0. |
| Hosted ordinary comparison | SAFE, 0; no warning. |
| Hosted external destination | CAUTION, 35; no high-risk warning. |
| Hosted brand + external | HIGH_RISK, 80; warning visible. |

The hosted pages are controlled fixtures, still not an independent accuracy
benchmark. HTTPS hosting removes the eight local HTTP/IP context points.
Google's separate test still returns structural 0; it is not covered by the
AMTSO test entry. Full results, including exact URLs and dates:
[classroom web rehearsal](classroom-web-results-2026-11-02.json).

Public teaching Site update: **version 4, deployment succeeded**. Exact version,
source commit, URL and timestamp are in
[the deployment record](classroom-deployment-2026-11-02.json). The version 3 web
rehearsal verified extension behavior; version 4 changes explanation text and
links only. The live local request lab is not part of the public deployment.

Visual records: [external recipient desktop](hands-on-visuals/live-lab-external-1440.png),
[brand scenario narrow](hands-on-visuals/live-lab-brand-390.png).

This remains a controlled explanation of credential routing. It establishes
neither general recall nor a false-positive rate. Advisory warnings do not
block all submissions. Legitimate SSO and HTTPS limits are explained in the UI.
