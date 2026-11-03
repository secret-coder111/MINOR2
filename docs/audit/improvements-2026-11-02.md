# PhishGuard: detection quality and interface review

Review date: 2 November 2026. Release: 0.5.0.

This review inspected the current extension, canonical policy, popup, warning,
settings, research feature contract and maintained tests. Existing uncommitted
work was preserved. This is an implementation review and controlled regression
assessment, not a certification of production phishing accuracy.

## Findings and implemented changes

| Area | Finding | Implemented change |
|---|---|---|
| Verification codes | A text field labelled `Email verification code` was not recognised as sensitive. `Email` suppressed its secret-code interpretation. | Recognise explicit verification, authenticator and authentication-code phrases. An email reference cannot suppress a code prompt on an ordinary text control. |
| Native GET submission | A same-origin GET form with an unnamed password field could receive credential-query exposure evidence even though native submission omits that field. With a mismatched brand title, the result became High risk. | New per-submission `credential_form_get_exposes_sensitive` observation requires a named sensitive control before adding GET credential-exposure evidence. |
| Popup interpretation | The large numeric score dominated the visual hierarchy, while guidance, coverage, correction controls and status competed for attention. | Put the verdict first; keep the numeric risk index secondary; separate site address, next step and indicators. Move inspection details and correction controls into disclosures. |
| Popup departure | High-risk users had guidance but no independent popup action to leave the page. | Add a High risk-only Leave this page action. Recheck active tab ID and URL before replacing that tab with `about:blank`. |
| Invalid UI data | An unknown outcome or invalid score could still be displayed as a result object. | Invalid results render Unknown, with no departure or correction action enabled. |
| Correction context | A selected correction could survive a document/outcome change while the popup stayed open. | Reset correction selection and feedback status when the displayed tab/document/outcome changes. |
| In-page warning | A full-width bar competed with the site's entire header, and all reasons required expansion. | A bordered warning card with a visible primary reason, ASCII site origin, red departure action and expandable full evidence. |
| Settings | An unstyled page mixed endpoint configuration, sensitivity and correction review. | Responsive card layout, labelled native controls, recommended-threshold shortcut, explicit privacy information and a correction empty state. |
| Browser/research consistency | Changes to credential recognition must also exist in offline feature extraction. | Mirror code-prompt semantics in Python; retain the new scoped observation in capture projection; add golden fixtures; advance policy version. |

### Reproduced decision changes

These are harmless synthetic fixtures using reserved example domains. They are
not observations of live phishing campaigns.

1. **Missed credential prompt:** a same-origin login under a reviewed lookalike
   address, with a nearby `PayPal sign in` heading and a text field labelled
   `Email verification code`, lost its sensitive credential context. It now
   has one sensitive field and High risk from bound identity plus address
   evidence. On a differently hosted page that already has a branded title and
   an external destination, identity-only evidence may already have warned;
   recognising the field correctly does not imply every such verdict changed.
2. **Invented query exposure:** a PayPal-titled page on an unrelated host, with
   a same-origin GET form and an unnamed password field, previously received
   identity 45 + transport 35 = 80/High risk. It now receives 45/Caution: the
   identity concern remains, but native query exposure has not been established.
3. **Named GET control:** adding a nonempty name to that sensitive control
   restores the query exposure observation and the corroborated High risk result.
4. **Benign controls:** recovery-email prose, coupon codes, postal codes and
   product codes remain non-sensitive in the new regression cases.
5. **Alternative flows:** a POST to an external identity service and a separate
   same-origin GET submitter are still evaluated independently. Their evidence
   is not added across different submission paths.

The GET change follows the [HTML form entry-list construction rules](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#constructing-the-entry-list).
It does not prove a script cannot read an unnamed field. Arbitrary script data
flow remains outside this privacy-preserving structural detector's coverage.

## Interface behavior

The popup displays **No strong indicators**, **Check before continuing** or
**Possible phishing**, alongside the canonical Low risk/Caution/High risk band.
Incomplete inspection remains a distinct neutral state. An invalid result is
Unknown. No screen calls a low score a verified identity or a probability.

The warning retains its previous security properties: reasons are inserted as
text; it does not steal keyboard focus; its Leave button remains a real button;
ordinary page interference is repaired; and extension-owned updates do not
trigger detector loops. The browser toolbar popup remains an independent view
because a webpage owns its document and can interfere with in-page content.

The card exposes its most important reason before expansion. The Leave action
precedes the disclosure in visual and keyboard order. Expanded evidence can
scroll within the viewport. No dismiss/automatic trust action was introduced.

Settings retain the current threshold of 65 and reputation-off default. The
recommended-threshold shortcut changes the form and requires Save settings to
persist it. Reputation controls disclose hostnames, frame coverage and the
remote service's ability to see an IP address. Corrections remain local,
explicitly reviewed candidates; they never silently retrain or allowlist a site.

## Architecture and data compatibility

- Detection remains local and rules-based. No cloud model, API key, Python
  service or background model download was added to the browser runtime.
- No typed values, passwords, cookies or editable text are read by the new checks.
- The historical 29-column numeric research vector remains unchanged.
- The new GET observation is a scoped policy extra. Aggregate page observations
  cannot overwrite a particular flow's observation. Older direct policy inputs
  without the flag keep conservative compatibility behavior.
- Policy version is 0.5.0 in JavaScript and Python. Changed extractor/policy
  hashes invalidate older captures for release qualification.
- Existing model weights remain research-only. They were not retrained, enabled
  or presented as compatible with these changed semantics.

## Further improvements, in priority order

| Priority | Work | Why it matters | Evidence needed before shipping |
|---|---|---|---|
| 1 | Independent, reviewed benchmark | Without one, there is no trustworthy estimate of missed phishing or false warnings. | Source/time-separated phishing and benign pages; related domains/content grouped; independent label review; frozen holdout. |
| 2 | Legitimate authentication coverage | SSO, enterprise identity providers, payment processors and regional banking domains can legitimately cross site boundaries. | Reviewed examples of redirect and form flows; regression pairs with deceptive counterparts; no broad domain safety exemption. |
| 3 | Brand identity coverage | The present reviewed list and finite lookalike aliases cover only a subset of brands and spellings. | Provenance for ownership mappings; migration review; multilingual and hosted-tenant tests; measured incremental recall and false positives. |
| 4 | Visual impersonation | A page can copy a logo and layout without exposing the text patterns inspected by this policy. | Local screenshot/OCR prototype; privacy review; measured CPU/memory/latency and unseen-brand evaluation. |
| 5 | Same-origin and script-mediated phishing | A plausible page can collect credentials and submit through JavaScript without suspicious HTML destinations. | Explicitly scoped local behavior research; real data-flow evidence; a privacy design that continues to avoid secret collection. |
| 6 | Local learned model | Content models may generalise beyond finite rules, but can introduce confident false positives. | Matching preprocessing; independent fitting/tuning/calibration/test partitions; FPR/recall confidence bounds; latency/memory limits; existing release gates. |
| 7 | Multistep/embedded authentication | Credential entry can occur after interactions, inside new frames, or across navigations. | Maintained browser tests for document binding, frame recovery, dynamic control reveals, page interference and opaque-content disclosure. |
| 8 | Performance on large pages | Root discovery and DOM/style analysis can become expensive on large or highly dynamic pages. | Controlled size/mutation benchmarks, upper-tail scan latency and memory measurements, bounded work and explicit coverage disclosures. |
| 9 | Warning comprehension | A technically correct warning still fails if people cannot understand or act on it. | Keyboard and screen-reader sessions; high-contrast checks; user tasks measuring safe decisions, comprehension and warning fatigue. |

Do not treat the table as evidence that any of these future capabilities has
already been implemented. The current browser UI and the two reproduced detector
repairs are the implemented scope of this release.

### How to measure fewer wrong results

Report these separately, with sample counts and confidence intervals:

- **False-positive rate:** legitimate pages incorrectly warned on, especially
  login, recovery, MFA, payment and SSO pages.
- **Recall:** phishing pages detected, stratified by identity theft, credential
  collection, visual-only deception, compromised sites and multistep flows.
- **Precision:** warned pages that are actually phishing, with the evaluation
  class prevalence stated. A balanced lab corpus does not represent browsing.
- **Coverage:** inspectable vs unchecked frames, controls and content; failures
  and pending reputation checks must not be interpreted as safety.
- **Runtime cost:** median and upper-tail scan time, warning delay, memory and
  repeated-scan behavior during SPA navigation and DOM changes.
- **Usability:** ability to find the actual domain, understand the reason and
  leave safely using keyboard and pointer input.

Use fixed fixtures to prevent regressions, tuning data to choose thresholds,
separate data for calibration, and an untouched future/source-separated holdout
for the final claim. Do not tune on the holdout, reuse known test domains across
splits, or promote unreviewed user corrections into truth.

## Verification

The final full JavaScript suite passed (31 tests), including six detector-quality
regressions and the additional same-origin OTP scenario.
All 37 Python tests passed, including browser/Python parity across the 49 golden
feature fixtures. The controlled demo validator passed.

The final isolated Edge **156.0.4314.58** smoke test passed. It exercised the
installed extension, dynamic SPA/metadata changes, the new OTP/GET cases,
same-origin lookalikes and benign provider phrases, frame/shadow/CSSOM behavior,
warning repair, actual worker stop/recovery, local capture isolation, settings,
feedback and the Leave action. The interactive sequence remained 8/Low risk,
43/Caution, 88/High risk, then 8/Low risk. Zero fixture POSTs occurred; browser
CSP also blocked direct form submission.

Popup widths of 352/320, warning desktop/narrow layouts, and settings widths of
1000/390 were checked. Screenshots were visually inspected. Reduced-motion
behavior was verified for the warning. Screen-reader testing and complete
high-contrast usability evaluation were not performed.

The smoke harness now retries discovery/attachment of a replacement worker after
shutdown; Chromium can briefly list an already-closed target. This repairs a
test-harness race without bypassing the actual worker-recovery assertion.

Evidence: [controlled before/after probes](detection-quality-results-2026-11-02.json),
[verification summary and source hashes](improvement-verification-2026-11-02.json),
[browser results](browser-smoke-results.json),
[popup preview](ui-0.5.0/popup.png),
[warning preview](ui-0.5.0/warning-mobile.png),
[settings preview](ui-0.5.0/settings.png).
Fixtures establish specific behavior, not production accuracy.

Standard commands:

```powershell
npm.cmd test
.\.venv\Scripts\python.exe -m unittest discover -s ml/tests -v
npm.cmd run test:demo
npm.cmd run test:browser
```

The first restricted Edge launch failed during browser/GPU startup. An isolated
retry rendered the popup and warning but ended before the full smoke report.
The system Node executable then became unavailable during this session; remaining
checks use an available Node 24 runtime with its directory added only to the
check process's PATH. The final direct-Node isolated run completed successfully;
the earlier interrupted/failed launches were not counted as passing tests.

## Try the update

1. Open `chrome://extensions` or `edge://extensions`.
2. Reload the unpacked extension from `C:\Users\wwwvi\Desktop\MINOR2\extension`.
3. Confirm version 0.5.0 and refresh website tabs.
4. Open the toolbar popup and Settings. The runtime needs no server or build.
5. For controlled examples, use the existing local Test Lab and presentation
   guide. Keep the threshold at 65 and optional reputation off for comparison.

There is no claim that all phishing is caught, that every false warning is
eliminated, or that this is the most accurate extension available.
