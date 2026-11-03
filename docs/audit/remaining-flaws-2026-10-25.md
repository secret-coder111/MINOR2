# Second review and public-demo verification - 25 October 2026

This review follows the earlier fixes in `improvements-2026-10-25.md`. Existing
working-tree changes and model artifacts were preserved. No production accuracy
claim or new trained-model deployment is made.

## Verified fixes

- **Web components:** open and nested shadow roots now contribute credential
  forms, root-scoped ARIA metadata and relevant DOM observations. Visibility
  respects hosts, slots, inert state and undistributed controls. Mutation
  observation covers open roots; late roots attached to existing hosts are
  discovered while visible, and detached trees are released.
- **Privacy:** branding extraction no longer uses `body.innerText`, which could
  include editable user text. Controls and inherited editable regions are
  excluded from label/brand text traversal. Non-executable JSON/data scripts no
  longer count as obfuscated executable code.
- **Lifecycle:** browser frame inventory, document identity, URL and lifecycle
  reconcile stale results. Hash navigation, replaced/removed frames, interrupted
  navigation and cached-page restoration have additional regression coverage.
- **Warnings:** ordinary removal, hiding, inline styling, ARIA changes and text
  replacement are repaired. A webpage still controls its own DOM; the extension
  popup remains the independent verdict surface.
- **Coverage:** the popup discloses known uninspected embedded documents without
  inventing phishing evidence or silently claiming complete inspection.
- **Capture integrity:** the browser collector now extracts in an isolated
  JavaScript world, preventing MAIN-world prototype replacement from forging
  feature results. Features, title, HTML and final URL are read together.
- **Dataset provenance:** filename fallbacks and source casing cannot establish
  source separation. Evaluation validates original freeze identity and timeline,
  including observation-before-freeze. Frozen identities include provenance and
  review metadata. Popularity-list seeds require explicit label review; historical
  automatic Umbrella negatives are not accepted as ground truth.
- **Presentation:** three local risk bands, public links, measured results,
  explanation cards and an observation/progress/reset interaction are available.

## Public examples actually checked

The isolated Edge 156 test visited only operator-owned benign documentation and
security test pages. No data was entered, forms submitted, warning bypassed or
protection disabled. These are observations of the chosen pages, not a benchmark.

| Requested website | Actual PhishGuard result |
|---|---|
| `https://example.com/` | 0, SAFE |
| `http://http-password.badssl.com/` | 35, CAUTION; final document remained HTTP |
| `https://mixed-form.badssl.com/` | 0, SAFE; a mixed form alone was not credential evidence |
| `https://www.amtso.org/check-desktop-phishing-page/` | 0, SAFE under local rules |
| `https://testsafebrowsing.appspot.com/s/phishing.html` | 0, SAFE under local rules in this Edge profile |

The AMTSO and Google examples are known security-product test entries. They are
not advertised as verified High risk detections by this extension. The demo
offers a local high-risk counterpart (88) and medium counterpart (43) so a
presentation can reliably show the actual rule-based warning flow. No scoring
exception or test-URL blacklist was added to manufacture those results.

Evidence: [public-page observations](public-demo-results.json),
[browser integration report](browser-smoke-results.json),
[presentation walkthrough](../presentation-demo.md).

## Validation

- `npm.cmd test`: all **12 JavaScript test files passed**, including extraction,
  runtime, model isolation and demo interaction regressions.
- `.\.venv\Scripts\python.exe -m unittest discover -s ml/tests -v`: all **20
  Python tests passed**, including **29 browser/Python parity fixtures**. The
  collector's explicit CDP domain initialization also passed its focused tests.
- Real **Edge 156.0.4314.42**: the complete integration run passed. It verified
  SPA/hash/attribute changes, frame removal, late open shadow root discovery,
  shadow form correction, warning repair, omitted-frame coverage, the local
  three-band demo and public-comparison selection/summary/reset controls.
- The actual Python-generated collector expression ran in a real isolated Edge
  world after the page's MAIN-world DOM/title prototypes were replaced. It still
  detected the password field and read the genuine document title and URL.
- Browser CSP blocked direct form submission; zero fixture POST requests were
  sent. Public link observations were recorded separately in the linked report.
- Desktop and mobile demo previews were captured and visually inspected. Source
  syntax, Python compilation and `git diff --check` passed.

The optional Playwright package is still absent, so the entire live collection
command was not exercised. The core isolated extraction was verified through the
same Chromium CDP APIs and actual generated expression; routing protections also
have mocked regressions. No representative production evaluation was performed.

## Remaining limits requiring more than a code patch

Closed shadow roots and inherited-origin `about:blank`/`srcdoc` documents remain
uninspected; known omitted frames are now disclosed. External-script data flow,
visual impersonation and compromised or unknown brands are not fully covered by
static features. The collector still needs external network isolation for DNS
rebinding and other browser channels; it is not a malware sandbox. Human labels,
source independence and representative untouched evaluation data are still
needed before claiming real-world accuracy or enabling a learned model.
