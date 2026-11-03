# How existing phishing extensions work—and what PhishGuard can learn

**Research date: 27 October 2026**

Phishing-detection extensions already use several approaches: threat databases, URL and page rules, behavior monitoring, and local language models. PhishGuard can learn from these approaches while retaining its privacy boundary: inspect page structure locally, avoid reading typed secrets, and make network services optional.

This report combines official product documentation with readable source code. A documented feature is a vendor statement; a source observation establishes what inspected code expresses. Neither proves current detection accuracy. Proposed architecture below is a recommendation, not a claim that the changes have been implemented.

## 1. The methods in plain language

A **reputation check** asks whether a website is already known to be malicious. A **heuristic** is a rule based on evidence, such as a credential form sending to an unrelated site. A **content model** learns patterns from labeled pages. **Behavior monitoring** observes what a page does as it runs.

These methods answer different questions. A database miss means “unknown to this source.” A password box means “credentials may be requested.” Neither independently means a page is safe or phishing.

| Product/project | Publicly documented core approach | Runtime and backend picture |
|---|---|---|
| Netcraft | Threat intelligence, infrastructure risk, URL checks, credential-leak detection | Browser protection connected to vendor services |
| Malwarebytes Browser Guard | URL/page patterns and behavioral heuristics; optional local AI | MV3 extension; separate Gemini Nano feature on supported Chrome devices |
| Bitdefender Web Sage, formerly TrafficLight | Threat intelligence plus premium AI scam analysis | Service-backed extension requiring sign-in; model internals undisclosed |
| PhishLang | HTML representation classified with MobileBERT | Chromium extension plus local model service |
| PhishDetect | Cached indicators plus explainable URL/HTML rules | JavaScript extension and Go analysis service; optional Docker browser |

The detailed sources and important qualifications follow.

## 2. Netcraft: combine reputation with additional evidence

Netcraft documents blocking known malicious sites and assigning risk to previously unseen sites using domain age, survey history, abusive hosting networks, unusual ports and raw IP addresses. Its credential-leak feature inspects outgoing requests for entered sensitive information sent to another domain, blocks matching traffic, and reports the infected page. This extends beyond checking a URL against a list. [Official extension documentation](https://www.netcraft.com/resources/apps-and-extensions/browser-extension)

The privacy policy says the extension sends visited hostnames; full paths are ordinarily checked locally, with specified reporting exceptions. Block analytics can include the blocked URL, reason, extension version, country and device details; analytics can be disabled. [Netcraft privacy policy](https://www.netcraft.com/legal/privacy)

**Useful lesson:** distinguish reputation, infrastructure risk and observed page evidence. A young domain should support a finding, not establish guilt.

**Privacy tradeoff:** credential-value inspection conflicts with PhishGuard’s promise not to inspect typed secrets. PhishGuard should continue examining form destinations and control metadata, while disclosing that arbitrary JavaScript exfiltration remains outside that narrower coverage.

The inspected sources do not disclose Netcraft’s full scoring formula, backend language, database technology, training corpus or model architecture. Assigning it “Random Forest,” “BERT,” “Python” or “React” would be speculation.

## 3. Malwarebytes: contextual patterns and optional local AI

Malwarebytes’ February 2026 engineering article describes an MV3 pattern engine with URL regular expressions, XPath/querySelector matching, page-content checks and favicon spoof detection. Its example combines hosted-page context, a password input and a homoglyph impersonation address. It also describes behavioral heuristics and rules refreshing every 30 minutes. Browser Guard therefore cannot accurately be summarized as only a blocklist or a single AI classifier. [Engineering article](https://www.malwarebytes.com/blog/inside-malwarebytes/2026/02/how-manifest-v3-forced-us-to-rethink-browser-guard-and-why-thats-a-good-thing)

A separate feature, **Scam Guard Lite**, uses Gemini Nano locally to analyze the current webpage. The user opens it through Browser Guard; the first use downloads the model. The documented availability is Chrome on supported Windows/macOS devices, subject to hardware requirements. This is distinct from automatic pattern protection. [Scam Guard Lite instructions](https://help.malwarebytes.com/hc/en-us/articles/49283487280923-Check-if-a-website-is-safe-with-Scam-Guard-Lite)

**Useful lesson:** combine independent contextual clues and offer heavier analysis only when supported and useful. Explain the evidence behind a warning.

The public materials inspected do not expose the entire frontend/backend stack, rule inventory, training data or calibration. Scam Guard Lite’s local processing statement should not be generalized to every component’s telemetry.

## 4. Bitdefender: current name and proprietary limits

TrafficLight has evolved into **Bitdefender Web Sage**. Its official FAQ describes a free Malicious Page Blocker using threat intelligence and Search Advisor ratings. Premium features add on-demand AI analysis, scam explanations and additional shopping/financial-fraud protection. Chrome and Edge are currently supported; sign-in is required even for free protection. [Official FAQ](https://www.bitdefender.co.uk/consumer/support/answer/139563/)

**Useful lesson:** show whether a result comes from reputation, rules or optional model analysis. Give a clear “service unavailable” state.

The inspected sources do not establish a particular transformer, CNN, frontend framework, backend language, dataset or entirely on-device inference. “AI-powered” is a capability description, not an implementation specification.

## 5. PhishLang: turn HTML into useful model input

### Detection sequence

PhishLang’s readable Python parser uses BeautifulSoup to select actionable page elements: headings, paragraphs, links, lists, title, footer, forms, scripts, inputs, buttons and selected embedded/navigation elements. It lowercases text and creates a structured text representation. Links retain their target; inputs retain type, name and placeholder. This lets a language model consider context rather than merely counting keywords. [Parser at inspected commit](https://github.com/UTA-SPRLab/phishlang/blob/6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd/src/parser_for_training_no_patch.py)

The training script fine-tunes `google/mobilebert-uncased` using Hugging Face Transformers and PyTorch for two classes: phishing and benign. It uses pandas, Datasets and scikit-learn. Public-script settings include 128-token inputs, ten epochs, learning rate 2e-5 and batch size 32. The prediction script scores overlapping windows and uses the maximum phishing softmax score. [Training](https://github.com/UTA-SPRLab/phishlang/blob/6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd/src/training.py), [prediction](https://github.com/UTA-SPRLab/phishlang/blob/6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd/src/patched_parser_prediction.py)

The saved model configuration identifies MobileBERT with 24 layers, four attention heads and 30,522 vocabulary items. This is a small language-model classifier, not a conversational chatbot and not screenshot matching. [Configuration](https://github.com/UTA-SPRLab/phishlang/blob/6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd/src/model/config.json)

### What “client side” means here

The NDSS paper describes a Chromium extension calling a local background model server. Detection remains on the user’s machine; that does not mean inference runs inside extension JavaScript. The paper discusses adversarial patching, language coverage, multistep pages and CAPTCHA/QR limitations. Its training settings differ from the public script, so paper results should not be assumed reproducible from that script unchanged. [Official NDSS paper](https://www.ndss-symposium.org/wp-content/uploads/2026-s1037-paper.pdf)

The fetched tree includes Python research code and packaged .deb/.crx files, but no unpacked extension/service implementation. Their exact libraries and interfaces were not established; no ONNX/Transformers.js implementation was verified. [Repository tree](https://api.github.com/repos/UTA-SPRLab/phishlang/git/trees/6b7283854ef8a6edc73f945c1ce7e51b2e1dc4fd?recursive=1)

### Source concerns and reuse

Static review found concerns worth testing independently: truncation occurs before windowing; incomplete windows are skipped, leaving very short inputs classified benign; evaluation mode is not explicitly enabled; and training fold selection appears inconsistent with the original dataset order. Optional chunking before splitting risks related fragments crossing partitions. These observations are **unvalidated runtime concerns**, not a reproduced accuracy assessment. The linked training/prediction files contain the relevant logic.

The transferable idea is **bounded, consistent page representation**, combined with adversarial evaluation. Copying its scripts or adopting its published accuracy would require much more validation.

## 6. PhishDetect: threat feeds and transparent rule evidence

### Detection sequence and actual technologies

PhishDetect’s extension downloads indicators, caches them, and compares host/registrable-domain hashes locally. Its background code redirects matched requests to a warning. Manual scans serialize page HTML and send it to the configured analysis service. [Background code](https://github.com/phishdetect/phishdetect-extension/blob/fd481f76dfba7d8e2ca97726927fae6d18db668e/src/js/background.js), [scan frontend](https://github.com/phishdetect/phishdetect-extension/blob/fd481f76dfba7d8e2ca97726927fae6d18db668e/src/ui/scan/scan.js)

The extension uses JavaScript, React 17, jQuery, Tailwind 2, Webpack/Babel, tldts and SHA-256. Its inspected manifest is **Manifest V2**, with background scripts and blocking webRequest. It needs modernization for a new Chromium implementation. [Dependencies](https://github.com/phishdetect/phishdetect-extension/blob/fd481f76dfba7d8e2ca97726927fae6d18db668e/package.json), [manifest](https://github.com/phishdetect/phishdetect-extension/blob/fd481f76dfba7d8e2ca97726927fae6d18db668e/src/manifest.json)

The core is **Go heuristic scoring**, not ML. URL checks include brand similarity/edit distance, punycode, address patterns and optional Safe Browsing. HTML checks include form controls, brand text, selected script patterns and optional YARA rules. Every matched check can return a name, explanation, score and evidence. [URL checks](https://github.com/phishdetect/phishdetect/blob/bd4f57050b9d816b31b2a3b00233fe8b03f86beb/checks/url_checks.go), [HTML checks](https://github.com/phishdetect/phishdetect/blob/bd4f57050b9d816b31b2a3b00233fe8b03f86beb/checks/html_checks.go)

“PhishDetect Node” is a Go service using Gorilla Mux and MongoDB; its name does not mean Node.js. Optional dynamic analysis runs Chrome in Docker through the DevTools Protocol, collecting rendered HTML, navigation, resources and screenshots. Screenshot collection alone does not establish visual ML. [Service](https://github.com/phishdetect/phishdetect-node/blob/74b0a67ff18d3ddaac1138365defd34960fa61c4/main.go), [browser implementation](https://github.com/phishdetect/phishdetect/blob/bd4f57050b9d816b31b2a3b00233fe8b03f86beb/browser/browser.go)

### What to adapt carefully

Adopt structured explanations and scoped cached intelligence. Do not copy old weights for password fields, hidden inputs, PHP or login phrases: these also occur on legitimate sites.

Static review also found a Base64 check apparently matching decode errors and a scan UI that prioritizes a safelist result over score. These require runtime validation before calling them demonstrated defects. Base64-encoded HTML uploads remain uploads; encoding does not preserve privacy. The core README labels the project experimental. [Core README](https://github.com/phishdetect/phishdetect/blob/bd4f57050b9d816b31b2a3b00233fe8b03f86beb/README.md)

## 7. Frontend and backend requirements for PhishGuard

An extension already has a frontend: popup, options page and warning/banner. Content scripts inspect the page; a background service worker coordinates document results and optional services. A separate React website is unnecessary for detection.

The inspected PhishGuard checkout already has an MV3 manifest, local URL/DOM/form analysis, explanations, document/frame handling and optional hostname reputation. Its README states that historical learned models do not currently change browser verdicts. Python training tools are an offline development workflow, not a required live backend.

| Component | Needed for the recommended local runtime? |
|---|---|
| Existing extension HTML/CSS/JavaScript and service worker | Yes |
| Local evidence policy and bundled domain data | Yes |
| Python server on every user's computer | No |
| Hosted database or dashboard | Only for a concrete managed-service feature |
| Optional reputation/feed service | Optional, explicitly disclosed |
| Local ML inference | Later, after independent evaluation |

Preserve the present privacy promise: no typed values/passwords/cookies, no default page uploads, and meaningful coverage/status disclosures. Form metadata can detect structural risk without claiming complete script-data-flow protection.

## 8. Recommended architecture and evaluation

Use this sequence:

1. **Bind the scan to the document.** Track tab, frame, navigation and result freshness.
2. **Extract local evidence.** Determine credential context, actual domain, claimed brand and submission destination. Bound work and disclose inaccessible content.
3. **Apply contextual policy.** Group correlated evidence and require corroboration for severe warnings. Ordinary login/SSO controls alone should not warn.
4. **Optionally consult reputation.** Cache with expiry and provenance. Keep failures visible and avoid secrets in extension code.
5. **Optionally run a measured local model.** Treat the model as another evidence source. Keep preprocessing identical in training/runtime and do not equate raw softmax output with a calibrated probability.
6. **Explain the verdict.** Display observed evidence, source and coverage. Re-scan meaningful changes with rate limits.

Before enabling ML, build an untouched evaluation corpus separated by time and related domains/content. Include legitimate login/SSO, banking and education pages as well as controlled phishing fixtures. Measure false-positive rate and recall separately, plus latency/memory. Test hidden filler, Unicode confusion, dynamic forms and multistep navigation. Regression fixtures demonstrate specific behavior; they do not establish real-world accuracy.

## 9. Licensing, provenance and practical limits

The inspected PhishDetect core/Node identify AGPL and the extension GPL terms. PhishLang's fetched repository metadata reports no license, and its tree exposes no LICENSE file. Clarify permission and applicable terms before reusing code, weights or datasets; attribution alone does not settle reuse permission. Independently implementing general design ideas is distinct from copying assets.

Inspected commits: PhishLang `6b72838`, PhishDetect core `bd4f570`, extension `fd481f7`, Node `74b0a67`. These snapshots do not establish current maintenance, compatibility or accuracy elsewhere. Commercial internals remain partly proprietary. A useful PhishGuard contribution is a transparent system with local processing, honest coverage and independently measured performance.
