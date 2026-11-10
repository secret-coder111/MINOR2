# Demonstrate PhishGuard to your professor

**Current demonstration:** the credential-entry lab has been removed. Use the
three read-only demos and their independent comparison links. The new
[URL checker](url-checker.md) accepts an address only and shows an incomplete
address-evidence assessment, an explicit loaded-page check from the extension,
and separate experimental-model diagnostics with measured metrics.

Public demonstrations and URL checker:
https://phishguard-classroom-visual-lab.www-vikramsahu001.chatgpt.site

The strongest demonstration is an experiment the professor can inspect and
change. Show the page's actual address, identity claim and credential destination;
then open the real PhishGuard toolbar popup and read the evidence it found.
The visual walkthrough explains a possible attack. It does not collect data or
serve as the extension's verdict.

## 1. Prepare the experiment

1. Open `chrome://extensions` in Chrome or `edge://extensions` in Edge.
2. Enable **Developer mode**, choose **Load unpacked**, and select
   `C:\Users\wwwvi\Desktop\MINOR2\extension`. If already installed, use
   **Reload**. Confirm **PhishGuard 0.6.0**, disable older copies and pin it.
3. In PhishGuard settings, use the default warning threshold **65** and keep
   optional reputation lookup disabled. This isolates local detection.
4. Use Node.js **22 or newer**. In PowerShell run:

   ```powershell
   Set-Location C:\Users\wwwvi\Desktop\MINOR2
   node --version
   npm.cmd run demo
   ```

5. Keep the terminal running. Open **http://127.0.0.1:8080/**, then refresh the
   tab after reloading the extension. Stop the server with **Ctrl+C** afterward.
6. Before presenting, open each comparison once and record its **actual** popup
   verdict. Do not use an old screenshot or a page's expected-result label as
   evidence of the currently running extension.

Use the overview's comparison links to visit the three pages. Each has a visual
walkthrough; the interactive page lets you change the same page's evidence.

| Page | Address | Purpose |
|---|---|---|
| Ordinary login | `http://127.0.0.1:8080/legitimate-demo.html` | Establish the baseline. |
| External destination | `http://127.0.0.1:8080/caution-demo.html` | Change where a credential form points. |
| Brand + external destination | `http://127.0.0.1:8080/phishing-demo.html` | Combine destination and identity concerns. |
| Interactive comparison | `http://127.0.0.1:8080/dynamic-demo.html` | Change the evidence, inspect rescans and reset. |
| Public website comparisons | `http://127.0.0.1:8080/public-examples.html` | Compare independent public pages and record observations. |

If port 8080 is busy, stop the previous demo terminal with Ctrl+C and try again.
If the popup has no result, refresh the page, check that only the current copy
is enabled, and inspect **Errors** on its extension card. See
[loading and troubleshooting](load-extension.md).

## 2. Understand the three pages

The important question is: **Which organization would receive the credentials,
and does that agree with the identity the page claims?** A login field by itself
does not answer that question.

| Property | Ordinary login | External destination | Brand + external destination |
|---|---|---|---|
| Page address | Local loopback address | Same local site | Same local site |
| Claimed identity | Ordinary fictional portal/bank | Ordinary fictional portal | Recognized PayPal claim, explicitly a lab example |
| Form `action` | `/demo-signin` | `https://example.invalid/collect` | `https://example.invalid/collect` |
| Resolved recipient | Current local site | Different illustrative site | Different illustrative site |
| Main concern | No corroborating identity/destination concern | Different recipient requires review | Brand mismatch and different recipient combine |
| Walkthrough expectation at threshold 65 | No strong indicators / Low risk | Caution | High risk with warning |

These are **expectations**, not live measurements. Read the current toolbar popup
after every change. The score is a risk index, not a probability of phishing.

### Page A: ordinary login

Say:

> This page has a password field, like almost every ordinary login page. Its
> action is a relative path. The browser resolves that path against the current
> site, so the destination stays on this local site. There is no mismatched
> recognized-brand claim combined with a different recipient. My extension
> should avoid accusing every ordinary login page of phishing.

Use the step or playback controls to follow the fictional data token from the
browser toward the first-party destination. Read the page's live facts/source
view: actual page URL, title and resolved form action. Open PhishGuard separately.

Explain the boundary: a first-party form is **not proof of legitimacy**. An
attacker can own an entire website and collect credentials on that same site.
This case tests whether the detector avoids a simplistic password-field warning.

### Page B: external destination

Say:

> The visible login still looks ordinary, but its form action points to another
> site. In a real submission, the destination server would receive the form's
> submitted fields. That creates a question about the recipient, even if the
> page itself looks convincing.

Step through the animation and point out where the destination differs from the
address bar. The animation's collector is an illustration. `example.invalid`
does not receive anything in this lab.

Continue:

> A different destination alone does not prove phishing. Organizations use
> authorized sign-in providers and cross-site authentication flows. The right
> question is whether that provider and flow are authorized. PhishGuard therefore
> uses Caution for this isolated concern rather than treating it as certainty.

For a normal federated sign-in, the application often redirects you to a trusted
identity provider; you authenticate there and the application receives a result
or token. Do not explain SSO as permission to type a password into any page that
posts to a third party. Verify the provider's actual address and the expected flow.

### Page C: brand + external destination

Say:

> Now the page claims a recognized brand, but the browser address is still our
> local lab address. Its credential form also points to another site. These are
> two separate, corroborating concerns about this same credential flow. This is
> why the extension raises the warning in this controlled example.

Show the actual URL, the identity claim and the actual action side by side. Step
through the hypothetical recipient and consequence, then open the extension's
popup and warning details. Explain the reasons using their actual wording.

This page imitates a phishing pattern for teaching. It is visibly labeled as a
local fixture and is not operated as a real phishing site or affiliated with PayPal.
The lab title and destination exist to exercise actual structural rules; the
detector is not reading an expected-verdict label from the page.

## 3. Explain how credentials could be stolen

Use the visual walkthrough to explain this **hypothetical** chain:

1. A person follows a deceptive link and reaches a page that asks for credentials.
2. The person trusts the copied identity without checking the actual address.
3. In a real form submission, the browser sends successful named fields to the
   form's resolved `action`, using its submission method. Password masking hides
   characters on screen; it does not hide the submitted password from its recipient.
4. If that recipient is attacker-controlled and unauthorized, the attacker can
   read the information received and try to use it against the real service.
5. A stolen password can enable account access when the service accepts it.
   Additional protections affect the outcome. Some attacks also relay short-lived
   codes in real time; a code field alone does not prove such an attack occurred.

**Why an HTTPS external destination can still harm:** HTTPS encrypts traffic to
the destination server. That server decrypts it. Encryption does not establish
that the recipient is the organization the user intended to trust.

**Why POST is not a safety guarantee:** POST generally places form fields in the
request body rather than the address bar. The receiving server still receives
them. GET can additionally expose sensitive values in URLs and logs.

**Why this visual is a simulation:** all moving tokens and displayed sample data
are fictional presentation objects. They do not come from typed credentials or
observed network traffic. Real attackers may also send data through JavaScript
instead of the form action; this release does not trace arbitrary script data flow.

## 4. A five-minute presentation script

| Time | What to do | What to say |
|---|---|---|
| 0:00-0:35 | Show extension version, settings and local URL. | “This release inspects URL, DOM and credential-form structure locally. It uses explainable rules. The saved research ML models do not decide its browser verdict.” |
| 0:35-1:20 | Open Ordinary login. Advance its visual and open the toolbar popup. | “A password field alone is ordinary login context. This is our baseline, not a certificate that a site is safe.” |
| 1:20-2:10 | Open External destination. Compare address and action, then advance the visual. | “The recipient changes. A real unauthorized recipient could read submitted fields. A legitimate provider can also be cross-site, so this isolated concern warrants review.” |
| 2:10-3:05 | Open Brand + external destination. Show its facts/source and real warning. | “The recognized identity claim does not match the address, and the same credential form points elsewhere. The evidence combines.” |
| 3:05-4:05 | Use Interactive test. Let the professor choose the scenario/order. Finish with Ordinary login / reset. | “Watch the popup change after a rescan. Returning to ordinary evidence clears the warning. The page's expected labels are teaching aids; this toolbar result comes from the extension.” |
| 4:05-4:35 | Show DevTools Network while running a visual and testing blocked submission. | “The animation is fictional. There is no credential POST or external collection. Submissions are intentionally blocked.” |
| 4:35-5:00 | State limits and offer the public comparison page. | “This experiment proves these cases and update behavior. An independent unseen benchmark is still needed to measure real-world false positives and missed phishing.” |

Wait roughly **1-2 seconds** after changing a scenario. Open the popup and use
**Check again** if necessary. Read coverage or unavailable-result notices rather
than assuming a completed inspection.

## 5. Make the demonstration independently inspectable

### Let the professor choose the experiment

Ask the professor to choose the next scenario or repeat the order in reverse.
They can inspect the page's live source facts and use DevTools on **these owned
local fixtures** to change the title or form action. The extension should react
to the actual page evidence, regardless of the page's expectation card.

A useful controlled challenge is to start with the ordinary scenario on the
interactive page and edit only its form action to `https://example.invalid/collect`
in DevTools **Elements**. Keep the ordinary title and heading. The destination
concern should now be present. Restore `/demo-signin` and inspect again. The
read-only fields, CSP and submission cancellation must stay in place.

For the combined case, select its scenario and inspect the title, heading and
form action directly. If testing manual removal of the brand claim, remove it
from both title and the relevant heading; leaving one claim can retain identity
evidence. Reload or select a scenario again to restore a known fixture state.

### Explain which output belongs to whom

- **Demo page:** scenario labels, expected results and animated explanations are
  teaching material controlled by the page.
- **Browser toolbar popup:** PhishGuard's actual verdict, reasons, site/frame
  details and inspection status. This is the output to record.
- **Browser security interstitial:** a Chrome/Edge or security-product result;
  it is separate from PhishGuard.

The in-page warning is inserted by the extension. Its appearance alone is less
independent evidence than opening the toolbar popup and inspecting the reasons.
Always show the actual popup in the presentation.

### Show that the visual does not steal information

1. Open browser DevTools and select **Network**. Clear the existing request log
   after the local page has finished loading.
2. Play or step through the visual. Only fictional tokens should move.
3. Click the page's blocked-submission test. It should report that no form data
   was submitted. Do not type real information or remove the lab's safeguards.
4. Inspect the requests. There should be **no credential POST and no request to
   `example.invalid`**. Loading local HTML/CSS/JavaScript before clearing the log
   is expected. Extension requests in other contexts are not necessarily listed
   in this page's Network panel.
5. Inspect the page's CSP meta tag: `form-action 'none'` blocks form navigation,
   and `connect-src 'none'` blocks page script connections. The JavaScript also
   cancels submit events. The Node demo server only accepts GET/HEAD and rejects
   POST with status 405. These controls belong to the lab, not to the detector.

Do not claim that PhishGuard generally prevents all credential exfiltration.
The warning recommends leaving; the fixtures themselves prevent submission.
This inspection supports the lab's no-collection design. It is not a complete
proof of all extension privacy properties.

## 6. If the professor asks for a site on the public web

Open the **Public website comparisons** link from the overview. Let the professor
choose one of its public pages and record the actual current popup result.
This gives an independent host while keeping the comparison reproducible.

| Public page | What it can demonstrate | What it cannot establish |
|---|---|---|
| [Example Domain](https://example.com/) | A neutral public page with no credential request. | A general measure of phishing accuracy. |
| [BadSSL HTTP password test](http://http-password.badssl.com/) | An independently hosted intentional insecure-password example, if it remains HTTP. | That BadSSL is a criminal phishing operator, or that today's result matches an old observation. |
| [AMTSO phishing test](https://www.amtso.org/check-desktop-phishing-page/) | Support for a harmless known phishing-protection test in participating security products. | A guaranteed High risk verdict from PhishGuard's local structural rules. |
| [Google Safe Browsing phishing fixture](https://testsafebrowsing.appspot.com/s/phishing.html) | A browser/security-provider blocklist test. | Detection by PhishGuard when the browser blocks the document before inspection. |

Do not enter credentials, bypass a browser warning or disable browser protection.
BadSSL may redirect or be upgraded to HTTPS, and public test pages can change.
The public comparison page's observations dated **25 October 2026** are historical,
not a promise about the day of your presentation. Check the final URL, inspection
status and current popup. A low result on an official test page is valid to report.

Say:

> This public fixture checks known-test support in browser or security products.
> My local detector evaluates different evidence. I will show its actual result,
> even if that result is low risk or inspection is unavailable. The controlled
> pages isolate the behaviors that my detector is designed to explain.

If asked to visit a random suspected phishing URL, explain that its availability,
content and browser blocking may change. A reproducible independent evaluation
uses reviewed, preserved evidence and a defined protocol. Browsing one live URL
on demand is a spot check, not an accuracy benchmark. The prepared official
tests and harmless local pages suffice to demonstrate the inspection workflow.

## 7. Likely professor questions

**“You made the page. How do I know the result is not hard-coded?”**

The page provides expectations and animations. The toolbar popup is separate.
Choose a different order, inspect the real form action, change one property in
DevTools and watch the extension rescan. The implementation is available in
[form extraction](../extension/src/content/form-features.js),
[DOM/identity extraction](../extension/src/content/dom-features.js) and the
[canonical scoring policy](../extension/src/shared/model-policy.js).
There is no need to add a demo hostname to the detector to force a verdict.

**“Why does the external-destination example only say Caution?”**

A destination difference can be legitimate. The detector asks for corroborating
evidence before the default high-risk warning. This reduces blanket warnings on
ordinary federated sign-in and unrelated login forms; it does not remove the
need to verify the actual provider.

**“Would the data really reach that server?”**

In a real permitted form submission, the resolved action identifies the target.
If the recipient is malicious, that is a way to collect fields. In this lab,
submission is blocked and the tokens are fictional. The visual explains the
possible path, not a captured theft.

**“Can a same-site HTTPS page still be phishing?”**

Yes. Attackers can own a domain with HTTPS and collect on that same site.
PhishGuard can use some additional identity/address evidence, but this release
does not promise to detect every such page or arbitrary script-based collection.

**“Is your detector AI or machine learning?”**

The current 0.6.0 browser release uses explainable rules. Research ML artifacts
exist in the repository but remain disabled for browser verdicts until compatible
training, independent calibration and untouched evaluation support deployment.

**“Does 88 mean 88 percent accurate or an 88 percent chance?”**

No. Any number shown is a rule-based risk index. An accuracy percentage requires
a labeled independent evaluation, a stated threshold and an explicit protocol.

**“What evidence would make your performance claim credible?”**

A reviewed unseen benchmark containing both phishing and legitimate sites,
including login, SSO, recovery, shared hosting and multiple languages. Split by
site/content and time to reduce leakage, freeze the policy before testing, and
report false positives, missed phishing, sample sizes, confidence intervals,
coverage limits and scan time. The same examples used to tune rules cannot also
be the only proof of their performance.

## 8. What you can honestly conclude

This is a controlled experiment: hold most of the page constant, change the
destination, then change the identity claim, and observe the extension separately.
It demonstrates the intended rule behavior, explanations, warning and rescan/reset
flow on these fixtures. The visual teaches the consequences without collecting
credentials. It does **not** establish production accuracy, verify every site's
ownership or prove detection of all phishing techniques.

Related: [short presentation guide](presentation-demo.md),
[current improvement report](audit/improvements-2026-11-02.md),
[machine-learning evaluation requirements](../ml/README.md).
