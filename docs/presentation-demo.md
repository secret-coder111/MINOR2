# Present PhishGuard safely

**Current flow:** the credential-entry lab has been removed. Run
`npm.cmd run demo`, then open http://127.0.0.1:8080/. Each of the three cards
links to our controlled demo and a public comparison: GitHub login, BadSSL HTTP
password test, and the harmless official AMTSO phishing feature check.

Choose **Check a URL**, or **Check another URL** in the extension popup, to paste
an address without visiting it. See [the URL checker guide](url-checker.md)
for scope, measured performance and the evaluation record.

The warning now has a **Close** button. Closing dismisses the same notification
for this document; the high-risk verdict remains in the toolbar popup. Use
**Check again** to show the warning again. New risk evidence or a new page can
also show another warning. Page-script clicks cannot dismiss it.

Public walkthrough:
https://phishguard-classroom-visual-lab.www-vikramsahu001.chatgpt.site

**2 November 2026:** Each of the three comparison pages now includes a four-step
visual credential journey: address, fictional input tokens, destination and
possible consequence. Use **Visual explanation**, then Play or Next step.
The map shows the actual browser origin and resolved form action. Expand the
page facts to inspect the title and action. It never reads or sends field values.
See the [full professor demonstration script and Q&A](professor-demonstration.md).

When an examiner edits the title or destination beyond a predefined case, the
visual changes to a neutral **Professor-edited page** narrative. It does not
assign the extension's verdict. Open the installed toolbar popup separately.

The demo now combines verified public website links with repeatable local
comparisons and an interactive observation checklist.

## Prepare

1. In Chrome open `chrome://extensions`; in Edge open `edge://extensions`.
2. Enable Developer mode. Load unpacked from
   `C:\Users\wwwvi\Desktop\MINOR2\extension`. Reload an already loaded copy,
   disable older copies, and pin PhishGuard to the toolbar.
3. Keep optional reputation disabled and use warning threshold **65** so the
   comparison demonstrates local detection with the default policy.
4. In PowerShell, from `C:\Users\wwwvi\Desktop\MINOR2`, run:

   ```powershell
   npm.cmd run demo
   ```

   Alternative if Node is unavailable:

   ```powershell
   .\.venv\Scripts\python.exe -m http.server 8080 --bind 127.0.0.1 --directory extension/demo
   ```

5. Open **http://127.0.0.1:8080/**. Refresh the demo tab after reloading the extension.

## Public website links

Open **http://127.0.0.1:8080/public-examples.html**. Each card opens its website in
a separate tab and offers a local comparison. Inspect the extension popup, return
to the card, and record the actual result. The progress counter and summary update
as you record results; Reset clears them. Observations are not uploaded or persisted.

Checked with the unpacked extension in Edge 156 on **25 October 2026**, with
reputation disabled and threshold 65:

| Public link | Actual PhishGuard result | What it demonstrates |
|---|---|---|
| [Example Domain](https://example.com/) | **0, Low risk** | A neutral page without a credential request. |
| [BadSSL HTTP password test](http://http-password.badssl.com/) | **35, Caution** | A password prompt on unencrypted HTTP. This is a security test site, not an accusation of phishing. |
| [AMTSO phishing test](https://www.amtso.org/check-desktop-phishing-page/) | **0, Low risk in local-rules mode** | A harmless, known phishing-protection test entry for supporting security products. It is not a verified High risk result from PhishGuard. |

The Google [Safe Browsing phishing fixture](https://testsafebrowsing.appspot.com/s/phishing.html)
also scored 0 in this isolated Edge check. A browser with supporting protection
may block a test page before PhishGuard can inspect it. Do not bypass a browser
warning for the presentation. The [recorded results](audit/public-demo-results.json)
include requested/final URLs and reasons. Live content, upgrades and security
settings can change these observations; verify them again before presenting.

**For a reliable High risk result from this extension**, use
http://127.0.0.1:8080/phishing-demo.html or the interactive Brand + external
destination scenario. These scored 88 locally. The separate medium fixture is
http://127.0.0.1:8080/caution-demo.html (43). No website names or test URLs were
added to the scoring policy to force a demonstration outcome.

Explain the public test honestly: “This checks known-test support in security
products. My local rules do not flag it from its page structure. The next
controlled example shows the combined indicators that my extension detects.”

## Show the behavior

Open the **Interactive test**. After each button click, allow a moment for the
rescan, then open the extension popup and read its actual reasons.

| Selection | Expected result at threshold 65 | Explanation |
|---|---|---|
| Ordinary login / reset | No strong indicators (popup badge: Low risk) | Password inputs alone do not establish phishing. |
| External destination | Caution | A credential form points to a different site; legitimate SSO can also do this. |
| Brand + external destination | High risk and a warning banner | The title claims PayPal on the local hostname, with an external credential destination. |
| Ordinary login / reset again | No strong indicators; banner clears | The actual evidence changed and the extension rescanned. |

The expected-result card belongs to the fixture and is not a live extension
reading. The popup is the extension-controlled output. The numeric score is a
risk index, not a percentage probability. Static comparison pages are available
at `/legitimate-demo.html` and `/phishing-demo.html`.
The `/caution-demo.html` page provides a third static comparison at the medium band.

## A short explanation to give your professor

> This is a local test page that imitates phishing behavior. My extension
> examines the URL and credential-form structure locally, without reading typed
> passwords. An ordinary login stays low risk. A different credential destination
> produces caution. When that combines with a recognized brand claim that does
> not match the hostname, the extension shows high risk and explains why. Resetting
> the page removes the warning after a rescan.

If asked about accuracy:

> This demonstration proves these cases and the extension's update flow work.
> It does not measure real-world accuracy. The current browser release uses
> explainable rules. The historical ML models are disabled until compatible
> training, independent calibration and untouched evaluation justify deployment.

If asked whether HTTPS means safe: encryption protects transport; the policy
also considers identity and destination evidence. A malicious page can use HTTPS.
If asked whether every warning is correct: legitimate SSO can send credentials
between sites, so a destination difference alone produces caution by default.

## Fixture safety and troubleshooting

Inputs are read-only. JavaScript cancels submit events, and `form-action 'none'`
in browser CSP blocks submission independently. The Node demo server also rejects
POST requests. No real credentials or external service is needed. The illustrative
collector uses `example.invalid`, covered by IANA's special-use `.invalid` domain.

If there is no result, refresh the tab, confirm the correct extension copy is
enabled, and inspect its Errors panel. If there is no high-risk banner, restore
threshold 65. Internal browser pages and browser-blocked pages may not be inspectable.
Use Ctrl+C to stop the server. If port 8080 is busy, stop the earlier server first.

Sources: [Chrome's unpacked-extension loading and reload instructions](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world),
[IANA special-use domain registry](https://www.iana.org/assignments/special-use-domain-names),
[BadSSL's test directory](https://badssl.com/),
[AMTSO's explanation of its harmless phishing test](https://www.amtso.org/feature-settings-check-phishing-page/),
[Google Safe Browsing test directory](https://testsafebrowsing.appspot.com/).
