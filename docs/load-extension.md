# Load and check PhishGuard

Use Chrome or Edge with this Manifest V3 version. Firefox packaging is not part
of this release.

1. Open `chrome://extensions` (Edge: `edge://extensions`).
2. Turn on **Developer mode** and choose **Load unpacked**.
3. Select **`C:\Users\wwwvi\Desktop\MINOR2\extension`**. This folder contains
   `manifest.json`. Do not select `MINOR2` or `ml`.
4. Confirm the card says **PhishGuard 0.5.0**, enable it, and pin it using the
   toolbar's Extensions menu.
5. Refresh a normal website tab, then open PhishGuard to see the current result.

No npm build, Python API, model server, API key or payment is needed to run it.
Detection is local; optional reputation lookup is disabled initially.

After source updates, click **Reload** on the extension card and refresh existing
website tabs. Disable older copies loaded from other folders. If errors appear,
open **Errors** or the service-worker inspection link on the extension card.

Official loading instructions:
https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world#load-unpacked

**Repeatable local demonstration**

From the project directory, start the built-in local server:

```powershell
npm.cmd run demo
```

Open **http://127.0.0.1:8080/** for the walkthrough. Set the extension warning
threshold to its default **65**. The interactive page changes evidence and lets
you show rescans and warning removal. See [presentation notes](presentation-demo.md).

If you prefer Python, the same fixtures can be served with:

```powershell
.\.venv\Scripts\python.exe -m http.server 8080 --bind 127.0.0.1 --directory extension/demo
```

If that environment is absent, use an installed Python with:

```powershell
python -m http.server 8080 --bind 127.0.0.1 --directory extension/demo
```

- `http://127.0.0.1:8080/legitimate-demo.html`: expected **No strong indicators**.
- `http://127.0.0.1:8080/phishing-demo.html`: expected **High risk**, from a
  mismatched PayPal identity claim and an external credential destination.
- `http://127.0.0.1:8080/caution-demo.html`: expected **Caution**.
- `http://127.0.0.1:8080/public-examples.html`: public links with measured results,
  explanatory cards and an interactive checklist. A public blocklist test is
  labelled separately from this extension's High risk examples.
- Fields are read-only. Submissions are prevented and the suspicious destination
  uses the reserved `example.invalid` name. No real password or phishing URL is needed.
- Browser CSP blocks form submission even if the demonstration script fails.
- `http://127.0.0.1:8080/dynamic-demo.html`: select ordinary login, external
  destination, brand + external destination, then reset. Expected results are
  No strong indicators, Caution, High risk, then No strong indicators.
- Press Ctrl+C in the terminal to stop the server.

The low score on a controlled fixture does not verify a live website's identity.
The interactive page's expected-result text is a teaching aid; open the extension
popup to show its actual verdict and reasons.

**If a result is missing**

Refresh the page after loading/reloading. Internal pages such as
`chrome://extensions`, the Chrome Web Store and browser error pages cannot always
be inspected. A Safe Browsing block may prevent the extension from seeing a page.
For `file://` tests, enable **Allow access to file URLs** in extension details;
the HTTP demo avoids that requirement. The popup updates as scans finish.

In 0.3.0, **Incomplete inspection** means a local low score has missing document
or control coverage. It is not a confirmation that the entire page is legitimate.
Optional reputation pending/errors are shown separately. Worker restarts request
fresh frame results rather than trusting stale stored tab output.

Options can review and export local correction candidates. Review the site and
evidence origin before using a correction; saving it does not retrain the detector.
The [repair report](audit/tester-repairs-2026-10-25.md) maps all audit findings to
their fixes, checks and remaining detection boundaries.
