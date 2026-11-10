# PhishGuard 0.6.0

PhishGuard is a Chromium extension that examines the address, page structure and credential forms of the current tab. It reports the evidence behind each verdict. The repository includes a local demo website, a URL checker and an offline model research pipeline.

## Run the demo website

Install Node.js 22 or newer, open a terminal in the repository root and run:

```powershell
npm.cmd run demo
```

On macOS or Linux, use `npm run demo`. Open [the demo home page](http://127.0.0.1:8080/) or [the URL checker](http://127.0.0.1:8080/url-checker.html). Keep the terminal open while you use the site. Press **Ctrl+C** to stop the server.

The demo server uses Node's built-in modules. You can start it immediately after downloading the project. If port 8080 is busy, stop the previous demo process and rerun the command.

## Load the extension in Chrome or Edge

1. Open `chrome://extensions` in Chrome or `edge://extensions` in Edge.
2. Turn on **Developer mode** and choose **Load unpacked**.
3. Select the repository's **`extension/`** folder, which contains `manifest.json`.
4. Confirm the card displays **PhishGuard 0.6.0**, pin it from the toolbar and refresh the demo tab.

The installed extension runs locally without a build or Python service. After source changes, click **Reload** on the extension card and refresh any open tabs you want to inspect. Disable older copies loaded from other folders. For a classroom walkthrough, use the ordinary-login, caution, high-risk and dynamic demo pages, and open the extension popup to read the live verdict. [Loading and troubleshooting](docs/load-extension.md) · [Presentation walkthrough](docs/professor-demonstration.md)

## What changed in 0.6.0

- The browser toolbar badge shows the state of the current scan, including caution, high risk and incomplete coverage. The popup displays available scan timing measurements.
- Brand checks can use visible authentication headings and accessible image names associated with the same sensitive form. The detector checks form context and excludes provider buttons and links from this identity signal.
- GET exposure checks account for whether the submission would include a named sensitive field. For example, a visible password field without a submitted name supplies login context without adding GET exposure evidence.
- Offline evaluation can group related records by reviewed campaign or template annotations and measure how removing an evidence family affects results on development captures.

[Architecture](docs/architecture.md) · [Feature dictionary](docs/feature-dictionary.md) · [Offline ML workflow](ml/README.md)

## What each result measures

| Where you see it | What it measures |
| --- | --- |
| Extension popup, badge and warning | Local evidence from the loaded page and inspected frames. High risk normally requires a credential context, corroborating evidence and the warning threshold, which defaults to 65. An explicitly enabled reputation service can also report a malicious verdict. |
| URL checker | Address and transport observations from the pasted URL. Pasting a URL runs the check locally without navigating to that address. Choose **Open page for an extension check** to inspect a loaded page separately. |
| Experimental model panel | The 3 November character TF-IDF and logistic regression diagnostic. Its reused internal test recorded 92.57% accuracy, 98.21% precision, 85.79% recall and 1.40% false-positive rate. |

The live extension uses the **0.6.0 evidence policy**. Its risk index expresses the strength of observed evidence. **No strong indicators** describes what was found during inspection. **Incomplete inspection** means some content was unchecked.

The 6 November login-boundary research candidate recorded **93.29% accuracy, 98.42% precision, 87.01% recall, 92.36% F1 and 1.22% false-positive rate** on a reused internal test with known login development sites excluded. It remains an offline experiment. The packaged checker retains the 3 November diagnostic. Both sets of metrics describe the indicated URL research tests, and representative live-extension accuracy remains unmeasured. [Packaged diagnostic results](docs/audit/url-checker-research-2026-11-03-expanded-comparison.json) · [6 November comparison](docs/audit/url-checker-research-2026-11-06-login-boundaries-comparison.json)

## Privacy and inspection coverage

The extension inspects field metadata without reading typed credentials. Optional reputation lookup is off by default. When enabled, it sends the inspected hostname to the configured service. Session tab results omit URL paths and queries. User-reviewed corrections can be exported for research. Predictions use the fixed release policy.

The browser limits inspection of protected pages, opaque frames and closed shadow roots. The extension uses accessible text and DOM structure, so image-only deception without readable metadata and arbitrary script behavior can escape inspection. [Privacy details](docs/privacy-policy.md)

## Development checks

From the repository root:

```powershell
npm.cmd ci
npm.cmd test
npm.cmd run test:demo
npm.cmd run test:browser
```

The browser smoke test needs a supported installed browser. For Python tests, install the dependencies in [`ml/requirements.txt`](ml/requirements.txt) and run `python -m unittest discover -s ml/tests -v`. See the [ML README](ml/README.md) for training inputs, calibration and release evaluation.
