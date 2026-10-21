# PhishGuard

A privacy-first browser extension that analyzes visited webpages locally and warns users about possible phishing patterns without uploading page contents or user credentials.

## Project goal

This project is a first working prototype for a browser-based phishing detector that:

- inspects URL, DOM, form, and static script signals on the page
- rescans after SPA route changes and dynamically inserted credential elements
- runs lightweight local inference on-device
- assigns a risk score between 0 and 100
- explains the strongest evidence in plain language
- never auto-submits or sends browsing data away from the browser

## Core design decisions

- Core phishing detection runs locally on the user device.
- The browser sees only URL and page structure; it does not inspect sensitive input values.
- Domain age lookup is optional and user-controlled.
- Hostname reputation lookup is optional and user-controlled; it is disabled unless the user supplies an endpoint.
- The first version warns instead of blocking automatically.
- Official brand domains are treated as trusted only until strong page-level evidence appears; a brand name alone is not a verdict.
- Explanations are based on observable page evidence rather than vague AI claims.

## Repository structure

- `extension/` — Chrome/Firefox WebExtension sources
- `ml/` — Python training pipeline for the feature schema and model
- `docs/` — architecture, privacy, and evaluation notes

## Quick start

1. Open the `extension/` folder in a Chromium-based browser with developer mode enabled.
2. Load the unpacked extension.
3. Visit a local test page or a safe demo page to observe the badge and popup.
4. Use the popup to view the score and reasons.

## Planned milestones

- Build the extension shell and feature schema
- Implement URL, DOM, and form extractors
- Add on-device scoring and explanations
- Add popup, warning banner, and options page
- Train a baseline Python model against the same feature names
- Export a versioned model package for browser inference

## Training evaluation

The training pipeline keeps URLs from the same registrable domain in the same partition. This grouped split gives a more realistic estimate of performance on previously unseen domains than a random URL split.

## Privacy statement

This project is designed to keep analysis local by default. It does not read user-entered form values, cookies, or page secrets. Any optional enrichment such as domain-age lookup must be explicitly enabled and only sends the hostname to the enrichment provider.
