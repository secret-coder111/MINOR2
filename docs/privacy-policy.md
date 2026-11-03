# Privacy policy - PhishGuard 0.4.0

The standalone URL checker reads only the address explicitly entered into its
URL field. It processes that address locally, does not automatically visit or
upload it, and saves no checking history. Its static diagnostic model is
separate from the extension's full-page verdicts. The former credential-entry
demonstration has been removed. Closing a warning keeps only a temporary
in-memory dismissal for that document; it does not save a hostname exemption.

Detection runs locally by default. The extension inspects URL structure, field
metadata and form destinations, DOM/script structure and generic brand indicators
in the title and visible text. It does not read typed input values, password
values, cookies or browser history.
Field metadata includes associated label text, ARIA names and placeholders;
editable label descendants and textarea contents are excluded from label reading.
Brand text scanning also excludes controls and editable regions. Open shadow roots
are inspected; closed roots are not bypassed. Result coverage identifies embedded
documents the extension could not inspect when the browser provides an inventory.

The local address check compares reviewed visual character substitutions and
embedded official-domain labels with a short primary brand heading next to the
same sensitive form. It does not fetch logos, screenshots, domain registration
records or page text from any external service. The popup displays site origins
and can request another local scan of the current page and its accessible frames.

Full document URLs are used in memory for analysis and rejection of old results.
Tab results in browser session storage omit URL paths, queries and fragments and
are removed when tabs close. Session storage is not exposed to content scripts.
Legacy persistent tab records are removed on upgrade/start.

Corrections require an explicit user action. They contain the top-page origin and
the evidence-frame origin (scheme, hostname and port), evidence frame number,
expected/observed outcome, score, timestamp and policy version. Coarse context
includes inspected, uninspected and pending document counts, coverage completeness,
optional reputation status and fixed evidence category names. Full URLs, page text,
field names/values and raw explanation text are excluded. Up to 100 entries are
retained locally; legacy records are sanitized or discarded. A failed storage
operation does not report that a save or deletion succeeded.

Options lets the user review corrections, mark checked entries for export and
clear all saved corrections. Export is an explicit JSON download containing only
reviewed, sanitized entries and a declaration that they are unverified candidates.
The file includes site origins and should be checked before sharing. No feedback
is uploaded, used as an allowlist, automatically learned, or treated as verified
ground truth. User review does not independently establish legitimacy. Separate
ownership and label verification is necessary before using candidates in an
evaluation or training dataset.

Optional reputation is disabled until the user enables it and supplies an
endpoint. It sends only each inspected document's hostname, including inspected
HTTP(S) frames, not paths, queries, form content or page text. Requests omit
credentials and reject redirects. Remote HTTPS is required, except localhost HTTP
for development. Embedded URL credentials and fragments are rejected. The
configured endpoint is saved in local settings. The configured service sees the hostname and ordinary connection
metadata such as IP address. The popup displays pending or failed optional lookups;
a failed request supplies no reputation verdict. A local Low risk result with
known missing/pending document coverage is displayed as incomplete inspection.
Successful inspection or an unknown/clean reputation response is no safety guarantee.
Changing reputation settings aborts pending requests and ignores their late results.

Optional reputation requests for the same endpoint and hostname share in-flight
work. A bounded cache holds at most 256 hostname verdicts with timestamps and an
endpoint digest. Available verdicts can remain in browser session storage after a
tab closes. Malicious verdicts stop being reused after ten minutes, safe/benign
verdicts after five minutes and unknown verdicts after thirty seconds. Expired
physical records can remain until the next cache write/clear or browser session
end. Failed lookups are held in worker memory briefly to avoid repeated requests.
Cache entries do not retain
the configured endpoint's path/query, page URL paths, page text or form values.
Disabling reputation clears the cached hostname verdicts.

Domain-age lookup is not implemented and no longer has a misleading control.
The bundled offline public suffix list makes no network requests. The extension
does not include API keys. Permissions support inspection, navigation events,
local/session storage and optional requests to the user-configured service.
