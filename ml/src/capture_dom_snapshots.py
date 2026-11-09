"""Safely capture bounded DOM snapshots for a reviewed URL list.

This uses a fresh Playwright context. The collector never clicks/submits forms,
blocks non-GET/HEAD requests and WebSockets, and does not grant permissions or allow downloads.
Page JavaScript still runs and may initiate GET requests; this is not a malware sandbox.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import hashlib
import re
from html import escape
from html.parser import HTMLParser
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from dataset_contract import label_value, normalize_url, label_is_reviewed, source_identity
from feature_engineering import (FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION, POLICY_VERSION,
    filter_policy_features, policy_source_hash, validate_feature_row)


def redact_field_values(source: str) -> str:
    """Retain structural HTML while dropping input values and textarea contents."""
    class Redactor(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.parts, self.in_textarea = [], False
        def handle_starttag(self, tag, attrs):
            self.parts.append('<' + tag + ''.join(' '+name if value is None else ' '+name+'="'+escape(value,quote=True)+'"'
                for name,value in attrs if not (tag == 'input' and name == 'value')) + '>')
            if tag == 'textarea': self.in_textarea = True
        def handle_startendtag(self, tag, attrs):
            self.handle_starttag(tag, attrs)
        def handle_endtag(self, tag):
            if tag == 'textarea': self.in_textarea = False
            self.parts.append('</'+tag+'>')
        def handle_data(self, value):
            if not self.in_textarea: self.parts.append(value)
        def handle_entityref(self, name):
            if not self.in_textarea: self.parts.append('&'+name+';')
        def handle_charref(self, name):
            if not self.in_textarea: self.parts.append('&#'+name+';')
        def handle_comment(self, value): self.parts.append('<!--'+value+'-->')
        def handle_decl(self, value): self.parts.append('<!'+value+'>')
    parser = Redactor()
    parser.feed(source)
    parser.close()
    return ''.join(parser.parts)


def browser_extractor() -> tuple[str, str]:
    root = Path(__file__).resolve().parents[2] / 'extension'
    names = ['src/shared/feature-schema.js', 'src/shared/constants.js', 'src/shared/public-suffix.js',
             'src/shared/domain-utils.js', 'src/shared/document-context.js', 'src/content/url-features.js',
             'src/content/form-features.js', 'src/content/dom-features.js']
    source = '\n'.join((root / name).read_text(encoding='utf-8') for name in names)
    script = '() => { window.PhishGuard = {}; ' + source + '''
        const form = window.PhishGuard.extractFormFeatures();
        return {...window.PhishGuard.extractUrlFeatures(), ...form,
            ...window.PhishGuard.extractDomFeatures(form)};
    }'''
    return script, hashlib.sha256(source.encode('utf-8')).hexdigest()


def capture_expression(extractor: str) -> str:
    """Read a single document state inside a trusted, isolated JS world."""
    return '''(() => {
        const features = (''' + extractor + ''')();
        const html = document.documentElement?.outerHTML || '';
        if (html.length > 2000000) throw new Error('Snapshot exceeds capture limit');
        return {features, html, title: document.title, final_url: location.href};
    })()'''


def isolated_snapshot(context, page, extractor: str, timeout_ms: int) -> dict:
    """Use extension-like JS isolation; never execute extraction in page MAIN.

    A page can replace its own DOM/Array prototypes and global bindings. CDP's
    isolated world has fresh bindings while observing the same live DOM, just
    like the extension's isolated content scripts. No cross-origin access is
    granted to this world.
    """
    session = context.new_cdp_session(page)
    try:
        # CDP domains are scoped to this newly attached session. Playwright's
        # own enabled Page domain belongs to a different session.
        session.send('Page.enable')
        session.send('Runtime.enable')
        before = session.send('Page.getFrameTree')['frameTree']['frame']
        frame_id = before['id']
        if not before.get('loaderId'):
            raise ValueError('Capture document loader identity is missing')
        world = session.send('Page.createIsolatedWorld', {
            'frameId': frame_id, 'worldName': 'phishguard-capture',
        })
        result = session.send('Runtime.evaluate', {
            'expression': capture_expression(extractor),
            'contextId': world['executionContextId'],
            'returnByValue': True, 'timeout': timeout_ms,
        })
        if result.get('exceptionDetails') or 'value' not in result.get('result', {}):
            raise ValueError('Isolated browser extraction failed; snapshot is not trusted')
        snapshot = result['result']['value']
        if (not isinstance(snapshot, dict) or not isinstance(snapshot.get('features'), dict)
            or not all(isinstance(snapshot.get(name), str) for name in ['html', 'title', 'final_url'])):
            raise ValueError('Isolated browser extraction returned an invalid snapshot')
        validate_feature_row({name: snapshot['features'].get(name) for name in FEATURE_SCHEMA})
        after = session.send('Page.getFrameTree')['frameTree']['frame']
        if (after.get('id'), after.get('loaderId')) != (frame_id, before['loaderId']):
            raise ValueError('Page navigated during isolated extraction')
        snapshot['document_identity'] = {'frame_id': frame_id, 'loader_id': before['loaderId']}
        return snapshot
    finally:
        session.detach()


class DocumentResponses:
    """Observe navigation responses before navigation; bind via CDP loader ID.

    URL equality cannot distinguish reloads or a completed script navigation.
    loaderId identifies the network document even after history.pushState.
    """
    def __init__(self, context, page):
        self.session = context.new_cdp_session(page)
        self.responses = {}
        self.redirects = {}
        self.request_count = 0
        self.session.on('Network.requestWillBeSent', self._request)
        self.session.on('Network.responseReceived', self._response)
        self.session.send('Network.enable')

    def _request(self, event):
        if event.get('type') != 'Document':
            return
        self.request_count += 1
        if self.request_count > 128:
            return
        identity = (event.get('frameId'), event.get('loaderId'))
        prior = event.get('redirectResponse')
        if prior:
            self.redirects.setdefault(identity, []).append({'url': prior.get('url'), 'status': prior.get('status')})

    def _response(self, event):
        if event.get('type') != 'Document':
            return
        response = event.get('response', {})
        identity = (event.get('frameId'), event.get('loaderId'))
        if not all(isinstance(value, str) and value for value in identity):
            return
        self.responses[identity] = {'frame_id': identity[0], 'loader_id': identity[1],
            'url': response.get('url'), 'status': response.get('status'),
            'redirect_chain': list(self.redirects.get(identity, []))}
        # A hostile loop must not make capture metadata unbounded. If the exact
        # requested loader is evicted, capture is rejected rather than guessed.
        while len(self.responses) > 128:
            oldest = next(iter(self.responses))
            self.responses.pop(oldest)
            self.redirects.pop(oldest, None)

    def for_snapshot(self, snapshot):
        identity = snapshot.get('document_identity') or {}
        if self.request_count > 128:
            raise ValueError('Too many navigation requests for a bounded trusted capture')
        response = self.responses.get((identity.get('frame_id'), identity.get('loader_id')))
        if (response is None or not normalize_url(response.get('url') or '')
            or type(response.get('status')) not in [int, float]
            or not float(response['status']).is_integer()):
            raise ValueError('No HTTP navigation response matches the captured document loader')
        return {**response, 'status': int(response['status'])}

    def close(self):
        self.session.detach()


def is_public_host(hostname: str) -> bool:
    try:
        address = ipaddress.ip_address(hostname)
        # is_private alone misses shared/CGNAT space (100.64.0.0/10), which
        # must not be reachable through an untrusted page's resource URLs.
        return address.is_global and not address.is_multicast
    except ValueError:
        try:
            addresses = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return False
        return bool(addresses) and all(is_public_host(item[4][0]) for item in addresses)


def configure_capture_routes(context, route_request, blocked_channels: list[str]) -> None:
    """Install HTTP and WebSocket guards before any page is created."""
    if not callable(getattr(context, 'route_web_socket', None)):
        raise RuntimeError('Capture requires Playwright >= 1.48 for WebSocket blocking')
    context.route('**/*', route_request)
    def block_web_socket(route):
        blocked_channels.append('WEBSOCKET')
        # Without connect_to_server(), the routed socket has no upstream.
        route.close()
    context.route_web_socket('**/*', block_web_socket)


def capture(input_file: Path, output_file: Path, limit: int | None, timeout_ms: int) -> None:
    if limit is not None and limit < 1:
        raise ValueError('Capture limit must be positive or omitted')
    if timeout_ms <= 0:
        raise ValueError('Capture timeout must be positive')
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError(
            "Playwright is required for capture. Install it separately, then run "
            "`playwright install chromium` in the isolated capture environment."
        ) from error

    with input_file.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if limit:
        rows = rows[:limit]
    output_file.parent.mkdir(parents=True, exist_ok=True)
    if output_file.exists():
        raise ValueError('Use a new capture output path to preserve the original snapshot evidence')
    extractor, extractor_hash = browser_extractor()

    with sync_playwright() as playwright, playwright.chromium.launch(
        headless=True,
        downloads_path=None,
    ) as browser:
        context = browser.new_context(
            java_script_enabled=True,
            accept_downloads=False,
            service_workers="block",
            permissions=[],
            ignore_https_errors=False,
        )
        context.set_default_timeout(timeout_ms)
        blocked_methods = []
        blocked_channels = []

        def route_request(route) -> None:
            if route.request.method.upper() not in {'GET','HEAD'}:
                blocked_methods.append(route.request.method.upper())
                route.abort()
                return
            request_url = urlsplit(route.request.url)
            if request_url.scheme not in {"http", "https"}:
                route.abort()
                return
            if not request_url.hostname or not is_public_host(request_url.hostname):
                route.abort()
                return
            if route.request.resource_type == "download":
                route.abort()
                return
            route.continue_()

        configure_capture_routes(context, route_request, blocked_channels)
        page = context.new_page()
        page.set_default_navigation_timeout(timeout_ms)

        with output_file.open("w", encoding="utf-8") as output:
            for row in rows:
                url = (row.get("url") or "").strip()
                label = label_value(row.get('label') or row.get('type'))
                url = normalize_url(url)
                if not url or label is None or not label_is_reviewed(row):
                    continue
                parsed = urlsplit(url if "://" in url else f"https://{url}")
                if parsed.scheme not in {"http", "https"} or not parsed.hostname or not is_public_host(parsed.hostname):
                    continue
                started = time.monotonic()
                source, provenance = source_identity(row, input_file.stem)
                record = {
                    "url": url,
                    "label": label,
                    "source": source,
                    'source_provenance': provenance,
                    'label_status': (row.get('label_status') or '').strip(),
                    **{name: (row.get(name) or '').strip() for name in ['reviewed_by', 'reviewed_at', 'label_evidence', 'page_type', 'campaign_id', 'template_group']},
                    'observed_at': datetime.now(timezone.utc).isoformat(),
                    'capture_success': False,
                }
                try:
                    # No prior page's cookies/storage are reused for the next sample.
                    page.close()
                    context.close()
                    blocked_methods.clear()
                    blocked_channels.clear()
                    context = browser.new_context(java_script_enabled=True, accept_downloads=False,
                        service_workers='block', permissions=[], ignore_https_errors=False)
                    context.set_default_timeout(timeout_ms)
                    configure_capture_routes(context, route_request, blocked_channels)
                    page = context.new_page()
                    page.set_default_navigation_timeout(timeout_ms)
                    responses = DocumentResponses(context, page)
                    try:
                        page.goto(url, wait_until="domcontentloaded")
                        page.wait_for_timeout(250)
                        snapshot = isolated_snapshot(context, page, extractor, timeout_ms)
                        navigation_response = responses.for_snapshot(snapshot)
                    finally:
                        responses.close()
                    title, html, features = snapshot['title'], snapshot['html'], snapshot['features']
                    if snapshot['final_url'] != page.url:
                        raise ValueError('Page navigated during capture; recapture the actual final document')
                    if len(html.encode('utf-8')) > 2_000_000:
                        raise ValueError('Snapshot exceeds 2 MiB capture limit')
                    status = navigation_response['status']
                    quality = 'review_required' if re.search(r'just a moment|checking your browser|access denied|verify (?:you are|that you are) human', title, re.I) else 'ok'
                    if blocked_methods or blocked_channels:
                        quality = 'review_required'
                    record.update({
                        "final_url": snapshot['final_url'],
                        "title": title,
                        "html": redact_field_values(html),
                        "status": status,
                        'navigation_response': navigation_response,
                        'capture_document_status': 'bound_to_loader',
                        'capture_success': bool(status is not None and 200 <= status < 300 and html.strip()),
                        'capture_quality': quality,
                        'blocked_non_read_requests': len(blocked_methods),
                        'blocked_web_sockets': len(blocked_channels),
                        'capture_partial': bool(blocked_methods or blocked_channels),
                        'field_values_redacted': True,
                        'capture_execution_world': 'isolated',
                        'feature_schema_version': FEATURE_SCHEMA_VERSION,
                        'extractor_sha256': extractor_hash,
                        'feature_row': {name: features[name] for name in FEATURE_SCHEMA},
                        'policy_features': filter_policy_features(features),
                        'policy_version': POLICY_VERSION,
                        'policy_sha256': policy_source_hash(),
                        "redirect_count": len(navigation_response['redirect_chain']),
                        "capture_seconds": round(time.monotonic() - started, 3),
                    })
                except Exception as error:
                    record.update({
                        "error": type(error).__name__,
                        "capture_seconds": round(time.monotonic() - started, 3),
                    })
                output.write(json.dumps(record, ensure_ascii=False) + "\n")
                output.flush()
        context.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_file", type=Path, help="CSV with url and label/type columns")
    parser.add_argument("output_file", type=Path, help="JSONL snapshot output")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout-ms", type=int, default=10_000)
    args = parser.parse_args()
    capture(args.input_file, args.output_file, args.limit, args.timeout_ms)


if __name__ == "__main__":
    main()
