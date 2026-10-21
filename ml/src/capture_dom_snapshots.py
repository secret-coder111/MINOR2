"""Safely capture bounded DOM snapshots for a reviewed URL list.

This uses an isolated Playwright context. It never submits forms, grants permissions,
downloads files, or permits navigation to localhost/private-network destinations.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import time
from pathlib import Path
from urllib.parse import urlsplit


def is_public_host(hostname: str) -> bool:
    try:
        address = ipaddress.ip_address(hostname)
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        )
    except ValueError:
        try:
            addresses = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return False
        return all(is_public_host(item[4][0]) for item in addresses)


def capture(input_file: Path, output_file: Path, limit: int | None, timeout_ms: int) -> None:
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
        page = context.new_page()
        page.set_default_navigation_timeout(timeout_ms)

        def route_request(route) -> None:
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

        context.route("**/*", route_request)

        def redirect_count(response) -> int:
            count = 0
            request = response.request if response else None
            while request and request.redirected_from:
                count += 1
                request = request.redirected_from
            return count

        with output_file.open("w", encoding="utf-8") as output:
            for row in rows:
                url = (row.get("url") or "").strip()
                label = (row.get("label") or row.get("type") or "").strip().lower()
                if not url or label not in {"0", "1", "benign", "legitimate", "good", "bad", "phishing", "malware", "defacement", "malicious"}:
                    continue
                parsed = urlsplit(url if "://" in url else f"https://{url}")
                if parsed.scheme not in {"http", "https"} or not parsed.hostname or not is_public_host(parsed.hostname):
                    continue
                started = time.monotonic()
                record = {
                    "url": url,
                    "label": 0 if label in {"0", "benign", "legitimate", "good"} else 1,
                    "source": row.get("source") or input_file.stem,
                }
                try:
                    response = page.goto(url, wait_until="domcontentloaded")
                    page.wait_for_timeout(250)
                    record.update({
                        "final_url": page.url,
                        "title": page.title(),
                        "html": page.content(),
                        "status": response.status if response else None,
                        "redirect_count": redirect_count(response),
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
