"""Import phishing feeds or unreviewed popularity seeds into a local CSV."""

from __future__ import annotations

import argparse
import csv
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

OPENPHISH_URL = 'https://openphish.com/feed.txt'
PHISHTANK_URL = 'https://data.phishtank.com/data/online-valid.csv'
UMBRELLA_URL = 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'


def download_text(url: str) -> str:
    request = Request(url, headers={'User-Agent': 'PhishGuard research feed importer/0.1'})
    with urlopen(request, timeout=60) as response:
        return response.read().decode('utf-8', errors='replace')


def collect_openphish() -> list[dict[str, str]]:
    observed_at = datetime.now(timezone.utc).isoformat()
    return [
        {'url': line.strip(), 'label': 'phishing', 'source': 'openphish', 'observed_at': observed_at}
        for line in download_text(OPENPHISH_URL).splitlines()
        if line.strip().startswith(('http://', 'https://'))
    ]


def collect_phishtank() -> list[dict[str, str]]:
    observed_at = datetime.now(timezone.utc).isoformat()
    reader = csv.DictReader(io.StringIO(download_text(PHISHTANK_URL)))
    records = []
    for row in reader:
        url = (row.get('url') or '').strip()
        if url.startswith(('http://', 'https://')):
            records.append({
                'url': url,
                'label': 'phishing',
                'source': 'phishtank',
                'observed_at': observed_at,
            })
    return records


def collect_umbrella() -> list[dict[str, str]]:
    observed_at = datetime.now(timezone.utc).isoformat()
    request = Request(UMBRELLA_URL, headers={'User-Agent': 'PhishGuard research feed importer/0.1'})
    with urlopen(request, timeout=60) as response:
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
        filename = archive.namelist()[0]
        lines = archive.read(filename).decode('utf-8', errors='replace').splitlines()
    return [
        # Popularity is a sampling source, not proof that a site/page is safe.
        # A reviewer must inspect and label these seeds before training/capture.
        {'url': f'https://{line.split(",", 1)[1].strip()}', 'label': '',
         'label_status': 'unreviewed_popularity_seed',
         'source': 'umbrella-top-1m', 'observed_at': observed_at}
        for line in lines
        if ',' in line and line.split(',', 1)[1].strip()
    ]


def write_records(records: list[dict[str, str]], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('w', encoding='utf-8', newline='') as handle:
        # Preserve provenance/review columns when exporting reviewed records.
        # Dropping filename_fallback here would upgrade it on the next import.
        columns = ['url', 'label', 'label_status', 'source', 'source_provenance', 'observed_at',
                   'reviewed_by', 'reviewed_at', 'label_evidence', 'page_type']
        writer = csv.DictWriter(handle, fieldnames=columns + sorted({key for row in records for key in row} - set(columns)))
        writer.writeheader()
        writer.writerows(records)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openphish', action='store_true')
    parser.add_argument('--phishtank', action='store_true')
    parser.add_argument('--umbrella', action='store_true')
    parser.add_argument('--output', type=Path, default=Path('ml/data/recent_phishing_feeds.csv'))
    args = parser.parse_args()
    if not args.openphish and not args.phishtank and not args.umbrella:
        parser.error('Choose --openphish, --phishtank, and/or --umbrella')

    records = []
    if args.openphish:
        records.extend(collect_openphish())
    if args.phishtank:
        records.extend(collect_phishtank())
    if args.umbrella:
        records.extend(collect_umbrella())
    write_records(records, args.output)
    print(f'Wrote {len(records)} records to {args.output}')


if __name__ == '__main__':
    main()
