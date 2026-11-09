"""Offline dataset identity, grouping and provenance shared by train/evaluation.

URL paths, queries and fragments retain case. Private PSL entries are included:
two github.io tenants are different sites. No network lookup happens here.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

PSL_PATH = Path(__file__).resolve().parents[2] / 'extension/src/shared/public-suffix-rules.json'
PHISHING_LABELS = {'0': 0, 'benign': 0, 'legitimate': 0, 'good': 0, 'safe': 0,
                   '1': 1, 'phishing': 1}
MIXED_THREAT_LABELS = {'bad': 1, 'malicious': 1, 'malware': 1, 'defacement': 1}
GROUP_ANNOTATION_FIELDS = ('campaign_id', 'template_group')


def group_annotations(record: dict) -> dict[str, str]:
    """Explicit reviewer-supplied relationships, not automatic label evidence.

    Related campaigns/templates can span registrable sites and have different
    HTML. Keep their reviewed identifiers through imports and frozen identities.
    Absent annotations do not imply campaigns are independent.
    """
    result = {}
    for name in GROUP_ANNOTATION_FIELDS:
        value = record.get(name)
        if value is None or value == '':
            continue
        if not isinstance(value, str) or len(value) > 200 or any(ord(c) < 32 for c in value):
            raise ValueError(f'{name} must be a short plain-text group identifier')
        value = re.sub(r'\s+', ' ', value.strip()).casefold()
        if value:
            result[name] = value
    return result


def annotation_keys(record: dict) -> list[str]:
    return [name + ':' + sha256(value) for name, value in group_annotations(record).items()]


def source_identity(record: dict, fallback: str = '') -> tuple[str, str]:
    """Preserve attribution trust through CSV/JSONL conversions.

    Absence of a provenance column retains the original explicit-source input
    contract. Once a marker exists, including an unknown marker, it can never
    be upgraded by merely serializing a filename into the source column.
    """
    source = str(record.get('source') or '').strip()
    marker = str(record.get('source_provenance') or '').strip().lower()
    if not source:
        return str(fallback).strip(), 'filename_fallback' if fallback else 'missing'
    return source, marker or 'explicit'


def label_value(value, include_other_threats: bool = False) -> int | None:
    if isinstance(value, bool):
        return None
    labels = PHISHING_LABELS | (MIXED_THREAT_LABELS if include_other_threats else {})
    return labels.get(str(value).strip().lower())


def label_is_reviewed(record: dict) -> bool:
    """Do not turn explicitly unreviewed sampling seeds into ground truth.

    A missing status retains the existing caller-supplied-label contract. This
    flag records review work; it cannot prove a human label is correct.
    """
    status = str(record.get('label_status') or '').strip().lower()
    if str(record.get('source') or '').strip().casefold() == 'umbrella-top-1m':
        return status == 'reviewed'
    return not status or status in {'reviewed', 'verified_feed'}


def canonicalize_urls(values: list[str]) -> list[str]:
    """Batch browser-identical normalization with Node's offline WHATWG URL API."""
    bridge = Path(__file__).with_name('canonicalize_urls.cjs')
    result = subprocess.run(['node', str(bridge)], input=json.dumps(values),
        text=True, encoding='utf-8', capture_output=True, check=True)
    return json.loads(result.stdout)


@lru_cache(maxsize=100_000)
def normalize_url(value: str) -> str:
    value = str(value or '').strip()
    if not value or any(ord(ch) < 32 for ch in value):
        return ''
    if '://' not in value:
        value = 'https://' + value
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {'http', 'https'} or not parts.hostname:
            return ''
        host = parts.hostname.lower()
        # This fast path is for ordinary already-escaped ASCII URLs. Delegate
        # Unicode/IDNA, numeric IPv4 notation, dot segments and special escaping
        # to exactly the same WHATWG parser used by Chromium.
        unusual = (not value.isascii() or bool(re.search(r'''[\\\s<>"`{}]''', value))
            or '@' in parts.netloc or '%' in host or "'" in parts.query
            or ('?' in value and not parts.query) or ('#' in value and not parts.fragment)
            or bool(re.search(r'(?:^|/)(?:\.|%2e)(?:\.|%2e)?(?:/|$)', parts.path, re.I)))
        last_label = host.rstrip('.').rsplit('.', 1)[-1]
        if re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)', last_label, re.I):
            try:
                unusual = unusual or str(ipaddress.IPv4Address(host)) != host
            except ValueError:
                unusual = True
        if ':' in host:
            unusual = unusual or str(ipaddress.IPv6Address(host)) != host
        if unusual:
            return canonicalize_urls([value])[0]
        port = parts.port
        if ':' in host:
            host = '[' + host + ']'
        authority = host
        if port is not None and not ((parts.scheme.lower() == 'https' and port == 443) or (parts.scheme.lower() == 'http' and port == 80)):
            authority += ':' + str(port)
        return urlunsplit((parts.scheme.lower(), authority, parts.path or '/', parts.query, parts.fragment))
    except (ValueError, UnicodeError):
        return ''


@lru_cache(maxsize=1)
def public_suffix_rules() -> tuple[set[str], set[str], set[str]]:
    data = json.loads(PSL_PATH.read_text(encoding='utf-8'))
    rules = data['rules']
    digest = hashlib.sha256('\n'.join(rules).encode('utf-8')).hexdigest()
    if data.get('rules_sha256') != digest:
        raise ValueError('Pinned Public Suffix List hash mismatch')
    return ({r for r in rules if not r.startswith(('!', '*.'))},
            {r[2:] for r in rules if r.startswith('*.')},
            {r[1:] for r in rules if r.startswith('!')})


def registrable_domain(value: str) -> str:
    normalized = normalize_url(value if '://' in value else 'https://' + value)
    hostname = (urlsplit(normalized).hostname or '').lower().rstrip('.')
    if not hostname:
        raise ValueError(f'Invalid URL/host: {value!r}')
    try:
        address = ipaddress.ip_address(hostname)
        return '[' + str(address) + ']' if address.version == 6 else str(address)
    except ValueError:
        pass
    labels = hostname.split('.')
    exact, wildcard, exceptions = public_suffix_rules()
    if len(labels) == 1:
        return '' if hostname in exact else hostname
    suffix_size = 1
    for start in range(len(labels)):
        candidate = '.'.join(labels[start:])
        if candidate in exceptions:
            suffix_size = len(labels) - start - 1
            break
        if candidate in exact:
            suffix_size = max(suffix_size, len(labels) - start)
        if start > 0 and candidate in wildcard:
            suffix_size = max(suffix_size, len(labels) - start + 1)
    return '.'.join(labels[-(suffix_size + 1):]) if len(labels) > suffix_size else ''


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def aware_timestamp(value, name: str = 'Timestamp') -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('timezone missing')
        return parsed
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(f'{name} requires a timezone-aware ISO timestamp') from error


def content_hash(record: dict) -> str:
    # Exact snapshots are linked; broad whitespace collapsing can alter script/text
    # semantics and is deliberately not used to claim near-duplicate protection.
    return sha256(record['html'].strip()) if record.get('html', '').strip() else ''


def record_domains(record: dict) -> set[str]:
    return {registrable_domain(url) or (urlsplit(url).hostname or '')
            for url in [record['url'], record.get('final_url') or record['url']]}


def connected_groups(records: list[dict]) -> list[str]:
    """Union sites, duplicate content and explicit campaign/template relationships."""
    parents: dict[str, str] = {}
    sizes: dict[str, int] = {}

    def find(key):
        parents.setdefault(key, key)
        sizes.setdefault(key, 1)
        root = key
        while parents[root] != root:
            root = parents[root]
        while parents[key] != key:
            previous = parents[key]
            parents[key] = root
            key = previous
        return root

    def union(a, b):
        first, second = find(a), find(b)
        if first == second:
            return
        if sizes[first] < sizes[second]:
            first, second = second, first
        parents[second] = first
        sizes[first] += sizes[second]

    keys = []
    for record in records:
        group_keys = ['domain:' + value for value in sorted(record_domains(record))]
        digest = content_hash(record)
        if digest:
            group_keys.append('html:' + digest)
        group_keys.extend('annotation:' + key for key in annotation_keys(record))
        for key in group_keys[1:]:
            union(group_keys[0], key)
        keys.append(group_keys[0])
    return [find(key) for key in keys]


def manifest(records: list[dict], purpose: str) -> dict:
    times = sorted({record.get('observed_at', '') for record in records if record.get('observed_at')})
    annotated = any(group_annotations(record) for record in records)
    result = {
        'version': 3, 'purpose': purpose, 'created_at': datetime.now(timezone.utc).isoformat(),
        'samples': len(records),
        'class_counts': {str(label): sum(r['label'] == label for r in records) for label in [0, 1]},
        'url_sha256': sorted({sha256(normalize_url(url)) for r in records for url in [r['url'], r.get('final_url') or r['url']]}),
        'domain_sha256': sorted({sha256(domain) for r in records for domain in record_domains(r)}),
        'content_sha256': sorted({content_hash(r) for r in records if content_hash(r)}),
        'record_sha256': sorted(sha256(json.dumps({
            'url': normalize_url(r['url']), 'final_url': normalize_url(r.get('final_url') or r['url']),
            'label': r['label'], 'source': r.get('source',''), 'observed_at': r.get('observed_at',''),
            'label_status': r.get('label_status', ''),
            'source_provenance': source_identity(r)[1],
            'reviewed_by': r.get('reviewed_by', ''), 'reviewed_at': r.get('reviewed_at', ''),
            'label_evidence': r.get('label_evidence', ''),
            'navigation_response': r.get('navigation_response'),
            'capture_document_status': r.get('capture_document_status'),
            'content_sha256': content_hash(r), 'title': r.get('title',''),
            'page_type': r.get('page_type',''),
            'feature_row': r.get('feature_row'), 'extractor_sha256': r.get('extractor_sha256'),
            'policy_features': r.get('policy_features'), 'policy_version':r.get('policy_version'),
            'policy_sha256':r.get('policy_sha256'),
            'capture_execution_world': r.get('capture_execution_world'),
            **({'group_annotations': group_annotations(r)} if group_annotations(r) else {}),
        }, sort_keys=True, separators=(',', ':'))) for r in records),
        'sources': sorted({str(r.get('source') or '').strip().casefold() for r in records}),
        'identified_source_samples': sum(bool(source_identity(r)[0])
            and source_identity(r)[1] == 'explicit' for r in records),
        'observed_at': times,
        'dated_samples': sum(bool(r.get('observed_at')) for r in records),
    }
    # Preserve historical v3 identities for unannotated collections. Adding or
    # changing annotations creates a new identity and cannot bless an old test.
    if annotated:
        result.update(version=4, group_sha256=sorted({sha256(key) for r in records for key in annotation_keys(r)}))
    return result


def assert_separated(reference: dict, candidate: dict, *, source_time: bool = False) -> dict:
    overlaps = {key: len(set(reference.get(key, [])) & set(candidate.get(key, [])))
                for key in ['url_sha256', 'domain_sha256', 'content_sha256', 'group_sha256']}
    if any(overlaps.values()):
        raise ValueError(f'Dataset overlaps training/selection data: {overlaps}')
    if source_time:
        sources = reference.get('sources', []) + candidate.get('sources', [])
        if (not reference.get('sources') or not candidate.get('sources')
            or any(not value or not str(value).strip() for value in sources)):
            raise ValueError('Future evaluation requires identified provenance sources for every sample')
        if any(value.get('identified_source_samples') != value['samples'] for value in [reference, candidate]):
            raise ValueError('Future evaluation requires explicit provenance for every sample; filename fallback is not an independent source')
        normalized_sources = lambda value: {str(source).strip().casefold() for source in value.get('sources', [])}
        if normalized_sources(reference) & normalized_sources(candidate):
            raise ValueError('Future evaluation sources overlap training/selection sources')
        if reference.get('dated_samples') != reference['samples'] or candidate.get('dated_samples') != candidate['samples']:
            raise ValueError('Future evaluation requires capture/observation dates for every sample')
        try:
            reference_dates = [aware_timestamp(t, 'Observation date') for t in reference['observed_at']]
            candidate_dates = [aware_timestamp(t, 'Observation date') for t in candidate['observed_at']]
            if max(reference_dates + candidate_dates) > datetime.now(timezone.utc):
                raise ValueError('Observation dates must not be in the future')
            if min(candidate_dates) <= max(reference_dates):
                raise ValueError('Future evaluation dates must be later than all training/selection dates')
        except (TypeError, IndexError) as error:
            raise ValueError('Observation dates must be valid ISO 8601 timestamps') from error
    return {'passed': True, 'overlaps': overlaps, 'source_time_separated': source_time}
