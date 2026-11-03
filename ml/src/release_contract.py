"""Predeclared release criteria; synthetic fixtures never establish accuracy.

The defaults are product acceptance targets, not achieved measurements. They
are stored before training and checked again at export. Change these targets
only before collecting/freezing a new test, never after seeing its results.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import math

from dataset_contract import aware_timestamp, connected_groups, source_identity, normalize_url
from train_model import wilson_interval


def release_requirements() -> dict:
    return {
        'version': 'phishguard-release-v1',
        'minimum_recall_lower_95ci': .80,
        'maximum_false_positive_rate_upper_95ci': .01,
        'minimum_independent_phishing_groups': 100,
        'minimum_independent_legitimate_groups': 400,
        'minimum_sources_per_class': 2,
        'minimum_per_legitimate_page_type': 20,
        'required_legitimate_page_types': ['login', 'sso', 'banking', 'education', 'payment', 'non_login'],
    }


def assert_reviews_frozen(records: list[dict], frozen_at: datetime) -> None:
    """A frozen label's review evidence must already exist at freeze time."""
    for record in records:
        if record.get('reviewed_at') and aware_timestamp(record['reviewed_at'], 'Review date') > frozen_at:
            raise ValueError('Label reviews must exist before the test manifest is frozen')


def independent_group_metrics(records: list[dict], predictions) -> dict:
    """Conservatively score independent connected sites/exact-content groups.

    Any warned legitimate page makes its group's legitimate outcome a false
    positive; any missed phishing page makes its phishing outcome a miss. A
    mixed-label group contributes to both classes, without treating its pages
    as independent observations. Near-duplicate/campaign review remains human.
    """
    groups = {}
    if len(records) != len(predictions):
        raise ValueError('One prediction is required for each evaluation record')
    for group, record, positive in zip(connected_groups(records), records, predictions):
        groups.setdefault(group, {0: [], 1: []})[record['label']].append(bool(positive))
    negative = [any(group[0]) for group in groups.values() if group[0]]
    positive = [all(group[1]) for group in groups.values() if group[1]]
    fp, tp = sum(negative), sum(positive)
    tn, fn = len(negative)-fp, len(positive)-tp
    return {
        'unit': 'connected_original_final_site_and_exact_content_group',
        'negative_rule': 'any warned legitimate page is a group false positive',
        'positive_rule': 'every phishing page must be detected for group success',
        'legitimate_groups': len(negative), 'phishing_groups': len(positive),
        'confusion_matrix': {'tn': tn, 'fp': fp, 'fn': fn, 'tp': tp},
        'false_positive_rate_95ci': wilson_interval(fp, len(negative)),
        'recall_95ci': wilson_interval(tp, len(positive)),
    }


def benchmark_review(records: list[dict], *, require_document_binding: bool = False) -> dict:
    """Machine-check review evidence/composition, never assert representativeness.

    A human must still verify attribution, labels, sampling and independence.
    This check stops an unexplained boolean from standing in for that record.
    """
    requirements = release_requirements()
    errors = []
    now = datetime.now(timezone.utc)
    reviewed = 0
    for index, record in enumerate(records):
        missing = [name for name in ['reviewed_by', 'label_evidence']
                   if not str(record.get(name) or '').strip()]
        if str(record.get('label_status') or '').lower() != 'reviewed':
            missing.append('label_status=reviewed')
        try:
            reviewed_at = aware_timestamp(record.get('reviewed_at'), 'Review date')
            observed_at = aware_timestamp(record.get('observed_at'), 'Observation date')
            if reviewed_at > now or reviewed_at < observed_at:
                raise ValueError('review must follow observation and cannot be in the future')
        except ValueError:
            missing.append('valid reviewed_at after observed_at')
        source, provenance = source_identity(record)
        if not source or provenance != 'explicit':
            missing.append('explicit source provenance')
        if require_document_binding:
            # The evaluators also support Python callers supplying records
            # directly. A marker alone must not bypass JSONL capture checks or
            # qualify static HTML reconstruction as rendered browser evidence.
            navigation = record.get('navigation_response')
            status = record.get('status')
            if (record.get('capture_success') is not True or record.get('error')
                or record.get('capture_partial') or record.get('capture_quality') != 'ok'
                or not isinstance(record.get('html'), str) or not record['html'].strip()):
                missing.append('successful complete document capture')
            if (record.get('capture_document_status') != 'bound_to_loader'
                or not isinstance(navigation, dict) or type(status) is not int or not 200 <= status < 300
                or navigation.get('status') != status
                or not all(isinstance(navigation.get(name), str) and navigation[name]
                           for name in ['frame_id', 'loader_id', 'url'])
                or not normalize_url(navigation.get('url') or '')):
                missing.append('captured document HTTP binding')
            from feature_engineering import FEATURE_SCHEMA_VERSION, extractor_source_hash, validate_feature_row
            try:
                validate_feature_row(record.get('feature_row'))
            except ValueError:
                missing.append('captured numeric browser features')
            if (record.get('capture_execution_world') != 'isolated'
                or record.get('feature_schema_version') != FEATURE_SCHEMA_VERSION
                or record.get('extractor_sha256') != extractor_source_hash()):
                missing.append('isolated current browser extractor identity')
        if missing:
            if len(errors) < 20:
                errors.append(f'Record {index+1}: missing ' + ', '.join(missing))
        else:
            reviewed += 1
    page_types = Counter(str(r.get('page_type') or '') for r in records if r['label'] == 0)
    sources = {str(label): sorted({source_identity(r)[0].casefold() for r in records if r['label'] == label})
               for label in [0, 1]}
    for label, values in sources.items():
        if len(values) < requirements['minimum_sources_per_class']:
            errors.append(f'Class {label} needs at least {requirements["minimum_sources_per_class"]} independently reviewed sources')
    for name in requirements['required_legitimate_page_types']:
        if page_types[name] < requirements['minimum_per_legitimate_page_type']:
            errors.append(f'Legitimate page_type={name} needs at least {requirements["minimum_per_legitimate_page_type"]} reviewed records')
    return {'passed': not errors and reviewed == len(records) and bool(records),
            'reviewed_records': reviewed, 'samples': len(records), 'sources_by_class': sources,
            'legitimate_page_types': dict(page_types), 'errors': errors,
            'meaning': 'Review evidence/composition checks only; independent human review must establish representative sampling and correct labels'}


def release_gate(metrics: dict, group_metrics: dict, review: dict,
                 requirements: dict | None, fpr_budget: float) -> dict:
    expected = release_requirements()
    errors = []
    if requirements != expected:
        errors.append('Missing or stale release requirements; predeclare the current contract before training')
    if (type(fpr_budget) not in [int, float] or not math.isfinite(fpr_budget)
        or not 0 <= fpr_budget <= expected['maximum_false_positive_rate_upper_95ci']):
        errors.append('Release FPR budget must be finite and no greater than 1 percent')
        fpr_budget = expected['maximum_false_positive_rate_upper_95ci']
    # Derive bounds from counts instead of trusting report-provided confidence
    # intervals, which could be stale, rounded or inconsistent.
    for name, values in [('page', metrics), ('independent group', group_metrics)]:
        cm = values.get('confusion_matrix', {}) if isinstance(values, dict) else {}
        if set(cm) != {'tn', 'fp', 'fn', 'tp'} or any(type(v) is not int or v < 0 for v in cm.values()):
            errors.append(f'{name} confusion matrix is invalid')
            continue
        negative, positive = cm['tn']+cm['fp'], cm['fn']+cm['tp']
        if wilson_interval(cm['fp'], negative)[1] > fpr_budget:
            errors.append(f'{name} FPR upper 95% bound exceeds the predeclared budget')
        if wilson_interval(cm['tp'], positive)[0] < expected['minimum_recall_lower_95ci']:
            errors.append(f'{name} recall lower 95% bound is below {expected["minimum_recall_lower_95ci"]}')
        if name == 'independent group':
            if positive < expected['minimum_independent_phishing_groups']:
                errors.append('Too few independent phishing groups')
            if negative < expected['minimum_independent_legitimate_groups']:
                errors.append('Too few independent legitimate groups')
    if not isinstance(review, dict) or review.get('passed') is not True:
        errors.append('Reviewed benchmark evidence/composition requirements failed')
    return {'passed': not errors, 'requirements': expected, 'errors': errors,
            'meaning': 'Release acceptance targets; risk scores are not calibrated phishing probabilities'}
