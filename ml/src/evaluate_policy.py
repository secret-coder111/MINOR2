"""Evaluate the shipped local verdict policy on reviewed captured page features.

This evaluates canonical outcomes with per-submission contexts, not score bands.
Network reputation, browser navigation/frame aggregation and UI delivery require
separate integration tests; no learned model is enabled by this evaluator.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix

from dataset_contract import manifest, assert_separated, normalize_url
from dom_dataset import load_snapshots
from feature_engineering import (FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION, POLICY_VERSION,
    extractor_source_hash, policy_source_hash, filter_policy_features, validate_feature_row)
from future_test_protocol import breakdown, page_type
from train_model import wilson_interval
from release_contract import benchmark_review, independent_group_metrics, release_gate, assert_reviews_frozen


def outcome_metrics(labels, positives) -> dict:
    tn,fp,fn,tp = confusion_matrix(labels,positives,labels=[0,1]).ravel()
    return {'confusion_matrix':dict(zip(['tn','fp','fn','tp'],map(int,[tn,fp,fn,tp]))),
        'false_positive_rate':float(fp/(fp+tn)), 'recall':float(tp/(tp+fn)),
        'false_positive_rate_95ci':wilson_interval(int(fp),int(fp+tn)),
        'recall_95ci':wilson_interval(int(tp),int(tp+fn))}


def evaluate_policy(records: list[dict], warning_threshold: int = 65,
    frozen_manifest: dict | None = None, development_manifest: dict | None = None,
    policy_lock: dict | None = None) -> dict:
    if not records or {record['label'] for record in records} != {0,1}:
        raise ValueError('Policy evaluation requires both reviewed classes')
    normalized_urls = [normalize_url(record['url']) for record in records]
    if not all(normalized_urls) or len(set(normalized_urls)) != len(records):
        raise ValueError('Duplicate original URLs across policy evaluation inputs need review before evaluation')
    if not isinstance(warning_threshold,int) or not 35 <= warning_threshold <= 90:
        raise ValueError('warning_threshold must be an integer from 35 through 90')
    features = []
    for record in records:
        if record.get('capture_success') is not True or record.get('error') or record.get('capture_partial') or record.get('capture_quality') != 'ok' or not 200 <= record.get('status',0) < 300 or not record.get('html','').strip():
            raise ValueError('Policy evaluation requires successfully captured, reviewed document records')
        if record.get('feature_schema_version') != FEATURE_SCHEMA_VERSION or record.get('extractor_sha256') != extractor_source_hash():
            raise ValueError('Snapshot extractor identity differs from the current browser extractor')
        if record.get('policy_version') != POLICY_VERSION or record.get('policy_sha256') != policy_source_hash():
            raise ValueError('Snapshot policy identity differs from the policy under evaluation')
        structural = filter_policy_features(record.get('policy_features'))
        if structural != record['policy_features']:
            raise ValueError('Captured policy data contains non-whitelisted fields')
        validate_feature_row(record.get('feature_row') or {})
        if any(structural.get(name) != record['feature_row'][name] for name in FEATURE_SCHEMA):
            raise ValueError('Policy numeric features disagree with the captured model features')
        # Even exploratory reports need identifiable capture dates, not an implicit
        # date manufactured at evaluation time.
        try:
            if datetime.fromisoformat(record.get('observed_at','').replace('Z','+00:00')).tzinfo is None:
                raise ValueError('timezone missing')
        except ValueError as error:
            raise ValueError('Every policy snapshot needs a timezone-aware capture date') from error
        features.append(structural)
    current = manifest(records,'frozen_policy_test')
    supplied = [value is not None for value in [frozen_manifest,development_manifest,policy_lock]]
    separated = False
    if any(supplied):
        if not all(supplied):
            raise ValueError('Verified policy evaluation requires frozen test, development manifest and policy lock together')
        identity = lambda value:{key:value.get(key) for key in current if key not in {'created_at','purpose'}}
        if identity(current) != identity(frozen_manifest):
            raise ValueError('Policy test records/labels/features changed after freezing')
        assert_separated(development_manifest,frozen_manifest,source_time=True)
        if policy_lock.get('policy_sha256') != policy_source_hash() or policy_lock.get('extractor_sha256') != extractor_source_hash():
            raise ValueError('Locked policy/extractor differs from evaluated code')
        if policy_lock.get('warning_threshold') != warning_threshold:
            raise ValueError('Warning threshold must be frozen in the policy lock before evaluation')
        try:
            frozen_at = datetime.fromisoformat(frozen_manifest['created_at'].replace('Z', '+00:00'))
            locked_at = datetime.fromisoformat(policy_lock['locked_at'].replace('Z', '+00:00'))
            if frozen_at.tzinfo is None or locked_at.tzinfo is None:
                raise ValueError('timezone missing')
        except (KeyError, TypeError, AttributeError, ValueError) as error:
            raise ValueError('Policy freeze/lock dates require timezone-aware ISO timestamps') from error
        evaluated_at = datetime.now(timezone.utc)
        if frozen_at > evaluated_at or locked_at > evaluated_at:
            raise ValueError('Policy freeze/lock timestamps must not be in the future')
        if frozen_at >= locked_at:
            raise ValueError('Freeze the test before policy selection is locked; otherwise report exploratory results')
        if any(datetime.fromisoformat(value.replace('Z', '+00:00')) > frozen_at
               for value in frozen_manifest.get('observed_at', [])):
            raise ValueError('Policy test observations must exist before the test manifest is frozen')
        assert_reviews_frozen(records, frozen_at)
        separated = True
    bridge = Path(__file__).with_suffix('.cjs')
    result = subprocess.run(['node',str(bridge)],input=json.dumps({'features':features,'warningThreshold':warning_threshold}),
        text=True,encoding='utf-8',capture_output=True,check=True)
    verdicts = json.loads(result.stdout)
    if any(v.get('policyVersion') != POLICY_VERSION or v.get('warning') != (v.get('outcome') == 'HIGH_RISK') for v in verdicts):
        raise ValueError('Policy returned inconsistent canonical outcome/warning state')
    labels = np.asarray([record['label'] for record in records])
    high = np.asarray([verdict['outcome']=='HIGH_RISK' for verdict in verdicts])
    caution_or_high = np.asarray([verdict['outcome'] in {'CAUTION','HIGH_RISK'} for verdict in verdicts])
    report = {'protocol':'frozen_source_time_separated_local_policy_v1' if separated else 'exploratory_local_policy_only',
        'scope':'shipped local document verdict policy; network reputation, frame aggregation and UI delivery excluded',
        'policy_version':POLICY_VERSION,'policy_sha256':policy_source_hash(),'extractor_sha256':extractor_source_hash(),
        'warning_threshold':warning_threshold,'samples':len(records),'leakage_check':{'passed':separated},
        'test_manifest':current,'high_risk_warning':outcome_metrics(labels,high),
        'caution_or_high_risk':outcome_metrics(labels,caution_or_high),
        'by_source':{'high_risk_warning':breakdown(records,labels,high.astype(float),.5,lambda r:r.get('source') or 'unspecified'),
                     'caution_or_high_risk':breakdown(records,labels,caution_or_high.astype(float),.5,lambda r:r.get('source') or 'unspecified')},
        'by_page_type':{'high_risk_warning':breakdown(records,labels,high.astype(float),.5,page_type),
                        'caution_or_high_risk':breakdown(records,labels,caution_or_high.astype(float),.5,page_type)},
        'outcome_counts':{name:sum(v['outcome']==name for v in verdicts) for name in ['SAFE','CAUTION','HIGH_RISK']},
        'verdicts':verdicts}
    report['independent_group_metrics'] = independent_group_metrics(records, high)
    report['benchmark_review'] = benchmark_review(records, require_document_binding=True)
    requirements = policy_lock.get('release_requirements') if policy_lock else None
    budget = policy_lock.get('fpr_budget', .01) if policy_lock else .01
    report['release_gate'] = release_gate(report['high_risk_warning'], report['independent_group_metrics'],
        report['benchmark_review'], requirements, budget)
    if not separated:
        report['release_gate']['passed'] = False
        report['release_gate']['errors'].append('Exploratory results cannot qualify a policy release')
    report['score_meaning'] = 'Uncalibrated evidence index; a score is not the probability that a page is phishing'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshots',type=Path,nargs='+')
    parser.add_argument('--warning-threshold',type=int,default=65)
    parser.add_argument('--frozen-manifest',type=Path)
    parser.add_argument('--development-manifest',type=Path)
    parser.add_argument('--policy-lock',type=Path,help='JSON with locked_at, policy_sha256, extractor_sha256 and warning_threshold')
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Use a new report path; do not overwrite evaluation evidence')
    load = lambda path:json.loads(path.read_text(encoding='utf-8')) if path else None
    receipt = args.frozen_manifest.with_suffix('.policy-used.json') if args.frozen_manifest else None
    if receipt and receipt.exists():
        raise ValueError('This frozen policy holdout has already been evaluated; collect a new untouched test')
    records = [record for path in args.snapshots for record in load_snapshots(path)]
    report = evaluate_policy(records,args.warning_threshold,load(args.frozen_manifest),load(args.development_manifest),load(args.policy_lock))
    rendered = json.dumps(report,indent=2)+'\n'
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(rendered,encoding='utf-8')
    if receipt:
        receipt.write_text(json.dumps({'policy_sha256':report['policy_sha256'],'evaluated_at':datetime.now(timezone.utc).isoformat(),
            'report_sha256':hashlib.sha256(rendered.encode('utf-8')).hexdigest()},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:report[key] for key in ['protocol','samples','outcome_counts','high_risk_warning','caution_or_high_risk']},indent=2))


if __name__ == '__main__':
    main()
