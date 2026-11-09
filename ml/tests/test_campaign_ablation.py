"""Protect evaluation independence and exact per-context evidence removal."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ml/src'))
from dataset_contract import connected_groups, manifest, assert_separated, group_annotations
from train_model import read_dataset, partition_records
from feature_engineering import (FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION, POLICY_VERSION, POLICY_CONTEXT_KEYS,
    build_feature_row, filter_policy_features, extractor_source_hash, policy_source_hash)
from evaluate_policy import evaluate_policy


class CampaignAblationTests(unittest.TestCase):
    def test_campaign_and_template_relationships_connect_distinct_sites(self):
        records = [
            {'url': 'https://a.test/', 'label': 1, 'campaign_id': 'Reviewed Campaign 1'},
            {'url': 'https://b.test/', 'label': 1, 'campaign_id': 'reviewed campaign 1', 'template_group': 'template-A'},
            {'url': 'https://c.test/', 'label': 1, 'template_group': 'TEMPLATE-a'},
            {'url': 'https://independent.test/', 'label': 0}]
        groups = connected_groups(records)
        self.assertEqual(len(set(groups[:3])), 1)
        self.assertNotEqual(groups[0], groups[3])
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            assert_separated(manifest(records[:1], 'fit'), manifest(records[1:2], 'test'))
        self.assertNotEqual(manifest(records[:1], 'frozen')['record_sha256'],
                            manifest([{**records[0], 'campaign_id': 'another'}], 'changed')['record_sha256'])
        # Unannotated historical manifests keep their v3 identity contract.
        self.assertEqual(manifest(records[3:], 'legacy')['version'], 3)

    def test_import_preserves_grouping_and_rejects_conflicting_duplicate_annotations(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'reviewed.csv'
            def write(rows):
                with path.open('w', newline='', encoding='utf-8') as handle:
                    writer = csv.DictWriter(handle, fieldnames=['url', 'label', 'campaign_id', 'template_group'])
                    writer.writeheader()
                    writer.writerows(rows)
            write([{'url': 'https://a.test/', 'label': 1},
                   {'url': 'https://a.test/', 'label': 1, 'campaign_id': 'reviewed-campaign'}])
            records = read_dataset([path])
            self.assertEqual(records[0]['campaign_id'], 'reviewed-campaign')
            write([{'url': 'https://a.test/', 'label': 1, 'campaign_id': name} for name in ['one', 'two']])
            with self.assertRaisesRegex(ValueError, 'conflicting campaign'):
                read_dataset([path])
        for invalid in [123, ['campaign'], 'x' * 201]:
            with self.assertRaises(ValueError): group_annotations({'campaign_id': invalid})

    def test_partition_keeps_campaigns_together(self):
        records = [{'url': f'https://site{i}.test/', 'label': i % 2, 'campaign_id': f'group-{i//2}'} for i in range(100)]
        parts = partition_records(records, 42)
        for name, rows in parts.items():
            for other_name, other in parts.items():
                if name != other_name: assert_separated(manifest(rows, name), manifest(other, other_name))

    def test_ablations_remove_scoped_evidence_without_modifying_baseline(self):
        features = {'brand_domain_mismatch': 1, 'has_password_input': 1, 'credential_contexts': [
            {'credential_context': 1, 'has_password_input': 1, 'brand_domain_mismatch': 1, 'cross_domain_form_action': 1}]}
        result = subprocess.run(['node', str(ROOT / 'ml/src/evaluate_policy.cjs')],
            input=json.dumps({'features': [features], 'warningThreshold': 65, 'ablations': True}),
            text=True, capture_output=True, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report['verdicts'][0]['outcome'], 'HIGH_RISK')
        self.assertEqual(report['ablations']['without_identity'][0]['outcome'], 'CAUTION')
        self.assertEqual(report['ablations']['without_destination'][0]['outcome'], 'CAUTION')
        self.assertEqual(report['ablations']['url_only'][0]['outcome'], 'SAFE')
        self.assertEqual(report['ablations']['without_transport'][0]['outcome'], 'HIGH_RISK')

    def test_evaluator_reports_ablations_only_for_development_data(self):
        records = []
        for label, host, title, action in [(0, 'ordinary.test', 'Member login', '/session'),
                                           (1, 'clone.test', 'PayPal sign in', 'https://collector.invalid/')]:
            url = f'https://{host}/'
            html = f'<title>{title}</title><form method="post" action="{action}"><input type="password" name="secret"></form>'
            features = build_feature_row(url, title, html)
            # Synthetic evaluator machinery fixture, never a captured benchmark.
            context = {name: features.get(name, 0) for name in POLICY_CONTEXT_KEYS}
            context.update(credential_context=1, has_password_input=1,
                           credential_field_count=1, sensitive_credential_field_count=1)
            features['credential_contexts'] = [context]
            records.append({'url': url, 'label': label, 'html': html, 'status': 200,
                'capture_success': True, 'capture_quality': 'ok', 'observed_at': '2026-01-01T00:00:00Z',
                'feature_row': {name: features[name] for name in FEATURE_SCHEMA},
                'feature_schema_version': FEATURE_SCHEMA_VERSION, 'extractor_sha256': extractor_source_hash(),
                'policy_features': filter_policy_features(features), 'policy_version': POLICY_VERSION,
                'policy_sha256': policy_source_hash()})
        report = evaluate_policy(records, ablations=True)
        self.assertFalse(report['release_gate']['passed'])
        self.assertFalse(report['ablations']['selection_performed'])
        self.assertEqual(report['ablations']['variants']['without_identity']['changed_outcomes'], 1)
        with self.assertRaisesRegex(ValueError, 'not a frozen release holdout'):
            evaluate_policy(records, frozen_manifest=manifest(records, 'frozen'), ablations=True)


if __name__ == '__main__':
    unittest.main()
