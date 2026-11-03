"""Adversarial release and navigation regressions; all data are synthetic."""
from __future__ import annotations

import contextlib
import hashlib
import io
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import joblib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ml/src'))

from capture_dom_snapshots import capture
from dataset_contract import manifest
from dom_dataset import load_snapshots
from export_browser_model import export_model
from feature_engineering import build_feature_row, FEATURE_SCHEMA_VERSION, extractor_source_hash
from future_test_protocol import evaluate
from release_contract import benchmark_review, independent_group_metrics, release_gate, release_requirements
from review_benchmark import review
from train_model import train


class ReleaseContractTests(unittest.TestCase):
    def test_all_negative_model_cannot_be_exported_as_validated(self):
        hosts = [''.join(value) for value in itertools.permutations('bcdfghj')]
        def records(values, source, date):
            return [{'url':f'https://{host}.test/', 'label':i%2, 'source':source, 'observed_at':date}
                    for i, host in enumerate(values)]
        development = records(hosts[:120], 'synthetic-development', '2025-01-01T00:00:00Z')
        future = records(hosts[120:920], 'synthetic-independent', '2025-02-01T00:00:00Z')
        frozen = manifest(future, 'frozen_future_test')
        metadata, _, model = train(development, fpr_budget=.01, reserved_test=frozen)
        self.assertEqual(metadata['release_requirements'], release_requirements())
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            model_path, metadata_path, report_path, output = [base / name for name in ['model.joblib', 'model.json', 'report.json', 'validated.js']]
            joblib.dump(model, model_path)
            metadata['model_file_sha256'] = hashlib.sha256(model_path.read_bytes()).hexdigest()
            metadata_path.write_text(json.dumps(metadata),encoding='utf-8')
            report = evaluate(model_path, metadata_path, future, [], frozen, representative_login_reviewed=True)
            self.assertEqual(report['metrics']['recall'], 0)
            self.assertLess(report['metrics']['false_positive_rate_95ci'][1], .01)
            self.assertFalse(report['release_gate']['passed'])
            # Even an asserted reviewed composition cannot waive detection.
            report['benchmark_review']['passed'] = True
            report_path.write_text(json.dumps(report),encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'recall lower 95% bound'):
                export_model(metadata_path, model_path, output, evaluation_report_path=report_path)
            self.assertFalse(output.exists())
            with contextlib.redirect_stdout(io.StringIO()):
                export_model(metadata_path, model_path, output, diagnostic_only=True)
            self.assertIn('"deployment_eligible":false',output.read_text(encoding='utf-8'))

    def test_independent_site_and_content_groups_prevent_inflated_confidence(self):
        # Hundreds of URLs from one site cannot become hundreds of independent
        # trials. Shared exact content also links otherwise different sites.
        records = [{'url':f'https://one.test/{i}', 'label':i%2} for i in range(800)]
        metrics = independent_group_metrics(records, [False]*len(records))
        self.assertEqual((metrics['legitimate_groups'],metrics['phishing_groups']), (1,1))
        gate = release_gate({'confusion_matrix':{'tn':400,'fp':0,'fn':0,'tp':400}}, metrics,
                            {'passed':True}, release_requirements(), .01)
        self.assertFalse(gate['passed'])
        duplicate = [{'url':f'https://copy{i}.test/', 'label':0,'html':'identical template'} for i in range(400)]
        self.assertEqual(independent_group_metrics(duplicate,[False]*400)['legitimate_groups'],1)

    def test_predeclared_review_and_coverage_contract(self):
        records = []
        types = release_requirements()['required_legitimate_page_types']
        for label, count in [(0,400),(1,100)]:
            for i in range(count):
                records.append({'url':f'https://label{label}-sample{i}.test/', 'label':label,
                    'source':f'independent-reviewed-source-{label}-{i%2}', 'source_provenance':'explicit',
                    'observed_at':'2025-01-01T00:00:00Z', 'label_status':'reviewed',
                    'reviewed_by':'synthetic-fixture-reviewer', 'reviewed_at':'2025-01-02T00:00:00Z',
                    'label_evidence':'Synthetic machinery test only; no real-world accuracy claim',
                    'page_type':types[i%len(types)] if label == 0 else 'phishing_same_site'})
        composition = benchmark_review(records)
        self.assertTrue(composition['passed'])
        self.assertTrue(review(records)['passed'])
        group_metrics = independent_group_metrics(records, [r['label'] == 1 for r in records])
        pages = {'confusion_matrix':{'tn':400,'fp':0,'fn':0,'tp':100}}
        self.assertTrue(release_gate(pages,group_metrics,composition,release_requirements(),.01)['passed'])
        stale = {**release_requirements(),'minimum_recall_lower_95ci':0}
        self.assertFalse(release_gate(pages,group_metrics,composition,stale,.01)['passed'])
        for budget in [.1, float('nan'), float('inf'), -1, True]:
            with self.subTest(budget=budget):
                self.assertFalse(release_gate(pages,group_metrics,composition,release_requirements(),budget)['passed'])
        # A boolean assertion and an arbitrary source label cannot stand in for
        # capture review evidence, and old unbound DOM needs recapturing.
        self.assertFalse(benchmark_review(records,require_document_binding=True)['passed'])
        document = {**records[0], 'capture_document_status':'bound_to_loader', 'capture_success':True,
                    'capture_quality':'ok', 'status':200, 'capture_execution_world':'isolated',
                    'html':'<p>synthetic document</p>', 'feature_schema_version':FEATURE_SCHEMA_VERSION,
                    'extractor_sha256':extractor_source_hash(),
                    'feature_row':build_feature_row(records[0]['url'],'','<p>synthetic document</p>')}
        marker_only = benchmark_review([document],require_document_binding=True)
        self.assertEqual(marker_only['reviewed_records'],0)
        self.assertIn('captured document HTTP binding',marker_only['errors'][0])
        document['navigation_response'] = {'frame_id':'top','loader_id':'real-loader',
                                           'url':document['url'],'status':200}
        self.assertEqual(benchmark_review([document],require_document_binding=True)['reviewed_records'],1)
        document['feature_row'] = None
        self.assertEqual(benchmark_review([document],require_document_binding=True)['reviewed_records'],0)
        records[0]['label_evidence'] = ''
        self.assertFalse(benchmark_review(records)['passed'])

    def test_completed_script_navigation_captures_final_404_and_preserves_provenance(self):
        start, final = 'https://capture-start.test/', 'https://capture-final.test/missing'
        features = build_feature_row(final, '404 Not Found', '<h1>404 Not Found</h1>')
        snapshot = {'features':{**features,'credential_contexts':[]},'html':'<h1>404 Not Found</h1>',
                    'title':'404 Not Found', 'final_url':final,
                    'document_identity':{'frame_id':'top','loader_id':'final'}}
        manager, browser, context, page, session = [MagicMock() for _ in range(5)]
        manager.__enter__.return_value.chromium.launch.return_value.__enter__.return_value = browser
        browser.new_context.return_value = context
        context.new_page.return_value = page
        context.new_cdp_session.return_value = session
        handlers = {}
        session.on.side_effect = lambda name, callback: handlers.update({name:callback})
        def goto(*args, **kwargs):
            for loader, url, status in [('initial',start,200),('final',final,404)]:
                handlers['Network.responseReceived']({'type':'Document','frameId':'top','loaderId':loader,
                    'response':{'url':url,'status':status}})
            response = MagicMock(status=200)
            return response
        page.goto.side_effect = goto
        page.url = final
        api = ModuleType('playwright.sync_api')
        api.sync_playwright = lambda: manager
        with tempfile.TemporaryDirectory() as folder:
            source, destination = Path(folder)/'input.csv', Path(folder)/'output.jsonl'
            source.write_text(f'url,label,source,source_provenance\n{start},0,exported-filename,filename_fallback\n',encoding='utf-8')
            with patch.dict(sys.modules,{'playwright':ModuleType('playwright'),'playwright.sync_api':api}), \
                 patch('capture_dom_snapshots.is_public_host',return_value=True), \
                 patch('capture_dom_snapshots.isolated_snapshot',return_value=snapshot):
                capture(source,destination,None,1000)
            record = json.loads(destination.read_text(encoding='utf-8'))
            self.assertEqual(record['status'],404)
            self.assertEqual(record['source_provenance'],'filename_fallback')
            self.assertFalse(record['capture_success'])
            self.assertEqual(record['navigation_response']['loader_id'],'final')
            with self.assertRaisesRegex(ValueError,'failed/non-success HTTP capture'):
                load_snapshots(destination)


if __name__ == '__main__':
    unittest.main()
