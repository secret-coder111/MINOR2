"""Collector isolation and provenance regressions; entirely offline."""
from __future__ import annotations

import json
import io
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ml/src'))

from capture_dom_snapshots import isolated_snapshot, DocumentResponses
from dataset_contract import assert_separated, manifest
from dom_dataset import load_snapshots
from feature_engineering import (build_feature_row, FEATURE_SCHEMA_VERSION, POLICY_VERSION,
    extractor_source_hash, policy_source_hash)
from future_test_protocol import evaluate
from evaluate_policy import evaluate_policy
from fetch_feeds import collect_umbrella, write_records
from train_model import read_dataset


class CaptureContractTests(unittest.TestCase):
    def test_popularity_seeds_require_label_review_before_use(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, 'w') as archive:
            archive.writestr('top.csv', '1,popular.test\n2,another.test\n')
        response = MagicMock()
        response.__enter__.return_value.read.return_value = archive_bytes.getvalue()
        with patch('fetch_feeds.urlopen', return_value=response):
            seeds = collect_umbrella()
        self.assertEqual(len(seeds), 2)
        self.assertTrue(all(row['label'] == '' and row['label_status'] == 'unreviewed_popularity_seed' for row in seeds))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'review.csv'
            write_records(seeds, path)
            self.assertEqual(read_dataset([path]), [])
            # Merely filling a label does not clear the explicit review marker.
            seeds[0]['label'] = 'legitimate'
            write_records(seeds, path)
            self.assertEqual(read_dataset([path]), [])
            seeds[0]['label_status'] = 'reviewed'
            write_records(seeds, path)
            self.assertEqual(len(read_dataset([path])), 1)
            # Historical popularity files also need review; old generated
            # "legitimate" labels alone are not enough.
            del seeds[0]['label_status']
            write_records(seeds, path)
            self.assertEqual(read_dataset([path]), [])

    def test_extraction_uses_isolated_world_and_atomic_document_snapshot(self):
        features = build_feature_row('https://safe.test/', '', '<input type=password>')
        snapshot = {'features': features, 'html': '<html><input type=password></html>',
                    'title': 'Member login', 'final_url': 'https://safe.test/'}
        context, page, session = Mock(), Mock(), Mock()
        context.new_cdp_session.return_value = session
        session.send.side_effect = [
            {}, {},
            {'frameTree': {'frame': {'id': 'actual-top-frame', 'loaderId': 'loader-1'}}},
            {'executionContextId': 17}, {'result': {'value': snapshot}},
            {'frameTree': {'frame': {'id': 'actual-top-frame', 'loaderId': 'loader-1'}}},
        ]
        self.assertEqual(isolated_snapshot(context, page, '() => ({})', 1000), snapshot)
        self.assertEqual(session.send.call_args_list[0].args, ('Page.enable',))
        self.assertEqual(session.send.call_args_list[1].args, ('Runtime.enable',))
        world_call, evaluate_call = session.send.call_args_list[3:5]
        self.assertEqual(world_call.args, ('Page.createIsolatedWorld', {
            'frameId': 'actual-top-frame', 'worldName': 'phishguard-capture'}))
        self.assertEqual(evaluate_call.args[0], 'Runtime.evaluate')
        params = evaluate_call.args[1]
        self.assertEqual(params['contextId'], 17)
        self.assertEqual(params['timeout'], 1000)
        self.assertTrue(params['returnByValue'])
        self.assertIn('title: document.title, final_url: location.href', params['expression'])
        page.evaluate.assert_not_called()
        session.detach.assert_called_once_with()

    def test_isolated_extraction_errors_are_never_valid_snapshots(self):
        for returned in [{'exceptionDetails': {'text': 'untrusted exception'}},
                         {'result': {'value': None}}, {'result': {'value': {}}}]:
            with self.subTest(returned=returned):
                context, session = Mock(), Mock()
                context.new_cdp_session.return_value = session
                session.send.side_effect = [
                    {}, {},
                    {'frameTree': {'frame': {'id': 'top', 'loaderId': 'loader-1'}}},
                    {'executionContextId': 9}, returned,
                ]
                with self.assertRaises(ValueError):
                    isolated_snapshot(context, Mock(), '() => ({})', 1000)
                session.detach.assert_called_once_with()

    def test_navigation_status_uses_exact_loader_not_initial_goto_response(self):
        context, session = Mock(), Mock()
        context.new_cdp_session.return_value = session
        tracker = DocumentResponses(context, Mock())
        tracker._response({'type':'Document','frameId':'top','loaderId':'initial',
            'response':{'url':'https://start.test/', 'status':200}})
        tracker._response({'type':'Document','frameId':'top','loaderId':'final',
            'response':{'url':'https://final.test/missing', 'status':404}})
        snapshot = {'final_url':'https://final.test/missing',
                    'document_identity':{'frame_id':'top','loader_id':'final'}}
        self.assertEqual(tracker.for_snapshot(snapshot)['status'],404)
        # Same URL reloads also have independent loader IDs, so URL matching
        # cannot accidentally revive the previous successful response.
        tracker._response({'type':'Document','frameId':'top','loaderId':'reload',
            'response':{'url':'https://start.test/', 'status':503}})
        snapshot['document_identity']['loader_id'] = 'reload'
        self.assertEqual(tracker.for_snapshot(snapshot)['status'],503)
        snapshot['document_identity']['loader_id'] = 'unobserved'
        with self.assertRaisesRegex(ValueError,'matches the captured document'):
            tracker.for_snapshot(snapshot)
        snapshot['document_identity']['loader_id'] = 'initial'
        tracker.request_count = 129
        with self.assertRaisesRegex(ValueError, 'Too many navigation'):
            tracker.for_snapshot(snapshot)
        tracker.close()
        session.detach.assert_called_once_with()

    def test_isolated_snapshot_rejects_navigation_to_same_url_during_extraction(self):
        context, session = Mock(), Mock()
        context.new_cdp_session.return_value = session
        snapshot = {'features':build_feature_row('https://page.test/','','<p>sample</p>'),
                    'html':'<p>sample</p>', 'title':'', 'final_url':'https://page.test/'}
        session.send.side_effect = [{}, {},
            {'frameTree':{'frame':{'id':'top','loaderId':'before'}}},
            {'executionContextId':1}, {'result':{'value':snapshot}},
            {'frameTree':{'frame':{'id':'top','loaderId':'after'}}}]
        with self.assertRaisesRegex(ValueError,'navigated during'):
            isolated_snapshot(context,Mock(),'() => ({})',1000)

    def test_filename_fallback_cannot_establish_source_separation(self):
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            train_path, test_path = [Path(folder) / name for name in ['renamed-training.csv', 'renamed-future.csv']]
            train_path.write_text('url,label,observed_at\nhttps://train.test/,0,' + (now-timedelta(days=3)).isoformat() + '\n', encoding='utf-8')
            test_path.write_text('url,label,observed_at\nhttps://future.test/,1,' + (now-timedelta(days=1)).isoformat() + '\n', encoding='utf-8')
            reference = manifest(read_dataset([train_path]), 'training')
            candidate = manifest(read_dataset([test_path]), 'test')
            self.assertEqual(reference['identified_source_samples'], 0)
            with self.assertRaisesRegex(ValueError, 'filename fallback'):
                assert_separated(reference, candidate, source_time=True)
            # A CSV source column copied from a filename remains untrusted.
            reloaded = []
            for original in [train_path, test_path]:
                records = read_dataset([original])
                copied = original.with_name('roundtrip-' + original.name)
                import csv
                with copied.open('w',encoding='utf-8',newline='') as output:
                    writer = csv.DictWriter(output,fieldnames=list(records[0]))
                    writer.writeheader()
                    writer.writerows(records)
                values = read_dataset([copied])
                self.assertEqual(values[0]['source_provenance'],'filename_fallback')
                reloaded.append(manifest(values,'roundtrip'))
            with self.assertRaisesRegex(ValueError,'filename fallback'):
                assert_separated(*reloaded,source_time=True)
            # Sources differing only by casing/whitespace are the same source.
            records = [{'url':'https://train.test/','label':0,'source':' Reviewed Feed ',
                        'observed_at':(now-timedelta(days=3)).isoformat()}]
            future = [{'url':'https://future.test/','label':1,'source':'reviewed feed',
                       'observed_at':(now-timedelta(days=1)).isoformat()}]
            with self.assertRaisesRegex(ValueError, 'sources overlap'):
                assert_separated(manifest(records,'training'), manifest(future,'test'), source_time=True)
            future[0]['source'] = 'independent review'
            assert_separated(manifest(records,'training'), manifest(future,'test'), source_time=True)
            future[0]['observed_at'] = (now+timedelta(days=1)).isoformat()
            with self.assertRaisesRegex(ValueError, 'must not be in the future'):
                assert_separated(manifest(records,'training'), manifest(future,'test'), source_time=True)

    def test_snapshot_source_fallback_remains_unverified_after_loading(self):
        record = {'url':'https://sample.test/','final_url':'https://sample.test/','label':0,
                  'html':'<p>Reviewed fixture</p>','capture_success':True,'status':200,
                  'capture_quality':'ok','observed_at':'2025-01-01T00:00:00Z'}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'renamed-source.jsonl'
            path.write_text(json.dumps(record)+'\n',encoding='utf-8')
            loaded = load_snapshots(path)
            self.assertEqual(loaded[0]['source_provenance'],'filename_fallback')
            self.assertEqual(manifest(loaded,'sample')['identified_source_samples'],0)
            # Re-exporting a loaded JSONL must never upgrade its trust status.
            path.write_text(json.dumps(loaded[0])+'\n',encoding='utf-8')
            self.assertEqual(manifest(load_snapshots(path),'sample')['identified_source_samples'],0)
            path.write_text(json.dumps({**loaded[0],'label_status':'unreviewed_popularity_seed'})+'\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'unreviewed sampling seeds'):
                load_snapshots(path)

    def test_policy_test_cannot_be_frozen_before_its_observations(self):
        now = datetime.now(timezone.utc)
        records = []
        for label in [0, 1]:
            url = f'https://policy-sample{label}.test/'
            html = f'<p>Reviewed synthetic sample {label}</p>'
            features = build_feature_row(url, '', html)
            records.append({'url':url,'final_url':url,'label':label,'source':'policy-test',
                'observed_at':(now-timedelta(days=4)).isoformat(),'html':html,
                'status':200,'capture_success':True,'capture_quality':'ok',
                'feature_row':features,'feature_schema_version':FEATURE_SCHEMA_VERSION,
                'extractor_sha256':extractor_source_hash(), 'policy_features':{**features,'credential_contexts':[]},
                'policy_version':POLICY_VERSION,'policy_sha256':policy_source_hash()})
        frozen = {**manifest(records,'policy-test'),'created_at':(now-timedelta(days=5)).isoformat()}
        development = manifest([{'url':'https://policy-development.test/','label':0,
            'source':'policy-development','observed_at':(now-timedelta(days=6)).isoformat()}],'development')
        lock = {'policy_sha256':policy_source_hash(),'extractor_sha256':extractor_source_hash(),
                'warning_threshold':65,'locked_at':(now-timedelta(days=2)).isoformat()}
        with self.assertRaisesRegex(ValueError, 'observations must exist before'):
            evaluate_policy(records,65,frozen,development,lock)
        records[0]['reviewed_at'] = (now-timedelta(days=2)).isoformat()
        frozen = {**manifest(records,'policy-test'), 'created_at':(now-timedelta(days=3)).isoformat()}
        with self.assertRaisesRegex(ValueError, 'reviews must exist before'):
            evaluate_policy(records,65,frozen,development,lock)

    def test_model_evaluation_preserves_original_freeze_timeline(self):
        now = datetime.now(timezone.utc)
        records = [{'url':'https://safe-future.test/','label':0,'source':'future-review',
                    'observed_at':(now-timedelta(days=4)).isoformat()},
                   {'url':'https://phishing-future.test/','label':1,'source':'future-review',
                    'observed_at':(now-timedelta(days=4)).isoformat()}]
        frozen = {**manifest(records,'frozen_future_test'), 'created_at':(now-timedelta(days=3)).isoformat()}
        metadata = {'development_manifest':manifest([{'url':'https://development.test/','label':0,
            'source':'development-review','observed_at':(now-timedelta(days=6)).isoformat()}],'development'),
            'reserved_test_manifest':frozen, 'training_started_at':(now-timedelta(days=2)).isoformat()}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'model.json'
            path.write_text(json.dumps(metadata),encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'freeze date differs'):
                evaluate(Path('never-loaded.joblib'),path,records,[],{**frozen,'created_at':(now-timedelta(days=5)).isoformat()})
            for invalid in ['2025-01-01T00:00:00', (now+timedelta(days=1)).isoformat()]:
                path.write_text(json.dumps({**metadata,'training_started_at':invalid}),encoding='utf-8')
                with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, 'timezone-aware|must not be in the future'):
                    evaluate(Path('never-loaded.joblib'),path,records,[],frozen)
            impossible = {**frozen,'created_at':(now-timedelta(days=5)).isoformat()}
            path.write_text(json.dumps({**metadata,'reserved_test_manifest':impossible}),encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'observations must exist before'):
                evaluate(Path('never-loaded.joblib'),path,records,[],impossible)
            records[0]['reviewed_at'] = (now-timedelta(days=2)).isoformat()
            late_review = {**manifest(records,'frozen_future_test'),
                           'created_at':(now-timedelta(days=3)).isoformat()}
            path.write_text(json.dumps({**metadata,'reserved_test_manifest':late_review}),encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'reviews must exist before'):
                evaluate(Path('never-loaded.joblib'),path,records,[],late_review)


if __name__ == '__main__':
    unittest.main()
