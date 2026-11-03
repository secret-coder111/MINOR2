"""Offline regressions: no network, live phishing, credentials or accuracy claims."""
from __future__ import annotations
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'ml/src'))
from dataset_contract import normalize_url, registrable_domain, connected_groups, manifest, assert_separated
from feature_engineering import FEATURE_SCHEMA, URL_FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION, build_feature_row, extractor_source_hash, validate_feature_row
from train_model import read_dataset, build_matrix, grouped_split, train, select_fpr_threshold
from dom_dataset import load_snapshots, validate_records
from export_browser_model import export_model, serialized_probabilities
from future_test_protocol import evaluate, load_records, model_probabilities
from capture_dom_snapshots import redact_field_values, is_public_host, configure_capture_routes
from train_char_model import train as train_character
from export_browser_char_model import export_model as export_character
from evaluate_policy import evaluate_policy
from feature_engineering import filter_policy_features, policy_source_hash, POLICY_VERSION


class PipelineTests(unittest.TestCase):
    def test_url_identity_and_permanent_conflict_quarantine(self):
        self.assertEqual(normalize_url(' HTTPS://Example.COM:443/Aa?Token=X#Part '), 'https://example.com/Aa?Token=X#Part')
        self.assertNotEqual(normalize_url('example.com/A'), normalize_url('example.com/a'))
        self.assertEqual(normalize_url(''), '')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'urls.csv'
            path.write_text('url,label\nhttps://site.example/A,good\nhttps://site.example/A,phishing\nhttps://site.example/A,good\nhttps://site.example/a,good\nhttps://malware.example/,malware\n', encoding='utf-8')
            records = read_dataset([path])
            self.assertEqual([r['url'] for r in records], ['https://site.example/a'])
            self.assertEqual(len(read_dataset([path], include_other_threats=True)), 2)

    def test_full_psl_and_private_tenants(self):
        cases = {'https://a.b.example.co.uk/x':'example.co.uk', 'https://tenant.github.io':'tenant.github.io',
            'https://x.city.kawasaki.jp/':'city.kawasaki.jp', 'https://a.b.ck/':'a.b.ck',
            'https://www.ck/':'www.ck', 'https://127.0.0.1/':'127.0.0.1',
            'https://[2001:db8::1]/':'[2001:db8::1]', 'https://co.uk/':'',
            'http://localhost/':'localhost', 'https://食狮.com.cn/':'xn--85x722f.com.cn'}
        for url, expected in cases.items():
            with self.subTest(url=url): self.assertEqual(registrable_domain(url), expected)

    def test_redirect_content_groups_and_mixed_label_sites(self):
        records = [{'url':'https://a.test/start','final_url':'https://common.test/a','label':0,'html':'same'},
                   {'url':'https://b.test/start','final_url':'https://common.test/b','label':1,'html':'different'},
                   {'url':'https://c.test/start','label':0,'html':'same'}]
        self.assertEqual(len(set(connected_groups(records))), 1)
        records.extend({'url':f'https://independent{i}.test/','label':i%2} for i in range(30))
        left, right = grouped_split(records, .3, 42)
        assert_separated(manifest(left,'left'), manifest(right,'right'))
        first_three = [all(r in side for r in records[:3]) for side in [left,right]]
        self.assertTrue(any(first_three))
        self.assertEqual(validate_records(records)['cross_class_domain_overlap'], ['common.test'])
        # A common template across thousands of hosts must not overflow a
        # recursive union-find or let later records disconnect earlier groups.
        templates = [{'url':f'https://template{i}.test/','label':i%2,'html':'one common template'} for i in range(1500)]
        self.assertEqual(len(set(connected_groups(templates))),1)

    def test_snapshot_capture_validation_and_final_document_features(self):
        record = {'url':'https://start.test/original', 'final_url':'https://final.test/redirected2',
                  'label':0,'html':'<form><input type=password></form>','status':200,'capture_success':True,
                  'observed_at':'2026-01-01T00:00:00+00:00','capture_quality':'ok'}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'snapshots.jsonl'
            def load(value):
                path.write_text(json.dumps(value)+'\n', encoding='utf-8')
                return load_snapshots(path)
            loaded = load(record)
            self.assertEqual(build_matrix(loaded, URL_FEATURE_SCHEMA)[0], build_matrix([{**record,'url':record['final_url']}], URL_FEATURE_SCHEMA)[0])
            for updates in [{'html':' \n\t'}, {'final_url':'javascript:alert(1)'}, {'status':404}, {'capture_success':False}, {'observed_at':''}, {'capture_quality':'challenge'}]:
                with self.subTest(updates=updates), self.assertRaises(ValueError): load({**record,**updates})
            navigation = {'frame_id':'top','loader_id':'loader-1','url':record['final_url'],'status':200}
            bound = {**record,'navigation_response':navigation,'capture_document_status':'bound_to_loader'}
            self.assertEqual(load(bound)[0]['capture_document_status'],'bound_to_loader')
            for update in [{'navigation_response':{**navigation,'status':404}},
                           {'navigation_response':{**navigation,'loader_id':''}},
                           {'navigation_response':None}]:
                with self.subTest(update=update), self.assertRaisesRegex(ValueError,'document'):
                    load({**bound,**update})
        with self.assertRaisesRegex(ValueError, 'missing DOM'):
            build_matrix([{'url':'https://page.test/','label':0}])
        self.assertEqual(len(build_matrix([{'url':'https://page.test/','label':0}], URL_FEATURE_SCHEMA)[0]), len(URL_FEATURE_SCHEMA))

    def test_browser_python_named_feature_parity(self):
        fixtures = json.loads((ROOT/'ml/tests/fixtures/feature-golden.json').read_text(encoding='utf-8'))
        result = subprocess.run(['node', str(ROOT/'ml/tests/feature-parity.cjs')], input=json.dumps({'fixtures':fixtures,'schema':FEATURE_SCHEMA}), capture_output=True, text=True, check=True, cwd=ROOT)
        browser_rows = json.loads(result.stdout)
        for fixture, browser in zip(fixtures, browser_rows):
            python = build_feature_row(fixture['url'], fixture['title'], fixture['html'])
            with self.subTest(fixture=fixture['name']): self.assertEqual(python, browser)

    def test_snapshot_identity_types_and_duplicate_observations(self):
        features = build_feature_row('https://page.test/', '', '<p>Page</p>')
        record = {'url':'https://page.test/', 'final_url':'https://page.test/', 'label':0,
            'html':'<p>Page</p>', 'status':200, 'capture_success':True, 'capture_quality':'ok',
            'observed_at':'2026-01-01T00:00:00Z', 'feature_row':features,
            'feature_schema_version':FEATURE_SCHEMA_VERSION, 'extractor_sha256':extractor_source_hash()}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'snapshots.jsonl'
            path.write_text((json.dumps(record)+'\n')*2,encoding='utf-8')
            self.assertEqual(len(load_snapshots(path)), 1)
            for update in [{'extractor_sha256':'stale'}, {'redirect_count':-1}, {'redirect_count':True},
                           {'feature_row':{**features,'has_password_input':False}}]:
                with self.subTest(update=update), self.assertRaises(ValueError):
                    path.write_text(json.dumps({**record, **update})+'\n',encoding='utf-8')
                    load_snapshots(path)
            path.write_text(json.dumps(record)+'\n'+json.dumps({**record,'html':'<p>Changed</p>'})+'\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'different captures'): load_snapshots(path)
            path.write_text('[]\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'must be an object'): load_snapshots(path)
        for invalid in [None, [], {**features,'url_length':True}]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError): validate_feature_row(invalid)

    def test_evaluation_deduplicates_inputs_before_counting(self):
        common = {'status':200,'capture_success':True,'capture_quality':'ok',
                  'observed_at':'2026-01-01T00:00:00Z','source':'reviewed'}
        phish = {**common,'url':'https://phish.test/','final_url':'https://phish.test/', 'label':1,'html':'<p>phishing fixture</p>'}
        legitimate = {**common,'url':'https://safe.test/','final_url':'https://safe.test/', 'label':0,'html':'<p>safe fixture</p>'}
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder)/name for name in ['phish.jsonl','safe.jsonl','changed.jsonl']]
            for path, record in zip(paths,[phish,legitimate,{**phish,'final_url':'https://redirect.test/'}]):
                path.write_text(json.dumps(record)+'\n',encoding='utf-8')
            records, counts = load_records([paths[0],paths[0]],[paths[1]],None,42)
            self.assertEqual(len(records),2)
            self.assertEqual(counts['phishing_records'],1)
            with self.assertRaisesRegex(ValueError,'same URL'): load_records([paths[0],paths[2]],[paths[1]],None,42)
            with self.assertRaisesRegex(ValueError,'Duplicate evaluation URLs'):
                evaluate(Path('unused.joblib'),Path('unused.json'),[phish,phish,legitimate],[],exploratory=True)
            with self.assertRaisesRegex(ValueError,'both phishing and legitimate'):
                evaluate(Path('unused.joblib'),Path('unused.json'),[phish],[],exploratory=True)

    def test_fpr_calibration_uses_budget_not_f1(self):
        labels = [0,0,0,0,1,1,1]
        probabilities = [0.1,0.2,0.8,0.9,0.6,0.85,0.99]
        threshold, metrics = select_fpr_threshold(labels, probabilities, 0)
        self.assertGreater(threshold, .9)
        self.assertEqual(metrics['false_positive_rate'], 0)
        self.assertAlmostEqual(metrics['recall'], 1/3)
        with self.assertRaises(ValueError): select_fpr_threshold([0,1],[1,1],0)
        for probabilities in [[-.1,.8],[.1,1.1],[.2],[.1,float('nan')]]:
            with self.subTest(probabilities=probabilities), self.assertRaises(ValueError):
                select_fpr_threshold([0,1],probabilities,.1)

    def test_capture_html_redacts_values_without_running_scripts(self):
        source = '<form><input type=password value="secret"><input type=hidden value="token"><textarea name=seed>private words &amp; token</textarea></form><script>fetch("/app")</script>'
        redacted = redact_field_values(source)
        for sensitive in ['secret','value=','private words','token']:
            self.assertNotIn(sensitive,redacted)
        self.assertIn('<input type="password">',redacted)
        self.assertIn('fetch("/app")',redacted)

    def test_capture_guards_shared_network_space_and_websockets(self):
        for host in ['100.64.0.1','127.0.0.1','169.254.1.1','10.0.0.1','::1','224.0.0.1','[::1]']:
            with self.subTest(host=host), patch('capture_dom_snapshots.socket.getaddrinfo',return_value=[]):
                self.assertFalse(is_public_host(host))
        self.assertTrue(is_public_host('8.8.8.8'))
        context, socket_route = Mock(), Mock()
        blocked = []
        configure_capture_routes(context, Mock(), blocked)
        pattern, handler = context.route_web_socket.call_args.args
        self.assertEqual(pattern,'**/*')
        handler(socket_route)
        socket_route.close.assert_called_once_with()
        socket_route.connect_to_server.assert_not_called()
        self.assertEqual(blocked,['WEBSOCKET'])
        with self.assertRaisesRegex(RuntimeError,'Playwright >= 1.48'):
            configure_capture_routes(object(),Mock(),[])

    def test_character_pipeline_calibrates_independently_and_is_diagnostic_only(self):
        records = [{'url':f'https://start-safe{i}.test/','final_url':f'https://safe{i}.test/about','label':0} for i in range(40)]
        records += [{'url':f'https://start-bad{i}.test/','final_url':f'http://verify-account{i}.test/login-wallet','label':1} for i in range(40)]
        artifact,model,vectorizer = train_character(records,fpr_budget=.1)
        self.assertEqual(artifact['calibration']['method'],'independent_fpr_budget')
        self.assertFalse(artifact['deployment_eligible'])
        self.assertIn('abo',vectorizer.vocabulary_)
        with patch('future_test_protocol.joblib.load',return_value={'model':model,'vectorizer':vectorizer}):
            actual, _ = model_probabilities(Path('unused.joblib'), records)
        expected = model.predict_proba(vectorizer.transform([r['final_url'] for r in records]))[:,1]
        np.testing.assert_allclose(actual,expected)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            model_path, metadata_path = base/'char.joblib',base/'char.json'
            joblib.dump({'model':model,'vectorizer':vectorizer},model_path)
            artifact['model_file_sha256'] = hashlib.sha256(model_path.read_bytes()).hexdigest()
            metadata_path.write_text(json.dumps(artifact),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'research-only'):
                export_character(metadata_path,model_path,base/'char.js')
            export_character(metadata_path,model_path,base/'char.js',diagnostic_only=True)
            self.assertIn('"deployment_eligible":false',(base/'char.js').read_text(encoding='utf-8'))

    def test_actual_policy_evaluation_preserves_submission_contexts(self):
        fixtures = [
            {'url':'https://college.example/login','title':'College login','label':0,
             'html':'<title>College login</title><form method=post><input type=password></form>'},
            {'url':'https://fake-login.example/','title':'PayPal','label':1,
             'html':'<title>PayPal</title><form method=post action=https://external.test/collect><input type=password></form>'},
            {'url':'https://mixed.example/login','title':'Member login','label':0,
             'html':'<title>Member login</title><form method=post action=https://sso.other.test/login><input type=email autocomplete=username></form><form method=get action=/check><input type=password></form>'},
            {'url':'https://spa-default.example/login','title':'Member login','label':0,
             'html':'<title>Member login</title><form><input type=password></form>'},
            {'url':'https://spa-script.example/login','title':'Member login','label':0,
             'html':'<title>Member login</title><form action="javascript:;" method=get><input type=password></form>'},
        ]
        script = "const fs=require('node:fs');const extract=require('./extension/tests/unit/extract-fixture.cjs');process.stdout.write(JSON.stringify(JSON.parse(fs.readFileSync(0,'utf8')).map(f=>extract(f.html,f.url))));"
        result = subprocess.run(['node','-e',script],input=json.dumps(fixtures),text=True,capture_output=True,check=True,cwd=ROOT)
        records = []
        for fixture, features in zip(fixtures,json.loads(result.stdout)):
            records.append({**fixture,'final_url':fixture['url'],'status':200,'capture_success':True,
                'capture_quality':'ok','observed_at':'2026-02-01T00:00:00+00:00','source':'synthetic-policy',
                'feature_row':{name:features[name] for name in FEATURE_SCHEMA},
                'feature_schema_version':FEATURE_SCHEMA_VERSION,'extractor_sha256':extractor_source_hash(),
                'policy_features':filter_policy_features(features),'policy_version':POLICY_VERSION,
                'policy_sha256':policy_source_hash()})
        report = evaluate_policy(records)
        self.assertEqual([v['outcome'] for v in report['verdicts']],['SAFE','HIGH_RISK','CAUTION','SAFE','SAFE'])
        self.assertEqual(report['high_risk_warning']['confusion_matrix'],{'tn':4,'fp':0,'fn':0,'tp':1})
        self.assertEqual(report['caution_or_high_risk']['confusion_matrix'],{'tn':3,'fp':1,'fn':0,'tp':1})
        self.assertEqual(report['protocol'],'exploratory_local_policy_only')
        self.assertFalse(report['leakage_check']['passed'])
        self.assertIn('synthetic-policy',report['by_source']['high_risk_warning'])
        altered = [{**record,'policy_features':{**record['policy_features'],'credential_form_method_get':0}} for record in records]
        self.assertNotEqual(manifest(records,'original')['record_sha256'],manifest(altered,'altered')['record_sha256'])
        with self.assertRaises(ValueError): evaluate_policy([{**records[0],'policy_sha256':'stale'},*records[1:]])
        with self.assertRaises(ValueError): evaluate_policy(records, frozen_manifest=manifest(records,'frozen'))
        frozen = {**manifest(records,'frozen'),'created_at':'2026-02-02T00:00:00Z'}
        development = manifest([{'url':'https://development.test/','label':0,'html':'independent training content',
            'source':'synthetic-training','observed_at':'2026-01-01T00:00:00Z'}],'development')
        lock = {'locked_at':'2026-02-03T00:00:00Z','policy_sha256':policy_source_hash(),
                'extractor_sha256':extractor_source_hash(),'warning_threshold':65}
        verified = evaluate_policy(records,65,frozen,development,lock)
        self.assertTrue(verified['leakage_check']['passed'])
        with self.assertRaisesRegex(ValueError,'Warning threshold'):
            evaluate_policy(records,60,frozen,development,lock)
        with self.assertRaisesRegex(ValueError,'timezone-aware'):
            evaluate_policy(records,65,frozen,development,{**lock,'locked_at':'2026-02-03T00:00:00'})
        future_time = datetime.now(timezone.utc) + timedelta(days=1)
        with self.assertRaisesRegex(ValueError,'must not be in the future'):
            evaluate_policy(records,65,frozen,development,{**lock,'locked_at':future_time.isoformat()})
        with self.assertRaisesRegex(ValueError,'must not be in the future'):
            evaluate_policy(records,65,{**frozen,'created_at':future_time.isoformat()},development,
                            {**lock,'locked_at':(future_time+timedelta(days=1)).isoformat()})

    def test_training_exact_export_and_provenance_gates(self):
        # Artificial machinery smoke test; these metrics are never a detection benchmark.
        records = [{'url':f'https://safe{i}.test/','label':0,'source':'synthetic-train','observed_at':'2026-01-01T00:00:00+00:00'} for i in range(60)]
        records += [{'url':f'http://{i+1}.22.33.44/login-verify','label':1,'source':'synthetic-train','observed_at':'2026-01-01T00:00:00+00:00'} for i in range(60)]
        future = [{'url':f'https://future-safe{i}.test/','label':0,'source':'synthetic-future','observed_at':'2026-02-01T00:00:00+00:00'} for i in range(10)]
        future += [{'url':f'http://{i+1}.44.55.66/login-verify','label':1,'source':'synthetic-future','observed_at':'2026-02-01T00:00:00+00:00'} for i in range(10)]
        frozen = manifest(future,'frozen_future_test')
        artifact, metrics, model = train(records, fpr_budget=.1, reserved_test=frozen)
        self.assertEqual(artifact['feature_schema'], URL_FEATURE_SCHEMA)
        self.assertFalse(artifact['deployment_eligible'])
        for a, left in artifact['manifests'].items():
            for b, right in artifact['manifests'].items():
                if a != b: assert_separated(left,right)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            model_path, metadata_path, output = base/'model.joblib',base/'model.json',base/'model.js'
            joblib.dump(model, model_path)
            artifact['model_file_sha256'] = hashlib.sha256(model_path.read_bytes()).hexdigest()
            metadata_path.write_text(json.dumps(artifact), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'truncation'):
                export_model(metadata_path, model_path, output, max_trees=31, diagnostic_only=True)
            with self.assertRaisesRegex(ValueError, 'evaluation report'):
                export_model(metadata_path, model_path, output)
            export_model(metadata_path, model_path, output, diagnostic_only=True)
            browser = json.loads(output.read_text(encoding='utf-8').split(' = ',1)[1].rstrip(';\n'))
            x = build_matrix(records, URL_FEATURE_SCHEMA)
            np.testing.assert_allclose(model.predict_proba(x)[:,1], serialized_probabilities(browser,x), atol=1e-12)
            rows = [dict(zip(URL_FEATURE_SCHEMA, row)) for row in x]
            js = subprocess.run(['node',str(ROOT/'ml/tests/browser-model-parity.cjs')],
                input=json.dumps({'modelPath':str(output),'features':rows}),capture_output=True,text=True,check=True,cwd=ROOT)
            browser_results = json.loads(js.stdout)
            self.assertTrue(all(result is not None for result in browser_results))
            np.testing.assert_allclose(model.predict_proba(x)[:,1],[result['probability'] for result in browser_results],atol=1e-12)
            self.assertTrue(all(result['compatible'] and not result['deploymentEligible'] for result in browser_results))
            self.assertEqual(len(browser['trees']), len(model.estimators_))
            evaluation = evaluate(model_path, metadata_path, future, [], frozen_manifest=frozen)
            self.assertTrue(evaluation['leakage_check']['passed'])
            self.assertEqual(evaluation['dom_coverage']['status'], 'unobserved')
            with self.assertRaises(ValueError): evaluate(model_path,metadata_path,records,[],frozen_manifest=frozen)
            with self.assertRaises(ValueError): assert_separated(manifest(records,'train'),manifest(records,'test'),source_time=True)
            with self.assertRaises(ValueError): evaluate(model_path,metadata_path,future,[])


if __name__ == '__main__':
    unittest.main()
