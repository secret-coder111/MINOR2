"""Offline parity for finite address matches; fixture outcomes are not accuracy."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ml/src'))
from feature_engineering import (brand_address_policy_features, filter_policy_features,
    build_feature_row, FEATURE_SCHEMA, POLICY_VERSION, policy_source_hash)


class BrandAddressTests(unittest.TestCase):
    def test_browser_python_policy_extra_parity(self):
        fixtures = json.loads((ROOT/'ml/tests/fixtures/brand-address-golden.json').read_text(encoding='utf-8'))
        process = subprocess.run(['node', str(ROOT/'ml/tests/brand-address-parity.cjs')],
            input=json.dumps(fixtures), text=True, encoding='utf-8', capture_output=True, check=True, cwd=ROOT)
        browser = json.loads(process.stdout)
        for fixture, observed in zip(fixtures, browser):
            with self.subTest(fixture=fixture):
                expected = brand_address_policy_features(fixture['url'], fixture['identity'], sensitive_context=fixture['sensitive'])
                self.assertEqual(expected, observed)

    def test_schema_and_capture_projection(self):
        self.assertEqual(POLICY_VERSION, '0.6.0')
        self.assertEqual(len(policy_source_hash()), 64)
        self.assertEqual(list(build_feature_row('https://paypa1.com/')), FEATURE_SCHEMA)
        context = {key:0 for key in ['credential_context','has_password_input','credential_field_count',
            'sensitive_credential_field_count','cross_domain_form_action','credential_target_ip',
            'credential_transport_downgrade','credential_insecure_transport','credential_form_method_get',
            'credential_form_explicit_get','credential_script_action','invalid_credential_action']}
        context['credential_form_get_exposes_sensitive'] = 1
        extras = brand_address_policy_features('https://paypa1.com/', 'PayPal sign in', sensitive_context=True)
        record = {**extras, 'credential_contexts':[{**context, **extras}], 'private_text':'never retain'}
        filtered = filter_policy_features(record)
        self.assertEqual(filtered['brand_address_deception'], 1)
        self.assertEqual(filtered['credential_contexts'][0]['credential_brand_address_match'], 1)
        self.assertEqual(filtered['credential_contexts'][0]['credential_form_get_exposes_sensitive'], 1)
        self.assertNotIn('private_text', filtered)
        self.assertNotIn('brand_address_deception', filtered['credential_contexts'][0])


if __name__ == '__main__':
    unittest.main()
