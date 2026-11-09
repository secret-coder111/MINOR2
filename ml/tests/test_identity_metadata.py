"""Finite prompt/identity parity fixtures; these are not accuracy measurements."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ml/src'))
from feature_engineering import FEATURE_SCHEMA, build_feature_row


class IdentityMetadataTests(unittest.TestCase):
    def test_browser_python_named_feature_parity(self):
        fixtures = json.loads((ROOT/'ml/tests/fixtures/identity-metadata-golden.json').read_text(encoding='utf-8'))
        result = subprocess.run(['node', str(ROOT/'ml/tests/feature-parity.cjs')],
            input=json.dumps({'fixtures':fixtures,'schema':FEATURE_SCHEMA}), capture_output=True,
            text=True, encoding='utf-8', check=True, cwd=ROOT)
        browser = json.loads(result.stdout)
        for fixture, observed in zip(fixtures, browser):
            with self.subTest(fixture=fixture['name']):
                python = build_feature_row(fixture['url'], fixture['title'], fixture['html'])
                self.assertEqual(python, observed)
                for name, expected in fixture['expected'].items():
                    if name in FEATURE_SCHEMA:
                        self.assertEqual(python[name], expected, name)


if __name__ == '__main__':
    unittest.main()
