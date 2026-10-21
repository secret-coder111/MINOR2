const assert = require('assert');

const { PHISH_GUARD_FEATURES } = require('../../src/shared/feature-schema.js');

try {
  assert.ok(Array.isArray(PHISH_GUARD_FEATURES), 'Feature schema should be an array.');
  assert.ok(PHISH_GUARD_FEATURES.length > 20, 'Expected a substantial feature set.');
  assert.ok(PHISH_GUARD_FEATURES.some((item) => item.name === 'has_password_input'), 'has_password_input feature missing.');
  assert.ok(PHISH_GUARD_FEATURES.some((item) => item.name === 'cross_domain_form_action'), 'cross_domain_form_action feature missing.');
  console.log('Feature schema validation passed.');
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
