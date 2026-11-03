const assert = require('node:assert/strict');
global.self = global;
require('../../src/shared/feature-schema.js');
require('../../src/shared/trained-model.js');
const model = () => ({ feature_schema: ['url_length'], threshold: 0.5,
  feature_schema_version: '0.2.0', extractor_version: '0.2.0',
  trees: [[[0, 0.1, 1, 2, 0], [-1, 0, 0, 0, 0.2], [-1, 0, 0, 0, 0.9]]] });
global.PHISH_GUARD_TRAINED_MODEL = model();
const predict = global.PhishGuard.predictTrainedModel;
assert.equal(predict({ url_length: 0.1 }).probability, 0.9, 'Matches sklearn float32 input semantics');
assert.equal(predict({ url_length: 0 }).probability, 0.2);
assert.equal(predict({ url_length: 0 }).deploymentEligible, false);
global.PHISH_GUARD_TRAINED_MODEL = { ...model(), deployment_eligible: true, deployment_status: 'validated' };
assert.equal(predict({ url_length: 0 }).deploymentEligible, false, 'An artifact cannot approve its own deployment');
assert.equal(predict({}), null, 'Missing model input is not fabricated as an observation');
global.PHISH_GUARD_TRAINED_MODEL = { ...model(), extractor_version: '0.1.0' };
assert.equal(predict({ url_length: 0.1 }), null, 'Incompatible extraction cannot produce a deployment prediction');
assert.equal(predict({ url_length: 0.1 }, { allowLegacyDiagnostic: true }).deploymentEligible, false);
global.PHISH_GUARD_TRAINED_MODEL = { ...model(), trees: [[[0, 1, 0, 0, 0]]] };
assert.equal(predict({ url_length: 0 }), null, 'Cyclic trees are rejected');
global.PHISH_GUARD_TRAINED_MODEL = { ...model(), trees: [[[-1, 0, 0, 0, 2]]] };
assert.equal(predict({ url_length: 0 }), null, 'Invalid probability is rejected');
console.log('Versioned model compatibility, corruption and float32 parity validation passed.');
