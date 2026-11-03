// Actual shipped local verdict policy; offline, no page scripts and no network.
const fs = require('node:fs');
const path = require('node:path');
const policy = require(path.resolve(__dirname, '../../extension/src/shared/model-policy.js'));
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(input.features.map(features => policy.scoreEvidence(features,
  { warningThreshold: input.warningThreshold }))));
