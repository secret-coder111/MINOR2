// Actual shipped local verdict policy; offline, no page scripts and no network.
const fs = require('node:fs');
const path = require('node:path');
const policy = require(path.resolve(__dirname, '../../extension/src/shared/model-policy.js'));
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const score = features => policy.scoreEvidence(features, { warningThreshold: input.warningThreshold });
const verdicts = input.features.map(score);
if (input.ablations) {
  const { variants, project } = require('./policy_ablation.cjs');
  process.stdout.write(JSON.stringify({ verdicts, ablations: Object.fromEntries(variants.map(variant =>
    [variant, input.features.map(features => score(project(features, variant)))])) }));
} else process.stdout.write(JSON.stringify(verdicts));
