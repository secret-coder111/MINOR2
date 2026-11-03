const fs = require('node:fs');
const extract = require('../../extension/tests/unit/extract-fixture.cjs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(input.fixtures.map(fixture => {
  const features = extract(fixture.html, fixture.url);
  return Object.fromEntries(input.schema.map(name => [name, features[name]]));
})));
