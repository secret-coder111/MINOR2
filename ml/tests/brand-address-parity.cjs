const fs = require('node:fs');
const extract = require('../../extension/tests/unit/extract-fixture.cjs');
const fixtures = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(fixtures.map(fixture => {
  const html = `<h1>${fixture.identity}</h1><form method="post"><input type="${fixture.sensitive ? 'password' : 'email'}"></form>`;
  const features = extract(html, fixture.url);
  const context = features.credential_contexts[0] || {};
  return { brand_address_deception: features.brand_address_deception,
    credential_brand_identity_claim: context.credential_brand_identity_claim || 0,
    credential_brand_address_match: context.credential_brand_address_match || 0 };
})));
