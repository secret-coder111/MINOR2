const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const root = path.resolve(__dirname, '../..');
const files = [
  'shared/constants.js', 'shared/domain-utils.js', 'shared/document-context.js',
  'content/url-features.js', 'content/form-features.js', 'content/dom-features.js'
];
const sources = files.map((file) => fs.readFileSync(path.join(root, 'src', file), 'utf8'));
const suffixes = JSON.parse(fs.readFileSync(path.join(root, 'src/shared/public-suffix-rules.json'), 'utf8'));

module.exports = function extractFixture(html, url, setup) {
  const dom = new JSDOM(html, { url, runScripts: 'outside-only' });
  dom.window.PHISH_GUARD_PSL = suffixes;
  sources.forEach((source) => dom.window.eval(source));
  if (setup) setup(dom.window);
  const { PhishGuard } = dom.window;
  const formFeatures = PhishGuard.extractFormFeatures();
  const result = {
    ...PhishGuard.extractUrlFeatures(),
    ...formFeatures,
    ...PhishGuard.extractDomFeatures(formFeatures)
  };
  dom.window.close();
  return result;
};
