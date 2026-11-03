// Publishable teaching assets and an explicitly selected diagnostic URL bundle.
// Never copy raw datasets, estimators, credentials, profiles or user corrections.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');
require('./prepare-url-checker.cjs');
const workspace = path.resolve(__dirname, '..');
const source = path.join(workspace, 'extension/demo');
const site = path.join(workspace, 'sites/phishguard-classroom');
const output = path.join(site, 'dist');
const files = ['index.html', 'legitimate-demo.html', 'caution-demo.html', 'phishing-demo.html',
  'dynamic-demo.html', 'public-examples.html', 'professor-guide.html', 'demo.css', 'demo.js',
  'public-examples.js', 'journey.css', 'journey.js', 'url-checker.html', 'url-checker.css',
  'url-checker.js', 'url-analysis.js', 'url-core.js', 'url-model.js', 'page-check.js'];
fs.mkdirSync(output, { recursive: true });
for (const file of files) fs.copyFileSync(path.join(source, file), path.join(output, file));
assert.deepEqual(fs.readdirSync(output).sort(), [...files].sort(), 'Only explicitly selected public teaching assets may be packaged');
let references = 0;
for (const name of files.filter(file => file.endsWith('.html'))) {
  const dom = new JSDOM(fs.readFileSync(path.join(output, name), 'utf8'), { url: 'https://classroom.example/' + name });
  const doc = dom.window.document;
  if (doc.querySelector('.journey-link > span')) assert.equal(doc.querySelector('.journey-link > span').textContent, '\u2192', 'The visual route arrow must survive packaging');
  if (doc.querySelector('.journey-sso strong')) assert.match(doc.querySelector('.journey-sso strong').textContent, /\u2192/, 'The SSO route arrows must survive packaging');
  const csp = doc.querySelector('meta[http-equiv="Content-Security-Policy"]').content;
  assert.match(csp, /form-action 'none'/);
  assert.match(csp, /connect-src 'none'/);
  for (const control of doc.querySelectorAll('input,textarea')) {
    if (name === 'url-checker.html' && control.id === 'urlInput') {
      assert.equal(control.type, 'text');
      assert.equal(control.maxLength, 4096);
      assert.equal(control.autocomplete, 'off');
    } else assert.equal(control.readOnly, true);
  }
  for (const node of doc.querySelectorAll('[href],[src]')) {
    const value = node.getAttribute('href') || node.getAttribute('src');
    if (!value || /^(?:https?:|mailto:)/i.test(value)) continue;
    const [file, fragment] = value.split('#');
    const target = file || name;
    assert(files.includes(target), `Unexpected local reference ${name}: ${value}`);
    if (fragment) {
      const linked = new JSDOM(fs.readFileSync(path.join(output, target), 'utf8'));
      assert(linked.window.document.getElementById(fragment), `Missing fragment ${target}#${fragment}`);
      linked.window.close();
    }
    references++;
  }
  dom.window.close();
}
console.log(JSON.stringify({ directory: output, files: files.length, localReferences: references,
  forms: 'read-only demos; one explicit URL-only input; submission and page-script connections blocked by CSP', privateProjectDataCopied: false }));
