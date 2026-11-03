const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const extract = require('./extract-fixture.cjs');
const { scoreEvidence } = require('../../src/shared/model-policy.js');
const root = path.resolve(__dirname, '../../demo');
for (const [name, expected] of [['legitimate-demo.html', 'SAFE'], ['caution-demo.html', 'CAUTION'], ['phishing-demo.html', 'HIGH_RISK']]) {
  const html = fs.readFileSync(path.join(root, name), 'utf8');
  assert.equal(scoreEvidence(extract(html, 'http://127.0.0.1:8080/' + name)).outcome, expected, name);
  const dom = new JSDOM(html, { url: 'http://127.0.0.1:8080/' + name, runScripts: 'outside-only' });
  assert.match(dom.window.document.querySelector('meta[http-equiv="Content-Security-Policy"]').content, /form-action 'none'/,
    'Browser policy must block submissions even if demo JavaScript fails');
  dom.window.eval(fs.readFileSync(path.join(root, 'demo.js'), 'utf8'));
  const submit = new dom.window.Event('submit', { bubbles: true, cancelable: true });
  dom.window.document.querySelector('form').dispatchEvent(submit);
  assert.equal(submit.defaultPrevented, true, 'Demo cannot submit to its illustrative destination');
  assert.match(dom.window.document.getElementById('demoStatus').textContent, /No form data was submitted/);
  assert([...dom.window.document.querySelectorAll('input')].every((input) => input.readOnly));
  dom.window.close();
}

const interactive = new JSDOM(fs.readFileSync(path.join(root, 'dynamic-demo.html'), 'utf8'), {
  url: 'http://127.0.0.1:8080/dynamic-demo.html', runScripts: 'outside-only'
});
interactive.window.eval(fs.readFileSync(path.join(root, 'demo.js'), 'utf8'));
const document = interactive.window.document;
assert.match(document.querySelector('meta[http-equiv="Content-Security-Policy"]').content, /form-action 'none'/);
for (const [scenario, expected, label] of [
  ['normal', 'SAFE', 'No strong indicators'], ['external', 'CAUTION', 'Caution'],
  ['phishing', 'HIGH_RISK', 'High risk'], ['normal', 'SAFE', 'No strong indicators']
]) {
  const button = document.querySelector(`[data-demo-scenario="${scenario}"]`);
  button.click();
  assert.equal(button.getAttribute('aria-pressed'), 'true');
  assert.equal(document.querySelectorAll('[aria-pressed="true"]').length, 1);
  assert.equal(document.getElementById('expectedResult').textContent, label);
  const actual = scoreEvidence(extract(interactive.serialize(), interactive.window.location.href));
  assert.equal(actual.outcome, expected, `Interactive scenario ${scenario}`);
  const submit = new interactive.window.Event('submit', { bubbles: true, cancelable: true });
  document.getElementById('scenarioForm').dispatchEvent(submit);
  assert.equal(submit.defaultPrevented, true);
  assert.match(document.getElementById('demoStatus').textContent, /No form data was submitted/);
}
interactive.window.close();

const publicExamples = new JSDOM(fs.readFileSync(path.join(root, 'public-examples.html'), 'utf8'), {
  url: 'http://127.0.0.1:8080/public-examples.html', runScripts: 'outside-only'
});
publicExamples.window.eval(fs.readFileSync(path.join(root, 'public-examples.js'), 'utf8'));
const publicDocument = publicExamples.window.document;
for (const link of publicDocument.querySelectorAll('a[target="_blank"]')) {
  assert.match(link.rel, /noopener/);
  assert.match(link.rel, /noreferrer/);
}
assert.equal(publicDocument.querySelector('a.launch').href, 'https://github.com/login');
const observations = Array.from(publicDocument.querySelectorAll('[data-observation]'));
for (const [index, value] of ['Low risk', 'Caution', 'Browser blocked / no extension result'].entries()) {
  observations[index].value = value;
  observations[index].dispatchEvent(new publicExamples.window.Event('change', { bubbles: true }));
}
assert.equal(publicDocument.getElementById('observationProgress').textContent, '3 of 3 examples recorded.');
assert.equal(publicDocument.querySelectorAll('#observationSummary li').length, 3);
assert.match(publicDocument.getElementById('observationSummary').textContent, /BadSSL HTTP password test: Caution/);
publicDocument.getElementById('resetObservations').click();
assert.equal(publicDocument.getElementById('observationProgress').textContent, '0 of 3 examples recorded.');
assert(observations.every(choice => choice.value === ''));
assert.match(publicDocument.body.textContent, /Observed PhishGuard result.*Low risk, 0\/100/);
publicExamples.window.close();
console.log('Controlled demonstration verdicts and submission prevention passed.');
