const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { JSDOM } = require('jsdom');
const extract = require('./extract-fixture.cjs');
const { scoreEvidence } = require('../../src/shared/model-policy.js');
const root = path.resolve(__dirname, '../../demo');
const tick = () => new Promise(resolve => setImmediate(resolve));
function load(name) {
  const dom = new JSDOM(fs.readFileSync(path.join(root, name), 'utf8'), { url: 'http://127.0.0.1:8080/' + name, runScripts: 'outside-only' });
  const { window } = dom;
  for (const input of window.document.querySelectorAll('input')) {
    Object.defineProperty(input, 'value', { get() { throw new Error('The explanation must not read a field value'); } });
  }
  window.fetch = () => { throw new Error('No network activity is allowed'); };
  window.HTMLFormElement.prototype.submit = () => { throw new Error('No submission is allowed'); };
  window.eval(fs.readFileSync(path.join(root, 'demo.js'), 'utf8'));
  window.eval(fs.readFileSync(path.join(root, 'journey.js'), 'utf8'));
  return dom;
}
test('the three visual journeys preserve real structural verdicts and never read or submit fields', () => {
  for (const [name, outcome] of [['legitimate-demo.html', 'SAFE'], ['caution-demo.html', 'CAUTION'], ['phishing-demo.html', 'HIGH_RISK']]) {
    const dom = load(name), doc = dom.window.document;
    const action = doc.querySelector('form').getAttribute('action');
    assert.equal(doc.getElementById('journeyActualOrigin').textContent, 'http://127.0.0.1:8080');
    assert.equal(doc.getElementById('journeyActualTitle').textContent, doc.title);
    for (let step = 1; step <= 3; step++) doc.getElementById('journeyNext').click();
    assert.equal(doc.getElementById('journeyReceipt').hidden, false);
    assert.match(doc.getElementById('journeyReceipt').textContent, /No actual data was sent/);
    assert.equal(doc.querySelector('form').getAttribute('action'), action);
    assert.equal(scoreEvidence(extract(dom.serialize(), dom.window.location.href)).outcome, outcome, name);
    const event = new dom.window.Event('submit', { bubbles: true, cancelable: true });
    doc.querySelector('form').dispatchEvent(event);
    assert.equal(event.defaultPrevented, true);
    assert.match(doc.querySelector('meta[http-equiv="Content-Security-Policy"]').content, /connect-src 'none'/);
    doc.getElementById('journeyReset').click();
    assert.equal(doc.getElementById('credentialJourney').dataset.step, '0');
    assert.equal(doc.getElementById('journeyReceipt').hidden, true);
    dom.window.close();
  }
});
test('visual page facts track the actual form and title when the presenter changes evidence', async () => {
  const dom = load('dynamic-demo.html'), doc = dom.window.document;
  doc.querySelector('[data-demo-scenario="phishing"]').click();
  await tick();
  assert.equal(doc.getElementById('journeyScenario').textContent, 'Brand + external destination');
  assert.equal(doc.getElementById('journeyActualDestination').textContent, 'https://example.invalid/collect');
  doc.title = 'Professor selected portal';
  doc.getElementById('scenarioForm').action = '/professor-chosen-destination';
  await tick();
  assert.equal(doc.getElementById('journeyActualTitle').textContent, 'Professor selected portal');
  assert.equal(doc.getElementById('journeyScenario').textContent, 'Professor-edited page');
  assert.equal(doc.getElementById('journeyActualDestination').textContent, 'http://127.0.0.1:8080/professor-chosen-destination');
  assert.match(doc.getElementById('journeyCode').textContent, /Professor selected portal/);
  doc.querySelector('[data-demo-scenario="normal"]').click();
  await tick();
  assert.equal(doc.getElementById('journeyScenario').textContent, 'Ordinary login');
  assert.equal(scoreEvidence(extract(dom.serialize(), dom.window.location.href)).outcome, 'SAFE');
  dom.window.close();
});
test('play, pause and reset control the teaching timer without changing the form', () => {
  const dom = load('legitimate-demo.html'), { window } = dom, doc = window.document;
  const queued = new Map(); let id = 0;
  window.setTimeout = fn => { queued.set(++id, fn); return id; };
  window.clearTimeout = key => queued.delete(key);
  doc.getElementById('journeyPlay').click();
  assert.equal(queued.size, 1);
  doc.getElementById('journeyPlay').click();
  assert.equal(queued.size, 0);
  doc.getElementById('journeyPlay').click();
  for (let step = 0; step < 3; step++) {
    const [key, fn] = queued.entries().next().value;
    queued.delete(key); fn();
  }
  assert.equal(doc.getElementById('credentialJourney').dataset.step, '3');
  assert.equal(queued.size, 0);
  assert.equal(doc.querySelector('form').getAttribute('action'), '/demo-signin');
  window.close();
});
