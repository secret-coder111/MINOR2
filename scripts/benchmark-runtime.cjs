/* Local rendered-browser extraction benchmark. No page scripts or form submissions. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
const option = (name, fallback) => { const i = args.indexOf(name); return i < 0 ? fallback : args[i + 1]; };
const output = path.resolve(root, option('--output', '.browser-smoke/runtime-benchmark.json'));
const samples = Number(option('--samples', 7));
if (!Number.isInteger(samples) || samples < 3 || samples > 100) throw new Error('Use 3 through 100 samples');
if (!output.startsWith(root + path.sep) || fs.existsSync(output)) throw new Error('Choose a new report path inside this checkout');
const executable = process.env.PHISHGUARD_EDGE_PATH || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const profile = path.join(root, '.browser-smoke', `benchmark-${Date.now()}`);
const sources = ['shared/feature-schema.js', 'shared/constants.js', 'shared/public-suffix.js',
  'shared/domain-utils.js', 'shared/document-context.js', 'shared/model-policy.js',
  'content/url-features.js', 'content/form-features.js', 'content/dom-features.js']
  .map(name => fs.readFileSync(path.join(root, 'extension/src', name), 'utf8')).join('\n');
// Budgets fixed before measurement; local engineering targets, not universal limits.
const cases = [{ name: 'small', nodes: 500, controls: 4, p95_budget_ms: 100 },
  { name: 'medium', nodes: 5000, controls: 100, p95_budget_ms: 500 },
  { name: 'large', nodes: 20000, controls: 600, p95_budget_ms: 1500 }];
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(check, label) {
  const start = Date.now();
  while (Date.now() - start < 30000) { const value = await check(); if (value) return value; await pause(100); }
  throw new Error(`Timed out: ${label}`);
}
class CDP {
  constructor(socket) {
    this.socket = socket; this.sequence = 0; this.pending = new Map();
    socket.addEventListener('message', event => {
      const message = JSON.parse(String(event.data)), item = this.pending.get(message.id);
      if (!item) return;
      this.pending.delete(message.id); clearTimeout(item.timer);
      message.error ? item.reject(new Error(JSON.stringify(message.error))) : item.resolve(message.result);
    });
  }
  call(method, params = {}, sessionId) {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 45000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  async evaluate(expression, sessionId, contextId) {
    const result = await this.call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true,
      ...(contextId ? { contextId } : {}) }, sessionId);
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  close() { for (const item of this.pending.values()) clearTimeout(item.timer); this.pending.clear(); this.socket.close(); }
}
async function main() {
  if (!fs.existsSync(executable)) throw new Error('Installed Edge not found; set PHISHGUARD_EDGE_PATH');
  fs.mkdirSync(profile, { recursive: true });
  let submissions = 0;
  const server = http.createServer((request, response) => {
    if (!['GET', 'HEAD'].includes(request.method)) submissions++;
    const fixture = cases.find(value => request.url === '/' + value.name);
    if (!fixture) { response.writeHead(404); response.end(); return; }
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; form-action 'none'; base-uri 'none'" });
    response.end('<!doctype html><title>Controlled performance fixture</title><h1>Member portal</h1>' +
      '<p>Ordinary non-sensitive content</p>'.repeat(fixture.nodes) +
      '<form method="post">' + '<label>Password<input type="password" name="synthetic" readonly></label>'.repeat(fixture.controls) +
      '<button>Never submitted</button></form>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let child, cdp, stderr = '';
  const report = { scope: 'Isolated-world production extractors and canonical scoring on rendered local synthetic documents; not detector accuracy or end-to-end warning latency',
    created_at: new Date().toISOString(), samples_per_case: samples, warmups_per_case: 2,
    source_sha256: crypto.createHash('sha256').update(sources).digest('hex'),
    environment: { platform: process.platform, architecture: process.arch, cpu: os.cpus()[0]?.model,
      logical_cpus: os.cpus().length, total_memory_bytes: os.totalmem(), node: process.version }, cases: [] };
  try {
    child = spawn(executable, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
      '--disable-background-networking', '--disable-extensions', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
    { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
    child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4000); });
    child.on('error', error => { stderr += String(error); });
    const parts = await until(() => {
      try { const value = fs.readFileSync(path.join(profile, 'DevToolsActivePort'), 'utf8').trim().split(/\r?\n/);
        return /^\d+$/.test(value[0]) && value[1]?.startsWith('/devtools/browser/') ? value : null;
      } catch (error) { if (['ENOENT', 'EBUSY', 'EPERM'].includes(error.code)) return null; throw error; }
    }, 'isolated Edge startup');
    const socket = new WebSocket(`ws://127.0.0.1:${parts[0]}${parts[1]}`);
    await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
    cdp = new CDP(socket);
    report.browser = (await cdp.call('Browser.getVersion')).product;
    for (const fixture of cases) {
      const target = await cdp.call('Target.createTarget', { url: `http://127.0.0.1:${server.address().port}/${fixture.name}` });
      const { sessionId } = await cdp.call('Target.attachToTarget', { targetId: target.targetId, flatten: true });
      await until(() => cdp.evaluate('document.readyState === "complete"', sessionId), 'fixture document ready');
      const tree = await cdp.call('Page.getFrameTree', {}, sessionId);
      const { executionContextId } = await cdp.call('Page.createIsolatedWorld', { frameId: tree.frameTree.frame.id, worldName: 'PhishGuardPerformance' }, sessionId);
      await cdp.evaluate(sources, sessionId, executionContextId);
      const results = [];
      for (let i = 0; i < samples + 2; i++) {
        const result = await cdp.evaluate(`(() => { const start=performance.now(); const form=PhishGuard.extractFormFeatures();
          const features={...PhishGuard.extractUrlFeatures(),...form,...PhishGuard.extractDomFeatures(form)};
          const extracted=performance.now(); const verdict=PhishGuard.scoreEvidence(features);
          return {extraction_ms:extracted-start,policy_ms:performance.now()-extracted,
            outcome:verdict.outcome,credential_fields:features.credential_field_count}; })()`, sessionId, executionContextId);
        if (result.credential_fields !== fixture.controls) throw new Error('Benchmark did not inspect all fixture controls');
        if (i >= 2) results.push(result);
      }
      const sorted = results.map(row => row.extraction_ms).sort((a, b) => a - b);
      const quantile = q => sorted[Math.ceil(sorted.length * q) - 1];
      const heap = await cdp.call('Runtime.getHeapUsage', {}, sessionId);
      report.cases.push({ ...fixture, median_extraction_ms: quantile(.5), p95_extraction_ms: quantile(.95),
        maximum_extraction_ms: sorted.at(-1), budget_passed: quantile(.95) <= fixture.p95_budget_ms,
        heap_used_bytes: heap.usedSize, measurements: results });
      await cdp.call('Target.closeTarget', { targetId: target.targetId });
    }
    report.fixture_submissions = submissions;
    report.passed = submissions === 0 && report.cases.every(value => value.budget_passed);
    if (!report.passed) process.exitCode = 1;
  } catch (error) {
    report.passed = false; report.error = String(error); report.browser_output = stderr; process.exitCode = 1;
  } finally {
    if (cdp) { try { await cdp.call('Browser.close'); } catch (_) {} cdp.close(); }
    if (child && child.exitCode === null) { await pause(1000); if (child.exitCode === null) child.kill(); }
    await new Promise(resolve => server.close(resolve));
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report, null, 2));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
