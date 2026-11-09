/* Local, harmless Chromium smoke test. Requires installed Edge; no browser download. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { spawn, spawnSync } = require('node:child_process');
const workspace = path.resolve(__dirname, '../..');
const extension = path.join(workspace, 'extension');
const profileRoot = path.resolve(workspace, '.browser-smoke');
const profile = path.join(profileRoot, `edge-${Date.now()}`);
const executable = process.env.PHISHGUARD_EDGE_PATH || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

class CDP {
  constructor(socket) {
    this.socket = socket; this.sequence = 0; this.pending = new Map();
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data));
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id); clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(`${pending.method}: ${JSON.stringify(message.error)}`)); else pending.resolve(message.result);
    });
  }
  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
    return new CDP(socket);
  }
  call(method, params = {}, sessionId) {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timed out: ${method}`)); }, 10000);
      this.pending.set(id, { resolve, reject, timer, method });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  async evaluate(expression, sessionId) {
    const response = await this.call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
    if (response.exceptionDetails) throw new Error(JSON.stringify(response.exceptionDetails));
    return response.result.value;
  }
  close() { this.socket.close(); for (const pending of this.pending.values()) clearTimeout(pending.timer); }
}

async function until(check, description, timeout = 15000) {
  const start = Date.now(); let last;
  while (Date.now() - start < timeout) {
    last = await check(); if (last) return last; await delay(100);
  }
  throw new Error(`Timed out waiting for ${description}; last=${JSON.stringify(last)}`);
}

(async () => {
  assert.ok(fs.existsSync(executable), `Edge executable is missing: ${executable}`);
  fs.mkdirSync(profile, { recursive: true });
  const form = '<form action="/session" method="post"><label>Email<input type="email" name="email"></label><label>Password<input type="password" name="password"></label><button>Sign in</button></form>';
  let submissions = 0;
  const server = http.createServer((request, response) => {
    if (request.method === 'POST') submissions += 1;
    if (request.url.startsWith('/demo/')) {
      const name = request.url.slice('/demo/'.length);
      if (!['dynamic-demo.html', 'legitimate-demo.html', 'caution-demo.html', 'phishing-demo.html', 'index.html', 'public-examples.html', 'public-examples.js', 'demo.css', 'demo.js', 'journey.js', 'journey.css', 'professor-guide.html', 'url-checker.html', 'url-checker.css', 'url-checker.js', 'url-analysis.js', 'url-core.js', 'url-model.js', 'page-check.js'].includes(name)) {
        response.writeHead(404); response.end(); return;
      }
      const type = name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html';
      response.setHeader('Content-Type', `${type}; charset=utf-8`);
      response.end(fs.readFileSync(path.join(extension, 'demo', name))); return;
    }
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (request.url === '/capture-start') response.end('<!doctype html><title>Initial 200</title><script>location.replace("/capture-final")</script>');
    else if (request.url === '/capture-final') { response.statusCode = 404; response.end('<!doctype html><title>Final 404</title><h1>Missing page</h1>'); }
    else if (request.url.startsWith('/suspicious')) response.end('<!doctype html><title>PayPal Account Verification</title><h1>PayPal sign in</h1><form action="https://collector.invalid/collect" method="post"><input type="password" name="password"><button>Sign in</button></form>');
    else if (request.url.startsWith('/framed')) response.end('<!doctype html><title>College portal</title><h1>College portal</h1><iframe src="/suspicious" title="Local controlled test frame"></iframe>');
    else response.end(`<!doctype html><title>College Portal</title><h1>College Portal</h1>${form}`);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  let child; let cdp; let stderr = '';
  const observations = {};
  try {
    child = spawn(executable, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--remote-debugging-port=0', `--user-data-dir=${profile}`, `--load-extension=${extension}`, `--disable-extensions-except=${extension}`, 'about:blank'], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk.toString()).slice(-4000); });
    child.on('error', (error) => { stderr += String(error); });
    const portFile = path.join(profile, 'DevToolsActivePort');
    const [port, endpoint] = await until(() => {
      try {
        const parts = fs.readFileSync(portFile, 'utf8').trim().split(/\r?\n/);
        return /^\d+$/.test(parts[0]) && parts[1]?.startsWith('/devtools/browser/') ? parts : null;
      } catch (error) {
        if (['ENOENT', 'EBUSY', 'EPERM'].includes(error.code)) return null;
        throw error;
      }
    }, 'readable isolated Edge debugging port', 20000);
    cdp = await CDP.connect(`ws://127.0.0.1:${port}${endpoint}`);
    const browserVersion = await cdp.call('Browser.getVersion');
    observations.browser = browserVersion.product;
    const target = await cdp.call('Target.createTarget', { url: `${origin}/ordinary` });
    const page = await cdp.call('Target.attachToTarget', { targetId: target.targetId, flatten: true });
    const serviceWorker = await until(async () => (await cdp.call('Target.getTargets')).targetInfos.find((item) => item.type === 'service_worker' && /chrome-extension:.*\/src\/background\/service-worker\.js$/.test(item.url)), 'PhishGuard service worker loaded from unpacked extension');
    const worker = await cdp.call('Target.attachToTarget', { targetId: serviceWorker.targetId, flatten: true });
    let workerSession = worker.sessionId;
    await cdp.call('Runtime.enable', {}, workerSession);
    observations.workerContext = await cdp.evaluate("({url:globalThis.location?.href, chrome:typeof chrome, self:typeof self, document:typeof document, phishguard:typeof PhishGuard})", workerSession);
    await until(() => cdp.evaluate("typeof chrome !== 'undefined' && !!chrome.runtime", workerSession), 'extension API bindings in service worker');
    observations.extensionId = await cdp.evaluate('chrome.runtime.id', workerSession);
    const tabId = await until(() => cdp.evaluate(`chrome.tabs.query({}).then(tabs => tabs.find(tab => tab.url && tab.url.startsWith(${JSON.stringify(origin)}))?.id)`, workerSession), 'fixture tab');
    const read = () => cdp.evaluate(`chrome.storage.session.get('tab_${tabId}').then(value => value.tab_${tabId} || null)`, workerSession);
    const readAction = () => cdp.evaluate(`Promise.all([chrome.action.getBadgeText({tabId:${tabId}}), chrome.action.getTitle({tabId:${tabId}})]).then(([text,title])=>({text,title}))`, workerSession);
    let result = await until(read, 'ordinary local login result');
    assert.notEqual(result.outcome, 'HIGH_RISK');
    assert.equal(await cdp.evaluate("!!document.getElementById('phishguard-warning-banner')", page.sessionId), false);
    observations.localHttpLogin = { score: result.score, outcome: result.outcome, note: 'Local HTTP/IP fixtures can produce transport/address caution; no high-risk banner.' };
    assert.equal(result.inspectionScope.scriptDataFlow, 'not_verified');
    assert.equal(result.inspectionScope.formDestinations, 'declared_only');
    assert.match((await readAction()).title, /safety is not verified|Incomplete inspection/);

    await cdp.evaluate("document.querySelector('form').action='https://collector.invalid/collect'", page.sessionId);
    result = await until(async () => { const value = await read(); return value && value.outcome === 'CAUTION' && value; }, 'external destination caution');
    const cautionAction = await until(async () => { const value = await readAction(); return /Caution/.test(value.title) && value; }, 'browser-owned caution status');
    assert.equal(cautionAction.text, '!');
    assert.equal(await cdp.evaluate("!!document.getElementById('phishguard-warning-banner')", page.sessionId), false);
    observations.browserOwnedCaution = cautionAction;

    await cdp.evaluate("history.pushState({}, '', '/spa'); document.title='PayPal Account Verification'; document.querySelector('form').action='https://collector.invalid/collect'", page.sessionId);
    result = await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK' && value; }, 'SPA/attribute-change high-risk verdict');
    await until(() => cdp.evaluate("!!document.getElementById('phishguard-warning-banner')", page.sessionId), 'SPA warning banner');
    const highAction = await until(async () => { const value = await readAction(); return /High phishing risk/.test(value.title) && value; }, 'browser-owned high-risk status');
    assert.equal(highAction.text, '!');
    const timedWarning = await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK'
      && Number.isFinite(value.runtimeTiming?.scan_to_warning_dom_ms) && value; }, 'bounded warning DOM timing recorded');
    assert.ok(timedWarning.metadata.runtime_timing.extraction_ms >= 0);
    assert.ok(timedWarning.metadata.runtime_timing.policy_ms >= 0);
    assert.ok(timedWarning.runtimeTiming.scan_to_warning_dom_ms >= timedWarning.runtimeTiming.scan_to_result_ms);
    observations.runtimeTiming = { evidenceFrame: timedWarning.metadata.runtime_timing, topDocument: timedWarning.runtimeTiming,
      scope: 'Latest observed local scan and warning DOM insertion; not paint, prevention, or an accuracy benchmark.' };
    observations.browserOwnedHighRisk = highAction;
    observations.spaMutation = { score: result.score, outcome: result.outcome };
    await cdp.evaluate("document.title='College Portal'; document.querySelector('form').action='/session'", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome !== 'HIGH_RISK' && value; }, 'attribute correction rescanned');
    await until(async () => !(await cdp.evaluate("!!document.getElementById('phishguard-warning-banner')", page.sessionId)), 'corrected warning removed');
    await until(async () => /safety is not verified/.test((await readAction()).title), 'browser-owned stale warning cleared');
    observations.attributeCorrection = 'warning removed';

    const priorToken = (await read()).identity.documentToken;
    await cdp.call('Page.navigate', { url: `${origin}/framed` }, page.sessionId);
    result = await until(async () => { const value = await read(); return value && value.identity.documentToken !== priorToken && value.outcome === 'HIGH_RISK' && value.evidenceFrame.frameId !== 0 && value; }, 'embedded-frame warning reaches top page');
    await until(() => cdp.evaluate("!!document.getElementById('phishguard-warning-banner')", page.sessionId), 'embedded-frame top banner');
    observations.embeddedFrame = { score: result.score, outcome: result.outcome, frameId: result.evidenceFrame.frameId };
    await cdp.evaluate("document.querySelector('iframe').remove()", page.sessionId);
    await until(async () => { const value = await read(); return value && value.inspectedFrames === 1 && value.outcome !== 'HIGH_RISK' && value; }, 'removed frame warning cleared');
    observations.frameRemoval = 'warning removed';
    assert.ok(!JSON.stringify(await read()).includes('/suspicious'), 'session result must omit full frame path');

    const semanticBrandChecks = [];
    for (const scenario of [
      { name: 'article heading', html: '<article><h2>PayPal sign in</h2><form method="post" action="https://collector.invalid/collect"><input type="password" name="password"><button>Sign in</button></form></article>', outcome: 'HIGH_RISK' },
      { name: 'local image alternate text', html: '<img alt="PayPal logo"><form method="post" action="https://collector.invalid/collect"><input type="password" name="password"><button>Sign in</button></form>', outcome: 'HIGH_RISK' },
      { name: 'provider button image', html: '<button type="button">Continue with <img alt="PayPal logo"></button><form method="post" action="https://collector.invalid/collect"><input type="password" name="password"><button>Sign in</button></form>', outcome: 'CAUTION' }
    ]) {
      const priorScan = (await read()).identity.scanId;
      await cdp.evaluate(`document.title='Member login'; document.body.innerHTML=${JSON.stringify(scenario.html)}`, page.sessionId);
      const value = await until(async () => { const value = await read(); return value && value.identity.scanId > priorScan
        && value.outcome === scenario.outcome && value; }, `semantic brand ${scenario.name}`);
      if (scenario.outcome === 'CAUTION') assert.equal(value.metadata.evidence_categories.identity, 0, 'provider branding alone cannot establish impersonation');
      semanticBrandChecks.push({ name: scenario.name, outcome: value.outcome, score: value.score });
    }
    observations.semanticBrandChecks = semanticBrandChecks;

    // Reserved .test URLs are fulfilled from this process before networking.
    // This exercises a real HTTPS-origin URL without visiting a phishing site.
    const interceptedErrors = [];
    const intercept = (event) => {
      const message = JSON.parse(String(event.data));
      if (message.sessionId !== page.sessionId || message.method !== 'Fetch.requestPaused') return;
      const provider = new URL(message.params.request.url).pathname === '/provider';
      const html = provider
        ? '<!doctype html><title>Community sign in</title><h1>Sign in with PayPal</h1><form method="post" action="/session"><input type="password"><button>Continue</button></form>'
        : '<!doctype html><title>Account</title><h1>PayPal</h1><form method="post" action="/session"><input type="password"><button>Sign in</button></form>';
      cdp.call('Fetch.fulfillRequest', { requestId: message.params.requestId, responseCode: 200,
        responseHeaders: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' }, { name: 'Content-Security-Policy', value: "form-action 'none'" }],
        body: Buffer.from(html).toString('base64') }, page.sessionId).catch((error) => interceptedErrors.push(String(error)));
    };
    cdp.socket.addEventListener('message', intercept);
    await cdp.call('Fetch.enable', { patterns: [{ urlPattern: 'https://paypa1.test/*', requestStage: 'Request' }] }, page.sessionId);
    await cdp.call('Page.navigate', { url: 'https://paypa1.test/login' }, page.sessionId);
    const sameOriginRisk = await until(async () => { const value = await read(); return value && value.pageOrigin === 'https://paypa1.test' && value.outcome === 'HIGH_RISK' && value; }, 'same-origin deceptive brand login');
    assert.equal(sameOriginRisk.metadata.evidence_categories.destination, 0, 'new protection does not invent an external form destination');
    assert.ok(sameOriginRisk.metadata.evidence_categories.address >= 25);
    observations.sameOriginLookalike = { score: sameOriginRisk.score, outcome: sameOriginRisk.outcome, externalDestination: false };

    // Open the real popup in a background target while the inspected site stays
    // active. This uses extension APIs and DOM, not a stubbed screenshot.
    await cdp.evaluate(`chrome.tabs.update(${tabId}, {active:true})`, workerSession);
    const popupTarget = await cdp.call('Target.createTarget', { url: `chrome-extension://${observations.extensionId}/src/popup/popup.html`, background: true });
    const popupSession = (await cdp.call('Target.attachToTarget', { targetId: popupTarget.targetId, flatten: true })).sessionId;
    await until(() => cdp.evaluate("document.getElementById('riskBadge')?.textContent === 'High risk'", popupSession), 'real popup displays active-site high risk');
    assert.equal(await cdp.evaluate("document.getElementById('siteOrigin').textContent", popupSession), 'https://paypa1.test');
    await cdp.evaluate("document.getElementById('rescanBtn').click()", popupSession);
    await until(() => cdp.evaluate("document.getElementById('scanStatus').textContent === 'Page checked again.'", popupSession), 'popup manual rescan actually finishes');
    await cdp.call('Emulation.setDeviceMetricsOverride', { width: 240, height: 600, deviceScaleFactor: 1, mobile: false }, popupSession);
    assert.equal(await cdp.evaluate('document.body.getBoundingClientRect().width', popupSession), 540, 'Intrinsic popup width must escape a tiny provisional browser viewport');
    await cdp.call('Emulation.setDeviceMetricsOverride', { width: 540, height: 600, deviceScaleFactor: 1, mobile: false }, popupSession);
    assert.equal(await cdp.evaluate('document.documentElement.scrollWidth <= innerWidth', popupSession), true, 'popup fits its normal width');
    const popupPreview = await cdp.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false }, popupSession);
    fs.writeFileSync(path.join(profileRoot, 'popup-0.5.0.png'), Buffer.from(popupPreview.data, 'base64'));
    assert.equal(await cdp.evaluate("document.getElementById('leaveBtn').hidden", popupSession), false);
    assert.equal(await cdp.evaluate("document.querySelectorAll('#urlCheckerBtn').length", popupSession), 1);
    observations.popup = 'real origin, current-tab scope, high-risk next step, manual rescan, intrinsic width 540px and 600px screenshot verified';
    await cdp.call('Target.closeTarget', { targetId: popupTarget.targetId });
    await cdp.call('Page.navigate', { url: 'https://paypa1.test/provider' }, page.sessionId);
    await until(async () => { const value = await read(); return value && value.pageOrigin === 'https://paypa1.test'
      && value.identity.documentToken !== sameOriginRisk.identity.documentToken && value.outcome === 'SAFE'; }, 'provider mention does not activate deceptive identity');
    assert.deepEqual(interceptedErrors, []);
    await cdp.call('Fetch.disable', {}, page.sessionId);
    cdp.socket.removeEventListener('message', intercept);
    observations.lookalikeProviderControl = 'provider phrase alone remains low risk; no submission made';

    // Exercise the exact fixtures the student will present, using the installed
    // extension and browser DOM observer, rather than a second scoring engine.
    const beforeDemo = (await read()).identity.documentToken;
    await cdp.call('Page.navigate', { url: `${origin}/demo/dynamic-demo.html` }, page.sessionId);
    await until(async () => { const value = await read(); return value && value.identity.documentToken !== beforeDemo && value.outcome === 'SAFE'; }, 'interactive demo first scan');
    const demoResults = [];
    for (const [scenario, expected] of [['external', 'CAUTION'], ['phishing', 'HIGH_RISK'], ['normal', 'SAFE']]) {
      await cdp.evaluate(`document.querySelector('[data-demo-scenario="${scenario}"]').click()`, page.sessionId);
      const current = await until(async () => { const value = await read(); return value && value.outcome === expected && value; }, `interactive ${scenario} rescan`);
      await until(async () => (await cdp.evaluate("!!document.getElementById('phishguard-warning-banner')", page.sessionId)) === (expected === 'HIGH_RISK'), `interactive ${scenario} banner state`);
      demoResults.push({ scenario, score: current.score, outcome: current.outcome });
      if (scenario === 'phishing') {
        await cdp.evaluate("document.querySelector('[data-phishguard-details]').open=true", page.sessionId);
        assert.match(await cdp.evaluate("document.getElementById('phishguard-warning-banner').textContent", page.sessionId), /Pause before entering passwords/);
        for (const [name, width, height] of [['desktop', 1440, 1050], ['mobile', 390, 950]]) {
          await cdp.call('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false }, page.sessionId);
          assert.equal(await cdp.evaluate('document.documentElement.scrollWidth <= innerWidth', page.sessionId), true, `interactive lab fits ${name} width`);
          const preview = await cdp.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, page.sessionId);
          fs.writeFileSync(path.join(profileRoot, `warning-${name}-0.5.0.png`), Buffer.from(preview.data, 'base64'));
          assert.equal(await cdp.evaluate("(() => { const rect=document.getElementById('phishguard-warning-banner').getBoundingClientRect(); return rect.left >= 0 && rect.right <= innerWidth && rect.bottom <= innerHeight; })()", page.sessionId), true, 'warning card remains within the viewport');
        }
        await cdp.call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] }, page.sessionId);
        assert.equal(await cdp.evaluate("getComputedStyle(document.getElementById('phishguard-warning-banner')).animationName", page.sessionId), 'none');
        await cdp.call('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, page.sessionId);
        observations.warningPresentation = 'expanded contextual reasons, desktop/mobile layout and reduced motion verified';
        await cdp.evaluate("document.querySelector('[data-phishguard-close]').click()", page.sessionId);
        assert.equal(await cdp.evaluate("!!document.querySelector('[data-phishguard-close]')", page.sessionId), true, 'page-script clicks cannot dismiss the notification');
        const closePoint = await cdp.evaluate("(() => {const r=document.querySelector('[data-phishguard-close]').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()", page.sessionId);
        await cdp.call('Input.dispatchMouseEvent', { type: 'mousePressed', ...closePoint, button: 'left', clickCount: 1 }, page.sessionId);
        await cdp.call('Input.dispatchMouseEvent', { type: 'mouseReleased', ...closePoint, button: 'left', clickCount: 1 }, page.sessionId);
        await until(() => cdp.evaluate("!document.querySelector('[data-phishguard-close]')", page.sessionId), 'trusted user click closes the warning');
        assert.equal((await read()).outcome, 'HIGH_RISK', 'closing the notification preserves the verdict');
        const dismissedScan = (await read()).identity.scanId;
        await cdp.evaluate(`chrome.tabs.sendMessage(${tabId},{type:'REQUEST_RESCAN'})`, workerSession);
        await until(async () => (await read()).identity.scanId > dismissedScan, 'automatic rescan after dismissal');
        assert.equal(await cdp.evaluate("!!document.querySelector('[data-phishguard-close]')", page.sessionId), false, 'same warning stays dismissed during automatic rescans');
        await cdp.evaluate(`chrome.tabs.sendMessage(${tabId},{type:'REQUEST_RESCAN',reason:'user'})`, workerSession);
        await until(() => cdp.evaluate("!!document.querySelector('[data-phishguard-close]')", page.sessionId), 'explicit user rescan restores the warning');
        observations.warningDismissal = 'trusted close works; synthetic page click rejected; verdict retained; automatic rescan stays dismissed; explicit rescan restores warning';
      }
    }
    await cdp.evaluate("document.querySelector('#scenarioForm button').click()", page.sessionId);
    assert.match(await cdp.evaluate("document.getElementById('demoStatus').textContent", page.sessionId), /No form data was submitted/);
    // Direct form.submit bypasses submit event handlers. CSP must still block it.
    await cdp.evaluate("document.addEventListener('securitypolicyviolation', event => { if (event.violatedDirective === 'form-action') window.__demoFormBlocked = true; }); HTMLFormElement.prototype.submit.call(document.getElementById('scenarioForm'));", page.sessionId);
    await until(() => cdp.evaluate('window.__demoFormBlocked === true', page.sessionId), 'browser CSP blocks submission without JavaScript handler');
    assert.equal(submissions, 0, 'No demo form request reaches a server');
    observations.interactiveDemo = demoResults;
    observations.demoSubmission = 'JavaScript cancellation and browser CSP verified; zero POST requests';
    const visualJourneys = [];
    for (const [name, expected] of [['legitimate-demo.html', 'SAFE'], ['caution-demo.html', 'CAUTION'], ['phishing-demo.html', 'HIGH_RISK']]) {
      const previousJourneyToken = (await read())?.identity.documentToken;
      await cdp.call('Page.navigate', { url: `${origin}/demo/${name}` }, page.sessionId);
      const initial = await until(async () => { const value = await read(); return value && value.identity.documentToken !== previousJourneyToken && value.outcome === expected && value; }, `visual journey ${name} actual extension verdict`);
      await until(() => cdp.evaluate("!!document.getElementById('journeyNext')", page.sessionId), 'visual controls loaded');
      const originalAction = await cdp.evaluate("document.querySelector('form').getAttribute('action')", page.sessionId);
      await cdp.evaluate("for(let i=0;i<3;i++)document.getElementById('journeyNext').click();document.querySelector('.journey-facts').open=true", page.sessionId);
      assert.equal(await cdp.evaluate("document.getElementById('journeyReceipt').hidden", page.sessionId), false);
      assert.equal(await cdp.evaluate("document.querySelector('form').getAttribute('action')", page.sessionId), originalAction);
      await until(async () => { const value = await read(); return value && value.identity.scanId > initial.identity.scanId && value.outcome === expected; }, 'animation does not change the actual verdict');
      for (const [size, width, height] of [['desktop', 1440, 1050], ['narrow', 390, 950]]) {
        await cdp.call('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false }, page.sessionId);
        assert.equal(await cdp.evaluate('document.documentElement.scrollWidth <= innerWidth', page.sessionId), true, `visual journey fits ${size}`);
        const preview = await cdp.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, page.sessionId);
        fs.writeFileSync(path.join(profileRoot, `journey-${name.replace('.html','')}-${size}.png`), Buffer.from(preview.data, 'base64'));
      }
      await cdp.call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] }, page.sessionId);
      await cdp.evaluate("document.getElementById('journeyReset').click();document.getElementById('journeyNext').click();document.getElementById('journeyNext').click()", page.sessionId);
      assert.equal(await cdp.evaluate("getComputedStyle(document.querySelector('.journey-packet')).animationName", page.sessionId), 'none');
      assert.equal(submissions, 0);
      visualJourneys.push({ page: name, outcome: expected, animation: 'fictional tokens only; no submitted fields; route unchanged' });
    }
    observations.visualJourneys = visualJourneys;
    await cdp.call('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, page.sessionId);
    const beforeJourneyReturn = (await read())?.identity.documentToken;
    await cdp.call('Page.navigate', { url: `${origin}/demo/dynamic-demo.html` }, page.sessionId);
    await until(async () => { const value = await read(); return value && value.identity.documentToken !== beforeJourneyReturn && value.outcome === 'SAFE'; }, 'return from visual pages to the baseline interactive test');
    const beforeMetadata = (await read()).identity.scanId;
    await cdp.evaluate("document.title='PayPal Account Verification'; document.body.innerHTML='<form action=\"https://example.invalid/collect\" method=\"post\"><input type=\"text\" id=\"opaque\" name=\"opaque\"></form>'", page.sessionId);
    await until(async () => { const value = await read(); return value && value.identity.scanId > beforeMetadata && value.outcome === 'SAFE'; }, 'generic text field has no credential context');
    await cdp.evaluate("document.getElementById('opaque').setAttribute('placeholder', 'Password')", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK'; }, 'metadata-only password prompt triggers high-risk rescan');
    await cdp.evaluate("document.getElementById('opaque').setAttribute('placeholder', 'Example')", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'SAFE'; }, 'metadata correction clears credential warning');
    observations.metadataMutation = 'placeholder-only password prompt rescanned to high risk; correction cleared warning';
    await cdp.evaluate("document.querySelector('input').placeholder='Email verification code'", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK'; }, 'email verification code is recognized as sensitive');
    await cdp.evaluate("const form=document.querySelector('form');form.method='get';form.action='/session';document.querySelector('input').removeAttribute('name')", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'CAUTION'; }, 'unnamed secret control does not invent GET exposure');
    await cdp.evaluate("document.querySelector('input').name='verificationCode'", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK'; }, 'named secret control restores GET exposure evidence');
    observations.detectionQuality = 'OTP metadata recognized; unnamed GET avoids invented leakage; named GET remains high risk with brand mismatch';
    await cdp.evaluate("document.querySelector('input').placeholder='Example';document.querySelector('form').method='post'", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'SAFE'; }, 'quality fixtures reset before shadow-tree checks');
    const beforeShadowHost = (await read()).identity.scanId;
    await cdp.evaluate("const host=document.createElement('div');host.id='shadowFixture';document.body.appendChild(host)", page.sessionId);
    await until(async () => { const value = await read(); return value && value.identity.scanId > beforeShadowHost; }, 'empty shadow host first observed');
    await cdp.evaluate("document.getElementById('shadowFixture').attachShadow({mode:'open'}).innerHTML='<form action=\"https://example.invalid/collect\" method=\"post\"><input type=\"password\" name=\"password\"></form>'", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK'; }, 'late open shadow credential form detected');
    await until(() => cdp.evaluate("!!document.getElementById('phishguard-warning-banner')", page.sessionId), 'shadow warning appears');
    await cdp.evaluate("document.getElementById('phishguard-warning-banner').remove()", page.sessionId);
    await until(() => cdp.evaluate("!!document.getElementById('phishguard-warning-banner')", page.sessionId), 'removed warning repaired');
    await cdp.evaluate("const warning=document.getElementById('phishguard-warning-banner');warning.setAttribute('style','display:none');warning.hidden=true;warning.textContent='altered by page'", page.sessionId);
    await until(() => cdp.evaluate("(() => { const warning=document.getElementById('phishguard-warning-banner');return !warning.hidden && getComputedStyle(warning).display !== 'none' && warning.textContent.startsWith('PhishGuard:'); })()", page.sessionId), 'hidden/styled/replaced warning repaired');
    await cdp.evaluate("document.title='College Portal';document.getElementById('shadowFixture').shadowRoot.querySelector('form').action='/session'", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'SAFE'; }, 'shadow correction rescanned');
    observations.openShadow = 'late root discovered, credentials detected, warning interference repaired, correction cleared risk';
    // Use an ordinary local page: the teaching demo intentionally blocks inline
    // styles via CSP, which would make this CSSOM visibility fixture invalid.
    const beforeCssDocument = (await read()).identity.documentToken;
    await cdp.call('Page.navigate', { url: `${origin}/ordinary` }, page.sessionId);
    await until(async () => { const value = await read(); return value && value.identity.documentToken !== beforeCssDocument && value.outcome === 'SAFE'; }, 'ordinary page for CSS visibility fixture');
    const beforeCss = (await read()).identity.scanId;
    await cdp.evaluate("document.title='PayPal sign in';document.body.innerHTML='<style id=\"cssFixture\">#cssPassword{display:none}</style><form method=\"post\" action=\"https://collector.invalid/collect\"><input id=\"cssPassword\" type=\"password\"></form>';true", page.sessionId);
    await until(async () => { const value = await read(); return value && value.identity.scanId > beforeCss && value.outcome === 'SAFE'; }, 'hidden field stays neutral');
    await cdp.evaluate("document.getElementById('cssFixture').sheet.insertRule('#cssPassword{display:block}',1);true", page.sessionId);
    const cssResult = await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK' && value; }, 'CSSOM-only reveal automatically rescanned', 7000);
    observations.cssomReveal = { outcome: cssResult.outcome, score: cssResult.score };
    await cdp.evaluate("document.title='College Portal';document.body.innerHTML='<details><summary>Archived login</summary><form method=\"post\" action=\"http://old-sso.invalid/collect\"><input type=\"password\"></form></details>';true", page.sessionId);
    await until(async () => { const value = await read(); return value && value.identity.scanId > cssResult.identity.scanId && value.outcome === 'SAFE'; }, 'closed details controls do not warn');
    assert.equal(await cdp.evaluate("document.querySelector('input').checkVisibility({visibilityProperty:true,opacityProperty:true,contentVisibilityAuto:true})", page.sessionId), false);
    await cdp.evaluate("document.querySelector('details').open=true;true", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK'; }, 'opening details rescans active controls');
    await cdp.evaluate("document.querySelector('details').open=false;true", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'SAFE'; }, 'closing details clears warning');
    observations.collapsedControls = 'closed SAFE; open HIGH_RISK; closed SAFE';
    const beforeHash = (await read()).identity.scanId;
    await cdp.evaluate("location.hash='comparison'", page.sessionId);
    await until(async () => { const value = await read(); return value && value.identity.scanId > beforeHash && value.outcome === 'SAFE'; }, 'hash navigation rescanned');
    observations.hashNavigation = 'current document rescanned';
    await cdp.evaluate("const inherited=document.createElement('iframe');inherited.id='inheritedFixture';inherited.srcdoc='<title>PayPal sign in</title><form method=\"post\" action=\"https://collector.invalid/collect\"><input type=\"password\"></form>';document.body.appendChild(inherited)", page.sessionId);
    const inheritedResult = await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK' && value.evidenceFrame.frameId !== 0 && value; }, 'inherited srcdoc credential document inspected');
    observations.inheritedDocument = { score: inheritedResult.score, outcome: inheritedResult.outcome, origin: inheritedResult.evidenceFrame.origin };
    await cdp.evaluate("document.getElementById('inheritedFixture').remove()", page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'SAFE' && value.inspectedFrames === 1; }, 'inherited frame removal reconciled');
    await cdp.evaluate("const frame=document.createElement('iframe');frame.setAttribute('sandbox','');frame.srcdoc='<h1>Opaque embedded document</h1>';document.body.appendChild(frame)", page.sessionId);
    const coverageResult = await until(async () => { const value = await read(); return value && value.coverage?.uninspectedFrames >= 1 && value; }, 'srcdoc coverage gap disclosed');
    observations.coverage = coverageResult.coverage;

    await cdp.call('Page.navigate', { url: `${origin}/framed` }, page.sessionId);
    await until(async () => { const value = await read(); return value && value.outcome === 'HIGH_RISK' && value.coverage.complete && value.evidenceFrame.frameId !== 0; }, 'risky iframe before worker shutdown');
    const beforeWorkerRestart = await read();
    await cdp.call('Target.detachFromTarget', { sessionId: workerSession });
    const stoppedWorker = await cdp.call('Target.closeTarget', { targetId: serviceWorker.targetId });
    assert.equal(stoppedWorker.success, true, 'isolated extension worker can be stopped');
    // Only the top document changes. Its static risky child must be asked to
    // recover by the new worker rather than being silently dropped.
    await cdp.evaluate("document.body.appendChild(document.createElement('p'));true", page.sessionId);
    workerSession = await until(async () => {
      const restartedTarget = (await cdp.call('Target.getTargets')).targetInfos.find((item) => item.type === 'service_worker'
        && item.targetId !== serviceWorker.targetId && /chrome-extension:.*\/src\/background\/service-worker\.js$/.test(item.url));
      if (!restartedTarget) return null;
      // Chromium can briefly list the old/stopping worker after closeTarget.
      // Attach to the replacement while it exists, rather than treating that
      // target-discovery race as a detector failure.
      try {
        const attached = await cdp.call('Target.attachToTarget', { targetId: restartedTarget.targetId, flatten: true });
        await cdp.call('Runtime.enable', {}, attached.sessionId);
        return attached.sessionId;
      } catch (error) {
        if (/No target with given id|Session closed|No session with given id|Cannot find context/i.test(String(error))) return null;
        throw error;
      }
    }, 'attach to the restarted worker');
    await until(async () => { const value = await read(); return value && value.identity.scanId > beforeWorkerRestart.identity.scanId && value.outcome === 'HIGH_RISK' && value.coverage.complete && value.evidenceFrame.frameId !== 0; }, 'cold worker recovers risky static child');
    observations.workerRestart = 'actual worker stopped; top-only mutation restarted it and risky static iframe recovered';

    // Actual public-comparison controls, including reset, in the browser.
    await cdp.call('Page.navigate', { url: `${origin}/demo/public-examples.html` }, page.sessionId);
    await until(() => cdp.evaluate("!!document.getElementById('resetObservations')", page.sessionId), 'public comparison page');
    await cdp.evaluate("document.querySelectorAll('[data-observation]').forEach((node,index) => { node.selectedIndex=index+1;node.dispatchEvent(new Event('change')); })", page.sessionId);
    assert.equal(await cdp.evaluate("document.getElementById('observationProgress').textContent", page.sessionId), '3 of 3 examples recorded.');
    await cdp.evaluate("document.getElementById('resetObservations').click()", page.sessionId);
    assert.equal(await cdp.evaluate("document.getElementById('observationProgress').textContent", page.sessionId), '0 of 3 examples recorded.');
    observations.publicComparisonControls = 'observation selection, summary and reset passed';
    const previews = [];
    for (const [name, width] of [['desktop', 1280], ['mobile', 390]]) {
      try {
      await cdp.call('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 }, page.sessionId);
      const screenshot = await cdp.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false }, page.sessionId);
      fs.writeFileSync(path.join(profileRoot, `public-examples-${name}.png`), Buffer.from(screenshot.data, 'base64'));
      previews.push({ name, captured: true });
      } catch (error) { previews.push({ name, captured: false, error: String(error) }); }
    }
    observations.previews = previews;
    await cdp.call('Emulation.clearDeviceMetricsOverride', {}, page.sessionId);

    await cdp.call('Page.navigate', { url: `${origin}/ordinary` }, page.sessionId);
    await until(() => cdp.evaluate("document.querySelectorAll('input[type=password]').length === 1", page.sessionId), 'collector isolation fixture');
    const python = path.join(workspace, '.venv/Scripts/python.exe');
    if (fs.existsSync(python)) {
    const expression = spawnSync(python, ['-X', 'utf8', '-c', "import sys;sys.path.insert(0,'ml/src');from capture_dom_snapshots import browser_extractor,capture_expression;print(capture_expression(browser_extractor()[0]))"], { cwd: workspace, encoding: 'utf8', windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    assert.equal(expression.status, 0, expression.stderr);
    await cdp.evaluate("Document.prototype.querySelectorAll=()=>[];Element.prototype.querySelectorAll=()=>[];Object.defineProperty(Document.prototype,'title',{get:()=> 'FORGED'});true", page.sessionId);
    assert.equal(await cdp.evaluate("document.querySelectorAll('input').length", page.sessionId), 0);
    await cdp.call('Page.enable', {}, page.sessionId);
    await cdp.call('Runtime.enable', {}, page.sessionId);
    const tree = await cdp.call('Page.getFrameTree', {}, page.sessionId);
    const isolated = await cdp.call('Page.createIsolatedWorld', { frameId: tree.frameTree.frame.id, worldName: 'phishguard-capture' }, page.sessionId);
    const capture = await cdp.call('Runtime.evaluate', { expression: expression.stdout, contextId: isolated.executionContextId, returnByValue: true, timeout: 5000 }, page.sessionId);
    assert.ok(!capture.exceptionDetails, JSON.stringify(capture.exceptionDetails));
    assert.equal(capture.result.value.features.has_password_input, 1);
    assert.equal(capture.result.value.title, 'College Portal');
    assert.equal(capture.result.value.final_url, `${origin}/ordinary`);
    observations.captureWorldIsolation = 'real collector expression resisted page MAIN-world DOM/title prototype poisoning';
    const navigationEvents = [];
    const traceNavigation = (event) => {
      const value = JSON.parse(String(event.data));
      if (value.sessionId === page.sessionId && ['Network.requestWillBeSent', 'Network.responseReceived'].includes(value.method)
          && value.params?.type === 'Document') navigationEvents.push({ method: value.method, params: value.params });
    };
    cdp.socket.addEventListener('message', traceNavigation);
    await cdp.call('Network.enable', {}, page.sessionId);
    await cdp.call('Page.navigate', { url: `${origin}/capture-start` }, page.sessionId);
    const finalFrame = await until(async () => {
      const value = (await cdp.call('Page.getFrameTree', {}, page.sessionId)).frameTree.frame;
      return value.url === `${origin}/capture-final` && value.loaderId && value;
    }, 'completed JavaScript navigation to final 404 document');
    await until(() => navigationEvents.some((event) => event.method === 'Network.responseReceived' && event.params.loaderId === finalFrame.loaderId), 'final navigation response event');
    cdp.socket.removeEventListener('message', traceNavigation);
    const boundStatus = spawnSync(python, ['-X', 'utf8', 'ml/tests/verify_browser_navigation.py'], { cwd: workspace, encoding: 'utf8', windowsHide: true,
      input: JSON.stringify({ events: navigationEvents, document_identity: { frame_id: finalFrame.id, loader_id: finalFrame.loaderId } }) });
    assert.equal(boundStatus.status, 0, boundStatus.stderr);
    observations.captureDocumentBinding = JSON.parse(boundStatus.stdout);
    } else observations.captureWorldIsolation = 'not run: local .venv Python is absent';
    const optionsTarget = await cdp.call('Target.createTarget', { url: `chrome-extension://${observations.extensionId}/src/options/options.html` });
    const optionsSession = (await cdp.call('Target.attachToTarget', { targetId: optionsTarget.targetId, flatten: true })).sessionId;
    await until(() => cdp.evaluate("!!document.getElementById('saveOptions') && !document.getElementById('saveOptions').disabled", optionsSession), 'real options storage initialization');
    await cdp.evaluate("document.getElementById('reputationEnabled').checked=true;document.getElementById('reputationEndpoint').value='https://user:secret@rep.invalid/check';document.getElementById('saveOptions').click();true", optionsSession);
    await until(() => cdp.evaluate("document.getElementById('status').textContent.includes('without embedded username')", optionsSession), 'real options reject unusable endpoint');
    await cdp.evaluate("document.getElementById('reputationEnabled').checked=false;document.getElementById('reputationEndpoint').value='';document.getElementById('saveOptions').click();true", optionsSession);
    await until(() => cdp.evaluate("document.getElementById('status').textContent.startsWith('Settings saved.')", optionsSession), 'real options confirm storage write');
    // Seed only a synthetic annotation in this isolated profile; no user data or
    // actual site judgment is created, and no download/network request is sent.
    await cdp.evaluate(`chrome.storage.local.set({phishguard_feedback:[{topOrigin:${JSON.stringify(origin)},evidenceOrigin:${JSON.stringify(origin)},timestamp:Date.now(),expectedOutcome:'SAFE',observedOutcome:'CAUTION',score:35,policyVersion:'0.3.0',context:{inspectedFrames:1,coverageComplete:true,reputationStatus:'disabled',activeCategories:['destination']}}]})`, workerSession);
    await cdp.call('Page.reload', {}, optionsSession);
    await until(() => cdp.evaluate("!!document.querySelector('#feedbackList input[type=checkbox]')", optionsSession), 'real reviewed-correction interface');
    await cdp.evaluate("const checkbox=document.querySelector('#feedbackList input[type=checkbox]');checkbox.checked=true;checkbox.dispatchEvent(new Event('change',{bubbles:true}));true", optionsSession);
    await until(() => cdp.evaluate("!document.getElementById('exportFeedback').disabled", optionsSession), 'persisted review enables explicit export');
    try {
      for (const width of [1000, 390]) {
        await cdp.call('Emulation.setDeviceMetricsOverride', { width, height: 1000, deviceScaleFactor: 1, mobile: false }, optionsSession);
        assert.equal(await cdp.evaluate('document.documentElement.scrollWidth <= innerWidth', optionsSession), true, `settings fit ${width}px`);
        const optionsPreview = await cdp.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, optionsSession);
        fs.writeFileSync(path.join(profileRoot, `options-${width}-0.5.0.png`), Buffer.from(optionsPreview.data, 'base64'));
      }
    } catch (_) { /* Screenshots must not hide functional test results. */ }
    await cdp.evaluate("document.getElementById('clearData').click();true", optionsSession);
    await until(() => cdp.evaluate("document.getElementById('feedbackStatus').textContent === 'Saved corrections cleared.'", optionsSession), 'real options confirm correction deletion');
    observations.optionsAndFeedback = 'unusable endpoint rejected; settings saved; synthetic correction reviewed; export enabled; correction deletion confirmed';
    await cdp.call('Target.closeTarget', { targetId: optionsTarget.targetId });
    await cdp.call('Page.navigate', { url: `${origin}/demo/index.html` }, page.sessionId);
    await until(() => cdp.evaluate("!!document.querySelector('a[href=\"dynamic-demo.html\"]')", page.sessionId), 'test lab overview loaded');
    await cdp.call('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1050, deviceScaleFactor: 1, mobile: false }, page.sessionId);
    const labPreview = await cdp.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, page.sessionId);
    fs.writeFileSync(path.join(profileRoot, 'test-lab-overview-0.4.1.png'), Buffer.from(labPreview.data, 'base64'));
    await cdp.call('Page.navigate', { url: `${origin}/suspicious` }, page.sessionId);
    await until(() => cdp.evaluate("!!document.querySelector('[data-phishguard-leave]')", page.sessionId), 'warning leave action available');
    await cdp.evaluate("document.querySelector('[data-phishguard-leave]').click()", page.sessionId);
    await until(() => cdp.evaluate("location.href === 'about:blank'", page.sessionId), 'warning action opens a blank page');
    observations.leavePageAction = 'explicit user click replaced the risky fixture with about:blank';
    await cdp.call('Page.navigate', { url: `${origin}/demo/url-checker.html` }, page.sessionId);
    await until(() => cdp.evaluate("document.getElementById('modelMetrics')?.children.length === 4 && !document.getElementById('checkUrl').disabled", page.sessionId), 'standalone URL checker UI ready');
    const checkerResults = [];
    for (const [address, expectedBand] of [['https://github.com/login', 'low'], ['http://http-password.badssl.com/', 'caution'], ['http://banamxr.com/1/mexico/', 'caution'], ['https://paypal.com.security-check.example.invalid/verify', 'caution']]) {
      await cdp.evaluate(`document.getElementById('urlInput').value=${JSON.stringify(address)};document.getElementById('checkUrl').click()`, page.sessionId);
      const observed = await cdp.evaluate("({score:document.getElementById('urlScore').textContent,band:document.getElementById('urlResult').dataset.band,hidden:document.getElementById('urlResult').hidden,host:document.getElementById('checkedHost').textContent,url:location.href})", page.sessionId);
      assert.equal(observed.hidden, false);
      assert.equal(observed.band, expectedBand, 'Unreleased ML scores cannot produce a primary phishing accusation');
      assert.equal(observed.host, new URL(address).hostname);
      assert.equal(observed.url, `${origin}/demo/url-checker.html`, 'checking does not navigate to the submitted URL');
      if (address === 'http://banamxr.com/1/mexico/') assert.equal(Number(observed.score), 15);
      checkerResults.push({ address, score: Number(observed.score), band: observed.band });
    }
    assert.equal(await cdp.evaluate("document.getElementById('modelMetrics').children.length", page.sessionId), 4);
    for (const width of [1440, 390]) {
      await cdp.call('Emulation.setDeviceMetricsOverride', { width, height: 1050, deviceScaleFactor: 1, mobile: false }, page.sessionId);
      assert.equal(await cdp.evaluate('document.documentElement.scrollWidth <= innerWidth', page.sessionId), true, `URL checker fits ${width}px`);
      const screenshot = await cdp.call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, page.sessionId);
      fs.writeFileSync(path.join(profileRoot, `url-checker-${width}.png`), Buffer.from(screenshot.data, 'base64'));
    }
    await cdp.evaluate("document.getElementById('urlInput').value='javascript:alert(1)';document.getElementById('checkUrl').click()", page.sessionId);
    assert.equal(await cdp.evaluate("document.getElementById('urlResult').hidden && !document.getElementById('openCheckedUrl').hasAttribute('href')", page.sessionId), true, 'invalid input removes stale results and navigation');
    observations.urlChecker = { checks: checkerResults, invalidInputClearsOldResult: true, modelMetricsVisible: true, automaticVisits: false,
      modelVersion: await cdp.evaluate('window.PHISHGUARD_URL_PREVIEW.model_version', page.sessionId),
      modelMetrics: await cdp.evaluate("[...document.querySelectorAll('#modelMetrics dd')].map(node=>node.textContent)", page.sessionId) };
    // Check the same self-contained page under the extension's own CSP.
    const checkerPopup = await cdp.call('Target.createTarget', { url: `chrome-extension://${observations.extensionId}/src/popup/popup.html`, background: true });
    const checkerPopupSession = (await cdp.call('Target.attachToTarget', { targetId: checkerPopup.targetId, flatten: true })).sessionId;
    await until(() => cdp.evaluate("!!document.getElementById('urlCheckerBtn')", checkerPopupSession), 'popup URL-checker action');
    await cdp.evaluate("document.getElementById('urlCheckerBtn').click()", checkerPopupSession);
    const packagedTarget = await until(async () => (await cdp.call('Target.getTargets')).targetInfos.find(item => item.url === `chrome-extension://${observations.extensionId}/demo/url-checker.html`), 'packaged URL checker tab opened from popup');
    const packagedSession = (await cdp.call('Target.attachToTarget', { targetId: packagedTarget.targetId, flatten: true })).sessionId;
    await until(() => cdp.evaluate("document.getElementById('modelMetrics')?.children.length === 4", packagedSession), 'packaged model runs under extension CSP');
    observations.urlChecker.popupEntry = 'packaged checker opened; model metrics loaded under extension CSP';
    const loadedChecks = [];
    for (const [route, expected] of [['ordinary', 'No strong page indicators'], ['suspicious', 'High phishing risk']]) {
      const address = `${origin}/${route}`;
      await cdp.evaluate(`document.getElementById('urlInput').value=${JSON.stringify(address)};document.getElementById('checkUrl').click();document.getElementById('openCheckedUrl').click()`, packagedSession);
      await until(() => cdp.evaluate(`document.getElementById('pageCheckTitle').textContent.startsWith(${JSON.stringify(expected)})`, packagedSession), `loaded-page URL inspection ${route}`, 18000);
      loadedChecks.push(await cdp.evaluate("({title:document.getElementById('pageCheckTitle').textContent,details:document.getElementById('pageCheckDetails').textContent,reasons:document.getElementById('pageCheckReasons').textContent})", packagedSession));
    }
    observations.urlChecker.loadedPageChecks = loadedChecks;
    await cdp.call('Target.closeTarget', { targetId: packagedTarget.targetId });
    await cdp.call('Target.closeTarget', { targetId: checkerPopup.targetId });
    if (process.argv.includes('--public-demos') || process.env.PHISHGUARD_CLASSROOM_URL) {
      // Only operator-owned benign test pages. Never submit fields, bypass an
      // interstitial or turn a requested risk band into a hard-coded verdict.
      const checks = [];
      const publicUrls = process.argv.includes('--public-demos') ? ['https://github.com/login', 'https://example.com/', 'http://http-password.badssl.com/', 'https://mixed-form.badssl.com/', 'https://www.amtso.org/check-desktop-phishing-page/', 'https://testsafebrowsing.appspot.com/s/phishing.html'] : [];
      if (process.env.PHISHGUARD_CLASSROOM_URL) {
        const classroom = new URL(process.env.PHISHGUARD_CLASSROOM_URL);
        assert.equal(classroom.protocol, 'https:');
        assert(classroom.hostname.endsWith('.chatgpt.site'), 'Classroom rehearsal uses the published educational Site');
        for (const name of ['legitimate-demo.html', 'caution-demo.html', 'phishing-demo.html', 'url-checker.html']) publicUrls.push(new URL(name, classroom.origin + '/').href);
      }
      for (const url of publicUrls) {
        const old = await read();
        const entry = { requestedUrl: url, checkedAt: new Date().toISOString() };
        try {
          const navigation = await cdp.call('Page.navigate', { url }, page.sessionId);
          if (navigation.errorText) entry.navigationError = navigation.errorText;
          const observed = await until(async () => {
            const value = await read();
            return value && value.identity.documentToken !== old?.identity.documentToken && value;
          }, 'public page inspection', 10000).catch(() => null);
          Object.assign(entry, await cdp.evaluate('({effectiveUrl:location.href,title:document.title})', page.sessionId));
          if (url.endsWith('/url-checker.html')) {
            await until(() => cdp.evaluate("document.getElementById('modelMetrics')?.children.length === 4 && !document.getElementById('checkUrl').disabled", page.sessionId), 'published URL checker UI ready');
            await cdp.evaluate("document.getElementById('urlInput').value='https://github.com/login';document.getElementById('checkUrl').click()", page.sessionId);
            entry.urlChecker = await cdp.evaluate("({host:document.getElementById('checkedHost').textContent,score:document.getElementById('urlScore').textContent,band:document.getElementById('urlResult').dataset.band,hidden:document.getElementById('urlResult').hidden,metrics:document.getElementById('modelMetrics').children.length,modelVersion:window.PHISHGUARD_URL_PREVIEW?.model_version,modelMetrics:[...document.querySelectorAll('#modelMetrics dd')].map(node=>node.textContent)})", page.sessionId);
            assert.equal(entry.urlChecker.host, 'github.com');
            assert.equal(entry.urlChecker.score, '0');
            assert.equal(entry.urlChecker.band, 'low');
            assert.equal(entry.urlChecker.hidden, false);
            assert.equal(entry.urlChecker.metrics, 4);
            assert.equal(entry.urlChecker.modelVersion, observations.urlChecker.modelVersion, 'Published model version matches the checked local artifact');
            assert.deepEqual(entry.urlChecker.modelMetrics, observations.urlChecker.modelMetrics, 'Published metrics match the actual local model');
            await cdp.evaluate("document.getElementById('urlInput').value='http://banamxr.com/1/mexico/';document.getElementById('checkUrl').click()", page.sessionId);
            entry.httpScoreRegression = await cdp.evaluate("({score:document.getElementById('urlScore').textContent,breakdown:document.getElementById('scoreBreakdown').textContent,band:document.getElementById('urlResult').dataset.band})", page.sessionId);
            assert.equal(entry.httpScoreRegression.score, '15');
            assert.equal(entry.httpScoreRegression.band, 'caution');
            assert.match(entry.httpScoreRegression.breakdown, /HTTP transport: \+15/);
          }
          if (observed) {
            entry.phishguard = { score: observed.score, outcome: observed.outcome, reasons: observed.reasons, inspectedFrames: observed.inspectedFrames,
              securityTest: observed.securityTest || null, warningVisible: await cdp.evaluate("!!document.querySelector('[data-phishguard-title]')", page.sessionId) };
          } else entry.phishguard = null;
        } catch (error) {
          entry.error = String(error);
          if (url.endsWith('/url-checker.html')) { checks.push(entry); observations.publicDemos = checks; throw error; }
        }
        checks.push(entry);
      }
      const publicReport = { browser: observations.browser, scope: 'Harmless public security fixtures or owner-hosted educational scenarios; no credentials entered or forms submitted; no browser warning bypass. Hosted scenarios remain controlled tests, not an independent accuracy benchmark.', checks };
      fs.writeFileSync(path.join(workspace, process.env.PHISHGUARD_CLASSROOM_URL ? 'docs/audit/classroom-web-results-2026-11-03.json' : 'docs/audit/public-demo-results.json'), JSON.stringify(publicReport, null, 2) + '\n');
      observations.publicDemos = checks;
    }
    const report = { passed: true, ...observations };
    fs.writeFileSync(path.join(workspace, 'docs/audit/browser-smoke-results.json'), JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report, null, 2));
  } catch (error) {
    const report = { passed: false, ...observations, error: String(error), browserOutput: stderr };
    fs.writeFileSync(path.join(workspace, 'docs/audit/browser-smoke-results.json'), JSON.stringify(report, null, 2) + '\n');
    console.error(JSON.stringify(report, null, 2));
    process.exitCode = 1;
  } finally {
    if (cdp) { try { await cdp.call('Browser.close'); } catch (_) {} cdp.close(); }
    if (child && child.exitCode === null) { await delay(1000); if (child.exitCode === null) child.kill(); }
    await new Promise((resolve) => server.close(resolve));
    // Keep the isolated profile for review; it never touches an existing user profile.
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
