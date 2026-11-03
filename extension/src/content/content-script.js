window.PhishGuard = window.PhishGuard || {};

(function () {
  const api = window.PhishGuard.browser;
  const documentToken = window.crypto && window.crypto.randomUUID
    ? window.crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const isTop = window.top === window;
  let scanId = 0;
  let scanTimer = null;
  let firstScheduledAt = 0;
  let stopped = false;
  let warningBanner = null;
  let warningMessage = null;
  let dismissedWarning = null;
  let latestWarningKey = null;
  let warningParts = null;
  const warningElements = [];
  const warningTexts = [];
  let observer = null;
  let rootPoll = null;
  let observedRoots = [];
  let watchedControls = [];
  let renderingFingerprint = '';
  let visibilityWatchTruncated = false;
  const warningNodes = new WeakSet();
  const resetStyle = 'all:initial!important;box-sizing:border-box!important;visibility:visible!important;opacity:1!important;';
  const warningStyle = resetStyle + 'display:block!important;position:fixed!important;top:16px!important;left:auto!important;right:16px!important;bottom:auto!important;width:calc(100vw - 32px)!important;max-width:640px!important;background:#fff!important;color:#253d53!important;z-index:2147483647!important;padding:20px!important;margin:0!important;border:1px solid #edcbd1!important;border-top:4px solid #b32e42!important;border-radius:16px!important;font:14px/1.5 system-ui,sans-serif!important;box-shadow:0 12px 48px #172d4533!important;transform:none!important;filter:none!important;clip-path:none!important;max-height:min(78vh,560px)!important;overflow:auto!important;animation:none!important;transition:none!important;';

  function warningElement(tag, parent, style, attributes = {}) {
    const node = document.createElement(tag);
    const record = { node, style: resetStyle + style, attributes, children: [] };
    warningElements.push(record);
    warningNodes.add(node);
    if (parent) parent.children.push(node);
    return record;
  }

  function warningText(parent, value) {
    const node = document.createTextNode(value);
    const record = { node, value };
    parent.children.push(node);
    warningTexts.push(record);
    warningNodes.add(node);
    return record;
  }

  function createWarningContent(id) {
    const root = { node: warningBanner, style: warningStyle, attributes: { id, role: 'alert', 'aria-label': 'PhishGuard phishing warning' }, children: [] };
    warningElements.push(root);
    const wrap = warningElement('div', root, 'display:block!important;max-width:1100px!important;margin:0 auto!important;');
    const header = warningElement('div', wrap, 'display:flex!important;align-items:center!important;justify-content:space-between!important;gap:10px!important;flex-wrap:wrap!important;padding-right:72px!important;min-height:44px!important;');
    const title = warningElement('strong', header, 'display:block!important;color:#a5263c!important;font:750 18px/1.35 system-ui,sans-serif!important;', { 'data-phishguard-title': '' });
    const titleText = warningText(title, 'PhishGuard: High phishing risk');
    const badge = warningElement('span', header, 'display:inline-block!important;color:#a5263c!important;background:#fff0f2!important;border:1px solid #edcbd1!important;border-radius:7px!important;padding:4px 8px!important;font:650 11px/1.4 system-ui,sans-serif!important;');
    const badgeText = warningText(badge, 'High risk');
    const close = warningElement('button', header, 'display:inline-block!important;position:absolute!important;top:12px!important;right:12px!important;border:1px solid #d7e0e8!important;border-radius:8px!important;background:#f5f8fa!important;color:#253d53!important;padding:8px 12px!important;cursor:pointer!important;min-height:44px!important;font:650 12px/1.3 system-ui,sans-serif!important;',
      { type: 'button', 'data-phishguard-close': '', 'aria-label': 'Close phishing warning' });
    warningText(close, 'Close \u00d7');
    close.node.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      // A hostile page must not dismiss protection using element.click().
      if (!event.isTrusted) return;
      dismissedWarning = latestWarningKey;
      removeWarningBanner();
    });
    const message = warningElement('p', wrap, 'display:block!important;color:#253d53!important;margin:10px 0!important;font:500 14px/1.5 system-ui,sans-serif!important;');
    const messageText = warningText(message, 'Potential phishing detected. Pause before entering passwords, payment details or security codes.');
    const site = warningElement('p', wrap, 'display:block!important;color:#596b7c!important;margin:8px 0!important;overflow-wrap:anywhere!important;font:12px/1.5 system-ui,sans-serif!important;', { 'data-phishguard-site': '' });
    let siteOrigin = '';
    try { siteOrigin = new URL(window.location.href).origin; } catch (_) {}
    warningText(site, 'Current website: ' + siteOrigin);
    const primary = warningElement('p', wrap, 'display:block!important;color:#6e2938!important;background:#fff3f5!important;border-left:3px solid #b32e42!important;border-radius:5px!important;padding:10px 12px!important;margin:12px 0!important;overflow-wrap:anywhere!important;font:500 13px/1.5 system-ui,sans-serif!important;', { 'data-phishguard-primary-reason': '' });
    const primaryText = warningText(primary, '');
    const affected = warningElement('p', wrap, 'display:none!important;', { 'data-phishguard-frame': '' });
    const frameText = warningText(affected, '');
    const bottom = warningElement('div', wrap, 'display:flex!important;flex-direction:column!important;align-items:stretch!important;gap:14px!important;margin-top:12px!important;');
    const details = warningElement('details', bottom, 'display:block!important;order:1!important;min-width:0!important;color:#253d53!important;font:14px/1.5 system-ui,sans-serif!important;', { 'data-phishguard-details': '' });
    const summary = warningElement('summary', details, 'display:list-item!important;list-style:disclosure-closed inside!important;color:#253d53!important;cursor:pointer!important;font:650 13px/1.5 system-ui,sans-serif!important;');
    warningText(summary, 'Review all indicators');
    const list = warningElement('ul', details, 'display:block!important;margin:8px 0 0!important;padding-left:20px!important;list-style:disc!important;');
    const reasons = Array.from({ length: 3 }, () => {
      const item = warningElement('li', list, 'display:none!important;');
      return { item, text: warningText(item, '') };
    });
    const actions = warningElement('div', bottom, 'display:flex!important;order:0!important;align-items:center!important;gap:12px!important;flex-wrap:wrap!important;');
    const leave = warningElement('button', actions, 'display:inline-block!important;border:1px solid #b32e42!important;border-radius:9px!important;background:#b32e42!important;color:#fff!important;padding:11px 18px!important;cursor:pointer!important;min-height:44px!important;font:750 13px/1.4 system-ui,sans-serif!important;', { type: 'button', 'data-phishguard-leave': '' });
    warningText(leave, 'Leave this page');
    leave.node.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (warningMessage) window.location.replace('about:blank');
    });
    for (const record of [leave, close, summary]) {
      record.node.addEventListener('focus', repairWarningBanner);
      record.node.addEventListener('blur', repairWarningBanner);
    }
    const guidance = warningElement('span', actions, 'display:block!important;color:#596b7c!important;flex:1 1 180px!important;font:12px/1.5 system-ui,sans-serif!important;');
    warningText(guidance, 'Open the service using a saved bookmark or an address you know.');
    bottom.children = [actions.node, details.node];
    const note = warningElement('p', details, 'display:block!important;color:#596b7c!important;margin:10px 0 0!important;font:12px/1.5 system-ui,sans-serif!important;');
    warningText(note, 'The risk index is not a probability. Review the independent result in PhishGuard’s toolbar popup.');
    return { titleText, badgeText, messageText, affected, frameText, primaryText, reasons, leave, details };
  }

  function buildFeatureObject() {
    const urlFeatures = window.PhishGuard.extractUrlFeatures();
    const formFeatures = window.PhishGuard.extractFormFeatures();
    const domFeatures = window.PhishGuard.extractDomFeatures(formFeatures);
    return { url: window.location.href, ...urlFeatures, ...formFeatures, ...domFeatures,
      runtime_coverage: { visibility_watch_truncated: visibilityWatchTruncated } };
  }

  function removeWarningBanner() {
    warningMessage = null;
    if (warningBanner) warningBanner.remove();
  }

  function repairWarningBanner() {
    if (!warningMessage || !warningBanner || stopped) return;
    // These repairs cover ordinary page interference. The popup remains the
    // independent warning surface because the page owns its document and CSS.
    // Rebuild only altered structure. Keeping nodes stable preserves keyboard
    // focus, native details state and event handlers during ordinary rescans.
    for (const record of warningElements) {
      const focused = document.activeElement === record.node ? 'outline:3px solid #5eead4!important;outline-offset:3px!important;' : '';
      const style = record.style + focused;
      if (record.node.getAttribute('style') !== style) record.node.setAttribute('style', style);
      for (const name of ['hidden', 'inert', 'aria-hidden', 'disabled']) if (record.node.hasAttribute(name)) record.node.removeAttribute(name);
      for (const [name, value] of Object.entries(record.attributes)) if (record.node.getAttribute(name) !== value) record.node.setAttribute(name, value);
      const children = record.node.childNodes;
      if (children.length !== record.children.length || record.children.some((child, index) => children[index] !== child)) record.node.replaceChildren(...record.children);
    }
    for (const record of warningTexts) if (record.node.data !== record.value) record.node.data = record.value;
    if (!warningBanner.isConnected && document.documentElement) document.documentElement.appendChild(warningBanner);
  }

  function handleResult(message) {
    if (!isTop || !message || message.type !== 'ANALYZE_RESULT' || !message.payload) return;
    const result = message.payload;
    const identity = result.identity;
    if (!identity || identity.documentToken !== documentToken || identity.scanId !== scanId || identity.url !== window.location.href) return;
    if (result.outcome !== 'HIGH_RISK' && !result.securityTest) {
      // A cold worker must recover the child verdict before clearing its warning.
      if (!(result.coverage && result.coverage.recovering)) {
        dismissedWarning = null;
        removeWarningBanner();
      }
      return;
    }
    latestWarningKey = JSON.stringify([window.location.href, result.outcome, result.securityTest?.id || '', result.reasons || []]);
    if (dismissedWarning === latestWarningKey) return;
    if (!document.documentElement) return;
    if (!warningBanner) {
      warningBanner = document.createElement('div');
      let id = 'phishguard-warning-banner';
      // Page-owned IDs must not let a page hide its form mutations or be overwritten.
      if (document.getElementById(id)) id += `-${documentToken}`;
      warningBanner.id = id;
      warningNodes.add(warningBanner);
      warningParts = createWarningContent(id);
    }
    const testOnly = result.securityTest && result.outcome !== 'HIGH_RISK';
    warningMessage = testOnly ? 'PhishGuard: Security test recognised' : 'PhishGuard: High phishing risk';
    warningParts.titleText.value = warningMessage;
    warningParts.messageText.value = testOnly
      ? 'AMTSO provides this harmless page to check phishing protection. PhishGuard recognised its known test address. No credentials are needed.'
      : 'Potential phishing detected. Pause before entering passwords, payment details or security codes.';
    const score = Number(result.score);
    warningParts.badgeText.value = testOnly ? 'Official test entry' : Number.isFinite(score) ? `${Math.round(Math.max(0, Math.min(100, score)))}/100 risk index` : 'High risk';
    const embedded = result.evidenceFrame && result.evidenceFrame.frameId !== 0;
    let origin = '';
    try {
      const url = new URL(result.evidenceFrame && result.evidenceFrame.origin);
      if (['http:', 'https:'].includes(url.protocol)) origin = url.origin;
    } catch (_) {}
    warningParts.affected.style = resetStyle + (embedded ? 'display:block!important;color:#a5263c!important;margin:8px 0!important;overflow-wrap:anywhere!important;font:12px/1.5 system-ui,sans-serif!important;' : 'display:none!important;');
    warningParts.frameText.value = embedded ? `An embedded page is affected${origin ? ': ' + origin : '.'}` : '';
    const reasons = testOnly ? [result.securityTest.explanation, 'The local rule score is unchanged. This feature check does not measure real-world phishing accuracy.']
      : Array.isArray(result.reasons) ? result.reasons.filter((reason) => typeof reason === 'string' && reason.trim()).slice(0, 3) : [];
    if (!reasons.length) reasons.push('Several risk indicators were found. Open PhishGuard in your toolbar to review the full report.');
    warningParts.primaryText.value = reasons[0].slice(0, 240);
    warningParts.reasons.forEach((reason, index) => {
      reason.item.style = resetStyle + (reasons[index] ? 'display:list-item!important;color:#253d53!important;margin:6px 0!important;overflow-wrap:anywhere!important;font:13px/1.5 system-ui,sans-serif!important;' : 'display:none!important;');
      reason.text.value = (reasons[index] || '').slice(0, 240);
    });
    repairWarningBanner();
  }

  function sendForAnalysis() {
    if (stopped) return;
    refreshObservedRoots();
    refreshRenderingWatch();
    scanId += 1;
    const context = window.PhishGuard.getPageContext && window.PhishGuard.getPageContext();
    if (context && !context.supported) return;
    const message = { type: 'ANALYZE_PAGE', identity: { documentToken, scanId, url: window.location.href,
      ...(context && context.inherited ? { contextUrl: context.url } : {}) }, payload: buildFeatureObject() };
    try {
      const pending = api.runtime.sendMessage(message);
      if (pending && pending.then) pending.then(handleResult).catch(() => {});
    } catch (_) { /* Reloading the extension invalidates existing script contexts. */ }
  }

  function scheduleAnalysis(delay = 600) {
    if (stopped) return;
    const now = Date.now();
    if (!firstScheduledAt) firstScheduledAt = now;
    if (scanTimer) window.clearTimeout(scanTimer);
    // A busy SPA must not postpone a scan forever.
    const wait = Math.max(0, Math.min(delay, 2000 - (now - firstScheduledAt)));
    scanTimer = window.setTimeout(() => {
      scanTimer = null;
      firstScheduledAt = 0;
      sendForAnalysis();
    }, wait);
  }

  function extensionNode(node) {
    return !!(node && warningNodes.has(node));
  }

  const observation = {
    childList: true, subtree: true, characterData: true, attributes: true,
    attributeFilter: ['action', 'formaction', 'formmethod', 'form', 'method', 'type', 'name', 'id', 'src', 'href', 'content', 'http-equiv', 'hidden', 'inert', 'disabled', 'readonly', 'aria-disabled', 'aria-readonly', 'style', 'width', 'height', 'class', 'autocomplete', 'aria-label', 'aria-labelledby', 'aria-hidden', 'aria-level', 'placeholder', 'role', 'open', 'slot', 'contenteditable']
  };

  function controlVisibility(element) {
    if (!element.isConnected) return 'detached';
    if (window.PhishGuard.isRenderedControl) return window.PhishGuard.isRenderedControl(element) ? 'visible' : 'hidden';
    // The real extractor supplies the composed-tree helper. This fallback is
    // useful during startup or in a restricted DOM and never reads field values.
    const style = window.getComputedStyle(element);
    return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' ? 'hidden' : 'visible';
  }

  function renderingState() {
    return watchedControls.map(controlVisibility).join(',');
  }

  function refreshRenderingWatch() {
    const roots = observedRoots.length ? observedRoots : [document];
    const controls = roots.flatMap((root) => Array.from(root.querySelectorAll(window.PhishGuard.CREDENTIAL_CONTROL_SELECTOR || 'input, textarea, [role="textbox"]')));
    // Bound periodic layout work; full extraction still sees all controls, and
    // the popup discloses a truncated periodic watch instead of claiming coverage.
    visibilityWatchTruncated = controls.length > 512;
    watchedControls = controls.slice(0, 512);
    renderingFingerprint = renderingState();
  }

  function refreshObservedRoots() {
    if (!observer || stopped || !document || !document.documentElement) return false;
    const roots = window.PhishGuard.getDetectionRoots ? window.PhishGuard.getDetectionRoots() : [document];
    if (roots.length === observedRoots.length && roots.every((root, index) => root === observedRoots[index])) return false;
    // Rebuilding also releases detached shadow trees from long-lived SPA tabs.
    observer.disconnect();
    observedRoots = roots;
    for (const root of roots) observer.observe(root, observation);
    return true;
  }

  function startRootDiscovery() {
    if (rootPoll !== null) return;
    // Attaching an open shadow root to an existing host emits no DOM mutation.
    // Discover those roots while visible; the individual roots then use normal
    // mutation observation rather than repeatedly analyzing unchanged pages.
    rootPoll = window.setInterval(() => {
      if (document.visibilityState === 'hidden') return;
      const rootsChanged = refreshObservedRoots();
      const rendering = renderingState();
      if (rootsChanged || rendering !== renderingFingerprint) {
        renderingFingerprint = rendering;
        scheduleAnalysis(0);
      }
    }, 3000);
  }

  if (window.MutationObserver) {
    observer = new MutationObserver((mutations) => {
      repairWarningBanner();
      const changed = mutations.some((mutation) => {
        if (mutation.type === 'childList') {
          const nodes = [...mutation.addedNodes, ...mutation.removedNodes];
          // Text-only warning interference was repaired above. A page-owned
          // element moved into the warning can contain controls, so still scan.
          if (extensionNode(mutation.target)) return nodes.some((node) => node.nodeType === 1 && !extensionNode(node));
          return nodes.some((node) => !extensionNode(node));
        }
        if (extensionNode(mutation.target)) return false;
        return mutation.type === 'attributes' || mutation.type === 'characterData';
      });
      // Discover roots in the debounced scan, rather than walking an entire
      // large page on every animation/style mutation.
      if (changed) scheduleAnalysis();
    });
    refreshObservedRoots();
    startRootDiscovery();
  }
  window.addEventListener('pagehide', () => {
    stopped = true;
    if (observer) observer.disconnect();
    observedRoots = [];
    watchedControls = [];
    if (scanTimer) window.clearTimeout(scanTimer);
    scanTimer = null;
    firstScheduledAt = 0;
    if (rootPoll !== null) window.clearInterval(rootPoll);
    rootPoll = null;
  });
  window.addEventListener('pageshow', (event) => {
    if (!event.persisted) return;
    stopped = false;
    refreshObservedRoots();
    startRootDiscovery();
    sendForAnalysis();
    repairWarningBanner();
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'hidden') scheduleAnalysis(0);
  });

  // Inspect before normal credential interaction and native submission. This
  // reduces idle/debounce blind windows; it does not claim to block arbitrary JS.
  let lastInteractionScan = 0;
  const interaction = (event) => {
    const target = event.composedPath ? event.composedPath()[0] : event.target;
    if (extensionNode(target)) return;
    if (!target || !target.matches || !target.matches('input, textarea, [role="textbox"], button, form')) return;
    if (event.type !== 'submit' && Date.now() - lastInteractionScan < 200) return;
    lastInteractionScan = Date.now();
    if (scanTimer) window.clearTimeout(scanTimer);
    scanTimer = null;
    firstScheduledAt = 0;
    sendForAnalysis();
  };
  for (const name of ['focusin', 'pointerdown', 'submit']) document.addEventListener(name, interaction, true);
  document.addEventListener('load', (event) => {
    if (event.target && event.target.matches && event.target.matches('link[rel="stylesheet"], iframe')) scheduleAnalysis(0);
  }, true);
  window.addEventListener('resize', () => scheduleAnalysis(100));
  document.addEventListener('toggle', (event) => { if (!extensionNode(event.target)) scheduleAnalysis(0); }, true);

  // Main-world pushState/replaceState is observed by the worker's webNavigation listener.
  window.addEventListener('popstate', () => scheduleAnalysis(100));
  window.addEventListener('hashchange', () => scheduleAnalysis(100));
  api.runtime.onMessage.addListener((message) => {
    if (message && message.type === 'REQUEST_RESCAN') {
      if (message.reason === 'user') dismissedWarning = null;
      scheduleAnalysis(50);
    }
    else handleResult(message);
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', sendForAnalysis, { once: true });
  else sendForAnalysis();
})();
