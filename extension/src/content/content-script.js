window.PhishGuard = window.PhishGuard || {};

(function () {
  function buildFeatureObject() {
    const urlFeatures = window.PhishGuard.extractUrlFeatures();
    const formFeatures = window.PhishGuard.extractFormFeatures();
    const domFeatures = window.PhishGuard.extractDomFeatures();

    return {
      url: window.location.href,
      ...urlFeatures,
      ...formFeatures,
      ...domFeatures,
      brand_name_in_url: /google|microsoft|apple|paypal|amazon|bank|icici|hdfc|sbi|axis/i.test(window.location.href) ? 1 : 0,
      brand_name_in_title: domFeatures.brand_name_in_title,
      brand_name_in_visible_text: domFeatures.brand_name_in_visible_text,
      has_unusual_port: urlFeatures.has_unusual_port,
      domain_registration_age_days: 0,
      model_version: window.PHISH_GUARD_MODEL_VERSION || 'unknown'
    };
  }

  function removeWarningBanner() {
    const existing = document.getElementById('phishguard-warning-banner');
    if (existing) existing.remove();
  }

  function sendForAnalysis() {
    const features = buildFeatureObject();
    window.PhishGuard.browser.runtime.sendMessage({
      type: 'ANALYZE_PAGE',
      payload: features
    });
  }

  let scanTimer = null;
  function scheduleAnalysis(delay = 750) {
    if (scanTimer) window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(() => {
      scanTimer = null;
      sendForAnalysis();
    }, delay);
  }

  function handleResult(message) {
    if (!message || message.type !== 'ANALYZE_RESULT') {
      return;
    }

    if (message.payload && message.payload.warning) {
      const banner = document.createElement('div');
      banner.style.position = 'fixed';
      banner.style.top = '0';
      banner.style.left = '0';
      banner.style.right = '0';
      banner.style.background = '#d93025';
      banner.style.color = '#fff';
      banner.style.zIndex = '2147483647';
      banner.style.padding = '12px 16px';
      banner.style.fontFamily = 'sans-serif';
      banner.style.fontSize = '14px';
      banner.style.lineHeight = '1.5';
      banner.style.boxShadow = '0 4px 12px rgba(0,0,0,0.2)';
      banner.style.borderBottom = '1px solid rgba(255,255,255,0.2)';
      banner.innerHTML = '<strong>PhishGuard warning:</strong> ' + window.PhishGuard.safeText(message.payload.label) + ' — risk ' + message.payload.score + '/100. Continue only if you trust this page.';

      const existing = document.getElementById('phishguard-warning-banner');
      if (existing) existing.remove();
      banner.id = 'phishguard-warning-banner';
      document.body.prepend(banner);
    } else {
      removeWarningBanner();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      sendForAnalysis();
      scheduleAnalysis(1500);
    });
  } else {
    sendForAnalysis();
    scheduleAnalysis(1500);
  }

  if (window.MutationObserver && document.documentElement) {
    const observer = new MutationObserver((mutations) => {
      const significantChange = mutations.some((mutation) => (
        mutation.type === 'childList'
        && Array.from(mutation.addedNodes).some((node) => (
          node.nodeType === Node.ELEMENT_NODE
          && (
            (node.matches && node.matches('form, input, iframe, script'))
            || (node.querySelector && node.querySelector('form, input, iframe, script'))
          )
        ))
      ));
      if (significantChange) scheduleAnalysis();
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  ['pushState', 'replaceState'].forEach((method) => {
    const original = window.history[method];
    if (typeof original !== 'function') return;
    window.history[method] = function (...args) {
      const result = original.apply(this, args);
      scheduleAnalysis(250);
      return result;
    };
  });
  window.addEventListener('popstate', () => scheduleAnalysis(250));
  window.addEventListener('hashchange', () => scheduleAnalysis(250));
  document.addEventListener('focusin', (event) => {
    if (event.target && event.target.matches && event.target.matches('input, textarea')) {
      scheduleAnalysis(250);
    }
  });

  window.PhishGuard.browser.runtime.onMessage.addListener((message) => {
    handleResult(message);
  });
})();
