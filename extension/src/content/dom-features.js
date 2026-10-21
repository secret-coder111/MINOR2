window.PhishGuard = window.PhishGuard || {};

window.PhishGuard.extractDomFeatures = function () {
  const scriptBlocks = Array.from(document.querySelectorAll('script'));
  const iframeNodes = Array.from(document.querySelectorAll('iframe'));
  const externalScripts = Array.from(document.querySelectorAll('script[src]'));
  const metaRefresh = Array.from(document.querySelectorAll('meta[http-equiv="refresh"], meta[http-equiv="Refresh"]'));

  const scriptsText = scriptBlocks.map((script) => script.textContent || '').join(' ');
  const obfuscationPatterns = [
    /eval\s*\(/gi,
    /atob\s*\(/gi,
    /fromCharCode\s*\(/gi,
    /document\.write\s*\(/gi,
    /Function\s*\(/gi
  ];

  let obfuscatedScore = 0;
  obfuscationPatterns.forEach((pattern) => {
    if (pattern.test(scriptsText)) {
      obfuscatedScore += 0.25;
    }
  });

  const longEncoded = (scriptsText.match(/[A-Za-z0-9+/=]{200,}/g) || []).length;
  obfuscatedScore += Math.min(longEncoded * 0.1, 0.8);

  const hiddenIframes = iframeNodes.filter((frame) => {
    const style = (frame.getAttribute('style') || '').toLowerCase();
    const width = Number(frame.getAttribute('width') || 0);
    const height = Number(frame.getAttribute('height') || 0);
    return frame.hasAttribute('hidden')
      || style.replace(/\s/g, '').includes('display:none')
      || style.replace(/\s/g, '').includes('visibility:hidden')
      || width === 0
      || height === 0;
  }).length;

  const externalScriptCount = externalScripts.filter((script) => {
    const src = script.getAttribute('src') || '';
    if (!src) return false;
    try {
      const url = new URL(src, window.location.href);
      return url.hostname !== window.location.hostname;
    } catch (error) {
      return false;
    }
  }).length;

  const visibleText = (() => {
    if (!document.body) return '';
    if (typeof document.body.innerText === 'string' && document.body.innerText) {
      return document.body.innerText;
    }
    const clone = document.body.cloneNode(true);
    clone.querySelectorAll('script, style, noscript, template, [hidden]').forEach((node) => node.remove());
    clone.querySelectorAll('[style]').forEach((node) => {
      const style = (node.getAttribute('style') || '').toLowerCase().replace(/\s/g, '');
      if (style.includes('display:none') || style.includes('visibility:hidden')) node.remove();
    });
    return clone.textContent || '';
  })().toLowerCase();

  const titleText = (document.title || '').toLowerCase();
  const brandNameInVisibleText = /google|microsoft|apple|paypal|amazon|bank|icici|hdfc|sbi|axis/i.test(visibleText) ? 1 : 0;
  const brandNameInTitle = /google|microsoft|apple|paypal|amazon|bank|icici|hdfc|sbi|axis/i.test(titleText) ? 1 : 0;
  const path = window.location.pathname || '';
  const isFrontPage = path === '' || path === '/' || /^\/(home|index|welcome)(\.[a-z0-9]+)?$/i.test(path);
  const hasCredentialForm = document.querySelector(
    'input[type="password"], input[name*="password" i], input[name*="otp" i], input[name*="card" i], input[name*="cvv" i]'
  ) !== null;
  const frontpageSignals = [
    hasCredentialForm,
    hiddenIframes > 0,
    metaRefresh.length > 0,
    obfuscatedScore >= 0.5,
    brandNameInTitle === 1 && hasCredentialForm,
    brandNameInVisibleText === 1 && hasCredentialForm && visibleText.length < 600
  ].filter(Boolean).length;

  return {
    obfuscated_script_score: Number(Math.min(obfuscatedScore, 1).toFixed(2)),
    hidden_iframe_count: hiddenIframes,
    external_script_count: externalScriptCount,
    meta_refresh_count: metaRefresh.length,
    brand_name_in_title: brandNameInTitle,
    brand_name_in_visible_text: brandNameInVisibleText,
    frontpage_is_landing_page: isFrontPage ? 1 : 0,
    frontpage_has_credential_form: hasCredentialForm ? 1 : 0,
    frontpage_suspicious_signal_count: isFrontPage ? frontpageSignals : 0
  };
};
