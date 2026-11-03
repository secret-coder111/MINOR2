(function (global) {
  'use strict';
  const data = global.PHISH_GUARD_PSL || (typeof require === 'function'
    ? require('./public-suffix-rules.json') : null);
  if (!data || !Array.isArray(data.rules)) throw new Error('Offline public suffix data is missing');
  const exact = new Set();
  const wildcard = new Set();
  const exceptions = new Set();
  data.rules.forEach((rule) => {
    if (rule.startsWith('!')) exceptions.add(rule.slice(1));
    else if (rule.startsWith('*.')) wildcard.add(rule.slice(2));
    else exact.add(rule);
  });

  function normalizeHostname(value) {
    const text = String(value || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!text || /[\s/@?#]/.test(text)) return '';
    try {
      const host = new URL(`http://${text.includes(':') && !text.startsWith('[') ? `[${text}]` : text}/`).hostname;
      return host.toLowerCase().replace(/\.$/, '');
    } catch (_) { return ''; }
  }
  function isIpAddress(value) {
    const host = normalizeHostname(value);
    return /^\[[0-9a-f:]+\]$/i.test(host)
      || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
  }
  function isLoopback(value) {
    const host = normalizeHostname(value);
    return host === 'localhost' || host.endsWith('.localhost') || host === '[::1]'
      || /^127\./.test(host);
  }
  function getRegistrableDomain(value) {
    const host = normalizeHostname(value);
    if (!host) return '';
    if (isIpAddress(host)) return host;
    if (!host.includes('.')) return exact.has(host) ? '' : host;
    const labels = host.split('.');
    let suffixLength = 1; // PSL prevailing '*' rule, also for reserved test domains.
    for (let i = 0; i < labels.length; i += 1) {
      const candidate = labels.slice(i).join('.');
      if (exceptions.has(candidate)) {
        suffixLength = labels.length - i - 1;
        break;
      }
      if (exact.has(candidate)) suffixLength = Math.max(suffixLength, labels.length - i);
      if (i > 0 && wildcard.has(candidate)) suffixLength = Math.max(suffixLength, labels.length - i + 1);
    }
    return labels.length > suffixLength ? labels.slice(-suffixLength - 1).join('.') : '';
  }
  function sameSite(first, second) {
    const a = normalizeHostname(first);
    const b = normalizeHostname(second);
    if (!a || !b) return false;
    if (a === b) return true;
    const siteA = getRegistrableDomain(a);
    const siteB = getRegistrableDomain(b);
    return Boolean(siteA && siteB && siteA === siteB);
  }
  const api = { normalizeHostname, getRegistrableDomain, sameSite, isIpAddress,
    isLoopback, pslVersion: data.version, pslHash: data.rules_sha256 };
  global.PhishGuard = global.PhishGuard || {};
  global.PhishGuard.domainUtils = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : self);
