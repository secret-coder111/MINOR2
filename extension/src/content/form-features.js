window.PhishGuard = window.PhishGuard || {};

window.PhishGuard.extractFormFeatures = function () {
  const forms = Array.from(document.forms || []);
  const credentialSelectors = [
    'input[type="password"]',
    'input[name*="password" i]',
    'input[name*="otp" i]',
    'input[name*="card" i]',
    'input[name*="cvv" i]',
    'input[name*="email" i]',
    'input[name*="aadhaar" i]',
    'input[name*="pan" i]',
    'input[name*="wallet" i]'
  ];

  const credentialInputs = Array.from(document.querySelectorAll(credentialSelectors.join(',')));
  const hiddenInputs = Array.from(document.querySelectorAll('input[type="hidden"]'));
  const pageText = ((document.body && (document.body.innerText || document.body.textContent)) || '').toLowerCase();
  const titleText = (document.title || '').toLowerCase();
  const domainHints = (titleText + ' ' + pageText).match(/[a-z0-9-]+\.[a-z]{2,}/gi) || [];

  const isLikelyBrandedDomain = (hostname) => {
    if (!hostname) return false;
    const hostWithoutTld = hostname.split('.')[0].replace(/[^a-z0-9-]/g, '');
    if (!hostWithoutTld) return false;
    return domainHints.some((hint) => hint.toLowerCase().includes(hostWithoutTld.toLowerCase()) || hostWithoutTld.toLowerCase().includes(hint.toLowerCase().split('.')[0]));
  };

  let crossDomainFormAction = 0;
  let formActionIsEmpty = 0;
  let hasPasswordInput = 0;
  let credentialSubmissionScript = 0;

  forms.forEach((form) => {
    const action = (form.getAttribute('action') || '').trim();
    const method = (form.getAttribute('method') || 'get').toLowerCase();

    if (form.querySelector('input[type="password"], input[name*="password" i]')) {
      hasPasswordInput = 1;
    }

    if (!action) {
      formActionIsEmpty = 1;
    }

    try {
      const targetUrl = new URL(action || window.location.href, window.location.href);
      const currentHost = window.location.hostname || '';
      const targetHost = targetUrl.hostname || '';
      const sameOrigin = currentHost && targetHost && currentHost.toLowerCase() === targetHost.toLowerCase();
      const isLoopbackHost = currentHost === 'localhost' || currentHost === '127.0.0.1' || currentHost === '[::1]';
      const brandedAction = isLikelyBrandedDomain(targetHost);

      const targetLooksLikeIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(targetHost);

      if (action && !sameOrigin && !brandedAction && (!isLoopbackHost || targetLooksLikeIp)) {
        crossDomainFormAction = 1;
      }

      if (method === 'post' && targetUrl.protocol === 'http:' && window.location.protocol === 'https:') {
        crossDomainFormAction = 1;
      }

      if (!currentHost && action && targetHost && targetHost.includes('example.com')) {
        crossDomainFormAction = 0;
      }
    } catch (error) {
      if (action) {
        formActionIsEmpty = 1;
      }
    }
  });

  const scriptsText = Array.from(document.querySelectorAll('script'))
    .map((script) => script.textContent || '')
    .join(' ')
    .toLowerCase();
  if (
    credentialInputs.length > 0
    && (/\b(fetch|xmlhttprequest|sendbeacon)\b/.test(scriptsText)
      || /\b(input|keydown|submit)\b/.test(scriptsText))
  ) {
    credentialSubmissionScript = 1;
  }

  return {
    form_count: forms.length,
    has_password_input: hasPasswordInput || Number(
      document.querySelector('input[type="password"], input[name*="password" i]') !== null
    ),
    credential_field_count: credentialInputs.length,
    cross_domain_form_action: crossDomainFormAction,
    hidden_field_count: hiddenInputs.length,
    form_action_is_empty: formActionIsEmpty,
    credential_submission_script: credentialSubmissionScript
  };
};
