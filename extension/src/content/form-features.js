window.PhishGuard = window.PhishGuard || {};

// Open shadow trees are ordinary page UI. Keep the same traversal available to
// the runtime so a component's later changes trigger the same extraction.
window.PhishGuard.getDetectionRoots = function () {
  const roots = [document];
  for (let index = 0; index < roots.length; index += 1) {
    roots[index].querySelectorAll('*').forEach((node) => {
      if (node.shadowRoot) roots.push(node.shadowRoot);
    });
  }
  return roots;
};
window.PhishGuard.composedParent = function (node) {
  return node.assignedSlot || node.parentElement || (node.getRootNode && node.getRootNode().host) || null;
};
window.PhishGuard.isEditableMetadata = function (node) {
  // Even a label referenced from outside an editor may contain user input.
  for (let element = node.nodeType === 1 ? node : node.parentElement; element; element = window.PhishGuard.composedParent(element)) {
    if (element.isContentEditable || element.hasAttribute('contenteditable')) return true;
  }
  return false;
};
window.PhishGuard.isExecutableScript = function (script) {
  const type = String(script.getAttribute('type') || '').trim().toLowerCase();
  return !type || type === 'module'
    || /^(?:text|application)\/(?:x-)?(?:java|ecma)script(?:1\.[0-5])?(?:\s*;.*)?$/.test(type);
};

window.PhishGuard.CREDENTIAL_CONTROL_SELECTOR = 'input, textarea, [role="textbox"]';
// Temporary DOM associations stay in this isolated world. Only the structural
// feature object is serialized; references and field contents are never sent.
window.PhishGuard.formFeatureDomContexts = new WeakMap();
window.PhishGuard.isRenderedControl = function (element) {
  if (!element || !element.isConnected) return false;
  const ownStyle = window.getComputedStyle ? window.getComputedStyle(element) : element.style;
  if (ownStyle && ['hidden', 'collapse'].includes(ownStyle.visibility)) return false;
  if (typeof element.checkVisibility === 'function') {
    try {
      if (!element.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })) return false;
    } catch (error) { /* Older engines still get the structural checks below. */ }
  }
  const ancestry = [];
  for (let node = element; node && node.nodeType === 1; node = window.PhishGuard.composedParent(node)) {
    ancestry.push(node);
    const style = window.getComputedStyle ? window.getComputedStyle(node) : node.style;
    if (node.hasAttribute('hidden') || node.hasAttribute('inert')
      || (node.parentElement && node.parentElement.shadowRoot && !node.assignedSlot)
      || (node.tagName === 'DIALOG' && !node.hasAttribute('open'))
      || (style && (style.display === 'none' || style.opacity === '0' || style.contentVisibility === 'hidden'))) return false;
    if (node.tagName === 'DETAILS' && !node.hasAttribute('open') && node !== element) {
      const summary = Array.from(node.children).find((child) => child.tagName === 'SUMMARY');
      // The first summary remains rendered even while the details is closed.
      if (!summary || !ancestry.includes(summary)) return false;
    }
  }
  return true;
};

// Inspect field metadata and destinations only. Never read input values or run page scripts.
window.PhishGuard.extractFormFeatures = function () {
  const roots = window.PhishGuard.getDetectionRoots();
  const query = (selector) => roots.flatMap((root) => Array.from(root.querySelectorAll(selector)));
  const forms = query('form');
  const domainUtils = window.PhishGuard.domainUtils;
  const inputs = query(window.PhishGuard.CREDENTIAL_CONTROL_SELECTOR);
  const pageContext = window.PhishGuard.getPageContext ? window.PhishGuard.getPageContext() : null;
  let page = window.location;
  try { if (pageContext && pageContext.url) page = new URL(pageContext.url); } catch (error) {}
  const authPattern = /(?:^|[^a-z])(?:login|signin|sign[\s_-]+in|log[\s_-]+in|auth|authenticate|authentication|account)(?:$|[^a-z])/i;
  const sensitiveNames = new Set([
    'password', 'passwd', 'pwd', 'passcode', 'otp', 'totp', 'cvv', 'cvc',
    'pan', 'aadhaar', 'aadhar', 'wallet', 'seed', 'mnemonic', 'card',
    'creditcard', 'cardnumber', 'cardno', 'seedphrase', 'recoveryphrase'
  ]);
  const identityNames = new Set(['email', 'username', 'userid', 'login']);
  const sensitiveAutocomplete = new Set([
    'current-password', 'new-password', 'one-time-code', 'cc-number', 'cc-csc', 'cc-exp', 'cc-exp-month', 'cc-exp-year'
  ]);
  const tokens = (text) => String(text || '')
    .normalize('NFKC').replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, '')
    .replace(/([a-z])([A-Z])/g, '$1 $2').replace(/([a-zA-Z])([0-9])/g, '$1 $2')
    .replace(/([0-9])([a-zA-Z])/g, '$1 $2').toLowerCase().split(/[^\p{L}\p{M}\p{N}]+/u).filter(Boolean);
  // Finite, reviewed prompt phrases, not a claim of arbitrary language coverage.
  // Preserve combining marks (including Hindi vowel signs) during tokenization.
  const localizedPassword = ['पासवर्ड', 'कूटशब्द', 'mot de passe', 'contraseña', 'passwort', 'senha', 'пароль', 'كلمة المرور', '密码', 'パスワード'];
  const localizedIdentity = ['ईमेल', 'ई मेल', 'उपयोगकर्ता नाम', 'courriel', 'adresse e mail', 'correo electrónico', 'correo electronico', 'usuario', 'البريد الإلكتروني', '邮箱', '电子邮件', 'メールアドレス'];
  const localizedCode = ['ओटीपी', 'सत्यापन कोड', 'एक बार का पासवर्ड', 'code de vérification', 'código de verificación'];
  const containsPhrase = (text, phrases) => phrases.some((phrase) => ` ${text} `.includes(` ${tokens(phrase).join(' ')} `));
  const metadataCache = new WeakMap();
  const metadataText = (node) => {
    if (!node || window.PhishGuard.isEditableMetadata(node)) return '';
    if (metadataCache.has(node)) return metadataCache.get(node);
    // Read accessible label text only. Textareas and editable descendants can
    // contain actual user input, so never traverse them when reading a label.
    const parts = [];
    const pending = [node];
    while (pending.length) {
      const current = pending.pop();
      if (current.nodeType === 3) { parts.push(current.nodeValue || ''); continue; }
      if (current.nodeType !== 1 || current.matches('input, textarea, select, option, script, style, template, [contenteditable]')) continue;
      for (let index = current.childNodes.length - 1; index >= 0; index -= 1) pending.push(current.childNodes[index]);
    }
    const text = parts.join(' ');
    metadataCache.set(node, text);
    return text;
  };
  const accessibleMetadata = (input) => {
    // Search widgets often mention passwords in help searches; their prose is
    // not a password prompt. Input name/type/autocomplete checks still apply.
    if (!input.matches('[role="textbox"]') && input.tagName !== 'TEXTAREA' && !['text', 'password', 'email', 'tel', 'number'].includes(input.type)) return '';
    const labels = Array.from(input.labels || []).map(metadataText);
    const scope = input.getRootNode();
    const labelledBy = String(input.getAttribute('aria-labelledby') || '').split(/\s+/)
      .filter(Boolean).map((id) => metadataText(scope.getElementById(id)));
    return tokens([input.getAttribute('aria-label'), input.getAttribute('placeholder'), ...labels, ...labelledBy].join(' ')).join(' ');
  };
  const passwordMetadata = /\b(?:password|passwd|pwd)\b/;
  const codeMetadata = /\b(?:otp|totp|one time (?:code|password)|verification code|authentication code|authenticator code|two factor(?: authentication)? code|security code)\b/;
  const sensitiveMetadata = /\b(?:password|passwd|pwd|passcode|otp|totp|cvv|cvc|aadhaar|aadhar)\b|\b(?:one time (?:code|password)|verification code|authentication code|authenticator code|two factor(?: authentication)? code|(?:credit )?card number|credit card|security code|card security code|expiration(?: date)?|expiry(?: date)?|seed phrase|recovery phrase|pan number)\b/;
  const identityMetadata = /\b(?:email|e mail|username|user name|userid|user id)\b/;
  const visible = window.PhishGuard.isRenderedControl;
  const active = (input) => {
    if (input.disabled || input.matches(':disabled') || ['hidden', 'button', 'submit', 'reset', 'image', 'checkbox', 'radio', 'file'].includes(input.type)) return false;
    if (!input.matches('input, textarea')) {
      let editable = Boolean(input.isContentEditable);
      for (let node = input; node; node = window.PhishGuard.composedParent(node)) {
        if (!node.hasAttribute('contenteditable')) continue;
        const declared = String(node.getAttribute('contenteditable') || '').toLowerCase();
        if (['', 'true', 'plaintext-only', 'false'].includes(declared)) {
          editable = declared !== 'false';
          break;
        }
      }
      // ARIA read-only/disabled alone does not prevent the browser from
      // editing a contenteditable surface. Do not let it hide an active field.
      if (input.getAttribute('role') !== 'textbox' || !editable) return false;
    }
    return visible(input);
  };
  const fieldInfo = (input) => {
    if (!active(input)) return null;
    const nameTokens = tokens(`${input.getAttribute('name') || ''} ${input.id || ''}`);
    const compactNames = [input.getAttribute('name'), input.id].map((name) => String(name || '').toLowerCase().replace(/[^a-z0-9]/g, ''));
    const autocomplete = String(input.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
    const metadata = accessibleMetadata(input);
    const nameMetadata = nameTokens.join(' ');
    const explicitIdentity = input.type === 'email' || nameTokens.some((token) => identityNames.has(token))
      || compactNames.some((name) => identityNames.has(name)) || autocomplete.some((token) => ['username', 'email'].includes(token))
      || containsPhrase(nameMetadata, localizedIdentity);
    const identityControl = input.type === 'email' || autocomplete.some((token) => ['username', 'email'].includes(token));
    // "Email to reset your password" requests an identity, not a password.
    // Keep concrete type/name/autocomplete evidence independent of label prose.
    const metadataRequestsIdentity = explicitIdentity || identityMetadata.test(metadata) || containsPhrase(metadata, localizedIdentity);
    const passwordFromMetadata = !metadataRequestsIdentity && (passwordMetadata.test(metadata) || containsPhrase(metadata, localizedPassword));
    // "Email verification code" asks for a secret code, not an email address.
    // Generic coupon/postal codes remain neutral; recovery prose still cannot
    // turn an actual email control into a password prompt.
    const requestsCode = codeMetadata.test(metadata) || containsPhrase(metadata, localizedCode);
    const sensitiveFromMetadata = (!metadataRequestsIdentity || (!identityControl && requestsCode))
      && (sensitiveMetadata.test(metadata) || containsPhrase(metadata, localizedPassword) || requestsCode);
    const passwordFromName = !identityControl && containsPhrase(nameMetadata, localizedPassword);
    const sensitive = input.type === 'password'
      || (!identityControl && (nameTokens.some((token) => sensitiveNames.has(token))
        || compactNames.some((name) => sensitiveNames.has(name) || name === 'creditcardnumber')))
      || autocomplete.some((token) => sensitiveAutocomplete.has(token))
      || sensitiveFromMetadata || passwordFromName || (!identityControl && containsPhrase(nameMetadata, localizedCode));
    const identity = input.type === 'email' || nameTokens.some((token) => identityNames.has(token))
      || compactNames.some((name) => identityNames.has(name))
      || autocomplete.includes('username') || autocomplete.includes('email')
      || identityMetadata.test(metadata) || containsPhrase(metadata, localizedIdentity) || containsPhrase(nameMetadata, localizedIdentity);
    if (!sensitive && !identity) return null;
    const password = input.type === 'password' || (!identityControl && nameTokens.some((token) => ['password', 'passwd', 'pwd'].includes(token)))
      || autocomplete.some((token) => ['current-password', 'new-password'].includes(token))
      || passwordFromMetadata || passwordFromName;
    // Custom editors have no native form submission semantics. Recognize their
    // prompt without inventing a destination or reading editable contents.
    return { input, form: input.matches('input, textarea') ? input.form : null, sensitive, identity, password, explicitUsername: autocomplete.includes('username') };
  };
  const fields = inputs.map(fieldInfo).filter(Boolean);
  const fieldsByForm = new Map();
  fields.forEach((field) => {
    if (!fieldsByForm.has(field.form)) fieldsByForm.set(field.form, []);
    fieldsByForm.get(field.form).push(field);
  });
  const hasSensitiveFields = fields.some((field) => field.sensitive);
  const hasAuthContext = (form, fieldsForForm) => fieldsForForm.some((field) => field.sensitive || field.explicitUsername)
    || (form && authPattern.test([form.getAttribute('action'), form.id, form.getAttribute('name')].join(' ')))
    || (!hasSensitiveFields && authPattern.test(`${document.title || ''} ${page.pathname || ''}`));
  const credentialForms = forms.filter((form) => {
    const formFields = fieldsByForm.get(form) || [];
    return formFields.length > 0 && hasAuthContext(form, formFields);
  });
  const unassociated = fieldsByForm.get(null) || [];
  const credentialContext = credentialForms.length > 0 || (unassociated.length > 0 && hasAuthContext(null, unassociated));
  let crossSite = 0;
  let emptyAction = 0;
  let invalidAction = 0;
  let insecureTransport = 0;
  let downgrade = 0;
  let targetIp = 0;
  let methodGet = 0;
  let explicitGet = 0;
  let scriptAction = 0;
  let crossOrigin = 0;
  let targetUnusualPort = 0;
  const credentialContexts = [];
  const contextControls = [];
  const makeContext = (contextFields) => {
    contextControls[credentialContexts.length] = contextFields.map((field) => field.input);
    return {
    context_index: credentialContexts.length,
    credential_context: 1,
    has_password_input: Number(contextFields.some((field) => field.password)),
    credential_field_count: contextFields.length,
    sensitive_credential_field_count: contextFields.filter((field) => field.sensitive).length,
    identity_only_form: Number(!contextFields.some((field) => field.sensitive)),
    cross_domain_form_action: 0,
    credential_form_cross_site: 0,
    credential_form_cross_origin: 0,
    credential_target_unusual_port: 0,
    credential_target_ip: 0,
    credential_transport_downgrade: 0,
    credential_insecure_transport: 0,
    credential_form_method_get: 0,
    credential_form_explicit_get: 0,
    credential_form_native_get: 0,
    credential_form_get_exposes_sensitive: 0,
    credential_destination_unknown: 0,
    credential_script_action: 0,
    invalid_credential_action: 0,
    form_action_is_empty: 0
    };
  };
  const isIp = (host) => domainUtils ? domainUtils.isIpAddress(host) : /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:]+\]$/i.test(host);
  const isLoopback = (host) => domainUtils ? domainUtils.isLoopback(host) : ['localhost', '127.0.0.1', '[::1]'].includes(host);
  const sameSite = (a, b) => domainUtils ? domainUtils.sameSite(a, b) : String(a).toLowerCase() === String(b).toLowerCase();
  const submittersByForm = new Map();
  query('button, input[type="submit"], input[type="image"]').forEach((node) => {
    if (!node.form || node.disabled || node.matches(':disabled') || !visible(node) || (node.tagName === 'BUTTON' && node.type !== 'submit')) return;
    if (!submittersByForm.has(node.form)) submittersByForm.set(node.form, []);
    submittersByForm.get(node.form).push(node);
  });
  const scriptsMayIntercept = query('script').filter(window.PhishGuard.isExecutableScript)
    .some((script) => script.hasAttribute('src') || /\b(?:submit|preventDefault|fetch|XMLHttpRequest|sendBeacon)\b/i.test(script.textContent || ''));

  credentialForms.forEach((form) => {
    // form= associations and submitter overrides can target a form from outside its subtree.
    const submitters = submittersByForm.get(form) || [];
    // A missing method on an Ajax form does not prove a native GET will occur.
    // This narrowly identifies an available native submission path; no script
    // text or field value is ever sent to the worker.
    const possibleInterception = form.hasAttribute('onsubmit') || submitters.some((node) => node.hasAttribute('onclick'))
      || scriptsMayIntercept;
    const blockingInputs = inputs.filter((input) => input.tagName === 'INPUT' && input.form === form
      && ['text', 'search', 'url', 'tel', 'email', 'password', 'date', 'month', 'week', 'time', 'datetime-local', 'number'].includes(input.type));
    const nativeSubmitPath = submitters.length > 0 || blockingInputs.length === 1;
    const targets = [{ action: form.getAttribute('action'), method: form.getAttribute('method') }];
    submitters.forEach((node) => {
      if (node.hasAttribute('formaction') || node.hasAttribute('formmethod')) {
        targets.push({
          action: node.hasAttribute('formaction') ? node.getAttribute('formaction') : form.getAttribute('action'),
          method: node.hasAttribute('formmethod') ? node.getAttribute('formmethod') : form.getAttribute('method')
        });
      }
    });
    targets.forEach(({ action, method }) => {
      const declaredMethod = String(method || '').toLowerCase();
      // HTML enumerated values are case-insensitive, but surrounding whitespace is invalid.
      const effectiveMethod = ['get', 'post', 'dialog'].includes(declaredMethod) ? declaredMethod : 'get';
      if (effectiveMethod === 'dialog') {
        // Closing a dialog does not submit over the network, but it must not
        // erase the fact that this page visibly requests sensitive fields.
        credentialContexts.push(makeContext(fieldsByForm.get(form)));
        return;
      }
      const context = makeContext(fieldsByForm.get(form));
      // Native submission omits unnamed controls. Inspect names only, never
      // values, and keep the observation bound to this form's sensitive UI.
      context.credential_form_get_exposes_sensitive = Number(effectiveMethod === 'get'
        && fieldsByForm.get(form).some((field) => field.sensitive && Boolean(field.input.name)));
      if (!['get', 'post'].includes(effectiveMethod) || effectiveMethod === 'get') context.credential_form_method_get = 1;
      context.credential_form_explicit_get = Number(Boolean(declaredMethod.trim()) && effectiveMethod === 'get');
      const rawAction = String(action || '').trim();
      if (!rawAction) context.form_action_is_empty = 1;
      try {
        // Empty action submits to the document URL, not to an HTML <base> URL.
        const target = rawAction ? new URL(rawAction, form.ownerDocument.baseURI || page.href) : new URL(page.href);
        if (!rawAction && pageContext && pageContext.inherited) {
          // An inherited origin identifies the source site, but cannot turn an
          // about:blank/srcdoc empty action into a proven HTTP destination.
          context.credential_destination_unknown = 1;
        } else if (target.protocol === 'javascript:') {
          // JavaScript-intercepted forms do not establish a network destination or GET submission.
          context.credential_script_action = 1;
          context.credential_form_explicit_get = 0;
        } else if (!['http:', 'https:'].includes(target.protocol)) {
          context.invalid_credential_action = 1;
        } else {
          context.cross_domain_form_action = Number(!sameSite(page.hostname, target.hostname));
          context.credential_form_cross_site = context.cross_domain_form_action;
          context.credential_form_cross_origin = Number(page.origin !== target.origin);
          context.credential_target_unusual_port = Number(Boolean(target.port) && !['80', '443'].includes(target.port) && !isLoopback(target.hostname));
          context.credential_insecure_transport = Number(target.protocol === 'http:' && !isLoopback(target.hostname));
          context.credential_transport_downgrade = Number(page.protocol === 'https:' && target.protocol === 'http:' && !isLoopback(target.hostname));
          context.credential_target_ip = Number(isIp(target.hostname) && !isLoopback(target.hostname));
          context.credential_form_native_get = Number(effectiveMethod === 'get' && !context.credential_form_explicit_get
            && !possibleInterception && nativeSubmitPath
            && fieldsByForm.get(form).some((field) => field.sensitive && Boolean(field.input.name)));
        }
      } catch (error) {
        context.invalid_credential_action = 1;
      }
      // Flat features are retained for the numeric model contract. Verdicts use scoped contexts.
      crossSite = Math.max(crossSite, context.cross_domain_form_action);
      crossOrigin = Math.max(crossOrigin, context.credential_form_cross_origin);
      targetUnusualPort = Math.max(targetUnusualPort, context.credential_target_unusual_port);
      insecureTransport = Math.max(insecureTransport, context.credential_insecure_transport);
      downgrade = Math.max(downgrade, context.credential_transport_downgrade);
      targetIp = Math.max(targetIp, context.credential_target_ip);
      methodGet = Math.max(methodGet, context.credential_form_method_get);
      explicitGet = Math.max(explicitGet, context.credential_form_explicit_get);
      scriptAction = Math.max(scriptAction, context.credential_script_action);
      invalidAction = Math.max(invalidAction, context.invalid_credential_action);
      emptyAction = Math.max(emptyAction, context.form_action_is_empty);
      credentialContexts.push(context);
    });
  });
  if (unassociated.length > 0 && hasAuthContext(null, unassociated)) {
    // Orphan fields still establish credential context, without inventing a form destination.
    credentialContexts.push(makeContext(unassociated));
  }
  const scriptsText = query('script:not([src])').filter(window.PhishGuard.isExecutableScript)
    .map((script) => script.textContent || '').join(' ');
  const scriptActivity = fields.length > 0 && /\b(fetch|XMLHttpRequest|sendBeacon|input|keydown|submit)\b/i.test(scriptsText);
  const result = {
    form_count: forms.length,
    has_password_input: Number(fields.some((field) => field.password)),
    password_form_count: credentialForms.filter((form) => fieldsByForm.get(form).some((field) => field.password)).length,
    credential_field_count: fields.length,
    sensitive_credential_field_count: fields.filter((field) => field.sensitive).length,
    credential_context: Number(credentialContext),
    identity_only_form: Number(credentialContext && !hasSensitiveFields),
    credential_contexts: credentialContexts,
    cross_domain_form_action: crossSite,
    credential_form_cross_site: crossSite,
    credential_form_cross_origin: crossOrigin,
    credential_target_unusual_port: targetUnusualPort,
    credential_transport_downgrade: downgrade,
    credential_insecure_transport: insecureTransport,
    credential_target_ip: targetIp,
    credential_form_method_get: methodGet,
    credential_form_explicit_get: explicitGet,
    credential_script_action: scriptAction,
    invalid_credential_action: invalidAction,
    hidden_field_count: inputs.filter((input) => input.type === 'hidden' && !input.disabled).length,
    form_action_is_empty: emptyAction,
    // Static token coincidence cannot establish which data a request sends.
    credential_submission_script: 0,
    credential_script_activity: Number(scriptActivity)
  };
  window.PhishGuard.formFeatureDomContexts.set(result, {
    sensitiveControls: fields.filter((field) => field.sensitive).map((field) => field.input),
    contextControls
  });
  return result;
};
