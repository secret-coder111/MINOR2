window.PhishGuard = window.PhishGuard || {};

window.PhishGuard.extractDomFeatures = function (knownFormFeatures) {
  const pageContext = window.PhishGuard.getPageContext ? window.PhishGuard.getPageContext() : null;
  let page = window.location;
  try { if (pageContext && pageContext.url) page = new URL(pageContext.url); } catch (error) {}
  const roots = window.PhishGuard.getDetectionRoots();
  const query = (selector) => roots.flatMap((root) => Array.from(root.querySelectorAll(selector)));
  const styles = new WeakMap();
  const styleOf = (node) => {
    if (!styles.has(node)) styles.set(node, window.getComputedStyle ? window.getComputedStyle(node) : node.style);
    return styles.get(node);
  };
  const scriptBlocks = query('script:not([src])').filter(window.PhishGuard.isExecutableScript);
  const iframeNodes = query('iframe');
  const externalScripts = query('script[src]').filter(window.PhishGuard.isExecutableScript);
  // A refresh element inside a shadow tree cannot navigate the document.
  const metaRefresh = Array.from(document.querySelectorAll('meta[http-equiv]'))
    .filter((node) => String(node.getAttribute('http-equiv')).toLowerCase() === 'refresh');
  const scriptsText = scriptBlocks.map((script) => script.textContent || '').join(' ');
  const obfuscationPatterns = [
    /eval\s*\(/i, /atob\s*\(/i, /fromCharCode\s*\(/i, /document\.write\s*\(/i, /Function\s*\(/i
  ];
  let obfuscatedScore = obfuscationPatterns.filter((pattern) => pattern.test(scriptsText)).length * 0.25;
  const longEncoded = (scriptsText.match(/[A-Za-z0-9+/=]{200,}/g) || []).length;
  obfuscatedScore += Math.min(longEncoded * 0.1, 0.8);
  const isZeroSize = (value) => /^\s*0+(?:\.0+)?(?:px|%)?\s*$/i.test(String(value));
  const isHidden = (element) => {
    const ownStyle = styleOf(element);
    if (ownStyle && ['hidden', 'collapse'].includes(ownStyle.visibility)) return true;
    for (let node = element; node && node.nodeType === 1; node = window.PhishGuard.composedParent(node)) {
      if (node.hasAttribute('hidden')) return true;
      const style = styleOf(node);
      if (style && (style.display === 'none' || style.opacity === '0')) return true;
    }
    // Missing attributes mean default/unknown dimensions, never zero.
    if (['width', 'height'].some((name) => element.hasAttribute(name) && isZeroSize(element.getAttribute(name)))) return true;
    const style = styleOf(element);
    if (style && (isZeroSize(style.width) || isZeroSize(style.height))) return true;
    // Layout is unavailable in jsdom. In a real document use a rendered box only if one exists.
    if (document.documentElement.clientWidth > 0 && element.getClientRects().length > 0) {
      const rect = element.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0 || rect.right < 0 || rect.bottom < 0) return true;
    }
    return false;
  };
  // Bound style/layout work on documents containing an unusually large number of frames.
  const hiddenIframes = iframeNodes.slice(0, 200).filter(isHidden).length;
  const externalScriptCount = externalScripts.filter((script) => {
    const src = script.getAttribute('src') || '';
    if (!src) return false;
    try {
      return new URL(src, document.baseURI || page.href).hostname !== page.hostname;
    } catch (error) {
      return false;
    }
  }).length;
  const visibleText = (() => {
    if (!document.body) return '';
    // innerText/textContent include textarea defaults and editable user text.
    // Walk rendered page labels only, including slots and open shadow content.
    const text = [];
    const pending = [document.body];
    while (pending.length) {
      const node = pending.pop();
      if (node.nodeType === 3) {
        const parent = window.PhishGuard.composedParent(node);
        const style = styleOf(parent);
        if (!style || !['hidden', 'collapse'].includes(style.visibility)) text.push(node.nodeValue || '');
        continue;
      }
      if (node.nodeType !== 1 || node.matches('input, textarea, select, option, script, style, noscript, template, [hidden], [contenteditable]')) continue;
      const style = styleOf(node);
      if ((node.tagName === 'DIALOG' && !node.hasAttribute('open'))
        || (style && (style.display === 'none' || style.opacity === '0' || style.contentVisibility === 'hidden'))) continue;
      let children = node.shadowRoot ? node.shadowRoot.childNodes : node.childNodes;
      if (node.tagName === 'DETAILS' && !node.hasAttribute('open')) {
        const summary = Array.from(node.children).find((child) => child.tagName === 'SUMMARY');
        children = summary ? [summary] : [];
      }
      if (node.tagName === 'SLOT') {
        const assigned = node.assignedNodes({ flatten: true });
        if (assigned.length) children = assigned;
      }
      for (let index = children.length - 1; index >= 0; index -= 1) pending.push(children[index]);
    }
    return text.join(' ');
  })();
  const brandPattern = /(?:^|[^a-z0-9])(?:google|microsoft|apple|paypal|amazon|icici|hdfc|sbi|axis)(?=$|[^a-z0-9])/i;
  const path = page.pathname || '';
  const isFrontPage = path === '' || path === '/' || /^\/(home|index|welcome)(\.[a-z0-9]+)?$/i.test(path);
  const formFeatures = knownFormFeatures || (window.PhishGuard.extractFormFeatures ? window.PhishGuard.extractFormFeatures() : {});
  // Exact, short branding next to sensitive controls can identify a login at
  // any heading level. Semantic article wrappers do not make a live form inert.
  // Read only non-editable label nodes; never read credential/editor contents.
  const headingText = (heading) => {
    const parts = [], pending = [heading];
    while (pending.length) {
      const node = pending.pop();
      if (node.nodeType === 3) { parts.push(node.nodeValue || ''); continue; }
      if (node.nodeType !== 1 || node.matches('input, textarea, select, option, script, style, template, [contenteditable]')
        || window.PhishGuard.isEditableMetadata(node) || !window.PhishGuard.isRenderedControl(node)) continue;
      for (let index = node.childNodes.length - 1; index >= 0; index -= 1) pending.push(node.childNodes[index]);
    }
    return parts.join(' ').replace(/\s+/g, ' ').trim();
  };
  const headingClaimPattern = /^(?:(?:welcome to|sign in to|log in to|login to)\s+)?(?:google|microsoft|apple|paypal|amazon|icici|hdfc|sbi|axis)(?:\s+(?:account|accounts|login|sign in|log in|secure login|internet banking|online banking))?\s*[.!]?$/i;
  const details = window.PhishGuard.formFeatureDomContexts.get(formFeatures) || { sensitiveControls: [], contextControls: [] };
  const contextualSelector = 'nav, footer, aside, [role="comment"]';
  const inContextualContent = (element) => {
    // Element.closest stops at a shadow boundary. Preserve the contextual
    // boundary when a footer/widget arrives through a component or slot.
    for (let node = element; node; node = window.PhishGuard.composedParent(node)) {
      if (node.matches && node.matches(contextualSelector)) return true;
    }
    return false;
  };
  const containsControl = (scope, control) => {
    if (control.form === scope) return true;
    for (let node = control; node; node = window.PhishGuard.composedParent(node)) if (node === scope) return true;
    return false;
  };
  const nearbySensitiveControls = (heading) => {
    if (inContextualContent(heading)) return [];
    const form = heading.closest('form');
    if (form) return details.sensitiveControls.filter((control) => containsControl(form, control));
    // Keep unrelated footer logins, articles and distant provider widgets out
    // of this identity claim. A nearby short instruction may precede the UI.
    let sibling = heading.nextElementSibling;
    for (let index = 0; sibling && index < 3; index += 1, sibling = sibling.nextElementSibling) {
      if (sibling.matches(contextualSelector + ', h1, h2, h3, h4, h5, h6, [role="heading"]')) break;
      const controls = details.sensitiveControls.filter((control) => !inContextualContent(control) && containsControl(sibling, control));
      if (controls.length) return controls;
    }
    return [];
  };
  const headingClaims = Number(formFeatures.sensitive_credential_field_count) > 0
    ? query('h1, h2, h3, h4, h5, h6, [role="heading"]')
      .filter((heading) => !heading.hasAttribute('role') || heading.getAttribute('role') !== 'heading'
        || /^[1-6]$/.test(heading.getAttribute('aria-level') || '2'))
      .filter((heading) => !inProviderControl(heading))
      .filter(window.PhishGuard.isRenderedControl).map((heading) => ({ text: headingText(heading), controls: nearbySensitiveControls(heading) }))
      .filter(({ text, controls }) => controls.length > 0 && text.length <= 100 && headingClaimPattern.test(text))
      .map((claim) => ({ ...claim, brand: window.PhishGuard.getBrandInfo(page.href, claim.text) })) : [];
  const imageNameText = (node) => {
    if (!node || window.PhishGuard.isEditableMetadata(node)) return '';
    const parts = [], pending = [node];
    while (pending.length) {
      const current = pending.pop();
      if (current.nodeType === 3) { parts.push(current.nodeValue || ''); continue; }
      if (current.nodeType !== 1 || current.matches('input, textarea, select, option, script, style, template, [contenteditable]')) continue;
      for (let index = current.childNodes.length - 1; index >= 0; index -= 1) pending.push(current.childNodes[index]);
    }
    return parts.join(' ');
  };
  const imageName = (node) => {
    const root = node.getRootNode();
    const referenced = String(node.getAttribute('aria-labelledby') || '').split(/\s+/)
      .filter(Boolean).map((id) => imageNameText(root.getElementById(id))).join(' ');
    const title = node.tagName.toLowerCase() === 'svg' ? imageNameText(node.querySelector('title')) : '';
    return String(referenced || node.getAttribute('aria-label') || node.getAttribute('alt') || title).normalize('NFKC').replace(/\s+/g, ' ').trim();
  };
  const imagePattern = /^(?:(?:logo of|logo for)\s+)?(google|microsoft|apple|paypal|amazon|icici|hdfc|sbi|axis)(?:\s+logo)?\s*[.!]?$/i;
  function inProviderControl(node) {
    for (let current = node; current; current = window.PhishGuard.composedParent(current)) {
      if (current.matches && current.matches('a, button, [role="button"], [role="link"]')) return true;
    }
    return false;
  }
  // Accessible image names only: no image downloads, filename guesses or OCR.
  // Logos on provider buttons/links and distant page furniture are not claims
  // that the surrounding credential form belongs to that provider.
  const imageClaims = Number(formFeatures.sensitive_credential_field_count) > 0
    ? query('img, svg[role="img"], [role="img"][aria-label], [role="img"][aria-labelledby]')
      .filter((node) => window.PhishGuard.isRenderedControl(node) && !window.PhishGuard.isEditableMetadata(node) && !inProviderControl(node))
      .map((node) => ({ name: imageName(node), controls: nearbySensitiveControls(node) }))
      .map(({ name, controls }) => ({ match: imagePattern.exec(name), controls }))
      .filter(({ match, controls }) => match && controls.length > 0)
      .map(({ match, controls }) => ({ controls, brand: window.PhishGuard.getBrandInfo(page.href, match[1]) })) : [];
  const identityClaims = [...headingClaims, ...imageClaims];
  const bodyMismatch = identityClaims.some((claim) => claim.brand.brandDomainMismatch);
  const bodyIdentity = identityClaims.some((claim) => claim.brand.brandIdentityClaim);
  const pageBrand = window.PhishGuard.getBrandInfo(page.href, document.title || '');
  const credentialContexts = (formFeatures.credential_contexts || []).map((context, index) => {
    const controls = details.contextControls[index] || [];
    const contextClaims = identityClaims.filter((claim) => claim.controls.some((control) => controls.includes(control)));
    const contextMismatch = contextClaims.some((claim) => claim.brand.brandDomainMismatch);
    // Address and identity must describe the SAME brand at the SAME sensitive
    // submission context. Titles/mentions/provider buttons cannot supply this
    // new corroboration, nor can a different form elsewhere on the page.
    const addressMatch = contextClaims.some((claim) => claim.brand.titleBrands
      .some((brand) => claim.brand.addressDeceptionBrands.includes(brand)));
    return { ...context, brand_domain_mismatch: Number(pageBrand.brandDomainMismatch || contextMismatch),
      credential_brand_identity_claim: Number(contextClaims.length > 0),
      credential_brand_address_match: Number(addressMatch) };
  });
  // These are weak structural observations. A login, a brand, and a short page are not deception.
  const frontpageSignals = [hiddenIframes > 0, metaRefresh.length > 0, obfuscatedScore >= 0.5].filter(Boolean).length;
  return {
    obfuscated_script_score: Number(Math.min(obfuscatedScore, 1).toFixed(2)),
    hidden_iframe_count: hiddenIframes,
    iframe_scan_truncated: Number(iframeNodes.length > 200),
    external_script_count: externalScriptCount,
    meta_refresh_count: metaRefresh.length,
    brand_name_in_title: Number(brandPattern.test(document.title || '')),
    brand_name_in_visible_text: Number(brandPattern.test(visibleText)),
    body_brand_identity_claim: Number(bodyIdentity),
    body_brand_domain_mismatch: Number(bodyMismatch),
    brand_identity_claim: Number(pageBrand.brandIdentityClaim || bodyIdentity),
    brand_domain_mismatch: Number(pageBrand.brandDomainMismatch || bodyMismatch),
    credential_contexts: credentialContexts,
    // Keep this named feature about title/hostname evidence only.
    page_title_mismatch: Number(pageBrand.brandDomainMismatch),
    frontpage_is_landing_page: Number(isFrontPage),
    frontpage_has_credential_form: Number(Boolean(formFeatures.credential_context)),
    frontpage_suspicious_signal_count: isFrontPage ? frontpageSignals : 0
  };
};
