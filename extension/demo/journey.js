// A teaching animation, not a detector or credential collector. It reads only
// the document title, URL and form attributes. No field value is read or sent.
(() => {
  'use strict';
  const host = document.getElementById('credentialJourney');
  const form = document.getElementById('scenarioForm') || document.querySelector('form');
  if (!host || !form) return;
  const byId = (id) => document.getElementById(id);
  const lessons = {
    custom: {
      name: 'Professor-edited page', band: 'custom', receiver: 'Observed form recipient',
      recipient: 'Authorization and ownership require verification',
      stages: [
        ['Read the edited facts', 'The page differs from the predefined teaching scenario. Inspect the actual origin, title and resolved destination below.'],
        ['Keep the example fictional', 'Only fixed fictional tokens are shown. Editing a page does not authorize entering real passwords or submitting a form.'],
        ['Follow the actual destination', 'The form action displayed below reflects the edited document. This animation performs no transfer and makes no claim about the recipient’s ownership.'],
        ['Test the detector independently', 'Open PhishGuard, request Check again and read its actual reasons. Record the result even when it differs from your prediction.']
      ],
      consequence: 'A manually edited example needs its own interpretation. No predetermined safe or phishing outcome is assigned by this page.',
      cue: 'The extension must inspect the current document. The animation does not calculate or substitute a verdict.'
    },
    normal: {
      name: 'Ordinary login', band: 'low', receiver: 'Same-site service',
      recipient: 'An intended first-party service',
      stages: [
        ['Read the address', 'The browser is on the address shown below. A familiar appearance or an HTTPS padlock alone cannot verify who owns it.'],
        ['Prepare the example', 'Imagine a user choosing to sign in. The tokens below are fixed illustrations; they are never read from the form.'],
        ['Follow the destination', 'In a real native form submission, the browser would send named controls to the resolved form action. This example points to the same site.'],
        ['Explain the outcome', 'An intended service would check credentials and establish a session. This demonstration authenticates nobody. Same-site submission is normal context, not proof of legitimacy.']
      ],
      consequence: 'No theft is illustrated in this baseline. A compromised first-party site could still be dangerous.',
      cue: 'No external destination or mismatched recognized-brand claim is introduced. Open the extension for its actual result.'
    },
    external: {
      name: 'External destination', band: 'medium', receiver: 'Different-site recipient',
      recipient: 'An external recipient whose authorization is unknown',
      stages: [
        ['Read the address', 'The page keeps its ordinary portal identity. Its credential form points to a different hostname.'],
        ['Prepare the example', 'The fictional email and secret represent information a user might submit. This page does not take or read any real values.'],
        ['Follow the destination', 'A real browser follows the form action, even if the button says “Sign in” and the page looks familiar. The address displayed above the page is not the submission destination.'],
        ['Ask who is authorized', 'If this recipient is unauthorized, submitting a real password could disclose it. A trusted identity or payment provider can also be external: the destination alone does not prove phishing.']
      ],
      consequence: 'Possible exposure if the recipient is unauthorized. We have not demonstrated that an external service is malicious.',
      cue: 'One destination concern calls for review. It does not establish a malicious owner or justify declaring every SSO flow phishing.'
    },
    phishing: {
      name: 'Brand + external destination', band: 'high', receiver: 'Illustrative unauthorized collector',
      recipient: 'A hypothetical attacker-controlled recipient',
      stages: [
        ['Spot the identity conflict', 'The page claims a recognized brand, but the browser address is not that brand’s recognized domain. This is an explicitly labelled training example.'],
        ['Prepare the example', 'In a real attack, the victim trusts the claimed brand and enters a password or code. Here, only fixed fictional tokens are shown.'],
        ['Follow the destination', 'The form points to a different site. If a victim submitted real credentials to an unauthorized collector, that recipient could receive them. HTTPS would encrypt the trip to that recipient; it would not make the recipient honest.'],
        ['Explain possible misuse', 'An attacker could try stolen credentials at the genuine service. Success depends on validity, timing and MFA protections; phishing-resistant MFA can prevent some attacks. No such login or theft happens here.']
      ],
      consequence: 'Theft is a hypothetical consequence of deception plus submission to an unauthorized recipient. No data is stolen in this lab.',
      cue: 'A mismatched brand claim and an external credential destination corroborate each other. The toolbar popup supplies the live PhishGuard verdict.'
    }
  };
  let step = 0;
  let timer = null;
  let facts = null;
  function readFacts() {
    const raw = form.getAttribute('action') || '';
    let destination;
    try { destination = new URL(raw || location.href, raw ? document.baseURI : location.href); } catch (_) {}
    let scenario = document.body.dataset.journeyScenario || 'normal';
    const titleMatches = { normal: /^(?:College Portal|Contoso Bank)$/, external: /^College Portal$/,
      phishing: /^PayPal (?:Account Verification|Security Update)$/ };
    const external = Boolean(destination && destination.origin !== location.origin);
    if (!destination || !titleMatches[scenario] || !titleMatches[scenario].test(document.title)
      || (scenario === 'normal' ? external : !external || destination.hostname !== 'example.invalid')
      || (form.getAttribute('method') || 'get').toLowerCase() !== 'post') scenario = 'custom';
    return { title: document.title, origin: location.origin, action: raw,
      resolved: destination ? destination.href : 'Invalid destination',
      method: (form.getAttribute('method') || 'get').toUpperCase(),
      external, scenario };
  }
  function stop() {
    clearTimeout(timer); timer = null;
    byId('journeyPlay').textContent = 'Play walkthrough';
    byId('journeyPlay').setAttribute('aria-pressed', 'false');
  }
  function render() {
    const lesson = lessons[facts.scenario] || lessons.normal;
    host.dataset.band = lesson.band;
    host.dataset.step = String(step);
    byId('journeyScenario').textContent = lesson.name;
    byId('journeyStep').textContent = `Step ${step + 1} of 4`;
    byId('journeyStageTitle').textContent = lesson.stages[step][0];
    byId('journeyNarration').textContent = lesson.stages[step][1];
    byId('journeyRecipient').textContent = lesson.receiver;
    byId('journeyRecipientDescription').textContent = lesson.recipient;
    byId('journeyOutcome').textContent = lesson.consequence;
    byId('journeyEvidence').textContent = lesson.cue;
    byId('journeyActualOrigin').textContent = facts.origin;
    byId('journeyBrowserAddress').textContent = facts.origin;
    byId('journeyRecipientAddress').textContent = facts.resolved;
    byId('journeyReceiptTitle').textContent = facts.scenario === 'phishing' ? 'Collector view (illustrated)'
      : facts.scenario === 'normal' ? 'Intended service (illustrated)' : 'Recipient view (illustrated)';
    byId('journeyActualTitle').textContent = facts.title;
    byId('journeyActualDestination').textContent = facts.resolved;
    byId('journeyRouteLabel').textContent = facts.external ? 'Different origin in this document' : 'Same origin in this document';
    byId('journeyCode').textContent = `<title>${facts.title}</title>\n<form method="${facts.method.toLowerCase()}" action="${facts.action}">\n  <!-- Read-only demonstration controls; submission blocked -->\n</form>`;
    byId('journeyTokens').hidden = step < 1;
    byId('journeyReceipt').hidden = step < 3;
    byId('journeyPrevious').disabled = step === 0;
    byId('journeyNext').disabled = step === 3;
    byId('journeyProgress').value = step + 1;
    host.querySelectorAll('[data-journey-step]').forEach((node, index) => {
      node.setAttribute('aria-current', index === step ? 'step' : 'false');
    });
  }
  function refreshFacts() {
    const next = readFacts();
    if (JSON.stringify(next) === JSON.stringify(facts)) return;
    stop(); step = 0; facts = next; render();
  }
  byId('journeyNext').addEventListener('click', () => { stop(); step = Math.min(3, step + 1); render(); });
  byId('journeyPrevious').addEventListener('click', () => { stop(); step = Math.max(0, step - 1); render(); });
  byId('journeyReset').addEventListener('click', () => { stop(); step = 0; render(); });
  byId('journeyPlay').addEventListener('click', () => {
    if (timer) { stop(); return; }
    if (step === 3) step = 0;
    render();
    byId('journeyPlay').textContent = 'Pause walkthrough';
    byId('journeyPlay').setAttribute('aria-pressed', 'true');
    const advance = () => {
      step = Math.min(3, step + 1); render();
      if (step === 3) stop(); else timer = setTimeout(advance, 4200);
    };
    timer = setTimeout(advance, 4200);
  });
  byId('journeyReadFacts').addEventListener('click', () => {
    refreshFacts();
    byId('journeyFactsStatus').textContent = 'Page facts read again. Open PhishGuard and use Check again for the extension’s result.';
  });
  const observer = new MutationObserver(refreshFacts);
  observer.observe(document.head, { childList: true, subtree: true, characterData: true });
  observer.observe(form, { attributes: true, attributeFilter: ['action', 'method'] });
  observer.observe(document.body, { attributes: true, attributeFilter: ['data-journey-scenario'] });
  window.addEventListener('pagehide', () => { stop(); observer.disconnect(); }, { once: true });
  refreshFacts();
})();
