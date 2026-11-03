// The HTML also sets CSP form-action 'none', so submission stays blocked if this
// script fails. These fixtures never need typed credentials or network requests.
document.addEventListener('submit', (event) => {
  event.preventDefault();
  const status = document.getElementById('demoStatus');
  if (status) status.textContent = 'Demonstration only. No form data was submitted.';
});

const demoScenarios = {
  normal: {
    title: 'College Portal', action: '/demo-signin', expected: 'No strong indicators',
    detail: 'An ordinary first-party login. A password field alone does not establish phishing.',
    identity: 'An ordinary college portal identity.', destination: 'A relative destination on the current site.'
  },
  external: {
    title: 'College Portal', action: 'https://example.invalid/collect', expected: 'Caution',
    detail: 'The credential destination is on another site. Legitimate sign-in providers can do this too.',
    identity: 'The ordinary college portal identity stays the same.', destination: 'The form now points to an illustrative external collector.'
  },
  phishing: {
    title: 'PayPal Account Verification', action: 'https://example.invalid/collect', expected: 'High risk',
    detail: 'A recognized brand claim on the local hostname combines with an external credential destination.',
    identity: 'The page now claims a recognized brand on a different hostname.', destination: 'The external credential destination remains in place.'
  }
};

document.querySelectorAll('[data-demo-scenario]').forEach((button) => {
  button.addEventListener('click', () => {
    const scenario = demoScenarios[button.dataset.demoScenario];
    if (!scenario) return;
    document.body.dataset.journeyScenario = button.dataset.demoScenario;
    document.title = scenario.title;
    document.getElementById('scenarioHeading').textContent = scenario.title;
    document.getElementById('scenarioForm').setAttribute('action', scenario.action);
    document.getElementById('expectedResult').textContent = scenario.expected;
    document.getElementById('scenarioDetail').textContent = scenario.detail;
    document.getElementById('destination').textContent = scenario.action;
    document.getElementById('demoStatus').textContent = '';
    const resultCard = document.getElementById('scenarioResult');
    if (resultCard) resultCard.dataset.band = button.dataset.demoScenario;
    const identityDetail = document.getElementById('identityDetail');
    const destinationDetail = document.getElementById('destinationDetail');
    if (identityDetail) identityDetail.textContent = scenario.identity;
    if (destinationDetail) destinationDetail.textContent = scenario.destination;
    document.querySelectorAll('[data-demo-scenario]').forEach((other) => {
      other.setAttribute('aria-pressed', String(other === button));
    });
  });
});
