document.addEventListener('DOMContentLoaded', () => {
  const domainAgeEnabled = document.getElementById('domainAgeEnabled');
  const reputationEnabled = document.getElementById('reputationEnabled');
  const reputationEndpoint = document.getElementById('reputationEndpoint');
  const warningThreshold = document.getElementById('warningThreshold');
  const thresholdValue = document.getElementById('thresholdValue');

  chrome.storage.local.get(['phishguard_options'], (result) => {
    const options = result.phishguard_options || {
      domainAgeEnabled: false,
      reputationEnabled: false,
      reputationEndpoint: '',
      warningThreshold: 65
    };
    domainAgeEnabled.checked = Boolean(options.domainAgeEnabled);
    reputationEnabled.checked = Boolean(options.reputationEnabled);
    reputationEndpoint.value = options.reputationEndpoint || '';
    warningThreshold.value = String(options.warningThreshold || 65);
    thresholdValue.textContent = String(options.warningThreshold || 65);
  });

  warningThreshold.addEventListener('input', () => {
    thresholdValue.textContent = warningThreshold.value;
  });

  document.getElementById('clearData').addEventListener('click', () => {
    chrome.storage.local.clear();
    alert('Local data cleared.');
  });

  function saveOptions() {
    chrome.storage.local.set({
      phishguard_options: {
        domainAgeEnabled: domainAgeEnabled.checked,
        reputationEnabled: reputationEnabled.checked,
        reputationEndpoint: reputationEndpoint.value.trim(),
        warningThreshold: Number(warningThreshold.value)
      }
    });
  }

  document.addEventListener('change', saveOptions);
  reputationEndpoint.addEventListener('input', saveOptions);
});
