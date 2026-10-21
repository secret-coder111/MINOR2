document.addEventListener('DOMContentLoaded', async () => {
  const riskBadge = document.getElementById('riskBadge');
  const scoreText = document.getElementById('scoreText');
  const statusText = document.getElementById('statusText');
  const modelText = document.getElementById('modelText');
  const reasonList = document.getElementById('reasonList');
  let resultData = {};

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const currentTab = tabs[0];

  chrome.storage.local.get([`tab_${currentTab.id}`], (result) => {
    const data = result[`tab_${currentTab.id}`];
    resultData = data || {};
    if (!data || data.url !== currentTab.url) {
      riskBadge.textContent = 'Unknown';
      riskBadge.className = 'badge neutral';
      scoreText.textContent = 'No result yet';
      const blockedPage = currentTab.url && /^(chrome-error|chrome):\/\//i.test(currentTab.url);
      statusText.textContent = blockedPage
        ? 'Chrome blocked this page before PhishGuard could inspect it.'
        : 'Waiting for analysis to finish.';
      modelText.textContent = blockedPage ? 'Model: page unavailable' : 'Model: no analysis yet';
      return;
    }

    const score = Number(data.score || 0);
    if (score <= 34) {
      riskBadge.textContent = 'Safe';
      riskBadge.className = 'badge safe';
    } else if (score <= 64) {
      riskBadge.textContent = 'Caution';
      riskBadge.className = 'badge warn';
    } else {
      riskBadge.textContent = 'High risk';
      riskBadge.className = 'badge danger';
    }

    scoreText.textContent = `${score}/100 risk`;
    statusText.textContent = data.label || 'No strong phishing indicators found.';
    const metadata = data.metadata || {};
    const modelVersion = metadata.model_version || 'unknown';
    const modelState = metadata.trained_model_applied ? 'applied' : 'safety gate inactive';
    modelText.textContent = `Model: ${modelVersion} (${modelState})`;

    reasonList.innerHTML = '';
    (data.reasons || []).forEach((reason) => {
      const item = document.createElement('li');
      item.textContent = reason;
      reasonList.appendChild(item);
    });
  });

  document.getElementById('reportBtn').addEventListener('click', () => {
    chrome.storage.local.get(['phishguard_feedback'], (stored) => {
      const feedback = Array.isArray(stored.phishguard_feedback) ? stored.phishguard_feedback : [];
      feedback.unshift({
        tab: currentTab.url,
        timestamp: Date.now(),
        action: 'wrong_result',
        score: Number(resultData.score || 0),
        label: resultData.label || 'unknown'
      });
      chrome.storage.local.set({ phishguard_feedback: feedback.slice(0, 100) });
    });
    statusText.textContent = 'Feedback saved locally.';
  });

  document.getElementById('continueBtn').addEventListener('click', () => {
    window.close();
  });
});
