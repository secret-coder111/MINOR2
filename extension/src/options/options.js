document.addEventListener('DOMContentLoaded', async () => {
  const reputationEnabled = document.getElementById('reputationEnabled');
  const reputationEndpoint = document.getElementById('reputationEndpoint');
  const warningThreshold = document.getElementById('warningThreshold');
  const thresholdValue = document.getElementById('thresholdValue');
  const status = document.getElementById('status');
  const feedbackStatus = document.getElementById('feedbackStatus');
  const reviewList = document.getElementById('feedbackList');
  const exportButton = document.getElementById('exportFeedback');
  let feedback = [];
  let feedbackBusy = false;
  function updateReputationControls() {
    reputationEndpoint.disabled = !reputationEnabled.checked;
    document.getElementById('reputationMode').textContent = reputationEnabled.checked
      ? 'Hostname lookups will be enabled when you save.' : 'Local analysis only. No reputation requests.';
  }
  reputationEnabled.addEventListener('change', updateReputationControls);
  document.getElementById('resetThreshold').addEventListener('click', () => {
    warningThreshold.value = '65';
    thresholdValue.textContent = '65';
    status.textContent = 'Recommended threshold selected. Save settings to apply it.';
  });

  document.getElementById('saveOptions').disabled = true;
  try {
    const result = await window.PhishGuard.storageCall('local', 'get', ['phishguard_options']);
    const settings = result.phishguard_options || {};
    reputationEnabled.checked = Boolean(settings.reputationEnabled);
    reputationEndpoint.value = settings.reputationEndpoint || '';
    const threshold = Number(settings.warningThreshold);
    warningThreshold.value = String(Number.isFinite(threshold) ? Math.max(35, Math.min(90, threshold)) : 65);
    thresholdValue.textContent = warningThreshold.value;
  } catch (_) { status.textContent = 'Could not load saved settings. Device storage may be unavailable.'; }
  finally { document.getElementById('saveOptions').disabled = false; updateReputationControls(); }

  async function saveOptions() {
    const endpoint = reputationEndpoint.value.trim();
    if (reputationEnabled.checked) {
      try {
        const url = new URL(endpoint);
        if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new Error();
      } catch (_) { status.textContent = 'Enter an HTTPS endpoint without embedded username, password or fragment (HTTP is allowed for localhost development). Settings were not saved.'; return; }
    }
    const button = document.getElementById('saveOptions');
    button.disabled = true;
    status.textContent = 'Saving settings…';
    try {
      await window.PhishGuard.storageCall('local', 'set', { phishguard_options: {
        reputationEnabled: reputationEnabled.checked,
        reputationEndpoint: endpoint,
        warningThreshold: Math.max(35, Math.min(90, Number(warningThreshold.value) || 65))
      } });
      status.textContent = 'Settings saved. Open pages will be rescanned.';
    } catch (_) { status.textContent = 'Could not save settings. Device storage may be unavailable; try again.'; }
    finally { button.disabled = false; }
  }
  warningThreshold.addEventListener('input', () => { thresholdValue.textContent = warningThreshold.value; });
  document.getElementById('saveOptions').addEventListener('click', saveOptions);
  document.getElementById('clearData').addEventListener('click', async () => {
    if (feedbackBusy) return;
    feedbackBusy = true;
    feedbackStatus.textContent = 'Clearing saved corrections…';
    try {
      await window.PhishGuard.storageCall('local', 'remove', 'phishguard_feedback');
      feedback = [];
      renderFeedback();
      feedbackStatus.textContent = 'Saved corrections cleared.';
    } catch (_) { feedbackStatus.textContent = 'Could not clear saved corrections. They may still be on this device; try again.'; }
    finally { feedbackBusy = false; }
  });

  function renderFeedback() {
    reviewList.replaceChildren();
    document.getElementById('feedbackEmpty').hidden = feedback.length > 0;
    exportButton.disabled = !feedback.some((entry) => entry.reviewed);
    document.getElementById('feedbackCount').textContent = `${feedback.length} saved correction(s); ${feedback.filter((entry) => entry.reviewed).length} marked reviewed.`;
    const names = { SAFE: 'Low risk', CAUTION: 'Caution', HIGH_RISK: 'High risk' };
    feedback.forEach((entry) => {
      const item = document.createElement('li');
      const summary = document.createElement('p');
      const date = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'Unknown time';
      summary.textContent = `${entry.topOrigin} — ${names[entry.observedOutcome]} → ${names[entry.expectedOutcome]} (${date}). Evidence origin: ${entry.evidenceOrigin}. Policy: ${entry.policyVersion}.`;
      item.appendChild(summary);
      const context = document.createElement('small');
      context.textContent = `${entry.context.inspectedFrames} document(s) inspected; coverage ${entry.context.coverageComplete ? 'complete for inspectable documents' : 'partial or unknown'}; reputation: ${entry.context.reputationStatus}.`;
      item.appendChild(context);
      const label = document.createElement('label');
      const reviewed = document.createElement('input');
      reviewed.type = 'checkbox';
      reviewed.checked = entry.reviewed;
      reviewed.addEventListener('change', async () => {
        if (feedbackBusy) { reviewed.checked = entry.reviewed; return; }
        feedbackBusy = true;
        reviewed.disabled = true;
        try {
          // Re-read before updating so corrections saved by the popup survive.
          const stored = await window.PhishGuard.storageCall('local', 'get', ['phishguard_feedback']);
          const latest = window.PhishGuard.sanitizeFeedback(stored && stored.phishguard_feedback);
          const candidate = latest.find((value) => value.timestamp === entry.timestamp && value.topOrigin === entry.topOrigin
            && value.expectedOutcome === entry.expectedOutcome && value.observedOutcome === entry.observedOutcome);
          if (!candidate) throw new Error('Correction no longer exists');
          candidate.reviewed = reviewed.checked;
          await window.PhishGuard.storageCall('local', 'set', { phishguard_feedback: latest });
          feedback = latest;
          renderFeedback();
          feedbackStatus.textContent = 'Review status saved. User review does not independently verify a label or change predictions.';
        } catch (_) {
          reviewed.checked = entry.reviewed;
          feedbackStatus.textContent = 'Could not update review status. Reload options and try again.';
        } finally { feedbackBusy = false; reviewed.disabled = false; }
      });
      label.append(reviewed, document.createTextNode(' I checked this correction and want to include it in export'));
      item.appendChild(document.createElement('br'));
      item.appendChild(label);
      reviewList.appendChild(item);
    });
  }

  exportButton.addEventListener('click', async () => {
    try {
      const stored = await window.PhishGuard.storageCall('local', 'get', ['phishguard_feedback']);
      feedback = window.PhishGuard.sanitizeFeedback(stored && stored.phishguard_feedback);
      renderFeedback();
      const reviewed = feedback.filter((entry) => entry.reviewed);
      if (!reviewed.length) { feedbackStatus.textContent = 'Mark at least one checked correction for export.'; return; }
      const payload = { schemaVersion: 1, kind: 'phishguard_user_reviewed_candidates', exportedAt: new Date().toISOString(),
        verifiedGroundTruth: false, automaticLearning: false, corrections: reviewed };
      const href = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = href;
      link.download = `phishguard-reviewed-feedback-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(href), 1000);
      feedbackStatus.textContent = 'Export download requested. The file contains reviewed site origins and annotation context; check it before sharing. Labels still require independent verification.';
    } catch (_) { feedbackStatus.textContent = 'Could not export corrections. Device storage or download support may be unavailable; try again.'; }
  });

  try {
    const stored = await window.PhishGuard.storageCall('local', 'get', ['phishguard_feedback']);
    feedback = window.PhishGuard.sanitizeFeedback(stored && stored.phishguard_feedback);
    renderFeedback();
  } catch (_) { feedbackStatus.textContent = 'Could not load corrections. Device storage may be unavailable.'; }
});
