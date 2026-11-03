(() => {
  const choices = Array.from(document.querySelectorAll('[data-observation]'));
  const summary = document.getElementById('observationSummary');
  function render() {
    summary.replaceChildren();
    let completed = 0;
    choices.forEach((choice) => {
      choice.closest('[data-observation-card]').classList.toggle('observation-recorded', Boolean(choice.value));
      if (!choice.value) return;
      completed += 1;
      const item = document.createElement('li');
      item.textContent = `${choice.closest('[data-observation-card]').querySelector('h2').textContent}: ${choice.value}`;
      summary.appendChild(item);
    });
    if (!completed) {
      const item = document.createElement('li');
      item.textContent = 'No observations recorded yet.';
      summary.appendChild(item);
    }
    document.getElementById('observationProgress').textContent = `${completed} of ${choices.length} examples recorded.`;
    const meter = document.getElementById('observationMeter');
    if (meter) { meter.max = choices.length; meter.value = completed; }
  }
  choices.forEach((choice) => choice.addEventListener('change', render));
  document.getElementById('resetObservations').addEventListener('click', () => {
    choices.forEach((choice) => { choice.value = ''; });
    render();
  });
})();
