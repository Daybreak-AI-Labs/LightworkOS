(function () {
  'use strict';
  // Plain sentences only: a failed request becomes a readable message, never
  // the server's own detail text or a browser exception name.
  function errText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  function plainError(text) { var error = new Error(text); error.plain = true; return error; }
  var form = document.getElementById('setup-initialize');
  if (form) form.addEventListener('submit', async function (event) {
    event.preventDefault();
    var button = form.querySelector('button');
    var message = document.getElementById('setup-message');
    if (button.disabled || !form.reportValidity()) return;
    button.disabled = true; message.textContent = 'Saving initial settings…';
    try {
      var response = await fetch('/api/v1/setup/initialize', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({confirm:document.getElementById('setup-confirm').checked})});
      if (!response.ok) throw plainError(errText(response, 'save the initial settings'));
      var result = await response.json();
      if (!result || result.initialized !== true) throw plainError('Initial settings could not be confirmed. Refresh the page and try again.');
      window.location.reload();
    } catch (error) { message.textContent = error && error.plain ? error.message : errText(error, 'save the initial settings'); button.disabled = false; }
  });
  var outcomeForm = document.getElementById('first-outcome-form');
  if (outcomeForm) {
    var select = document.getElementById('first-outcome-department');
    var goalLine = document.getElementById('first-outcome-goal');
    var showGoal = function () {
      var option = select.options[select.selectedIndex];
      if (option && goalLine) goalLine.textContent = 'The task: "' + option.getAttribute('data-goal') + '" The result waits in ' + option.getAttribute('data-lands-in') + '.';
    };
    select.addEventListener('change', showGoal); showGoal();
    outcomeForm.addEventListener('submit', async function (event) {
      event.preventDefault();
      var button = document.getElementById('first-outcome-run');
      var message = document.getElementById('first-outcome-message');
      // No run button until an AI service is ready: never send a request
      // that can only answer "not ready".
      if (!button || button.disabled) return;
      button.disabled = true; message.textContent = 'Creating the sample workspace and starting the task…';
      var opening = false;
      try {
        var response = await fetch('/api/v1/first-outcome/run', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({department:select.value})});
        var result = null;
        try { result = await response.json(); } catch (ignored) { result = null; }
        if (response.status === 409 && result && result.detail && result.detail.ready === false) {
          message.textContent = (window.mvPlainDetail(result.detail.detail) || 'No AI service is ready yet, so the sample task cannot run.') + ' ';
          var link = document.createElement('a'); link.href = result.detail.href; link.textContent = 'Connect an AI service'; message.appendChild(link);
          return;
        }
        if (!response.ok || !result || !result.href) throw plainError(errText(response, 'start the sample task'));
        message.textContent = 'The sample task is running. Its result will wait in ' + result.lands_in + '. Opening it…';
        opening = true; window.location.assign(result.href);
      } catch (error) { message.textContent = error && error.plain ? error.message : errText(error, 'start the sample task'); }
      // The task has started: keep the button off while its page opens, so a
      // second click cannot start the sample again.
      finally { if (!opening) button.disabled = false; }
    });
  }
  var download = document.getElementById('setup-download');
  if (download) download.addEventListener('click', async function () {
    if (download.disabled) return;
    download.disabled = true;
    var message = document.getElementById('setup-report-message');
    message.textContent = 'Preparing setup report…';
    try {
      var response = await fetch('/api/v1/setup/checks', {cache:'no-store'});
      if (!response.ok) throw plainError('The setup report is unavailable. An administrator can download it.');
      var result = await response.json();
      if (!result.runtime || !result.assurance) throw plainError('The setup report could not be verified. Refresh the page and try again.');
      var url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], {type:'application/json'}));
      var link = document.createElement('a'); link.href = url; link.download = 'Lightwork-setup-report.json'; link.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      message.textContent = 'Setup report downloaded. Live connections still need separate testing.';
    } catch (error) { message.textContent = error && error.plain ? error.message : errText(error, 'prepare the setup report'); }
    finally { download.disabled = false; }
  });
})();
