/* Full setup guide: check and install a prepared settings file. */
(function () {
  'use strict';
  var form = document.getElementById('guide-file-form');
  if (!form) return;
  var input = document.getElementById('guide-file-input');
  var install = document.getElementById('guide-file-install');
  var status = document.getElementById('guide-file-status');
  var out = document.getElementById('guide-file-out');
  var reviewed = null, busy = false;
  input.addEventListener('change', function () { reviewed = null; install.hidden = true; status.textContent = 'Check the selected file before installing it.'; });
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  async function failText(failure, action) {
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
    if (plain) return plain;
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function send(path, file) {
    return window.mvFetchJSON(path, {method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: file});
  }
  function recoveryActions(token) {
    var check = el('button', 'btn btn--ghost', 'Check installation result'); check.type = 'button';
    check.addEventListener('click', async function () {
      check.disabled = true;
      try {
        var result = await window.mvFetchJSON('/api/v1/setup/settings-file/result/' + encodeURIComponent(token), {cache:'no-store'});
        status.textContent = result.summary;
        if (result.matches_review && result.audit_pending) {
          var reconcile = el('button','btn btn--ghost','Record confirmed current file'); reconcile.type = 'button';
          reconcile.addEventListener('click', async function () {
            reconcile.disabled = true;
            try { var done = await send('/api/v1/setup/settings-file/reconcile/' + encodeURIComponent(token), ''); status.textContent = done.summary; reconcile.remove(); }
            catch (failure) { status.textContent = await failText(failure,'record the current file'); reconcile.disabled = false; }
          }); out.appendChild(reconcile);
        }
      } catch (failure) { status.textContent = await failText(failure,'check the installation result'); }
      finally { check.disabled = false; }
    }); out.appendChild(check);
  }
  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (busy) return;
    busy = true; reviewed = null;
    install.hidden = true;
    out.textContent = '';
    var file = input.files[0];
    if (!file) { busy = false; status.textContent = 'Choose a settings file first.'; return; }
    status.textContent = 'Checking the file…';
    try {
      var data = await send('/api/v1/setup/settings-file/check', file);
      if (input.files[0] !== file) return;
      reviewed = data.valid ? {file: file, token: data.review} : null;
      status.textContent = data.summary;
      var impact = el('ul');
      (data.impact || []).forEach(function (item) { impact.appendChild(el('li', null, (item.change ? item.change + ' - ' : '') + item.label + ': ' + JSON.stringify(item.before) + ' → ' + JSON.stringify(item.after) + '. ' + item.impact + '. ' + item.source + (item.overridden ? ' (file choice is overridden)' : ''))); });
      out.appendChild(impact);
      if (data.technical && data.technical.length) {
        var details = el('details'); details.open = !data.valid;
        details.appendChild(el('summary', null, data.valid ? 'Notes about this file' : 'Settings to correct'));
        var ul = el('ul'); data.technical.forEach(function (t) { ul.appendChild(el('li', 'muted', t.text)); });
        details.appendChild(ul); out.appendChild(details);
      }
      if (!data.valid) {
        var settings = el('a', 'btn btn--ghost', 'Change settings in Lightwork');
        settings.href = '/settings/all'; out.appendChild(settings);
      }
      install.hidden = !data.valid;
    } catch (failure) { status.textContent = await failText(failure, 'check the file'); } finally { busy = false; }
  });
  install.addEventListener('click', async function () {
    if (busy || !reviewed || reviewed.file !== input.files[0]) return;
    busy = true;
    var file = reviewed.file, token = reviewed.token;
    if (!file) { busy = false; status.textContent = 'Choose a settings file first.'; return; }
    var ok = window.mvConfirm ? await window.mvConfirm('Replace this installation\'s settings with this file? The current settings file is kept as a backup copy.', {okText: 'Install'}) : false;
    if (!ok) { busy = false; return; }
    install.hidden = true;
    status.textContent = 'Installing…';
    try {
      var data = await send('/api/v1/setup/settings-file/install?confirm=true&review=' + encodeURIComponent(token), file);
      status.textContent = data.summary + (data.audit_pending ? ' The activity receipt is pending; the installation itself is confirmed.' : '');
      if (data.audit_pending) recoveryActions(token);
    } catch (failure) {
      status.textContent = await failText(failure, 'install the settings file');
      recoveryActions(token);
    } finally { busy = false; }
  });
})();
