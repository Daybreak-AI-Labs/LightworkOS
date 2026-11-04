(function () {
  'use strict';
  var source = document.getElementById('today-preferences'); if (!source) return;
  var model = JSON.parse(source.textContent), busy = false, pending = null;
  async function save(name, remove) {
    if (busy) return;
    var pins = model.pins.filter(function (value) { return value !== name; }); if (!remove) pins.push(name);
    busy = true; pending = new AbortController(); var own = pending, timer = setTimeout(function () { own.abort(); }, 20000);
    var status = document.getElementById('today-pin-status'); status.textContent = 'Saving your template pins.';
    try {
      var result = await window.mvFetchJSON('/api/v1/preferences', {method: 'POST', cache: 'no-store', signal: own.signal, plainDetail: true,
        body: {context: model.context, expected_revision: model.revision, scope: 'personal', changes: {template_favorites: pins}}}, 'save your template pins');
      if (result.context !== model.context) throw new Error('Your account or workspace changed. Refresh Today.');
      window.location.reload();
    } catch (error) { status.textContent = own.signal.aborted ? 'The save response was interrupted. Refresh to check the saved pins before trying again.' : error.message; }
    finally { clearTimeout(timer); busy = false; }
  }
  var add = document.getElementById('today-pin-template'); if (add) add.addEventListener('click', function () { save(document.getElementById('today-template').value, false); });
  document.querySelectorAll('[data-unpin-template]').forEach(function (button) { button.addEventListener('click', function () { save(button.dataset.unpinTemplate, true); }); });
  window.addEventListener('pagehide', function () { if (pending) pending.abort(); });
  window.addEventListener('pageshow', function (event) { if (event.persisted) window.location.reload(); });
}());
