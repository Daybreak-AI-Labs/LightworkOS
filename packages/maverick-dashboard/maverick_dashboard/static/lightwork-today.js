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
  // The pin controls arrive with the templates card, so listen on the page.
  document.addEventListener('click', function (event) {
    var target = event.target && event.target.closest ? event.target : null;
    if (!target) return;
    if (target.closest('#today-pin-template')) { save(document.getElementById('today-template').value, false); return; }
    var unpin = target.closest('[data-unpin-template]');
    if (unpin) save(unpin.dataset.unpinTemplate, true);
  });

  // Each work source loads on its own (/today/sections/<source>), so a slow
  // source delays only its own cards and shows its own error.
  var loads = {};
  function placeholders(name) {
    return Array.prototype.slice.call(document.querySelectorAll('[data-today-source="' + name + '"]'));
  }
  function failed(name, message) {
    placeholders(name).forEach(function (holder) {
      holder.removeAttribute('aria-busy');
      var status = holder.querySelector('[data-today-status]'); if (!status) return;
      status.textContent = message + ' ';
      var retry = document.createElement('button');
      retry.type = 'button'; retry.className = 'btn btn--ghost'; retry.textContent = 'Try again';
      retry.addEventListener('click', function () { status.textContent = 'Loading…'; holder.setAttribute('aria-busy', 'true'); load(name); });
      status.appendChild(retry);
    });
  }
  async function load(name) {
    if (loads[name]) loads[name].abort();
    var own = loads[name] = new AbortController(), timer = setTimeout(function () { own.abort(); }, 30000);
    try {
      var response = await window.fetch('/today/sections/' + encodeURIComponent(name), {
        credentials: 'same-origin', cache: 'no-store', signal: own.signal, headers: {Accept: 'text/html'}});
      if (response.redirected || response.status === 401) return failed(name, 'Your sign-in has expired. Refresh the page to sign in again.');
      if (!response.ok) return failed(name, 'This could not be loaded just now.');
      var fresh = new DOMParser().parseFromString(await response.text(), 'text/html');
      if (own !== loads[name]) return;
      placeholders(name).forEach(function (holder) {
        var copy = fresh.getElementById(holder.id);
        if (copy) holder.replaceWith(document.importNode(copy, true));
        else holder.remove();
      });
      if (window.mvFormatTimes) window.mvFormatTimes(document.querySelector('main') || document.body);
    } catch (_error) {
      if (own === loads[name]) failed(name, own.signal.aborted ? 'This took too long to load.' : 'This could not be loaded. Check your connection.');
    } finally { clearTimeout(timer); }
  }
  var names = {};
  document.querySelectorAll('[data-today-source]').forEach(function (holder) { names[holder.dataset.todaySource] = true; });
  Object.keys(names).forEach(load);
  window.addEventListener('pagehide', function () {
    if (pending) pending.abort();
    Object.keys(loads).forEach(function (name) { loads[name].abort(); });
  });
  window.addEventListener('pageshow', function (event) { if (event.persisted) window.location.reload(); });
}());
