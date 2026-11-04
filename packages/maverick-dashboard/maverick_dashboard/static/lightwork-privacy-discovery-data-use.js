(function (global) {
  'use strict';
  var root = document.getElementById('pddb-root');
  if (!root) return;
  var R = global.LwRecords, catalog = null, saved = null, review = null, busy = false;
  var base = '/api/v1/privacy/data-discovery/data-use', storageKey = null;
  function el(id) { return document.getElementById('pddb-' + id); }
  function say(text) { const line = el('status'); if (typeof window.mvStatus === 'function') window.mvStatus(line, text); else line.textContent = text; }
  function human(value) { return R.human(value); }
  function call(path, method, body) { return R.call(method || 'GET', base + path, body); }
  function error(failure, action) { return failure && failure.message || R.errorText(failure, action); }
  function persist(value) {
    try {
      if (value) { global.localStorage.setItem(storageKey, JSON.stringify(value)); }
      else global.localStorage.removeItem(storageKey);
    } catch (_) { throw new Error('Allow this browser to remember the saved request before updating a dataset. Your choices are kept.'); }
    saved = value;
  }
  function controls() {
    ['report', 'dataset', 'prepare'].forEach(function (name) { el(name).disabled = busy || !catalog || !!saved; });
    el('refresh').disabled = busy || !!saved;
    el('apply').disabled = busy || !saved || saved.phase !== 'review' || !review || review.expires_at <= Date.now() / 1000;
    el('original').disabled = busy || !saved;
    el('new').disabled = busy || (saved && !['review', 'complete', 'not_saved', 'withdrawn'].includes(saved.phase));
    el('review').hidden = !saved;
    el('form').hidden = !!saved;
  }
  function options(target, rows, label, placeholder) {
    var previous = target.value;
    target.textContent = '';
    var first = document.createElement('option'); first.value = ''; first.textContent = placeholder; target.appendChild(first);
    rows.forEach(function (row) { var item = document.createElement('option'); item.value = row.id; item.textContent = label(row); target.appendChild(item); });
    if (rows.some(function (row) { return row.id === previous; })) target.value = previous;
  }
  async function refresh() {
    var value = await call('/choices');
    if (catalog && value.context !== catalog.context) throw new Error('Your account or workspace changed. Reload the page before continuing.');
    catalog = value; storageKey = 'lightwork.discovery-data-use.' + value.context;
    options(el('report'), value.reports, function (row) { return human(row.source_name) + ' · ' + R.when(row.finished_at) + ' · ' + row.findings + ' findings'; }, 'Choose a scan report');
    options(el('dataset'), value.datasets, function (row) { return human(row.name); }, 'Choose a saved dataset');
    el('scope').textContent = value.scope;
    controls();
    return value;
  }
  function show(value) {
    if (value.outcome === 'withdrawn') {
      review = null;
      el('categories').hidden = true;
      el('summary').textContent = 'Saved request status';
      ['before', 'after', 'impact', 'expiry'].forEach(function (name) { el(name).textContent = ''; });
      persist({context: saved.context, reference: saved.reference, phase: value.can_close ? 'withdrawn' : 'unconfirmed'});
      controls(); say(value.message + ' No update was repeated.'); return;
    }
    review = value;
    el('categories').hidden = false;
    el('summary').textContent = human(value.dataset) + ' · ' + value.findings + ' reviewed findings from ' + human(value.source);
    el('before').textContent = value.before.length ? value.before.map(human).join(', ') : 'No personal-data categories recorded';
    el('after').textContent = value.after.map(human).join(', ');
    el('impact').textContent = value.scope;
    el('expiry').textContent = value.outcome === 'complete' ? 'Saved ' + R.when(value.completed_at) : 'Confirm by ' + R.when(value.expires_at) + '.';
    persist({context: saved.context, reference: saved.reference, phase: value.outcome === 'review' ? 'review' : value.outcome,
      proposal_sha256: value.proposal_sha256});
    controls();
    say(value.outcome === 'complete' ? (value.changed ? 'The dataset was updated. No update was repeated.' : 'The dataset already had these exact approved categories. No update was repeated.') :
      value.outcome === 'unconfirmed' ? 'An update was attempted, but its outcome is not confirmed. The request is kept. Read its saved outcome; do not repeat it.' : 'Check the dataset and approved categories, then confirm the update.');
  }
  async function original() {
    if (!saved || busy) return;
    busy = true; controls();
    try { show(await call('/original/' + encodeURIComponent(saved.reference) + '?context=' + encodeURIComponent(saved.context))); }
    catch (failure) {
      if (failure && failure.status === 404 && saved.phase === 'preparing') {
        saved.phase = 'not_saved'; persist(saved); say('No saved review was found. No dataset update was sent. You can choose another report.');
      } else say(error(failure, 'read the saved outcome') + ' Your request is kept. No update was repeated.');
    } finally { busy = false; controls(); }
  }
  el('form').addEventListener('submit', async function (event) {
    event.preventDefault();
    if (busy || saved || !catalog || !el('form').reportValidity()) return;
    busy = true; controls();
    try {
      persist({context: catalog.context, reference: R.newKey(), phase: 'preparing'});
      show(await call('/prepare', 'POST', {context: catalog.context, inventory: catalog.inventory,
        reference: saved.reference, report_id: el('report').value, asset_id: el('dataset').value}));
    } catch (failure) { say(error(failure, 'prepare the dataset update') + (saved ? ' Your request is kept. Read its saved outcome before continuing.' : '')); }
    finally { busy = false; controls(); }
  });
  el('apply').addEventListener('click', async function () {
    if (busy || !saved || !review || saved.phase !== 'review') return;
    busy = true; controls();
    try {
      persist({context: saved.context, reference: saved.reference, proposal_sha256: saved.proposal_sha256, phase: 'applying'});
      show(await call('/apply', 'POST', {context: saved.context, reference: saved.reference, proposal_sha256: saved.proposal_sha256}));
    } catch (failure) { say(error(failure, 'update the dataset') + ' Your request is kept. Read its saved outcome; do not repeat the update.'); }
    finally { busy = false; controls(); }
  });
  el('original').addEventListener('click', original);
  el('new').addEventListener('click', function () {
    if (busy || !saved || !['review', 'complete', 'not_saved', 'withdrawn'].includes(saved.phase)) return;
    try { persist(null); review = null; controls(); el('report').focus(); say('Choose the report and dataset for a new review.'); }
    catch (failure) { say(error(failure, 'open a new review')); }
  });
  el('refresh').addEventListener('click', async function () {
    if (busy || saved) return; busy = true; controls();
    try { await refresh(); say('The available choices are current.'); } catch (failure) { say(error(failure, 'refresh choices')); }
    finally { busy = false; controls(); }
  });
  global.LightworkDiscoveryDataUse = {
    openReview: async function (context, isCurrent) {
      if (!/^[0-9a-f]{64}$/.test(context || '') || typeof isCurrent !== 'function' || !isCurrent() || busy || saved) {
        say('Your current work is kept. Finish or read the saved review before opening another.'); return false;
      }
      busy = true; controls();
      try {
        var report = el('report').value, dataset = el('dataset').value;
        var value = await call('/choices');
        if (!isCurrent() || value.context !== context || saved || report !== el('report').value || dataset !== el('dataset').value ||
            ((report || dataset) && catalog && value.inventory !== catalog.inventory)) {
          say('Your current choices are kept. Refresh them yourself before opening another review.'); return false;
        }
        catalog = value; storageKey = 'lightwork.discovery-data-use.' + value.context;
        options(el('report'), value.reports, function (row) { return human(row.source_name) + ' · ' + R.when(row.finished_at) + ' · ' + row.findings + ' findings'; }, 'Choose a scan report');
        options(el('dataset'), value.datasets, function (row) { return human(row.name); }, 'Choose a saved dataset');
        el('scope').textContent = value.scope;
        busy = false; controls(); root.scrollIntoView({block: 'center'}); el('report').focus(); return true;
      } catch (failure) { say(error(failure, 'open dataset review')); return false; }
      finally { busy = false; controls(); }
    }
  };
  (async function () {
    busy = true; controls();
    try {
      await refresh();
      var raw = global.localStorage.getItem(storageKey);
      if (raw) {
        var retained = JSON.parse(raw);
        if (retained.context === catalog.context && /^[a-zA-Z0-9][a-zA-Z0-9_-]{15,95}$/.test(retained.reference || '') &&
            ['preparing', 'review', 'applying', 'unconfirmed', 'complete', 'not_saved', 'withdrawn'].includes(retained.phase)) saved = retained;
      }
      say(saved ? 'Your saved request is kept. Reading its original outcome…' : 'Choose a report and the dataset it describes.');
    } catch (failure) { say(error(failure, 'load available reports and datasets')); }
    finally { busy = false; controls(); }
    if (saved) await original();
  })();
})(window);
