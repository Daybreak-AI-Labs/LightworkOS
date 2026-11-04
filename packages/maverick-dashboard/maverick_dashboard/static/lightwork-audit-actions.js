/* Exact native audit reviews and result reads; effect requests never retry. */
(function () {
  'use strict';
  var root = document.getElementById('maintenance-results');
  if (!root) return;
  var reviewPanel = document.getElementById('audit-maintenance-review');
  var saved = document.getElementById('audit-maintenance-saved');
  var message = document.getElementById('audit-maintenance-message');
  var loadingText = message.textContent;
  var current = null, busy = false, account = '', epoch = 0;
  function el(tag, text, css) { var e = document.createElement(tag); if (text) e.textContent = text; if (css) e.className = css; return e; }
  function say(text) { window.mvStatus ? window.mvStatus(message, text) : (message.textContent = text); }
  function lock(value) {
    busy = value;
    root.querySelectorAll('button').forEach(function (b) { b.disabled = value; });
    ['aud-seal', 'aud-worm-push'].forEach(function (id) { var b = document.getElementById(id); if (b) b.disabled = value; });
  }
  function button(text, handler, css) {
    var b = el('button', text, css || 'btn btn--ghost'); b.type = 'button'; b.disabled = busy;
    b.addEventListener('click', async function () {
      if (busy) return;
      lock(true);
      try { await handler(); } catch (e) { say(error(e)); if (e.status === 403) clear(); }
      finally { lock(false); }
    }); return b;
  }
  function error(e) { return window.mvPlainDetail(e.detail) || window.mvErrorText(e, 'read the saved maintenance result'); }
  async function call(url, body) {
    var started = epoch;
    var value = await window.mvFetchJSON(url, {method: body ? 'POST' : 'GET', body: body, timeout: 15000,
      onAccess: clear}, 'read the maintenance review');
    if (started !== epoch) throw {status: 409, detail: 'Your account or workspace changed. Reopen saved maintenance results before continuing.'};
    return value;
  }
  function path(value) { return '/api/v1/audit/action-reviews/' + encodeURIComponent(value.review); }
  function clear() { epoch += 1; current = null; reviewPanel.textContent = ''; reviewPanel.hidden = true; saved.textContent = ''; account = ''; }
  function nonce() { var bytes = new Uint8Array(16); crypto.getRandomValues(bytes); return Array.from(bytes, function (b) { return b.toString(16).padStart(2, '0'); }).join(''); }
  function date(value) { return new Date(value * 1000).toLocaleString(); }
  function state(value) {
    return {prepared: 'Awaiting your review', reserved: 'Original result uncertain', unknown: 'Original result uncertain',
      confirmed: 'Original request completed', failed: 'Completed with problems', cancelled: 'Cancelled'}[value] || 'Unavailable';
  }
  function present(value) {
    current = value;
    reviewPanel.textContent = ''; reviewPanel.hidden = false;
    var title = el('h3', value.action === 'seal' ? 'Review encryption of closed days' : 'Review copies of closed days');
    title.tabIndex = -1; reviewPanel.appendChild(title);
    reviewPanel.appendChild(el('p', value.message));
    reviewPanel.appendChild(el('p', 'Source: ' + value.source + '. Recorded ' + date(value.recorded_at) + '. Today’s activity is excluded.', 'muted'));
    if (value.state === 'prepared') reviewPanel.appendChild(el('p', 'This review expires ' + date(value.expires) + '.', 'muted'));
    if (value.destination && value.destination.location) {
      reviewPanel.appendChild(el('p', 'Destination: ' + value.destination.provider + ' · ' + value.destination.location));
      reviewPanel.appendChild(el('p', 'Protection: ' + value.destination.mode + '. ' + value.destination.protection));
      reviewPanel.appendChild(el('p', 'New copies: retention through ' + new Date(value.retain_until).toLocaleString() + ' (' + value.destination.retention_days + ' days at review). Existing copies are checked against their own recorded retention, shown below.'));
    }
    if (!value.rows.length) reviewPanel.appendChild(el('p', 'No closed days are available. No storage availability or copy protection was established.'));
    var columns = ['Closed day (UTC)', 'Size', 'Source protection', 'Reviewed action / original result'];
    var wrap = el('div', '', 'table-scroll'), table = el('table', '', 'table'), head = el('thead'), tr = el('tr');
    table.setAttribute('role', 'table'); head.setAttribute('role', 'rowgroup'); tr.setAttribute('role', 'row');
    columns.forEach(function (text) { var th = el('th', text); th.scope = 'col'; th.setAttribute('role', 'columnheader'); tr.appendChild(th); });
    head.appendChild(tr); table.appendChild(head); var body = el('tbody');
    body.setAttribute('role', 'rowgroup');
    value.rows.forEach(function (row) {
      var r = el('tr'); r.setAttribute('role', 'row'); [row.day, row.bytes.toLocaleString() + ' bytes', row.encrypted ? 'Encrypted' : 'Unencrypted',
        {sealed: 'Encrypted by this request', copied: 'Copied and retention proof checked by this request', already_present: 'Existing copy checked',
         unknown: 'Original result uncertain; no repeat', failed: 'Could not be changed'}[row.status] || row.status].forEach(function (text, index) {
           var cell = el('td', text); cell.dataset.label = columns[index]; cell.setAttribute('role', 'cell'); r.appendChild(cell);
         });
      if (row.existing_retention) r.lastChild.appendChild(el('p', 'Existing recorded retention through ' + new Date(row.existing_retention).toLocaleString() + '. Availability is checked at confirmation.', 'muted'));
      body.appendChild(r);
    }); table.appendChild(body); wrap.appendChild(table); reviewPanel.appendChild(wrap);
    var actions = el('div', '', 'aud-actions');
    var acknowledgment = null;
    if (value.reconcile && value.state === 'prepared') {
      var label = el('label'); acknowledgment = el('input'); acknowledgment.type = 'checkbox';
      label.appendChild(acknowledgment); label.appendChild(document.createTextNode(' I understand an earlier copy may already exist and remains unknown. This separate request may create another retained version.'));
      reviewPanel.appendChild(label);
    }
    if (value.state === 'prepared' && value.rows.some(function (row) { return row.selected; })) {
      actions.appendChild(button(value.reconcile ? 'Make this separately reviewed copy' : value.action === 'seal' ? 'Encrypt these reviewed days' : 'Copy these reviewed days', async function () {
        if (!current || current.review !== value.review) return;
        if (value.reconcile && (!acknowledgment || !acknowledgment.checked)) { say('Acknowledge the earlier uncertain effect before authorizing this separate copy.'); return; }
        var operation = nonce();
        say('Starting the reviewed request. If the reply is interrupted, read its original result here.');
        try {
          var completed = await call(value.action === 'seal' ? '/api/v1/audit/seal' : '/api/v1/audit/write-once/push',
            {preview: false, review: value.review, operation: operation, acknowledge_uncertain: !!(acknowledgment && acknowledgment.checked)});
          present(completed); say(completed.message);
        } catch (failure) {
          say(error(failure) + ' Reading the saved original result; the effect will not be sent again.');
          try { var original = await call(path(value)); present(original); say(original.message); }
          catch (unavailable) { say('The original reply was interrupted and its saved result is unavailable. Use “Read original result” before considering another action.'); }
        }
        await load();
      }, 'btn btn--primary'));
    }
    if (value.state === 'prepared') actions.appendChild(button('Cancel this review', async function () {
      var cancelled = await call(path(value) + '/cancel', {}); present(cancelled); say(cancelled.message); await load();
    }));
    actions.appendChild(button('Read original result', async function () { var receipt = await call(path(value)); present(receipt); say(receipt.message); await load(); }));
    var exportLink = el('a', 'Download review details', 'btn btn--ghost'); exportLink.href = path(value) + '/evidence'; exportLink.setAttribute('download', ''); actions.appendChild(exportLink);
    reviewPanel.appendChild(actions); title.focus();
  }
  async function load() {
    var value = await call('/api/v1/audit/action-reviews');
    if (account && account !== value.context) clear();
    account = value.context; saved.textContent = '';
    if (value.observation_problem) saved.appendChild(el('p', value.observation_problem));
    (value.native_unknown || []).forEach(function (row) {
      var destination = row.destination || {}, location = destination.directory || (destination.bucket ? destination.bucket + '/' + (destination.prefix || '') : 'operator-supplied storage');
      saved.appendChild(el('p', 'Uncertain earlier copy of ' + row.day + ' · ' + location + ' · attempted ' + new Date(row.attempted_at).toLocaleString() + '. ' + row.meaning));
    });
    var separate = document.getElementById('audit-maintenance-separate'); if (separate) separate.hidden = !value.separate_copy_available;
    // Loaded: the first-load line goes; a message from an action stays.
    if (message.textContent === loadingText) say('');
    if (!value.reviews.length) saved.appendChild(window.mvEmpty((window.LightworkI18n ? window.LightworkI18n.text('No maintenance reviews saved yet') : 'No maintenance reviews saved yet'),
      (window.LightworkI18n ? window.LightworkI18n.text('Encryption and storage-copy reviews you start above are kept here for this account and workspace.') : 'Encryption and storage-copy reviews you start above are kept here for this account and workspace.'), null, {compact: true}));
    value.reviews.forEach(function (row) {
      var line = el('div', '', 'aud-actions');
      line.appendChild(el('span', (row.action === 'seal' ? 'Encryption' : 'Storage copy') + ' · ' + date(row.recorded_at) + ' · ' + state(row.state)));
      line.appendChild(button(row.state === 'prepared' ? 'Open review' : 'Read original result', async function () { present(await call(path(row))); }));
      saved.appendChild(line);
    });
  }
  [['aud-seal', 'seal'], ['aud-worm-push', 'copy']].forEach(function (entry) {
    var b = document.getElementById(entry[0]); if (!b) return;
    b.addEventListener('click', async function () {
      if (busy) return; lock(true); say('Checking the exact closed days and storage settings…');
      try { present(await call(entry[1] === 'seal' ? '/api/v1/audit/seal' : '/api/v1/audit/write-once/push', {preview: true})); await load(); say('Review all listed days and protection before continuing.'); }
      catch (e) { say(error(e)); if (e.status === 403) clear(); }
      finally { lock(false); }
    });
  });
  var separate = document.getElementById('audit-maintenance-separate');
  if (separate) separate.addEventListener('click', async function () {
    if (busy) return; lock(true);
    try { present(await call('/api/v1/audit/write-once/push', {preview: true, reconcile: true})); say('Review the full current source, destination and retention. Acknowledge that a copy may already exist before authorizing this separate request.'); }
    catch (e) { say(error(e)); if (e.status === 403) clear(); }
    finally { lock(false); }
  });
  window.addEventListener('lightwork:context-changed', clear);
  document.addEventListener('lightwork:copilot-context-changed', clear);
  document.addEventListener('lightwork:access-changed', clear);
  window.addEventListener('pageshow', function (event) { if (event.persisted) { clear(); load().catch(function (e) { say(error(e)); }); } });
  load().catch(function (e) { say(error(e)); if (e.status === 403) clear(); });
})();
