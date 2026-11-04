// Small helpers shared by the compliance and privacy workflow pages: load a
// record list on page load, render it as a table with a button per row, run
// an action with a confirmation, and report the outcome in plain words.
// Record references, versions and request keys are carried from the chosen
// row or generated here, never typed by a person.
(function (global) {
  'use strict';
  var doc = global.document;

  function human(value) {
    if (value === null || value === undefined || value === '') return '';
    if (global.mvHuman) return global.mvHuman(value);
    var s = String(value).replace(/[_-]+/g, ' ').trim();
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function when(ts) {
    if (!ts || !isFinite(ts)) return '';
    if (global.mvWhen) return global.mvWhen(ts);
    try { return (window.mvTimeAbsolute ? window.mvTimeAbsolute(ts) : new Date(ts * 1000).toLocaleString()); } catch (e) { return ''; }
  }

  function day(ts) {
    if (!ts || !isFinite(ts)) return '';
    try { return (window.mvDateAbsolute ? window.mvDateAbsolute(ts) : new Date(ts * 1000).toLocaleDateString()); } catch (e) { return ''; }
  }

  function errorText(failure, action) {
    if (global.mvErrorText) return global.mvErrorText(failure, action);
    return 'Could not ' + action + '. Try again.';
  }

  // One JSON request (mvFetchJSON). A refusal rejects with the shared plain
  // sentence; an empty answer is an empty record.
  function call(method, url, body) {
    return global.mvFetchJSON(url, { method: method || 'GET', body: body === null ? undefined : body })
      .then(function (data) { return data || {}; });
  }

  function randomPart(length) {
    var alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    var out = '';
    var bytes = new Uint8Array(length);
    if (global.crypto && global.crypto.getRandomValues) global.crypto.getRandomValues(bytes);
    else for (var i = 0; i < length; i++) bytes[i] = Math.floor(Math.random() * 256);
    for (var j = 0; j < length; j++) out += alphabet[bytes[j] % alphabet.length];
    return out;
  }

  // A fresh record reference like "assessment-20260927-k3x9q2".
  function newId(prefix) {
    var d = new Date();
    var stamp = String(d.getFullYear()) + ('0' + (d.getMonth() + 1)).slice(-2) + ('0' + d.getDate()).slice(-2);
    return (prefix || 'record') + '-' + stamp + '-' + randomPart(6);
  }

  // A fresh request key (for safe retries); never shown to anyone.
  function newKey() {
    if (global.crypto && typeof global.crypto.randomUUID === 'function') return global.crypto.randomUUID();
    return 'req-' + randomPart(24);
  }

  function slug(text, fallback) {
    var s = String(text || '').toLowerCase();
    if (s.normalize) s = s.normalize('NFKD');
    s = s.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
    return s || fallback || 'item';
  }

  // "2026-10-01" or "2026-10-01T09:30" from a date / datetime-local input
  // to Unix seconds (local time).
  function toEpoch(value) {
    if (!value) return null;
    var t = new Date(value.length <= 10 ? value + 'T23:59:59' : value).getTime();
    return isFinite(t) ? Math.floor(t / 1000) : null;
  }

  function isoDateIn(days) {
    var d = new Date(Date.now() + days * 86400000);
    return d.toISOString().slice(0, 10);
  }

  function el(tag, cls, text) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  function button(label, kind, handler) {
    var b = el('button', 'btn ' + (kind === 'primary' ? 'btn--primary' : kind === 'danger' ? 'btn--danger' : 'btn--ghost'), label);
    b.type = 'button';
    b.addEventListener('click', function () { handler(b); });
    return b;
  }

  // Render rows as a table. columns: [{label, value(row) -> text|Node}].
  // actions: [{label, kind, when(row) -> bool, run(row, button)}].
  // empty: {text, action: {label, run}} shown when there are no rows.
  function table(container, columns, rows, actions, empty) {
    container.textContent = '';
    if (!rows || !rows.length) {
      var p = el('p', 'muted', (empty && empty.text) || 'Nothing here yet. Items appear here once they are added.');
      container.appendChild(p);
      if (empty && empty.action) container.appendChild(button(empty.action.label, 'primary', empty.action.run));
      return;
    }
    var wrap = el('div');
    wrap.style.overflowX = 'auto';
    var t = el('table');
    var head = el('tr');
    columns.forEach(function (c) { var th = el('th', '', c.label); th.scope = 'col'; head.appendChild(th); });
    if (actions && actions.length) { var th = el('th', '', 'Actions'); th.scope = 'col'; head.appendChild(th); }
    var thead = el('thead'); thead.appendChild(head); t.appendChild(thead);
    var tbody = el('tbody');
    rows.forEach(function (row) {
      var tr = el('tr');
      columns.forEach(function (c) {
        var td = el('td');
        var v = c.value(row);
        if (v && typeof v === 'object' && v.nodeType) td.appendChild(v);
        else td.textContent = v === undefined || v === null || v === '' ? '—' : String(v);
        tr.appendChild(td);
      });
      if (actions && actions.length) {
        var cell = el('td');
        var box = el('div');
        box.style.display = 'flex'; box.style.gap = '.4rem'; box.style.flexWrap = 'wrap';
        actions.forEach(function (a) {
          if (a.when && !a.when(row)) return;
          box.appendChild(button(a.label, a.kind, function (b) { a.run(row, b); }));
        });
        if (!box.childNodes.length) box.appendChild(el('span', 'muted', 'No actions'));
        cell.appendChild(box);
        tr.appendChild(cell);
      }
      tbody.appendChild(tr);
    });
    t.appendChild(tbody);
    wrap.appendChild(t);
    container.appendChild(wrap);
  }

  function badge(text, kind) { return el('span', 'badge ' + (kind || 'info'), text); }

  function confirm(message, okText) {
    return global.mvConfirm ? global.mvConfirm(message, { okText: okText || 'Save this change' }) : Promise.resolve(false);
  }

  function form(title, fields, okText) {
    return global.mvForm ? global.mvForm(title, fields, { okText: okText || 'Save' }) : Promise.resolve(null);
  }

  // Server-side fingerprint of an uploaded file (nothing is stored).
  function fingerprint(file) {
    return global.mvFetchJSON('/api/v1/compliance/fingerprint', {
      method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file,
    });
  }

  // Ask for a file with a hidden picker; resolves to the File or null.
  function pickFile(accept) {
    return new Promise(function (resolve) {
      var input = el('input');
      input.type = 'file';
      if (accept) input.accept = accept;
      input.hidden = true;
      input.addEventListener('change', function () {
        var f = input.files && input.files[0];
        input.remove();
        resolve(f || null);
      });
      doc.body.appendChild(input);
      input.click();
    });
  }

  function download(name, data, type) {
    var blob = new global.Blob([typeof data === 'string' ? data : JSON.stringify(data, null, 2)],
      { type: type || 'application/json' });
    var url = global.URL.createObjectURL(blob);
    var a = el('a');
    a.href = url; a.download = name; doc.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { global.URL.revokeObjectURL(url); }, 1000);
  }

  global.LwRecords = {
    human: human, when: when, day: day, errorText: errorText, call: call,
    newId: newId, newKey: newKey, slug: slug, toEpoch: toEpoch, isoDateIn: isoDateIn,
    el: el, button: button, table: table, badge: badge, confirm: confirm, form: form,
    fingerprint: fingerprint, pickFile: pickFile, download: download,
  };
})(typeof window !== 'undefined' ? window : this);
