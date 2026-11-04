/* Shared building blocks for the consent workbench pages: a JSON client that
   fails closed, record tables with row buttons, selectors filled from real
   records, date-picker conversion and in-browser fingerprints. Messages a
   person sees always go through mvErrorText (lightwork-ui.js), never the raw
   server text. */
(function (root) {
  'use strict';
  var doc = root.document;
  var INVALID = 'The reply from the server could not be read. Try again.';

  function el(tag, cls, text) {
    var node = doc.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  // One JSON client per API base (mvFetchJSON). A non-2xx response throws an
  // Error whose .status drives the plain sentence; malformed bodies never
  // count as success.
  function client(base) {
    return async function jsonClient(path, options) {
      var opts = Object.assign({ cache: 'no-store' }, options || {});
      if (opts.json !== undefined) { opts.body = opts.json; delete opts.json; }
      try { return await root.mvFetchJSON(base + path, opts); }
      catch (error) {
        // A refusal without a plain detail keeps the pages' own next step.
        if (!error.unreadable && error.status && typeof error.detail !== 'string') error.message = 'That didn\'t work. Refresh the page and try again.';
        if (!error.unreadable) throw error;
        var bad = new Error(INVALID);
        bad.status = 0;
        throw bad;
      }
    };
  }

  function errorText(failure, action) {
    if (typeof root.mvErrorText === 'function') return root.mvErrorText(failure, action);
    return (action ? 'Could not ' + action + '. ' : '') + 'Something went wrong. Try again.';
  }

  // Write a message into a status line; errors switch it to an alert.
  function say(node, text, isError) {
    if (!node) return;
    node.setAttribute('role', isError ? 'alert' : 'status');
    node.classList.toggle('danger-text', !!isError);
    node.textContent = text || '';
  }
  function fail(node, failure, action) {
    var text = errorText(failure, action);
    say(node, text, true);
    return text;
  }

  // A readable name becomes a stored reference: "Email marketing" -> "email-marketing".
  function slug(text, prefix) {
    var value = String(text || '').toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '')
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 96).replace(/-+$/, '');
    if (!value) value = (prefix || 'item') + '-' + reference().slice(0, 8);
    return value;
  }

  function reference() {
    if (root.crypto && typeof root.crypto.randomUUID === 'function') return root.crypto.randomUUID();
    var bytes = new Uint8Array(16), out = '';
    if (root.crypto && root.crypto.getRandomValues) root.crypto.getRandomValues(bytes);
    else for (var j = 0; j < bytes.length; j++) bytes[j] = Math.floor(Math.random() * 256);
    for (var i = 0; i < bytes.length; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
    return out;
  }

  // <input type="datetime-local"> / type="date" <-> seconds since 1970.
  function toSeconds(value) {
    if (!value) return NaN;
    var when = new Date(value.length === 10 ? value + 'T00:00' : value);
    var ms = when.getTime();
    return Number.isFinite(ms) ? Math.floor(ms / 1000) : NaN;
  }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function toInput(seconds, dateOnly) {
    if (!Number.isFinite(Number(seconds)) || !seconds) return '';
    var d = new Date(Number(seconds) * 1000);
    var day = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
    return dateOnly ? day : day + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function when(seconds) {
    if (typeof root.mvWhen === 'function') return root.mvWhen(Number(seconds));
    if (!seconds || !Number.isFinite(Number(seconds))) return '';
    return (window.mvTimeAbsolute ? window.mvTimeAbsolute(Number(seconds)) : new Date(Number(seconds) * 1000).toLocaleString());
  }
  function human(value) {
    if (typeof root.mvHuman === 'function') return root.mvHuman(value);
    var text = String(value == null ? '' : value).replace(/[_-]+/g, ' ').trim();
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  // Fingerprints are computed here from a chosen file or typed value, never typed.
  async function sha256(data) {
    var bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    var digest = await root.crypto.subtle.digest('SHA-256', bytes);
    return Array.prototype.map.call(new Uint8Array(digest), function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }
  async function sha256File(file) {
    var buffer = typeof file.arrayBuffer === 'function' ? await file.arrayBuffer()
      : await new Promise(function (resolve, reject) {
        var reader = new root.FileReader();
        reader.onload = function () { resolve(reader.result); };
        reader.onerror = function () { reject(reader.error); };
        reader.readAsArrayBuffer(file);
      });
    return sha256(new Uint8Array(buffer));
  }

  // Fill a <select> from records. items: [{value, label}] or strings.
  function fill(select, items, placeholder) {
    var keep = select.value;
    select.replaceChildren();
    if (placeholder) {
      var first = el('option', '', placeholder); first.value = ''; select.appendChild(first);
    }
    (items || []).forEach(function (item) {
      var option = el('option', '', item && item.label !== undefined ? item.label : item);
      option.value = String(item && item.value !== undefined ? item.value : item);
      select.appendChild(option);
    });
    if (keep && Array.prototype.some.call(select.options, function (o) { return o.value === keep; })) select.value = keep;
    return select;
  }

  // Record table with one button per action per row, or an empty state that
  // says what to do next and offers the button to do it.
  // spec: {label, columns:[{label, value(row) -> text|Node}], actions:[{label,
  //   run(row, button), kind:'danger'|'primary', when(row)}], empty:{title,
  //   body, action:{label, run}}}
  function table(host, rows, spec) {
    host.replaceChildren();
    if (!rows || !rows.length) {
      var empty = el('div', 'mv-empty');
      empty.appendChild(el('p', 'mv-empty__title', (spec.empty && spec.empty.title) || 'Nothing here yet.'));
      if (spec.empty && spec.empty.body) empty.appendChild(el('p', 'mv-empty__body', spec.empty.body));
      if (spec.empty && spec.empty.action) {
        var start = el('button', 'btn btn--primary', spec.empty.action.label);
        start.type = 'button';
        start.addEventListener('click', function () { spec.empty.action.run(start); });
        empty.appendChild(start);
      }
      host.appendChild(empty);
      return empty;
    }
    var grid = el('table');
    if (spec.label) grid.appendChild(el('caption', 'sr-only', spec.label));
    var head = el('thead'), headRow = el('tr');
    spec.columns.forEach(function (column) {
      var th = el('th', '', column.label); th.scope = 'col'; headRow.appendChild(th);
    });
    if (spec.actions && spec.actions.length) {
      var actionsHead = el('th', '', 'Actions'); actionsHead.scope = 'col'; headRow.appendChild(actionsHead);
    }
    head.appendChild(headRow); grid.appendChild(head);
    var body = el('tbody');
    rows.forEach(function (row) {
      var tr = el('tr');
      spec.columns.forEach(function (column) {
        var td = el('td'), value = column.value(row);
        if (value && typeof value === 'object' && value.nodeType) td.appendChild(value);
        else td.textContent = value === undefined || value === null ? '' : String(value);
        tr.appendChild(td);
      });
      if (spec.actions && spec.actions.length) {
        var cell = el('td'), box = el('div', 'mv-row__actions');
        spec.actions.forEach(function (action) {
          if (action.when && !action.when(row)) return;
          var button = el('button', 'btn' + (action.kind ? ' btn--' + action.kind : ''),
            typeof action.label === 'function' ? action.label(row) : action.label);
          button.type = 'button';
          var name = spec.name ? spec.name(row) : '';
          if (name) button.setAttribute('aria-label', button.textContent + ': ' + name);
          button.addEventListener('click', function () { action.run(row, button); });
          box.appendChild(button);
        });
        cell.appendChild(box); tr.appendChild(cell);
      }
      body.appendChild(tr);
    });
    grid.appendChild(body); host.appendChild(grid);
    return grid;
  }

  function badge(text, tone) { return el('span', 'badge ' + (tone || 'idle'), text); }

  // Run one action at a time from a button: disables it while pending.
  async function busy(button, work) {
    if (button && button.disabled) return undefined;
    if (button) button.disabled = true;
    try { return await work(); }
    finally { if (button) button.disabled = false; }
  }

  // A definition list summary of a few chosen facts.
  function facts(host, pairs) {
    host.replaceChildren();
    var list = el('dl', 'cw-facts');
    pairs.forEach(function (pair) {
      if (pair[1] === undefined || pair[1] === null || pair[1] === '') return;
      list.appendChild(el('dt', '', pair[0]));
      var dd = el('dd');
      if (pair[1] && typeof pair[1] === 'object' && pair[1].nodeType) dd.appendChild(pair[1]);
      else dd.textContent = String(pair[1]);
      list.appendChild(dd);
    });
    host.appendChild(list);
    return list;
  }

  function confirm(message, okText) {
    if (typeof root.mvConfirm === 'function') return root.mvConfirm(message, { okText: okText || 'Save this change' });
    return Promise.resolve(false);
  }

  function open(section, focusSelector) {
    if (!section) return;
    section.hidden = false;
    if (typeof section.scrollIntoView === 'function') section.scrollIntoView({ block: 'start' });
    var target = focusSelector ? section.querySelector(focusSelector) : section.querySelector('input:not([type=hidden]), select, textarea, button');
    if (target && typeof target.focus === 'function') target.focus();
  }

  // Choices offered by selectors instead of typed codes.
  var COUNTRIES = [
    ['US', 'United States'], ['CA', 'Canada'], ['GB', 'United Kingdom'], ['IE', 'Ireland'],
    ['DE', 'Germany'], ['FR', 'France'], ['ES', 'Spain'], ['IT', 'Italy'], ['NL', 'Netherlands'],
    ['BE', 'Belgium'], ['SE', 'Sweden'], ['DK', 'Denmark'], ['NO', 'Norway'], ['FI', 'Finland'],
    ['PL', 'Poland'], ['PT', 'Portugal'], ['AT', 'Austria'], ['CH', 'Switzerland'], ['AU', 'Australia'],
    ['NZ', 'New Zealand'], ['JP', 'Japan'], ['KR', 'South Korea'], ['SG', 'Singapore'], ['IN', 'India'],
    ['BR', 'Brazil'], ['MX', 'Mexico'], ['ZA', 'South Africa'], ['AE', 'United Arab Emirates'],
  ].map(function (pair) { return { value: pair[0], label: pair[1] }; });
  var JURISDICTIONS = [
    ['global', 'Worldwide'], ['eu', 'European Union'], ['uk', 'United Kingdom'], ['us', 'United States'],
    ['us-ca', 'California'], ['us-co', 'Colorado'], ['us-va', 'Virginia'], ['us-ct', 'Connecticut'],
    ['ca', 'Canada'], ['ca-qc', 'Quebec'], ['br', 'Brazil'], ['au', 'Australia'], ['jp', 'Japan'], ['in', 'India'],
  ].map(function (pair) { return { value: pair[0], label: pair[1] }; });
  var LOCALES = [
    ['en-US', 'English (United States)'], ['en-GB', 'English (United Kingdom)'], ['fr-FR', 'French (France)'],
    ['fr-CA', 'French (Canada)'], ['de-DE', 'German'], ['es-ES', 'Spanish (Spain)'], ['es-MX', 'Spanish (Mexico)'],
    ['it-IT', 'Italian'], ['nl-NL', 'Dutch'], ['pt-BR', 'Portuguese (Brazil)'], ['pt-PT', 'Portuguese (Portugal)'],
    ['sv-SE', 'Swedish'], ['da-DK', 'Danish'], ['pl-PL', 'Polish'], ['ja-JP', 'Japanese'], ['ko-KR', 'Korean'],
    ['zh-CN', 'Chinese (Simplified)'],
  ].map(function (pair) { return { value: pair[0], label: pair[1] }; });
  var CHANNELS = [
    ['all', 'All channels'], ['email', 'Email'], ['sms', 'Text message'], ['phone', 'Phone'],
    ['web', 'Website'], ['mobile_app', 'Mobile app'], ['post', 'Mail'], ['in_person', 'In person'],
  ].map(function (pair) { return { value: pair[0], label: pair[1] }; });
  function labelFor(list, value) {
    for (var i = 0; i < list.length; i++) if (list[i].value === value) return list[i].label;
    return human(value);
  }

  root.LightworkConsentWorkbench = Object.freeze({
    COUNTRIES: COUNTRIES, JURISDICTIONS: JURISDICTIONS, LOCALES: LOCALES, CHANNELS: CHANNELS,
    labelFor: labelFor, INVALID: INVALID, el: el, client: client, errorText: errorText, say: say, fail: fail,
    slug: slug, reference: reference, toSeconds: toSeconds, toInput: toInput, when: when,
    human: human, sha256: sha256, sha256File: sha256File, fill: fill, table: table,
    badge: badge, busy: busy, facts: facts, confirm: confirm, open: open,
  });
})(typeof window === 'undefined' ? globalThis : window);
