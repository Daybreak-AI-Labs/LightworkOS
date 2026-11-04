/* Finance page: the tax preparation suite (first draft, firm readiness,
   test on past returns, tax table updates). The server checks every
   permission and recomputes everything; nothing here is ever filed. */
(function () {
  'use strict';

  var root = document.getElementById('tax-root');
  if (!root) return;
  var API = '/api/v1/tax';
  var STATE_NAMES = {AL: 'Alabama', AK: 'Alaska', AZ: 'Arizona', AR: 'Arkansas', CA: 'California', CO: 'Colorado',
    CT: 'Connecticut', DE: 'Delaware', DC: 'District of Columbia', FL: 'Florida', GA: 'Georgia', HI: 'Hawaii',
    ID: 'Idaho', IL: 'Illinois', IN: 'Indiana', IA: 'Iowa', KS: 'Kansas', KY: 'Kentucky', LA: 'Louisiana',
    ME: 'Maine', MD: 'Maryland', MA: 'Massachusetts', MI: 'Michigan', MN: 'Minnesota', MS: 'Mississippi',
    MO: 'Missouri', MT: 'Montana', NE: 'Nebraska', NV: 'Nevada', NH: 'New Hampshire', NJ: 'New Jersey',
    NM: 'New Mexico', NY: 'New York', NC: 'North Carolina', ND: 'North Dakota', OH: 'Ohio', OK: 'Oklahoma',
    OR: 'Oregon', PA: 'Pennsylvania', RI: 'Rhode Island', SC: 'South Carolina', SD: 'South Dakota',
    TN: 'Tennessee', TX: 'Texas', UT: 'Utah', VT: 'Vermont', VA: 'Virginia', WA: 'Washington',
    WV: 'West Virginia', WI: 'Wisconsin', WY: 'Wyoming'};

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function say(id, text) { window.mvStatus($(id), text || ''); }
  function money(value) {
    return window.mvMoney ? window.mvMoney(Number(value) || 0) : (Number(value) || 0).toLocaleString(undefined, {style: 'currency', currency: 'USD'});
  }
  function stateName(code) { return STATE_NAMES[code] || code; }
  async function failText(failure, action) {
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
    if (plain) return plain;
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function request(path, options) {
    options = options || {};
    var init = {method: options.method || 'GET', cache: 'no-store', body: options.json};
    if (options.json === undefined && options.body !== undefined) {
      init.headers = {'Content-Type': options.type || 'application/octet-stream'};
      init.body = options.body;
    }
    return window.mvFetchJSON(API + path, init);
  }
  function readFile(file, asText) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(reader.result); };
      reader.onerror = function () { reject(reader.error); };
      if (asText) reader.readAsText(file); else reader.readAsArrayBuffer(file);
    });
  }
  function table(headers, rows) {
    var wrap = el('div', 'fa-scroll');
    var t = el('table');
    var head = el('tr');
    headers.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; head.appendChild(th); });
    var thead = el('thead'); thead.appendChild(head); t.appendChild(thead);
    var body = el('tbody');
    rows.forEach(function (cells) {
      var tr = el('tr');
      cells.forEach(function (cell) {
        var td = el('td');
        if (cell && cell.nodeType) td.appendChild(cell); else td.textContent = cell == null ? '' : String(cell);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    t.appendChild(body);
    wrap.appendChild(t);
    return wrap;
  }
  function technical(box, rows) {
    if (!rows || !rows.length) return;
    var details = el('details');
    details.appendChild(el('summary', null, 'Technical details'));
    var list = el('ul', 'muted');
    rows.forEach(function (row) { list.appendChild(el('li', null, typeof row === 'string' ? row : row.text)); });
    details.appendChild(list);
    box.appendChild(details);
  }
  function saveText(text, name) {
    var link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([text], {type: 'text/plain'}));
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  var docTypes = [];
  var tablesInfo = null;

  async function loadStatus() {
    try {
      var data = await request('');
      tablesInfo = data;
      docTypes = data.document_types || [];
      say('tax-tables-line', 'Tax year ' + data.tax_year + ' · ' + data.tables +
        (data.update_channel ? ' · updated automatically' : ''));
      var select = root.querySelector('[data-tax-states]');
      var boxes = root.querySelector('[data-tax-state-boxes]');
      (data.states || []).forEach(function (code) {
        var option = el('option', null, stateName(code));
        option.value = code;
        select.appendChild(option);
        var label = el('label');
        var input = el('input'); input.type = 'checkbox'; input.name = 'states'; input.value = code;
        label.appendChild(input);
        label.appendChild(document.createTextNode(' ' + stateName(code)));
        boxes.appendChild(label);
      });
      var forms = root.querySelector('[data-tax-form-boxes]');
      docTypes.forEach(function (type) {
        var label = el('label');
        var input = el('input'); input.type = 'checkbox'; input.name = 'forms'; input.value = type;
        label.appendChild(input);
        label.appendChild(document.createTextNode(' ' + type));
        forms.appendChild(label);
      });
      var back = $('tax-tables-back');
      if (back) back.hidden = !data.can_roll_back;
    } catch (failure) {
      say('tax-tables-line', await failText(failure, 'load the tax tables'));
    }
  }

  // ---- first draft ------------------------------------------------------------
  var prepare = $('tax-prepare');
  prepare.addEventListener('submit', async function (event) {
    event.preventDefault();
    var out = $('tax-prepare-out'); out.textContent = '';
    var files = Array.prototype.slice.call(prepare.elements.documents.files || []);
    if (!files.length) { say('tax-prepare-status', 'Choose at least one document.'); return; }
    if (files.length > 50) { say('tax-prepare-status', 'Choose 50 documents or fewer.'); return; }
    var button = prepare.querySelector('button[type="submit"]');
    button.disabled = true;
    say('tax-prepare-status', 'Preparing the draft…');
    try {
      var documents = [];
      for (var i = 0; i < files.length; i++) {
        documents.push({name: files[i].name.slice(0, 200), text: String(await readFile(files[i], true)).slice(0, 200000)});
      }
      var f = prepare.elements;
      var data = await request('/prepare', {method: 'POST', json: {
        documents: documents, filing_status: f.filing_status.value, dependents: Number(f.dependents.value),
        state: f.state.value, estimated_payments: Number(f.estimated_payments.value) || 0,
        prior_year_overpayment: Number(f.prior_year_overpayment.value) || 0,
        taxpayer_65: f.taxpayer_65.checked, taxpayer_blind: f.taxpayer_blind.checked,
        spouse_65: f.spouse_65.checked, spouse_blind: f.spouse_blind.checked}});
      say('tax-prepare-status', data.refund
        ? 'Draft refund of ' + money(-data.balance) + ' for tax year ' + data.tax_year + '.'
        : 'Draft amount owed: ' + money(data.balance) + ' for tax year ' + data.tax_year + '.');
      var facts = el('ul', 'fa-inline');
      [['Total income', data.total_income], ['Taxable income', data.taxable_income], ['Tax', data.tax], ['Already paid', data.paid]]
        .forEach(function (pair) { facts.appendChild(el('li', 'badge', pair[0] + ': ' + money(pair[1]))); });
      if (data.state) {
        facts.appendChild(el('li', 'badge', stateName(data.state.code) + ': ' + (data.state.computed
          ? (data.state.balance < 0 ? 'refund ' + money(-data.state.balance) : 'owes ' + money(data.state.balance))
          : 'prepared in your tax software')));
      }
      out.appendChild(facts);
      out.appendChild(el('h3', null, 'Draft lines'));
      out.appendChild(table(['Line', 'Amount', 'From'], data.lines.map(function (l) { return [l.label, money(l.amount), l.source]; })));
      out.appendChild(el('h3', null, 'Documents'));
      out.appendChild(table(['Document', 'Recognised as', 'Needs a closer look'], data.documents.map(function (d) {
        return [d.name, d.type === 'UNKNOWN' ? 'Not recognised' : d.type, d.check ? 'Yes' : 'No'];
      })));
      if (data.open_items.length) {
        out.appendChild(el('h3', null, 'For the preparer to resolve before filing'));
        var list = el('ul');
        data.open_items.forEach(function (item) { list.appendChild(el('li', null, item)); });
        out.appendChild(list);
      }
      if (data.carried.length) {
        out.appendChild(el('h3', null, 'Other figures found (not added into the draft)'));
        out.appendChild(table(['Figure', 'Amount'], data.carried.map(function (c) { return [c.label, money(c.amount)]; })));
      }
      out.appendChild(el('p', 'muted', data.disclaimer));
      var download = el('button', 'btn', 'Download the review package');
      download.type = 'button';
      download.addEventListener('click', function () { saveText(data.text, 'Tax-draft-review-package.txt'); });
      out.appendChild(download);
    } catch (failure) {
      say('tax-prepare-status', await failText(failure, 'prepare the draft'));
    } finally {
      button.disabled = false;
    }
  });

  // ---- firm readiness -----------------------------------------------------------
  var readiness = $('tax-readiness');
  function addNameRow() {
    var holder = root.querySelector('[data-tax-names]');
    var index = holder.children.length + 1;
    var row = el('div', 'tax-name-row');
    var l1 = el('label', 'fa-field'); l1.appendChild(el('span', null, 'Your name for it'));
    var input = el('input', 'input'); input.maxLength = 120; input.name = 'alias_label';
    input.setAttribute('aria-label', 'Your name for document ' + index);
    l1.appendChild(input);
    var l2 = el('label', 'fa-field'); l2.appendChild(el('span', null, 'Which form it is'));
    var select = el('select', 'select'); select.name = 'alias_type';
    select.setAttribute('aria-label', 'Form for document ' + index);
    docTypes.forEach(function (t) { var o = el('option', null, t); o.value = t; select.appendChild(o); });
    l2.appendChild(select);
    var remove = el('button', 'btn btn--ghost', 'Remove');
    remove.type = 'button';
    remove.addEventListener('click', function () { row.remove(); });
    row.appendChild(l1); row.appendChild(l2); row.appendChild(remove);
    holder.appendChild(row);
  }
  root.querySelector('[data-tax-add-name]').addEventListener('click', addNameRow);
  readiness.addEventListener('submit', async function (event) {
    event.preventDefault();
    var out = $('tax-readiness-out'); out.textContent = '';
    var checked = function (name) {
      return Array.prototype.slice.call(readiness.querySelectorAll('input[name="' + name + '"]:checked')).map(function (i) { return i.value; });
    };
    var other = readiness.elements.other_forms.value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
    var names = Array.prototype.slice.call(readiness.querySelectorAll('.tax-name-row')).map(function (row) {
      return {label: row.querySelector('[name="alias_label"]').value.trim(), type: row.querySelector('[name="alias_type"]').value};
    }).filter(function (n) { return n.label; });
    say('tax-readiness-status', 'Checking…');
    try {
      var data = await request('/readiness', {method: 'POST', json: {
        firm: readiness.elements.firm.value.trim(), clients: Number(readiness.elements.clients.value) || 0,
        states: checked('states'), forms: checked('forms').concat(other).slice(0, 100), names: names}});
      say('tax-readiness-status', data.summary);
      var facts = el('ul', 'fa-inline');
      facts.appendChild(el('li', 'badge ' + (data.ready ? 'ok' : 'warn'), data.ready ? 'Ready' : 'Not ready'));
      if (data.drafted_states.length) facts.appendChild(el('li', 'badge', 'States Lightwork drafts: ' + data.drafted_states.map(stateName).join(', ')));
      out.appendChild(facts);
      var list = el('ul');
      data.checks.forEach(function (c) {
        var li = el('li');
        li.appendChild(el('span', 'badge ' + (c.ok ? 'idle' : 'warn'), c.ok ? 'Good to know' : 'Fix first'));
        li.appendChild(document.createTextNode(' ' + c.text));
        list.appendChild(li);
      });
      out.appendChild(list);
      technical(out, data.technical);
    } catch (failure) {
      say('tax-readiness-status', await failText(failure, 'check readiness'));
    }
  });

  // ---- test on past returns ------------------------------------------------------
  var backtest = $('tax-backtest-file');
  backtest.addEventListener('change', async function () {
    var out = $('tax-backtest-out'); out.textContent = '';
    if (!backtest.files.length) return;
    say('tax-backtest-status', 'Preparing a draft for each client…');
    try {
      var raw = await readFile(backtest.files[0], false);
      var data = await request('/backtest', {method: 'POST', body: raw, type: 'application/zip'});
      say('tax-backtest-status', data.in_scope
        ? data.matched + ' of ' + data.in_scope + ' comparable returns matched what was filed (' + Math.round(data.accuracy * 100) + '%).'
        : 'None of these returns could be compared: each one includes something a preparer handles by hand.');
      out.appendChild(table(['Client', 'Result', 'Largest difference'], data.returns.map(function (r) {
        var result = !r.in_scope ? 'Not compared: ' + r.why_not_compared.join('; ') : (r.matched ? 'Matched' : 'Different');
        return [r.client, result, r.in_scope ? money(r.largest_difference) : ''];
      })));
      var download = el('button', 'btn', 'Download the full report');
      download.type = 'button';
      download.addEventListener('click', function () { saveText(data.text, 'Tax-test-report.txt'); });
      out.appendChild(download);
    } catch (failure) {
      say('tax-backtest-status', await failText(failure, 'test the returns'));
    }
  });

  // ---- tax tables (installation administrators) ----------------------------------
  var check = $('tax-tables-check');
  if (check) {
    check.addEventListener('click', async function () {
      var ok = await window.mvConfirm('Check the publisher for newer tax tables? Lightwork contacts the update address set for this installation and applies a newer signed update if there is one.', {okText: 'Check now'});
      if (!ok) return;
      say('tax-tables-status', 'Checking…');
      var out = $('tax-tables-out'); out.textContent = '';
      try {
        var data = await request('/tables/check', {method: 'POST'});
        say('tax-tables-status', data.summary);
        technical(out, data.technical);
        if (data.status === 'applied') loadStatusLine();
      } catch (failure) {
        say('tax-tables-status', await failText(failure, 'check for newer tables'));
      }
    });
    var checkUrl = $('tax-tables-check-url');
    if (checkUrl) checkUrl.addEventListener('click', async function () {
      var address = ($('tax-tables-url').value || '').trim();
      if (!/^https:\/\/\S+$/.test(address) || address.length > 500) {
        say('tax-tables-status', 'Enter an address that starts with https://.'); return;
      }
      var ok = await window.mvConfirm('Check this address for newer tax tables? Lightwork contacts it once and applies a newer update only if it is signed by a publisher you trust.', {okText: 'Check now'});
      if (!ok) return;
      say('tax-tables-status', 'Checking…');
      var out = $('tax-tables-out'); out.textContent = '';
      try {
        var data = await request('/tables/check', {method: 'POST', json: {url: address}});
        say('tax-tables-status', data.summary);
        technical(out, data.technical);
        if (data.status === 'applied') loadStatusLine();
      } catch (failure) {
        say('tax-tables-status', await failText(failure, 'check that address'));
      }
    });
    $('tax-tables-file').addEventListener('change', async function (event) {
      var input = event.target;
      if (!input.files.length) return;
      var ok = await window.mvConfirm('Apply this tax table update? It is used for every draft from now on. The current tables are kept so you can go back.', {okText: 'Apply update'});
      if (!ok) { input.value = ''; return; }
      say('tax-tables-status', 'Applying…');
      try {
        var raw = await readFile(input.files[0], false);
        var data = await request('/tables/apply', {method: 'POST', body: raw, type: 'application/json'});
        say('tax-tables-status', 'Update applied. Now using: ' + data.tables + '.');
        loadStatusLine();
      } catch (failure) {
        say('tax-tables-status', await failText(failure, 'apply the update'));
      } finally {
        input.value = '';
      }
    });
    $('tax-tables-back').addEventListener('click', async function () {
      var ok = await window.mvConfirm('Go back to the previous tax tables? Drafts prepared from now on use the older tables.', {okText: 'Go back'});
      if (!ok) return;
      try {
        await request('/tables/roll-back', {method: 'POST'});
        say('tax-tables-status', 'Now using the previous tax tables.');
        loadStatusLine();
      } catch (failure) {
        say('tax-tables-status', await failText(failure, 'go back to the previous tables'));
      }
    });
  }
  async function loadStatusLine() {
    try {
      var data = await request('');
      say('tax-tables-line', 'Tax year ' + data.tax_year + ' · ' + data.tables + (data.update_channel ? ' · updated automatically' : ''));
      var back = $('tax-tables-back');
      if (back) back.hidden = !data.can_roll_back;
    } catch (ignored) { /* the line keeps its last value */ }
  }

  loadStatus();
  window.lightworkTax = {tables: function () { return tablesInfo; }};
})();
