/* Savings: learning checkpoints, record check and outside agents by vendor.
   Performance: tasks finished and stopped each day, and how long each tool takes. */
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function get(path) {
    return window.mvFetchJSON(path, {cache: 'no-store'});
  }
  function table(headers, rows) {
    var t = el('table'), head = el('tr');
    headers.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; head.appendChild(th); });
    var thead = el('thead'); thead.appendChild(head); t.appendChild(thead);
    var body = el('tbody');
    rows.forEach(function (cells) {
      var tr = el('tr');
      cells.forEach(function (c) { tr.appendChild(el('td', null, c == null ? '' : String(c))); });
      body.appendChild(tr);
    });
    t.appendChild(body);
    return t;
  }
  function bar(value, max) {
    var width = max ? Math.round(value / max * 100) : 0;
    var outer = el('span', 'ops-bar');
    var inner = el('span', 'ops-bar__fill');
    inner.style.width = width + '%';
    outer.appendChild(inner);
    return outer;
  }

  var valueForm = $('value-report-form');
  if (valueForm) {
    var load = async function () {
      var status = $('value-report-status'), out = $('value-report-out'), vendors = $('value-report-vendors');
      status.textContent = 'Loading…';
      try {
        var data = await get('/api/v1/insights/value-report?days=' + encodeURIComponent(valueForm.elements.days.value));
        out.textContent = ''; vendors.textContent = '';
        out.appendChild(el('li', null, data.learning));
        out.appendChild(el('li', null, data.record));
        if (data.vendors.length) {
          vendors.appendChild(el('h3', null, 'Outside agents by vendor'));
          vendors.appendChild(table(['Vendor', 'Finished', 'Failed'], data.vendors.map(function (v) { return [v.vendor, v.delivered, v.failed]; })));
        }
        status.textContent = '';
      } catch (failure) { status.textContent = errorText(failure, 'load the report'); }
    };
    valueForm.addEventListener('submit', function (event) { event.preventDefault(); load(); });
    load();
  }

  var chartsForm = $('ops-charts-form');
  if (chartsForm) {
    var draw = async function () {
      var status = $('ops-charts-status');
      status.textContent = 'Loading…';
      try {
        var data = await get('/api/v1/insights/charts?days=' + encodeURIComponent(chartsForm.elements.days.value));
        var tasks = $('ops-charts-tasks'), tools = $('ops-charts-tools');
        tasks.textContent = ''; tools.textContent = '';
        var max = Math.max.apply(null, data.tasks.map(function (d) { return d.finished + d.stopped; }).concat([0]));
        var t = table(['Day', 'Finished', 'Stopped', 'Total'], []);
        var body = t.querySelector('tbody');
        data.tasks.forEach(function (d) {
          var tr = el('tr');
          [(window.mvDateAbsolute && window.mvDateAbsolute(d.day)) || d.day, d.finished, d.stopped].forEach(function (v) { tr.appendChild(el('td', null, String(v))); });
          var cell = el('td', null, String(d.finished + d.stopped) + ' '); cell.appendChild(bar(d.finished + d.stopped, max)); tr.appendChild(cell);
          body.appendChild(tr);
        });
        tasks.appendChild(t);
        if (!data.tools.length) tools.appendChild(el('p', 'muted', 'No tools have been used since this server started.'));
        else tools.appendChild(table(['Tool', 'Uses', 'Typical', 'Slow (1 in 20)', 'Slowest'], data.tools.map(function (r) {
          return [window.mvHuman ? window.mvHuman(r.tool) : r.tool, r.uses, Math.round(r.typical_ms), Math.round(r.slow_ms), Math.round(r.slowest_ms)];
        })));
        status.textContent = '';
      } catch (failure) { status.textContent = errorText(failure, 'load the charts'); }
    };
    chartsForm.addEventListener('submit', function (event) { event.preventDefault(); draw(); });
    draw();
  }
})();
