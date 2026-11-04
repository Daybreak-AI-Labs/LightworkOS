/* Questions about tasks (Spending page), task health (task page) and
   recorded steps (Replay page). Each block starts only when its panel is on
   the page; the server checks access to every task again. */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function human(value) { return window.mvHuman ? window.mvHuman(value) : String(value == null ? '' : value); }
  function when(ts) { return ts && window.mvWhen ? window.mvWhen(ts) : (ts ? new Date(ts * 1000).toLocaleString() : ''); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function say(node, text) { window.mvStatus(node, text || ''); }
  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function failText(failure, action) {
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
    if (plain) return plain;
    return errorText(failure, action);
  }
  async function request(url, options) {
    options = options || {};
    return window.mvFetchJSON(url, {method: options.method || 'GET', cache: 'no-store', body: options.json});
  }
  function table(headers, rows, caption) {
    var wrap = el('div', 'io-scroll');
    var t = el('table');
    if (caption) t.appendChild(el('caption', 'sr-only', caption));
    var head = el('tr');
    headers.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; head.appendChild(th); });
    var thead = el('thead'); thead.appendChild(head); t.appendChild(thead);
    var body = el('tbody');
    rows.forEach(function (cells) {
      var tr = el('tr');
      cells.forEach(function (cell) { tr.appendChild(el('td', null, cell == null ? '' : String(cell))); });
      body.appendChild(tr);
    });
    t.appendChild(body);
    wrap.appendChild(t);
    return wrap;
  }
  function option(select, value, label) {
    var opt = el('option', null, label);
    opt.value = value;
    select.appendChild(opt);
  }

  // ---- Spending: questions about your tasks (analytics) ---------------------
  var MONEY = {spend: true, spend_per_task: true};
  function shown(metric, value) {
    if (MONEY[metric]) return window.mvMoney ? window.mvMoney(Number(value || 0)) : Number(value || 0).toLocaleString(undefined, {style: 'currency', currency: 'USD'});
    return Math.round(Number(value || 0)).toLocaleString();
  }
  function groupLabel(group, value) {
    if (group === 'none') return 'All tasks';
    if (group === 'status' || group === 'outcome') return human(value);
    return value;
  }
  function analytics() {
    var form = $('io-ask-form');
    if (!form) return;
    var status = $('io-ask-status');
    var out = $('io-ask-out');
    async function load() {
      try {
        var choices = await request('/api/v1/analytics/choices');
        if (!choices.available) {
          say(status, choices.reason || 'Task questions need an add-on that is not installed on this server. Whoever installed Lightwork can add it.');
          return;
        }
        choices.metrics.forEach(function (m) { option(form.elements.metric, m.value, m.label); });
        choices.groups.forEach(function (g) { option(form.elements.group, g.value, g.label); });
        form.hidden = false;
        say(status, 'Pick what to measure and how to group it, then press Answer.');
        if (choices.can_write_queries) queries();
      } catch (failure) {
        say(status, await failText(failure, 'load the question choices'));
      }
    }
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      out.textContent = '';
      var body = {metric: form.elements.metric.value, group: form.elements.group.value,
        since: form.elements.since.value || null, until: form.elements.until.value || null};
      var submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      say(status, 'Working it out…');
      try {
        var answer = await request('/api/v1/analytics/ask', {method: 'POST', json: body});
        if (!answer.rows.length) { say(status, 'No finished tasks match. Try a wider date range.'); return; }
        say(status, answer.question + ': ' + plural(answer.rows.length, 'row') + '.');
        var metricLabel = form.elements.metric.selectedOptions[0].textContent;
        var groupName = form.elements.group.selectedOptions[0].textContent;
        out.appendChild(table([groupName, metricLabel], answer.rows.map(function (r) {
          return [groupLabel(body.group, r.group), shown(body.metric, r.value)];
        }), answer.question));
      } catch (failure) {
        say(status, await failText(failure, 'answer the question'));
      } finally {
        submit.disabled = false;
      }
    });
    load();
  }
  function queries() {
    var box = $('io-query');
    if (!box) return;
    box.hidden = false;
    var run = $('io-query-run');
    var status = $('io-query-status');
    var out = $('io-query-out');
    run.addEventListener('click', async function () {
      out.textContent = '';
      var text = $('io-query-text').value.trim();
      if (!text) { say(status, 'Write a question first.'); return; }
      run.disabled = true;
      say(status, 'Running (read only, stopped after 15 seconds)…');
      try {
        var data = await request('/api/v1/analytics/query', {method: 'POST', json: {query: text}});
        say(status, data.rows.length ? plural(data.rows.length, 'row') + (data.more ? ' shown (there are more).' : '.') : 'No rows.');
        if (data.rows.length) out.appendChild(table(data.columns, data.rows, 'Query result'));
      } catch (failure) {
        say(status, await failText(failure, 'run the question'));
      } finally {
        run.disabled = false;
      }
    });
  }

  // ---- Task page: health score (diag health) ---------------------------------
  function health() {
    var btn = $('task-health-check');
    if (!btn) return;
    var goal = btn.getAttribute('data-goal');
    var status = $('task-health-status');
    var out = $('task-health-out');
    btn.addEventListener('click', async function () {
      out.textContent = '';
      btn.disabled = true;
      say(status, 'Checking…');
      try {
        var h = await request('/api/v1/goals/' + encodeURIComponent(goal) + '/health');
        say(status, 'Health: ' + h.score + ' out of 100 (grade ' + h.grade + ').' +
          (h.finished ? '' : ' The task has not finished, which lowers the score.'));
        var rows = h.parts.map(function (p) { return [p.label, (p.points > 0 ? '+' : '') + p.points]; });
        rows.push(['AI used (tokens)', h.tokens_used.toLocaleString()]);
        out.appendChild(table(['Part of the score', 'Points'], rows, 'How the health score is made'));
      } catch (failure) {
        say(status, await failText(failure, 'check the task health'));
      } finally {
        btn.disabled = false;
      }
    });
  }

  // ---- Replay page: recorded steps (diag replay) -----------------------------
  function steps() {
    var btn = $('io-steps-show');
    if (!btn) return;
    var goal = btn.getAttribute('data-goal');
    var kind = $('io-steps-kind');
    var status = $('io-steps-status');
    var out = $('io-steps-out');
    var filled = false;
    btn.addEventListener('click', async function () {
      out.textContent = '';
      btn.disabled = true;
      say(status, 'Reading the recording…');
      try {
        var data = await request('/api/v1/goals/' + encodeURIComponent(goal) + '/recorded-steps?kind=' + encodeURIComponent(kind.value));
        if (!data.recording) { say(status, 'Step-by-step recording is turned off, so this task has no recording. Whoever installed Lightwork can turn it on.'); return; }
        if (data.damaged) { say(status, 'The recording for this task failed its integrity check, so it is not shown. Ask an administrator to check the recording.'); return; }
        if (!filled && data.kinds.length) {
          data.kinds.forEach(function (k) { option(kind, k, human(k)); });
          kind.disabled = false;
          filled = true;
        }
        if (!data.total) { say(status, 'This task has no recorded steps yet.'); return; }
        say(status, (kind.value ? plural(data.matching, 'step') + ' of this kind, out of ' : '') + plural(data.total, 'recorded step') + '.');
        out.appendChild(table(['Step', 'Time', 'Kind', 'Who', 'What happened'], data.steps.map(function (s) {
          return [s.step, when(s.time), human(s.kind), human(s.who), s.text];
        }), 'Recorded steps'));
      } catch (failure) {
        say(status, await failText(failure, 'read the recording'));
      } finally {
        btn.disabled = false;
      }
    });
  }

  function start() {
    analytics();
    health();
    steps();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
  window.lightworkInsightOps = {start: start};
})();
