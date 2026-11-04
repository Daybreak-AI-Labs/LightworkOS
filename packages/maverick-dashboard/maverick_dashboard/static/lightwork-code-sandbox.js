/* The task page's "Run code for this task" panel: open a code session, run
   steps, read each session's log, close it. The server checks the person's
   access to the task, the task's limits and the sandbox rules on every step. */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function when(ts) { return ts && window.mvWhen ? window.mvWhen(ts) : (ts ? new Date(ts * 1000).toLocaleString() : ''); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function say(node, text) { window.mvStatus(node, text || ''); }
  function button(label, cls) { var b = el('button', 'btn ' + (cls || 'btn--ghost'), label); b.type = 'button'; return b; }
  async function failText(failure, action) {
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
    if (plain) return plain;
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function request(url, options) {
    options = options || {};
    return window.mvFetchJSON(url, {method: options.method || 'GET', cache: 'no-store', body: options.json});
  }
  function firstLine(text) { return String(text || '').split('\n')[0].slice(0, 120); }

  function start() {
    var panel = $('code-sandbox');
    if (!panel) return;
    var goal = panel.getAttribute('data-goal');
    var base = '/api/v1/goals/' + encodeURIComponent(goal) + '/code';
    var status = $('code-sandbox-status');
    var body = $('code-sandbox-body');
    var state = {current: null, limits: null, loaded: false};

    function logTable(steps) {
      var wrap = el('div', 'io-scroll');
      var t = el('table');
      t.appendChild(el('caption', 'sr-only', 'Code session log'));
      var head = el('tr');
      ['Step', 'Time', 'Result', 'Seconds', 'Code'].forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; head.appendChild(th); });
      var thead = el('thead'); thead.appendChild(head); t.appendChild(thead);
      var tb = el('tbody');
      steps.forEach(function (s) {
        var tr = el('tr');
        [s.step, when(s.time), s.ok ? 'Finished' : 'Stopped with an error', s.seconds == null ? '' : Number(s.seconds).toFixed(1),
          firstLine(s.code)].forEach(function (cell) { tr.appendChild(el('td', null, cell == null ? '' : String(cell))); });
        tb.appendChild(tr);
      });
      t.appendChild(tb);
      wrap.appendChild(t);
      return wrap;
    }

    async function showLog(id, holder) {
      holder.textContent = '';
      try {
        var data = await request(base + '/sessions/' + encodeURIComponent(id) + '/log');
        if (!data.steps.length) { holder.appendChild(el('p', 'muted', 'No steps were run in this session.')); return; }
        holder.appendChild(logTable(data.steps));
      } catch (failure) {
        holder.appendChild(el('p', 'muted', await failText(failure, 'load the log')));
      }
    }

    function stepResult(log, code, r) {
      var item = el('div', 'cs-step');
      item.appendChild(el('p', null, (r.ok ? 'Finished' : 'Stopped with an error') +
        (r.seconds == null ? '' : ' in ' + Number(r.seconds).toFixed(1) + ' seconds') + ': ' + firstLine(code)));
      if (r.output) item.appendChild(el('pre', 'cs-output', r.output));
      if (!r.output && r.ok) item.appendChild(el('p', 'muted', 'It printed nothing.'));
      if (r.problems) {
        var d = el('details');
        d.appendChild(el('summary', null, r.ok ? 'Warnings it printed' : 'What went wrong'));
        d.appendChild(el('pre', 'cs-output', r.problems));
        item.appendChild(d);
      }
      if (r.cut_short) item.appendChild(el('p', 'muted', 'The output was too long, so only the beginning is shown.'));
      if (r.not_kept && r.not_kept.length) item.appendChild(el('p', 'muted', 'Not kept for the next step: ' + r.not_kept.join(', ') + '.'));
      log.insertBefore(item, log.firstChild);
    }

    function workspace(id) {
      var box = el('div', 'panel');
      box.appendChild(el('p', null, 'Code session open. ' + (state.limits ? 'Each step may run for up to ' +
        state.limits.seconds_per_step + ' seconds, and a session allows ' + plural(state.limits.steps_per_session, 'step') + '.' : '')));
      var label = el('label', 'cs-field');
      label.appendChild(el('span', null, 'Code to run (Python)'));
      var code = el('textarea', 'textarea');
      code.rows = 6;
      code.maxLength = state.limits ? state.limits.code_characters : 20000;
      code.spellcheck = false;
      code.id = 'code-sandbox-code';
      label.appendChild(code);
      box.appendChild(label);
      var row = el('div', 'cs-row');
      var run = button('Run', 'btn--primary');
      var close = button('Close session', 'btn--ghost');
      row.appendChild(run);
      row.appendChild(close);
      box.appendChild(row);
      var log = el('div');
      box.appendChild(log);
      run.addEventListener('click', async function () {
        var text = code.value;
        if (!text.trim()) { say(status, 'Write some code first.'); code.focus(); return; }
        run.disabled = true;
        say(status, 'Running…');
        try {
          var r = await request(base + '/sessions/' + encodeURIComponent(id) + '/run', {method: 'POST', json: {code: text}});
          stepResult(log, text, r);
          say(status, r.ok ? 'Step finished.' : 'The step stopped with an error. The details are below.');
        } catch (failure) {
          say(status, await failText(failure, 'run the code'));
        } finally {
          run.disabled = false;
        }
      });
      close.addEventListener('click', async function () {
        var ok = await window.mvConfirm('Close this code session? The values kept between steps are discarded. Its log stays with the task.', {okText: 'Close session'});
        if (!ok) return;
        close.disabled = true;
        try {
          await request(base + '/sessions/' + encodeURIComponent(id) + '/close', {method: 'POST', json: {}});
          state.current = null;
          say(status, 'Session closed.');
          await load();
        } catch (failure) {
          say(status, await failText(failure, 'close the session'));
          close.disabled = false;
        }
      });
      return box;
    }

    function render(data) {
      body.textContent = '';
      if (!data.enabled) { say(status, 'Running code is turned off. An administrator can turn it on in Settings.'); return; }
      if (!data.allowed) { say(status, 'Code here would run directly on this computer, so only installation administrators may run it.'); return; }
      state.limits = data.limits;
      var open = data.sessions.filter(function (s) { return s.open; });
      if (!state.current && open.length) state.current = open[0].id;
      say(status, state.current ? '' : 'Start a session to run code. Sessions close by themselves after ' + data.limits.idle_minutes + ' idle minutes.');
      if (state.current) body.appendChild(workspace(state.current));
      else {
        var startBtn = button('Start a code session', 'btn--primary');
        startBtn.addEventListener('click', async function () {
          startBtn.disabled = true;
          try {
            var s = await request(base + '/sessions', {method: 'POST', json: {}});
            state.current = s.id;
            await load();
          } catch (failure) {
            say(status, await failText(failure, 'start a code session'));
            startBtn.disabled = false;
          }
        });
        var row = el('div', 'cs-row'); row.appendChild(startBtn); body.appendChild(row);
      }
      var past = data.sessions.filter(function (s) { return s.id !== state.current; });
      if (!past.length) return;
      body.appendChild(el('h4', null, 'Your earlier sessions on this task'));
      past.forEach(function (s) {
        var row = el('div', 'cs-row');
        row.appendChild(el('span', null, 'Started ' + when(s.started) + ', ' + plural(s.steps, 'step') + (s.open ? ' (still open)' : '')));
        var show = button('Show log', 'btn--ghost');
        var holder = el('div');
        show.addEventListener('click', function () { showLog(s.id, holder); });
        row.appendChild(show);
        if (s.open) {
          var use = button('Use this session', 'btn--ghost');
          use.addEventListener('click', function () { state.current = s.id; render(data); });
          row.appendChild(use);
        }
        body.appendChild(row);
        body.appendChild(holder);
      });
    }

    async function load() {
      say(status, 'Loading…');
      try { render(await request(base)); } catch (failure) { say(status, await failText(failure, 'load code sessions')); }
    }
    // Load only when the person opens the panel.
    panel.addEventListener('toggle', function () {
      if (panel.open && !state.loaded) { state.loaded = true; load(); }
    });
    if (panel.open) { state.loaded = true; load(); }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
  window.lightworkCodeSandbox = {start: start};
})();
