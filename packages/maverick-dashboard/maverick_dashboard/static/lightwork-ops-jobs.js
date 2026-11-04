// Shared by the Learning, Learned, Workforce, Tasks and Savings buttons that
// replace terminal commands: plain requests, plain errors, and background
// jobs (start, show progress, offer Stop when the job can stop, then show
// the result). Everything a person sees is a plain sentence.
(function () {
  'use strict';
  if (window.LWJobs) return;
  var POLL_MS = 1500, contextEpoch = 0;
  var surfaces = new Map();
  function contextChanged() {
    contextEpoch++;
    surfaces.forEach(function (out, status) {
      if (!status.isConnected) { surfaces.delete(status); return; }
      out.replaceChildren();
      status.textContent = 'Your account, workspace or access changed. Read current tasks before continuing.';
    });
  }
  document.addEventListener('lightwork:workspace-changed', contextChanged);
  document.addEventListener('lightwork:account-context-changed', contextChanged);
  document.addEventListener('lightwork:copilot-context-changed', function (event) {
    if (event.detail?.reason !== 'selection') contextChanged();
  });
  window.addEventListener('lightwork:context-changed', contextChanged);
  var LEARNING_KINDS = new Set(['self_harness_run', 'self_harness_corpus_quality', 'self_harness_clash',
    'self_harness_transfer', 'flywheel', 'self_modify_run']);

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function money(v) { return window.mvMoney ? window.mvMoney(Number(v) || 0) : '$' + (Number(v) || 0).toFixed(2); }
  function when(ts) { return (typeof window.mvWhen === 'function' ? window.mvWhen(ts) : '') || ''; }

  // A failed request as one sentence. Our routes write their refusals for
  // people; anything else gets the shared wording.
  async function problem(failure, action) {
    if (failure && [404, 409, 413, 422, 503].indexOf(failure.status) >= 0) {
      var text = window.mvPlainDetail ? window.mvPlainDetail(failure.detail) : '';
      if (text) return text;
    }
    if (failure && failure.status === 403) return 'Only an administrator can ' + action + '.';
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, action) : 'Could not ' + action + '.';
  }

  async function request(url, opts) {
    opts = opts || {};
    var init = { method: opts.method || 'GET', raw: !!opts.raw, body: opts.json };
    if (opts.json === undefined && opts.body !== undefined) {
      init.headers = { 'Content-Type': opts.type || 'application/octet-stream' };
      init.body = opts.body;
    }
    return window.mvFetchJSON(url, init);
  }

  function saveBlob(blob, name) {
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(link.href); }, 1000);
  }

  function technical(lines, title) {
    var box = el('details', 'lw-ops-tech');
    box.appendChild(el('summary', null, title || 'Technical details'));
    var list = el('ul');
    (lines || []).forEach(function (t) { if (t !== '' && t != null) list.appendChild(el('li', null, String(t))); });
    box.appendChild(list);
    return box;
  }

  function table(headers, rows) {
    var t = el('table');
    var head = el('tr');
    headers.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; head.appendChild(th); });
    var thead = el('thead'); thead.appendChild(head); t.appendChild(thead);
    var body = el('tbody');
    rows.forEach(function (cells) {
      var tr = el('tr');
      cells.forEach(function (c) {
        var td = el('td');
        if (c instanceof Node) td.appendChild(c); else td.textContent = c == null ? '' : String(c);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    t.appendChild(body);
    return t;
  }

  var STATE_TEXT = {
    admitted: 'The task is recorded. Waiting for its worker to start.',
    not_started: 'The worker did not start this task. Read its recorded admission before deciding what to do next.',
    running: 'Working on it. You can leave this page and check progress later.',
    unavailable: 'The worker is unavailable here. Read its last recorded progress in Learning before deciding what to do next. Work is never repeated automatically.',
    stopping: 'Stopping at the next safe point…',
    done: 'Finished.',
    stopped: 'Stopped early. Here is what was done before it stopped.',
    failed: ''
  };
  var JOB_STATES = new Set(['admitted', 'running', 'stopping', 'done', 'stopped', 'failed', 'not_started']);
  function jobReference(job) {
    return job && typeof job.id === 'string' && /^[a-f0-9]{16}$/.test(job.id) ? { id: job.id,
      kind: typeof job.kind === 'string' && job.kind ? job.kind : null } : null;
  }
  function validJob(job, original) {
    return job && typeof job === 'object' && !Array.isArray(job) &&
      typeof job.id === 'string' && /^[a-f0-9]{16}$/.test(job.id) &&
      typeof job.kind === 'string' && job.kind.trim().length > 0 && JOB_STATES.has(job.state) &&
      (job.result == null || typeof job.result === 'object' && !Array.isArray(job.result)) &&
      (!original || job.id === original.id && (!original.kind || job.kind === original.kind));
  }
  function unsupportedReply() {
    return { status: 503, detail: 'The task reply could not be confirmed. Read its recorded progress before deciding what to do next.' };
  }
  function recordedProblem(failure, fallback) {
    if (failure && [404, 409, 413, 422, 503].includes(failure.status) && window.mvPlainDetail) {
      try { return window.mvPlainDetail(failure.detail) || fallback; } catch (_) { /* keep the safe wording */ }
    }
    return fallback;
  }
  function recovery(ui, original, epoch) {
    var link = el('a', null, 'Open recorded tasks');
    var learning = original && (LEARNING_KINDS.has(original.kind) ||
      ['factory_guidance_check', 'factory_guidance_adopt', 'factory_guidance_restore'].includes(original.kind));
    link.href = learning ? '/learned?learning_task=' + encodeURIComponent(original.id) + '#learning-job-history' : '/learning#lo-jobs-panel';
    if (original) {
      var read = el('button', 'btn btn--ghost', 'Read recorded progress');
      read.type = 'button';
      read.addEventListener('click', async function () {
        if (epoch !== contextEpoch || read.disabled) return;
        read.disabled = true;
        try {
          var reply = await request('/api/v1/learning-ops/jobs/' + encodeURIComponent(original.id));
          if (epoch !== contextEpoch) return;
          if (!validJob(reply && reply.job, original)) throw unsupportedReply();
          // Read native progress without calling the renderer that failed.
          await follow(reply.job, { status: ui.status, out: ui.out, action: ui.action });
          if (epoch === contextEpoch) { ui.status.appendChild(document.createTextNode(' ')); ui.status.appendChild(link); }
        } catch (failure) {
          if (failure && [401, 403].includes(failure.status)) { contextChanged(); return; }
          if (epoch !== contextEpoch) return;
          var message = recordedProblem(failure, 'The latest progress could not be confirmed.') +
            ' Do not start this work again to find out.';
          if (epoch === contextEpoch) { ui.status.textContent = message; recovery(ui, original, epoch); }
        } finally { read.disabled = false; }
      });
      ui.status.appendChild(document.createTextNode(' ')); ui.status.appendChild(read);
    }
    ui.status.appendChild(document.createTextNode(' ')); ui.status.appendChild(link);
  }

  // Start a job (POST ``url``), then poll it until it ends. ``ui`` holds:
  // status (element for the progress line), out (element for the result),
  // render(result, job) -> Node|Node[]|null, action (words for errors).
  async function run(url, init, ui) {
    var epoch = contextEpoch;
    surfaces.set(ui.status, ui.out);
    ui.out.textContent = '';
    ui.status.textContent = 'Starting…';
    var job;
    try {
      var reply = await request(url, init);
      job = reply && reply.job;
      if (epoch !== contextEpoch) return null;
    } catch (failure) {
      if (epoch !== contextEpoch) return null;
      if (failure && [401, 403].includes(failure.status)) { contextChanged(); return null; }
      var startProblem = recordedProblem(failure, 'The task start could not be confirmed.');
      if (epoch === contextEpoch) {
        ui.status.textContent = startProblem + ' Read recorded tasks before deciding what to do next. Work is never repeated automatically.';
        recovery(ui, null, epoch);
      }
      return null;
    }
    return follow(job, ui);
  }

  function follow(job, ui) {
    var epoch = contextEpoch;
    surfaces.set(ui.status, ui.out);
    return new Promise(function (resolve) {
      var stop = null, original = jobReference(job), settled = false, timer = null;
      function finish(value) {
        if (settled) return;
        settled = true; clearTimeout(timer); resolve(value);
      }
      async function unconfirmed(failure) {
        try {
          if (epoch !== contextEpoch) return;
          if (failure && [401, 403].includes(failure.status)) { contextChanged(); return; }
          var message = recordedProblem(failure, 'The latest task view could not be confirmed.') +
            ' Work may already be recorded. Do not start it again to find out.';
          if (epoch !== contextEpoch) return;
          ui.out.replaceChildren(); ui.status.textContent = message;
          recovery(ui, original, epoch);
        } catch (_) { /* a broken display must still settle the waiting control */
        } finally { finish(null); }
      }
      function show(j) {
        ui.status.textContent = j.state === 'failed' ? (j.problem || 'This task could not finish. Read its recorded result before deciding what to do next; do not repeat work automatically.') : STATE_TEXT[j.state] || '';
        if (j.observation_saved === false || j.retention_problem) {
          ui.status.textContent += ' ' + (j.retention_problem || 'This live result could not be confirmed in retained history. Read its underlying records before deciding what to do next.');
        }
        if (j.can_stop && !stop) {
          var learning = LEARNING_KINDS.has(j.kind);
          stop = el('button', 'btn btn--ghost', learning ? 'Review a stop' : 'Stop');
          stop.type = 'button';
          stop.addEventListener('click', async function () {
            if (epoch !== contextEpoch) return;
            if (learning) {
              if (!/^[a-f0-9]{16}$/.test(j.id || '')) return;
              window.location.assign('/learned?learning_task=' + encodeURIComponent(j.id) + '#learning-job-history');
              return;
            }
            if (!(await window.mvConfirm('Stop this task? It stops at the next safe point and keeps what it has already done.',
              { okText: 'Stop' }))) return;
            if (epoch !== contextEpoch) return;
            stop.disabled = true;
            try {
              await request('/api/v1/learning-ops/jobs/' + encodeURIComponent(j.id) + '/stop', { method: 'POST', json: {} });
            } catch (failure) {
              var stopProblem = await problem(failure, 'stop the task');
              if (epoch === contextEpoch) { ui.status.textContent = stopProblem; stop.disabled = false; }
            }
          });
          ui.status.appendChild(document.createTextNode(' '));
          ui.status.appendChild(stop);
        } else if (stop && j.can_stop) {
          ui.status.appendChild(document.createTextNode(' '));
          ui.status.appendChild(stop);
        }
      }
      async function tick(j) {
        if (settled) return;
        if (epoch !== contextEpoch) { finish(null); return; }
        if (!validJob(j, original)) throw unsupportedReply();
        original = jobReference(j);
        show(j);
        if (['admitted', 'running', 'stopping'].includes(j.state) && j.worker_available === false) {
          ui.status.textContent = STATE_TEXT.unavailable + (j.retention_problem ? ' ' + j.retention_problem : '');
          recovery(ui, original, epoch);
          finish(null);
          return;
        }
        if (j.state === 'admitted' || j.state === 'running' || j.state === 'stopping') {
          timer = setTimeout(async function () {
            try {
              var reply = await request('/api/v1/learning-ops/jobs/' + encodeURIComponent(j.id));
              await tick(reply && reply.job);
            } catch (failure) {
              await unconfirmed(failure);
            }
          }, POLL_MS);
          return;
        }
        ui.out.textContent = '';
        if (j.result && j.state !== 'failed' && ui.render) {
          var nodes = await ui.render(j.result, j);
          if (epoch !== contextEpoch) { finish(null); return; }
          (Array.isArray(nodes) ? nodes : [nodes]).forEach(function (n) { if (n) ui.out.appendChild(n); });
        }
        finish(j);
      }
      tick(job).catch(unconfirmed);
    });
  }

  // Wire a button to start a job; ``prepare`` returns {url, init} or null
  // (null = the person cancelled or something is missing).
  function wire(button, prepare, ui) {
    if (!button) return;
    button.addEventListener('click', async function () {
      if (button.dataset.inFlight === 'true') return;
      button.dataset.inFlight = 'true';
      try {
        var spec = await prepare();
        if (!spec) return;
        button.disabled = true;
        var job = await run(spec.url, spec.init, ui);
        if (job && ui.after) ui.after(job);
      } finally {
        button.disabled = false;
        delete button.dataset.inFlight;
      }
    });
  }

  function readFile(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(reader.result); };
      reader.onerror = function () { reject(reader.error); };
      reader.readAsArrayBuffer(file);
    });
  }

  function readText(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(reader.result); };
      reader.onerror = function () { reject(reader.error); };
      reader.readAsText(file);
    });
  }

  window.LWJobs = { el: el, plural: plural, money: money, when: when, problem: problem,
    request: request, saveBlob: saveBlob, technical: technical, table: table, run: run,
    follow: follow, wire: wire, readFile: readFile, readText: readText };
})();
