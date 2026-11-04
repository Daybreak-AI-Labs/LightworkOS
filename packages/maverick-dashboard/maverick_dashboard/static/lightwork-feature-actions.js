/* Buttons for features that were only reachable from a terminal, one small
   block per page. Each block starts only when its panel is on the page. The
   server checks every permission; the page also hides controls the signed-in
   person cannot use (data-fa-needs="operate|admin|installation_admin"). */
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
  // A plain server sentence is shown as is; anything else gets the shared
  // plain message.
  async function failText(failure, action) {
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
    if (plain) return plain;
    return errorText(failure, action);
  }
  async function request(url, options) {
    options = options || {};
    var init = {method: options.method || 'GET', cache: 'no-store', raw: !!options.raw, body: options.json};
    if (options.json === undefined && options.body !== undefined) {
      init.headers = {'Content-Type': options.type || 'application/octet-stream'};
      init.body = options.body;
    }
    return window.mvFetchJSON(url, init);
  }
  function say(node, text) { window.mvStatus(node, text || ''); }
  function badge(ok, yes, no) { return el('span', 'badge ' + (ok ? 'ok' : 'warn'), ok ? yes : no); }
  function money(value) {
    var n = Number(value) || 0;
    return window.mvMoney ? window.mvMoney(n) : n.toLocaleString(undefined, {style: 'currency', currency: 'USD'});
  }
  function percent(value) { return Math.round((Number(value) || 0) * 100) + '%'; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function technical(container, rows, title) {
    if (!rows || !rows.length) return;
    var details = el('details', 'fa-technical');
    details.appendChild(el('summary', null, title || 'Technical details'));
    var list = el('ul', 'muted');
    rows.forEach(function (row) { list.appendChild(el('li', null, typeof row === 'string' ? row : row.text)); });
    details.appendChild(list);
    container.appendChild(details);
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

  // ---- who may do what (drives data-fa-needs) --------------------------------
  var accountPromise = null;
  function account() {
    if (!accountPromise) accountPromise = request('/api/v1/account/me').catch(function () { return null; });
    return accountPromise;
  }
  async function applyNeeds() {
    var nodes = document.querySelectorAll('[data-fa-needs]');
    if (!nodes.length) return;
    var me = await account();
    nodes.forEach(function (node) {
      var need = node.getAttribute('data-fa-needs');
      var allowed = me && me.can ? !!me.can[need] : false;
      node.hidden = !allowed;
    });
  }

  // ---- Your account ----------------------------------------------------------
  async function accountPanel() {
    var root = $('fa-account');
    if (!root) return;
    var status = $('fa-account-status');
    var me = await account();
    if (!me) { say(status, 'Could not load your account. Try again.'); return; }
    say(status, '');
    var facts = el('dl', 'fa-facts');
    function fact(label, value) { facts.appendChild(el('dt', null, label)); facts.appendChild(el('dd', null, value)); }
    fact('Signed in as', me.name);
    fact('Role', me.role);
    fact('Role set by', me.role_source);
    fact('Access changes', 'Ask your ' + me.access_owner.toLowerCase() + '. Tool ceilings require an installation administrator.');
    if (me.workspace) fact('Workspace', me.workspace);
    fact('Departments', me.all_departments ? 'All departments' : (me.departments.join(', ') || 'None yet'));
    fact('Departments set by', me.department_source);
    fact('Tools your tasks may use', me.tools + (me.blocked_tools ? ' (' + plural(me.blocked_tools, 'tool') + ' blocked)' : ''));
    fact('Riskiest action allowed', me.risk);
    fact('Tool limits', me.limits_enforced ? 'Enforced' : 'Advisory only (not enforced)');
    fact('Allowed tools', me.allowed_tool_names.length ? me.allowed_tool_names.join(', ') : me.allowed_tool_summary);
    fact('Blocked tools', me.blocked_tool_names.join(', ') || 'No named tool blocks');
    fact('Tool policy set by', me.tool_policy_source);
    fact('Deployment profile', me.profile + (me.profile_overridden ? ' — overridden: enterprise boundary is off' : ''));
    fact('Enterprise boundary', me.enterprise_boundary ? 'Enforced' : 'Off');
    fact('Private content', me.privacy_scope);
    root.appendChild(facts);
    var list = el('ul', 'fa-list');
    me.abilities.forEach(function (a) {
      var li = el('li');
      li.appendChild(badge(a.allowed, 'Yes', 'No'));
      li.appendChild(document.createTextNode(' ' + a.label));
      list.appendChild(li);
    });
    root.appendChild(el('h2', null, 'What you can do'));
    root.appendChild(list);
    root.appendChild(el('h2', null, 'Examples of your base tool limits'));
    root.appendChild(el('p', 'muted', 'These examples describe the current dashboard grant. Task-specific permissions, file and network scope, consent and provider access are checked when the action runs.'));
    (me.tool_examples || []).forEach(function (example) { root.appendChild(el('p', null, example.label + ': ' + (example.allowed ? 'Within the base grant. ' : 'Not currently available. ') + example.reason)); });
    if (me.installation_admin) root.appendChild(el('p', 'muted', 'You can also change settings for the whole installation.'));
  }

  // ---- Knowledge: add to the company brain (cortex deposit) -----------------
  function cortexAdd() {
    var form = $('fa-cortex-add');
    if (!form) return;
    var status = $('fa-cortex-status');
    var submit = form.querySelector('button[type="submit"]'), file = $('fa-cortex-file');
    var busy = false, locked = false, generation = 0, edits = 0, fileGeneration = 0, reading = false;
    function stamp() {
      return JSON.stringify(['text', 'kind', 'source', 'domain', 'collection'].map(function (key) {
        return form.elements[key] ? form.elements[key].value : '';
      }));
    }
    function clear() {
      locked = true; generation++; fileGeneration++; reading = false;
      form.reset();
      Array.from(form.elements).forEach(function (field) { field.disabled = true; });
      say(status, 'Your account, workspace or access changed. Private work was cleared; reload Knowledge before adding anything.');
    }
    form.addEventListener('input', function () { edits++; });
    form.addEventListener('change', function (event) { if (event.target !== file) edits++; });
    window.addEventListener('lightwork:context-changed', clear);
    document.addEventListener('lightwork:workspace-changed', clear);
    document.addEventListener('lightwork:account-context-changed', clear);
    document.addEventListener('lightwork:copilot-context-changed', function (event) {
      if (!event.detail || event.detail.reason !== 'selection') clear();
    });
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (busy || locked) return;
      if (reading) { say(status, 'Wait for the chosen file to finish reading before adding this. Your entered text is kept.'); return; }
      var text = form.elements.text.value.trim();
      if (!text) { say(status, 'Write or paste what you want Lightwork to remember first.'); return; }
      var payload = {text: text, kind: form.elements.kind.value, source: form.elements.source.value.trim()};
      if (form.elements.domain && form.elements.domain.value) payload.domain = form.elements.domain.value;
      if (form.elements.collection && form.elements.collection.value) payload.collection = form.elements.collection.value;
      var submitted = stamp(), submittedEdits = edits, chosenFile = file && file.files[0], bound = generation;
      busy = true;
      submit.disabled = true;
      say(status, 'Adding…');
      try {
        var result = await window.mvFetchJSON('/api/v1/cortex/deposit', {method: 'POST', body: payload, cache: 'no-store', onAccess: clear});
        if (locked || bound !== generation) return;
        if (result.ok) {
          var unchanged = stamp() === submitted && edits === submittedEdits && (!file || file.files[0] === chosenFile);
          if (unchanged) { fileGeneration++; form.reset(); }
          say(status, 'Added. It can be found in searches from now on.' +
            (unchanged ? '' : ' Your newer draft is kept and has not been added.'));
        } else {
          say(status, 'Lightwork did not add this. The source may be turned off or the text may contain private details.');
        }
      } catch (failure) {
        if (!locked && bound === generation) say(status, await failText(failure, 'add this'));
      } finally {
        busy = false;
        submit.disabled = locked;
      }
    });
    if (file) {
      file.addEventListener('change', async function () {
        var current = ++fileGeneration, chosen = file.files[0], entered = stamp(), initialEdits = edits, bound = generation;
        reading = !!chosen;
        if (!chosen || locked) return;
        if (chosen.size > 20000 * 4 + 3) {
          reading = false;
          say(status, 'This file is too long. Keep up to 20,000 characters, or paste the part you want to add. Your draft is kept.');
          return;
        }
        try {
          var text = String(await readFile(chosen, true));
          if (locked || bound !== generation || current !== fileGeneration || file.files[0] !== chosen) return;
          if (text.length > 20000) {
            say(status, 'This file is too long. Keep up to 20,000 characters, or paste the part you want to add. Your draft is kept.');
            return;
          }
          if (edits !== initialEdits || stamp() !== entered) {
            say(status, 'Your draft changed while the file was read. It was kept; choose the file again if you still want to use it.');
            return;
          }
          form.elements.text.value = text;
          if (!form.elements.source.value) form.elements.source.value = chosen.name;
          say(status, 'File ready. Review the text before adding it.');
        } catch (failure) {
          if (!locked && bound === generation && current === fileGeneration) say(status, 'That file could not be read. Choose a text file.');
        } finally {
          if (current === fileGeneration) reading = false;
        }
      });
    }
  }

  // ---- Privacy: check column names, vendor summary, rebuild connections -----
  function columnCheck() {
    var button = $('fa-dm-check');
    if (!button) return;
    var status = $('fa-dm-check-status');
    var out = $('fa-dm-check-out');
    button.addEventListener('click', async function () {
      var columns = $('fa-dm-columns').value.split(/[\n,]+/).map(function (c) { return c.trim(); }).filter(Boolean);
      out.textContent = '';
      if (!columns.length) { say(status, 'Enter at least one column name.'); return; }
      button.disabled = true;
      say(status, 'Checking…');
      try {
        var data = await request('/api/v1/data-map/classify', {method: 'POST', json: {columns: columns.slice(0, 400)}});
        var flagged = Object.keys(data.flagged || {});
        if (!flagged.length) { say(status, 'None of these names look like personal data.'); return; }
        say(status, plural(flagged.length, 'column') + ' of ' + columns.length + ' probably hold personal data.');
        out.appendChild(table(['Column', 'Likely holds'], flagged.map(function (name) {
          return [name, data.flagged[name].map(function (c) { return window.mvHuman ? window.mvHuman(c) : c; }).join(', ')];
        })));
      } catch (failure) {
        say(status, await failText(failure, 'check the column names'));
      } finally {
        button.disabled = false;
      }
    });
  }
  async function vendorSummary() {
    var box = $('fa-vendor-posture');
    if (!box) return;
    try {
      var data = await request('/api/v1/vendors/posture');
      var parts = [plural(data.vendors, 'vendor')];
      var crit = data.by_criticality || {};
      ['critical', 'high'].forEach(function (level) {
        if (crit[level]) parts.push(crit[level] + ' ' + level + ' risk');
      });
      if (data.critical_monitoring_notes) parts.push(plural(data.critical_monitoring_notes, 'urgent monitoring alert'));
      box.textContent = parts.join(' · ');
      var status = data.by_status || {};
      var list = el('ul', 'fa-inline');
      Object.keys(status).forEach(function (key) {
        if (!status[key]) return;
        list.appendChild(el('li', 'badge', (window.mvHuman ? window.mvHuman(key) : key) + ': ' + status[key]));
      });
      if (list.children.length) box.appendChild(list);
    } catch (failure) {
      box.textContent = errorText(failure, 'load the vendor summary');
    }
  }
  function graphRebuild() {
    var button = $('fa-graph-rebuild');
    if (!button) return;
    var status = $('fa-graph-status');
    button.addEventListener('click', async function () {
      button.disabled = true;
      say(status, 'Rebuilding. This can take a minute…');
      try {
        var data = await request('/api/v1/graph/rebuild', {method: 'POST'});
        if (data.enabled === false) { say(status, 'Connections are turned off, so there is nothing to rebuild.'); return; }
        say(status, 'Rebuilt: ' + plural(data.entities, 'record') + ' and ' + plural(data.edges, 'connection') + '.');
      } catch (failure) {
        say(status, await failText(failure, 'rebuild the connections'));
      } finally {
        button.disabled = false;
      }
    });
  }

  // ---- Skills: check a skill file before adding it (skill validate) ---------
  function skillCheck() {
    var input = $('fa-skill-file');
    if (!input) return;
    var status = $('fa-skill-status');
    var out = $('fa-skill-out');
    input.addEventListener('change', async function () {
      out.textContent = '';
      if (!input.files.length) return;
      say(status, 'Checking…');
      try {
        var text = await readFile(input.files[0], true);
        var data = await request('/api/v1/skills/validate', {method: 'POST', body: text, type: 'text/markdown'});
        var errors = data.errors || [], warnings = data.warnings || [];
        if (data.ok && !warnings.length) say(status, 'This skill passes every check. You can add it.');
        else if (data.ok) say(status, 'This skill can be added. There ' + (warnings.length === 1 ? 'is 1 suggestion' : 'are ' + warnings.length + ' suggestions') + ' to improve it.');
        else say(status, 'This skill cannot be added yet: ' + plural(errors.length, 'problem') + ' must be fixed first.');
        technical(out, errors.concat(warnings));
      } catch (failure) {
        say(status, await failText(failure, 'check the skill'));
      }
    });
  }

  // ---- Spend: split by tag (diag cost-by-tag) --------------------------------
  function costByTag() {
    var button = $('fa-tags-run');
    if (!button) return;
    var status = $('fa-tags-status');
    var out = $('fa-tags-out');
    button.addEventListener('click', async function () {
      button.disabled = true;
      out.textContent = '';
      say(status, 'Adding up…');
      try {
        var data = await request('/api/v1/cost/by-tag?tag_field=' + encodeURIComponent($('fa-tags-field').value));
        var buckets = data.buckets || [];
        if (!buckets.length) { say(status, 'No priced tasks yet. Spending shows here after tasks finish.'); return; }
        say(status, 'Spending for ' + plural(buckets.length, 'group') + '.');
        out.appendChild(table(['Group', 'Spent', 'Tasks'], buckets.slice(0, 100).map(function (b) {
          return [b.tag === '(untagged)' ? 'Not labelled' : b.tag, money(b.cost), b.runs];
        })));
      } catch (failure) {
        say(status, await failText(failure, 'split spending'));
      } finally {
        button.disabled = false;
      }
    });
  }

  // ---- Workforce: how much each specialist may do alone ---------------------
  var RUNGS = {observe: 'Watch only', suggest: 'Suggest', request: 'Ask before acting', auto: 'Act on their own'};
  async function workforcePosture() {
    var box = $('fa-autonomy');
    if (!box) return;
    var status = $('fa-autonomy-status');
    try {
      var data = await request('/api/v1/workforce/posture');
      box.textContent = '';
      say(status, data.levels_enabled ? 'Each agent and specialist has its own level of independence.' :
        'Independence levels are turned off, so every agent and specialist follows the same approval rules.');
      // With levels off the per-level split is not applied to anything, so it
      // is not shown: the line above already says every specialist is treated alike.
      if (data.levels_enabled) {
        var list = el('ul', 'fa-inline');
        Object.keys(RUNGS).forEach(function (rung) {
          list.appendChild(el('li', 'badge', RUNGS[rung] + ': ' + ((data.autonomy_posture || {})[rung] || 0)));
        });
        if (data.packs_onboarding) list.appendChild(el('li', 'badge', 'Still learning the ropes: ' + data.packs_onboarding));
        box.appendChild(list);
      } else if (data.can_manage) {
        var setup = el('p', 'muted');
        setup.appendChild(el('span', null, 'To use these controls, turn on '));
        var settings = el('a', null, 'Per-agent independence levels');
        settings.href = '/settings/all?id=workforce.levels';
        setup.appendChild(settings);
        setup.appendChild(el('span', null, ' in Settings.'));
        box.appendChild(setup);
      }
      var cands = data.graduation_candidates || [];
      if (!cands.length) {
        box.appendChild(el('p', 'muted', 'No agent or specialist has earned more independence yet. They qualify after a series of approved tasks.'));
        return;
      }
      box.appendChild(el('h3', null, 'Ready for more independence'));
      box.appendChild(table(['Name', 'Approved work', 'Approval rate', 'Next step'], cands.map(function (c) {
        var link = el('a', null, window.mvHuman ? window.mvHuman(c.name) : c.name);
        link.href = '/agents?name=' + encodeURIComponent(c.name) + '#agent-autonomy';
        var action = el('span');
        if (c.can_grant) {
          var grant = el('button', 'btn btn--primary', 'Grant independence');
          grant.type = 'button';
          grant.addEventListener('click', async function () {
            if (grant.disabled) return;
            if (!(await window.mvConfirm('End supervision for ' + link.textContent + '? Its configured independence levels will take effect.',
                                         {okText: 'Grant independence'}))) return;
            grant.disabled = true;
            try {
              await request('/api/v1/agents/' + encodeURIComponent(c.name) + '/graduate',
                            {method: 'POST', json: {expected_generation: c.generation}});
              await workforcePosture();
              say(status, link.textContent + ' was granted its configured independence levels.');
            } catch (failure) {
              say(status, await failText(failure, 'grant independence'));
              grant.disabled = false;
            }
          });
          action.appendChild(grant);
        } else {
          var review = el('a', null, 'Review policy');
          review.href = link.href;
          action.appendChild(review);
          if (c.grant_block_reason) action.appendChild(el('p', 'muted', c.grant_block_reason));
        }
        return [link, c.sample, percent(c.approve_rate), action];
      })));
      technical(box, cands.map(function (c) { return c.name + ': ' + c.reason; }));
    } catch (failure) {
      say(status, errorText(failure, 'load independence levels'));
    }
  }

  // ---- Safety: how well the screening is tuned (calibrate) -----------------
  var LEVELS = {low: 'Strict', medium: 'Balanced', high: 'Relaxed', critical: 'Most relaxed'};
  function calibration() {
    var button = $('fa-calibration-run');
    if (!button) return;
    var status = $('fa-calibration-status');
    var out = $('fa-calibration-out');
    button.addEventListener('click', async function () {
      button.disabled = true;
      out.textContent = '';
      say(status, 'Testing against known attacks…');
      try {
        var data = await request('/api/v1/shield/calibration');
        var levels = Object.keys(data.thresholds || {});
        say(status, 'Tested with ' + plural(data.cases, 'example message') + '.');
        out.appendChild(table(['Screening level', 'Attacks caught', 'Safe messages wrongly stopped'], levels.map(function (lvl) {
          var s = data.thresholds[lvl];
          return [LEVELS[lvl] || (window.mvHuman ? window.mvHuman(lvl) : lvl), percent(s.recall), percent(s.fp_rate)];
        })));
        var rules = Object.keys(data.rule_hits || {}).slice(0, 20);
        technical(out, rules.map(function (r) { return r + ': ' + data.rule_hits[r]; }), 'Which checks fired (technical)');
      } catch (failure) {
        say(status, await failText(failure, 'test the screening'));
      } finally {
        button.disabled = false;
      }
    });
  }

  // ---- Learning: what the outcome engine learned (flywheel) ----------------
  async function flywheel() {
    var box = $('fa-flywheel');
    if (!box) return;
    var status = $('fa-flywheel-status');
    try {
      var data = await request('/api/v1/flywheel');
      var signal = data.signal || {};
      say(status, 'Learned from ' + plural(signal.grounded_outcomes || 0, 'real outcome') + ' and ' +
        plural(signal.human_feedback || 0, 'piece') + ' of feedback from people.');
      var guards = data.guardrails || [], habits = data.habits || [];
      if (!guards.length && !habits.length) {
        box.appendChild(el('p', 'muted', 'Nothing learned yet. This fills in as tasks finish and people give feedback.'));
        return;
      }
      if (guards.length) {
        box.appendChild(el('h3', null, 'Things it now avoids'));
        var gl = el('ul', 'fa-list');
        guards.slice(0, 20).forEach(function (g) { gl.appendChild(el('li', null, window.mvHuman ? window.mvHuman(g.action) : g.action)); });
        box.appendChild(gl);
      }
      if (habits.length) {
        box.appendChild(el('h3', null, 'Habits that help'));
        var hl = el('ul', 'fa-list');
        habits.slice(0, 20).forEach(function (h) { hl.appendChild(el('li', null, window.mvHuman ? window.mvHuman(h.action) : h.action)); });
        box.appendChild(hl);
      }
    } catch (failure) {
      say(status, errorText(failure, 'load what was learned'));
    }
  }

  // ---- Learning: share lessons with a trusted installation -----------------
  function lessons() {
    var root = $('fa-lessons');
    if (!root) return;
    var status = $('fa-lessons-status');
    var out = $('fa-lessons-out');
    $('fa-lessons-export').addEventListener('click', async function () {
      say(status, 'Packaging lessons…');
      try {
        var response = await request('/api/v1/learning-exchange/export', {method: 'POST', raw: true,
          json: {how_many: Number($('fa-lessons-count').value)}});
        saveBlob(await response.blob(), 'Lightwork-lessons.json');
        say(status, 'Downloaded ' + plural(Number(response.headers.get('X-Lightwork-Lessons') || 0), 'lesson') + '.');
      } catch (failure) {
        say(status, await failText(failure, 'download lessons'));
      }
    });
    var file = $('fa-lessons-file');
    file.addEventListener('change', async function () {
      out.textContent = '';
      if (!file.files.length) return;
      say(status, 'Checking the file…');
      try {
        var raw = await readFile(file.files[0], false);
        var preview = await request('/api/v1/learning-exchange/preview', {method: 'POST', body: raw, type: 'application/json'});
        say(status, preview.summary);
        if (preview.lessons.length) {
          var list = el('ul', 'fa-list');
          preview.lessons.forEach(function (text) { list.appendChild(el('li', null, text)); });
          out.appendChild(list);
        }
        technical(out, preview.technical);
        if (!preview.usable) return;
        var add = el('button', 'btn btn--primary', 'Add these lessons');
        add.type = 'button';
        add.addEventListener('click', async function () {
          var ok = await window.mvConfirm('Add ' + plural(preview.count, 'lesson') + ' from the other installation? Your agents start using them on their next tasks.', {okText: 'Add lessons'});
          if (!ok) return;
          add.disabled = true;
          try {
            var result = await request('/api/v1/learning-exchange/import', {method: 'POST', body: raw, type: 'application/json'});
            out.textContent = '';
            if (result.audit_complete === false || result.outcome === 'unconfirmed') {
              say(status, result.message);
              return;
            }
            say(status, 'Added ' + plural(result.added, 'lesson') + '. Anything private or unsafe was left out.');
          } catch (failure) {
            say(status, await failText(failure, 'add the lessons'));
            add.disabled = false;
          }
        });
        out.appendChild(add);
      } catch (failure) {
        say(status, await failText(failure, 'check the file'));
      }
    });
  }

  // ---- Roles: move customizations (overrides export / load) ----------------
  function customizations() {
    var root = $('fa-custom');
    if (!root) return;
    var status = $('fa-custom-status');
    var out = $('fa-custom-out');
    $('fa-custom-export').addEventListener('click', async function () {
      say(status, 'Packaging your customizations…');
      try {
        var response = await request('/api/v1/customizations/export', {raw: true});
        saveBlob(await response.blob(), 'Lightwork-customizations.zip');
        say(status, 'Downloaded ' + plural(Number(response.headers.get('X-Lightwork-Specialists') || 0), 'agent or specialist change', 'agent and specialist changes') +
          ' and ' + plural(Number(response.headers.get('X-Lightwork-Roles') || 0), 'role change') + '.');
      } catch (failure) {
        say(status, await failText(failure, 'download customizations'));
      }
    });
    var file = $('fa-custom-file');
    file.addEventListener('change', async function () {
      out.textContent = '';
      if (!file.files.length) return;
      say(status, 'Checking the file…');
      try {
        var raw = await readFile(file.files[0], false);
        var preview = await request('/api/v1/customizations/preview', {method: 'POST', body: raw, type: 'application/zip'});
        say(status, preview.summary);
        if (preview.items.length) {
          out.appendChild(table(['What', 'Name', 'Result'], preview.items.map(function (item) {
            return [item.kind, item.name, badge(item.ok, 'Will be loaded', 'Will be skipped')];
          })));
        }
        technical(out, preview.technical);
        if (!preview.usable) return;
        var load = el('button', 'btn btn--primary', 'Load these customizations');
        load.type = 'button';
        load.addEventListener('click', async function () {
          var ok = await window.mvConfirm('Load ' + plural(preview.usable, 'customization') + '? Matching agents, specialists and roles in this workspace are replaced by the ones in the file.', {okText: 'Load'});
          if (!ok) return;
          load.disabled = true;
          try {
            var result = await request('/api/v1/customizations/load', {method: 'POST', body: raw, type: 'application/zip'});
            out.textContent = '';
            say(status, 'Loaded ' + plural(result.specialists, 'agent or specialist change', 'agent and specialist changes') + ' and ' + plural(result.roles, 'role change') +
              (result.skipped ? '; ' + result.skipped + ' skipped.' : '.'));
            technical(out, result.technical);
          } catch (failure) {
            say(status, await failText(failure, 'load the customizations'));
            load.disabled = false;
          }
        });
        out.appendChild(load);
      } catch (failure) {
        say(status, await failText(failure, 'check the file'));
      }
    });
  }

  // ---- Tool servers: browse the registry and add one -----------------------
  function registry() {
    var root = $('fa-registry');
    if (!root) return;
    var status = $('fa-registry-status');
    var out = $('fa-registry-out');
    var search = $('fa-registry-search');
    var servers = [];
    function render() {
      out.textContent = '';
      var q = search.value.trim().toLowerCase();
      var shown = servers.filter(function (s) {
        return !q || s.name.toLowerCase().indexOf(q) >= 0 || s.summary.toLowerCase().indexOf(q) >= 0;
      });
      if (!shown.length) { out.appendChild(el('p', 'muted', q ? 'No tool servers match your search.' : 'The list is empty.')); return; }
      out.appendChild(table(['Tool server', 'What it does', 'Where it runs', ''], shown.slice(0, 200).map(function (s) {
        var name = el('span', null, s.name);
        if (s.verified) { name.appendChild(document.createTextNode(' ')); name.appendChild(el('span', 'badge ok', 'Verified')); }
        var look = el('button', 'btn', 'Look before adding');
        look.type = 'button';
        look.setAttribute('aria-label', 'Look at ' + s.name + ' before adding it');
        look.addEventListener('click', function () { preview(s); });
        return [name, s.summary, s.online ? 'Online service' : 'On this computer', look];
      })));
    }
    // Before adding: the exact program or address, and (on request) its tools.
    async function preview(s) {
      var box = $('fa-registry-preview');
      box.textContent = '';
      say(status, 'Looking up ' + s.name + '…');
      var p;
      try {
        p = await request('/api/v1/mcp-registry/preview', {method: 'POST', json: {name: s.name}});
      } catch (failure) {
        say(status, await failText(failure, 'look up the tool server'));
        return;
      }
      say(status, 'Check what ' + p.name + ' does before adding it.');
      box.appendChild(el('h3', null, 'Before adding ' + p.name));
      var facts = [['Where it runs', p.online ? 'On another company\'s computers' : 'On this computer']];
      if (p.online) facts.push(['Web address it connects to', p.address]);
      else {
        facts.push(['Program it starts', [p.program].concat(p.arguments).join(' ')]);
        facts.push(['Program checked before it starts', p.program_checked ? 'Yes, against its published fingerprint' : 'No']);
      }
      if (p.settings.length) facts.push(['Settings it is given', p.settings.join(', ')]);
      if (p.gets_every_server_setting) facts.push(['Also given', 'Every setting of this server, including its passwords and keys']);
      if (p.extra_headers.length) facts.push(['Extra details sent with each request', p.extra_headers.join(', ')]);
      box.appendChild(table(['Detail', 'Value'], facts));
      var tools = el('div');
      var ask = el('button', 'btn btn--ghost', 'Ask which tools it offers');
      ask.type = 'button';
      ask.addEventListener('click', async function () {
        var ok = await window.mvConfirm('Start ' + p.name + ' once to ask which tools it offers? ' +
          (p.online ? 'Lightwork contacts its web address.' : 'Lightwork runs its program on this computer for a few seconds.') +
          ' Nothing is added.', {okText: 'Ask'});
        if (!ok) return;
        ask.disabled = true;
        tools.textContent = '';
        try {
          var found = await request('/api/v1/mcp-registry/tools', {method: 'POST', json: {name: p.name, fingerprint: p.fingerprint, confirm: true}});
          if (!found.tools.length) tools.appendChild(el('p', 'muted', 'It answered, but offers no tools.'));
          else tools.appendChild(table(['Tool', 'What it does'], found.tools.map(function (t) { return [t.name, t.description]; })));
        } catch (failure) {
          tools.appendChild(el('p', 'muted', await failText(failure, 'ask the tool server')));
        } finally {
          ask.disabled = false;
        }
      });
      var add = el('button', 'btn btn--primary', 'Add this tool server');
      add.type = 'button';
      add.addEventListener('click', async function () {
        var ok = await window.mvConfirm('Add the ' + p.name + ' tool server? Agents can use its tools from their next task.' +
          (p.online ? ' It runs on another company\'s computers, so task details may be sent there.' : ' It runs on this computer.'), {okText: 'Add'});
        if (!ok) return;
        add.disabled = true;
        try {
          await request('/api/v1/mcp-registry/add', {method: 'POST', json: {name: p.name, fingerprint: p.fingerprint}});
          box.textContent = '';
          say(status, p.name + ' was added. Reload the page and press Test to check that it works.');
        } catch (failure) {
          say(status, await failText(failure, 'add the tool server'));
          add.disabled = false;
        }
      });
      var row = el('p', 'fa-row');
      row.appendChild(ask);
      row.appendChild(add);
      box.appendChild(row);
      box.appendChild(tools);
    }
    $('fa-registry-load').addEventListener('click', async function () {
      say(status, 'Loading the list…');
      try {
        var data = await request('/api/v1/mcp-registry');
        if (!data.configured) { say(status, 'No tool server list is set up for this installation. Whoever installed Lightwork can add one.'); return; }
        servers = data.servers || [];
        say(status, plural(servers.length, 'tool server') + ' available.');
        search.hidden = false;
        render();
      } catch (failure) {
        say(status, await failText(failure, 'load the list'));
      }
    });
    search.addEventListener('input', render);
  }

  function start() {
    applyNeeds();
    accountPanel();
    cortexAdd();
    columnCheck();
    vendorSummary();
    graphRebuild();
    skillCheck();
    costByTag();
    workforcePosture();
    calibration();
    flywheel();
    lessons();
    customizations();
    registry();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
  window.lightworkFeatureActions = {start: start};
})();
