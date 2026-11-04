/* Buttons for skill, add-on, connector and template operations that were
   only reachable from a terminal. Each block starts only when its panel is on
   the page; the server checks every permission and confirmation again. */
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
  function when(ts) { return ts && window.mvWhen ? window.mvWhen(ts) : (ts ? new Date(ts * 1000).toLocaleString() : 'Never'); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function say(node, text) { window.mvStatus(node, text || ''); }
  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function failText(failure, action) {
    try {
      var detail = failure && failure.detail;
      if (failure && typeof failure.clone === 'function') detail = ((await failure.clone().json()) || {}).detail;
      var plain = window.mvPlainDetail ? window.mvPlainDetail(detail) : '';
      if (plain) return plain;
    } catch (ignored) { /* not a readable body */ }
    return errorText(failure, action);
  }
  // JSON through the shared helper; raw: the Response itself (a download).
  async function request(url, options) {
    options = options || {};
    if (!options.raw) {
      return window.mvFetchJSON(url, {method: options.method || 'GET', cache: 'no-store', body: options.json});
    }
    var init = {method: options.method || 'GET', cache: 'no-store', credentials: 'same-origin',
      headers: {Accept: 'application/json'}};
    if (options.json !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(options.json);
    }
    var response = await window.fetch(url, init);
    if (!response.ok) throw response;
    return response;
  }
  function table(headers, rows, caption) {
    var wrap = el('div', 'to-scroll');
    var t = el('table');
    if (caption) t.appendChild(el('caption', 'sr-only', caption));
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
  function technical(container, rows) {
    if (!rows || !rows.length) return;
    var details = el('details', 'to-technical');
    details.appendChild(el('summary', null, 'Technical details'));
    var list = el('ul', 'muted');
    rows.forEach(function (row) { list.appendChild(el('li', null, typeof row === 'string' ? row : row.text)); });
    details.appendChild(list);
    container.appendChild(details);
  }
  function button(label, cls) {
    var b = el('button', 'btn ' + (cls || ''), label);
    b.type = 'button';
    return b;
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
  function list(items, cls) {
    var ul = el('ul', cls || 'to-list');
    items.forEach(function (item) { ul.appendChild(el('li', null, item)); });
    return ul;
  }

  // ---- Skills: add from a web address after a check ------------------------
  function skillSource() {
    var kind = (document.querySelector('input[name="to-skill-kind"]:checked') || {}).value || 'web';
    if (kind === 'github') {
      var project = $('to-skill-gh-project').value.trim().replace(/^https:\/\/github\.com\//, '').replace(/\/+$/, '');
      var file = $('to-skill-gh-file').value.trim().replace(/^\/+/, '');
      if (!/^[\w.-]+\/[\w.-]+$/.test(project)) return {error: 'Enter the GitHub project as its owner and name, for example your-company/skills.'};
      if (file && !/^[\w./-]+$/.test(file)) return {error: 'The file name may only use letters, numbers, dots, dashes and slashes.'};
      return {source: 'gh:' + project + (file ? ':' + file : '')};
    }
    var url = $('to-skill-url').value.trim();
    if (!/^https:\/\//.test(url)) return {error: 'Enter the web address of the skill, starting with https://.'};
    return {source: url};
  }
  function skillKind() {
    var kind = (document.querySelector('input[name="to-skill-kind"]:checked') || {}).value || 'web';
    $('to-skill-web').hidden = kind !== 'web';
    $('to-skill-gh').hidden = kind !== 'github';
  }
  function renderSkillPreview(out, status, source, p) {
    out.textContent = '';
    var card = el('div', 'panel to-card');
    card.appendChild(el('h3', null, p.name ? human(p.name) : 'Unnamed skill'));
    if (p.triggers.length) {
      card.appendChild(el('p', 'muted', 'Used when a task mentions:'));
      var tags = el('div', 'to-tags');
      p.triggers.forEach(function (t) { tags.appendChild(el('span', 'badge', t)); });
      card.appendChild(tags);
    }
    card.appendChild(el('p', null, p.tools.length ? 'Tools it can use: ' + p.tools.map(human).join(', ') + '.' :
      'It does not list any tools.'));
    if (p.signed) card.appendChild(el('p', 'muted', 'It is signed by its publisher. The signature is checked when it is added.'));
    card.appendChild(el('p', 'muted', 'What it tells agents to do' + (p.instructions_cut_short ? ' (the beginning):' : ':')));
    card.appendChild(el('div', 'to-text', p.instructions || 'No instructions.'));
    if (p.problems.length) {
      card.appendChild(el('p', null, 'Must be fixed by whoever wrote it:'));
      card.appendChild(list(p.problems));
    }
    if (p.suggestions.length) {
      card.appendChild(el('p', 'muted', 'Suggestions:'));
      card.appendChild(list(p.suggestions));
    }
    technical(card, p.technical);
    out.appendChild(card);
    if (!p.ok) { say(status, 'This skill cannot be added yet: ' + plural(p.problems.length, 'problem') + ' must be fixed first.'); return; }
    say(status, 'This skill passes the checks. Read what it does, then add it if you trust where it came from.');
    var add = button('Add this skill', 'btn--primary');
    add.addEventListener('click', async function () {
      var label = p.name ? human(p.name) : 'this skill';
      var ok = await window.mvConfirm('Add the skill “' + label + '”? Agents follow its instructions from the next task. Only continue if you trust where it came from.', {okText: 'Add skill'});
      if (!ok) return;
      add.disabled = true;
      say(status, 'Adding…');
      try {
        var s = await request('/api/v1/skills/source-install', {method: 'POST', json: {source: source, fingerprint: p.fingerprint, confirm: true}});
        if (window.lwAppendSkill) window.lwAppendSkill(s);
        out.textContent = '';
        say(status, 'Added ' + human(s.name) + '. Agents use it from the next task.');
      } catch (failure) {
        say(status, await failText(failure, 'add the skill'));
        add.disabled = false;
      }
    });
    out.appendChild(add);
  }
  function skillInstall() {
    var check = $('to-skill-check');
    if (!check) return;
    var status = $('skill-install-msg');
    var out = $('to-skill-preview');
    document.querySelectorAll('input[name="to-skill-kind"]').forEach(function (r) { r.addEventListener('change', skillKind); });
    skillKind();
    check.addEventListener('click', async function () {
      out.textContent = '';
      var picked = skillSource();
      if (picked.error) { say(status, picked.error); return; }
      check.disabled = true;
      say(status, 'Reading and checking the skill…');
      try {
        var p = await request('/api/v1/skills/source-preview', {method: 'POST', json: {source: picked.source}});
        renderSkillPreview(out, status, picked.source, p);
      } catch (failure) {
        say(status, await failText(failure, 'check the skill'));
      } finally {
        check.disabled = false;
      }
    });
  }

  // ---- Skills suggested by completed work ---------------------------------
  function learnedSkills() {
    var panel = $('to-learned-skills'); if (!panel) return;
    var status = $('to-learned-status'), suggestions = $('to-learned-list'), added = $('to-learned-added');
    var preview = $('to-learned-review'), result = $('to-learned-result'), history = $('to-learned-history');
    var original = $('to-learned-original'), reload = $('to-learned-refresh');
    var context = null, pending = null, busy = false, generation = 0, reviewGeneration = 0;
    function lock(value) {
      busy = value;
      panel.querySelectorAll('button,input').forEach(function (item) { item.disabled = value; });
      original.disabled = value || !pending;
      var confirm = preview.querySelector('[data-confirm]');
      var checked = preview.querySelector('input[type="checkbox"]');
      if (confirm) confirm.disabled = value || !checked || !checked.checked;
    }
    function invalidate() { reviewGeneration++; preview.replaceChildren(); }
    function changed() {
      generation++; invalidate(); context = null; pending = null;
      suggestions.replaceChildren(); added.replaceChildren(); result.replaceChildren(); history.replaceChildren();
      lock(false); say(status, 'Your account, workspace or access changed. Refresh suggestions before continuing.');
    }
    async function call(url, options) {
      options = options || {};
      try {
        return await window.mvFetchJSON(url, {method: options.method || 'GET', cache: 'no-store',
          body: options.json, timeout: 30000, onAccess: changed});
      } catch (failure) {
        if (failure.status === 409 && String(failure.detail || '').indexOf('Your account or workspace changed.') === 0) changed();
        throw failure;
      }
    }
    function preserve(operation) {
      pending = operation;
      original.disabled = busy || !pending;
      if (context && pending) {
        try { sessionStorage.setItem('learned-skill-change:' + context, pending); } catch (_) {}
        document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {
          detail: {selection: {kind: 'learned_skill_change', operation: pending}}}));
      }
    }
    function show(row) {
      result.replaceChildren();
      result.appendChild(el('h3', null, 'Your original skill change'));
      result.appendChild(el('p', null, row.message));
      if (row.current) result.appendChild(el('p', 'muted sk-small', 'Current skills: ' + row.current));
      if (row.recorded_at) result.appendChild(el('p', 'muted sk-small', 'Recorded ' + when(row.recorded_at)));
    }
    async function readOriginal(operation) {
      if (busy || !context || !/^[a-f0-9]{32}$/.test(operation)) return;
      var started = generation; invalidate(); lock(true);
      try {
        var row = await call('/api/v1/skills/learned-requests/' + encodeURIComponent(operation));
        if (started !== generation) return;
        if (row.context !== context) { changed(); return; }
        preserve(operation); show(row); say(status, 'Read the original result. No skill was added or removed.');
      } catch (failure) {
        if (started === generation) say(status, await failText(failure, 'read the original change') + ' Nothing was repeated.');
      } finally { if (started === generation) lock(false); }
    }
    // Keep the page's installed skills list in step with a confirmed change.
    function syncInstalled(outcome, row) {
      var done = outcome && outcome.confirmed && outcome.result;
      if (!done || typeof done.name !== 'string') return;
      document.querySelectorAll('#installed-skills [data-skill]').forEach(function (card) {
        if (card.getAttribute('data-skill') === done.name) card.remove();
      });
      if (outcome.action === 'admit' && window.lwAppendSkill) {
        window.lwAppendSkill({name: done.name, triggers: row.triggers || [], tools_needed: row.tools || []});
      }
    }
    async function reviewAction(row, action, chosen, nameInput) {
      if (busy || !context) return;
      var started = generation, draft = ++reviewGeneration; preview.replaceChildren(); lock(true);
      try {
        var review = await call('/api/v1/skills/learned-candidates/' + encodeURIComponent(row.name) + '/review',
          {method: 'POST', json: {action: action, fingerprint: row.fingerprint, publish_name: chosen || '', context: context}});
        if (started !== generation || draft !== reviewGeneration) return;
        if (review.context !== context) { changed(); return; }
        preview.appendChild(el('h3', null, action === 'admit' ? 'Review this skill before adding it' : 'Review this skill removal'));
        preview.appendChild(el('p', null, review.message));
        review.changes.forEach(function (change) {
          preview.appendChild(el('h4', null, change.label));
          var text = el('p', null, change.after); text.style.whiteSpace = 'pre-wrap'; text.style.overflowWrap = 'anywhere';
          preview.appendChild(text);
        });
        var label = el('label', 'sk-field'), checked = el('input');
        checked.type = 'checkbox'; label.appendChild(checked);
        label.appendChild(el('span', null, 'I reviewed this exact change and all displayed instructions.'));
        preview.appendChild(label);
        var apply = button(action === 'admit' ? 'Add reviewed skill' : 'Remove reviewed skill', 'btn--primary');
        apply.setAttribute('data-confirm', 'true'); apply.disabled = true; preview.appendChild(apply);
        checked.addEventListener('change', function () { apply.disabled = busy || !checked.checked; });
        apply.addEventListener('click', async function () {
          if (busy || !checked.checked || draft !== reviewGeneration || started !== generation) return;
          if (nameInput && slug(nameInput.value) !== chosen) { invalidate(); say(status, 'The name changed. Review the skill again.'); return; }
          lock(true); preserve(review.operation);
          try {
            var outcome = await call('/api/v1/skills/learned-candidates/' + encodeURIComponent(row.name) + '/' + action,
              {method: 'POST', json: {fingerprint: row.fingerprint, confirm: true, review_token: review.token,
                ...(action === 'admit' ? {publish_name: chosen} : {})}});
            if (started !== generation) return;
            if (outcome.context !== context) { changed(); return; }
            show(outcome); say(status, outcome.message);
            syncInstalled(outcome, row);
            invalidate(); lock(false);
            // Refreshing the lists must not replace the confirmation the person just got.
            if (await refresh()) say(status, outcome.message);
          } catch (failure) {
            if (started === generation) {
              invalidate();
              say(status, await failText(failure, 'change this skill') +
                ' The change may have completed. Check the original result before another decision.');
            }
          } finally { if (started === generation) lock(false); }
        });
      } catch (failure) {
        if (started === generation) say(status, await failText(failure, 'review this skill'));
      } finally { if (started === generation) lock(false); }
    }
    function slug(value) {
      return String(value || '').toLowerCase().normalize('NFKD')
        .replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    }
    async function refresh() {
      if (busy) return null;
      var started = ++generation; invalidate(); lock(true);
      try {
        var data = await call('/api/v1/skills/learned-candidates');
        if (started !== generation) return null;
        if (context && data.context !== context) { changed(); return null; }
        context = data.context; suggestions.replaceChildren(); added.replaceChildren(); history.replaceChildren();
        var rows = data.suggestions || [];
        say(status, data.blocked || (rows.length ? plural(rows.length, 'suggestion') + ' ready for your review.' :
          'No new suggestions yet. Repeated shared successes can produce suggestions for review.'));
        rows.forEach(function (row) {
          var card = el('article', 'panel to-card'); card.appendChild(el('h3', null, human(row.name)));
          card.appendChild(el('p', 'muted sk-small', 'Suggested from completed shared tasks. Review its sources and every instruction before adding it.'));
          var sources = el('p', 'muted sk-small');
          (row.source_tasks || []).forEach(function (id, index) {
            if (index) sources.appendChild(document.createTextNode(' · '));
            var link = el('a', null, 'Task ' + id); link.href = '/chat/goal/' + encodeURIComponent(id); sources.appendChild(link);
          });
          card.appendChild(sources);
          card.appendChild(el('p', null, 'Used when a task mentions: ' + (row.triggers || []).join(', ')));
          card.appendChild(el('p', null, row.tools.length ? 'Tools requested: ' + row.tools.map(human).join(', ') : 'It requests no tools.'));
          card.appendChild(el('p', 'muted sk-small', 'Full instructions:'));
          card.appendChild(el('pre', 'to-text', row.instructions || 'No instructions.'));
          if (row.problems.length) card.appendChild(list(row.problems));
          if (row.ok && data.can_add) {
            var label = el('label', 'sk-field'); label.appendChild(el('span', null, 'Save this skill as'));
            var name = el('input', 'input'); name.type = 'text'; name.maxLength = 96; name.value = human(row.name);
            name.setAttribute('aria-label', 'Name for ' + human(row.name)); label.appendChild(name); card.appendChild(label);
            name.addEventListener('input', invalidate);
            var add = button('Review adding this skill', 'btn--primary');
            add.addEventListener('click', function () {
              var chosen = slug(name.value);
              if (!chosen || chosen.length > 96) { say(status, 'Choose a short name with letters or numbers.'); name.focus(); return; }
              reviewAction(row, 'admit', chosen, name);
            }); card.appendChild(add);
          }
          suggestions.appendChild(card);
        });
        if ((data.added || []).length) {
          added.appendChild(el('h3', null, 'Current added suggestions'));
          added.appendChild(el('p', 'muted sk-small', 'This is the current list. Original change receipts are separate below.'));
          data.added.forEach(function (row) {
            var card = el('div', 'sk-actions'); card.appendChild(el('span', null, human(row.name)));
            if (row.status) card.appendChild(el('span', 'muted sk-small', row.status));
            if (row.recall_ready === true) card.appendChild(el('span', 'muted sk-small',
              row.use_tracking === false ? 'Use history is turned off.' :
                row.uses > 0 ? 'Used on ' + plural(row.uses, 'later task') + '.' : 'No later task has used this skill yet.'));
            var remove = button('Review removal', 'btn--danger'); remove.setAttribute('aria-label', 'Review removal of ' + human(row.name));
            remove.addEventListener('click', function () { reviewAction(row, 'withdraw', ''); });
            card.appendChild(remove); added.appendChild(card);
          });
        }
        // The cards above were built while busy; disable them until the load
        // finishes, or a click in between is silently dropped.
        lock(true);
        var saved = await call('/api/v1/skills/learned-requests');
        if (started !== generation) return null;
        if (saved.context !== context) { changed(); return null; }
        if (saved.requests.length) {
          history.appendChild(el('h3', null, 'Recent original changes'));
          saved.requests.forEach(function (row) {
            var read = button((row.action === 'admit' ? 'Add ' : 'Remove ') + human(row.name) +
              (row.confirmed ? ' · Read original change' : ' · Result unconfirmed'));
            read.addEventListener('click', function () { readOriginal(row.operation); });
            history.appendChild(read);
          });
        }
        if (!pending) {
          var query = new URL(location.href).searchParams.get('learned_request');
          try { pending = query || sessionStorage.getItem('learned-skill-change:' + context); } catch (_) { pending = query; }
          if (!/^[a-f0-9]{32}$/.test(pending || '')) pending = null;
        }
        return data;
      } catch (failure) {
        if (started === generation) say(status, await failText(failure, 'load suggested skills') + ' Your displayed work is kept.');
        return null;
      } finally { if (started === generation) lock(false); }
    }
    original.addEventListener('click', function () { if (pending) readOriginal(pending); });
    reload.addEventListener('click', refresh);
    document.addEventListener('lightwork:workspace-changed', changed);
    document.addEventListener('lightwork:account-context-changed', changed);
    window.addEventListener('lightwork:context-changed', changed);
    document.addEventListener('lightwork:copilot-context-changed', function (event) {
      if (!event.detail || event.detail.reason !== 'selection') changed();
    });
    refresh();
  }

  // ---- Skills: track record ------------------------------------------------
  function rate(row) { return row.win_rate == null ? 'Not known yet' : Math.round(row.win_rate * 100) + '%'; }
  function priority(row) { return row.weight >= 0.995 ? 'Normal' : 'Lowered to ' + Math.round(row.weight * 100) + '%'; }
  function usageRows(skills) {
    return skills.map(function (s) {
      return [human(s.name), s.uses, s.wins, s.losses, rate(s), priority(s), s.last_used ? when(s.last_used) : 'Never'];
    });
  }
  var USAGE_HEAD = ['Skill', 'Times used', 'Tasks it helped', 'Tasks it did not help', 'Success rate', 'Priority', 'Last used'];
  async function skillUsage() {
    var box = $('to-skill-usage');
    if (!box) return;
    var status = $('to-skill-usage-status');
    try {
      var data = await request('/api/v1/skills/usage');
      if (!data.skills.length) { say(status, 'No skills yet. Their track record shows here once agents use them.'); return; }
      var used = data.skills.filter(function (s) { return s.uses; }).length;
      say(status, used ? plural(used, 'skill') + ' used so far. Skills that rarely help are given a lower priority automatically.' :
        'No skill has been used yet. The numbers fill in as agents use them.');
      box.appendChild(table(USAGE_HEAD, usageRows(data.skills), 'How each skill is doing'));
    } catch (failure) {
      say(status, await failText(failure, 'load how skills are doing'));
    }
  }

  // ---- Skills: tidy up the ones that rarely help (skills evict) -------------
  function skillTidy() {
    var find = $('to-tidy-check');
    if (!find) return;
    var status = $('to-tidy-status');
    var out = $('to-tidy-out');
    function rule() { return {min_uses: Number($('to-tidy-uses').value), max_success: Number($('to-tidy-rate').value)}; }
    find.addEventListener('click', async function () {
      out.textContent = '';
      find.disabled = true;
      say(status, 'Looking…');
      var picked = rule();
      try {
        var data = await request('/api/v1/skills/tidy-preview', {method: 'POST', json: picked});
        var found = data.skills;
        if (!found.length) { say(status, 'No skill matches. Every skill that has had a fair trial helps often enough.'); return; }
        say(status, plural(found.length, 'skill') + ' rarely help. Nothing is removed until you confirm.');
        out.appendChild(table(USAGE_HEAD, usageRows(found), 'Skills that rarely help'));
        var remove = button('Remove ' + plural(found.length, 'skill'), 'btn--danger');
        remove.addEventListener('click', async function () {
          var ok = await window.mvConfirm('Remove ' + plural(found.length, 'skill') + ' that rarely help? Agents stop using them from the next task. This cannot be undone.', {okText: 'Remove ' + plural(found.length, 'skill')});
          if (!ok) return;
          remove.disabled = true;
          try {
            var result = await request('/api/v1/skills/tidy', {method: 'POST', json: {min_uses: picked.min_uses, max_success: picked.max_success,
              names: found.map(function (s) { return s.name; }), confirm: true}});
            result.removed.forEach(function (name) {
              document.querySelectorAll('[data-skill]').forEach(function (card) { if (card.getAttribute('data-skill') === name) card.remove(); });
            });
            out.textContent = '';
            say(status, 'Removed ' + plural(result.removed.length, 'skill') + '.' + (result.skipped ? ' ' + plural(result.skipped, 'skill') + ' no longer matched and were kept.' : ''));
          } catch (failure) {
            say(status, await failText(failure, 'remove the skills'));
            remove.disabled = false;
          }
        });
        out.appendChild(remove);
      } catch (failure) {
        say(status, await failText(failure, 'find skills that rarely help'));
      } finally {
        find.disabled = false;
      }
    });
  }

  // ---- Add-ons: approved versions, pinning and reloading ---------------------
  var STATE_CLASS = {match: 'ok', drifted: 'warn', missing: 'warn', unpinned: ''};
  function versions() {
    var box = $('to-versions');
    if (!box) return;
    var status = $('to-versions-status');
    var pin = $('to-versions-pin');
    function render(data) {
      box.textContent = '';
      say(status, data.summary);
      if (data.rule) box.appendChild(el('p', 'muted', data.rule));
      if (!data.addons.length) return;
      box.appendChild(table(['Add-on', 'Approved version', 'Installed version', 'Check', 'Actions'], data.addons.map(function (a) {
        var reload = null;
        if (a.installed) {
          reload = button('Reload', 'btn--ghost');
          reload.setAttribute('aria-label', 'Reload ' + a.name);
          reload.addEventListener('click', async function () {
            var ok = await window.mvConfirm('Reload the add-on “' + a.name + '” from its files on this server? Tasks already running keep the old version until they finish.', {okText: 'Reload'});
            if (!ok) return;
            reload.disabled = true;
            try {
              var result = await request('/api/v1/plugins/reload', {method: 'POST', json: {addon: a.name, confirm: true}});
              say(status, a.name + ' was reloaded (' + plural(result.reloaded_parts, 'part') + '). New tasks use the version on disk.');
            } catch (failure) {
              say(status, await failText(failure, 'reload the add-on'));
            } finally {
              reload.disabled = false;
            }
          });
        }
        return [a.name, a.approved || '—', a.installed || '—', el('span', 'badge ' + (STATE_CLASS[a.state] || ''), a.label), reload || ''];
      }), 'Add-on versions'));
    }
    async function load() {
      try { render(await request('/api/v1/plugins/versions')); } catch (failure) { say(status, await failText(failure, 'check add-on versions')); }
    }
    if (pin) pin.addEventListener('click', async function () {
      var ok = await window.mvConfirm('Pin the versions installed now as the approved ones? From then on, Lightwork compares every add-on against them and flags any change.', {okText: 'Pin versions'});
      if (!ok) return;
      pin.disabled = true;
      try {
        var data = await request('/api/v1/plugins/versions/pin', {method: 'POST', json: {confirm: true}});
        render(data);
        say(status, 'Pinned ' + plural(data.pinned, 'add-on') + '. ' + data.summary);
      } catch (failure) {
        say(status, await failText(failure, 'pin the versions'));
      } finally {
        pin.disabled = false;
      }
    });
    load();
  }

  async function pluginUsage() {
    var box = $('to-plugin-usage');
    if (!box) return;
    var status = $('to-plugin-usage-status');
    try {
      var data = await request('/api/v1/plugins/usage');
      var note = data.counting ? '' : ' Counting is off, so new uses are not counted. An administrator can turn it on in Settings.';
      if (!data.tools.length) { say(status, 'No add-on tool has been used yet.' + note); return; }
      say(status, plural(data.tools.length, 'add-on tool') + ' used.' + note);
      box.appendChild(table(['Tool', 'Add-on', 'Times used', 'Last used'], data.tools.map(function (t) {
        return [human(t.tool), t.addon || '—', t.calls, when(t.last_used)];
      }), 'How often add-on tools are used'));
    } catch (failure) {
      say(status, await failText(failure, 'load add-on use'));
    }
  }

  function starter() {
    var form = $('to-starter-form');
    if (!form) return;
    var status = $('to-starter-status');
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      var name = form.elements.name.value.trim();
      if (!name) { say(status, 'Give the add-on a name first.'); return; }
      var submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      say(status, 'Preparing the starter files…');
      try {
        var response = await request('/api/v1/plugins/starter', {method: 'POST', raw: true, json: {name: name, kind: form.elements.kind.value}});
        var slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
        saveBlob(await response.blob(), slug + '-starter.zip');
        say(status, 'Downloaded. Give it to a developer to build on. Nothing was installed on this server.');
      } catch (failure) {
        say(status, await failText(failure, 'prepare the starter add-on'));
      } finally {
        submit.disabled = false;
      }
    });
  }

  // ---- Connections: systems of record and a change preview -------------------
  function fieldRow(holder) {
    var row = el('div', 'to-field');
    var n = holder.children.length + 1;
    var name = el('input', 'input'); name.type = 'text'; name.maxLength = 80; name.setAttribute('aria-label', 'Field ' + n + ' name');
    name.placeholder = 'Field, for example Amount';
    var kind = el('select', 'select'); kind.setAttribute('aria-label', 'Field ' + n + ' kind of value');
    [['text', 'Text'], ['number', 'Number'], ['yes_no', 'Yes or no'], ['empty', 'Clear it']].forEach(function (o) {
      var opt = el('option', null, o[1]); opt.value = o[0]; kind.appendChild(opt);
    });
    var value = el('input', 'input'); value.type = 'text'; value.maxLength = 2000; value.setAttribute('aria-label', 'Field ' + n + ' new value');
    value.placeholder = 'New value';
    var remove = button('Remove', 'btn--ghost'); remove.setAttribute('aria-label', 'Remove field ' + n);
    remove.addEventListener('click', function () { row.remove(); });
    kind.addEventListener('change', function () { value.disabled = kind.value === 'empty'; });
    row.appendChild(name); row.appendChild(kind); row.appendChild(value); row.appendChild(remove);
    holder.appendChild(row);
  }
  function renderChange(out, r) {
    out.textContent = '';
    out.appendChild(el('p', null, r.summary));
    var facts = [['Risk of this change', r.risk], ['Needs a person to approve it', r.needs_approval ? 'Yes' : 'No']];
    if (r.read_current_values) {
      facts.push(['Could be undone', r.can_undo ? 'Yes' : 'No']);
      if (r.money_at_stake) facts.push(['Money at stake', window.mvMoney ? window.mvMoney(r.money_at_stake) : Number(r.money_at_stake).toLocaleString(undefined, {style: 'currency', currency: 'USD'})]);
    }
    out.appendChild(table(['Question', 'Answer'], facts, 'What this change would do'));
    if (r.undo_note) out.appendChild(el('p', 'muted', r.undo_note));
    out.appendChild(el('p', null, 'This was only a preview. Nothing was changed.'));
    technical(out, r.technical);
  }
  function connectors() {
    var box = $('to-connectors');
    if (!box) return;
    var status = $('to-connectors-status');
    var form = $('to-change-form');
    var fields = $('to-change-fields');
    var out = $('to-change-out');
    function recordShown() { $('to-change-record-wrap').hidden = form.elements.change.value === 'create'; }
    async function load() {
      try {
        var me = await request('/api/v1/account/me');
        if (!me || !me.can || !me.can.installation_admin) return;
      } catch (ignored) { return; }
      $('to-connectors-panel').hidden = false;
      try {
        var data = await request('/api/v1/governed-connectors');
        if (!data.enabled) {
          say(status, 'No system of record is connected for checked changes yet. Whoever installed Lightwork can turn this on in Settings.');
          return;
        }
        say(status, plural(data.connectors.length, 'system') + ' Lightwork may change, each change checked first.');
        box.appendChild(table(['System', 'Risk of a change', 'Needs approval'], data.connectors.map(function (c) {
          return [human(c.name), c.change_risk, c.needs_approval ? 'Yes' : 'No'];
        }), 'Systems of record'));
        var pick = form.elements.connector;
        data.connectors.filter(function (c) { return c.can_address_records; }).forEach(function (c) {
          var opt = el('option', null, human(c.name)); opt.value = c.name; pick.appendChild(opt);
        });
        if (!pick.options.length) return;
        var readBox = form.elements.read_current_values;
        if (!data.can_read_prior) {
          readBox.checked = false; readBox.disabled = true;
          $('to-change-read-note').textContent = 'Reading current values is turned off, so the preview cannot say whether a change could be undone.';
        }
        form.hidden = false;
        fieldRow(fields);
      } catch (failure) {
        say(status, await failText(failure, 'load the connected systems'));
      }
    }
    form.elements.change.addEventListener('change', recordShown);
    $('to-change-add-field').addEventListener('click', function () { fieldRow(fields); });
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      out.textContent = '';
      var rows = Array.prototype.map.call(fields.querySelectorAll('.to-field'), function (row) {
        var controls = row.querySelectorAll('input, select');
        return {name: controls[0].value.trim(), kind: controls[1].value, value: controls[2].value};
      }).filter(function (f) { return f.name; });
      var body = {connector: form.elements.connector.value, change: form.elements.change.value,
        record_type: form.elements.record_type.value.trim(), record_id: form.elements.change.value === 'create' ? '' : form.elements.record_id.value.trim(),
        fields: form.elements.change.value === 'delete' ? [] : rows, read_current_values: !!form.elements.read_current_values.checked};
      var submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      say(status, 'Working out what would happen…');
      try {
        renderChange(out, await request('/api/v1/governed-connectors/preview', {method: 'POST', json: body}));
        say(status, 'Preview ready. Nothing was changed.');
      } catch (failure) {
        say(status, await failText(failure, 'preview the change'));
      } finally {
        submit.disabled = false;
      }
    });
    recordShown();
    load();
  }

  // ---- Templates: download your ratings (template ratings-export) ------------
  async function ratings() {
    var btn = $('to-ratings-download');
    if (!btn) return;
    var status = $('to-ratings-status');
    try {
      var me = await request('/api/v1/account/me');
      if (!me || !me.can || !me.can.installation_admin) return;
    } catch (ignored) { return; }
    $('to-ratings').hidden = false;
    btn.addEventListener('click', async function () {
      btn.disabled = true;
      try {
        var response = await request('/api/v1/templates/ratings-export', {raw: true});
        saveBlob(await response.blob(), 'Lightwork-template-ratings.json');
        say(status, 'Downloaded your ratings. Only the stars are included; your comments stay here.');
      } catch (failure) {
        say(status, await failText(failure, 'download your ratings'));
      } finally {
        btn.disabled = false;
      }
    });
  }

  function start() {
    skillInstall();
    learnedSkills();
    skillUsage();
    skillTidy();
    versions();
    pluginUsage();
    starter();
    connectors();
    ratings();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
  window.lightworkToolOps = {start: start};
})();
