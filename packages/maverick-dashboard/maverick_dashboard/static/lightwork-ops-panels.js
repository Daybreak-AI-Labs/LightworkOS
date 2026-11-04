// Buttons for operations that also exist on the command line: activity log
// checkpoints, security checks on Lightwork's own activity, privacy tools, a
// person's uploaded documents, AI governance checks and downloads, regulatory
// alerts, and reviewer tests. Each panel is wired only when its markup is on
// the page. Plain words only; exact technical wording stays in a collapsed
// "Technical details" section.
(function () {
  'use strict';
  if (window.__lwOpsPanels) return;   // several pages include the script once each
  window.__lwOpsPanels = true;

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = String(text);
    return node;
  }
  function say(node, text) { window.mvStatus(node, String(text || '')); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function human(value) { return window.mvHuman ? window.mvHuman(value) : String(value || ''); }
  // A calendar day in the shared date format ("Oct 6, 2026"); the raw value stays the option value.
  function dayText(day) { return (window.mvDateAbsolute && window.mvDateAbsolute(day)) || String(day || ''); }
  function when(stamp) {
    if (typeof stamp === 'number') return window.mvWhen ? window.mvWhen(stamp) : new Date(stamp * 1000).toLocaleString();
    var d = new Date(stamp);
    return isNaN(d.getTime()) ? '' : window.mvTimeAbsolute ? window.mvTimeAbsolute(stamp) : d.toLocaleString();
  }
  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function failText(failure, action) {
    // A server sentence written for people is shown as is.
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
    if (plain) return plain;
    return errorText(failure, action);
  }
  async function request(url, options) {
    options = options || {};
    return window.mvFetchJSON(url, {method: options.method || 'GET', cache: 'no-store', body: options.json});
  }
  async function confirmed(message, okText) {
    return window.mvConfirm ? window.mvConfirm(message, {okText: okText}) : false;
  }
  function table(headers, rows, caption) {
    var wrap = el('div', 'ops-scroll');
    var t = el('table');
    if (caption) { var c = el('caption', 'sr-only', caption); t.appendChild(c); }
    var head = el('thead'); var hr = el('tr');
    headers.forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; hr.appendChild(th); });
    head.appendChild(hr); t.appendChild(head);
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
  function technical(box, lines, title) {
    if (!box || !lines || !lines.length) return;
    var d = el('details');
    d.appendChild(el('summary', null, title || 'Technical details'));
    var pre = el('pre', 'ops-technical');
    pre.textContent = lines.join('\n');
    d.appendChild(pre);
    box.appendChild(d);
  }
  function button(text, cls) {
    var b = el('button', cls || 'btn btn--ghost', text);
    b.type = 'button';
    return b;
  }
  function readFile(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(String(reader.result || '')); };
      reader.onerror = function () { reject(reader.error); };
      reader.readAsText(file);
    });
  }
  function busy(btn, fn) {
    return async function () {
      if (btn.disabled) return;
      btn.disabled = true;
      try { await fn(); } finally { btn.disabled = false; }
    };
  }

  // ---- who may do what: [data-ops-needs] hides controls a person cannot use
  var accountPromise = null;
  function account() {
    if (!accountPromise) accountPromise = request('/api/v1/account/me').catch(function () { return null; });
    return accountPromise;
  }
  async function applyNeeds() {
    var nodes = document.querySelectorAll('[data-ops-needs]');
    if (!nodes.length) return;
    var me = await account();
    nodes.forEach(function (node) {
      var need = node.getAttribute('data-ops-needs');
      node.hidden = !(me && me.can && me.can[need]);
    });
  }

  // ---- background downloads: start, wait, then offer the file ----------------
  function waitForDownload(statusUrl, done) {
    var tries = 0;
    async function poll() {
      tries += 1;
      try {
        var state = await request(statusUrl);
        if (state.state === 'ready') { done(null, statusUrl + '/download'); return; }
        if (state.state === 'failed') { done(state.message || 'The download could not be prepared. Try again.'); return; }
      } catch (failure) { done(await failText(failure, 'prepare the download')); return; }
      if (tries > 400) { done('This is taking too long. Try again later.'); return; }
      setTimeout(poll, 2000);
    }
    setTimeout(poll, 300);
  }

  // ======================================================================
  // Activity log: independent checkpoints
  // ======================================================================
  function checkpoints() {
    var root = $('ops-ckpt');
    if (!root) return;
    var rows = $('ops-ckpt-rows');
    var result = $('ops-ckpt-result');
    var daySel = $('ops-ckpt-day');
    var canAdmin = root.getAttribute('data-can-admin') === 'true';

    async function load() {
      say(rows, 'Loading…');
      try {
        var data = await request('/api/v1/audit/checkpoints');
        rows.textContent = '';
        if (data.problem) rows.appendChild(el('p', null, data.problem));
        if (daySel) {
          daySel.textContent = '';
          if (!data.days.length) daySel.appendChild(el('option', null, 'No days recorded yet'));
          data.days.forEach(function (d) {
            var o = el('option', null, dayText(d.day) + (d.has_checkpoint ? ' (has a checkpoint)' : ''));
            o.value = d.day;
            daySel.appendChild(o);
          });
        }
        if (!data.checkpoints.length) {
          var how = daySel ? 'Choose a day above and publish its checkpoint to start.' : 'An administrator publishes them.';
          rows.appendChild(window.mvEmpty
            ? window.mvEmpty('No checkpoints yet', 'Published checkpoints appear here, one per day. ' + how, null, { compact: true })
            : el('p', 'muted', 'No checkpoints yet. ' + how));
          return;
        }
        rows.appendChild(table(['Day', 'Kind', 'Entries covered', 'Published', 'Actions'],
          data.checkpoints.map(function (c) {
            var actions = el('span', 'ops-actions');
            var keep = el('a', 'btn btn--ghost', 'Keep a receipt');
            keep.href = '/api/v1/audit/checkpoints/' + encodeURIComponent(c.sequence) + '/receipt';
            keep.setAttribute('download', '');
            keep.setAttribute('aria-label', 'Keep a receipt for the checkpoint of ' + dayText(c.day));
            actions.appendChild(keep);
            if (canAdmin && c.can_retire) {
              var retire = button('Retire', 'btn btn--danger');
              retire.setAttribute('data-sequence', String(c.sequence));
              retire.setAttribute('aria-label', 'Retire the checkpoint of ' + dayText(c.day));
              retire.addEventListener('click', busy(retire, async function () {
                if (!(await confirmed('Retire the checkpoint of ' + dayText(c.day) + '? That day was deleted by your record-keeping policy; retiring records that on purpose so later checks do not flag it. This cannot be undone.', 'Retire'))) return;
                try {
                  await request('/api/v1/audit/checkpoints/retire', {method: 'POST', json: {sequence: c.sequence, confirm: true}});
                  say(result, 'The checkpoint of ' + dayText(c.day) + ' was retired.');
                  await load();
                } catch (failure) { say(result, await failText(failure, 'retire the checkpoint')); }
              }));
              actions.appendChild(retire);
            }
            return [dayText(c.day), c.kind, String(c.entries), when(c.created_at), actions];
          }), 'Published checkpoints, newest first'));
      } catch (failure) {
        say(rows, await failText(failure, 'load the checkpoints'));
      }
    }

    var publish = $('ops-ckpt-publish');
    if (publish) publish.addEventListener('click', busy(publish, async function () {
      var day = daySel && daySel.value;
      if (!day || !/^\d{4}-\d{2}-\d{2}$/.test(day)) { say(result, 'Choose a day first.'); return; }
      var erasure = $('ops-ckpt-erasure') && $('ops-ckpt-erasure').checked;
      var message = erasure
        ? 'Start a new checkpoint for ' + day + ' because its log changed after a person\'s data was erased? The earlier checkpoint stays on record.'
        : 'Publish the checkpoint of ' + dayText(day) + '? It is kept in a separate folder so a later change to that day can be proven.';
      if (!(await confirmed(message, 'Publish'))) return;
      say(result, 'Publishing…');
      try {
        var done = await request('/api/v1/audit/checkpoints/publish', {method: 'POST', json: {day: day, after_erasure: !!erasure}});
        say(result, 'Published checkpoint ' + done.sequence + ' for ' + dayText(done.day) + '. Keep its receipt somewhere else, such as your email, so rolling it back can be caught.');
        await load();
      } catch (failure) { say(result, await failText(failure, 'publish the checkpoint')); }
    }));

    var verify = $('ops-ckpt-verify');
    if (verify) verify.addEventListener('click', busy(verify, async function () {
      var file = $('ops-ckpt-receipt') && $('ops-ckpt-receipt').files[0];
      var receipt = null;
      if (file) {
        if (file.size > 4096) { say(result, 'That file is too large to be a checkpoint receipt.'); return; }
        try { receipt = await readFile(file); } catch (e) { say(result, 'That file could not be read. Choose it again, or try a different file.'); return; }
      }
      say(result, 'Checking…');
      try {
        var v = await request('/api/v1/audit/checkpoints/verify', {method: 'POST', json: {receipt: receipt}});
        result.textContent = '';
        if (v.intact) {
          result.appendChild(el('p', null, 'The signed checkpoint commitments match the retained prefixes of the activity log. Later entries beyond those prefixes are outside this check.' +
            (v.keys_pinned ? ' Every checkpoint is signed with a pinned key.' : '') +
            (v.pinned ? ' Your kept receipt matches too.' : ' Choose a receipt you kept independently to compare checkpoint history through that receipt.')));
        } else if (v.none_yet) {
          result.appendChild(el('p', null, 'No checkpoints have been published yet. Publish one above to fix the audit history at this point.'));
        } else {
          result.appendChild(el('p', null, 'Problems were found:'));
          var ul = el('ul');
          v.problems.forEach(function (p) { ul.appendChild(el('li', null, p)); });
          result.appendChild(ul);
          technical(result, v.technical);
        }
      } catch (failure) { say(result, await failText(failure, 'check the checkpoints')); }
    }));
    load();
    checkpointSettings(load);
  }

  // Where checkpoints are kept and which keys may sign them (installation admins).
  function checkpointSettings(reloadList) {
    var box = $('ops-ckpt-settings');
    if (!box) return;
    var msg = $('ops-ckpt-settings-msg');
    var folder = $('ops-ckpt-folder');
    async function loadSettings() {
      try {
        var data = await request('/api/v1/audit/checkpoints/settings');
        folder.value = data.folder || '';
        var where = data.default_folder ? 'Checkpoints are kept beside each workspace\'s activity log.'
          : 'Checkpoints are kept in ' + data.folder + '.';
        where += data.keys.length ? ' Only checkpoints signed with ' + plural(data.keys.length, 'pinned key') + ' are accepted.'
          : ' Checkpoints signed by any key this installation trusts are accepted.';
        if (data.keys.length && data.signing_on && !data.own_key_pinned) {
          where += ' This installation\'s own key is not pinned, so it cannot publish new checkpoints.';
        }
        say($('ops-ckpt-where'), where);
        var list = $('ops-ckpt-keys');
        list.textContent = '';
        if (!data.keys.length) {
          var none = el('li');
          none.appendChild(window.mvEmpty
            ? window.mvEmpty('No keys pinned', 'Pinned keys appear here. Until you pin one, checkpoints signed by any key this installation trusts are accepted. Pin a key below to accept only the checkpoints it signs.', null, { compact: true })
            : el('span', 'muted', 'No keys are pinned.'));
          list.appendChild(none);
        }
        data.keys.forEach(function (k) {
          var li = el('li');
          li.appendChild(el('span', null, (k.own ? 'This installation\'s key' : 'Key') + ', fingerprint '));
          li.appendChild(el('strong', null, k.fingerprint));
          var remove = button('Unpin');
          remove.setAttribute('aria-label', 'Unpin the key ' + k.fingerprint);
          remove.addEventListener('click', busy(remove, async function () {
            var last = data.keys.length === 1;
            if (last && !(await confirmed('Unpin the last key? Checkpoints signed by any key this installation trusts will be accepted again.', 'Unpin'))) return;
            await save('/api/v1/audit/checkpoints/settings/keys/remove', {fingerprint: k.fingerprint, confirm: last}, 'unpin the key');
          }));
          li.appendChild(document.createTextNode(' '));
          li.appendChild(remove);
          list.appendChild(li);
        });
        box.setAttribute('data-keys', String(data.keys.length));
      } catch (failure) { say($('ops-ckpt-where'), await failText(failure, 'load the checkpoint settings')); }
    }
    async function save(url, body, action) {
      try {
        var r = await request(url, {method: 'POST', json: body});
        say(msg, r.message);
        await loadSettings();
        if (reloadList) await reloadList();
      } catch (failure) { say(msg, await failText(failure, action)); }
    }
    async function pin(body) {
      var widening = Number(box.getAttribute('data-keys') || '0') > 0;
      if (widening && !(await confirmed('Also accept checkpoints signed with this key? The keys already pinned stay pinned.', 'Pin key'))) return;
      body.confirm = widening;
      await save('/api/v1/audit/checkpoints/settings/keys', body, 'pin the key');
    }
    var check = $('ops-ckpt-folder-check');
    check.addEventListener('click', busy(check, async function () {
      say(msg, 'Checking…');
      try {
        var r = await request('/api/v1/audit/checkpoints/settings/folder/check', {method: 'POST', json: {folder: folder.value.trim()}});
        say(msg, r.message);
      } catch (failure) { say(msg, await failText(failure, 'check the folder')); }
    }));
    var use = $('ops-ckpt-folder-save');
    use.addEventListener('click', busy(use, async function () {
      var chosen = folder.value.trim();
      var text = chosen ? 'Keep checkpoints in ' + chosen + ' from now on? Checks will read the checkpoints in that folder, not the ones kept so far.'
        : 'Keep checkpoints beside each workspace\'s activity log again? Checks will read the checkpoints kept there.';
      if (!(await confirmed(text, 'Use this folder'))) return;
      await save('/api/v1/audit/checkpoints/settings/folder', {folder: chosen, confirm: true}, 'use the folder');
    }));
    var own = $('ops-ckpt-key-own');
    own.addEventListener('click', busy(own, async function () { await pin({own_key: true}); }));
    var add = $('ops-ckpt-key-add');
    add.addEventListener('click', busy(add, async function () {
      var text = $('ops-ckpt-key-paste').value.trim();
      if (!text) { say(msg, 'Paste a public key first.'); return; }
      await pin({key: text});
      $('ops-ckpt-key-paste').value = '';
    }));
    var file = $('ops-ckpt-key-file');
    file.addEventListener('change', async function () {
      var f = file.files[0];
      if (!f) return;
      if (f.size > 4096) { say(msg, 'That file is too large to be a public key.'); return; }
      var text;
      try { text = await readFile(f); } catch (e) { say(msg, 'That file could not be read. Choose it again, or try a different file.'); return; }
      await pin({key: text.trim()});
      file.value = '';
    });
    loadSettings();
  }

  // ======================================================================
  // Security: defenses, events, a sweep for attacks, and fixes
  // ======================================================================
  function security() {
    var root = $('ops-sec');
    if (!root) return;
    var canInstall = root.getAttribute('data-can-install') === 'true';

    async function posture() {
      var box = $('ops-sec-defenses');
      try {
        var data = await request('/api/v1/security/own/posture');
        box.textContent = '';
        box.appendChild(el('p', null, data.summary));
        var ul = el('ul', 'ops-list');
        data.defenses.forEach(function (d) {
          var li = el('li');
          li.appendChild(el('span', 'badge ' + (d.on ? 'active' : 'blocked'), d.on ? 'On' : 'Off'));
          li.appendChild(document.createTextNode(' ' + d.label + ' '));
          if (!d.on) { var a = el('a', null, 'Turn it on'); a.href = d.href; li.appendChild(a); }
          ul.appendChild(li);
        });
        box.appendChild(ul);
        technical(box, data.technical);
      } catch (failure) { say(box, await failText(failure, 'load which defenses are on')); }
    }

    var load = $('ops-sec-load');
    if (load) load.addEventListener('click', busy(load, async function () {
      var out = $('ops-sec-detections');
      say(out, 'Reading the activity log…');
      try {
        var data = await request('/api/v1/security/own/detections?severity=' + encodeURIComponent($('ops-sec-severity').value));
        out.textContent = '';
        out.appendChild(el('p', null, data.total ? plural(data.total, 'security event') + ' found.' : 'No security events were found.'));
        (data.notes || []).forEach(function (n) { out.appendChild(el('p', 'muted', n)); });
        if (data.detections.length) {
          out.appendChild(table(['When', 'What happened', 'How serious', 'Who'], data.detections.map(function (d) {
            return [when(d.when), d.what, d.severity, d.who];
          }), 'Security events, newest first'));
        }
      } catch (failure) { say(out, await failText(failure, 'read the security events')); }
    }));

    var sweep = $('ops-sec-sweep');
    if (sweep) sweep.addEventListener('click', busy(sweep, async function () {
      var out = $('ops-sec-sweep-out');
      var since = $('ops-sec-since').value || null;
      var until = $('ops-sec-until').value || null;
      if (since && until && since > until) { say(out, 'The start date must be before the end date.'); return; }
      say(out, 'Looking through the activity log…');
      try {
        var data = await request('/api/v1/security/own/sweep', {method: 'POST', json: {since: since, until: until}});
        out.textContent = '';
        out.appendChild(el('p', null, data.summary + ' ' + plural(data.entries_checked, 'entry', 'entries') + ' checked.'));
        if (data.findings.length) {
          out.appendChild(table(['Warning sign', 'How serious', 'Times', 'Assistants involved', 'Last seen'],
            data.findings.map(function (f) { return [f.what, f.severity, String(f.count), String(f.assistants), when(f.last_seen)]; }),
            'Warning signs found'));
        }
      } catch (failure) { say(out, await failText(failure, 'look for signs of attack')); }
    }));

    var fixes = $('ops-sec-fixes-load');
    async function loadFixes() {
      var out = $('ops-sec-fixes');
      say(out, 'Checking…');
      try {
        var data = await request('/api/v1/security/own/fixes');
        out.textContent = '';
        out.appendChild(el('p', null, data.summary));
        if (!data.fixes.length) return;
        out.appendChild(table(['Gap', 'Fix', 'Actions'], data.fixes.map(function (f) {
          var actions = el('span', 'ops-actions');
          if (f.can_apply && canInstall) {
            var apply = button('Apply this fix', 'btn');
            apply.addEventListener('click', busy(apply, async function () {
              if (!(await confirmed('Apply this fix: ' + f.label + '? Lightwork\'s own settings change, the change is recorded in the activity log, and it takes effect after Lightwork restarts.', 'Apply'))) return;
              try {
                var r = await request('/api/v1/security/own/fixes/apply', {method: 'POST', json: {control: f.control, confirm: true}});
                say($('ops-sec-fixes-result'), r.message);
                await loadFixes();
              } catch (failure) { say($('ops-sec-fixes-result'), await failText(failure, 'apply the fix')); }
            }));
            actions.appendChild(apply);
          }
          var go = el('a', 'btn btn--ghost', 'Change it yourself');
          go.href = f.href;
          actions.appendChild(go);
          return [f.label, f.automatic ? (f.can_apply ? 'Can be applied here' : (f.why_not || 'Automatic fixes are off')) : 'Needs a person to decide', actions];
        }), 'Security gaps and fixes'));
      } catch (failure) { say(out, await failText(failure, 'check for security gaps')); }
    }
    if (fixes) fixes.addEventListener('click', busy(fixes, loadFixes));
    posture();
  }

  // ======================================================================
  // Privacy: breach deadlines, file scans, questionnaire links
  // ======================================================================
  function breachPlanner() {
    var btn = $('ops-breach-plan');
    if (!btn) return;
    var out = $('ops-breach-out');
    btn.addEventListener('click', busy(btn, async function () {
      var regimes;
      try { regimes = (await request('/api/v1/breach/regimes')).regimes || []; }
      catch (failure) {
        say(out, failure && failure.status === 403
          ? 'The breach deadline planner is turned off. Ask an administrator to turn it on in Settings.'
          : await failText(failure, 'load the laws'));
        return;
      }
      if (!window.mvForm) return;
      var fields = regimes.map(function (r) { return {key: 'law:' + r.regime, label: r.name, type: 'bool'}; });
      fields.push({key: 'people', label: 'People affected (whole number, blank if unknown)', type: 'text'});
      fields.push({key: 'discovered', label: 'Day it was discovered', type: 'date'});
      fields.push({key: 'sensitive', label: 'It involves sensitive data (health, money, identity numbers)', type: 'bool'});
      fields.push({key: 'malicious', label: 'Someone did this on purpose', type: 'bool'});
      var values = await window.mvForm('Plan the notifications for a data breach', fields, {okText: 'Show deadlines'});
      if (!values) return;
      var chosen = Object.keys(values).filter(function (k) { return k.indexOf('law:') === 0 && values[k] === true; })
        .map(function (k) { return k.slice(4); });
      if (!chosen.length) { say(out, 'Choose at least one law.'); return; }
      var rawPeople = values.people == null ? '' : String(values.people).trim();
      if (rawPeople && !/^(0|[1-9][0-9]*)$/.test(rawPeople)) {
        say(out, 'Enter a whole number of people, or leave the count blank if it is unknown.');
        return;
      }
      var people = rawPeople ? Number(rawPeople) : null;
      if (people !== null && !Number.isSafeInteger(people)) {
        say(out, 'Enter a smaller whole number of people.');
        return;
      }
      var body = {jurisdictions: chosen, subjects_affected: people, sensitive: !!values.sensitive, malicious: !!values.malicious};
      if (values.discovered) {
        var t = Date.parse(values.discovered + 'T00:00:00');
        if (!isNaN(t)) body.discovered_at = t / 1000;
      }
      say(out, 'Working out the deadlines…');
      try {
        var plan = await request('/api/v1/breach/plan', {method: 'POST', json: body});
        out.textContent = '';
        if (plan.subjects_affected == null) {
          out.appendChild(el('p', 'muted', 'Affected-person count not provided. Check count-based reporting thresholds before relying on this plan.'));
        }
        out.appendChild(table(['Law', 'Tell', 'Deadline', 'Notes'], (plan.obligations || []).map(function (o) {
          return [o.name || human(o.regime), o.authority, o.authority_due_at ? when(o.authority_due_at) : 'As the law sets out', o.threshold_note || ''];
        }), 'Who to tell and by when'));
        if (plan.notice) out.appendChild(el('p', 'muted', plan.notice));
      } catch (failure) { say(out, await failText(failure, 'work out the deadlines')); }
    }));
  }

  function dataMapScans() {
    var buttons = document.querySelectorAll('.ops-dm-scan');
    if (!buttons.length) return;
    var msg = $('ops-dm-scan-msg') || $('pe-dm-msg');
    buttons.forEach(function (btn) {
      btn.addEventListener('click', busy(btn, async function () {
        var kind = btn.getAttribute('data-kind');
        var name = btn.getAttribute('data-name') || '';
        var body = {revision: Number(btn.getAttribute('data-revision')) || 1};
        if (kind === 'bucket') {
          var values = window.mvForm ? await window.mvForm('Scan the files in ' + name, [
            {key: 'bucket', label: 'Storage bucket name', type: 'text', required: true, default: name.toLowerCase()},
            {key: 'folder', label: 'Folder inside the bucket (optional)', type: 'text'}], {okText: 'Scan files'}) : null;
          if (!values) return;
          body.bucket = String(values.bucket || '').trim().toLowerCase();
          body.folder = String(values.folder || '').trim();
        } else if (!(await confirmed('Read a sample of the files on the SharePoint site ' + name + ' and record which kinds of personal data they hold? Only what was found is saved, never the files.', 'Scan files'))) {
          return;
        }
        say(msg, 'Reading a sample of the files…');
        try {
          var r = await request('/api/v1/data-map/assets/' + encodeURIComponent(btn.getAttribute('data-asset')) + '/scan-files',
            {method: 'POST', json: body});
          say(msg, name + ': ' + r.message);
          if (r.revision) btn.setAttribute('data-revision', String(r.revision));
        } catch (failure) { say(msg, await failText(failure, 'scan the files')); }
      }));
    });
  }

  function questionnaireLinks() {
    var btn = $('ops-qlinks');
    if (!btn) return;
    var out = $('ops-qlinks-msg');
    btn.addEventListener('click', busy(btn, async function () {
      var startOver = $('ops-qlinks-restart') && $('ops-qlinks-restart').checked;
      if (startOver && !(await confirmed('Start preparing the questionnaire links again from your vendor records? Shared forms stay unavailable until it finishes.', 'Start over'))) return;
      say(out, 'Preparing…');
      try {
        var r = await request('/api/v1/vendors/questionnaire-links/prepare', {method: 'POST', json: {start_over: !!startOver}});
        say(out, r.message);
        if (r.ready && $('ops-qlinks-restart')) $('ops-qlinks-restart').checked = false;
      } catch (failure) { say(out, await failText(failure, 'prepare the questionnaire links')); }
    }));
  }

  // ======================================================================
  // A person's uploaded documents (Compliance > A person's data)
  // ======================================================================
  function personDocuments() {
    var check = $('ops-docs-check');
    var erase = $('ops-docs-erase');
    if (!check && !erase) return;
    var out = $('ops-docs-result');
    function chosen() {
      var sel = $('cmp-person');
      if (!sel || !sel.value) return null;
      var opt = sel.options[sel.selectedIndex];
      return {channel: opt.getAttribute('data-channel'), user: opt.getAttribute('data-user'),
        name: opt.getAttribute('data-name') || opt.textContent.replace(/\s*\([^)]*\)\s*$/, '')};
    }
    if (check) check.addEventListener('click', busy(check, async function () {
      var p = chosen();
      if (!p) { say(out, 'Choose a person first.'); return; }
      say(out, 'Checking…');
      try {
        var r = await request('/api/v1/compliance/people/documents/check', {method: 'POST', json: {channel: p.channel, user: p.user}});
        say(out, r.message);
      } catch (failure) { say(out, await failText(failure, 'check their documents')); }
    }));
    if (erase) erase.addEventListener('click', busy(erase, async function () {
      var p = chosen();
      if (!p) { say(out, 'Choose a person first.'); return; }
      var preview;
      try {
        preview = await request('/api/v1/compliance/people/documents/check', {method: 'POST', json: {channel: p.channel, user: p.user}});
      } catch (failure) { say(out, await failText(failure, 'check their documents')); return; }
      if (!preview.remaining) { say(out, 'Nothing to erase: ' + preview.message); return; }
      if (!(await confirmed('Erase ' + plural(preview.remaining, 'piece') + ' of uploaded documents about ' + p.name + '? This cannot be undone. Their conversations and tasks are not touched; use Erase their data for everything.', 'Continue'))) return;
      var typed = window.mvForm ? await window.mvForm('Type the person\'s name to confirm', [
        {key: 'name', label: 'Name (' + p.name + ')', type: 'text', required: true}], {okText: 'Erase documents'}) : null;
      if (!typed) return;
      if (String(typed.name || '').trim().toLowerCase() !== p.name.trim().toLowerCase()) {
        say(out, 'The name you typed does not match. Nothing was erased. Type the exact name to continue.');
        return;
      }
      say(out, 'Erasing…');
      try {
        var r = await request('/api/v1/compliance/people/documents/erase', {method: 'POST',
          json: {channel: p.channel, user: p.user, confirm: true, confirm_name: String(typed.name).trim()}});
        say(out, r.message);
      } catch (failure) { say(out, await failText(failure, 'erase their documents')); }
    }));
  }

  // ======================================================================
  // AI governance: company rules, AI gateway, checks, insurance pack
  // ======================================================================
  async function policy() {
    var box = $('ops-policy');
    if (!box) return;
    try {
      var data = await request('/api/v1/governance-ops/policy');
      box.textContent = '';
      box.appendChild(el('p', null, data.summary));
      if (data.rules.length) {
        var ul = el('ul', 'ops-list');
        data.rules.forEach(function (r) { ul.appendChild(el('li', null, r)); });
        box.appendChild(ul);
      }
      if (data.regulations.length) box.appendChild(el('p', 'muted', 'Some rules come from these regulations: ' + data.regulations.join(', ') + '.'));
    } catch (failure) { say(box, await failText(failure, 'load the company rules')); }
  }

  async function gateway() {
    var box = $('ops-gateway');
    if (!box) return;
    try {
      var data = await request('/api/v1/governance-ops/gateway');
      box.textContent = '';
      box.appendChild(el('p', null, data.summary));
      if (!data.callers.length) { box.appendChild(el('p', 'muted', 'No app has used the AI gateway yet. Apps appear here after their first request through the gateway.')); return; }
      box.appendChild(table(['App', 'Team', 'AI model', 'Requests', 'Last result', 'Last used'], data.callers.map(function (c) {
        return [c.app, c.team, c.model, String(c.calls), c.last_result, when(c.last_seen)];
      }), 'Apps that used the AI gateway, most recent first'));
    } catch (failure) { say(box, await failText(failure, 'load the AI gateway')); }
  }

  var assetsPromise = null;
  function fillAssets() {
    var selects = document.querySelectorAll('select[data-ops-assets]');
    if (!selects.length) return;
    if (!assetsPromise) assetsPromise = request('/api/v1/governance-ops/assets').then(function (d) { return d.assets || []; })
      .catch(function () { return []; });
    assetsPromise.then(function (assets) {
      selects.forEach(function (sel) {
        assets.forEach(function (a) { var o = el('option', null, a.name); o.value = a.id; sel.appendChild(o); });
      });
    });
  }

  function explainability() {
    var root = $('ops-explain');
    if (!root) return;
    var out = $('ops-explain-out');
    var groups = $('ops-fair-groups');
    function addGroup(name) {
      var row = el('div', 'ops-row');
      var n = el('input', 'input'); n.type = 'text'; n.maxLength = 120; n.value = name || '';
      n.setAttribute('aria-label', 'Group name');
      var s = el('input', 'input'); s.type = 'number'; s.min = '0'; s.setAttribute('aria-label', 'Number chosen');
      var t = el('input', 'input'); t.type = 'number'; t.min = '1'; t.setAttribute('aria-label', 'Number in the group');
      var rm = button('Remove');
      rm.addEventListener('click', function () { row.remove(); });
      [n, s, t, rm].forEach(function (x) { row.appendChild(x); });
      groups.appendChild(row);
    }
    if (groups) { addGroup(''); addGroup(''); }
    var add = $('ops-fair-add');
    if (add) add.addEventListener('click', function () { addGroup(''); });
    var fair = $('ops-fair-run');
    if (fair) fair.addEventListener('click', busy(fair, async function () {
      var list = Array.prototype.map.call(groups.querySelectorAll('.ops-row'), function (row) {
        var inputs = row.querySelectorAll('input');
        return {name: inputs[0].value.trim(), selected: Number(inputs[1].value), total: Number(inputs[2].value)};
      }).filter(function (g) { return g.name; });
      if (list.length < 2) { say(out, 'Enter at least two groups.'); return; }
      if (list.some(function (g) { return !(g.total >= 1) || !(g.selected >= 0) || g.selected > g.total; })) {
        say(out, 'Each group needs how many were chosen and how many were in the group.'); return;
      }
      var asset = $('ops-explain-asset') ? $('ops-explain-asset').value : '';
      say(out, 'Checking…');
      try {
        var r = await request('/api/v1/governance-ops/fairness', {method: 'POST', json: {groups: list, asset_id: asset || null}});
        out.textContent = '';
        out.appendChild(el('p', null, r.summary + (r.saved ? ' Saved as evidence.' : '')));
        out.appendChild(table(['Group', 'Chosen', 'Compared with the most-chosen group', 'Result'], r.groups.map(function (g) {
          return [g.group, Math.round((g.rate || 0) * 100) + '%', Math.round((g.ratio || 0) * 100) + '%', g.passes ? 'Passes' : 'Below four-fifths'];
        }), 'Fairness by group'));
      } catch (failure) { say(out, await failText(failure, 'check fairness')); }
    }));

    var sheetText = null, header = [], rowCount = 0;
    var file = $('ops-sheet-file');
    if (file) file.addEventListener('change', async function () {
      sheetText = null;
      var f = file.files[0];
      if (!f) return;
      if (f.size > 2 * 1024 * 1024) { say(out, 'That spreadsheet is too large.'); return; }
      try { sheetText = await readFile(f); } catch (e) { say(out, 'That file could not be read. Choose it again, or try a different file.'); return; }
      var lines = sheetText.split(/\r?\n/).filter(function (l) { return l.trim(); });
      header = (lines[0] || '').split(',').map(function (h) { return h.trim().replace(/^"|"$/g, ''); });
      rowCount = Math.max(0, lines.length - 1);
      var score = $('ops-sheet-score'), row = $('ops-sheet-row');
      score.textContent = ''; row.textContent = '';
      header.forEach(function (h, i) { var o = el('option', null, h); o.value = h; if (i === header.length - 1) o.selected = true; score.appendChild(o); });
      for (var i = 1; i <= Math.min(rowCount, 5000); i++) { var o = el('option', null, 'Decision ' + i); o.value = String(i); row.appendChild(o); }
      say(out, 'Loaded ' + plural(rowCount, 'decision') + ' with ' + plural(header.length, 'column') + '.');
    });
    function sheetBody(extra) {
      var asset = $('ops-explain-asset') ? $('ops-explain-asset').value : '';
      var body = {sheet: sheetText, asset_id: asset || null};
      Object.keys(extra).forEach(function (k) { body[k] = extra[k]; });
      return body;
    }
    var sens = $('ops-sens-run');
    if (sens) sens.addEventListener('click', busy(sens, async function () {
      if (!sheetText) { say(out, 'Choose a spreadsheet first.'); return; }
      say(out, 'Checking…');
      try {
        var r = await request('/api/v1/governance-ops/sensitivity', {method: 'POST', json: sheetBody({score_column: $('ops-sheet-score').value})});
        out.textContent = '';
        out.appendChild(el('p', null, r.summary + (r.saved ? ' Saved as evidence.' : '')));
        out.appendChild(table(['Input', 'How strongly it moves the score', 'When it is higher'], r.ranked.map(function (x) {
          return [x.input, String(x.strength), x.direction];
        }), 'Inputs ranked by influence'));
      } catch (failure) { say(out, await failText(failure, 'rank the inputs')); }
    }));
    var reasons = $('ops-reasons-run');
    if (reasons) reasons.addEventListener('click', busy(reasons, async function () {
      if (!sheetText) { say(out, 'Choose a spreadsheet first.'); return; }
      say(out, 'Checking…');
      try {
        var r = await request('/api/v1/governance-ops/reasons', {method: 'POST', json: sheetBody({row: Number($('ops-sheet-row').value) || 1})});
        out.textContent = '';
        out.appendChild(el('p', null, r.summary + (r.saved ? ' Saved as evidence.' : '')));
        out.appendChild(table(['Input', 'Value', 'Usual value', 'How unusual', 'Direction'], r.reasons.map(function (x) {
          return [x.input, String(x.value), String(x.usual), x.how_far + ' times the usual spread', x.direction === 'above' ? 'Higher than usual' : 'Lower than usual'];
        }), 'Main reasons for this decision'));
      } catch (failure) { say(out, await failText(failure, 'explain the decision')); }
    }));
  }

  function insurancePack() {
    var btn = $('ops-pack-start');
    if (!btn) return;
    var out = $('ops-pack-msg');
    var link = $('ops-pack-link');
    btn.addEventListener('click', busy(btn, async function () {
      if (!(await confirmed('Prepare the signed insurance evidence pack? It summarises your AI systems, evidence and decisions for an insurer, and the download is recorded in the activity log.', 'Prepare'))) return;
      link.textContent = '';
      say(out, 'Preparing the pack. This can take a few minutes; you can keep working.');
      try {
        var asset = $('ops-pack-asset') ? $('ops-pack-asset').value : '';
        var started = await request('/api/v1/governance-ops/underwriting-pack', {method: 'POST', json: {asset_id: asset || null}});
        waitForDownload('/api/v1/governance-ops/underwriting-pack/' + encodeURIComponent(started.job), function (problem, href) {
          if (problem) { say(out, problem); return; }
          var a = el('a', 'btn', 'Save the pack');
          a.href = href; a.setAttribute('download', '');
          link.appendChild(a);
          say(out, 'The pack is ready.');
        });
      } catch (failure) { say(out, await failText(failure, 'prepare the pack')); }
    }));
  }

  // ======================================================================
  // Regulatory alerts into impact records
  // ======================================================================
  function regulatoryFeed() {
    var look = $('ops-feed-look');
    if (!look) return;
    var out = $('ops-feed-msg');
    var form = $('ops-feed-form');
    function fill(sel, items) {
      sel.textContent = '';
      items.forEach(function (i) { var o = el('option', null, i.label); o.value = i.value; sel.appendChild(o); });
    }
    look.addEventListener('click', busy(look, async function () {
      say(out, 'Reading the alerts…');
      try {
        var p = await request('/api/v1/governance-ops/regulatory-feed/preview', {method: 'POST', json: {queue: $('ops-feed-queue').value}});
        fill($('ops-feed-regimes'), p.regimes);
        fill($('ops-feed-domains'), p.domains);
        form.hidden = !p.alerts;
        say(out, p.alerts ? plural(p.alerts, 'alert') + ' found. Choose what your rule covers, then create the records.' : 'There are no alerts in that queue.');
      } catch (failure) { say(out, await failText(failure, 'read the alerts')); }
    }));
    var run = $('ops-feed-run');
    if (run) run.addEventListener('click', busy(run, async function () {
      function picked(id) { return Array.prototype.map.call($(id).selectedOptions, function (o) { return o.value; }); }
      var body = {queue: $('ops-feed-queue').value, regimes: picked('ops-feed-regimes'), domains: picked('ops-feed-domains'),
        asset_ids: picked('ops-feed-assets'), send_notices: $('ops-feed-notices').checked, confirm: true};
      if (!body.regimes.length && !body.domains.length) { say(out, 'Choose at least one regulation or area.'); return; }
      if (!(await confirmed('Create impact records for the alerts that match your choices?' + (body.send_notices ? ' Customer notices will also be sent.' : ''), 'Create records'))) return;
      say(out, 'Working…');
      try {
        var r = await request('/api/v1/governance-ops/regulatory-feed/sync', {method: 'POST', json: body});
        out.textContent = r.summary;
        technical(out, r.technical);
      } catch (failure) { say(out, await failText(failure, 'create the impact records')); }
    }));
  }

  // ======================================================================
  // Safety monitoring: a reviewer test you write, and data-path checks
  // ======================================================================
  function immune() {
    var form = $('ops-canary-form');
    if (form) {
      var msg = $('ops-canary-msg');
      form.addEventListener('submit', async function (event) {
        event.preventDefault();
        var submit = form.querySelector('button[type="submit"]');
        var body = {action: form.elements.action.value.trim(), detail: form.elements.detail.value.trim(),
          decision_class: form.elements.decision_class.value.trim(), flaw: form.elements.flaw.value.trim(),
          risk: form.elements.risk.value, requested_by: form.elements.requested_by.value || null,
          undoable: !form.elements.undoable || form.elements.undoable.value !== 'no'};
        if (!body.action || !body.detail || !body.decision_class || !body.flaw) { say(msg, 'Fill in every field.'); return; }
        if (!(await confirmed('Place this test approval in the approvals queue? Reviewers are not told it is a test.', 'Place test'))) return;
        submit.disabled = true;
        try {
          var r = await request('/api/v1/immune/canaries/written', {method: 'POST', json: body});
          form.reset();
          say(msg, r.message);
        } catch (failure) { say(msg, await failText(failure, 'place the test approval')); }
        finally { submit.disabled = false; }
      });
      request('/api/v1/immune/choices').then(function (c) {
        var sel = form.elements.requested_by;
        (c.people || []).forEach(function (p) { var o = el('option', null, p.label); o.value = p.value; sel.appendChild(o); });
        var list = $('ops-canary-classes');
        if (list) (c.decision_classes || []).forEach(function (k) { var o = el('option'); o.value = k; list.appendChild(o); });
      }).catch(function () { /* the picker stays optional */ });
    }
    var check = $('ops-network-run');
    if (!check) return;
    var out = $('ops-network-out');
    check.addEventListener('click', busy(check, async function () {
      function dial(id) {
        var v = $(id) ? $(id).value : '';
        return v === 'on' ? true : (v === 'off' ? false : null);
      }
      var body = {shared_messaging: $('ops-network-shared').checked,
        levels: dial('ops-network-levels'), grounding: dial('ops-network-grounding')};
      var f = $('ops-network-file') && $('ops-network-file').files[0];
      if (f) {
        if (f.size > 512 * 1024) { say(out, 'That file is too large.'); return; }
        try { body.graph = await readFile(f); } catch (e) { say(out, 'That file could not be read. Choose it again, or try a different file.'); return; }
      }
      say(out, 'Checking every assistant. This can take a little while…');
      try {
        var r = await request('/api/v1/immune/network/check', {method: 'POST', json: body});
        out.textContent = '';
        out.appendChild(el('p', null, r.summary + (r.total > r.shown ? ' The first ' + r.shown + ' are shown.' : '')));
        if (r.chains.length) {
          out.appendChild(table(['Kind', 'Assistants in the chain', 'Reads private data with', 'Sends data out with', 'Risk'], r.chains.map(function (c) {
            return [c.kind, c.path.join(' → '), c.reads_with, c.sends_with, c.risk];
          }), 'Chains that let private data out'));
        }
      } catch (failure) { say(out, await failText(failure, 'check the assistants')); }
    }));
  }

  function start() {
    applyNeeds();
    checkpoints();
    security();
    breachPlanner();
    dataMapScans();
    questionnaireLinks();
    personDocuments();
    policy();
    gateway();
    fillAssets();
    explainability();
    insurancePack();
    regulatoryFeed();
    immune();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
