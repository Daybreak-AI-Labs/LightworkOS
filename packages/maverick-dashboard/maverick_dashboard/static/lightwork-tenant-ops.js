/* Workspaces page: set up a client in one step, and re-protect workspace keys. */
(function () {
  'use strict';
  var BASE = '/api/v1/admin/workspace-ops';
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  async function failText(failure, action) {
    var plain = window.mvPlainDetail ? window.mvPlainDetail(failure && failure.detail) : '';
    if (plain) return plain;
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  async function call(path, method, body) {
    return window.mvFetchJSON(path, {method: method || 'GET', cache: 'no-store', body: body});
  }

  // ---- one-step client setup (the create form's optional invitation) -----
  var roles = document.querySelector('[data-onboard-roles]');
  if (roles) {
    var msg = $('tenant-add-msg');
    call(BASE + '/roles').then(function (data) {
      roles.textContent = '';
      data.roles.forEach(function (r) {
        var o = el('option', null, r.label); o.value = r.value; if (r.value === 'admin') o.selected = true; roles.appendChild(o);
      });
      if (!data.invitations_on) {
        var invite = $('tenant-invite');
        if (invite) {
          invite.open = false;
          invite.querySelectorAll('input, select').forEach(function (c) { c.disabled = true; });
          invite.querySelector('p').appendChild(el('span', null, ' Invitations are turned off, so a workspace cannot invite its administrator yet. Turn them on in Settings.'));
        }
      }
    }).catch(function () { /* the built-in Admin choice stays */ });
    var copy = $('tenant-onboard-copy');
    if (copy) copy.addEventListener('click', async function () {
      var field = $('tenant-onboard-link');
      try { await navigator.clipboard.writeText(field.value); msg.textContent = 'Invitation link copied.'; }
      catch (e) { field.select(); msg.textContent = 'Select the link and copy it.'; }
    });
  }

  var keys = $('tenant-keys');
  if (keys) {
    var keysMsg = $('tenant-keys-msg');
    var keysOut = $('tenant-keys-out');
    var rotate = $('tenant-keys-rotate');
    async function readKeys() {
      var current = keys.elements.current_key.files[0];
      var next = keys.elements.new_key.files[0];
      if (!current || !next) throw new Error('choose');
      if (current.size > 4096 || next.size > 4096) throw new Error('size');
      return {current_key: (await current.text()).trim(), new_key: (await next.text()).trim()};
    }
    function render(data) {
      keysOut.textContent = '';
      keysOut.appendChild(el('p', null, data.summary));
      if (data.rows && data.rows.length) {
        var table = el('table'), head = el('tr');
        ['Workspace', 'Result'].forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; head.appendChild(th); });
        var thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
        var tbody = el('tbody');
        data.rows.forEach(function (r) { var tr = el('tr'); tr.appendChild(el('td', null, r.workspace)); tr.appendChild(el('td', null, r.result)); tbody.appendChild(tr); });
        table.appendChild(tbody); keysOut.appendChild(table);
      }
      if (data.technical && data.technical.length) {
        var details = el('details'); details.appendChild(el('summary', null, 'Technical details (for your IT team)'));
        var ul = el('ul'); data.technical.forEach(function (t) { ul.appendChild(el('li', 'muted', t.text)); });
        details.appendChild(ul); keysOut.appendChild(details);
      }
    }
    function keyProblem(e) {
      return e && e.message === 'size' ? 'Those files are too large to be key files.' : 'Choose both key files first.';
    }
    keys.addEventListener('submit', async function (event) {
      event.preventDefault();
      rotate.hidden = true;
      var body;
      try { body = await readKeys(); } catch (e) { keysMsg.textContent = keyProblem(e); return; }
      keysMsg.textContent = 'Checking each workspace…';
      try {
        var data = await call(BASE + '/keys/preview', 'POST', body);
        render(data);
        rotate.hidden = !(data.total && data.rows.some(function (r) { return r.result === 'Would be re-protected'; }));
        keysMsg.textContent = '';
      } catch (failure) { keysMsg.textContent = await failText(failure, 'check the keys'); }
    });
    rotate.addEventListener('click', async function () {
      var body;
      try { body = await readKeys(); } catch (e) { keysMsg.textContent = keyProblem(e); return; }
      var ok = window.mvConfirm ? await window.mvConfirm('Re-protect every workspace\'s key with the new master key? Keep the current key until this shows no failures.', {okText: 'Re-protect'}) : false;
      if (!ok) return;
      body.confirm = true;
      rotate.hidden = true;
      keysMsg.textContent = 'Re-protecting workspaces…';
      try {
        var job = (await call(BASE + '/keys/rotate', 'POST', body)).job;
        for (var i = 0; i < 600 && job.state === 'running'; i++) {
          await new Promise(function (resolve) { setTimeout(resolve, 1000); });
          job = (await call(BASE + '/jobs/' + encodeURIComponent(job.id))).job;
        }
        if (job.state === 'done') {
          render(job.result);
          keysMsg.textContent = job.result && job.result.failed ? 'Some workspaces still need attention. Keep the current key and check the list below.' : 'Every workspace now uses the new key.';
        } else if (job.state === 'running') {
          keysMsg.textContent = 'Still working. Check back in a few minutes.';
        } else {
          keysMsg.textContent = (window.mvPlainDetail && window.mvPlainDetail(job.error)) ||
            'Re-protecting stopped before every workspace was done. Keep the current key and try again.';
        }
        if (job.record_warning) keysMsg.textContent += ' The result could not be added to the activity record. Keep the current key and ask your administrator to reconcile it before continuing.';
      } catch (failure) { keysMsg.textContent = await failText(failure, 're-protect the workspaces'); }
      keys.reset();
    });
  }
})();
