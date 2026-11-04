/* Reviewed setup uses the same tenant and named credential authority as work. */
(function () {
  'use strict';
  var el = function (id) { return document.getElementById('vs-' + id); };
  if (!el('panel')) return;
  if (document.getElementById('vendor-onboarding').dataset.namedSignin === 'false') return;
  var state = null, context = null, busy = false, locked = false, draft = null, names = {};
  // People are shown by name from the workspace member list; a sign-in handle
  // is shown only when no name is known.
  function ownerLabel(owner) {
    if (names[owner]) return names[owner];
    if (!owner.startsWith('user:')) return owner;
    var handle = owner.slice(5);
    return handle.indexOf('@') > 0 || /^[A-Za-z][A-Za-z .'-]{0,60}$/.test(handle) ? handle : 'A workspace member';
  }
  function connectionLabel(name) {
    var words = String(name).replace(/[_-]+/g, ' ').trim();
    return words.charAt(0).toUpperCase() + words.slice(1);
  }
  function controls() {
    var blocked = !state || !state.readiness || state.readiness.deployment.supported !== true;
    ['ticket', 'document', 'confirm'].forEach(function (id) { el(id).disabled = busy || locked || blocked; });
    el('resource-owner').disabled = busy || locked || blocked || state.owner_locked;
    el('enable').disabled = busy || locked || blocked || state.modules_enabled || !el('confirm').checked;
    el('save').disabled = busy || locked || blocked || !state.modules_enabled || !el('resource-owner').value || !el('ticket').value || !el('confirm').checked;
    el('refresh').disabled = busy || locked;
    el('off').hidden = !state || state.modules_enabled !== true;
    el('disable').disabled = busy || locked || !state || state.modules_enabled !== true || !el('off-confirm').checked;
  }
  function clear(message, lock) {
    draft = null; state = null; locked = !!lock; el('ticket').replaceChildren(); el('document').replaceChildren();
    el('resource-owner').replaceChildren();
    el('owner').textContent = ''; el('confirm').checked = false; el('status').textContent = message; controls();
    el('readiness-summary').textContent = 'Setup has not been confirmed.'; el('next-actions').replaceChildren();
    el('deployment').textContent = 'Deployment status has not been confirmed.';
  }
  function rememberChoices() {
    // Keep only nonsecret choices in this page, never reusable authority or confirmation.
    if (!state) return;
    draft = {context: state.context, configuration: state.configuration,
      revision: state.revision, owner: el('resource-owner').value};
    ['ticket', 'document'].forEach(function (name) {
      var row = state.connections.find(function (item) { return item.name === el(name).value; });
      draft[name] = row ? {name: row.name, revision: row.revision} : null;
    });
  }
  function requireRefresh(message) {
    state = null; el('confirm').checked = false;
    el('status').textContent = message + ' Refresh setup to check what was saved before retrying. Your choices are kept on this page.';
    el('readiness-summary').textContent = 'Setup has not been confirmed.'; el('next-actions').replaceChildren();
    el('deployment').textContent = 'Deployment status has not been confirmed.';
  }
  function restoreChoices(data) {
    var saved = draft; draft = null;
    if (!saved) return;
    // A changed revision may be our lost response or another administrator's save.
    // Render canonical state in either case; never replay an old submission.
    if (saved.configuration !== data.configuration || saved.revision !== data.revision) {
      el('status').textContent += ' Current saved settings are shown because setup changed. Review them before making another change.';
      return;
    }
    if (!data.readiness.deployment.supported) return;
    var removed = [];
    if ((!data.owner_locked && data.eligible_owners.includes(saved.owner)) ||
        (data.owner_locked && data.binding.resource_owner === saved.owner)) el('resource-owner').value = saved.owner;
    else if (saved.owner) removed.push('vendor review owner');
    ['ticket', 'document'].forEach(function (name) {
      var selected = saved[name], connector = name === 'ticket' ? 'jira' : 'gdrive';
      if (!selected) { el(name).value = ''; return; }
      var current = data.connections.find(function (row) { return row.name === selected.name && row.connector === connector && row.has_token === true && row.revision === selected.revision; });
      if (current) el(name).value = current.name;
      else { el(name).value = ''; removed.push(name === 'ticket' ? 'Jira connection' : 'Google Drive connection'); }
    });
    el('status').textContent += removed.length ? ' Choose again: ' + removed.join(', ') + '. Access or connection details changed.' : ' Your valid choices were kept. Review and confirm before saving.';
  }
  function errorMessage(data, validation) {
    if (!validation && data && typeof data.detail === 'string') return data.detail;
    var fields = {resource_owner: 'Vendor review owner', ticket: 'Jira connection',
      document: 'Google Drive connection', ticket_revision: 'Jira connection',
      document_revision: 'Google Drive connection', confirm: 'Setup confirmation'};
    var labels = data && Array.isArray(data.detail) ? data.detail.map(function (error) {
      return error && Array.isArray(error.loc) && error.loc.length === 2 && error.loc[0] === 'body' && fields[error.loc[1]];
    }).filter(function (label) { return typeof label === 'string'; }) : [];
    return labels.length ? 'Check ' + Array.from(new Set(labels)).join(', ') + '.' : 'Setup could not be confirmed. Refresh the page and try again.';
  }
  function renderReadiness(readiness) {
    var links = ['/connections', '/users', '#vs-resource-owner', '#vs-ticket', '#vs-enable', '#vs-confirm', '#vs-save', '#vs-deployment'];
    if (!readiness || !['setup_required', 'configured', 'blocked'].includes(readiness.state) || !readiness.deployment || typeof readiness.deployment.supported !== 'boolean' || typeof readiness.deployment.message !== 'string' || !Array.isArray(readiness.actions) || readiness.live_provider_verified !== false || readiness.actions.some(function (action) { return !action || typeof action.label !== 'string' || !links.includes(action.href); })) throw new Error('Setup readiness was incomplete. Refresh before making changes.');
    if ((readiness.state === 'blocked') === readiness.deployment.supported) throw new Error('Setup readiness was inconsistent. Refresh before making changes.');
    el('readiness-summary').textContent = readiness.state === 'blocked' ? 'Deployment needs attention' : readiness.state === 'configured' ? 'Setup saved; provider access still needs checking' : 'Setup required';
    el('deployment').textContent = readiness.deployment.message;
    el('next-actions').replaceChildren();
    readiness.actions.forEach(function (action) {
      var row = document.createElement('li'), link = document.createElement('a');
      link.href = action.href; link.textContent = action.label; row.appendChild(link); el('next-actions').appendChild(row);
    });
  }
  function render(data) {
    if (!data || !/^[a-f0-9]{64}$/.test(data.context) || !/^[a-f0-9]{64}$/.test(data.configuration) || !Number.isSafeInteger(data.revision) || data.revision < 0 || typeof data.modules_enabled !== 'boolean' || !Array.isArray(data.connections) || data.connections.some(function (row) { return !row || typeof row.name !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(row.name) || !['jira', 'gdrive'].includes(row.connector) || typeof row.revision !== 'string' || !row.revision || row.revision.length > 64 || typeof row.has_token !== 'boolean'; }) || new Set(data.connections.map(function (row) { return row.name; })).size !== data.connections.length || !data.binding || typeof data.owner_locked !== 'boolean' || !Array.isArray(data.eligible_owners) || data.eligible_owners.some(function (owner) { return typeof owner !== 'string' || !owner.startsWith('user:') || owner.length > 256; }) || typeof data.binding.resource_owner !== 'string' || (data.owner_locked && !data.binding.resource_owner)) throw new Error('Setup response was incomplete. Refresh setup before making changes.');
    if (context && data.context !== context) { clear('Your account or workspace changed. Reload the page.', true); return; }
    renderReadiness(data.readiness);
    state = data; context = data.context; el('confirm').checked = false; el('off-confirm').checked = false;
    ['ticket', 'document'].forEach(function (name) {
      var select = el(name), placeholder = document.createElement('option');
      placeholder.value = ''; placeholder.textContent = name === 'ticket' ? 'Choose Jira connection' : 'Uploaded evidence only'; select.replaceChildren(placeholder);
      data.connections.filter(function (row) { return row.connector === (name === 'ticket' ? 'jira' : 'gdrive') && row.has_token; }).forEach(function (row) {
        var option = document.createElement('option'); option.value = row.name; option.textContent = connectionLabel(row.name); select.appendChild(option);
      });
      select.value = data.binding[name + '_connection'] || '';
    });
    var owners = el('resource-owner'), placeholder = document.createElement('option');
    placeholder.value = ''; placeholder.textContent = 'Choose a workspace member'; owners.replaceChildren(placeholder);
    (data.owner_locked ? [data.binding.resource_owner] : data.eligible_owners).forEach(function (owner) {
      var option = document.createElement('option'); option.value = owner; option.textContent = ownerLabel(owner); owners.appendChild(option);
    });
    owners.value = data.binding.resource_owner;
    el('owner').textContent = data.owner_locked ? 'Existing vendor review owner: ' + ownerLabel(data.binding.resource_owner) + '. This setup cannot transfer ownership.' : 'Choose the owner for this workspace’s vendor records. Your saved credentials remain under your authority.';
    el('status').textContent = !data.readiness.deployment.supported ? 'Resolve the deployment issue above before changing setup.' : data.modules_enabled ? (data.revision ? 'Workspace setup saved. Connection access and evidence still require verification.' : 'Workflow enabled. Choose the owner and connections, then save this workspace setup.') : 'Enable the workflow, then choose the owner and saved connections for this workspace.';
  }
  async function call(method, suffix, body) {
    if (busy || locked) return;
    rememberChoices(); busy = true; controls();
    var response, data;
    try {
      var headers = {'Accept': 'application/json', 'Content-Type': 'application/json'};
      if (context) headers['X-Lightwork-Setup-Context'] = context;
      response = await fetch('/api/v1/vendor-setup' + (suffix || ''), {method: method, headers: headers, credentials: 'same-origin', cache: 'no-store', body: body ? JSON.stringify(body) : undefined});
      if (response.status === 401) { clear('Your sign-in ended. Sign in again to manage setup.', true); return; }
      if (response.status === 403) { clear('This account cannot change vendor setup. Ask an installation administrator to check your role and workspace access.', true); return; }
      if (method === 'GET' && response.status === 409) { clear('Your account, workspace or setup access changed. Reload the page to review current setup.', true); return; }
      try { data = await response.json(); }
      catch (_) { if (response.ok) { clear('Setup response was incomplete. Refresh setup before making changes.', false); return; } }
      if (response.status === 409) { clear(errorMessage(data) + ' Refresh setup to review current choices.', false); return; }
      if (!response.ok) { requireRefresh(errorMessage(data, response.status === 422)); return; }
      render(data);
      if (!locked && method === 'GET') restoreChoices(data);
      else draft = null;
    } catch (error) {
      if (response && response.ok) clear(error.message || 'Setup response was incomplete. Refresh setup.', false);
      else requireRefresh('Setup is unavailable. Refresh the page and try again.');
    }
    finally { busy = false; controls(); }
  }
  function reviewed() { return {confirm: true, context: state.context, configuration: state.configuration}; }
  el('next-actions').addEventListener('click', function (event) {
    var link = event.target.closest('a');
    if (!link || !link.getAttribute('href').startsWith('#vs-')) return;
    var message = document.getElementById('vo-message'), inset = 64;
    if (message) {
      var style = getComputedStyle(message), top = parseFloat(style.top);
      if (Number.isFinite(top)) inset = top;
      if (style.position === 'sticky') inset += message.getBoundingClientRect().height;
    }
    // Keep native fragment navigation and keyboard focus below both sticky surfaces.
    el('panel').style.setProperty('--vs-anchor-offset', (inset + 16) + 'px');
  });
  el('form').addEventListener('change', function (event) { if (event.target !== el('confirm')) el('confirm').checked = false; controls(); });
  el('refresh').addEventListener('click', function () { call('GET'); });
  el('enable').addEventListener('click', function () { if (!el('enable').disabled) call('POST', '/enable', reviewed()); });
  el('off-confirm').addEventListener('change', controls);
  el('disable').addEventListener('click', async function () {
    if (el('disable').disabled) return;
    var ask = typeof window.mvConfirm === 'function' ? window.mvConfirm : null;
    if (ask && !(await ask('Turn off vendor onboarding? Vendor requests stop until you turn it back on. Nothing is deleted.', {okText: 'Turn off'}))) return;
    if (!state || el('disable').disabled) return;
    call('POST', '/disable', reviewed());
  });
  el('form').addEventListener('submit', function (event) {
    event.preventDefault(); if (el('save').disabled) return;
    var ticket = state.connections.find(function (row) { return row.name === el('ticket').value; });
    var doc = state.connections.find(function (row) { return row.name === el('document').value; });
    call('PUT', '', Object.assign(reviewed(), {ticket: ticket.name, ticket_revision: ticket.revision, document: doc ? doc.name : '', document_revision: doc ? doc.revision : '', expected_revision: state.revision, resource_owner: el('resource-owner').value}));
  });
  fetch('/api/v1/choices/people', {credentials: 'same-origin', headers: {'Accept': 'application/json'}})
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) { (d && d.people || []).forEach(function (p) { if (p && typeof p.value === 'string' && typeof p.label === 'string') names[p.value] = p.label; }); })
    .catch(function () { return null; })
    .then(function () { call('GET'); });
}());
