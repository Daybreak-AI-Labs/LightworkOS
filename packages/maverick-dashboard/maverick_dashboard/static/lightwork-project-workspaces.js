/* Native project workspace controls: bounded reads, current sources and reviewed CAS. */
(function () {
  'use strict';
  var root = document.getElementById('pw-root'); if (!root) return;
  var project = Number(root.dataset.project), context = root.dataset.context, base = '/api/v1/project-workspaces';
  var model = null, busy = false, generation = 0, controllers = new Set(), pending = null, uncertain = false, source = null;
  var dirty = new Set(), recovery = {}, newMilestone = null, selectedMilestone = '';
  function id(name) { return document.getElementById('pw-' + name); }
  function node(tag, text, parent) { var el = document.createElement(tag); if (text !== undefined) el.textContent = String(text); if (parent) parent.appendChild(el); return el; }
  function button(text, parent, handler) { var el = node('button', text, parent); el.type = 'button'; el.className = 'btn btn--ghost'; el.dataset.pwAction = ''; el.onclick = handler; return el; }
  function uid() { return (window.mvNewId ? window.mvNewId() : crypto.randomUUID()).replace(/-/g, ''); }
  function status(message) { window.mvStatus(id('status'), message); }
  function closePrivateView() {
    generation++; model = null; source = null; pending = null; uncertain = true;
    controllers.forEach(function (controller) { controller.abort(); });
    Object.values(recovery).forEach(function (item) { if (item) item.dispose(); }); recovery = {};
    root.querySelectorAll('textarea,input').forEach(function (el) { el.value = ''; el.checked = false; });
    id('workspace').hidden = true; id('list').replaceChildren(); id('source-content').textContent = ''; id('change-list').replaceChildren();
    dirty.clear(); id('remedy').hidden = false; lock(false);
  }
  function lock(value) { busy = value; root.querySelectorAll('[data-pw-action],#pw-confirm,#pw-refresh').forEach(function (el) { el.disabled = value || uncertain; }); id('check').disabled = value; id('retry-exact').disabled = value; id('cancel').hidden = !value; }
  async function call(path, body) {
    var controller = new AbortController(); controllers.add(controller);
    try {
      var kept = 'This project operation could not be confirmed. Your draft is kept. Refresh the page and try again.', data;
      try {
        data = await window.mvFetchJSON(base + path, {method: body ? 'POST' : 'GET', cache: 'no-store', signal: controller.signal, timeout: 20000,
          headers: {'X-Lightwork-Project-Context': context}, body: body, plainDetail: true, messages: {401: kept, 403: kept},
          onAccess: function (error) { closePrivateView(); status(error.message); }}, body ? 'save the project change' : 'load the project');
      } catch (error) {
        if (error.status && !window.mvPlainDetail(error.detail)) error.message = kept;
        throw error;
      }
      if (!data || typeof data !== 'object' || (data.context && data.context !== context)) { closePrivateView(); status('The current account or workspace changed. Reload before continuing.'); var changed = new Error('The current account or workspace could not be confirmed. Reload before continuing.'); changed.status = 409; throw changed; }
      return data;
    } finally { controllers.delete(controller); }
  }
  function select(name, choices, empty, selected) {
    var el = id(name), current = selected === undefined ? Array.from(el.selectedOptions, function (option) { return option.value; }) : selected;
    el.replaceChildren(); if (empty !== null) { var blank = node('option', empty || 'Choose an item', el); blank.value = ''; }
    choices.forEach(function (row) { var option = node('option', row.title || row.label || String(row.id), el); option.value = String(row.id); option.selected = current.includes(option.value); });
  }
  function lines(value) { return value.split('\n').map(function (line) { return line.trim(); }).filter(Boolean); }
  function detailsPayload() { return {outcome:id('outcome-input').value, criteria:lines(id('criteria-input').value), labels:lines(id('labels-input').value), default_view:id('default-view').value}; }
  function milestonePayload() { return {id:id('milestone-select').value || newMilestone || (newMilestone = uid()), title:id('milestone-title').value, due:id('milestone-due').value,
    goals:Array.from(id('goals').selectedOptions, function (option) { return Number(option.value); }), reviews:Array.from(id('reviews').selectedOptions, function (option) { return option.value; })}; }
  function bindRecovery(form, read, restore) {
    if (!window.mvDraftRecovery || recovery[form]) return;
    recovery[form] = window.mvDraftRecovery.create({host:id(form + '-form'), key:'project-workspace:' + project + ':' + form,
      read:read, restore:function (value) { restore(value); dirty.add(form); invalidate(); }});
  }
  function restoreDetails(value) { id('outcome-input').value = value.outcome || ''; id('criteria-input').value = (value.criteria || []).join('\n'); id('labels-input').value = (value.labels || []).join('\n'); id('default-view').value = value.default_view || 'list'; }
  function restoreMilestone(value) {
    newMilestone = value.id || uid(); id('milestone-select').value = value.id || ''; selectedMilestone = id('milestone-select').value;
    id('milestone-title').value = value.title || ''; id('milestone-due').value = value.due || '';
    ['goals','reviews'].forEach(function (name) { Array.from(id(name).options).forEach(function (option) { option.selected = (value[name] || []).map(String).includes(option.value); }); });
  }
  function invalidate() { if (!uncertain && !busy) { pending = null; id('review-panel').hidden = true; } }
  function fillEditor() {
    var w = model.workspace, choices = model.choices;
    if (!dirty.has('details')) restoreDetails(w);
    var rows = w.editor.milestones.map(function (row) { return {id:row.id, title:row.title}; });
    select('milestone-select', rows, 'New milestone'); select('dependent', rows, 'Choose a milestone'); select('prerequisite', rows, 'Choose a prerequisite');
    select('goals', choices.goals, null); select('reviews', choices.reviews, null);
    select('member', choices.members.map(function (actor) { return {id:actor, title:actor.replace(/^user:/, '')}; }), 'Choose a colleague');
    select('source', choices.goals.filter(function (row) { return row.result_available; }).map(function (row) { return {id:'result/' + row.id, title:'Saved result: ' + row.title}; }).concat(
      choices.reviews.map(function (row) { return {id:'review/' + row.id, title:'Review: ' + row.title + ' (' + row.status + ')'}; })), 'Choose a current source');
    id('members').replaceChildren(); w.members.forEach(function (actor) { var row = node('li', actor.replace(/^user:/, ''), id('members')); button('Review removal', row, function () { review('member', {member:actor, allowed:false}); }); });
    id('defaults-status').textContent = model.defaults.structure ? 'A private reusable structure is available.' : 'You have not saved a reusable project structure yet.';
    bindRecovery('details', detailsPayload, restoreDetails); bindRecovery('milestone', milestonePayload, restoreMilestone);
  }
  function renderMilestones() {
    var host = id('milestones'), view = id('view').value, rows = model.workspace.milestones.slice(); host.replaceChildren(); host.dataset.view = view;
    var names = new Map(rows.map(function (row) { return [row.id, row.title]; })), columns = new Map();
    if (view === 'timeline') rows.sort(function (a,b) { return (a.due || '9999').localeCompare(b.due || '9999'); });
    if (view === 'board') rows.sort(function (a,b) { return a.state.localeCompare(b.state); });
    if (!rows.length) node('p', model.workspace.can_edit ? 'Add a milestone and link the tasks or reviews that demonstrate its outcome.' : 'The project owner has not added milestones yet.', host);
    rows.forEach(function (row) {
      var target = host;
      if (view === 'board') { if (!columns.has(row.state)) { var column = node('section', undefined, host); node('h3', row.state, column); columns.set(row.state, column); } target = columns.get(row.state); }
      var card = node('article', undefined, target); node(view === 'board' ? 'h4' : 'h3', row.title, card); node('p', row.state + (row.due ? ' · Target ' + row.due : ' · No target date'), card);
      node('p', row.depends_on.length ? 'Planning prerequisites: ' + row.depends_on.map(function (key) { return names.get(key) || 'Unavailable milestone'; }).join(', ') : 'No planning prerequisites', card);
      var list = node('ul', undefined, card); row.sources.forEach(function (item) { var li = node('li', undefined, list), link = node('a', item.title, li); link.href = item.href; node('span', ' · ' + item.status, li); });
      if (row.restricted_sources) node('p', 'Some linked work requires separate current access. Its content and identity are hidden here.', card);
      if (model.workspace.can_edit) {
        ['up','down'].forEach(function (direction) { button('Move ' + direction, card, function () { review('reorder', {id:row.id, direction:direction}); }); });
        button('Review removal', card, function () { review('remove_milestone', {id:row.id}); });
      }
    });
  }
  function render() {
    var w = model.workspace; source = null; id('source-panel').hidden = true; id('source-content').textContent = ''; id('workspace').hidden = false; id('title').textContent = w.name; id('outcome').textContent = w.outcome || 'The owner has not defined the outcome yet.';
    id('criteria').replaceChildren(); w.criteria.forEach(function (text) { node('li', text, id('criteria')); }); id('labels').textContent = w.labels.length ? 'Labels: ' + w.labels.join(' · ') : 'No labels';
    id('sharing').textContent = w.can_edit ? 'You own this project. Planning members do not gain access to your private tasks.' : 'Shared planning view. Private tasks and fixed reviews keep their separate access rules.';
    id('accepted').replaceChildren(); node('h3', 'Latest accepted deliverable', id('accepted'));
    if (w.latest_accepted) { node('p', w.latest_accepted.title + ' · Accepted ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(w.latest_accepted.accepted_at) : new Date(w.latest_accepted.accepted_at * 1000).toLocaleString()), id('accepted')); var link = node('a', 'Open your authorized review inbox', id('accepted')); link.href = w.latest_accepted.href; }
    else node('p', 'No current accepted review is visible to you for this project. A completed task alone does not count as accepted.', id('accepted'));
    if (!id('view').dataset.chosen) id('view').value = new URLSearchParams(location.search).get('view') || w.default_view;
    if (!['list','board','timeline'].includes(id('view').value)) id('view').value = 'list'; renderMilestones();
    id('context').replaceChildren(); if (!w.context.length) node('li', 'No reviewed context sources yet. Add a source above and review it.', id('context'));
    w.context.forEach(function (item) { var li = node('li', item.title + ' · ' + item.state, id('context'));
      if (item.fresh) button('Open reviewed source', li, function () { openSource('/' + project + '/context/' + item.reference, false); });
      if (w.can_edit && item.reference) button('Review removing source', li, function () { review('remove_context', {reference:item.reference}); }); });
    id('owner').hidden = !w.can_edit; if (w.can_edit) fillEditor();
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail:{selection:{kind:'project', id:project}}}));
  }
  async function refresh() {
    if (busy || uncertain) return; var started = ++generation; lock(true); status('Checking current project access and linked outcomes.');
    try {
      var data = await call(project ? '/' + project : ''); if (started !== generation) return;
      if (project) { model = data; render(); } else {
        id('list').replaceChildren(); if (!data.projects.length) node('p', 'No active owned or explicitly shared project workspaces. Create a project from Projects to start.', id('list'));
        data.projects.forEach(function (item) { var card = node('section', undefined, id('list')); card.className = 'panel'; var link = node('a', item.name, card); link.href = root.dataset.planHref ? root.dataset.planHref.replace('{id}', encodeURIComponent(item.project_id)) : '/project-workspaces/' + item.project_id; node('p', item.outcome || 'Outcome not defined yet', card); node('p', item.owned ? 'Your project' : 'Shared planning', card); });
      }
      status(dirty.size ? 'Current status refreshed. Your unsaved editor values are kept; review them against the current workspace.' : 'Current workspace and source access checked.'); id('remedy').hidden = true;
      return true;
    } catch (error) { if (started === generation) { status(error.message); id('remedy').hidden = false; if (error.status === 403 || error.status === 404) { id('workspace').hidden = true; id('list').replaceChildren(); } } }
    finally { if (started === generation) lock(false); }
    return false;
  }
  function display(value, parent) {
    if (value === null || value === undefined) { node('p', 'Not set', parent); return; }
    if (Array.isArray(value)) { if (!value.length) node('p', 'None', parent); value.forEach(function (item) { display(item, node('li', undefined, parent)); }); return; }
    if (typeof value === 'object') { var list = node('dl', undefined, parent); Object.entries(value).forEach(function (entry) { node('dt', entry[0].replace(/_/g, ' '), list); display(entry[1], node('dd', undefined, list)); }); return; }
    node('span', typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value, parent);
  }
  async function review(action, payload, form) {
    if (busy || uncertain || !model) return; var started = generation; lock(true); pending = null; status('Preparing the current before-and-after review.');
    try {
      var result = await call('/' + project + '/prepare', {action:action, payload:payload}); if (started !== generation) return;
      pending = {action:action, payload:payload, expected_revision:result.revision, operation_id:uid(), confirmed:true, form:form || null};
      id('change-list').replaceChildren(); result.changes.forEach(function (change) { node('h3', change.label, id('change-list')); node('h4', 'Current', id('change-list')); display(change.before, id('change-list')); node('h4', 'After this change', id('change-list')); display(change.after, id('change-list')); });
      if (!result.changes.length) node('p', 'No planning values would change.', id('change-list'));
      id('review-summary').textContent = result.summary; id('confirm-choice').checked = false; id('review-panel').hidden = false; id('check').hidden = true; id('retry-exact').hidden = true; id('confirm').hidden = false; id('review-title').focus(); status('Review the changes and sharing scope, then confirm separately.');
    } catch (error) { status(error.message); } finally { lock(false); }
  }
  function pendingBody() { var body = {...pending}; delete body.form; return body; }
  async function confirmedSave() {
    var form = pending && pending.form;
    if (form && JSON.stringify(form === 'details' ? detailsPayload() : milestonePayload()) === JSON.stringify(pending.payload)) {
      dirty.delete(form); if (recovery[form]) await recovery[form].clear();
    }
    uncertain = false; pending = null; id('review-panel').hidden = true; lock(false); var refreshed = await refresh();
    if (refreshed) status('The reviewed change is saved. Current project status has been refreshed.');
    else if (model) status('The reviewed change is saved, but current project status could not be refreshed. Use Refresh current status to check again.');
  }
  async function apply() {
    if (busy || uncertain || !pending || !id('confirm-choice').checked) { status('Select the confirmation checkbox after reviewing the change.'); return; }
    lock(true); status('Saving the reviewed change.');
    try { await call('/' + project + '/change', pendingBody()); lock(false); await confirmedSave(); }
    catch (error) {
      if (!error.status || error.status >= 500) { uncertain = true; id('check').hidden = false; id('confirm').hidden = true; status(error.message + ' Check this exact operation before another change; it will not be sent again automatically.'); }
      else { pending = null; id('review-panel').hidden = true; status(error.message); }
    } finally { lock(false); }
  }
  async function check() {
    if (busy || !pending || !uncertain) return; lock(true);
    try { var result = await call('/' + project + '/receipt', pendingBody()); if (result.confirmed) { lock(false); await confirmedSave(); }
      else { id('retry-exact').hidden = false; status('No saved receipt is visible yet. The original request may still finish. Check again, or explicitly retry this exact reviewed operation; its request identity prevents applying it twice. Your draft is kept.'); } }
    catch (error) { status(error.message + ' The outcome remains unconfirmed.'); } finally { lock(false); }
  }
  async function openSource(path, canUse) {
    if (busy || uncertain) return; lock(true); source = null;
    try { var value = await call(path); source = value; id('source-title').textContent = value.title; id('source-content').textContent = value.content; id('source-state').textContent = value.stale ? 'The source has changed. Ask its owner for a current review.' : 'Current source access checked. ' + (value.accepted ? 'This captured result has an accepted review.' : 'This source is not an accepted deliverable.'); id('add-source').hidden = !canUse || value.stale; id('source-panel').hidden = false; id('source-title').focus(); }
    catch (error) { id('source-panel').hidden = true; status(error.message); } finally { lock(false); }
  }
  ['details','milestone'].forEach(function (form) { id(form + '-form').addEventListener('input', function (event) { if (event.target.closest('.draft-recovery') || event.target.id === 'pw-milestone-select') return; dirty.add(form); invalidate(); }); id(form + '-form').addEventListener('change', function (event) { if (event.target.closest('.draft-recovery') || event.target.id === 'pw-milestone-select') return; dirty.add(form); invalidate(); }); });
  id('details-form').onsubmit = function (event) { event.preventDefault(); review('details', detailsPayload(), 'details'); };
  id('milestone-form').onsubmit = function (event) { event.preventDefault(); review('milestone', milestonePayload(), 'milestone'); };
  id('milestone-select').onchange = async function () {
    if (dirty.has('milestone') && !(await window.mvConfirm('Replace your unsaved milestone draft with the saved milestone you chose? Your unsaved edits are lost.', {okText: 'Replace draft'}))) { id('milestone-select').value = selectedMilestone; return; }
    var saved = model.workspace.editor.milestones.find(function (row) { return row.id === id('milestone-select').value; }); restoreMilestone(saved || {id:uid()}); dirty.delete('milestone'); invalidate();
  };
  id('dependency-form').onsubmit = function (event) { event.preventDefault(); review('dependency', {id:id('dependent').value, prerequisite:id('prerequisite').value, required:id('required').value === 'true'}); };
  id('view').onchange = function () { id('view').dataset.chosen = 'true'; var url = new URL(location.href); url.searchParams.set('view', id('view').value); history.replaceState(null, '', url.pathname + url.search); renderMilestones(); };
  id('share').onclick = function () { review('member', {member:id('member').value, allowed:true}); };
  ['save','apply'].forEach(function (action) { id(action + '-defaults').onclick = function () { review(action + '_defaults', {defaults_revision:model.defaults.revision}); }; });
  id('source-preview').onclick = function () { if (id('source').value) openSource('/' + project + '/sources/' + id('source').value, true); };
  id('add-source').onclick = function () { if (source) review('context', {kind:source.kind, source_id:source.source_id, version:source.version}); };
  id('confirm').onclick = apply; id('check').onclick = check; id('refresh').onclick = refresh;
  id('retry-exact').onclick = async function () { if (!busy && uncertain && pending) { uncertain = false; id('retry-exact').hidden = true; await apply(); } };
  id('back').onclick = function () { if (!busy && !uncertain) { pending = null; id('review-panel').hidden = true; } };
  id('cancel').onclick = function () { controllers.forEach(function (controller) { controller.abort(); }); };
  window.addEventListener('pagehide', function () { generation++; controllers.forEach(function (controller) { controller.abort(); }); Object.values(recovery).forEach(function (item) { if (item) item.dispose(); }); });
  window.addEventListener('beforeunload', function (event) { if (dirty.size || pending || uncertain) { event.preventDefault(); event.returnValue = ''; } });
  window.addEventListener('lightwork:drafts-ready', function () { if (model && model.workspace.can_edit) fillEditor(); });
  refresh();
})();
