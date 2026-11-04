/* Schedule authority comes only from server-reviewed, individually approved work. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  if (!$('starter-team-schedules')) return;
  const base = '/api/v1/starter-team-schedules';
  let schedules = [], setups = [], teams = [], account = '', token = null;
  let busy = false, generation = 0, opener = null;
  const node = (tag, text, cls) => { const result = document.createElement(tag); if (text !== undefined) result.textContent = String(text); if (cls) result.className = cls; return result; };
  const selected = () => schedules.find(row => row.id === $('sts-saved').value);
  const text = value => String(value === null || value === undefined ? '' : value);
  function message(value) { $('sts-message').textContent = value; }
  async function api(path, body) {
    return window.mvFetchJSON(base + path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
      headers: {'Accept': 'application/json', 'Content-Type': 'application/json'}, body,
      serverDetail: 'The schedule operation could not be completed. Refresh its current state and review again.',
      messages: {unreadable: 'The response could not be read. Check the original result before trying again.'}
    }, 'check the scheduled team work');
  }
  function options(select, values, preferred, empty) {
    select.replaceChildren();
    if (!values.length) { const option = node('option', empty); option.value = ''; select.appendChild(option); }
    values.forEach(([value, label]) => { const option = node('option', label); option.value = value; select.appendChild(option); });
    if (values.some(([value]) => value === preferred)) select.value = preferred;
  }
  function display(value) {
    if (Array.isArray(value)) { const list = node('ul'); value.forEach(item => { const li = node('li'); li.appendChild(display(item)); list.appendChild(li); }); return list; }
    if (value !== null && typeof value === 'object') { const dl = node('dl'); Object.entries(value).forEach(([key, item]) => { const dd = node('dd'); dd.appendChild(display(item)); dl.append(node('dt', key.replaceAll('_', ' ')), dd); }); return dl; }
    return node('span', text(value));
  }
  function remember() {
    try { if (token) sessionStorage.setItem('lightwork-starter-schedule-review', JSON.stringify({token, account})); else sessionStorage.removeItem('lightwork-starter-schedule-review'); } catch (_) { /* Recovery still works in this page when browser storage is unavailable. */ }
  }
  function restore() {
    if (token) return;
    try { const saved = JSON.parse(sessionStorage.getItem('lightwork-starter-schedule-review') || 'null'); if (!saved) return; if (saved.account !== account) { sessionStorage.removeItem('lightwork-starter-schedule-review'); return; } token = saved.token; $('sts-review-content').replaceChildren(node('p', 'A previous confirmation may have completed. Check its original result before making another change.')); $('sts-confirm').disabled = true; $('sts-original').hidden = false; $('sts-review').showModal(); } catch (_) { /* An unreadable recovery marker never authorizes a repeat. */ }
  }
  function inputTables(team) {
    const host = $('sts-tables'); host.replaceChildren();
    team.inputs.forEach((table, index) => {
      const wrap = node('div', undefined, 'st-field'), id = 'sts-table-' + index;
      const label = node('label', table.label); label.htmlFor = id;
      const area = node('textarea', undefined, 'input st-csv'); area.id = id; area.dataset.scheduleTable = table.key; area.value = table.columns.join(',') + '\n'; area.required = true; area.spellcheck = false;
      const fileLabel = node('label', 'Choose a CSV file for ' + table.label); fileLabel.htmlFor = id + '-file';
      const file = node('input'); file.type = 'file'; file.id = id + '-file'; file.accept = '.csv,text/csv';
      file.addEventListener('change', async () => { const chosen = file.files[0]; if (!chosen) return; if (chosen.size > 200000) { message('Choose a CSV export smaller than 200 KB.'); return; } area.value = await chosen.text(); });
      wrap.append(label, node('p', table.description, 'muted'), area, fileLabel, file); host.appendChild(wrap);
    });
    $('sts-as-of').value = new Date().toISOString().slice(0, 10);
  }
  function teamName(setup) { const team = teams.find(row => setup && row.id === setup.team_id); return team ? team.title : 'Saved team'; }
  async function showSchedule(resetInputs) {
    const row = selected(), version = ++generation;
    $('sts-pause').disabled = !row; $('sts-tick').disabled = !row || row.paused;
    $('sts-inbox').hidden = !row;
    if (!row) { $('sts-state').textContent = 'No schedule selected.'; return; }
    const setup = setups.find(item => item.id === row.setup_id), team = teams.find(item => setup && item.id === setup.team_id);
    $('sts-state').textContent = teamName(setup) + ' — ' + (row.paused ? 'Paused' : text(row.status || 'Ready for approved packages').replaceAll('_', ' ')) + '. Ends ' + new Date(row.end_at * 1000).toLocaleString(undefined, {timeZone: 'UTC'}) + ' UTC. Up to ' + row.max_runs + ' runs and $' + row.max_total_dollars + ' total.';
    $('sts-pause').textContent = row.paused ? 'Review resume' : 'Review pause';
    if (team && resetInputs) inputTables(team);
    if ($('starter-team-schedules').contains(document.activeElement)) {
      const selection = {kind: 'starter_team_schedule', id: row.id};
      window.LightworkCopilotEarlySelection = {selection};
      document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection}}));
    }
    try {
      const result = await api('/' + encodeURIComponent(row.id) + '/items');
      if (version !== generation) return;
      const host = $('sts-history'); host.replaceChildren();
      if (!result.items.length) host.appendChild(node('p', 'No evidence packages yet. Add and review one above.'));
      result.items.forEach((item, index) => { const section = node('section', undefined, 'st-result'); section.append(node('h4', 'Evidence package ' + (index + 1)), node('p', 'State: ' + text(item.status).replaceAll('_', ' '))); const details = node('details'); details.appendChild(node('summary', 'Reviewed scope and source references')); const review = item.runtime_review || {}; details.appendChild(display({'Scope': review.scope, 'Sources': review.source_scope || [], 'Maximum dollars': review.max_dollars})); section.appendChild(details); host.appendChild(section); });
    } catch (error) { if (version === generation) $('sts-history').replaceChildren(node('p', error.message)); }
  }
  async function refresh(preferred) {
    try {
      const [current, catalog] = await Promise.all([api(''), window.mvFetchJSON('/api/v1/starter-teams', {credentials: 'same-origin'}, 'read your saved teams').catch(() => { throw new Error('Your saved teams are unavailable. Check workspace access and refresh.'); })]);
      if (current.context !== catalog.context) throw new Error('Your workspace changed while loading. Refresh before reviewing scheduled work.');
      const old = $('sts-saved').value;
      account = current.context; schedules = current.schedules; setups = catalog.setups; teams = catalog.teams;
      $('sts-worker').textContent = current.worker && current.worker.running ? 'Background worker running while Lightwork is open. It advances only approved packages that are due.' : 'Background worker is not running. You can review a due run here; saving a schedule does not start a worker.';
      options($('sts-setup'), setups.map(row => [row.id, teamName(row) + ' - ' + row.owner_label]), $('sts-setup').value, 'Save a starter team first');
      options($('sts-saved'), schedules.map(row => [row.id, teamName(setups.find(item => item.id === row.setup_id)) + ' - ' + new Date(row.start_at * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC']), preferred || old, 'No reviewed schedules');
      $('sts-create-review').disabled = !setups.length;
      await showSchedule($('sts-saved').value !== old || !$('sts-tables').children.length);
      message(schedules.length + ' reviewed schedules. Each run still needs its own approved evidence package.'); restore();
    } catch (error) { generation += 1; schedules = []; account = ''; $('sts-inbox').hidden = true; $('sts-history').replaceChildren(); $('sts-create-review').disabled = true; $('sts-tick').disabled = true; $('sts-pause').disabled = true; options($('sts-saved'), [], '', 'Unavailable'); message(error.message); }
  }
  async function review(action, arguments_) {
    if (busy || token) return; busy = true; opener = document.activeElement;
    try { const result = await api('/review', {action, arguments: arguments_, expected_context: account}); token = result.token; $('sts-review-content').replaceChildren(display(result.preview)); $('sts-review-message').textContent = ''; $('sts-confirm').disabled = false; $('sts-original').hidden = true; $('sts-review').showModal(); }
    catch (error) { message(error.message); } finally { busy = false; }
  }
  async function confirm(recovery) {
    if (busy || !token) return; busy = true; $('sts-confirm').disabled = true; $('sts-original').disabled = true; remember();
    try {
      const result = await api(recovery ? '/original' : '/confirm', {token, confirmed: !recovery});
      if (result.status === 'unconfirmed') { $('sts-review-message').textContent = result.message; $('sts-original').hidden = false; return; }
      await refresh(result.schedule && result.schedule.id); token = null; remember(); $('sts-review').close(); const outcome = result.outcome || {}; message((outcome.Result || 'The reviewed operation is recorded.') + ' ' + (outcome.Status || 'Review current status and provider prerequisites before expecting a run.')); if (opener) opener.focus();
    } catch (error) { $('sts-review-message').textContent = error.message + ' Check the original result before another attempt.'; $('sts-original').hidden = false; }
    finally { busy = false; $('sts-original').disabled = false; }
  }
  $('sts-start').value = new Date(Date.now() + 15 * 60000).toISOString().slice(0, 16);
  $('sts-end').value = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 16);
  $('sts-create-form').addEventListener('submit', event => { event.preventDefault(); review('schedule', {setup_id: $('sts-setup').value, start_at: Date.parse($('sts-start').value + 'Z') / 1000, end_at: Date.parse($('sts-end').value + 'Z') / 1000, interval_hours: Number($('sts-interval').value), max_runs: Number($('sts-count').value), max_dollars_per_run: Number($('sts-run-dollars').value), max_total_dollars: Number($('sts-total-dollars').value), max_wall_seconds: Number($('sts-wall').value)}); });
  $('sts-saved').addEventListener('change', () => showSchedule(true));
  $('sts-item-form').addEventListener('submit', event => { event.preventDefault(); const row = selected(); if (!row) return; const tables = {}; document.querySelectorAll('[data-schedule-table]').forEach(area => { tables[area.dataset.scheduleTable] = area.value; }); review('item', {schedule_id: row.id, as_of: $('sts-as-of').value, tables}); });
  $('sts-pause').addEventListener('click', () => { const row = selected(); if (row) review('pause', {schedule_id: row.id, paused: !row.paused}); });
  $('sts-tick').addEventListener('click', () => { const row = selected(); if (row) review('tick', {schedule_id: row.id}); });
  $('sts-confirm').addEventListener('click', () => confirm(false)); $('sts-original').addEventListener('click', () => confirm(true));
  $('sts-cancel').addEventListener('click', () => { if (!busy) { $('sts-review').close(); token = null; remember(); if (opener) opener.focus(); } });
  $('sts-review').addEventListener('cancel', event => { if (busy) event.preventDefault(); else { token = null; remember(); } });
  $('sts-refresh').addEventListener('click', () => refresh());
  document.addEventListener('lightwork:starter-team-selected', () => { if (!busy && !token) refresh(); });
  refresh();
})();
