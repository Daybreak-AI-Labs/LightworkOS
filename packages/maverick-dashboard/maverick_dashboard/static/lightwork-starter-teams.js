/* Shared reviewed controls: every write remains bound to its server preview. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const base = '/api/v1/starter-teams';
  let teams = [], setups = [], token = null, busy = false, opener = null, historyGeneration = 0, accountContext = null;
  let editedTeam = null, inputSetup = null;
  const element = (tag, text, className) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; };
  const pretty = value => Array.isArray(value) ? value.join('\n') : typeof value === 'object' ? Object.entries(value || {}).map(([key, item]) => key + ': ' + item).join('\n') : String(value);
  const selectedTeam = () => teams.find(team => team.id === $('st-team').value);
  const selectedSetup = () => setups.find(setup => setup.id === $('st-saved').value);
  function message(text) { $('st-message').textContent = text; }
  function remember() {
    try { if (token) sessionStorage.setItem('lightwork-starter-team-review', JSON.stringify({token, accountContext})); else sessionStorage.removeItem('lightwork-starter-team-review'); } catch (_) { /* The open page still retains its exact recovery token. */ }
  }
  function restore() {
    if (token) return;
    try { const saved = JSON.parse(sessionStorage.getItem('lightwork-starter-team-review') || 'null'); if (!saved) return; if (saved.accountContext !== accountContext) { sessionStorage.removeItem('lightwork-starter-team-review'); return; } token = saved.token; $('st-review-content').replaceChildren(element('p', 'A previous confirmation may have completed. Check its original result before making another change.')); $('st-confirm').disabled = true; $('st-original').hidden = false; $('st-review').showModal(); } catch (_) { /* An unreadable marker never authorizes a repeat. */ }
  }
  async function api(path, body) {
    return window.mvFetchJSON(base + path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
      headers: {'Accept': 'application/json', 'Content-Type': 'application/json'}, body,
      serverDetail: 'This work could not be completed. Check the selected workspace and try again.',
      messages: {unreadable: 'The response could not be read. Check the original result before trying again.'}
    }, 'check the starter-team work');
  }
  function addList(host, title, values) {
    host.appendChild(element('h3', title)); const list = element('ul');
    values.forEach(value => list.appendChild(element('li', value))); host.appendChild(list);
  }
  function showTeam() {
    const team = selectedTeam(), host = $('st-details'); host.replaceChildren();
    if (!team) return;
    host.appendChild(element('p', team.summary)); host.appendChild(element('h3', 'Finished work'));
    host.appendChild(element('p', team.deliverable));
    addList(host, 'Acceptance checks', team.acceptance);
    addList(host, 'Inputs and connection preparation', team.connections.flatMap(connection => [connection.name + ' — ' + connection.access + ' access', ...connection.prerequisites]));
    addList(host, 'When a person must step in', team.stop_conditions);
    addList(host, 'Actions outside this team', team.blocked_actions);
    if (editedTeam !== team.id) { $('st-scope').value = team.sample_goal; editedTeam = team.id; }
  }
  function chooseOptions(select, values, current, empty) {
    select.replaceChildren();
    if (!values.length) { const option = element('option', empty); option.value = ''; select.appendChild(option); }
    values.forEach(([value, label]) => { const option = element('option', label); option.value = value; select.appendChild(option); });
    if (values.some(([value]) => value === current)) select.value = current;
  }
  function tableInputs(team) {
    const host = $('st-input-tables'); host.replaceChildren();
    team.inputs.forEach((table, index) => {
      const field = element('div', undefined, 'st-field'), id = 'st-table-' + index;
      const label = element('label', table.label); label.htmlFor = id;
      const input = element('textarea', undefined, 'input st-csv'); input.id = id; input.dataset.table = table.key; input.value = table.columns.join(',') + '\n'; input.required = true; input.spellcheck = false;
      const fileLabel = element('label', 'Choose a CSV file for ' + table.label); fileLabel.htmlFor = id + '-file';
      const file = element('input'); file.id = id + '-file'; file.type = 'file'; file.accept = '.csv,text/csv';
      file.addEventListener('change', async () => { const chosen = file.files[0]; if (!chosen) return; if (chosen.size > 200000) { message('Choose a CSV file smaller than 200 KB.'); return; } input.value = await chosen.text(); });
      field.append(label, element('p', table.description, 'muted'), input, fileLabel, file); host.appendChild(field);
    });
    $('st-date').value = new Date().toISOString().slice(0, 10);
  }
  function renderCase(row, host) {
    const section = element('section', undefined, 'st-result'); section.id = 'case-' + row.id;
    const sample = row.mode === 'sample'; section.appendChild(element('h3', sample ? 'Sample result' : 'Your record checks'));
    section.appendChild(element('p', 'Status: ' + String(row.status).replaceAll('_', ' ')));
    const output = row.output || {}; section.appendChild(element('p', output.deliverable || 'Review package'));
    const findings = output.findings || []; section.appendChild(element('p', findings.length + ' findings for review.'));
    findings.forEach(finding => {
      const item = element('div', undefined, 'st-result'); item.appendChild(element('h4', finding.title || finding.rule_id || 'Finding'));
      [['reason', 'Finding'], ['proposed_action', 'Next work'], ['source', 'Source'], ['row_id', 'Record'], ['owner_role', 'Review owner']].forEach(([key, label]) => { if (finding[key] !== undefined) item.appendChild(element('p', label + ': ' + pretty(finding[key]))); });
      section.appendChild(item);
    });
    (output.handoffs || []).forEach(handoff => { section.appendChild(element('p', handoff.summary || 'Review the saved handoff.')); });
    const details = element('details'); details.appendChild(element('summary', 'Source references and review evidence'));
    const evidence = element('ul'); (output.evidence || []).forEach(item => evidence.appendChild(element('li', 'Record ' + item.row_id + ' — ' + item.source))); details.appendChild(evidence); section.appendChild(details);
    const exportButton = element('button', 'Download full review evidence', 'btn'); exportButton.type = 'button';
    exportButton.addEventListener('click', () => { const url = URL.createObjectURL(new Blob([JSON.stringify(row, null, 2)], {type: 'application/json'})); const link = element('a'); link.href = url; link.download = 'starter-team-evidence.json'; link.click(); URL.revokeObjectURL(url); });
    section.appendChild(exportButton); host.appendChild(section);
    if (!sample) renderRuntimeControls(row, section);
  }
  function renderRuntimeControls(row, section) {
    const form = element('form', undefined, 'st-fields'), title = element('h4', 'Specialist workflow');
    const budgetId = 'st-budget-' + row.id, timeId = 'st-time-' + row.id;
    const budgetLabel = element('label', 'Maximum total cost (USD)'); budgetLabel.htmlFor = budgetId;
    const budget = element('input', undefined, 'input'); budget.id = budgetId; budget.type = 'number'; budget.min = '.01'; budget.max = '100'; budget.step = '.01'; budget.value = '1'; budget.required = true;
    const timeLabel = element('label', 'Maximum total time (seconds)'); timeLabel.htmlFor = timeId;
    const wall = element('input', undefined, 'input'); wall.id = timeId; wall.type = 'number'; wall.min = '30'; wall.max = '3600'; wall.value = '900'; wall.required = true;
    const launch = element('button', 'Review specialist workflow', 'btn'); launch.type = 'submit';
    const progress = element('div'); progress.setAttribute('aria-live', 'polite');
    const check = element('button', 'Check specialist progress', 'btn'); check.type = 'button';
    check.addEventListener('click', async () => {
      check.disabled = true;
      try {
        const value = await api('/cases/' + encodeURIComponent(row.id) + '/runtime'), runtime = value.runtime;
        progress.replaceChildren();
        if (!runtime) { progress.appendChild(element('p', 'No specialist workflow has started for this case.')); return; }
        budget.value = runtime.max_dollars || (runtime.review || {}).max_dollars || budget.value;
        wall.value = runtime.max_wall_seconds || (runtime.review || {}).max_wall_seconds || wall.value;
        progress.appendChild(element('p', 'Workflow: ' + String(runtime.status).replaceAll('_', ' ')));
        (runtime.stages || []).forEach(stage => progress.appendChild(element('p', 'Specialist ' + (stage.index + 1) + ': ' + String(stage.state).replaceAll('_', ' ') + (stage.result ? ' — ' + pretty(stage.result) : ''))));
        if (runtime.reason) progress.appendChild(element('p', 'Next review: ' + runtime.reason));
        if (runtime.result) {
          progress.appendChild(element('p', typeof runtime.result === 'string' ? runtime.result : pretty(runtime.result), 'st-result-text'));
          const download = element('button', 'Download specialist deliverable', 'btn'); download.type = 'button';
          download.addEventListener('click', () => { const url = URL.createObjectURL(new Blob([runtime.result], {type: 'text/markdown'})); const link = element('a'); link.href = url; link.download = 'starter-team-deliverable.md'; link.click(); URL.revokeObjectURL(url); });
          progress.appendChild(download);
        }
        const evidence = element('button', 'Download specialist run evidence', 'btn'); evidence.type = 'button';
        evidence.addEventListener('click', () => { const url = URL.createObjectURL(new Blob([JSON.stringify(runtime, null, 2)], {type: 'application/json'})); const link = element('a'); link.href = url; link.download = 'starter-team-runtime.json'; link.click(); URL.revokeObjectURL(url); });
        progress.appendChild(evidence);
        progress.appendChild(element('p', 'Review the full deliverable before accepting a business result. A recorded run does not establish provider or customer qualification.'));
      } catch (error) { progress.replaceChildren(element('p', error.message)); } finally { check.disabled = false; }
    });
    form.addEventListener('submit', event => { event.preventDefault(); review('runtime', {case_id: row.id, max_dollars: Number(budget.value), max_wall_seconds: Number(wall.value)}); });
    form.append(title, element('p', 'This uses your configured AI service. Review the exact evidence and budget before starting. Lightwork continues through the approved roster while running; pause the team to hold later stages. Outside actions remain blocked.'), budgetLabel, budget, timeLabel, wall, launch, check, progress); section.appendChild(form);
  }
  async function showSaved() {
    const setup = selectedSetup(), generation = ++historyGeneration;
    const selection = setup ? {kind: 'starter_team', id: setup.id} : {};
    window.LightworkCopilotEarlySelection = {selection};
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection}}));
    document.dispatchEvent(new CustomEvent('lightwork:starter-team-selected', {detail: {setup, context: accountContext}}));
    $('st-sample').disabled = !setup || setup.paused; $('st-pause').disabled = !setup;
    $('st-inputs-section').hidden = !setup; $('st-inputs-review').disabled = !setup || setup.paused;
    $('st-history').replaceChildren(element('p', setup ? 'Loading results…' : 'No saved team selected.'));
    if (!setup) { $('st-saved-state').textContent = ''; return; }
    const team = teams.find(item => item.id === setup.team_id);
    $('st-saved-state').textContent = (setup.paused ? 'Paused' : 'Ready for manual runs') + ' · ' + setup.owner_label + ' · ' + setup.scope;
    $('st-pause').textContent = setup.paused ? 'Review resume' : 'Review pause';
    if (team && inputSetup !== setup.id) { tableInputs(team); inputSetup = setup.id; }
    try { const value = await api('/setups/' + encodeURIComponent(setup.id) + '/cases'); if (generation !== historyGeneration) return; const host = $('st-history'); host.replaceChildren(); if (!value.cases.length) host.appendChild(element('p', 'No results yet. Start with the bundled sample.')); value.cases.forEach(row => renderCase(row, host)); }
    catch (error) { if (generation === historyGeneration) $('st-history').replaceChildren(element('p', error.message)); }
  }
  async function refresh(preferred) {
    try {
      const value = await api('');
      if (accountContext && accountContext !== value.context) { $('st-owner').value = ''; $('st-scope').value = ''; token = null; remember(); editedTeam = null; inputSetup = null; $('st-input-tables').replaceChildren(); $('st-review').close(); }
      accountContext = value.context; teams = value.teams; setups = value.setups;
      let target = preferred || $('st-saved').value;
      const hash = window.location.hash;
      if (!preferred && hash.startsWith('#setup-')) target = hash.slice(7);
      if (!preferred && hash.startsWith('#case-')) { const original = await api('/cases/' + encodeURIComponent(hash.slice(6))); target = original.case.setup_id; }
      const linkedSetup = !preferred && (hash.startsWith('#case-') || hash.startsWith('#setup-')) ? setups.find(setup => setup.id === target) : null;
      chooseOptions($('st-team'), teams.map(team => [team.id, team.title]), linkedSetup ? linkedSetup.team_id : $('st-team').value, 'No permitted teams');
      chooseOptions($('st-saved'), setups.map(setup => [setup.id, (teams.find(team => team.id === setup.team_id) || {}).title + ' — ' + setup.owner_label]), target, 'No saved teams yet');
      showTeam(); await showSaved(); message(teams.length + ' teams available. Samples and record checks stay within the reviewed scope.');
      if (hash.startsWith('#case-')) { const original = document.getElementById(hash.slice(1)); if (original) original.scrollIntoView({block: 'nearest'}); }
      restore();
    } catch (error) { teams = []; setups = []; $('st-details').replaceChildren(); $('st-history').replaceChildren(); $('st-inputs-section').hidden = true; chooseOptions($('st-team'), [], '', 'Unavailable'); chooseOptions($('st-saved'), [], '', 'Unavailable'); message(error.message); }
  }
  async function review(action, arguments_) {
    if (busy || token) return; busy = true; opener = document.activeElement; message('Preparing the review…');
    try { const result = await api('/review', {action, arguments: arguments_, expected_context: accountContext}); token = result.token; const content = $('st-review-content'); content.replaceChildren(); Object.entries(result.preview).forEach(([key, value]) => content.append(element('dt', key), element('dd', pretty(value)))); $('st-review-message').textContent = ''; $('st-original').hidden = true; $('st-confirm').disabled = false; $('st-review').showModal(); message('Review the scope and consequences before confirming.'); }
    catch (error) { message(error.message); } finally { busy = false; }
  }
  async function confirm(recovery) {
    if (busy || !token) return; busy = true; $('st-confirm').disabled = true; $('st-original').disabled = true; remember();
    try {
      const result = await api(recovery ? '/original' : '/confirm', {token, confirmed: !recovery});
      if (result.status === 'unconfirmed') { $('st-review-message').textContent = result.message; return; }
      await refresh(result.setup && result.setup.id); token = null; remember(); $('st-review').close(); message(result.runtime ? 'Specialist workflow state recorded. Check its progress in the saved case.' : result.case ? 'The result and its source references are saved below.' : 'The team setup is saved.');
      if (opener) opener.focus();
    } catch (error) { $('st-review-message').textContent = error.message + ' Check the original result before trying again.'; $('st-original').hidden = false; }
    finally { busy = false; $('st-original').disabled = false; }
  }
  $('st-team').addEventListener('change', showTeam); $('st-saved').addEventListener('change', showSaved);
  $('st-setup-form').addEventListener('submit', event => { event.preventDefault(); if (selectedTeam()) review('setup', {team_id: selectedTeam().id, owner_label: $('st-owner').value, scope: $('st-scope').value, cadence: $('st-cadence').value, max_rows: Number($('st-limit').value)}); });
  $('st-sample').addEventListener('click', () => { const setup = selectedSetup(); if (setup) review('sample', {setup_id: setup.id}); });
  $('st-pause').addEventListener('click', () => { const setup = selectedSetup(); if (setup) review('pause', {setup_id: setup.id, paused: !setup.paused}); });
  $('st-inputs-form').addEventListener('submit', event => { event.preventDefault(); const setup = selectedSetup(); if (!setup) return; const tables = {}; document.querySelectorAll('[data-table]').forEach(input => { tables[input.dataset.table] = input.value; }); review('inputs', {setup_id: setup.id, as_of: $('st-date').value, tables}); });
  $('st-confirm').addEventListener('click', () => confirm(false)); $('st-original').addEventListener('click', () => confirm(true));
  $('st-cancel').addEventListener('click', () => { if (!busy) { $('st-review').close(); token = null; remember(); if (opener) opener.focus(); } });
  $('st-review').addEventListener('cancel', event => { if (busy) event.preventDefault(); else { token = null; remember(); } });
  $('st-refresh').addEventListener('click', () => refresh()); refresh();
  window.LightworkStarterTeams = {context: () => accountContext, setup: selectedSetup, refresh};
  window.addEventListener('hashchange', () => refresh());
})();
