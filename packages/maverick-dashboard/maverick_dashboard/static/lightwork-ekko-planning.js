// Private, owner-entered opportunity plans. Observation is never started here.
(() => {
  'use strict';
  const root = document.getElementById('ekko-planning');
  if (!root) return;
  const $ = id => document.getElementById(id);
  const api = '/api/v1/ekko';
  const discovery = window.LightworkEkkoDiscovery;
  let plans = [], enabled = false, generation = 0, read = 0, busy = false, workspaceContext = '';
  let editing = null, selected = null, pendingSample = null;
  const device = () => window.LightworkEkkoDevice();
  const stamp = () => ({generation, device: device()});
  const current = value => value.generation === generation && value.device === device() && root.isConnected && location.pathname === '/ekko';
  const say = (id, value) => { const line = $(id); if (typeof window.mvStatus === 'function') window.mvStatus(line, value); else line.textContent = value; };
  const text = (tag, style, value) => window.mvEl(tag, style, String(value));
  const getPlan = id => plans.find(plan => plan.opportunity_id === id);
  const stageName = stage => ({shortlisted: 'Shortlisted', pilot: 'In pilot', parked: 'Parked for later'}[stage] || 'Saved');

  async function request(path, options) {
    const scope = stamp();
    try { return await window.mvFetchJSON(api + path, {timeout: 15000, ...(options || {})}, 'update your opportunity workspace'); }
    catch (error) {
      const detail = window.mvPlainDetail && window.mvPlainDetail(error.detail);
      const contextChanged = error.status === 409 && error.detail && error.detail.code === 'ekko_context_changed';
      if (current(scope) && ([401, 403].includes(error.status) || contextChanged)) {
        discovery.close();
        document.dispatchEvent(new CustomEvent('lightwork:ekko-scope-reset'));
        say('ekko-planning-availability', 'Access changed. Refresh the page to check your current permissions.');
      }
      throw new Error(detail || 'Could not confirm this change. Refresh saved plans to check the current result before retrying.');
    }
  }

  function lock(value) {
    busy = value;
    $('ekko-plan-save').disabled = value || !enabled;
    $('ekko-pilot-record').disabled = value || !enabled;
    $('ekko-plan-remove').disabled = value;
    root.setAttribute('aria-busy', String(value));
  }

  function assumptions() {
    return {runs_per_week: Number($('ekko-plan-frequency').value), manual_minutes: Number($('ekko-plan-before').value),
      remaining_minutes: $('ekko-plan-after').value === '' ? null : Number($('ekko-plan-after').value),
      setup_hours: $('ekko-plan-setup').value === '' ? null : Number($('ekko-plan-setup').value)};
  }

  function benefitPreview() {
    const a = assumptions();
    if (Object.values(a).some(value => value !== null && (!Number.isFinite(value) || value < 0))) {
      say('ekko-benefit-preview', 'Use non-negative numbers for each assumption.'); return;
    }
    if (!a.runs_per_week || !a.manual_minutes || a.remaining_minutes === null || a.setup_hours === null) {
      say('ekko-benefit-preview', 'Enter frequency, current effort, remaining effort and setup time. Use zero only where you expect no effort.'); return;
    }
    const weekly = a.runs_per_week * (a.manual_minutes - a.remaining_minutes) / 60;
    const four = weekly * 4 - a.setup_hours;
    say('ekko-benefit-preview', 'Planning estimate: ' + weekly.toFixed(2) + ' human hours per week; ' + four.toFixed(2) +
      ' hours over four weeks after setup. ' + (weekly > 0 ? 'Setup breaks even after about ' + (a.setup_hours / weekly).toFixed(2) +
      ' weeks at this volume.' : 'These assumptions do not produce a positive weekly time saving.'));
  }

  function readReview() {
    const review = {task_type: $('ekko-review-type').value};
    ['goal', 'inputs', 'output', 'approval'].forEach(key => { review[key] = $('ekko-review-' + key).value.trim(); });
    return review;
  }

  function taskGuidance() {
    const guidance = {
      general: 'The draft will use your goal and review criteria.',
      reporting: 'The draft will check the reporting period and source coverage, prepare the summary, and reconcile totals.',
      reconciliation: 'The draft will check matching keys and tolerance rules, separate matches from exceptions, and verify control totals.',
      document_review: 'The draft will check the selected document and criteria, build a source-linked findings table, and flag uncertain conclusions.'
    };
    say('ekko-task-guidance', guidance[$('ekko-review-type').value] || guidance.general);
  }

  function populate(plan) {
    ['goal', 'inputs', 'output', 'approval'].forEach(key => { $('ekko-review-' + key).value = plan.review[key]; });
    $('ekko-review-type').value = plan.review.task_type || 'general';
    $('ekko-plan-frequency').value = plan.assumptions.runs_per_week;
    $('ekko-plan-before').value = plan.assumptions.manual_minutes;
    $('ekko-plan-after').value = plan.assumptions.remaining_minutes ?? '';
    $('ekko-plan-setup').value = plan.assumptions.setup_hours ?? '';
    $('ekko-plan-stage').value = plan.stage;
    editing = plan; benefitPreview(); taskGuidance();
  }

  function render() {
    const filter = $('ekko-plans-filter').value;
    const visible = plans.filter(plan => filter === 'all' || (filter === 'parked' ? plan.stage === 'parked' : plan.stage !== 'parked'));
    visible.sort((a, b) => (b.benefit.weekly_hours ?? -Infinity) - (a.benefit.weekly_hours ?? -Infinity) || a.review.goal.localeCompare(b.review.goal));
    const list = $('ekko-plans-list'); list.textContent = '';
    if (!visible.length) list.appendChild(text('p', 'ekko-note', 'No saved plans in this view. Review an opportunity above to create one.'));
    visible.forEach(plan => {
      const card = text('article', 'ekko-opportunity', '');
      card.appendChild(text('h3', '', plan.review.goal));
      card.appendChild(text('p', 'ekko-meta', stageName(plan.stage) + ' · ' + (plan.benefit.complete
        ? plan.benefit.weekly_hours.toFixed(2) + ' estimated human hours/week' : 'Benefit assumptions incomplete')));
      card.appendChild(text('p', 'ekko-note', plan.pilot.runs
        ? plan.pilot.accepted + ' of ' + plan.pilot.runs + ' reported pilot results accepted; ' + plan.pilot.total_minutes_saved + ' net human minutes saved.'
        : 'No pilot results recorded.'));
      const button = text('button', 'btn', 'Open saved plan'); button.type = 'button';
      button.dataset.plan = plan.opportunity_id; card.appendChild(button); list.appendChild(card);
    });
    $('ekko-plan-save-controls').hidden = !enabled;
    $('ekko-planning-off').hidden = enabled;
    lock(busy);
  }

  function showPilot(plan) {
    selected = plan; pendingSample = null;
    $('ekko-pilot').hidden = false;
    $('ekko-pilot-form').reset();
    say('ekko-pilot-message', '');
    $('ekko-pilot-title').textContent = plan.review.goal + ' · ' + stageName(plan.stage);
    const details = $('ekko-plan-details'); details.textContent = '';
    [['Inputs', plan.review.inputs], ['Expected result', plan.review.output], ['Human review', plan.review.approval]].forEach(([label, value]) => {
      details.appendChild(text('p', 'ekko-note', label + ': ' + value));
    });
    const p = plan.pilot;
    $('ekko-pilot-summary').textContent = p.runs ? 'Owner-reported pilot: ' + p.accepted + '/' + p.runs + ' results accepted. Net time saved: ' +
      p.total_minutes_saved + ' minutes; median ' + p.median_minutes_saved + ' minutes per run. This is not verified platform evidence.'
      : 'No pilot runs yet. Record real observations after testing the draft.';
    details.appendChild(text('p', 'ekko-note', 'Saved plan expires ' + new Date(plan.expires_at * 1000).toLocaleString() + '.'));
    $('ekko-pilot-before').value = plan.assumptions.manual_minutes || '';
    lock(busy);
  }

  function clearPilot() {
    selected = pendingSample = null; $('ekko-pilot').hidden = true; $('ekko-pilot-form').reset();
    ['ekko-plan-details', 'ekko-pilot-title', 'ekko-pilot-summary'].forEach(id => { $(id).textContent = ''; });
    say('ekko-pilot-message', '');
  }

  async function load() {
    const scope = stamp(), version = ++read;
    try {
      const data = await request('/plans?device_id=' + encodeURIComponent(scope.device));
      if (!current(scope) || version !== read) return;
      if (!data || !Array.isArray(data.plans) || typeof data.enabled !== 'boolean' || !/^[a-f0-9]{64}$/.test(data.context || '')) throw new Error('Saved plans could not be read. Try again.');
      if (workspaceContext && workspaceContext !== data.context) { discovery.close(); clearPilot(); }
      workspaceContext = data.context;
      plans = data.plans; enabled = data.enabled;
      say('ekko-planning-availability', enabled ? 'Private plans are available. New saves expire within ' + data.retention_days + ' days.' : 'Existing plans can still be inspected and removed.');
      if (selected && !getPlan(selected.opportunity_id)) clearPilot();
      render();
    } catch (error) {
      if (current(scope) && version === read) {
        enabled = false; plans = []; clearPilot(); render();
        say('ekko-planning-availability', error.message + ' Use Refresh saved plans to retry.');
      }
    }
  }

  async function openSaved(id) {
    if (busy) return;
    const plan = getPlan(id); if (!plan) return;
    const scope = stamp();
    if (discovery.candidate() && !(await window.mvConfirm('Open the saved version? Unsaved changes in the current task review will be replaced.', {okText: 'Open saved plan'}))) return;
    if (!current(scope)) return;
    showPilot(plan);
    if (discovery.hasCandidate(id)) { discovery.open(id); populate(plan); }
    else say('ekko-pilot-message', 'The source pattern no longer qualifies. You can inspect or remove this plan and record pilot observations; a new draft needs current evidence.');
    $('ekko-pilot-heading').focus();
  }

  async function savePlan() {
    if (busy || !enabled || !discovery.candidate() || !$('ekko-review-form').reportValidity()) return;
    if (!$('ekko-plan-consent').checked) { say('ekko-plan-save-message', 'Confirm that these notes may be saved privately before saving.'); return; }
    const scope = stamp(), candidate = discovery.candidate();
    const body = {device_id: scope.device, context: workspaceContext, acknowledge_private_storage: true, review: readReview(), assumptions: assumptions(), stage: $('ekko-plan-stage').value,
      evidence_revision: candidate.evidence_revision, expected_revision: editing && editing.opportunity_id === candidate.opportunity_id ? editing.revision : ''};
    lock(true); say('ekko-plan-save-message', 'Saving your private plan…');
    try {
      const result = await request('/candidates/' + candidate.opportunity_id + '/plan', {method: 'PUT', body});
      if (!current(scope) || discovery.candidate() !== candidate) return;
      if (!result || !result.saved || !result.plan) throw new Error('The save could not be confirmed. Refresh saved plans before retrying.');
      editing = result.plan; plans = plans.filter(plan => plan.opportunity_id !== candidate.opportunity_id).concat(result.plan);
      render(); showPilot(result.plan); say('ekko-plan-save-message', 'Plan saved privately. No workflow was saved or started.');
    } catch (error) { if (current(scope)) say('ekko-plan-save-message', error.message + ' Your entered notes are still here.'); }
    finally { if (current(scope)) lock(false); }
  }

  async function recordPilot(event) {
    event.preventDefault();
    if (busy || !enabled || !selected || !$('ekko-pilot-form').reportValidity()) return;
    const scope = stamp(), plan = selected;
    const values = {manual_minutes: Number($('ekko-pilot-before').value), remaining_minutes: Number($('ekko-pilot-after').value), accepted: $('ekko-pilot-accepted').value === 'yes'};
    if (pendingSample && pendingSample.values !== JSON.stringify(values)) {
      say('ekko-pilot-message', 'The earlier run was not confirmed. Refresh saved plans and reopen this plan before changing the values.'); return;
    }
    if (!pendingSample) pendingSample = {id: crypto.randomUUID(), values: JSON.stringify(values)};
    const body = {...values, context: workspaceContext, sample_id: pendingSample.id, expected_revision: plan.revision, device_id: scope.device};
    lock(true); say('ekko-pilot-message', 'Recording your observation…');
    try {
      const result = await request('/plans/' + plan.opportunity_id + '/runs', {method: 'POST', body});
      if (!current(scope) || selected !== plan) return;
      if (!result || !result.recorded || !result.plan) throw new Error('The result could not be confirmed. Refresh saved plans before recording another run.');
      plans = plans.filter(item => item.opportunity_id !== plan.opportunity_id).concat(result.plan);
      if (editing && editing.opportunity_id === plan.opportunity_id) editing = result.plan;
      showPilot(result.plan); render(); say('ekko-pilot-message', 'Pilot run recorded as your observation.');
    } catch (error) { if (current(scope)) say('ekko-pilot-message', error.message); }
    finally { if (current(scope)) lock(false); }
  }

  function removePlan() {
    if (busy || !selected) return;
    const scope = stamp(), plan = selected;
    // The plan leaves the page at once and the shared toast offers Undo; the
    // removal itself is sent when the Undo time is up or the person leaves.
    plans = plans.filter(item => item.opportunity_id !== plan.opportunity_id); selected = null; pendingSample = null;
    if (editing && editing.opportunity_id === plan.opportunity_id) editing = null;
    if (discovery.candidate() && discovery.candidate().opportunity_id === plan.opportunity_id) discovery.close();
    clearPilot(); render(); $('ekko-planning-heading').focus();
    window.mvUndo('Saved task plan removed, with its assumptions and pilot results. Recorded activity and any saved workflows are kept.', {
      action: 'remove the plan',
      run: async keepalive => {
        const result = await request('/plans/' + plan.opportunity_id, {method: 'DELETE', keepalive, body: {device_id: scope.device, context: workspaceContext, expected_revision: plan.revision}});
        if (!result || typeof result.removed !== 'boolean') throw new Error('Removal could not be confirmed. Refresh saved plans before trying again.');
        return {ok: true};
      },
      undo: () => {
        if (!current(scope) || getPlan(plan.opportunity_id)) return;
        plans = plans.concat(plan); render();
        if (!selected) { showPilot(plan); $('ekko-pilot-heading').focus(); }
      }
    });
  }

  $('ekko-plan-save').addEventListener('click', savePlan);
  $('ekko-pilot-form').addEventListener('submit', recordPilot);
  $('ekko-plan-remove').addEventListener('click', removePlan);
  $('ekko-plans-refresh').addEventListener('click', load);
  $('ekko-plans-filter').addEventListener('change', render);
  $('ekko-review-type').addEventListener('change', taskGuidance);
  ['frequency', 'before', 'after', 'setup'].forEach(name => $('ekko-plan-' + name).addEventListener('input', benefitPreview));
  $('ekko-plans-list').addEventListener('click', event => { const button = event.target.closest('button[data-plan]'); if (button) openSaved(button.dataset.plan); });
  document.addEventListener('lightwork:ekko-candidates-updated', load);
  document.addEventListener('lightwork:ekko-planning-review', load);
  document.addEventListener('lightwork:ekko-opportunity-opened', event => {
    const id = event.detail.opportunity_id;
    if (editing && editing.opportunity_id === id) return;
    editing = getPlan(id) || null;
    if (editing) populate(editing);
    benefitPreview(); taskGuidance();
  });
  document.addEventListener('lightwork:ekko-review-closed', () => { editing = null; });
  document.addEventListener('lightwork:ekko-scope-reset', () => {
    generation++; read++; plans = []; editing = selected = pendingSample = null; enabled = false; workspaceContext = '';
    clearPilot(); say('ekko-plan-save-message', '');
    say('ekko-planning-availability', 'Refresh saved plans for the current device and workspace.'); lock(false); render();
  });
  load();
})();
