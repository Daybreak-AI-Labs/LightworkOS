/* Shared live metric contract. Customer content is never inserted as HTML. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  if (!$('iv-app')) return;
  const api = '/api/v1/intent-value';
  let report, settings, benchmarks = [], selectedBenchmark, detail, proposals = [], recommendationNotice = '', external, selectedMetric = '', generation = 0, detailGeneration = 0;
  const money = (value, currency) => value == null || !currency ? 'Unavailable' :
    new Intl.NumberFormat(undefined, {style: 'currency', currency, maximumFractionDigits: 2}).format(value);
  const costs = values => Object.entries(values || {}).map(([unit, value]) => money(value, unit)).join(', ') || 'No known cost records';
  const node = (tag, text, cls) => { const el = document.createElement(tag); if (text != null) el.textContent = text; if (cls) el.className = cls; return el; };
  const button = (label, fn) => { const el = node('button', label, 'btn'); el.type = 'button'; el.addEventListener('click', fn); return el; };
  const link = (label, href) => { const el = node('a', label, 'btn btn--ghost'); el.href = href; return el; };
  async function request(path, method = 'GET', body) {
    const value = await window.mvFetchJSON(api + path, {method, body,
      onAccess: clearAccess, onContextChange: clearAccess,
      serverDetail: 'This request could not be completed. Refresh and review the current record.'}, 'read or update work value');
    if (value.state === 'audit_pending') throw new Error('The change is waiting for its audit record. Refresh status before trying another action.');
    return value;
  }
  function error(err) { $('iv-error').textContent = err.message; $('iv-error').hidden = false; $('iv-retry').hidden = false; }
  function clearAccess(err) {
    ++generation; ++detailGeneration;
    report = settings = detail = external = selectedBenchmark = undefined;
    benchmarks = []; proposals = []; selectedMetric = '';
    $('iv-report').hidden = true;
    $('iv-detail').close(); $('iv-detail-body').replaceChildren();
    $('iv-detail-title').textContent = 'Work explanation';
    $('iv-status').textContent = 'Access changed. Refresh to check your current account and workspace.';
    error(err);
  }
  function filters() {
    const entity = $('iv-entity').value.split('|');
    return new URLSearchParams({start: $('iv-start').value, end: $('iv-end').value, scope: $('iv-scope').value,
      intent: $('iv-intent').value, entity_kind: entity[0] || '', entity_id: entity[1] || ''});
  }
  async function load() {
    const version = ++generation;
    $('iv-status').textContent = 'Refreshing authorized work and execution evidence…';
    $('iv-report').hidden = true; $('iv-error').hidden = true; $('iv-retry').hidden = true;
    if (!$('iv-device').checkValidity()) {
      // The device name goes with the sync and the suggestions, so a malformed one is refused before any request.
      $('iv-status').textContent = 'Report unavailable; no zero-value claim was made.';
      error(new Error('Enter the name of an enrolled Ekko device, using letters, numbers, dots, dashes, colons or underscores, then review its observations again.'));
      return;
    }
    try {
      // Reads never record work. Recording newly observed work is the explicit sync, so the page syncs first.
      const synced = await request('/sync?device_id=' + encodeURIComponent($('iv-device').value), 'POST', {});
      if (version !== generation) return;
      const [metrics, config, defaults, suggestions] = await Promise.all([
        request('?' + filters()), request('/settings'), request('/benchmarks'),
        request('/opportunities?include_decided=' + $('iv-decided').checked + '&device_id=' + encodeURIComponent($('iv-device').value))
      ]);
      if (version !== generation) return;
      report = metrics; settings = config; benchmarks = defaults.benchmarks; proposals = suggestions.opportunities; external = suggestions.external_observations;
      recommendationNotice = suggestions.recommendations_enabled === false ? suggestions.notice : '';
      render(); $('iv-report').hidden = false;
      $('iv-status').textContent = 'Current ' + (report.scope === 'company' ? 'company' : 'personal') + ' report, checked ' + new Date(synced.checked_at * 1000).toLocaleString() + '.';
    } catch (err) { if (version === generation) { $('iv-status').textContent = 'Report unavailable; no zero-value claim was made.'; error(err); } }
  }
  function options(select, rows, empty) {
    const value = select.value; select.replaceChildren();
    if (empty) { const option = node('option', empty); option.value = ''; select.append(option); }
    rows.forEach(([value, text]) => { const option = node('option', text); option.value = value; select.append(option); });
    if ([...select.options].some(option => option.value === value)) select.value = value;
  }
  function render() {
    options($('iv-intent'), benchmarks.map(row => [row.id, row.label]), 'All activities');
    const entityKinds = {processes: 'Workflow', specialists: 'Specialist', agents: 'Agent'};
    const entities = report.by_entity.map(row => [row.kind + '|' + row.id, entityKinds[row.kind] + ': ' + (row.label || row.id)]);
    const selected = $('iv-entity').value;
    if (selected && !entities.some(row => row[0] === selected)) entities.push([selected, selected.replace('|', ': ')]);
    options($('iv-entity'), entities, 'All contributors');
    $('iv-scope').querySelector('[value="company"]').disabled = !settings.can_company;
    const t = report.totals;
    const metrics = [
      ['observed', 'Observed work', t.observed_work, 'Requests and activity; execution is separate.'],
      ['performed', 'Audit-backed work performed', t.performed_work, 'Unique business work, including unvalued items.'],
      ['gross', 'Gross estimated labor value', money(t.gross_estimated_labor_value, t.currency), 'Benchmarks × attributable effort × labor rate.'],
      ['cost', 'Known execution costs', costs(t.known_execution_costs), 'Recorded and estimated amounts, including failures.'],
      ['net', 'Estimated net benefit', money(t.net_estimated_benefit, t.currency), 'Gross value minus same-period known costs.'],
      ['opportunity', 'Potential opportunity value', money(t.opportunity_value, t.currency), 'Observed unexecuted work; never added to executed value.']
    ];
    $('iv-metrics').replaceChildren(...metrics.map(([key, label, value, note]) => {
      const el = button(label, () => showContributions(key)); el.className = 'iv-metric'; el.dataset.metric = key;
      el.append(node('strong', String(value)), node('span', note + ' Open explanation.')); return el;
    }));
    $('iv-coverage').textContent = (t.cost_incomplete || report.incomplete ? 'Incomplete coverage. ' : '') +
      (t.unvalued_work ? t.unvalued_work + ' performed work items do not yet have a defensible valuation. ' : '') +
      (t.missing_cost_count ? t.missing_cost_count + ' missing cost records. ' : '') +
      'Measured costs: ' + costs(t.measured_costs) + '. Estimated/runtime costs: ' + costs(t.estimated_costs) +
      '. External fees, subscription allocations and provider invoices are not completely covered. Currencies are kept separate.';
    $('iv-attribution').textContent = report.attribution;
    const bridge = report.legacy_bridge;
    $('iv-reconciliation').textContent = report.reconciliation + (bridge ? ' In this scope: ' + bridge.legacy_completed_attempts +
      ' legacy completed attempts versus ' + bridge.unique_audited_work + ' unique audit-backed work items; legacy assumed labor value ' +
      money(bridge.legacy_assumed_labor_value, bridge.legacy_labor_currency) + '; labor-estimate difference ' + money(bridge.labor_estimate_difference, t.currency) +
      '; known USD cost difference ' + money(bridge.known_usd_cost_difference, 'USD') + '. ' + bridge.explanation : '');
    if (selectedMetric) showContributions(selectedMetric, false); else showRows(report.rows);
    $('iv-trend').replaceChildren(...report.daily.map(day => {
      const tr = node('tr'); [day.day, day.performed_work, money(day.gross_estimated_labor_value, day.currency), costs(day.known_execution_costs)].forEach(value => tr.append(node('td', String(value)))); return tr;
    }));
    $('iv-opportunities').replaceChildren(...proposals.map(row => {
      const card = node('article', null, 'iv-opportunity'); card.append(node('h3', row.label), node('p', row.current_evidence.reason),
        node('p', row.current_evidence.observed_count + ' distinct work items · ' + row.current_evidence.executed_count + ' with execution evidence · ' + row.status),
        button('Review opportunity', () => openOpportunity(row))); return card;
    }));
    if (!proposals.length) $('iv-opportunities').append(node('p', recommendationNotice || 'No current suggestions. Recognizable observed work creates opportunities; repeatable audited results can support reusable drafts.'));
    $('iv-external').replaceChildren(node('p', external.notice));
    external.patterns.forEach(pattern => {
      const card = node('article', null, 'iv-opportunity');
      card.append(node('h4', pattern.label), node('p', pattern.occurrences + ' observations across ' + pattern.distinct_days + ' days. Business intent and value remain unknown.'),
        node('p', pattern.steps.map(step => [step.action, step.object_type, step.app].join(' ')).join(' → ')), link('Inspect evidence and native draft options in Ekko', pattern.href));
      $('iv-external').append(card);
    });
    $('iv-rate').value = settings.hourly_rate; $('iv-currency').value = settings.currency; $('iv-confirmation').checked = settings.completion_confirmation;
    $('iv-rate-basis').textContent = settings.labor_provenance + '. Confirmation records user opinion only and never establishes Lightwork execution.';
    $('iv-rate').disabled = !settings.can_edit || settings.labor_locked;
    ['iv-currency', 'iv-confirmation', 'iv-settings-save'].forEach(id => $(id).disabled = !settings.can_edit);
    options($('iv-benchmark-select'), benchmarks.map(row => [row.id, row.label])); showBenchmark();
  }
  function showContributions(key, move = true) {
    selectedMetric = key;
    const names = {gross: 'gross estimated labor value', net: 'estimated net benefit', cost: 'known execution costs', performed: 'audit-backed work', observed: 'observed work', opportunity: 'unexecuted opportunity value'};
    $('iv-explanation').textContent = 'Explanation of ' + names[key] + '. The rows below are the exact contributing work population. Open a row for assumptions, costs, evidence and recalculation history.';
    const rows = report.rows.filter(row => key === 'cost' ? row.cost_event_count || row.missing_cost_count : key === 'opportunity' ? row.observed && !row.performed && row.opportunity : key === 'observed' ? row.observed : key === 'performed' || key === 'gross' ? row.performed : true);
    showRows(rows);
    if (move) { $('iv-contributions').focus(); $('iv-contributions').scrollIntoView({block: 'start'}); }
  }
  function showRows(rows) {
    $('iv-empty').hidden = rows.length > 0;
    $('iv-work').replaceChildren(...rows.map(row => {
      const tr = node('tr'), td = node('td'); td.append(button(row.label, () => openWork(row.id))); tr.append(td);
      [row.performed ? 'Audit-backed · ' + row.state.replaceAll('_', ' ') : 'Observed only', money(row.gross, row.currency), costs(row.costs), money(row.net, row.currency)].forEach(value => tr.append(node('td', value))); return tr;
    }));
  }
  function openDialog(title) { ++detailGeneration; $('iv-detail-title').textContent = title; $('iv-detail-body').replaceChildren(); $('iv-detail-status').textContent = ''; if (!$('iv-detail').open) $('iv-detail').showModal(); }
  async function perform(el, fn) {
    el.disabled = true; $('iv-detail-status').textContent = 'Saving…';
    try { await fn(); $('iv-detail-status').textContent = 'Saved. Current history is retained.'; }
    catch (err) { $('iv-detail-status').textContent = err.message; error(err); }
    finally { el.disabled = false; }
  }
  async function openWork(id) {
    openDialog('Work explanation'); $('iv-detail-status').textContent = 'Loading current evidence…';
    const version = detailGeneration;
    try {
      const received = await request('/work/' + encodeURIComponent(id) + '?scope=' + $('iv-scope').value);
      if (!$('iv-detail').open || version !== detailGeneration) return;
      detail = received;
      openDialog(detail.label); const body = $('iv-detail-body'), last = detail.estimates.at(-1), input = last.assumptions;
      body.append(node('p', detail.classification.reason + ' Confidence: ' + detail.classification.confidence + '.'), node('p', detail.grouping),
        node('p', 'Current estimate version ' + last.version + ': ' + money(last.gross, input.currency) + ' gross; ' + (last.avoided_minutes ?? 'unknown') + ' estimated avoided minutes. ' + input.manual_work),
        node('p', input.hourly_rate + ' ' + input.currency + ' per hour · ' + input.labor_provenance), node('h3', 'Execution evidence'));
      body.append(node('p', detail.evidence.length ? detail.evidence.map(row => row.kind + ': ' + row.status + ', ' + new Date(row.at * 1000).toLocaleString() + ', receipt ' + row.id.slice(0, 12) + (row.full_task ? ', full component' : ', partial component')).join('; ') : 'Observation only. No eligible Lightwork completion receipt is available.'));
      body.append(node('h3', 'Calculation assumptions'));
      body.append(node('p', 'Deliverables per business object: ' + Object.entries(input.units || {}).map(([key, count]) =>
        (benchmarks.find(item => item.object === key)?.label.replace(/^\S+\s+/, '') || key) + ' × ' + count).join('; ') + '. Overlapping activities for the same deliverable are not added together.'));
      input.benchmarks.filter(Boolean).forEach(row => body.append(node('p', row.id.replaceAll('.', ' ') + ': ' + row.minutes + ' minutes (' + row.low_minutes + '–' + row.high_minutes + '), Lightwork share ' + row.attributable_share + ', retained review ' + row.review_minutes + ' minutes. Version ' + row.version + ', effective ' + row.effective_date + '. ' + row.scope + '. ' + row.provenance)));
      body.append(node('h3', 'Execution costs'));
      body.append(node('p', 'Gross labor estimate range: ' + (last.range ? last.range.map(value => money(value, input.currency)).join(' to ') : 'Unavailable') + '. ' + last.component_policy));
      detail.costs.forEach(row => body.append(node('p', money(row.amount, row.currency) + ' · ' + row.basis + ' · ' + row.status + ' · ' + new Date(row.at * 1000).toLocaleDateString() + (row.time_basis ? ' · ' + row.time_basis : ''))));
      (detail.provider_evidence || []).forEach(catalog => (catalog.receipts || []).forEach(receipt => body.append(node('p', 'Provider receipt ' + receipt.reference + ': ' + receipt.period + ', ' + receipt.basis + ', ' + (receipt.pricing_basis || 'pricing basis unavailable') + '. Invoice verification is not established.'))));
      body.append(node('p', detail.cost_limitations.join(' ')), node('h3', 'Estimate and correction history'));
      detail.estimates.forEach(row => body.append(node('p', 'Version ' + row.version + ': ' + money(row.gross, row.assumptions.currency) + ' · ' + row.reason + ' · ' + new Date(row.at * 1000).toLocaleString())));
      detail.sources.forEach(row => body.append(link(row.label, row.href)));
      if (detail.converted_to) body.append(node('p', 'This original opportunity was converted to linked execution. Its assumptions remain in history; its potential is excluded from remaining opportunity totals.'), button('Inspect linked execution', () => openWork(detail.converted_to)));
      if (detail.can_correct) correctionForm(body, detail);
      $('iv-detail-status').textContent = '';
    } catch (err) { if (version === detailGeneration) $('iv-detail-status').textContent = err.message; }
  }
  function correctionForm(body, row) {
    const form = node('form', null, 'iv-form'), label = node('label', 'Correct the business activity'), select = node('select'); select.setAttribute('aria-label', 'Corrected activity');
    options(select, benchmarks.map(item => [item.id, item.label])); select.multiple = true; select.size = 5;
    [...select.options].forEach(option => option.selected = row.intents.includes(option.value)); label.append(select, node('span', 'Choose up to four supported activities; clear all if intent is unknown.'));
    const sizeLabel = node('label', 'Scope assumption'), size = node('select'); size.setAttribute('aria-label', 'Work size');
    options(size, [['standard', 'Fits the benchmark component'], ['large', 'Larger or uncertain; leave unvalued']]); size.value = row.classification.size; sizeLabel.append(size);
    const reasonLabel = node('label', 'Reason'), reason = node('input'); reason.required = true; reason.maxLength = 1000; reason.setAttribute('aria-label', 'Correction reason'); reasonLabel.append(reason);
    const quantities = node('div'), unitInputs = new Map();
    function quantitiesForSelection() {
      const previous = new Map([...unitInputs].map(([key, input]) => [key, input.value])); unitInputs.clear(); quantities.replaceChildren();
      [...select.selectedOptions].forEach(option => {
        const item = benchmarks.find(item => item.id === option.value); if (unitInputs.has(item.object)) return;
        const name = item.label.replace(/^\S+\s+/, ''), label = node('label', 'Number of deliverables: ' + name), input = node('input');
        input.type = 'number'; input.min = '1'; input.max = '50'; input.step = '1'; input.required = true;
        input.value = previous.get(item.object) || String(row.classification.units?.[item.object] || 1);
        input.setAttribute('aria-label', 'Number of deliverables: ' + name); label.append(input); quantities.append(label); unitInputs.set(item.object, input);
      });
    }
    select.addEventListener('change', quantitiesForSelection); quantitiesForSelection();
    const save = node('button', 'Correct and recalculate', 'btn'); save.type = 'submit'; form.append(label, quantities, sizeLabel, reasonLabel, save);
    form.addEventListener('submit', event => { event.preventDefault(); perform(save, async () => {
      await request('/work/' + row.id + '/correct', 'POST', {revision: row.revision, intents: [...select.selectedOptions].map(option => option.value), units: Object.fromEntries([...unitInputs].map(([key, input]) => [key, Number(input.value)])), size: size.value, reason: reason.value}); await load(); await openWork(row.id);
    }); }); body.append(form);
    const recalc = button('Recalculate with current benchmarks', () => perform(recalc, async () => {
      await request('/work/' + row.id + '/recalculate', 'POST', {revision: row.revision}); await load(); await openWork(row.id);
    })); body.append(recalc);
    if (row.confirmation_enabled) {
      const confirm = button('Mark this result complete (optional)', () => perform(confirm, async () => {
        await request('/work/' + row.id + '/confirm', 'POST', {revision: row.revision}); await openWork(row.id);
      })); body.append(confirm, node('p', 'This is your opinion about the current result. You can revise it later; it creates no execution credit.'));
    }
  }
  function openOpportunity(row) {
    openDialog(row.label); const body = $('iv-detail-body'), evidence = row.current_evidence;
    body.append(node('p', evidence.reason), node('p', row.evaluation.step_evidence), node('p', row.evaluation.supported_execution),
      node('p', 'Original baseline: ' + row.baseline.work_ids.length + ' executed work items. Current support: ' + evidence.observed_count + ' observed, ' + evidence.executed_count + ' audit-backed.'),
      node('h3', 'Supporting work'));
    const potential = evidence.potential;
    if (potential) body.append(node('p', potential.work_count + ' unexecuted work items: ' + money(potential.gross, potential.currency) +
      ' potential labor value; range ' + (potential.range ? potential.range.map(value => money(value, potential.currency)).join(' to ') : 'unavailable') +
      '. ' + potential.unvalued + ' unvalued. This potential is never added to the execution total.'));
    evidence.work_ids.forEach(id => body.append(button('Inspect supporting work', () => openWork(id))));
    body.append(node('h3', 'Proposed steps and retained control')); const manual = new Set(row.manual_steps);
    row.steps.forEach(step => { const label = node('label'), input = node('input'); input.type = 'checkbox'; input.checked = manual.has(step.id); input.disabled = step.required_manual; input.addEventListener('change', () => input.checked ? manual.add(step.id) : manual.delete(step.id)); label.append(input, document.createTextNode(' Keep manual: ' + step.label)); body.append(label); });
    body.append(node('p', row.evaluation.human_control), node('p', row.evaluation.limitations.join(' ')), node('h3', 'Forecast incremental benefit'),
      node('p', money(row.forecast.incremental_labor_per_run, row.forecast.currency) + ' potential additional labor value per future run; expected execution cost ' + money(row.forecast.execution_cost_per_run, row.forecast.currency) +
        '; provisional incremental planning net ' + money(row.forecast.incremental_net_per_run, row.forecast.currency) + '. Cost and labor assumptions still need qualification.'),
      node('p', row.forecast.assumptions), node('p', row.forecast.cost_coverage), node('h3', 'After adoption'),
      node('p', row.outcome.message));
    if (row.outcome.state === 'executed') body.append(node('p', row.outcome.observed_runs + ' audit-backed work items. ' + row.outcome.feedback + '. Prior known cost per run: ' + money(row.outcome.prior_known_cost_per_run, row.outcome.currency) + '; current: ' + money(row.outcome.after_known_cost_per_run, row.outcome.currency) + '.'));
    if (row.outcome.state === 'executed') body.append(node('p', 'Original forecast incremental net per run: ' + money(row.outcome.forecast_incremental_net_per_run, row.outcome.currency) +
      '; before/after estimated incremental net: ' + money(row.outcome.estimated_incremental_net_per_run, row.outcome.currency) + '. ' + row.outcome.comparison_basis));
    (row.outcome.runs || []).forEach(run => body.append(button('Inspect adopted work and costs', () => openWork(run.work_id))));
    const actions = node('div', null, 'iv-actions');
    const cap = evidence.capability;
    const use = button(cap ? 'Use existing ' + cap.kind + ': ' + cap.label : 'Start this work in Chat', () => perform(use, async () => {
      const result = await request('/opportunities/' + row.id + '/use', 'POST', {revision: row.revision});
      await load(); const current = proposals.find(item => item.id === row.id); if (current) openOpportunity(current);
      $('iv-detail-body').append(node('p', result.message), link('Continue to selected capability', result.href));
    }));
    if (!['declined', 'deferred'].includes(row.status)) actions.append(use);
    if (cap) {
      (cap.learning_evidence || []).forEach(signal => body.append(node('p', 'Existing workflow learning: ' + signal.reason + '. ' + signal.blocking_reason)));
    }
    if (row.draft_id) actions.append(link('Inspect and edit workflow draft', '/flows/designer/' + encodeURIComponent(row.draft_id)));
    if (evidence.draft_supported && !row.draft_id && !['declined', 'deferred'].includes(row.status)) {
      const build = button('Build reviewable workflow draft', () => perform(build, async () => {
        let revision = row.revision;
        if ([...manual].sort().join(',') !== [...row.manual_steps].sort().join(',')) {
          const saved = await request('/opportunities/' + row.id + '/decision', 'POST', {revision, decision: 'adjust', manual_steps: [...manual]}); revision = saved.revision;
        }
        const result = await request('/opportunities/' + row.id + '/build', 'POST', {revision});
        await load(); const current = proposals.find(item => item.id === row.id); if (current) openOpportunity(current);
        $('iv-detail-body').append(node('p', result.message), link('Open draft in workflow builder', result.href));
      })); actions.append(build);
    }
    [['adjust', 'Save manual-step choices'], ['defer', 'Defer'], ['decline', 'Keep current process'], ['reopen', 'Reopen suggestion']].filter(([decision]) => decision !== 'adjust' || !row.draft_id).forEach(([decision, label]) => {
      const control = button(label, () => perform(control, async () => { await request('/opportunities/' + row.id + '/decision', 'POST', {revision: row.revision, decision, manual_steps: [...manual]}); await load(); $('iv-detail').close(); })); actions.append(control);
    }); body.append(actions, link('Check connections and provider readiness', '/workflow-readiness'));
  }
  function showBenchmark() {
    selectedBenchmark = benchmarks.find(row => row.id === $('iv-benchmark-select').value) || benchmarks[0]; if (!selectedBenchmark) return;
    const b = selectedBenchmark.benchmark;
    $('iv-benchmark-description').replaceChildren(node('p', b.scope + '. Units: ' + b.unit + '. Relevant dimensions: ' + selectedBenchmark.effort_dimensions.join(', ') + '.'),
      node('p', b.provenance + ' Version ' + b.version + ' · effective ' + b.effective_date + (b.override ? ' · company override' : ' · provisional default')));
    [['minutes', b.minutes], ['low', b.low_minutes], ['high', b.high_minutes], ['share', b.attributable_share], ['review', b.review_minutes]].forEach(([key, value]) => { $('iv-bm-' + key).value = value; $('iv-bm-' + key).disabled = !settings.can_edit; });
    $('iv-bm-reason').value = ''; $('iv-bm-reason').disabled = !settings.can_edit; $('iv-benchmark-save').disabled = !settings.can_edit;
  }
  $('iv-settings-form').addEventListener('submit', event => { event.preventDefault(); perform($('iv-settings-save'), async () => { await request('/settings', 'PUT', {revision: settings.revision, hourly_rate: Number($('iv-rate').value), currency: $('iv-currency').value, completion_confirmation: $('iv-confirmation').checked}); await load(); }); });
  $('iv-benchmark-form').addEventListener('submit', event => { event.preventDefault(); perform($('iv-benchmark-save'), async () => {
    await request('/benchmarks/' + selectedBenchmark.id, 'PUT', {revision: selectedBenchmark.revision, minutes: Number($('iv-bm-minutes').value), low_minutes: Number($('iv-bm-low').value), high_minutes: Number($('iv-bm-high').value), attributable_share: Number($('iv-bm-share').value), review_minutes: Number($('iv-bm-review').value), reason: $('iv-bm-reason').value}); await load();
  }); });
  $('iv-benchmark-select').addEventListener('change', showBenchmark);
  $('iv-filters').addEventListener('submit', event => { event.preventDefault(); load(); });
  $('iv-decided').addEventListener('change', load); $('iv-retry').addEventListener('click', load);
  $('iv-device-form').addEventListener('submit', event => { event.preventDefault(); load(); });
  $('iv-detail-close').addEventListener('click', () => $('iv-detail').close());
  const query = new URLSearchParams(location.search), now = new Date(), iso = date => date.toISOString().slice(0, 10);
  $('iv-start').value = query.get('start') || iso(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)));
  $('iv-end').value = query.get('end') || iso(now); $('iv-scope').value = query.get('scope') === 'company' ? 'company' : 'own';
  if (query.get('intent')) { const option = node('option', query.get('intent')); option.value = query.get('intent'); $('iv-intent').append(option); $('iv-intent').value = option.value; }
  if (query.get('entity_kind') && query.get('entity_id')) { const option = node('option', query.get('entity_id')); option.value = query.get('entity_kind') + '|' + query.get('entity_id'); $('iv-entity').append(option); $('iv-entity').value = option.value; }
  load();
}());
