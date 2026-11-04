(function () {
  'use strict';
  var root = document.getElementById('budget-guidance');
  var launch = document.querySelector('[data-budget-launch]');
  if (!root && !launch) return;
  var host = root || launch, generation = 0, controller = null, context = '', current = null;
  var status = root ? document.getElementById('budget-status') : launch.querySelector('[role="status"]');
  var i18n = window.LightworkI18n;
  function text(source, values) { return i18n ? i18n.text(source, values) : source.replace(/\{(\w+)\}/g, function (all, key) { return values && key in values ? String(values[key]) : all; }); }
  function set(element, source, values) { if (i18n) i18n.set(element, source, values); else { element.textContent = text(source, values); element.lang = 'en'; } }
  function node(tag, source, values) { var e = document.createElement(tag); if (source !== undefined) set(e, source, values); return e; }
  function content(tag, value) { var e = document.createElement(tag); e.textContent = value; e.lang = 'und'; e.dir = 'auto'; e.dataset.userContent = ''; return e; }
  function number(value) { return i18n ? i18n.number(value) : String(value); }
  function date(value) { return i18n ? i18n.formatDate(value) : new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString(); }
  var states = {available:'Available', blocked:'Blocked', unavailable:'Unavailable', unidentified:'No named account', not_bound:'Not bound', requested:'Requested', assigned:'Assigned', evidence_needed:'Evidence needed', reviewing:'Under review', verified:'Verified', pending:'Pending', reserved:'Reserved', settled:'Recorded', released:'Released', unknown:'Unknown', estimated:'Estimated', observed:'Observed'};
  function state(value) { return Object.prototype.hasOwnProperty.call(states, value) ? text(states[value]) : value; }
  function dimension(value) { var labels = {task:'Task ceiling', person:'Personal allowance', workspace:'Workspace allowance'}; return Object.prototype.hasOwnProperty.call(labels, value) ? text(labels[value]) : value && value.indexOf('provider:') === 0 ? text('Provider: {provider}', {provider:value.slice(9)}) : value; }
  // An accounting period key ("2026-09", "2026-10-04") reads as a month or day; requests keep the key.
  function period(value) { return window.mvDateAbsolute && window.mvDateAbsolute(value) || value; }
  function money(v) { return v === null || v === undefined ? text('Unavailable or uncapped (see basis)') : window.mvMoney(v); }
  function link(label, href, sourceContent) { var a = sourceContent ? content('a', label) : node('a', label); a.href = href; return a; }
  // Only the authored business message is shown; anything else (a dropped
  // connection, a non-JSON reply) gets one plain sentence, never raw text.
  function errorMessage(error) { var business = window.mvBusinessError && window.mvBusinessError(error); return business ? business.message : 'Budget details could not be refreshed. Try again in a moment.'; }
  async function call(url, options, signal) {
    return window.mvFetchJSON(url, Object.assign({cache: 'no-store', signal: signal}, options || {}), 'check the budget');
  }
  function paragraph(parent, source, values) { if (source) parent.appendChild(node('p', source, values)); }
  function render(value) {
    current = value; context = value.context;
    var out = root ? document.getElementById('budget-preview') : launch.querySelector('[data-budget-summary]');
    out.replaceChildren();
    paragraph(out, 'Effective task ceiling: {amount}; time ceiling: {duration}.', {amount:money(value.effective.max_dollars), duration:value.effective.max_wall_seconds === undefined ? text('Unavailable') : value.effective.max_wall_seconds === null ? text('Not configured') : text('{count} seconds', {count:number(value.effective.max_wall_seconds)})});
    if (value.headroom_complete) paragraph(out, 'Current usable headroom: {amount}', {amount:money(value.headroom)});
    else paragraph(out, 'Headroom is unavailable because at least one required ledger or identity is unknown. Refresh the preview, or ask your administrator to check the spending records.');
    if (value.binding_ceiling) paragraph(out, 'Binding ceiling: {ceiling}.', {ceiling:dimension(value.binding_ceiling)});
    paragraph(out, value.admission_allowed ? 'Dispatch will recheck authority and allowance before paid work.' : 'A current limit or accounting uncertainty may block paid work. Review the details before starting.');
    paragraph(out, 'Daily reset: {local} (midnight UTC). Provider periods are shown separately.', {local:date(value.reset_at)});
    if (!root) { out.appendChild(link('Review reservations, schedules and accounting help', '/budget' + (value.goal_id ? '?goal_id=' + value.goal_id : ''))); return; }
    paragraph(out, value.notice); paragraph(out, value.increase_owner); paragraph(out, value.task_error); paragraph(out, value.provider_error);
    ['person', 'workspace'].forEach(function (name) {
      var row = value[name], section = node('section'); section.className = 'panel'; section.appendChild(node('h2', name === 'person' ? 'Your daily allowance' : 'Workspace daily allowance'));
      if (row.message) paragraph(section, row.message);
      else paragraph(section, 'Cap {cap}; acknowledged {confirmed}; reserved {reserved}; unknown reservations {unknown}; remaining {remaining}.', {cap:money(row.cap), confirmed:money(row.confirmed), reserved:money(row.reserved), unknown:row.unknown_amount ? text('Amount unavailable') : money(row.unknown), remaining:money(row.remaining)});
      if (row.basis) paragraph(section, row.basis); out.appendChild(section);
    });
    paragraph(out, value.provider_coverage || 'Provider coverage unavailable. Refresh the preview in a minute.');
    (value.providers || []).forEach(function (row) {
      var section = node('section'); section.className = 'panel'; section.appendChild(content('h2', row.provider));
      paragraph(section, 'Period {period}; {state}; ceiling {cap}; remaining {remaining}.', {period:period(row.period), state:state(row.state), cap:money(row.cap), remaining:money(row.remaining)});
      if (row.basis) paragraph(section, row.basis);
      if (row.state === 'blocked' || row.state === 'unavailable') {
        var button = node('button', 'Request accounting help'); button.type = 'button'; button.className = 'btn btn--ghost';
        button.addEventListener('click', function () { mutate('/api/v1/budget/cases', {provider: row.provider, period: row.period, goal_id: value.goal_id}, button); }); section.appendChild(button);
      }
      out.appendChild(section);
    });
    if (value.task_receipts && value.task_receipts.length) {
      out.appendChild(node('h2', "This task's provider receipts"));
      value.task_receipts.forEach(function (row) { paragraph(out, '{reference}: {provider}, {period}, {state}; projected {projected}, recorded {actual}; basis {basis}.', {reference:row.reference, provider:row.provider, period:period(row.period), state:state(row.state), projected:money(row.projected), actual:money(row.actual), basis:state(row.cost_basis)}); });
    }
    var forecast = document.getElementById('budget-forecast'); forecast.replaceChildren();
    paragraph(forecast, value.forecast.message || value.forecast.price_basis || states[value.forecast.state] || 'Forecast unavailable. Refresh the preview in a minute.');
    if (value.forecast.state === 'available' && !value.forecast.items.length) paragraph(forecast, 'No schedule of yours runs before the daily reset. Schedules you set up in Automations appear here when they are due.');
    value.forecast.items.forEach(function (row) { var item = node('p'); item.appendChild(link(row.title, row.href, true)); item.appendChild(node('span', ' — {date}: {risk}. ', {date:date(row.due_at), risk:text(row.risk)})); item.appendChild(node('span', row.detail)); forecast.appendChild(item); });
    if (value.warnings_state !== 'available') paragraph(out, 'Budget notices could not be refreshed; the ledger preview remains separate. Refresh the page and try again.');
    (value.warnings || []).forEach(function (row) {
      var match = /^(person|workspace|provider:[a-z0-9_.-]+) allowance crossed ([0-9]+)%; review scheduled work$/.exec(row.label || '');
      if (match) paragraph(out, '{dimension} allowance crossed {percent}; review scheduled work', {dimension:dimension(match[1]), percent:i18n ? i18n.number(Number(match[2])/100, {style:'percent'}) : match[2] + '%'});
      else out.appendChild(content('p', row.label || ''));
    });
  }
  async function renderCases(signal) {
    if (!root) return;
    var out = document.getElementById('budget-cases');
    try {
      var data = await call('/api/v1/budget/cases', null, signal);
      if (signal.aborted || data.context !== context) return;
      out.replaceChildren();
      if (!data.items.length) paragraph(out, 'No accounting help requests yet. Requests appear here when someone asks Finance to review a cost.');
      data.items.forEach(function (row) {
        var card = node('section'); card.className = 'panel'; var heading = node('h3'); heading.appendChild(content('bdi', row.provider)); heading.append(' · '); heading.appendChild(content('bdi', period(row.period))); card.appendChild(heading);
        paragraph(card, '{reference}: {state}. Assigned to: {assignee}', {reference:row.id, state:state(row.state), assignee:row.assigned_to || text('Installation administrator queue')});
        paragraph(card, row.verification); if (row._audit_pending) paragraph(card, 'Audit delivery is pending; this is not a completed audited review.');
        if (data.admin) {
          var choose = node('button', 'Review this request with Copilot'); choose.type = 'button'; choose.className = 'btn btn--ghost';
          choose.addEventListener('click', function () {
            document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail: {selection: {case_id: row.id, goal_id: current.goal_id}}}));
            if (window.LightworkProductOperations) window.LightworkProductOperations.open();
          }); card.appendChild(choose);
          [['claim','Assign to me'],['request_evidence','Request final receipt evidence'],['verify','Verify original-period accounting']].forEach(function (action) {
            var button = node('button', action[1]); button.type = 'button'; button.className = 'btn btn--ghost';
            button.addEventListener('click', function () { mutate('/api/v1/budget/cases/' + encodeURIComponent(row.id), {expected_revision: row.revision, action: action[0]}, button); }); card.appendChild(button);
          }); card.appendChild(link('Open governed provider reconciliation', '/provider-spending'));
        }
        out.appendChild(card);
      });
    } catch (error) { if (!signal.aborted) { out.replaceChildren(); paragraph(out, errorMessage(error)); } }
  }
  async function mutate(url, body, button) {
    if (!current || !context) return;
    var submitted = context, c = new AbortController(), timer = setTimeout(function () { c.abort(); }, 20000);
    button.disabled = true;
    try {
      await call(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(Object.assign({}, body, {context:submitted}))}, c.signal);
      if (context === submitted) await refresh();
    } catch (error) { set(status, c.signal.aborted ? 'The response was interrupted. Refresh the durable request before trying again; it may already be recorded.' : errorMessage(error)); }
    finally { clearTimeout(timer); button.disabled = false; }
  }
  async function refresh() {
    var token = ++generation;
    if (controller) controller.abort(); controller = new AbortController(); var own = controller, timer = setTimeout(function () { own.abort(); }, 20000);
    var params = new URLSearchParams(), goal = host.dataset.goal;
    if (goal) params.set('goal_id', goal);
    if (root) new FormData(document.getElementById('budget-preview-form')).forEach(function (v,k) { if (String(v).trim()) params.set(k,v); });
    set(status, 'Checking current ceilings and reservations.');
    try {
      var value = await call('/api/v1/budget/preview?' + params.toString(), null, own.signal);
      if (token !== generation || own.signal.aborted) return;
      render(value); set(status, 'Observed {date}. No funds reserved and no paid request started.', {date:date(value.observed_at)});
      await renderCases(own.signal);
    } catch (error) {
      if (token !== generation) return;
      set(status, own.signal.aborted ? 'Budget preview timed out. Refresh before relying on these amounts.' : errorMessage(error));
      if ([401,403,404].indexOf(error.status) >= 0) { current = null; context = ''; (root ? document.getElementById('budget-preview') : launch.querySelector('[data-budget-summary]')).replaceChildren(); if(root) {document.getElementById('budget-cases').replaceChildren();document.getElementById('budget-forecast').replaceChildren();} }
    } finally { clearTimeout(timer); }
  }
  if (root && i18n) i18n.validation(document.getElementById('budget-preview-form'));
  if (root) document.getElementById('budget-preview-form').addEventListener('submit', function (event) {event.preventDefault(); refresh();});
  else launch.querySelector('button').addEventListener('click', refresh);
  window.addEventListener('pagehide', function () { generation++; if(controller)controller.abort(); current=null; context=''; });
  window.addEventListener('pageshow', function (event) {if(event.persisted)refresh();});
  refresh();
}());
