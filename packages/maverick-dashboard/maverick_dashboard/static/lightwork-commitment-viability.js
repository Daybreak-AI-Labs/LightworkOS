(function () {
  'use strict';
  const root = document.getElementById('cmv-enabled');
  if (!root) return;
  const context = root.dataset.context;
  const $ = id => document.getElementById(id);
  const message = $('cmv-message');
  const pending = new Map();
  let current = null, observationDraftOwner = null, busy = false, lostAccess = false;
  let cursors = {active:'', archived:''}, more = {active:false, archived:false};
  let openGeneration = 0, listGeneration = 0;

  const el = (tag, content) => {
    const node = document.createElement(tag);
    if (content !== undefined) node.textContent = String(content);
    return node;
  };
  const date = value => value ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(value) : new Date(value * 1000).toLocaleString()) : 'Not available';
  const inputDate = value => {
    const d = new Date(value * 1000), pad = part => String(part).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  const local = value => {
    const d = new Date(value);
    if (!value || Number.isNaN(d.getTime())) throw new Error('Enter a complete date and time.');
    return d.toISOString();
  };
  function freshOperation() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') {
      throw new Error('This browser cannot safely start a new save. Use a supported browser and try again.');
    }
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
  }
  const number = (data, key) => Number(data.get(key));
  // The live region announces updates without stealing keyboard focus from
  // the control a person is using.
  const say = text => { message.textContent = text; };
  const publish = id => document.dispatchEvent(new CustomEvent('lightwork:copilot-selection',
    {detail:{selection: id ? {kind:'commitment_review', id} : {}}}));
  function lock(value) {
    busy = value;
    root.setAttribute('aria-busy', String(value));
    root.querySelectorAll('button,input,select,textarea').forEach(item => { item.disabled = value || lostAccess; });
  }
  function resetObservation() {
    const form = $('cmv-trace');
    form.reset();
    form.elements.running_order.value = '';
    form.elements.blocked_order.value = '';
    observationDraftOwner = null;
  }
  function clearOpenReview(discardObservation=false) {
    if (discardObservation) resetObservation();
    current = null; openGeneration++; publish('');
    document.dispatchEvent(new CustomEvent('lightwork:commitment-review', {detail:{review:null}}));
    $('cmv-report').hidden = true;
  }
  function activeReview() {
    if (!current) return null;
    if ($('cmv-report').hidden || $('cmv-select').value !== current.id) {
      clearOpenReview(true);
      say('Open the selected review before recording a change.');
      return null;
    }
    return current;
  }
  function forget() {
    lostAccess = true; cursors = {active:'', archived:''}; listGeneration++; clearOpenReview(true);
    $('cmv-select').replaceChildren(new Option('Choose a review', ''));
    root.querySelectorAll('input,textarea').forEach(item => { item.value = ''; });
    lock(false);
  }
  async function request(path, method='GET', body) {
    let data;
    try {
      data = await window.mvFetchJSON('/api/v1/commitment-reviews' + path, {method, cache:'no-store', body, plainDetail:true,
        headers:{'Content-Type':'application/json','X-Lightwork-Commitment-Context':context}, onAccess:forget,
        messages:{422:'Check the entered values and try again.', offline:'The connection was interrupted. Refresh saved reviews before trying again.'}}, method === 'GET' ? 'load the saved reviews' : 'save the review');
    } catch (error) {
      if (error.unreadable) throw new Error('The current saved result could not be read. Refresh before trying again.');
      if (error.status === 409 && typeof error.detail === 'string' && error.detail.includes('account or workspace')) forget();
      throw error;
    }
    if (data.context !== context) { forget(); throw new Error('The account or workspace changed. Reload this page.'); }
    if (lostAccess) throw new Error('Access changed. Reload this page.');
    return data;
  }
  function uniqueOperation(scope, body) {
    const fingerprint = JSON.stringify(body);
    const old = pending.get(scope);
    if (old && old.fingerprint === fingerprint) return old.id;
    const id = freshOperation();
    pending.set(scope, {fingerprint, id});
    return id;
  }
  async function change(scope, action, success='Saved. The current review is shown below.') {
    if (busy || lostAccess) return;
    openGeneration++; listGeneration++;
    lock(true);
    say('Saving and checking the current review…');
    try {
      await action(); pending.delete(scope); say(success);
      if (current && !$('cmv-report').hidden) $('cmv-report-title').focus();
    }
    catch (error) { say(error.message + (lostAccess ? ' Reload this page.' : ' Your entered details remain here. Refresh the saved review before retrying.')); }
    finally { lock(false); }
  }
  async function list(reset=true) {
    const generation = ++listGeneration;
    const select = $('cmv-select');
    const selected = reset ? select.value : '';
    if (reset) {
      cursors={active:'',archived:''}; more={active:false,archived:false}; clearOpenReview();
      select.replaceChildren(new Option('Choose a review', ''));
    }
    const kinds = reset ? ['active','archived'] :
      ['active','archived'].filter(kind=>more[kind]);
    const pages = await Promise.all(kinds.map(async kind => ({kind, data:await request('?' +
      new URLSearchParams({limit:'50',cursor:cursors[kind],archived:String(kind==='archived')}))})));
    if (lostAccess || generation !== listGeneration) return;
    for (const {kind,data} of pages) {
      for (const row of data.items) {
        if (!Array.from(select.options).some(option=>option.value===row.id)) {
          select.append(new Option((kind==='archived'?'Archived · ':'')+row.title, row.id));
        }
      }
      cursors[kind]=data.page.next_cursor || '';
      more[kind]=data.page.has_more;
    }
    $('cmv-more').hidden = !more.active && !more.archived;
    if (selected && Array.from(select.options).some(option => option.value === selected)) select.value = selected;
    if (current) {
      if (Array.from(select.options).some(option => option.value === current.id)) select.value = current.id;
      else clearOpenReview();
    }
  }
  function card(parent, heading, paragraphs) {
    const section = el('section'); section.className='cmv-card';
    section.append(el('h3', heading));
    for (const line of paragraphs) section.append(el('p', line));
    parent.append(section);
    return section;
  }
  function exploreAlternative(data, gap) {
    const form = $('cmv-new');
    form.reset();
    const set = (name, value) => { form.elements.namedItem(name).value = String(value); };
    set('title', (data.title + ' · alternate choice').slice(0, 200));
    for (const [index, suffix] of ['a','b'].entries()) {
      const order = data.model.commitments[index];
      if (!order) continue;
      set(`order_${suffix}_name`, data.labels[order.id] || order.id);
      set(`order_${suffix}_due_at`, inputDate(order.due_at));
      set(`order_${suffix}_material_units`, order.demands.find(part => part.kind === 'material')?.units || 1);
      form.elements.namedItem(`order_${suffix}_uses_capacity`).checked = order.demands.some(part => part.kind === 'capacity');
    }
    const capacity = data.model.lots.find(lot => lot.kind === 'capacity');
    const stock = data.model.lots.find(lot => lot.kind === 'material');
    set('capacity_name', data.labels['work-center'] || 'Work center');
    set('capacity_units', capacity?.units || 1);
    set('material_name', data.labels.material || 'Material');
    set('stock_units', stock?.units || 0);
    set('stock_certainty', stock?.certainty || 'unknown');
    set('option_kind', gap.kind);
    set('option_units', Math.min(gap.remaining_shortfall_units, 1000000));
    // A new choice is a new operator assertion. Never copy its evidence or
    // approval from the earlier review.
    for (const name of ['option_name','option_ready_at','option_expires_at','option_cost_note','basis','review_by']) set(name, '');
    set('option_lead_hours', 0);
    $('cmv-copy-note').hidden = false;
    $('cmv-new-details').open = true;
    form.elements.namedItem('option_name').focus();
    say('The existing figures were copied into a new review. Recheck them, then enter the new choice and its source before saving.');
  }
  function render(data) {
    if (observationDraftOwner && observationDraftOwner !== data.id) resetObservation();
    observationDraftOwner = data.id;
    const select = $('cmv-select');
    const existing = Array.from(select.options).find(option => option.value === data.id);
    const displayTitle = (data.archived ? 'Archived · ' : '') + data.title;
    if (existing) existing.textContent = displayTitle;
    else select.add(new Option(displayTitle, data.id));
    select.value = data.id;
    current = data;
    document.dispatchEvent(new CustomEvent('lightwork:commitment-review', {detail:{review:data}}));
    publish(data.id);
    $('cmv-report').hidden = false;
    $('cmv-report-title').textContent = data.title;
    $('cmv-lifecycle-note').textContent = data.archived ?
      'Archived on '+date(data.retired_at)+'. This saved history is read-only.' :
      data.archive_pending ? 'Finishing this archive. Decisions are closed; the owner can resume below.' :
        'Active review';
    $('cmv-trace-details').hidden = data.archived || data.archive_pending;
    $('cmv-archive-details').hidden = data.archived || !data.owner_can_archive;
    $('cmv-archive-details').querySelector('summary').textContent = data.archive_pending ?
      'Finish archiving this review' : 'Finish and archive this review';
    const assessed = data.assessment;
    const language = {feasible:'Feasible within the reported model',
      unknown:'Uncertain within the reported model',
      infeasible:'Not feasible within the reported model'};
    $('cmv-report-state').textContent = language[assessed.status] || 'Assessment unavailable';
    $('cmv-report-explanation').textContent =
      (data.archived ? 'This assessment is recalculated from the archived reports and is not a current delivery promise. ' : '')+
      'This assessment covers two accepted orders using the capacity and stock entered here. It does not verify actual inventory, supplier commitments, production timing, or an external reservation.';
    const sourceNote = data.sources.length + ' attributed team reports. ' +
      (assessed.stale_source_ids.length ? assessed.stale_source_ids.length + ' source reports need rechecking. Start a new review with current figures.' :
        'Recheck the figures whenever conditions change.');
    $('cmv-source-note').textContent = sourceNote +
      (data.audit_status === 'pending' ? ' The activity receipt is still pending; refresh to verify it was recorded.' : ' The activity receipt is recorded.');
    const components = $('cmv-components'); components.replaceChildren();
    for (const component of assessed.components) {
      const names = component.commitment_ids.map(id => data.labels[id] || id).join(' and ');
      card(components, names, [language[component.status] || component.status,
        component.plans.length ? component.plans.length + ' conditional path available below.' : 'No current conditional path was found in this model.']);
    }
    const gaps = $('cmv-gaps'); gaps.replaceChildren();
    const resourceGaps = data.resource_gaps || [];
    if (data.resource_gap_blocked_by_order_change) {
      card(gaps, 'Order details need rechecking', ['At least one accepted-order report changed or expired. Lightwork cannot calculate its resource gap from those figures. Start a new review with current order details.']);
    }
    if (resourceGaps.length) gaps.append(el('h3', 'Where the reported plan runs short'));
    for (const gap of resourceGaps) {
      const resource = data.labels[gap.key] || (gap.kind === 'capacity' ? 'Work capacity' : 'Material');
      const names = gap.commitment_ids.map(id => data.labels[id] || id).join(' and ');
      const lines = [
        `For ${names}, confirmed reported ${resource} falls short by up to ${gap.confirmed_shortfall_units} units. The first shortfall is at ${date(gap.first_shortfall_at)}.`,
        gap.remaining_shortfall_units ?
          `Even if every still-possible report and recorded choice becomes real on time, this model still needs up to ${gap.remaining_shortfall_units} more ${resource} units. The first remaining shortfall is at ${date(gap.remaining_first_shortfall_at)}.` :
          'The uncertain reports or recorded choice could cover this shortfall, but they must be checked and the actual effect observed before anyone relies on them.',
      ];
      const sources = gap.conditional_source_ids.map(id => id.split(':').slice(-1)[0].replaceAll('-', ' '));
      const choices = gap.option_ids.map(id => data.labels[id] || id);
      if (sources.length) lines.push('Reports to recheck: ' + sources.join(', ') + '.');
      if (choices.length) lines.push('Conditional choices: ' + choices.join(', ') + '. Recording or confirming a choice does not acquire these units.');
      const section = card(gaps, resource, lines);
      if (gap.remaining_shortfall_units && !data.archived && !data.archive_pending) {
        const button = el('button', 'Explore another choice in a new review');
        button.type = 'button'; button.className = 'btn';
        button.addEventListener('click', () => exploreAlternative(data, gap));
        section.append(button);
      }
    }
    if (!resourceGaps.length && !data.resource_gap_blocked_by_order_change && assessed.status === 'infeasible') {
      card(gaps, 'The review window has passed', ['A past delivery time cannot be repaired by adding a hypothetical resource. Start a new review with current commitments and source reports.']);
    }
    const options = $('cmv-options'); options.replaceChildren();
    const option = data.model.options[0];
    const allPaths = assessed.components.flatMap(item => item.plans).filter(item => item.option_ids.includes(option.id));
    const paths = allPaths.filter(item => item.conditional_status === 'feasible' &&
      assessed.evaluated_at < item.latest_safe_bundle_decision_at);
    const optionCard = card(options, data.labels[option.id] || 'Conditional choice', [
      'Reported additional ' + option.units + ' ' + (option.kind === 'capacity' ? 'work' : 'material') + ' units. ' +
        'Ready no earlier than ' + date(option.ready_at) + '; choice expires ' + date(option.expires_at) + '.',
      option.cost_note ? 'Cost or condition: ' + option.cost_note : 'No cost or condition was entered.',
      option.owner_confirmation ? 'The owner recorded intent to use this choice. That did not order, reserve, or receive anything.' :
        'The owner has not confirmed this choice. Confirming records intent only; it does not reserve or order anything.',
      paths.length ? 'The model’s latest decision time is before ' + date(paths[0].latest_safe_bundle_decision_at) +
        '. Recheck sources before acting; changes can make this earlier.' :
        allPaths.length ? 'A possible path remains uncertain. Confirm the missing reports before deciding.' :
          'No currently actionable path uses this choice.'
    ]);
    if (data.audit_status === 'recorded' && !option.owner_confirmation && paths.length && data.owner_can_confirm) {
      const button = el('button', 'Confirm this choice for review'); button.type='button'; button.className='btn';
      button.addEventListener('click', () => confirm('option', '', option.id)); optionCard.append(button);
    }
    const proposals = $('cmv-proposals'); proposals.replaceChildren();
    if (data.proposals.length) proposals.append(el('h3', 'Suggested shared work'));
    for (const proposal of data.proposals) {
      const section = card(proposals, 'Possible shared work center', [
        'Your team reported ' + (data.labels[proposal.left_id] || proposal.left_id) + ' running while ' +
          (data.labels[proposal.right_id] || proposal.right_id) + ' waited. This suggests both need ' +
          (data.labels[proposal.resource_key] || 'the work center') + '. Review the observation before adding that dependency to this model.',
        'Only the review owner can confirm. Confirmation updates this model and reassesses affected work; it does not change either customer order.'
      ]);
      if (data.audit_status === 'recorded' && data.owner_can_confirm) {
        const button = el('button','Confirm shared work in this model'); button.type='button'; button.className='btn';
        button.addEventListener('click', () => confirm('dependency', proposal.id, 'conditional-option')); section.append(button);
      }
    }
    const sources = $('cmv-sources'); sources.replaceChildren();
    for (const source of data.sources) {
      const title = source.source_id.split(':').slice(-1)[0].replaceAll('-', ' ');
      card(sources, title, ['Entered by ' + source.entered_by + ' on ' + date(source.entered_at) + '.',
        'Basis: ' + source.basis, 'Check again by ' + date(source.review_by) + '.',
        assessed.stale_source_ids.includes(source.source_id) ? 'This report is no longer current.' : 'Current within the entered review window.']);
    }
    const running = $('cmv-trace').elements.running_order, blocked = $('cmv-trace').elements.blocked_order;
    for (const select of [running,blocked]) {
      const previous = select.value;
      select.replaceChildren(new Option('Choose an order',''));
      for (const item of data.model.commitments) select.append(new Option(data.labels[item.id] || item.id,item.id));
      select.value = previous;
    }
    if (busy || lostAccess) lock(busy);
  }
  async function open(id) {
    const select = $('cmv-select');
    if (current && (id !== current.id || select.value !== current.id)) clearOpenReview(true);
    if (!id) { say('Choose a saved review first.'); return; }
    if (observationDraftOwner && observationDraftOwner !== id) resetObservation();
    if (!Array.from(select.options).some(option => option.value === id)) {
      select.add(new Option('Opening review', id));
    }
    select.value = id;
    const generation = ++openGeneration;
    const data = await request('/' + encodeURIComponent(id));
    if (lostAccess || generation !== openGeneration || select.value !== id) return;
    render(data);
    say('Current assessment refreshed.');
  }
  async function confirm(kind, proposal, option) {
    const review = activeReview();
    if (!review || !review.owner_can_confirm) return;
    if (review.audit_status !== 'recorded') { say('The activity receipt is still pending. Refresh this review before deciding.'); return; }
    const selectedId = review.id, selectedRevision = review.revision;
    const scope = 'confirm:' + selectedId + ':' + kind + ':' + (proposal || option);
    await change(scope, async () => {
      const body = {expected_revision:selectedRevision,kind,proposal_id:proposal,option_id:option};
      body.operation_id = uniqueOperation(scope,body);
      await request('/' + encodeURIComponent(selectedId) + '/confirm','POST',body);
      await open(selectedId);
    });
  }
  function reviewForm(form) {
    const d = new FormData(form);
    const body = Object.fromEntries(d.entries());
    for (const field of ['order_a_due_at','order_b_due_at','option_ready_at','option_expires_at','review_by']) body[field]=local(d.get(field));
    for (const field of ['order_a_material_units','order_b_material_units','capacity_units','stock_units','option_units']) body[field]=number(d,field);
    body.order_a_uses_capacity=d.has('order_a_uses_capacity'); body.order_b_uses_capacity=d.has('order_b_uses_capacity');
    body.option_lead_seconds=number(d,'option_lead_hours')*3600; delete body.option_lead_hours;
    return body;
  }
  $('cmv-new').addEventListener('submit', event => {
    event.preventDefault();
    let draft;
    try { draft=reviewForm(event.currentTarget); }
    catch (error) { say(error.message); return; }
    change('create', async () => {
      const body={...draft}; body.operation_id=uniqueOperation('create',body);
      const result=await request('','POST',body);
      await list(); await open(result.id); $('cmv-new-details').open=false; $('cmv-copy-note').hidden=true;
    });
  });
  $('cmv-trace').addEventListener('submit', event => {
    event.preventDefault();
    const review = activeReview();
    if (!review) return;
    if (review.archived || review.archive_pending) {
      say('This review is closed to changes. Open its saved history instead.'); return;
    }
    if (review.audit_status !== 'recorded') { say('The activity receipt is still pending. Refresh this review before recording more work.'); return; }
    const selectedId=review.id, selectedRevision=review.revision;
    const scope='trace:' + selectedId;
    let draft;
    try {
      const d=new FormData(event.currentTarget);
      draft={expected_revision:selectedRevision,running_order:d.get('running_order'),blocked_order:d.get('blocked_order'),
        started_at:local(d.get('started_at')),ended_at:local(d.get('ended_at')),
        observed_at:local(d.get('observed_at')),review_by:local(d.get('review_by')),basis:d.get('basis')};
    } catch (error) { say(error.message); return; }
    change(scope, async () => {
      const body={...draft};
      body.operation_id=uniqueOperation(scope,body);
      await request('/'+encodeURIComponent(selectedId)+'/observations','POST',body);
      await open(selectedId);
    });
  });
  $('cmv-archive').addEventListener('submit', event => {
    event.preventDefault();
    const review = activeReview();
    if (!review || !review.owner_can_archive) return;
    if (!$('cmv-archive').elements.confirm_finished.checked) {
      say('Confirm that this review is finished before archiving it.'); return;
    }
    const id=review.id, revision=review.revision, scope='archive:'+id;
    change(scope, async () => {
      const body={expected_revision:revision,confirm_finished:true};
      body.operation_id=uniqueOperation(scope,body);
      await request('/'+encodeURIComponent(id)+'/archive','POST',body);
      await list(); await open(id);
      $('cmv-archive-details').open=false;
    }, 'Review archived. Its saved history remains available, and the active slot is free.');
  });
  $('cmv-select').addEventListener('change', () => {
    clearOpenReview(true);
    say($('cmv-select').value ?
      'Open the selected review to see its current assessment.' : 'Choose a saved review to open.');
  });
  $('cmv-open').addEventListener('click',()=>open($('cmv-select').value).catch(error=>say(error.message)));
  $('cmv-reassess').addEventListener('click',()=>{const review=activeReview(); if(review) open(review.id).catch(error=>say(error.message));});
  $('cmv-refresh').addEventListener('click',()=>list().then(()=>say('Saved reviews refreshed.')).catch(error=>say(error.message)));
  $('cmv-more').addEventListener('click',()=>list(false).catch(error=>say(error.message)));
  list().then(() => {
    const selected = new URLSearchParams(window.location.search).get('review');
    if (selected && /^CMV-[a-f0-9]{48}$/.test(selected)) return open(selected);
  }).catch(error=>say(error.message));
}());
