/* Billing page: what a plan includes, and Stripe billing (status, preview, send). */
(function () {
  'use strict';
  var BASE = '/api/v1/admin/billing-ops';
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
    return window.mvFetchJSON(path, {method: method || 'GET', cache: 'no-store', body: body, timeout: 30000});
  }
  function facts(rows) {
    var dl = el('dl');
    rows.forEach(function (row) { dl.appendChild(el('dt', null, row.label)); dl.appendChild(el('dd', null, row.value)); });
    return dl;
  }

  var planForm = $('plan-form');
  if (planForm) planForm.addEventListener('submit', async function (event) {
    event.preventDefault();
    var out = $('plan-out'), msg = $('plan-msg');
    out.textContent = '';
    msg.textContent = 'Reading the plan…';
    try {
      var data = await call(BASE + '/plan?' + new URLSearchParams({workspace: planForm.elements.workspace.value}).toString());
      out.appendChild(facts([
        {label: 'Plan', value: data.plan},
        {label: 'Includes', value: data.features.join(', ') || 'Nothing extra'},
        {label: 'Daily spending limit', value: data.daily_limit},
        {label: 'Tasks at the same time', value: data.tasks_at_once}
      ]));
      msg.textContent = '';
    } catch (failure) { msg.textContent = await failText(failure, 'read the plan'); }
  });

  var statusRun = $('stripe-status-run');
  if (statusRun) statusRun.addEventListener('click', async function () {
    var out = $('stripe-status-out');
    out.textContent = '';
    try {
      var data = await call(BASE + '/stripe');
      out.appendChild(el('p', null, data.summary));
      out.appendChild(facts(data.facts));
    } catch (failure) { out.appendChild(el('p', null, await failText(failure, 'check Stripe billing'))); }
  });

  var form = $('stripe-form');
  if (!form) return;
  var sync = $('stripe-sync'), review = null, generation = 0, busy = false;
  var recover = el('button', 'btn btn--ghost', 'Read retained sync receipt');
  recover.type = 'button'; sync.after(recover);
  function fields() {
    var data = {get: function (name) { var control = form.elements.namedItem(name); return control ? control.value : ''; }};
    return {workspace: String(data.get('workspace') || '').trim(),
      since: String(data.get('since') || '').trim() || null,
      until: String(data.get('until') || '').trim() || null,
      markup: Number(data.get('markup') || 0), minimum: Number(data.get('minimum') || 0)};
  }
  function key() { return JSON.stringify(fields()); }
  function lock(value) {
    busy = value;
    Array.from(form.elements).forEach(function (control) { control.disabled = value; });
    sync.disabled = value;
  }
  function invalidate() {
    review = null; ++generation; sync.hidden = true;
    $('stripe-msg').textContent = 'Fields changed. Review the exact charge again before sending.';
  }
  form.addEventListener('input', invalidate);
  form.addEventListener('change', invalidate);
  function renderReceipt(data) {
    var out = $('stripe-out'); out.textContent = '';
    out.appendChild(el('p', null, data.message));
    out.appendChild(el('p', 'muted', 'Receipt ' + data.attempt + ' • ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(data.updated_at) : new Date(data.updated_at * 1000).toLocaleString())));
    out.appendChild(facts(Object.keys(data.stages).map(function (name) {
      return {label: name, value: data.stages[name].state.replace(/_/g, ' ')};
    })));
    if (data.audit_pending) out.appendChild(el('p', null, 'The audit record is still pending. Do not treat this as fully acknowledged.'));
    var details = el('details'); details.appendChild(el('summary', null, 'Retained provider dispatch receipts'));
    details.appendChild(el('pre', null, JSON.stringify(data.dispatches, null, 2))); out.appendChild(details);
    var read = el('a', 'btn', 'Open receipt'); read.href = data.receipt_href; out.appendChild(read);
    var stripe = el('a', 'btn btn--ghost', 'Reconcile in Stripe'); stripe.href = data.reconciliation_href;
    stripe.target = '_blank'; stripe.rel = 'noopener noreferrer'; out.appendChild(stripe);
    $('stripe-msg').textContent = data.state === 'complete' ? 'Requested stages confirmed; payment is separate.' : 'Outcome incomplete or unknown. No automatic retry will occur.';
  }
  recover.addEventListener('click', async function () {
    if (busy) return;
    var selected = key(), request = ++generation;
    try {
      var data = await call(BASE + '/stripe/receipt?' + new URLSearchParams({workspace: fields().workspace}));
      if (selected !== key() || request !== generation) return;
      if (data.current) renderReceipt(data.current);
      else $('stripe-msg').textContent = 'No retained sync receipt exists for this workspace in this context.';
    } catch (failure) { if (request === generation) $('stripe-msg').textContent = await failText(failure, 'read the retained receipt'); }
  });
  form.addEventListener('submit', async function (event) {
    event.preventDefault(); if (busy) return;
    var selected = key(), request = ++generation, out = $('stripe-out'), msg = $('stripe-msg');
    out.textContent = ''; sync.hidden = true; review = null;
    msg.textContent = 'Preparing the exact billing review. No provider call is made by this preview.';
    var query = fields(); Object.keys(query).forEach(function (name) { if (query[name] === null) delete query[name]; });
    try {
      var data = await call(BASE + '/stripe/preview?' + new URLSearchParams(query));
      if (request !== generation || selected !== key()) return;
      review = {id: data.review_id, sha256: data.sha256, fields: selected, expires: data.review_expires};
      out.appendChild(el('p', null, data.summary));
      out.appendChild(facts([{label: 'Workspace', value: data.workspace}, {label: 'Plan', value: data.plan},
        {label: 'Reviewed content fingerprint', value: data.sha256},
        {label: 'Review expires', value: (window.mvTimeAbsolute ? window.mvTimeAbsolute(data.review_expires) : new Date(data.review_expires * 1000).toLocaleString())}]));
      var exact = el('details'); exact.appendChild(el('summary', null, 'Exact reviewed period, rates and line items'));
      exact.appendChild(el('pre', null, JSON.stringify({fields: fields(), snapshot: data.snapshot}, null, 2))); out.appendChild(exact);
      if (data.resume) out.appendChild(el('p', null, 'This resumes the retained attempt with its original rated contents and invoice identity. Confirmed stages are retained; unknown stages use native reconciliation and idempotency protections.'));
      if (data.ledger_changed_since_dispatch) out.appendChild(el('p', null, 'The local ledger has changed since the original dispatch. This review retains the exact original rated invoice and does not add newer usage.'));
      sync.textContent = data.resume ? 'Review and resume retained sync' : 'Send reviewed change to Stripe';
      sync.hidden = !data.can_sync; msg.textContent = '';
    } catch (failure) { if (request === generation) msg.textContent = await failText(failure, 'prepare billing review'); }
  });
  sync.addEventListener('click', async function () {
    if (busy || !review || review.fields !== key() || Date.now() >= review.expires * 1000) { invalidate(); return; }
    var approved = review, selected = key(), body = fields();
    var ok = window.mvConfirm ? await window.mvConfirm('Send exactly this reviewed billing change to Stripe? It may create or update the subscription and send the reviewed usage items.', {okText: 'Send reviewed change'}) : false;
    if (!ok || review !== approved || selected !== key()) return;
    Object.assign(body, {confirm: true, review_id: approved.id, sha256: approved.sha256});
    lock(true); sync.hidden = true;
    $('stripe-msg').textContent = 'Sending the reviewed change. Stage receipts are retained before provider dispatch.';
    try {
      var data = await call(BASE + '/stripe/sync', 'POST', body);
      if (selected === key()) renderReceipt(data);
    } catch (failure) {
      $('stripe-msg').textContent = (await failText(failure, 'finish the sync')) + ' The provider may have changed. Read the retained receipt before preparing an explicit retry.';
    } finally { review = null; lock(false); }
  });
  window.addEventListener('pagehide', function () { review = null; ++generation; });
})();
