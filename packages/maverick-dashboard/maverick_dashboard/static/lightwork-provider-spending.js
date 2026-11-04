/* Provider accounting: explicit review, no provider dispatch or automatic retry. */
(function () {
  'use strict';
  const root = document.getElementById('provider-spending');
  if (!root) return;
  const el = id => document.getElementById(id);
  const base = '/api/v1/recovery/provider-spending';
  let state = null, review = null, imported = null, holds = [], totals = [], busy = false, offset = 0, openReviews = [];
  const message = text => { el('spend-status').textContent = text; };
  // The shared money format ("$1,234.56", "under $0.01"); this recovery-shell
  // page loads without lightwork-ui.js, so mvMoney is not available here.
  const dollars = value => value > 0 && value < 0.005 ? 'under $0.01'
    : new Intl.NumberFormat('en-US', {style: 'currency', currency: 'USD'}).format(value);
  const labels = {};
  try { JSON.parse(root.dataset.providers || '[]').forEach(p => { labels[p.name] = p.label; }); } catch (_) { /* unrendered template */ }
  const providerLabel = name => labels[name] || (window.mvHuman ? window.mvHuman(name) : String(name));
  // The shared date format through LightworkI18n (this page has no lightwork-ui.js).
  const i18n = window.LightworkI18n;
  const when = seconds => { try { return i18n ? i18n.formatDate(seconds) : new Date(seconds * 1000).toLocaleString(); } catch (_) { return ''; } };
  const periodLabel = value => {
    if (/^\d{4}-\d{2}$/.test(value || '')) return i18n ? i18n.formatDate(value + '-01', {year: 'numeric', month: 'long'}) : new Date(value + '-01T00:00:00').toLocaleDateString(undefined, {year: 'numeric', month: 'long'});
    if (/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return i18n ? i18n.formatDate(value) : new Date(value + 'T00:00:00').toLocaleDateString();
    return value || '';
  };
  function providerOptions(select, chosen, withAll) {
    const names = new Set(Object.keys(labels));
    if (state) state.providers.forEach(row => names.add(row.provider));
    if (chosen) names.add(chosen);
    select.replaceChildren();
    if (withAll) { const all = document.createElement('option'); all.value = ''; all.textContent = 'All providers'; select.append(all); }
    [...names].sort((a, b) => providerLabel(a).localeCompare(providerLabel(b))).forEach(name => {
      const option = document.createElement('option'); option.value = name; option.textContent = providerLabel(name); select.append(option);
    });
    select.value = chosen || '';
  }
  function chosenPeriod() {
    return el('spend-period-kind').value === 'day' ? el('spend-period-day').value.trim() : el('spend-period').value.trim();
  }
  el('spend-period-kind').addEventListener('change', () => {
    const day = el('spend-period-kind').value === 'day';
    root.querySelectorAll('[data-period-for]').forEach(node => { node.hidden = node.dataset.periodFor !== (day ? 'day' : 'month'); });
  });
  function retainedReview(value) {
    if (!state) return null;
    try {
      const key = 'lightwork-spending-review:' + state.context;
      if (value === null) sessionStorage.removeItem(key);
      else if (value !== undefined) sessionStorage.setItem(key, value);
      return sessionStorage.getItem(key);
    } catch (_) { return null; }
  }
  function clear() {
    state = review = imported = null;
    holds = []; totals = [];
    ['spend-balances', 'spend-hold', 'spend-totals', 'spend-review-detail', 'spend-page', 'spend-export-date'].forEach(id => el(id).replaceChildren());
    ['spend-evidence', 'spend-actual', 'spend-repair-evidence', 'spend-import'].forEach(id => { el(id).value = ''; });
    el('spend-confirm').checked = false;
    el('spend-receipts-complete').checked = false;
    el('spend-review').hidden = el('spend-repair-form').hidden = true;
  }
  function controls() {
    root.querySelectorAll('button,input,select,textarea').forEach(node => { node.disabled = busy || !state; });
    el('spend-refresh').disabled = busy;
    el('spend-period-kind').disabled = el('spend-period').disabled = el('spend-period-day').disabled = el('spend-provider').disabled = busy;
    el('spend-load-period').disabled = busy;
    el('spend-open-review').disabled = busy || !state || !el('spend-review-pick').value;
    el('spend-export').disabled = busy || !state || !state.available || state.shared
      || state.ledger_health?.single_file_copy_available === false;
    ['spend-import', 'spend-inspect'].forEach(id => { el(id).disabled = busy || !state || !state.isolated || state.shared; });
    el('spend-hold-form').querySelectorAll('input,select,textarea,button').forEach(node => { node.disabled = busy || !holds.length; });
    el('spend-apply').disabled = busy || !state || !review || !el('spend-confirm').checked;
    el('spend-prev').disabled = busy || !state || !state.offset;
    el('spend-next').disabled = busy || !state || !state.providers.some(row => row.holds_next_offset !== null && row.holds_next_offset !== undefined);
  }
  async function request(path, options = {}) {
    const headers = {...(options.headers || {})};
    if (state) {
      headers['X-Lightwork-Spending-Context'] = state.context;
      headers['X-Lightwork-Expected-Tenant'] = state.expected_tenant;
    }
    const response = await fetch(base + path, {...options, headers, credentials: 'same-origin'});
    if ([401, 403, 409].includes(response.status)) {
      retainedReview(null); clear();
    }
    if (!response.ok) {
      let detail = '';
      try { detail = String((await response.clone().json()).detail || ''); } catch (_) { /* non-JSON response */ }
      throw new Error(response.status === 409
        ? (detail || 'Something changed since you loaded this page. Refresh and try again.')
        : (window.mvErrorText ? window.mvErrorText(response, 'finish this step') : 'This step could not be completed. Refresh and try again.'));
    }
    return response;
  }
  async function json(path, body) {
    return (await request(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})).json();
  }
  async function run(action) {
    if (busy) return;
    busy = true; controls();
    try { await action(); } catch (error) { message(error && error.message ? error.message : 'This step could not be completed. Try again.'); }
    finally { busy = false; controls(); }
  }
  function paragraph(parent, text) { const p = document.createElement('p'); p.textContent = text; parent.append(p); }
  async function refresh() {
    const period = chosenPeriod();
    const provider = el('spend-provider').value.trim();
    if (period && !/^[0-9]{4}-[0-9]{2}(-[0-9]{2})?$/.test(period)) throw new Error('Choose a month or a day.');
    clear();
    const params = new URLSearchParams({offset: String(offset), limit: '100'});
    if (period) params.set('period', period);
    if (provider) params.set('provider', provider);
    const response = await request('?' + params.toString());
    state = await response.json();
    providerOptions(el('spend-provider'), provider, true);
    const health = state.ledger_health || {};
    el('spend-health').textContent = (health.message || 'Spending record health could not be checked. Refresh the page to check again.')
      + (Number.isInteger(health.receipt_count) ? ` ${health.receipt_count.toLocaleString()} provider requests recorded.` : '')
      + (Number.isInteger(health.unresolved_count) && health.unresolved_count
        ? ` ${health.unresolved_count.toLocaleString()} request${health.unresolved_count === 1 ? '' : 's'} still need a final cost.` : '')
      + (health.single_file_copy_available === false
        ? ' This history needs a full Workspace recovery backup; the smaller checked copy is unavailable.' : '');
    const practiceLine = document.getElementById('spend-practice');
    if (practiceLine) { practiceLine.textContent = state.practice ? state.practice.text : ''; practiceLine.hidden = !state.practice; }
    message(state.available ? 'Spending is up to date.' : 'Spending records can\'t be read safely right now. Requests to providers with a limit are paused; no balance was reset.');
    if (!state.providers.length && state.available) {
      paragraph(el('spend-balances'), 'No spending limits are set for any provider. Set one in Spending limits to stop a provider at a cap.');
      const link = document.createElement('a'); link.className = 'btn btn--primary'; link.href = '/spending-limits'; link.textContent = 'Set spending limits';
      el('spend-balances').append(link);
    }
    state.providers.forEach(row => {
      const name = providerLabel(row.provider);
      paragraph(el('spend-balances'), `${name} · ${periodLabel(state.period)}: ${dollars(row.spent)} spent, ${dollars(row.reserved)} set aside. ` + (row.cap === null ? 'No limit is set for this provider.' : `${dollars(row.remaining)} left under today's ${dollars(row.cap)} limit.`));
      if (row.holds_total) paragraph(el('spend-page'), `${name}: showing ${row.holds.length} of ${row.holds_total} unresolved amounts set aside in this period.`);
      row.holds.forEach((hold, index) => {
        const choice = {...hold, provider: row.provider, period: state.period};
        const option = document.createElement('option'); option.value = String(holds.length);
        option.textContent = `${name} · request ${state.offset + index + 1} · about ${dollars(hold.projected)} · ${hold.state === 'unknown' ? 'final cost unknown' : 'may still be running'}`;
        holds.push(choice); el('spend-hold').append(option);
      });
    });
    if (!holds.length) paragraph(el('spend-page'), 'Nothing is waiting to be settled. Holds appear here while a task is still spending.');
    await loadReviews();
    const retained = retainedReview();
    if (retained) {
      const previous = await (await request('/review/' + encodeURIComponent(retained))).json();
      if (previous.state === 'completed') retainedReview(null);
      else showReview(previous);
    }
  }
  function reviewTitle(value) {
    return value.kind === 'hold'
      ? `Settle ${providerLabel(value.provider)} · ${periodLabel(value.period)} at ${dollars(value.actual)}`
      : `Repair spending records (${(value.totals || []).length} total${(value.totals || []).length === 1 ? '' : 's'})`;
  }
  async function loadReviews() {
    const pick = el('spend-review-pick');
    pick.replaceChildren();
    try { openReviews = (await (await request('/reviews')).json()).reviews || []; } catch (_) { openReviews = []; }
    if (!openReviews.length) {
      const none = document.createElement('option'); none.value = ''; none.textContent = 'None waiting'; pick.append(none);
    }
    openReviews.forEach(value => {
      const option = document.createElement('option'); option.value = value.id;
      option.textContent = reviewTitle(value) + (value.state === 'applying' ? ' (interrupted)' : '');
      pick.append(option);
    });
  }
  function showReview(value) {
    review = value; el('spend-confirm').checked = false;
    retainedReview(value.id);
    el('spend-review-detail').replaceChildren();
    if (value.kind === 'hold') paragraph(el('spend-review-detail'), `${providerLabel(value.provider)} · ${periodLabel(value.period)}: settle this request at ${dollars(value.actual)}.`);
    else value.totals.forEach(row => paragraph(el('spend-review-detail'), `${providerLabel(row.provider)} · ${periodLabel(row.period)}: ${dollars(row.confirmed)} confirmed spending. Money set aside stays separate.`));
    paragraph(el('spend-review-detail'), 'Your note: ' + value.evidence);
    if (value.kind === 'repair') paragraph(el('spend-review-detail'), `Final receipts checked for every request since ${when(value.exported_at)}, including other providers and periods.`);
    el('spend-review').hidden = false;
    message(value.state === 'applying' ? 'This correction was interrupted. Confirm again to finish it; no request to a provider will be repeated.' : 'Check the amounts, then confirm. Nothing has changed yet.');
  }
  async function download(path, name, method = 'POST') {
    const response = await request(path, {method});
    const url = URL.createObjectURL(await response.blob());
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    message(method === 'POST' ? 'Checked copy downloaded. Keep it apart from its recovery key.' : 'Details for support downloaded.');
  }
  el('spend-refresh').addEventListener('click', () => { offset = 0; run(refresh); });
  el('spend-load-period').addEventListener('click', () => { offset = 0; run(refresh); });
  el('spend-prev').addEventListener('click', () => { offset = Math.max(0, offset - 100); run(refresh); });
  el('spend-next').addEventListener('click', () => { offset += 100; run(refresh); });
  el('spend-export').addEventListener('click', () => run(() => download('/export', 'Lightwork-provider-accounting.json')));
  el('spend-diagnostics').addEventListener('click', () => run(() => download('/diagnostics', 'Lightwork-spending-diagnostics.json', 'GET')));
  el('spend-confirm').addEventListener('change', controls);
  el('spend-review-pick').addEventListener('change', controls);
  el('spend-open-review').addEventListener('click', () => run(async () => {
    const identifier = el('spend-review-pick').value;
    if (!identifier) throw new Error('Choose a correction from the list.');
    const selected = await (await request('/review/' + encodeURIComponent(identifier))).json();
    if (selected.state === 'completed') { retainedReview(null); review = null; el('spend-review').hidden = true; message('This correction is already finished. Nothing was repeated.'); }
    else showReview(selected);
  }));
  el('spend-hold-form').addEventListener('submit', event => {
    event.preventDefault();
    if (!el('spend-hold-form').reportValidity()) { message('Complete the final cost and receipt details.'); return; }
    run(async () => {
      const held = holds[Number(el('spend-hold').value)];
      if (!held) throw new Error('Choose a request from the list.');
      showReview(await json('/hold-review', {provider: held.provider, period: held.period, receipt: held.id,
        actual: Number(el('spend-actual').value), evidence: el('spend-evidence').value}));
    });
  });
  function appendTotal(row, index) {
    function field(id, text, control) {
      const label = document.createElement('label'); label.htmlFor = id; label.textContent = text;
      control.id = id; el('spend-totals').append(label, control); return control;
    }
    if (row.additional) {
      const provider = field(`spend-provider-${index}`, 'Provider', document.createElement('select'));
      provider.className = 'select'; provider.required = true; providerOptions(provider, '', false);
      const kind = field(`spend-kind-${index}`, 'Period', document.createElement('select'));
      kind.className = 'select';
      [['month', 'A whole month'], ['day', 'One day']].forEach(([value, text]) => { const o = document.createElement('option'); o.value = value; o.textContent = text; kind.append(o); });
      const month = field(`spend-period-${index}`, 'Month', document.createElement('input'));
      month.type = 'month'; month.className = 'input';
      const day = field(`spend-day-${index}`, 'Day', document.createElement('input'));
      day.type = 'date'; day.className = 'input';
      const sync = () => { const isDay = kind.value === 'day'; month.required = !isDay; day.required = isDay;
        month.previousSibling.hidden = month.hidden = isDay; day.previousSibling.hidden = day.hidden = !isDay; };
      kind.addEventListener('change', sync); sync();
    }
    const label = document.createElement('label'); label.htmlFor = `spend-total-${index}`;
    label.textContent = `${row.additional ? 'Confirmed total for this provider and period' : providerLabel(row.provider) + ' · ' + periodLabel(row.period) + ': confirmed total'} (at least ${dollars(row.confirmed)}; ${dollars(row.reserved)} set aside separately)`;
    const input = document.createElement('input'); input.id = label.htmlFor; input.type = 'number'; input.step = 'any'; input.min = String(row.confirmed); input.required = true; input.className = 'input';
    el('spend-totals').append(label, input);
  }
  el('spend-add-total').addEventListener('click', () => {
    if (!imported || busy || totals.length >= 500) return;
    totals.push({additional: true, confirmed: 0, reserved: 0}); appendTotal(totals[totals.length - 1], totals.length - 1);
  });
  el('spend-inspect').addEventListener('click', () => run(async () => {
    const file = el('spend-import').files[0];
    if (!file || file.size > 16 * 1024 * 1024) throw new Error('Choose a checked copy file of 16 MB or less.');
    imported = await (await request('/import', {method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: file})).json();
    totals = imported.totals; el('spend-totals').replaceChildren();
    totals.forEach(appendTotal);
    el('spend-receipts-complete').checked = false;
    el('spend-export-date').textContent = 'This copy was made ' + when(imported.exported_at) + '. Include every request made since then.';
    el('spend-repair-form').hidden = false;
    message('The copy checks out. Enter every confirmed total from final receipts. Nothing has changed yet.');
  }));
  el('spend-repair-form').addEventListener('submit', event => {
    event.preventDefault();
    if (!el('spend-repair-form').reportValidity()) { message('Fill in every total and tick the receipts box.'); return; }
    run(async () => {
      if (!imported) throw new Error('Choose and check the copy first.');
      showReview(await json('/repair-review', {imported: imported.id,
        totals: totals.map((row, index) => ({provider: row.additional ? el(`spend-provider-${index}`).value.trim() : row.provider,
          period: row.additional ? (el(`spend-kind-${index}`).value === 'day' ? el(`spend-day-${index}`).value : el(`spend-period-${index}`).value).trim() : row.period,
          confirmed: Number(el(`spend-total-${index}`).value)})),
        evidence: el('spend-repair-evidence').value, receipts_complete: el('spend-receipts-complete').checked}));
    });
  });
  el('spend-apply').addEventListener('click', () => run(async () => {
    if (!review || !el('spend-confirm').checked) throw new Error('Tick the box to confirm the correction.');
    const result = await json('/apply', {review: review.id, confirm: true});
    if (result.state !== 'completed') throw new Error('The correction was not confirmed. Refresh and open it again from Unfinished corrections.');
    retainedReview(null);
    await refresh(); message('Correction completed. Other amounts set aside were kept, and no request was repeated.');
  }));
  run(refresh);
})();
