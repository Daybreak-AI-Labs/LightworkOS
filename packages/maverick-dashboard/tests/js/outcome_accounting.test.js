'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const script = fs.readFileSync(path.resolve(
  __dirname, '../../maverick_dashboard/static/lightwork-outcome-accounting.js',
), 'utf8');
const digest = character => character.repeat(64);
const settle = async () => { for (let index = 0; index < 6; index += 1) await new Promise(resolve => setImmediate(resolve)); };

function costSummary(changes = {}) {
  const summary = {
    complete: true, coverage_complete: true, attempt_states_complete: true,
    settlement_status: 'observed', known_totals: {USD: '1'},
    aggregate_overflow_currencies: [], unknown_event_count: 0,
    additive_unknown_event_count: 0,
    failed_attempt_count: 0, failed_attempt_event_count: 0,
    budget_overrun_count: 0, informational_event_count: 0,
    coverage_event_count: 0, additive_event_count: 1, event_count: 1,
    superseded_event_count: 0, authenticated_provider_invoice_count: 0,
    local_signed_receipt_count: 0, reconciled_reservation_count: 0,
    display: 'USD 1', ...changes,
  };
  if (!Object.hasOwn(changes, 'additive_unknown_event_count')) {
    summary.additive_unknown_event_count = summary.unknown_event_count;
  }
  if (!Object.hasOwn(changes, 'additive_event_count')) {
    summary.additive_event_count = summary.event_count -
      summary.informational_event_count - summary.coverage_event_count;
  }
  return summary;
}

function record(index, changes = {}) {
  const base = {
    id: 'OAC-record-' + index, revision: 2, admission_id: 'admission-' + index,
    work_item_id: 'work-' + index, owner_id: 'user:alice',
    acceptance_contract_ref: 'contract:' + index, admitted_at: 1788880000 + index,
    disposition: 'active',
    technical_outcome: {status: 'unresolved', reason: 'authoritative_readback_missing_or_expired'},
    business_outcome: {status: 'unresolved', reason: 'current_human_decision_missing'},
    evidence_version: digest('a'), observation_count: 0, decision_count: 0,
    disposition_count: 0, costs: costSummary(),
  };
  return {...base, ...changes, costs: changes.costs || base.costs};
}

function categories(records) {
  const result = {accepted: 0, rejected: 0, failed: 0, cancelled: 0, unresolved: 0};
  records.forEach(row => {
    const category = row.disposition === 'cancelled' ? 'cancelled'
      : row.disposition === 'failed' || row.technical_outcome.status === 'failed' ? 'failed'
      : row.business_outcome.status === 'accepted' ? 'accepted'
      : row.business_outcome.status === 'rejected' ? 'rejected' : 'unresolved';
    result[category] += 1;
  });
  return result;
}

function defaultRecords() {
  const rows = Array.from({length: 10}, (_, index) => record(index));
  rows[0].business_outcome = {status: 'accepted', reason: 'current_human_decision'};
  rows[1].business_outcome = {status: 'accepted', reason: 'current_human_decision'};
  rows[2].business_outcome = {status: 'rejected', reason: 'current_human_decision'};
  rows[3].technical_outcome = {status: 'failed', reason: 'authoritative_readback_contradicts_intent'};
  rows[4].disposition = 'failed';
  rows[5].disposition = 'cancelled';
  rows[6].disposition = 'cancelled';
  for (let index = 0; index < 4; index += 1) {
    rows[index].costs = costSummary({
      complete: false, coverage_complete: false, settlement_status: 'incomplete',
      known_totals: {}, unknown_event_count: 1, display: 'Total incomplete.',
      failed_attempt_count: index < 3 ? 1 : 0,
      failed_attempt_event_count: index < 3 ? 1 : 0,
    });
  }
  return rows;
}

function payload(changes = {}) {
  const records = changes.records || defaultRecords();
  const overflow = (changes.costs && changes.costs.aggregate_overflow_currencies) || [];
  const baseCosts = {
    known_totals: {USD: '12.50'}, aggregate_overflow_currencies: overflow,
    totals_complete: overflow.length === 0,
    incomplete_records: records.filter(row => !row.costs.complete).length + (overflow.length ? 1 : 0),
    failed_attempts: records.reduce((total, row) => total + row.costs.failed_attempt_count, 0),
    basis: 'all admitted work in this scope; unknown cost is not zero',
  };
  const basePage = {
    limit: 100, cursor: null, has_more: false, next_cursor: null,
    scope_complete: true, scanned_records: records.length,
  };
  return {
    schema: 'lightwork.outcome-accounting-portfolio.v1', context: 'alice',
    admitted: records.length, reconciles: true, categories: categories(records), records,
    costs: {...baseCosts, ...(changes.costs || {})},
    page: {...basePage, ...(changes.page || {})},
    ...Object.fromEntries(Object.entries(changes).filter(([key]) => !['records', 'costs', 'page'].includes(key))),
  };
}

function costEvent(index, changes = {}) {
  return {
    id: 'COST-event-' + index, category: 'inference', attempt_state: 'succeeded',
    basis: 'observed', aggregation: 'additive', coverage: 'partial',
    attempt_ref: 'attempt:' + index, budget_state: 'within_limit',
    source_assurance: 'application_observation', evidence_ref: null,
    evidence_sha256: null, verification_authority: null,
    budget_reconciliation: null, pricing_evidence: null, amount: '1', currency: 'USD',
    quantity: null, unit: null, unknown_reason: null, source_ref: 'provider-call:' + index,
    source_version: digest('b'), correction_of: null, actor: 'system:runtime',
    recorded_at: 1788880100 + index, coverage_scope_sha256: null,
    current: true, current_reason: 'current', ...changes,
  };
}

function pricingEvidence() {
  return {
    model_id: 'provider:model', input_per_mtok: '1', output_per_mtok: '2',
    source: '<img src=x> published rate card', as_of: '2026-09-08',
    fetched_at: '2026-09-08T12:00:00Z', currency: 'USD', confidence: 0.4,
    verified: false, rate_card_version: 'rate-v1', evidence_id: 'price-v1',
    pricing_basis: 'Published list price.', applicability: 'Standard token usage.',
  };
}

function detail(summary, changes = {}) {
  const events = changes.events || [
    costEvent(0, {
      basis: 'settled', amount: '3', source_assurance: 'authenticated_provider_invoice',
      evidence_ref: 'invoice:line-1', evidence_sha256: digest('c'),
      verification_authority: 'provider-billing-api',
      budget_reconciliation: {
        reservation_ref: 'provider-cap:v1:openai:2026-09:request-1',
        reserved_amount: '4', final_amount: '3', currency: 'USD', delta: '1',
        status: 'released', verification_authority: 'provider-cost-cap:v1',
      },
    }),
    costEvent(1, {
      basis: 'settled', amount: '2', source_assurance: 'local_signed_receipt',
      evidence_ref: 'receipt:local-1', evidence_sha256: digest('d'),
      verification_authority: 'lightwork-local-receipt:v1',
    }),
    costEvent(2),
    costEvent(3, {basis: 'estimated', pricing_evidence: pricingEvidence()}),
    costEvent(4, {
      basis: 'unknown', amount: null, currency: null, attempt_state: 'unknown',
      unknown_reason: 'Provider usage was unavailable.', budget_state: 'metering_failed',
      budget_reconciliation: {
        reservation_ref: 'provider-cap:v1:openai:2026-09:request-2',
        reserved_amount: '5', final_amount: null, currency: 'USD', delta: null,
        status: 'held', verification_authority: 'provider-cost-cap:v1',
      },
    }),
  ];
  const costs = costSummary({
    complete: false, coverage_complete: false, attempt_states_complete: false,
    settlement_status: 'incomplete',
    known_totals: {USD: '7'}, unknown_event_count: 1, event_count: events.length,
    authenticated_provider_invoice_count: 1, local_signed_receipt_count: 1,
    reconciled_reservation_count: 2, display: 'At least USD 7; total incomplete.',
    events,
  });
  return {
    context: 'alice', id: summary.id, revision: summary.revision,
    admission_id: summary.admission_id, work_item_id: summary.work_item_id,
    owner_id: summary.owner_id, acceptance_contract_ref: summary.acceptance_contract_ref,
    admitted_at: summary.admitted_at, disposition: summary.disposition,
    technical_outcome: summary.technical_outcome, business_outcome: summary.business_outcome,
    evidence_version: summary.evidence_version,
    observations: [{
      id: 'OBS-observation-1', source_id: 'task:<img src=x>', source_version: digest('e'),
      result: 'confirmed', authoritative: true, summary: '<img src=x> source confirmed',
      observed_at: 1788880200, valid_until: 1788880300, correction_of: null,
      actor: 'system:readback', current: true, current_reason: 'current',
    }],
    decisions: [], dispositions: [], costs,
    platform_contract: {
      schema: 'lightwork.contract.outcome-record.v1', schema_version: 1,
      id: summary.id, tenant_id: 'workspace-one', owner_id: summary.owner_id,
      work_item_id: summary.work_item_id, revision: summary.revision,
      cost: {state: 'unknown', reason: 'cost_incomplete_or_not_expressible_in_one_currency'},
    },
    ...Object.fromEntries(Object.entries(changes).filter(([key]) => key !== 'events')),
  };
}

async function fixture(response, context = 'alice') {
  const dom = new JSDOM(
    '<div id="outcome-pilots" data-context="' + context + '">' +
      '<div id="op-accounting-summary">Loading current accounting…</div>' +
      '<button id="op-accounting-previous"></button><button id="op-accounting-next"></button>' +
    '</div>',
    {url: 'https://lightwork.test', runScripts: 'outside-only'},
  );
  const calls = [];
  dom.window.fetch = async (url, options) => {
    calls.push({url, options});
    return typeof response === 'function' ? response(url, options, calls.length) : response;
  };
  shell(dom.window);
  dom.window.eval(script);
  await settle();
  return {dom, host: dom.window.document.getElementById('op-accounting-summary'), calls};
}

test('keeps loading explicit, then renders a bounded empty state', async t => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const ui = await fixture(() => pending);
  t.after(() => ui.dom.window.close());
  assert.equal(ui.host.getAttribute('aria-busy'), 'true');
  assert.match(ui.host.textContent, /Loading current accounting/);
  const empty = payload({records: [], costs: {known_totals: {}}});
  release({ok: true, json: async () => empty});
  await settle();
  assert.equal(ui.host.getAttribute('aria-busy'), 'false');
  assert.match(ui.host.textContent, /No admitted outcome records are visible/);
  assert.match(ui.host.textContent, /Aggregate overflow: none detected/);
});

test('shows every cost assurance class and loads accessible in-app evidence details safely', async t => {
  const records = [
    record(0, {costs: costSummary({
      complete: false, coverage_complete: false, settlement_status: 'incomplete',
      known_totals: {USD: '7'}, unknown_event_count: 1, event_count: 5,
      authenticated_provider_invoice_count: 1, local_signed_receipt_count: 1,
      reconciled_reservation_count: 2, display: 'At least USD 7; total incomplete.',
    })}),
    record(1),
    record(2, {costs: costSummary({settlement_status: 'estimated'})}),
    record(3, {costs: costSummary({
      complete: false, coverage_complete: false, settlement_status: 'incomplete',
      known_totals: {}, unknown_event_count: 1, display: 'Total incomplete.',
    })}),
    record(4, {costs: costSummary({
      settlement_status: 'settled', authenticated_provider_invoice_count: 1,
    })}),
  ];
  const portfolio = payload({records, costs: {known_totals: {USD: '9'}}});
  const full = detail(records[0]);
  const ui = await fixture(async (url) => ({ok: true, json: async () => url.includes('/OAC-record-0') ? full : portfolio}));
  t.after(() => ui.dom.window.close());
  assert.equal(ui.calls[0].url, '/api/v1/outcome-accounting?limit=100');
  assert.equal(ui.calls[0].options.credentials, 'same-origin');
  assert.match(ui.host.textContent, /Authenticated provider invoice evidence: 2/);
  assert.match(ui.host.textContent, /Exact authenticated provider invoice cost: 1 record/);
  assert.match(ui.host.textContent, /Local signed receipt evidence: 1/);
  assert.match(ui.host.textContent, /Observed cost: 1 complete record/);
  assert.match(ui.host.textContent, /Estimated cost: 1 complete record/);
  assert.match(ui.host.textContent, /Unknown or incomplete cost: 2 record/);
  assert.match(ui.host.textContent, /Aggregate overflow: none detected/);

  const button = ui.host.querySelector('.op-accounting-record button');
  const region = ui.host.querySelector('.op-accounting-record-detail');
  assert.equal(button.getAttribute('aria-controls'), region.id);
  assert.equal(button.getAttribute('aria-expanded'), 'false');
  button.click();
  await settle();
  assert.equal(ui.calls[1].url, '/api/v1/outcome-accounting/OAC-record-0');
  assert.equal(ui.calls[1].options.headers['X-Lightwork-Pilot-Context'], 'alice');
  assert.equal(button.getAttribute('aria-expanded'), 'true');
  assert.equal(region.hidden, false);
  assert.match(region.textContent, /Authenticated provider invoice/);
  assert.match(region.textContent, /Local signed receipt/);
  assert.match(region.textContent, /unverified estimate/);
  assert.match(region.textContent, /Provider reservation: released/);
  assert.match(region.textContent, /Provider reservation: held/);
  assert.match(region.textContent, /Amount unknown/);
  assert.match(region.textContent, /Record provenance/);
  assert.equal(region.querySelector('img'), null);
  button.click();
  assert.equal(region.hidden, true);
  button.click();
  assert.equal(region.hidden, false);
  assert.equal(ui.calls.length, 2, 'loaded evidence toggles without another request');
});

test('derives incomplete attempt states from informational provider and failed-attempt evidence', async t => {
  const summary = record(0, {costs: costSummary({
    complete: false,
    coverage_complete: false,
    attempt_states_complete: false,
    settlement_status: 'incomplete',
    known_totals: {USD: '1'},
    unknown_event_count: 2,
    additive_unknown_event_count: 0,
    informational_event_count: 2,
    additive_event_count: 1,
    event_count: 3,
    display: 'At least USD 1; total incomplete.',
  })});
  const events = [
    costEvent(0),
    costEvent(1, {
      aggregation: 'informational', basis: 'unknown', amount: null, currency: null,
      attempt_state: 'unknown', unknown_reason: 'Provider usage state is unknown.',
    }),
    costEvent(2, {
      category: 'retry', aggregation: 'informational', basis: 'unknown',
      amount: null, currency: null, attempt_state: 'unknown',
      unknown_reason: 'Failed-attempt state is unknown.',
    }),
  ];
  const full = detail(summary, {events});
  full.costs = {...summary.costs, events};
  const portfolio = payload({records: [summary], costs: {known_totals: {USD: '1'}}});
  const ui = await fixture(async url => ({
    ok: true, json: async () => url.includes('/OAC-record-0') ? full : portfolio,
  }));
  t.after(() => ui.dom.window.close());

  const button = ui.host.querySelector('.op-accounting-record button');
  button.click();
  await settle();
  const region = ui.host.querySelector('.op-accounting-record-detail');
  assert.equal(region.dataset.loaded, 'true');
  assert.match(region.textContent, /Amount unknown/);

  full.costs.attempt_states_complete = true;
  const invalidUi = await fixture(async url => ({
    ok: true, json: async () => url.includes('/OAC-record-0') ? full : portfolio,
  }));
  t.after(() => invalidUi.dom.window.close());
  const invalidButton = invalidUi.host.querySelector('.op-accounting-record button');
  invalidButton.click();
  await settle();
  const invalidRegion = invalidUi.host.querySelector('.op-accounting-record-detail');
  assert.match(invalidRegion.textContent, /No record details were displayed/);
  assert.equal(invalidRegion.dataset.loaded, undefined);
});

test('shows aggregate overflow explicitly without treating it as zero', async t => {
  const records = [record(0)];
  const value = payload({
    records,
    costs: {
      known_totals: {}, aggregate_overflow_currencies: ['USD'], totals_complete: false,
      incomplete_records: 1,
    },
  });
  const ui = await fixture({ok: true, json: async () => value});
  t.after(() => ui.dom.window.close());
  assert.match(ui.host.textContent, /Aggregate overflow: totals for USD exceed/);
  assert.match(ui.host.textContent, /No priced aggregate cost can be displayed/);
  assert.doesNotMatch(ui.host.textContent, /Known recorded cost: USD 0/);
});

test('navigates bounded accounting pages without leaving the app', async t => {
  const firstRecords = [record(0)];
  const secondRecords = [record(1)];
  const responses = [
    payload({records: firstRecords, page: {has_more: true, next_cursor: 'OAC-next', scope_complete: false}}),
    payload({records: secondRecords, page: {cursor: 'OAC-next', scope_complete: false}}),
    payload({records: firstRecords, page: {has_more: true, next_cursor: 'OAC-next', scope_complete: false}}),
  ];
  const ui = await fixture(async () => ({ok: true, json: async () => responses.shift()}));
  t.after(() => ui.dom.window.close());
  const previous = ui.dom.window.document.getElementById('op-accounting-previous');
  const next = ui.dom.window.document.getElementById('op-accounting-next');
  assert.equal(previous.disabled, true); assert.equal(next.disabled, false);
  next.click(); await settle();
  assert.equal(ui.calls[1].url, '/api/v1/outcome-accounting?limit=100&cursor=OAC-next');
  assert.match(ui.host.textContent, /Work item work-1/);
  assert.equal(previous.disabled, false); assert.equal(next.disabled, true);
  previous.click(); await settle();
  assert.equal(ui.calls[2].url, '/api/v1/outcome-accounting?limit=100');
  assert.equal(previous.disabled, true); assert.equal(next.disabled, false);
});

test('refuses malformed or cross-context detail and displays none of its fields', async t => {
  const summary = record(0);
  const portfolio = payload({records: [summary]});
  for (const invalid of [
    detail(summary, {context: 'other', admission_id: '<img src=x> private'}),
    detail(summary, {id: 'OAC-record-other', admission_id: '<img src=x> private'}),
    detail(summary, {platform_contract: {
      schema: 'lightwork.contract.outcome-record.v1', schema_version: 1,
      id: summary.id, tenant_id: 'workspace-one', owner_id: 'user:other',
      work_item_id: summary.work_item_id, revision: summary.revision,
    }}),
    detail(summary, {events: [costEvent(0)], costs: undefined}),
  ]) {
    await t.test('invalid detail response', async t => {
      const ui = await fixture(async (url) => ({ok: true, json: async () => url.includes('/OAC-record-0') ? invalid : portfolio}));
      t.after(() => ui.dom.window.close());
      const button = ui.host.querySelector('.op-accounting-record button');
      button.click(); await settle();
      const region = ui.host.querySelector('.op-accounting-record-detail');
      assert.match(region.textContent, /No record details were displayed/);
      assert.doesNotMatch(region.textContent, /private/);
      assert.equal(region.querySelector('img'), null);
      assert.equal(region.dataset.loaded, undefined);
    });
  }
});

test('refuses portfolio count, context, money, overflow, cursor, and record mismatches', async t => {
  const base = payload();
  const invalidValues = [
    {...base, admitted: 11},
    {...base, context: 'other'},
    {...base, costs: {...base.costs, known_totals: {USD: 'NaN'}}},
    {...base, costs: {...base.costs, aggregate_overflow_currencies: ['USD'], totals_complete: false}},
    {...base, page: {...base.page, cursor: 'OAC-unrequested'}},
    {...base, page: {...base.page, has_more: true, next_cursor: null, scope_complete: false}},
    {...base, records: base.records.slice(1)},
  ];
  for (const value of invalidValues) {
    await t.test('invalid portfolio projection', async t => {
      const ui = await fixture({ok: true, json: async () => value});
      t.after(() => ui.dom.window.close());
      assert.match(ui.host.textContent, /invalid|do not reconcile|does not reconcile|did not match|do not add up|must be an amount of money|not the one this page asked for|not a valid link to the next page/);
      assert.equal(ui.host.querySelector('.op-accounting-record'), null);
      assert.equal(ui.host.querySelector('script'), null);
    });
  }
  const ui = await fixture({ok: false, status: 403, json: async () => { throw new SyntaxError('<script>secret</script>'); }});
  t.after(() => ui.dom.window.close());
  assert.match(ui.host.textContent, /unavailable|do not have permission/);
  assert.doesNotMatch(ui.host.textContent, /secret/);
});

test('invalid page context prevents every request', async t => {
  const ui = await fixture({ok: true, json: async () => payload()}, 'alice&#10;other');
  t.after(() => ui.dom.window.close());
  assert.equal(ui.calls.length, 0);
  assert.match(ui.host.textContent, /accounting context contains characters this page cannot show/);
});
