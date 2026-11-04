'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const {createHash, webcrypto} = require('node:crypto');
const {TextEncoder} = require('node:util');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(
  __dirname, '../../maverick_dashboard/static/lightwork-outcome-value.js',
), 'utf8');
const settle = async () => {
  for (let index = 0; index < 10; index += 1) await new Promise(resolve => setImmediate(resolve));
};
const waitFor = async (predicate, label) => {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.fail(`Timed out waiting for ${label}`);
};

const EXPORT_ENVELOPE = Object.freeze({
  schema: 'lightwork.outcome-value-export-envelope.v1',
  digest_algorithm: 'SHA-256',
  digest_encoding: 'lowercase-hex',
  canonicalization: 'lightwork.canonical-json-tree-f64-utf8hex.v1',
  node_encoding: 'tagged-arrays-null-[tag]-others-[tag,value]',
  object_encoding: 'sorted-[utf8hex-key,node]-pairs',
  string_encoding: 'utf-8-lowercase-hex',
  number_encoding: 'ieee-754-binary64-big-endian-lowercase-hex',
  object_key_order: 'utf-8-byte-lexicographic',
  array_order: 'preserved',
  serialization: 'compact-json-utf-8',
  excluded_fields: ['context', 'export_envelope.digest_sha256'],
});

const utf8Hex = value => Buffer.from(value, 'utf8').toString('hex');
function numberHex(value) {
  const buffer = Buffer.allocUnsafe(8);
  buffer.writeDoubleBE(value, 0);
  return buffer.toString('hex');
}
function exportCanonicalNode(value) {
  if (value === null) return ['null'];
  if (typeof value === 'boolean') return ['boolean', value ? 'true' : 'false'];
  if (typeof value === 'string') return ['string', utf8Hex(value)];
  if (typeof value === 'number') return ['number', numberHex(value)];
  if (Array.isArray(value)) return ['array', value.map(exportCanonicalNode)];
  const pairs = Object.entries(value).map(([key, item]) => [
    utf8Hex(key), exportCanonicalNode(item),
  ]);
  pairs.sort((left, right) => left[0] < right[0] ? -1 : left[0] > right[0] ? 1 : 0);
  return ['object', pairs];
}
function bindExport(report) {
  report.export_envelope = {...EXPORT_ENVELOPE};
  const unsigned = {...report, export_envelope: {...report.export_envelope}};
  delete unsigned.context;
  const canonical = JSON.stringify(exportCanonicalNode(unsigned));
  report.export_envelope.digest_sha256 = createHash('sha256')
    .update(canonical, 'utf8').digest('hex');
  return report;
}

function caseRow(changes = {}) {
  return {
    outcome: {
      id: 'OVA-case-one', revision: 3,
      admission_id: 'OPL-pilot-one:case-one',
      acceptance_contract_ref: 'outcome-pilot:OPL-pilot-one:' + 'a'.repeat(64),
      work_item_id: 'goal:<img src=x>',
      disposition: 'completed',
      technical_outcome: {status: 'verified', reason: 'authoritative_readback_confirmed'},
      business_outcome: {status: 'accepted', reason: 'current_human_decision'},
      costs: {known_totals: {USD: '3'}, failed_attempt_count: 1, complete: true},
    },
    category: 'accepted', value_revision: 2,
    timestamps: {
      admitted_at: 1788880000,
      last_observed_at: 1788880100,
      last_decided_at: 1788880200,
      last_disposition_at: 1788880300,
      last_cost_at: 1788880400,
      last_baseline_at: 1788880500,
    },
    comparison: {
      cost: {
        status: 'measured', net_savings: '7', roi_percent: '70',
        baseline: {basis: 'observed', value: '10', currency: 'USD'},
        delivered: {basis: 'observed', amount: '3', currency: 'USD'},
      },
      human_effort: {status: 'measured', minutes_saved: '45'},
      missing_components: [], measured_positive_roi: true,
    },
    baseline: {
      cost: {basis: 'observed', value: '10', currency: 'USD'},
      human_effort: {basis: 'observed', value: '60', currency: null},
    },
    renewal_count: 1, expansion_count: 0,
    ...changes,
  };
}

function payload(changes = {}) {
  const cases = changes.cases || [caseRow()];
  const categories = {accepted: 1, rejected: 0, failed: 0, cancelled: 0, unresolved: 0};
  return {
    schema: 'lightwork.outcome-value-cohort.v1', context: 'workspace-one',
    pilot_id: 'OPL-pilot-one', plan_version: 'a'.repeat(64),
    admission_manifest_sha256: 'b'.repeat(64),
    cohort_binding: {
      acceptance_contract_ref: 'outcome-pilot:OPL-pilot-one:' + 'a'.repeat(64),
      record_count: cases.length, record_ids_sha256: 'c'.repeat(64),
    },
    admitted: cases.length, categories, reconciles: true, scope_complete: true, cases,
    costs: {
      known_totals: {USD: '3'}, category_totals: {support: {USD: '3'}},
      unknown_event_counts_by_category: {}, incomplete_records: 0, failed_attempts: 1,
      aggregate_overflow_currencies: [], complete: true,
      allocation_assumptions_explicit: true,
    },
    comparison: {
      cost: {
        status: 'measured', missing_records: [], currency: 'USD',
        baseline_total: '10', delivered_total: '3', net_savings: '7',
        roi_percent: '70', measured_positive_roi: true,
      },
      human_effort: {status: 'measured', missing_records: [], minutes_saved: '45'},
      commercial_records_included: false,
    },
    commercial: {renewals: [{id: 'REN-one'}], expansions: []},
    commercial_counts: {renewals: 1, expansions: 0},
    commercial_records_complete: true,
    commercial_separate_from_savings: true,
    ...changes,
  };
}

function pilotPayload(pilotId, planVersion = 'd'.repeat(64)) {
  const item = caseRow({
    outcome: {
      ...caseRow().outcome,
      admission_id: `${pilotId}:case-one`,
      acceptance_contract_ref: `outcome-pilot:${pilotId}:${planVersion}`,
    },
  });
  return payload({
    pilot_id: pilotId,
    plan_version: planVersion,
    admission_manifest_sha256: 'e'.repeat(64),
    cohort_binding: {
      acceptance_contract_ref: `outcome-pilot:${pilotId}:${planVersion}`,
      record_count: 1,
      record_ids_sha256: 'f'.repeat(64),
    },
    cases: [item],
  });
}

function markup(context = 'workspace-one') {
  return `
    <div id="outcome-pilots" data-context="${context}">
      <p id="ov-status"></p><div id="ov-summary"></div>
      <select id="ov-pilot"><option value="">Choose</option></select>
      <select id="ov-record"><option value="">Choose</option></select>
      <button id="ov-load-more" hidden>Load more pilot cohorts</button>
      <button id="ov-refresh"></button><button id="ov-export"></button>
      <p id="ov-selected-summary"></p>
      <form id="ov-baseline-form">
        <select name="cost_basis"><option value="observed">Observed</option><option value="unknown">Unknown</option></select>
        <input name="cost_amount"><input name="currency"><textarea name="cost_unknown_reason"></textarea>
        <select name="human_basis"><option value="observed">Observed</option><option value="unknown">Unknown</option></select>
        <input name="human_minutes"><textarea name="human_unknown_reason"></textarea>
        <input name="source_ref"><textarea name="evidence_note"></textarea><textarea name="correction_reason"></textarea>
        <button type="submit">Save</button>
      </form>
      <form id="ov-cost-form">
        <select name="category"><option value="support">Support</option></select>
        <select name="attempt_state"><option value="failed">Failed</option></select>
        <select name="basis"><option value="observed">Observed</option><option value="unknown">Unknown</option></select>
        <select name="total_relationship"><option value="included_in_current_total">Included</option><option value="additional_to_current_total">Additional</option></select>
        <input name="amount"><input name="currency"><textarea name="unknown_reason"></textarea>
        <input name="quantity"><input name="unit"><input name="source_ref"><textarea name="evidence_note"></textarea>
        <select name="allocation_method"><option value="usage_weighted">Usage weighted</option></select>
        <textarea name="allocation_assumption"></textarea><textarea name="correction_reason"></textarea>
        <p id="ov-cost-relationship-help"></p><fieldset id="ov-cost-coverage">
        ${['provider_usage','failed_attempts','setup','review','exception','rework','support','allocation'].map(family => `
          <select name="coverage_${family}_status"><option value="included">Included</option><option value="zero">Zero</option><option value="unknown">Unknown</option></select>
          <textarea name="coverage_${family}_note">Reviewed evidence for ${family}.</textarea>
        `).join('')}
        </fieldset>
        <input type="checkbox" name="complete_coverage"><button type="submit">Save</button>
      </form>
      <form id="ov-commercial-form">
        <select name="kind"><option value="renewal">Renewal</option></select>
        <select name="stage"><option value="proposed">Proposed</option></select>
        <select name="basis"><option value="estimated">Estimated</option><option value="unknown">Unknown</option></select>
        <input name="amount"><input name="currency"><textarea name="unknown_reason"></textarea>
        <input name="source_ref"><textarea name="note"></textarea><textarea name="correction_reason"></textarea>
        <button type="submit">Save</button>
      </form>
    </div>`;
}

async function fixture(responder, context = 'workspace-one', pilotResponder = null) {
  const dom = new JSDOM(markup(context), {url: 'https://lightwork.test', runScripts: 'outside-only'});
  Object.defineProperty(dom.window, 'crypto', {configurable: true, value: webcrypto});
  dom.window.TextEncoder = TextEncoder;
  const calls = [];
  let responseCalls = 0;
  dom.window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    if (url.startsWith('/api/v1/outcome-pilots?')) {
      if (pilotResponder) return pilotResponder(url, options);
      return {ok: true, json: async () => ({
        context, partial: false,
        items: [{id: 'OPL-pilot-one', title: 'Pilot one'}],
        page: {has_more: false, next_cursor: null},
      })};
    }
    responseCalls += 1;
    return responder(url, options, responseCalls);
  };
  dom.window.eval(script);
  await settle();
  return {dom, calls, host: dom.window.document.getElementById('ov-summary')};
}

test('renders the reconciled denominator, cost categories, evidence class, and separate commercial records', async t => {
  const ui = await fixture(async () => ({ok: true, json: async () => payload()}));
  t.after(() => ui.dom.window.close());
  assert.equal(ui.calls[1].url, '/api/v1/outcome-accounting/cohort?pilot_id=OPL-pilot-one');
  assert.equal(ui.calls[1].options.credentials, 'same-origin');
  assert.equal(ui.calls[1].options.headers['X-Lightwork-Pilot-Context'], 'workspace-one');
  assert.match(ui.host.textContent, /1 admitted case/);
  assert.match(ui.host.textContent, /accepted 1/);
  assert.match(ui.host.textContent, /USD 3/);
  assert.match(ui.host.textContent, /Measured from operator-recorded evidence cost change: USD 7 net savings; ROI 70%/);
  assert.match(ui.host.textContent, /1 current renewal record/);
  assert.match(ui.host.textContent, /excluded from operational savings/);
  assert.match(ui.host.textContent, /Support: USD 3/);
  assert.equal(ui.host.querySelector('img'), null);
  const option = ui.dom.window.document.querySelector('#ov-record option:nth-child(2)');
  assert.match(option.textContent, /<img src=x>/i);
  assert.equal(option.querySelector('img'), null);
});

test('renders exact selected-case gaps, every timestamp, and aggregate unknown cost counts', async t => {
  const item = caseRow({
    baseline: null,
    timestamps: {
      admitted_at: 1788880000,
      last_observed_at: 1788880100,
      last_decided_at: null,
      last_disposition_at: 1788880300,
      last_cost_at: 1788880400,
      last_baseline_at: null,
    },
    comparison: {
      cost: {status: 'unavailable', net_savings: null, roi_percent: null},
      human_effort: {status: 'unavailable', minutes_saved: null},
      missing_components: ['baseline_cost', 'delivered_human_time'],
      measured_positive_roi: false,
    },
  });
  const report = payload({
    cases: [item],
    costs: {
      ...payload().costs,
      unknown_event_counts_by_category: {inference: 1, support: 2},
    },
    comparison: {
      cost: {
        status: 'unavailable', missing_records: ['OVA-case-one'],
        net_savings: null, roi_percent: null,
      },
      human_effort: {
        status: 'unavailable', missing_records: ['OVA-case-one'], minutes_saved: null,
      },
      commercial_records_included: false,
    },
  });
  const ui = await fixture(async () => ({ok: true, json: async () => report}));
  t.after(() => ui.dom.window.close());

  assert.match(ui.host.textContent, /Inference: 1 unknown event\./);
  assert.match(ui.host.textContent, /Support: 2 unknown events\./);
  const document = ui.dom.window.document;
  const selector = document.getElementById('ov-record');
  selector.value = 'OVA-case-one';
  selector.dispatchEvent(new ui.dom.window.Event('change', {bubbles: true}));
  const summary = document.getElementById('ov-selected-summary');
  assert.match(summary.textContent, /Missing comparison components: baseline_cost, delivered_human_time\./);
  assert.match(summary.textContent, new RegExp('Admitted: ' + new Date(1788880000 * 1000).toISOString()));
  assert.match(summary.textContent, new RegExp('Last observed: ' + new Date(1788880100 * 1000).toISOString()));
  assert.match(summary.textContent, /Last decided: not recorded\./);
  assert.match(summary.textContent, new RegExp('Last disposition: ' + new Date(1788880300 * 1000).toISOString()));
  assert.match(summary.textContent, new RegExp('Last cost: ' + new Date(1788880400 * 1000).toISOString()));
  assert.match(summary.textContent, /Last baseline: not recorded\./);
  assert.equal(summary.querySelector('img'), null);
});

test('rejects case category mismatches and malformed case timestamps', async t => {
  const invalidCases = [
    caseRow({category: 'rejected'}),
    caseRow({timestamps: {
      admitted_at: null,
      last_observed_at: 1788880100,
      last_decided_at: null,
      last_disposition_at: null,
      last_cost_at: null,
      last_baseline_at: null,
    }}),
  ];
  for (const item of invalidCases) {
    await t.test('invalid case projection', async t => {
      const ui = await fixture(async () => ({ok: true, json: async () => payload({cases: [item]})}));
      t.after(() => ui.dom.window.close());
      assert.match(ui.host.textContent, /wrong category for its outcome|admission time must be a date and time/i);
      assert.equal(ui.dom.window.document.getElementById('ov-export').disabled, true);
    });
  }
});

test('renders a bounded explanation when a valid cost ratio overflows', async t => {
  const item = caseRow();
  item.outcome = {
    ...item.outcome,
    costs: {
      ...item.outcome.costs,
      known_totals: {USD: '999999999999999999'},
    },
  };
  item.comparison = {
    ...item.comparison,
    cost: {
      status: 'unavailable',
      baseline: {basis: 'observed', value: '0.000000000001', currency: 'USD'},
      delivered: {basis: 'observed', amount: '999999999999999999', currency: 'USD'},
      net_savings: null,
      roi_percent: null,
      overflow: true,
      reason: 'the cost comparison exceeds the reporting bound',
    },
    missing_components: ['cost_comparison_overflow'],
    measured_positive_roi: false,
  };
  const report = payload({
    cases: [item],
    costs: {
      ...payload().costs,
      known_totals: {USD: '999999999999999999'},
      category_totals: {support: {USD: '999999999999999999'}},
    },
    comparison: {
      ...payload().comparison,
      cost: {
        status: 'unavailable', missing_records: ['OVA-case-one'],
        net_savings: null, roi_percent: null, overflow: true,
        reason: 'one or more case comparisons exceed the reporting bound',
      },
    },
  });
  const ui = await fixture(async () => ({ok: true, json: async () => report}));
  t.after(() => ui.dom.window.close());

  assert.match(ui.host.textContent, /Cost comparison unavailable/);
  assert.match(ui.host.textContent, /exceed the reporting bound/);
  assert.doesNotMatch(ui.host.textContent, /net savings; ROI/);
});

test('appends and selects a pilot cohort from page two without losing the current selection', async t => {
  const listRequests = [];
  const ui = await fixture(
    async url => ({
      ok: true,
      json: async () => url.includes('pilot_id=OPL-pilot-two')
        ? pilotPayload('OPL-pilot-two') : payload(),
    }),
    'workspace-one',
    async url => {
      listRequests.push(url);
      const request = new URL(url, 'https://lightwork.test');
      if (!request.searchParams.get('cursor')) {
        return {ok: true, json: async () => ({
          context: 'workspace-one', partial: true,
          items: [{id: 'OPL-pilot-one', title: 'Pilot one'}],
          page: {has_more: true, next_cursor: 'OPL-page-0001.json'},
        })};
      }
      return {ok: true, json: async () => ({
        context: 'workspace-one', partial: false,
        items: [
          {id: 'OPL-pilot-one', title: 'Pilot one duplicate'},
          {id: 'OPL-pilot-two', title: 'Pilot two'},
        ],
        page: {has_more: false, next_cursor: null},
      })};
    },
  );
  t.after(() => ui.dom.window.close());
  const document = ui.dom.window.document;
  const pilotSelector = document.getElementById('ov-pilot');
  const more = document.getElementById('ov-load-more');
  assert.equal(pilotSelector.value, 'OPL-pilot-one');
  assert.equal(more.hidden, false);

  more.click();
  await settle();
  assert.equal(pilotSelector.value, 'OPL-pilot-one');
  assert.deepEqual([...pilotSelector.options].map(option => option.value), [
    '', 'OPL-pilot-one', 'OPL-pilot-two',
  ]);
  assert.equal(more.hidden, true);
  assert.match(listRequests[1], /limit=100&cursor=OPL-page-0001\.json$/);

  pilotSelector.value = 'OPL-pilot-two';
  pilotSelector.dispatchEvent(new ui.dom.window.Event('change', {bubbles: true}));
  await settle();
  assert.ok(ui.calls.some(call => call.url.includes('pilot_id=OPL-pilot-two')));
  assert.equal(pilotSelector.value, 'OPL-pilot-two');
  assert.match(ui.host.textContent, /1 admitted case/);
});

test('rejects a malformed pilot page cursor before adding or loading a cohort', async t => {
  const ui = await fixture(
    async () => ({ok: true, json: async () => payload()}),
    'workspace-one',
    async () => ({ok: true, json: async () => ({
      context: 'workspace-one', partial: true,
      items: [{id: 'OPL-pilot-one', title: 'Pilot one'}],
      page: {has_more: true, next_cursor: '../another-account'},
    })}),
  );
  t.after(() => ui.dom.window.close());
  const document = ui.dom.window.document;
  assert.deepEqual([...document.getElementById('ov-pilot').options].map(option => option.value), ['']);
  assert.equal(document.getElementById('ov-load-more').hidden, true);
  assert.match(ui.host.textContent, /next page of pilots is not valid/i);
  assert.equal(ui.calls.some(call => call.url.includes('/cohort?')), false);
});

test('rejects an unavailable comparison that exposes ROI and displays no totals', async t => {
  const invalid = payload({
    comparison: {
      cost: {status: 'unavailable', missing_records: ['OVA-case-one'], net_savings: '7', roi_percent: '70'},
      human_effort: {status: 'unavailable', missing_records: ['OVA-case-one'], minutes_saved: null},
      commercial_records_included: false,
    },
  });
  const ui = await fixture(async () => ({ok: true, json: async () => invalid}));
  t.after(() => ui.dom.window.close());
  assert.match(ui.host.textContent, /incomplete comparison exposed savings/);
  assert.doesNotMatch(ui.host.textContent, /USD 3/);
  assert.equal(ui.dom.window.document.getElementById('ov-export').disabled, true);
});

test('rejects positive measured ROI when delivered human time is unavailable', async t => {
  const invalid = payload({
    comparison: {
      cost: {
        status: 'measured', missing_records: [], currency: 'USD',
        baseline_total: '10', delivered_total: '3', net_savings: '7',
        roi_percent: '70', measured_positive_roi: true,
      },
      human_effort: {
        status: 'unavailable', missing_records: ['OVA-case-one'], minutes_saved: null,
      },
      commercial_records_included: false,
    },
  });
  const ui = await fixture(async () => ({ok: true, json: async () => invalid}));
  t.after(() => ui.dom.window.close());
  assert.match(ui.host.textContent, /human-time evidence exposed ROI/i);
  assert.doesNotMatch(ui.host.textContent, /USD 3/);
  assert.equal(ui.dom.window.document.getElementById('ov-export').disabled, true);
});

test('rejects cohort totals that do not reconcile to admitted cases', async t => {
  const invalid = payload({
    costs: {
      ...payload().costs,
      known_totals: {USD: '4'},
    },
  });
  const ui = await fixture(async () => ({ok: true, json: async () => invalid}));
  t.after(() => ui.dom.window.close());
  assert.match(ui.host.textContent, /do not reconcile/);
  assert.doesNotMatch(ui.host.textContent, /Measured from operator-recorded evidence/);
  assert.equal(ui.dom.window.document.getElementById('ov-export').disabled, true);
});

test('rejects a case whose immutable admission belongs to another pilot', async t => {
  const foreign = caseRow({
    outcome: {
      ...caseRow().outcome,
      admission_id: 'OPL-another-pilot:case-one',
      acceptance_contract_ref: 'outcome-pilot:OPL-another-pilot:' + 'd'.repeat(64),
    },
  });
  const ui = await fixture(async () => ({
    ok: true, json: async () => payload({cases: [foreign]}),
  }));
  t.after(() => ui.dom.window.close());
  assert.match(ui.host.textContent, /does not belong to the selected frozen pilot/i);
  assert.equal(ui.dom.window.document.getElementById('ov-export').disabled, true);
});

test('submits baseline and complete allocated failed-attempt cost entirely in app', async t => {
  const calls = [];
  const ui = await fixture(async (url, options) => {
    calls.push({url, options});
    return {ok: true, json: async () => payload()};
  });
  t.after(() => ui.dom.window.close());
  const document = ui.dom.window.document;
  document.getElementById('ov-record').value = 'OVA-case-one';

  const baseline = document.getElementById('ov-baseline-form');
  baseline.elements.cost_amount.value = '10'; baseline.elements.currency.value = 'usd';
  baseline.elements.human_minutes.value = '60'; baseline.elements.source_ref.value = 'invoice:baseline';
  baseline.elements.evidence_note.value = 'Observed baseline evidence.';
  baseline.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  const baselineCall = calls.find(call => call.url.endsWith('/baseline'));
  assert.ok(baselineCall);
  const baselineBody = JSON.parse(baselineCall.options.body);
  assert.equal(baselineBody.expected_revision, 2);
  assert.equal(baselineBody.currency, 'USD');
  assert.equal(baselineBody.operation_id.startsWith('baseline_'), true);
  assert.equal(baselineCall.options.headers['X-Lightwork-Pilot-Context'], 'workspace-one');

  document.getElementById('ov-record').value = 'OVA-case-one';
  const cost = document.getElementById('ov-cost-form');
  cost.elements.total_relationship.value = 'additional_to_current_total';
  cost.elements.total_relationship.dispatchEvent(
    new ui.dom.window.Event('change', {bubbles: true}),
  );
  cost.elements.amount.value = '3'; cost.elements.currency.value = 'usd';
  cost.elements.quantity.value = '15'; cost.elements.unit.value = 'minutes';
  cost.elements.source_ref.value = 'timesheet:support'; cost.elements.evidence_note.value = 'Reviewed source.';
  cost.elements.allocation_assumption.value = 'Weighted by admitted case minutes.';
  cost.elements.complete_coverage.checked = true;
  cost.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  const costCall = calls.find(call => call.url.endsWith('/costs'));
  assert.ok(costCall);
  const costBody = JSON.parse(costCall.options.body);
  assert.equal(costBody.expected_revision, 3);
  assert.equal(costBody.attempt_state, 'failed');
  assert.equal(costBody.total_relationship, 'additional_to_current_total');
  assert.equal(costBody.allocation_method, 'usage_weighted');
  assert.equal(costBody.allocation_assumption, 'Weighted by admitted case minutes.');
  assert.equal(costBody.complete_coverage, true);
  assert.deepEqual(Object.keys(costBody.coverage_declarations).sort(), [
    'allocation', 'exception', 'failed_attempts', 'provider_usage',
    'review', 'rework', 'setup', 'support',
  ]);
  assert.equal(costBody.coverage_declarations.failed_attempts.status, 'included');
  assert.equal(costBody.coverage_declarations.support.note, 'Reviewed evidence for support.');
});

test('defaults cost detail to already included and requires an explicit choice to add it', async t => {
  const calls = [];
  const ui = await fixture(async (url, options) => {
    calls.push({url, options});
    return {ok: true, json: async () => payload()};
  });
  t.after(() => ui.dom.window.close());
  const document = ui.dom.window.document;
  document.getElementById('ov-record').value = 'OVA-case-one';
  const form = document.getElementById('ov-cost-form');
  assert.equal(form.elements.total_relationship.value, 'included_in_current_total');
  assert.equal(form.elements.complete_coverage.disabled, true);
  assert.match(document.getElementById('ov-cost-relationship-help').textContent, /without adding it again/i);

  form.elements.amount.value = '6'; form.elements.currency.value = 'USD';
  form.elements.source_ref.value = 'provider:detail';
  form.elements.evidence_note.value = 'Detail is already inside the current all-in total.';
  form.elements.allocation_assumption.value = 'Weighted by admitted case usage.';
  form.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  let writes = calls.filter(call => call.url.endsWith('/costs'));
  assert.equal(JSON.parse(writes[0].options.body).total_relationship, 'included_in_current_total');

  document.getElementById('ov-record').value = 'OVA-case-one';
  form.elements.total_relationship.value = 'additional_to_current_total';
  form.elements.total_relationship.dispatchEvent(
    new ui.dom.window.Event('change', {bubbles: true}),
  );
  assert.match(document.getElementById('ov-cost-relationship-help').textContent, /increases the current delivered total/i);
  form.elements.amount.value = '6'; form.elements.currency.value = 'USD';
  form.elements.source_ref.value = 'provider:additional';
  form.elements.evidence_note.value = 'This amount occurred after the all-in total.';
  form.elements.allocation_assumption.value = 'Weighted by admitted case usage.';
  form.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  writes = calls.filter(call => call.url.endsWith('/costs'));
  assert.equal(JSON.parse(writes[1].options.body).total_relationship, 'additional_to_current_total');
});

test('records commercial evidence separately and downloads only a validated complete export', async t => {
  let downloaded = 0;
  const ui = await fixture(async url => {
    const value = payload();
    if (url.includes('/cohort/export?')) {
      value.schema = 'lightwork.outcome-value-export.v1';
      value.cohort_sha256 = 'a'.repeat(64);
      value.generated_at = 1790000000;
      value.limitations = ['Synthetic local acceptance evidence only.'];
      bindExport(value);
    }
    return {ok: true, json: async () => value};
  });
  t.after(() => ui.dom.window.close());
  const document = ui.dom.window.document;
  ui.dom.window.URL.createObjectURL = () => 'blob:report';
  ui.dom.window.URL.revokeObjectURL = () => {};
  ui.dom.window.HTMLAnchorElement.prototype.click = () => { downloaded += 1; };
  document.getElementById('ov-record').value = 'OVA-case-one';
  const form = document.getElementById('ov-commercial-form');
  form.elements.amount.value = '100'; form.elements.currency.value = 'usd';
  form.elements.source_ref.value = 'crm:renewal'; form.elements.note.value = 'Proposed renewal.';
  form.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  const commercial = ui.calls.find(call => call.url.endsWith('/commercial'));
  assert.ok(commercial);
  const body = JSON.parse(commercial.options.body);
  assert.equal(body.kind, 'renewal'); assert.equal(body.basis, 'estimated');

  document.getElementById('ov-export').click();
  await waitFor(
    () => !/Preparing the complete report/.test(document.getElementById('ov-status').textContent),
    'the complete report export',
  );
  const exported = ui.calls.find(call => call.url.includes('/cohort/export?'));
  assert.ok(exported);
  assert.equal(downloaded, 1);
  assert.match(document.getElementById('ov-status').textContent, /downloaded/);
});

test('rejects an export whose frozen admission manifest changed after binding', async t => {
  let downloaded = 0;
  const ui = await fixture(async url => {
    const value = payload();
    if (url.includes('/cohort/export?')) {
      value.schema = 'lightwork.outcome-value-export.v1';
      value.cohort_sha256 = 'a'.repeat(64);
      value.generated_at = 1790000000;
      value.limitations = ['Synthetic local acceptance evidence only.'];
      bindExport(value);
      value.admission_manifest_sha256 = 'd'.repeat(64);
    }
    return {ok: true, json: async () => value};
  });
  t.after(() => ui.dom.window.close());
  ui.dom.window.URL.createObjectURL = () => 'blob:report';
  ui.dom.window.URL.revokeObjectURL = () => {};
  ui.dom.window.HTMLAnchorElement.prototype.click = () => { downloaded += 1; };

  ui.dom.window.document.getElementById('ov-export').click();
  await waitFor(
    () => !/Preparing the complete report/.test(
      ui.dom.window.document.getElementById('ov-status').textContent,
    ),
    'the changed-manifest rejection',
  );
  assert.equal(downloaded, 0);
  assert.match(ui.dom.window.document.getElementById('ov-status').textContent, /not audit-bound/i);
});

test('rejects structurally valid cohort payload tampering after export binding', async t => {
  let downloaded = 0;
  const ui = await fixture(async url => {
    const value = payload();
    if (url.includes('/cohort/export?')) {
      value.schema = 'lightwork.outcome-value-export.v1';
      value.cohort_sha256 = 'a'.repeat(64);
      value.generated_at = 1790000000;
      value.limitations = ['Synthetic local acceptance evidence only.'];
      bindExport(value);
      value.cases[0].outcome.work_item_id = 'goal:tampered-after-binding';
    }
    return {ok: true, json: async () => value};
  });
  t.after(() => ui.dom.window.close());
  ui.dom.window.URL.createObjectURL = () => 'blob:report';
  ui.dom.window.URL.revokeObjectURL = () => {};
  ui.dom.window.HTMLAnchorElement.prototype.click = () => { downloaded += 1; };

  ui.dom.window.document.getElementById('ov-export').click();
  await waitFor(
    () => !/Preparing the complete report/.test(
      ui.dom.window.document.getElementById('ov-status').textContent,
    ),
    'the tampered-payload rejection',
  );
  assert.equal(downloaded, 0);
  assert.match(ui.dom.window.document.getElementById('ov-status').textContent, /not audit-bound/i);
});

test('a lost save response retains the evidence and exact retry identity', async t => {
  let firstMutation = true;
  const ui = await fixture(async (_url, options) => {
    if (options.method === 'POST' && firstMutation) {
      firstMutation = false;
      throw new Error('response lost after commit');
    }
    return {ok: true, json: async () => payload()};
  });
  t.after(() => ui.dom.window.close());
  const document = ui.dom.window.document;
  document.getElementById('ov-record').value = 'OVA-case-one';
  const form = document.getElementById('ov-cost-form');
  form.elements.amount.value = '3'; form.elements.currency.value = 'USD';
  form.elements.quantity.value = '15'; form.elements.unit.value = 'minutes';
  form.elements.source_ref.value = 'timesheet:lost-response';
  form.elements.evidence_note.value = 'Reviewed source remains available.';
  form.elements.allocation_assumption.value = 'Weighted by admitted case minutes.';

  form.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  const first = ui.calls.filter(call => call.url.endsWith('/costs'))[0];
  assert.ok(first);
  assert.equal(form.elements.amount.value, '3');
  assert.match(document.getElementById('ov-status').textContent, /entries remain/i);

  form.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  const writes = ui.calls.filter(call => call.url.endsWith('/costs'));
  assert.equal(writes.length, 2);
  assert.equal(
    JSON.parse(writes[1].options.body).operation_id,
    JSON.parse(writes[0].options.body).operation_id,
  );
  assert.equal(form.elements.amount.value, '');
  assert.match(document.getElementById('ov-status').textContent, /saved/i);
});

test('an unverifiable post-save readback keeps the form and retry identity across refresh', async t => {
  let mutationCount = 0;
  let rejectedReadback = false;
  const refreshedCase = caseRow({
    outcome: {
      ...caseRow().outcome,
      id: 'OVA-case-one', revision: 4,
      admission_id: 'OPL-pilot-one:case-one',
      acceptance_contract_ref: 'outcome-pilot:OPL-pilot-one:' + 'a'.repeat(64),
      work_item_id: 'goal:<img src=x>',
      costs: {known_totals: {USD: '3'}, failed_attempt_count: 1, complete: true},
    },
  });
  const ui = await fixture(async (_url, options) => {
    if (options.method === 'POST') {
      mutationCount += 1;
      return {ok: true, json: async () => ({})};
    }
    if (mutationCount === 1 && !rejectedReadback) {
      rejectedReadback = true;
      const invalid = payload();
      invalid.costs.known_totals = {USD: '99'};
      return {ok: true, json: async () => invalid};
    }
    return {ok: true, json: async () => payload({cases: [refreshedCase]})};
  });
  t.after(() => ui.dom.window.close());
  const document = ui.dom.window.document;
  document.getElementById('ov-record').value = 'OVA-case-one';
  const form = document.getElementById('ov-cost-form');
  form.elements.amount.value = '3'; form.elements.currency.value = 'USD';
  form.elements.quantity.value = '15'; form.elements.unit.value = 'minutes';
  form.elements.source_ref.value = 'timesheet:ambiguous-readback';
  form.elements.evidence_note.value = 'Reviewed source remains available.';

  form.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  assert.equal(form.elements.amount.value, '3');
  assert.match(document.getElementById('ov-status').textContent, /could not be verified/i);
  const first = ui.calls.filter(call => call.url.endsWith('/costs'))[0];

  document.getElementById('ov-refresh').click();
  await settle();
  document.getElementById('ov-record').value = 'OVA-case-one';
  form.dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  const writes = ui.calls.filter(call => call.url.endsWith('/costs'));
  assert.equal(writes.length, 2);
  assert.equal(
    JSON.parse(writes[1].options.body).operation_id,
    JSON.parse(first.options.body).operation_id,
  );
  assert.equal(JSON.parse(writes[1].options.body).expected_revision, 4);
  assert.equal(form.elements.amount.value, '');
});

test('invalid page context prevents every request', async t => {
  const ui = await fixture(async () => assert.fail('fetch should not run'), 'bad\ncontext');
  t.after(() => ui.dom.window.close());
  assert.equal(ui.calls.length, 0);
  assert.match(ui.host.textContent, /open for a different account or workspace/);
});

test('a report closed by the pilots page stays closed when a request finishes or a field changes', async t => {
  const ui = await fixture(async () => ({ok: true, json: async () => payload()}));
  t.after(() => ui.dom.window.close());
  const d = ui.dom.window.document, root = d.getElementById('outcome-pilots');
  const refresh = d.getElementById('ov-refresh'), exporter = d.getElementById('ov-export');
  assert.equal(refresh.disabled, false);
  // The pilots page loses access while this refresh is still answering.
  refresh.click();
  root.dataset.valueLocked = 'true';
  await settle();
  assert.equal(refresh.disabled, true);
  assert.equal(exporter.disabled, true);
  // A field that would normally apply stays closed.
  const basis = d.querySelector('#ov-cost-form [name="basis"]');
  basis.value = 'observed';
  basis.dispatchEvent(new ui.dom.window.Event('change', {bubbles: true}));
  assert.equal(d.querySelector('#ov-cost-form [name="amount"]').disabled, true);
  assert.equal(d.querySelector('#ov-cost-form [name="complete_coverage"]').disabled, true);
});
