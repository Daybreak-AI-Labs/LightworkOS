'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const folder = path.resolve(__dirname, '../../maverick_dashboard');
const script = fs.readFileSync(path.join(folder, 'static/lightwork-tax.js'), 'utf8');
const finance = fs.readFileSync(path.join(folder, 'templates/finance.html'), 'utf8');
const start = finance.indexOf('<section class="panel" id="tax-root"');
const markup = finance.slice(start, finance.indexOf('</section>', start) + '</section>'.length);

function response(value, status = 200) {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}
const STATUS = {tax_year: 2025, tables: 'Built-in tables', can_roll_back: true, update_channel: false,
  states: ['CA', 'TX'], document_types: ['W-2', '1099-INT'], technical: []};

async function fixture(route, {confirm = true} = {}) {
  const dom = new JSDOM('<!doctype html><body>' + markup + '</body>', {url: 'https://lightwork.example/finance', runScripts: 'outside-only'});
  const {window} = dom, calls = [], confirms = [];
  shell(window);
  window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    if (url === '/api/v1/tax' && (!options.method || options.method === 'GET')) return response(STATUS);
    return route(url, options);
  };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.mvPlainDetail = (text) => (typeof text === 'string' && /^[A-Z][^_]*\.$/.test(text) ? text : '');
  window.URL.createObjectURL = () => 'blob:x';
  window.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  return {window, document: window.document, calls, confirms, settle};
}
function choose(window, input, files) {
  Object.defineProperty(input, 'files', {value: files.map(([name, text]) => new window.File([text], name)), configurable: true});
}

test('status fills state pickers with names and form boxes from the server', async (t) => {
  const ui = await fixture(() => response({}));
  t.after(() => ui.window.close());
  assert.match(ui.document.getElementById('tax-tables-line').textContent, /Tax year 2025 · Built-in tables/);
  const options = [...ui.document.querySelector('[data-tax-states]').options].map((o) => o.textContent);
  assert.deepEqual(options, ['Work it out from the documents', 'California', 'Texas']);
  assert.equal(ui.document.querySelectorAll('[data-tax-form-boxes] input').length, 2);
  assert.equal(ui.document.getElementById('tax-tables-back').hidden, false);
});

test('a first draft sends the documents and shows the refund plainly', async (t) => {
  const ui = await fixture(() => response({tax_year: 2025, refund: true, balance: -1528.5, total_income: 55000,
    taxable_income: 39250, tax: 4471.5, paid: 6000, lines: [{label: 'Wages (1040 line 1a)', amount: 55000, source: 'w2.txt'}],
    documents: [{name: 'w2.txt', type: 'W-2', check: false}], open_items: ['TX: nothing to do'], carried: [],
    state: {code: 'TX', computed: true, tax: 0, balance: 0}, disclaimer: 'Draft for a preparer.', text: 'package'}));
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('tax-prepare');
  choose(ui.window, form.elements.documents, [['w2.txt', 'Form W-2 ...']]);
  form.elements.filing_status.value = 'mfj';
  form.elements.taxpayer_65.checked = true;
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  const call = ui.calls.find((c) => c.url === '/api/v1/tax/prepare');
  const body = JSON.parse(call.options.body);
  assert.deepEqual(body.documents, [{name: 'w2.txt', text: 'Form W-2 ...'}]);
  assert.equal(body.filing_status, 'mfj');
  assert.equal(body.taxpayer_65, true);
  assert.match(ui.document.getElementById('tax-prepare-status').textContent, /Draft refund of/);
  const out = ui.document.getElementById('tax-prepare-out').textContent;
  assert.match(out, /Wages \(1040 line 1a\)/);
  assert.match(out, /Texas: refund|Texas: owes/);
  assert.match(out, /Download the review package/);
});

test('readiness sends ticked states, forms and document names', async (t) => {
  const ui = await fixture(() => response({ready: false, summary: 'Not ready yet. Fix the items marked below first.',
    drafted_states: ['TX'], handed_off_states: [], forms_drafted: [], checks: [{ok: false, text: 'Some states are not recognised: ZZ.'}],
    technical: [{text: 'invalid state code(s): ZZ'}]}));
  t.after(() => ui.window.close());
  const form = ui.document.getElementById('tax-readiness');
  form.elements.firm.value = 'Smith & Co';
  form.querySelector('input[name="states"][value="TX"]').checked = true;
  form.querySelector('input[name="forms"][value="W-2"]').checked = true;
  form.elements.other_forms.value = 'Mystery form';
  ui.document.querySelector('[data-tax-add-name]').click();
  const row = form.querySelector('.tax-name-row');
  row.querySelector('[name="alias_label"]').value = 'Wage slip';
  form.dispatchEvent(new ui.window.Event('submit', {cancelable: true}));
  await ui.settle();
  const body = JSON.parse(ui.calls.find((c) => c.url === '/api/v1/tax/readiness').options.body);
  assert.deepEqual(body, {firm: 'Smith & Co', clients: 0, states: ['TX'], forms: ['W-2', 'Mystery form'],
    names: [{label: 'Wage slip', type: 'W-2'}]});
  const out = ui.document.getElementById('tax-readiness-out');
  assert.match(out.textContent, /Fix first Some states are not recognised/);
  assert.equal(out.querySelector('details').open, false);
});

test('applying tax tables asks first and a cancel sends nothing', async (t) => {
  const ui = await fixture(() => response({applied: true, tables: 'Signed update 3'}), {confirm: false});
  t.after(() => ui.window.close());
  const input = ui.document.getElementById('tax-tables-file');
  choose(ui.window, input, [['tables.json', '{}']]);
  input.dispatchEvent(new ui.window.Event('change'));
  await ui.settle();
  assert.match(ui.confirms[0], /used for every draft from now on/);
  assert.equal(ui.calls.filter((c) => c.url.endsWith('/tables/apply')).length, 0);
});

test('a refused update shows the plain server sentence', async (t) => {
  const ui = await fixture(() => response({detail: 'This update is not from a publisher you trust, so it was not applied.'}, 409));
  t.after(() => ui.window.close());
  const input = ui.document.getElementById('tax-tables-file');
  choose(ui.window, input, [['tables.json', '{}']]);
  input.dispatchEvent(new ui.window.Event('change'));
  await ui.settle();
  assert.equal(ui.document.getElementById('tax-tables-status').textContent,
    'This update is not from a publisher you trust, so it was not applied.');
});
