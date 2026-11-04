'use strict';
// Page scripts for operations that also exist on the command line: each sends
// nothing until the person acts, confirms destructive or outside actions with
// mvConfirm (declining sends nothing), and shows plain results and errors.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const folder = path.resolve(__dirname, '../../maverick_dashboard');
const read = name => fs.readFileSync(path.join(folder, name), 'utf8').replace(/\r\n?/g, '\n');
// These controller fixtures represent an authorized operator render.
const strip = html => html.replace(/\{% if not can_operate %\}[\s\S]*?\{% endif %\}/g, '').replace(/\{%[\s\S]*?%\}/g, '').replace(/\{\{[\s\S]*?\}\}/g, '1').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
function slice(template, start, end) {
  const text = read('templates/' + template);
  const from = text.indexOf(start);
  assert.ok(from >= 0, start);
  const to = text.indexOf(end, from);
  assert.ok(to > from, template + ': missing end marker ' + end);
  return text.slice(from, to + end.length);
}

async function page(markup, script, reply, { confirm = true, shell = true, before = [], realTimers = false } = {}) {
  const dom = new JSDOM('<main>' + strip(markup) + '</main>', { url: 'https://app.example/x', runScripts: 'outside-only' });
  const w = dom.window, calls = [], asked = [];
  // shell: the page script uses the shell's shared helpers (mvFetchJSON,
  // mvStatus), which load before any page script as in base.html; the stubs
  // below still stand in for the rest.
  if (shell) {
    w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    w.eval(read('static/lightwork-ui.js'));
  }
  w.mvErrorText = (failure, action) => 'Could not ' + action + '. Plain message.';
  w.mvConfirm = async message => { asked.push(message); return confirm; };
  w.mvWhen = () => 'soon';
  // Waits run at once, unless the page bounds its requests with a timeout
  // (mvFetchJSON's timeout would otherwise expire before the reply).
  if (!realTimers) w.setTimeout = fn => { fn(); return 0; };
  // jsdom has no layout: scrolling a review into view does nothing here.
  w.Element.prototype.scrollIntoView = function () {};
  w.fetch = async (url, options = {}) => {
    calls.push({ url, options });
    const out = await reply(url, options);
    return out instanceof Response ? out : new Response(JSON.stringify(out));
  };
  // Inline helpers the page template includes ahead of its own script.
  before.forEach(name => w.eval(read(name)));
  w.eval(read('static/' + script));
  const settle = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };
  await settle();
  return { w, d: w.document, calls, asked, settle, $: id => w.document.getElementById(id) };
}

test('task journal lists, previews and undoes only after a confirmation', async t => {
  const markup = slice('task_file_recovery.html', '<section id="task-journal"', '</section>');
  const context = 'c'.repeat(64);
  const reply = (url, options) => {
    if (url.endsWith('/journal')) return { context, available: true, count: 1, entries: [{ file: 'notes.txt', change: 'existed', saved: true }], more: 0, incomplete: false, recording: true };
    const body = JSON.parse(options.body);
    return body.preview ? { context, available: true, preview: true, done: false, restored: 1, removed: 0, skipped: 0, complete: true }
      : { context, available: true, preview: false, done: true, restored: 1, removed: 0, skipped: 0, complete: true };
  };
  const declined = await page(markup, 'lightwork-task-journal.js', reply, { confirm: false });
  t.after(() => declined.w.close());
  assert.equal(declined.calls.length, 0, 'nothing is loaded until asked');
  declined.$('tj-preview').click();
  await declined.settle();
  assert.equal(declined.$('tj-review').hidden, false);
  assert.match(declined.$('tj-plan').textContent, /put back 1 file/);
  declined.$('tj-undo').click();
  await declined.settle();
  assert.match(declined.asked[0], /can’t be reversed/);
  assert.equal(declined.calls.filter(c => c.options.body && JSON.parse(c.options.body).preview === false).length, 0);
  const ui = await page(markup, 'lightwork-task-journal.js', reply);
  t.after(() => ui.w.close());
  ui.$('tj-preview').click();
  await ui.settle();
  ui.$('tj-undo').click();
  await ui.settle();
  const sent = JSON.parse(ui.calls.at(-1).options.body);
  assert.deepEqual([sent.preview, sent.confirm, sent.context], [false, true, context]);
  assert.match(ui.$('tj-status').textContent, /Put back 1 file/);
});

test('sharing a task on GitHub reviews exact content before uploading and shows only a safe link', async t => {
  const markup = '<div id="goal-export" data-goal="7"><button id="goal-gist"></button><p id="goal-export-msg"></p></div>';
  const fixture = async url => page(markup, 'lightwork-goal-export.js', endpoint => {
    if (endpoint.endsWith('/attempts')) return {attempts:[]};
    if (endpoint.endsWith('/preview')) return {account:'Synthetic account',scope:'Selected task',payload:{description:'Reviewed synthetic content'},preview_id:'review-1',sha256:'a'.repeat(64)};
    return {shared:true,url};
  });
  const ui = await fixture('https://gist.github.com/a');t.after(()=>ui.w.close());
  assert.equal(ui.calls.filter(c=>c.options.method==='POST').length,0);
  ui.$('goal-gist').click();await ui.settle();
  assert.equal(ui.calls.filter(c=>c.url==='/api/v1/goals/7/share/gist').length,0,'preview does not upload');
  assert.match(ui.d.querySelector('#goal-export pre').textContent,/Reviewed synthetic content/);
  Array.from(ui.d.querySelectorAll('#goal-export button')).find(b=>b.textContent==='Upload this reviewed copy').click();await ui.settle();
  const write=ui.calls.find(c=>c.url==='/api/v1/goals/7/share/gist');
  assert.deepEqual(JSON.parse(write.options.body),{confirm:true,preview_id:'review-1',sha256:'a'.repeat(64)});
  assert.equal(ui.d.querySelector('#goal-export-msg a').href,'https://gist.github.com/a');
  const bad=await fixture('javascript:alert(1)');t.after(()=>bad.w.close());
  bad.$('goal-gist').click();await bad.settle();
  Array.from(bad.d.querySelectorAll('#goal-export button')).find(b=>b.textContent==='Upload this reviewed copy').click();await bad.settle();
  assert.equal(bad.d.querySelector('#goal-export-msg a'),null);
});

test('the schedule picker sends plain choices and a chosen time zone, never a typed timetable', async t => {
  // The original-creation panel the picker reports to, then the form.
  const markup = slice('automations.html', '<section class="auto__section panel auto__original" id="auto-create-original"', '</section>') +
    slice('automations.html', '<details id="auto-new-sched"', '</details>\n  </section>');
  const context = 'c'.repeat(64);
  const ui = await page(markup, 'lightwork-schedule-picker.js', (url, options) => {
    if (url.endsWith('/options')) return { context, zones: ['UTC', 'Europe/Paris'], workflows: [], tasks: [{ id: 4, title: 'Weekly notes' }] };
    if (url.endsWith('/preview')) return { cron: '0 9 * * *', zone: 'UTC', next_runs: [1, 2, 3] };
    if (url.endsWith('/create-review')) return { context, title: 'Weekly notes', earlier_task: 'Weekly notes', work: 'Run the earlier task again',
      inputs: {}, next_runs: [1, 2], notice: 'Nothing runs until the first time shown.', reference: 'r'.repeat(32), operation: 'o'.repeat(32) };
    return { context, found: true, title: 'Weekly notes', message: 'Schedule created.', execution: 'It first runs at its next time.' };
  }, { shell: true, realTimers: true });
  t.after(() => ui.w.close());
  ui.$('auto-new-sched').open = true;
  ui.$('auto-new-sched').dispatchEvent(new ui.w.Event('toggle'));
  await ui.settle();
  assert.equal(ui.$('auto-new-zone').options.length, 2);
  ui.d.querySelector('input[name="what"][value="rerun"]').checked = true;
  ui.$('auto-new-rerun').value = '4';
  ui.$('auto-new-repeat').value = 'weekly';
  ui.$('auto-new-zone').value = 'Europe/Paris';
  ui.$('auto-new-form').dispatchEvent(new ui.w.Event('submit', { cancelable: true }));
  await ui.settle();
  assert.equal(ui.calls.some(c => c.url === '/api/v1/schedules/add'), false, 'a review comes first');
  assert.equal(ui.$('auto-new-review').hidden, false);
  ui.$('auto-new-confirm').click();
  await ui.settle();
  const add = ui.calls.find(c => c.url === '/api/v1/schedules/add');
  const body = JSON.parse(add.options.body);
  assert.equal(body.review_reference, 'r'.repeat(32));
  assert.equal(body.confirmed, true);
  assert.equal(body.what, 'rerun');
  assert.equal(body.goal_id, 4);
  assert.equal(body.timetable.repeat, 'weekly');
  assert.equal(body.timetable.zone, 'Europe/Paris');
  assert.deepEqual(body.timetable.days, [1]);
  assert.equal(body.timetable.advanced, undefined);
  assert.match(ui.$('auto-create-original-message').textContent, /Schedule created/);
});

test('library templates are added only by administrators after a confirmation', async t => {
  const markup = slice('templates_market.html', '<section class="panel tplm__library"', '</section>');
  const reply = url => url.endsWith('/add') ? { added: true, name: 'weekly-digest' }
    : { available: true, can_add: true, templates: [{ name: 'weekly-digest', summary: '<b>Weekly</b>', rating: 0, ratings: 0, installed: false }] };
  const ui = await page(markup, 'lightwork-community-templates.js', reply);
  t.after(() => ui.w.close());
  ui.$('tplm-library-load').click();
  await ui.settle();
  assert.equal(ui.d.querySelector('#tplm-library-list b'), null, 'summaries are text');
  ui.d.querySelector('#tplm-library-list button').click();
  await ui.settle();
  assert.match(ui.asked[0], /outside your organisation/);
  assert.deepEqual(JSON.parse(ui.calls.at(-1).options.body), { name: 'weekly-digest', confirm: true });
});

test('business specialist setup drafts, shows the draft plainly and approves by draft only', async t => {
  const markup = slice('agents.html', '<details class="af-card" id="biz-setup"', '</details>');
  const agent = { name: 'acme_bakery', summary: 'Bakery helper', risk: 'low', can_use: ['web_search'], cannot_use: [], refuses: [],
    instructions: 'Be kind', steps: [{ name: 'Read', instruction: 'Read orders', review: false }], gaps: [] };
  const ui = await page(markup, 'lightwork-business-agent.js', (url, options) => {
    if (url.endsWith('/draft')) return { job: 'd'.repeat(32) };
    if (url.endsWith('/approve')) return { job: 'e'.repeat(32) };
    if (url.includes('step=approve')) return { state: 'done', result: { saved: true, name: 'acme_bakery', documents_loaded: 0, message: '' } };
    return { state: 'done', result: { ran: true, with_ai: false, agent } };
  });
  t.after(() => ui.w.close());
  ui.$('biz-name').value = 'Acme Bakery';
  ui.$('biz-form').dispatchEvent(new ui.w.Event('submit', { cancelable: true }));
  await ui.settle();
  assert.equal(ui.$('biz-review').hidden, false);
  assert.match(ui.$('biz-summary').textContent, /Bakery helper/);
  ui.$('biz-approve').click();
  await ui.settle();
  const approve = ui.calls.find(c => c.url.endsWith('/approve'));
  assert.ok(approve.options.body instanceof ui.w.FormData, 'the pack itself is never sent back');
  assert.equal(approve.options.body.get('confirm'), 'true');
  // Adding opens the new agent's editor; that next page says it was added.
  const added = JSON.parse(ui.w.sessionStorage.getItem('lightwork-business-agent-added'));
  assert.equal(added.name, 'acme_bakery');
  ui.w.eval(read('static/lightwork-business-agent.js'));
  assert.match(ui.$("biz-status").textContent, /Added “Acme bakery”/);
  assert.equal(ui.w.sessionStorage.getItem('lightwork-business-agent-added'), null);
});

test('Ekko recording needs the consent box and reports counts plainly', async t => {
  const markup = slice('ekko.html', '<section class="card ekko-panel" id="ekko-recording"', '</section>');
  const ui = await page(markup, 'lightwork-ekko-recording.js', url => url.endsWith('/options') ? { windows_active_app: false }
    : url.endsWith('/import') ? { job: 'f'.repeat(32) } : { state: 'done', result: { recorded: 2, skipped: 1 } });
  t.after(() => ui.w.close());
  assert.equal(ui.$('ekko-rec-watch').hidden, true);
  ui.$('ekko-rec-import').click();
  await ui.settle();
  assert.match(ui.$('ekko-rec-msg').textContent, /Tick the box/);
  assert.equal(ui.calls.filter(c => c.url.endsWith('/import')).length, 0);
});

test('planning steps run in the background and show the plan as text', async t => {
  const markup = slice('chat_goal.html', '<details class="panel planning-steps"', '</details>');
  const ui = await page(markup, 'lightwork-planning-steps.js', url => url.endsWith('/planning-steps') ? { job: 'a'.repeat(32) }
    : { state: 'done', result: { ran: true, plan: ['<i>Read</i>', 'Write'], steps: [{ step: 'Read', output: 'ok' }], reviews: [{ verdict: 'done', notes: 'Fine' }], status: 'done', cost: 0.02 } });
  t.after(() => ui.w.close());
  assert.equal(ui.calls.length, 0);
  ui.$('ps-run').click();
  await ui.settle();
  assert.equal(ui.$('ps-result').hidden, false);
  assert.equal(ui.d.querySelector('#ps-result i'), null);
  assert.match(ui.$('ps-result').textContent, /Nothing about the task was changed/);
});

test('teach page learns a rule, and saving the draft needs a confirmation', async t => {
  const markup = read('templates/flow_teach.html').split('{% block content %}')[1].split('<style>')[0];
  const artifact = { spec: { inputs: { amount: { type: 'integer' } }, output_type: 'boolean' } };
  const reply = (url, options) => {
    if (url === '/api/v1/flows/1/teach') return { flow: { id: 'billing', name: 'Billing', version: 1, revision: 'r' }, steps: [{ id: 'decide', label: 'Decide', ready: true, rule: null }], tools: ['web_search'] };
    if (url.endsWith('/teach/examples')) return { available: true, runs: [] };
    if (url.endsWith('/approved')) return { recipes: [] };
    if (url.endsWith('/rule/learn')) return { artifact, summary: { rules: 2, examples: 4, inputs: [{ name: 'amount', kind: 'integer' }] } };
    if (url.endsWith('/rule/attach')) return { draft: { id: 'billing' }, note: 'Save to keep this change.' };
    return { id: 'billing', version: 2 };
  };
  const ui = await page(markup, 'lightwork-flow-teach.js', reply, { confirm: false, before: ['templates/flow_designer_inputs.js'] });
  t.after(() => ui.w.close());
  assert.equal(ui.$('tr-step').value, 'decide');
  // Every whole-number example value must be entered before learning.
  ui.$('tr-learn').click();
  await ui.settle();
  assert.equal(ui.calls.filter(c => c.url.endsWith('/rule/learn')).length, 0);
  assert.match(ui.$('ft-status').textContent, /Complete the highlighted example value/);
  ui.d.querySelectorAll('#tr-examples [data-input]').forEach((control, i) => { control.value = String(10 + i * 490); });
  ui.$('tr-learn').click();
  await ui.settle();
  const learn = JSON.parse(ui.calls.find(c => c.url.endsWith('/rule/learn')).options.body);
  assert.equal(learn.inputs[0].kind, 'integer');
  assert.equal(learn.examples.length, 2);
  assert.match(ui.$('tr-summary').textContent, /2 rules fit your 4 examples/);
  ui.$('tr-attach').click();
  await ui.settle();
  assert.equal(ui.$('ft-save').hidden, false);
  ui.$('ft-save-go').click();
  await ui.settle();
  assert.match(ui.asked[0], /next version/);
  assert.equal(ui.calls.filter(c => c.url === '/api/v1/flows').length, 0, 'declining saves nothing');
});

test('teach page still loads when reviewed-run learning is unavailable', async t => {
  const base = read('templates/flow_teach.html').split('{% block content %}')[1].split('<style>')[0];
  const markup = base.replace(/<section class="panel ft__section" id="teach-recipe"[\s\S]*?<\/section>/,
    '<section class="panel ft__section" id="teach-recipe">Signed examples are unavailable.</section>');
  const ui = await page(markup, 'lightwork-flow-teach.js', url => {
    if (url.endsWith('/teach')) return { flow: { id: 'billing', name: 'Billing', version: 1 }, steps: [], tools: [] };
    if (url.endsWith('/teach/examples')) return { available: false, runs: [] };
    return { recipes: [] };
  }, { before: ['templates/flow_designer_inputs.js'] });
  t.after(() => ui.w.close());
  assert.equal(ui.$('rc-learn'), null);
  assert.equal(ui.$('rc-draft'), null);
  assert.match(ui.$('ft-status').textContent, /^$/);
  assert.equal(ui.d.querySelector('#teach-rules') !== null, true);
});

test('a run at its first approval is kept as an example with plain, editable data descriptions', async t => {
  const markup = slice('flow_run.html', '<section class="panel fr__example" id="lx-card"', '</section>');
  const object = props => ({ type: 'object', properties: props, required: Object.keys(props), additionalProperties: false });
  const prepared = { expected_pause_binding: 'p'.repeat(64), allowed_tools: ['lookup'], max_days: 7,
    suggestion: { input_schema: object({ ref: { type: 'string', maxLength: 1024 } }),
      tool_data_schemas: { lookup: { arguments: object({ query: { type: 'string', maxLength: 1024 } }), result: object({}) } },
      unknown_results: ['lookup'] } };
  const ui = await page(markup, 'lightwork-learning-capture.js', (url, options) => {
    if (url.includes('/learning-example-decisions/')) return new Response('{}', { status: 404 });
    if (url.endsWith('/suggestion')) return prepared;
    return { status: 'enrolled', revision: 1 };
  });
  t.after(() => ui.w.close());
  assert.equal(ui.$('lx-enroll').hidden, false);
  assert.match(ui.$('lx-describe').textContent, /hasn’t seen what “lookup” gives back yet/i);
  assert.equal(ui.d.querySelectorAll('#lx-describe select').length, 5, 'every part has a kind chosen from a list');
  const groups = Array.from(ui.d.querySelectorAll('#lx-describe fieldset'));
  const result = groups.find(g => /gives back/.test(g.querySelector('legend').textContent));
  result.querySelector('input[type=text]').value = 'customer_id';
  result.querySelector('button.btn--ghost:not([aria-label^="Remove"])').click();
  await ui.settle();
  ui.$('lx-enroll-go').click();
  await ui.settle();
  assert.match(ui.asked[0], /learning example/);
  const sent = JSON.parse(ui.calls.at(-1).options.body);
  assert.equal(sent.expected_pause_binding, 'p'.repeat(64));
  assert.deepEqual(sent.tool_data_schemas.lookup.result.required, ['customer_id']);
  assert.ok(sent.retain_until > Date.now() / 1000);
  assert.match(ui.$('lx-status').textContent, /being kept as a learning example/);
});

// Decisions on a kept example are reviewed in full, then confirmed once with
// a ticked box (/api/v1/learning-example-decisions/<flow>/<run>).
const EXAMPLE_CONTEXT = 'c'.repeat(64);
function decisions(state, { review, apply } = {}) {
  return (url, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null;
    if (url.endsWith('/history')) return { context: EXAMPLE_CONTEXT, choices: [] };
    if (url.endsWith('/review')) return review ? review(body) : { context: EXAMPLE_CONTEXT, token: 'sealed-' + body.kind,
      operation: 'f'.repeat(32), changes: [{ label: 'Decision', after: body.kind }, { label: 'Reason', after: body.reason }] };
    if (url.endsWith('/apply')) return apply ? apply(body) : { context: EXAMPLE_CONTEXT, message: 'Your decision is recorded.' };
    if (url.endsWith('/learning-example-decisions/1/1')) return { context: EXAMPLE_CONTEXT, record: state.record, changes: state.changes };
    throw new Error('unexpected request ' + url);
  };
}
async function confirmReview(ui) {
  const host = ui.$('lx-decision-review'), box = host.querySelector('input[type=checkbox]');
  const save = [...host.querySelectorAll('button')].find(b => /^Confirm/.test(b.textContent));
  assert.equal(save.disabled, true, 'nothing is confirmed before the box is ticked');
  box.checked = true; box.dispatchEvent(new ui.w.Event('change'));
  save.click();
  await ui.settle();
}

test('a finished example is reviewed, then learning is allowed only after a confirmation', async t => {
  const markup = slice('flow_run.html', '<section class="panel fr__example" id="lx-card"', '</section>');
  const retain = Date.now() / 1000 + 5 * 86400;
  const state = { record: { status: 'awaiting_review', revision: 4, episode_sha256: 'e'.repeat(64), retain_until: retain },
    changes: [{ label: 'What the run started with', after: 'ref: <b>A-1</b>' }, { label: 'What “lookup” gave back', after: 'customer id: C9' }] };
  const ui = await page(markup, 'lightwork-learning-capture.js', decisions(state, {
    apply: body => {
      state.record = body.token === 'sealed-accept' ? { ...state.record, status: 'accepted', revision: 5 }
        : { ...state.record, status: 'accepted', revision: 6, grant_sha256: 'g'.repeat(64), training_available: true };
      return { context: EXAMPLE_CONTEXT, message: 'Your decision is recorded.' };
    } }));
  t.after(() => ui.w.close());
  assert.equal(ui.$('lx-review').hidden, false);
  assert.equal(ui.d.querySelector('#lx-evidence b'), null, 'recorded values are shown as text');
  assert.match(ui.$('lx-evidence').textContent, /customer id: C9/);
  ui.$('lx-accept').click();
  await ui.settle();
  assert.match(ui.$('lx-status').textContent, /Enter a brief reason/);
  ui.$('lx-review-reason').value = 'Matches the real order.';
  ui.$('lx-accept').click();
  await ui.settle();
  const review = JSON.parse(ui.calls.find(c => c.url.endsWith('/review')).options.body);
  assert.deepEqual(review, { context: EXAMPLE_CONTEXT, kind: 'accept', reason: 'Matches the real order.' });
  assert.equal(ui.calls.filter(c => c.url.endsWith('/apply')).length, 0, 'reviewing changes nothing');
  await confirmReview(ui);
  assert.deepEqual(JSON.parse(ui.calls.find(c => c.url.endsWith('/apply')).options.body), { token: 'sealed-accept', confirmed: true });
  assert.equal(ui.$('lx-grant').hidden, false);
  ui.$('lx-grant-reason').value = 'Teach the order flow.';
  ui.$('lx-grant-copies').checked = true;
  ui.$('lx-grant-go').click();
  await ui.settle();
  const grant = JSON.parse(ui.calls.filter(c => c.url.endsWith('/review')).at(-1).options.body);
  assert.equal(grant.kind, 'grant');
  assert.equal(grant.retain_copies, true);
  assert.ok(grant.use_until < retain);
  await confirmReview(ui);
  assert.equal(ui.calls.filter(c => c.url.endsWith('/apply')).length, 2);
  assert.equal(ui.$('lx-next').hidden, false);
});

test('learning capture distinguishes an unavailable check from an ineligible run and can refresh', async t => {
  const markup = slice('flow_run.html', '<section class="panel fr__example" id="lx-card"', '</section>');
  let available = false;
  const suggestion = { expected_pause_binding: 'p'.repeat(64), allowed_tools: [], max_days: 7,
    suggestion: { input_schema: { type: 'object', properties: {}, required: [], additionalProperties: false },
      tool_data_schemas: {}, unknown_results: [] } };
  const ui = await page(markup, 'lightwork-learning-capture.js', url => {
    if (url.includes('/learning-example-decisions/')) return new Response('{}', { status: 404 });
    if (url.endsWith('/suggestion')) return available ? suggestion : new Response('{}', { status: 503 });
    throw new Error('unexpected request');
  });
  t.after(() => ui.w.close());
  assert.equal(ui.$('lx-enroll').hidden, true);
  assert.match(ui.$('lx-status').textContent, /could not check this run’s learning status/i);
  assert.doesNotMatch(ui.$('lx-status').textContent, /can’t become a learning example/);

  available = true;
  ui.$('lx-refresh').click();
  await ui.settle();
  assert.equal(ui.$('lx-enroll').hidden, false);
  assert.match(ui.$('lx-status').textContent, /waiting at its first approval/);
});

test('learning capture does not mistake denied status for a missing example', async t => {
  const markup = slice('flow_run.html', '<section class="panel fr__example" id="lx-card"', '</section>');
  const ui = await page(markup, 'lightwork-learning-capture.js', () => new Response('{}', { status: 403 }));
  t.after(() => ui.w.close());

  assert.match(ui.$('lx-status').textContent, /not available to your account/);
  assert.equal(ui.$('lx-enroll').hidden, true);
  assert.equal(ui.$('lx-review').hidden, true);
  assert.equal(ui.$('lx-grant').hidden, true);
  assert.equal(ui.calls.length, 1, 'denial does not trigger a second lookup or a write');
  assert.equal(ui.$('lx-refresh').disabled, false);
});

test('uncertain review clears stale controls and only a fresh status check reveals the result', async t => {
  const markup = slice('flow_run.html', '<section class="panel fr__example" id="lx-card"', '</section>');
  const pending = { status: 'awaiting_review', revision: 4, episode_sha256: 'e'.repeat(64), retain_until: Date.now() / 1000 + 5 * 86400 };
  const state = { record: pending, changes: [{ label: 'What the run started with', after: 'nothing' }] };
  const ui = await page(markup, 'lightwork-learning-capture.js', decisions(state, {
    apply: () => {
      state.record = { ...pending, status: 'accepted', revision: 5 };
      throw new Error('connection lost after the decision');
    } }));
  t.after(() => ui.w.close());
  ui.$('lx-review-reason').value = 'This example matches the finished run.';
  ui.$('lx-accept').click();
  await ui.settle();
  await confirmReview(ui);
  assert.equal(ui.$('lx-decision-review').textContent, '', 'the stale review is gone');
  assert.equal(ui.$('lx-original').hidden, false);
  assert.match(ui.$('lx-original-status').textContent, /could not be confirmed.*nothing will be submitted again/i);
  assert.equal(ui.$('lx-review-reason').value, 'This example matches the finished run.', 'the entered reason is kept');
  assert.equal(ui.calls.filter(c => c.url.endsWith('/apply')).length, 1);

  ui.$('lx-refresh').click();
  await ui.settle();
  assert.equal(ui.$('lx-grant').hidden, false);
  assert.equal(ui.calls.filter(c => c.url.endsWith('/apply')).length, 1, 'refresh never replays a decision');
});
