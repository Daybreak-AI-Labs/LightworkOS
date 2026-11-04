// Run with: node --test packages/maverick-dashboard/tests/js/usability_survey.test.js
'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const settle = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve)); };
const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-usability-survey.js'), 'utf8');
const ITEMS = Array.from({length: 10}, (_, i) => 'Statement ' + (i + 1));

function load({offerSus = true, offerSeq = true, fail = false} = {}) {
  const dom = new JSDOM('<!doctype html><body><main id="content"><h1>Page</h1></main></body>',
    {url: 'https://lightwork.test/approvals', runScripts: 'outside-only'});
  const calls = [];
  dom.window.fetch = async (url, options = {}) => {
    calls.push({url, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : null});
    if (options.method === 'POST') return fail ? {ok: false, status: 500, json: async () => ({})} : {ok: true, json: async () => ({saved: true})};
    return {ok: true, json: async () => ({enabled: true, offer_sus: offerSus, offer_seq: url.includes('task=') && offerSeq,
      sus_items: ITEMS, seq_question: 'Overall, how difficult or easy was this task to complete?',
      roles: [{value: 'approver', label: 'I approve or reject requests'}],
      tasks: [{value: 'decide_approval', label: 'approve or reject a request'}]})};
  };
  shell(dom.window);
  dom.window.eval(source);
  return {window: dom.window, document: dom.window.document, calls};
}

test('the quarterly survey is a panel, never a dialog, and Not now hides it in one action', async () => {
  const {document, calls} = load();
  await settle();
  const box = document.getElementById('mv-survey-sus');
  assert.ok(box, 'the survey panel is shown');
  assert.equal(document.querySelector('dialog'), null);
  assert.notEqual(document.activeElement && document.activeElement.closest && document.activeElement.closest('#mv-survey-sus'), box);
  const later = Array.from(box.querySelectorAll('button')).find(b => b.textContent === 'Not now');
  later.click(); await settle();
  assert.deepEqual(calls.at(-1), {url: '/api/v1/usability-survey/dismiss', method: 'POST', body: {topic: 'sus'}});
  assert.match(box.textContent, /not ask about the survey again this quarter/);
  assert.equal(box.querySelector('button'), null);
});

test('all ten answers are needed, and a failed save keeps them', async () => {
  const {document, calls} = load({fail: true});
  await settle();
  const box = document.getElementById('mv-survey-sus');
  box.querySelector('button').click();
  const form = box.querySelector('form');
  for (let i = 0; i < 9; i++) form.querySelector(`input[name="sus-${i}"][value="4"]`).checked = true;
  form.dispatchEvent(new document.defaultView.Event('submit', {cancelable: true})); await settle();
  assert.match(box.textContent, /Answer statement 10/);
  assert.equal(calls.filter(c => c.method === 'POST').length, 0);
  form.querySelector('input[name="sus-9"][value="2"]').checked = true;
  form.elements.role.value = 'approver';
  form.dispatchEvent(new document.defaultView.Event('submit', {cancelable: true})); await settle();
  const sent = calls.at(-1);
  assert.equal(sent.url, '/api/v1/usability-survey/sus');
  assert.deepEqual(sent.body, {answers: [4, 4, 4, 4, 4, 4, 4, 4, 4, 2], role: 'approver'});
  assert.match(box.textContent, /still here/);
  assert.equal(form.querySelector('input[name="sus-0"][value="4"]').checked, true);
});

test('a decided approval asks the one ease question once', async () => {
  const {window, document, calls} = load({offerSus: false});
  await settle();
  assert.equal(document.getElementById('mv-survey-sus'), null);
  document.dispatchEvent(new window.CustomEvent('lightwork:approval-decided', {detail: {id: '1'}}));
  await settle();
  const box = document.getElementById('mv-survey-seq');
  assert.ok(box);
  assert.equal(box.querySelectorAll('input[name="seq"]').length, 7);
  box.querySelector('input[name="seq"][value="6"]').checked = true;
  box.querySelector('form').dispatchEvent(new window.Event('submit', {cancelable: true})); await settle();
  assert.deepEqual(calls.at(-1).body, {task: 'decide_approval', rating: 6});
  assert.match(box.textContent, /Thank you/);
  document.dispatchEvent(new window.CustomEvent('lightwork:approval-decided', {detail: {id: '2'}}));
  await settle();
  assert.equal(calls.filter(c => c.url.includes('task=decide_approval')).length, 1);
});

test('opening an old finished task does not ask; watching one finish does', async () => {
  const {window, document, calls} = load({offerSus: false});
  await settle();
  const project = status => document.dispatchEvent(new window.CustomEvent('lightwork:task-projection', {detail: {status}}));
  project('done'); await settle();
  assert.equal(calls.some(c => c.url.includes('task=run_task')), false);
  project('done'); await settle();
  assert.equal(calls.some(c => c.url.includes('task=run_task')), false);
  const second = load({offerSus: false});
  await settle();
  second.document.dispatchEvent(new second.window.CustomEvent('lightwork:task-projection', {detail: {status: 'running'}}));
  second.document.dispatchEvent(new second.window.CustomEvent('lightwork:task-projection', {detail: {status: 'done'}}));
  await settle();
  assert.equal(second.calls.some(c => c.url.includes('task=run_task')), true);
});

test('the panels arrive after the page content, so nothing already shown moves', async () => {
  const {window, document} = load();
  const heading = document.querySelector('main h1');
  await settle();
  const main = document.getElementById('content');
  assert.equal(main.firstElementChild, heading, 'the page still starts with its own heading');
  assert.equal(main.lastElementChild.id, 'mv-survey-sus');
  document.dispatchEvent(new window.CustomEvent('lightwork:approval-decided', {detail: {id: '1'}}));
  await settle();
  assert.equal(main.firstElementChild, heading);
  assert.equal(main.lastElementChild.id, 'mv-survey-seq');
  assert.match(document.getElementById('mv-survey-seq').textContent, /at the end of this page/);
});
