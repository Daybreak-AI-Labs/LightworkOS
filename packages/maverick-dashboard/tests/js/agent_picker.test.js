'use strict';
// Agent Factory's "Start from a specialist" searches /agents/picker as you
// type instead of shipping 2,031 options. It stays a combobox: focus stays in
// the field, arrows move through the matches, Enter or a click opens one.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {shell} = require('./_shell');
const {JSDOM, VirtualConsole} = require('jsdom');

const source = fs.readFileSync(path.join(__dirname, '../../maverick_dashboard/static/lightwork-agent-picker.js'), 'utf8');
const MARKUP = '<div class="af-combo"><input id="agent-picker" type="text" role="combobox" aria-autocomplete="list" ' +
  'aria-expanded="false" aria-controls="agent-picker-list" aria-label="Choose an agent or specialist to tailor" data-picker-src="/agents/picker">' +
  '<ul id="agent-picker-list" role="listbox" hidden></ul></div><button type="button" id="agent-picker-open">Open</button>' +
  '<p id="agent-picker-status" role="status"></p><label><input id="agent-show-needs-setup" type="checkbox"> Show those that need setup</label>';
const FORECAST = {name: 'fin_forecasting', label: 'Forecasting specialist', ready: true, readiness: 'Can start'};
const FORMS = {name: 'ops_forms', label: 'Form intake', ready: true, readiness: 'Can start'};
const tick = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

function page(answer) {
  const navigations = [];
  const console = new VirtualConsole();
  console.on('jsdomError', error => { if (/navigation/.test(error.message)) navigations.push(error.message); });
  const dom = new JSDOM(MARKUP, {url: 'http://localhost/agents', runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: console});
  shell(dom.window);
  const requests = [], toasts = [];
  dom.window.fetch = async url => {
    requests.push(String(url));
    const query = new URL(String(url), 'http://localhost').searchParams;
    const body = await answer(query);
    if (body instanceof Error) throw body;
    return {ok: true, status: 200, json: async () => body};
  };
  dom.window.mvToast = (text, options) => toasts.push([text, options]);
  dom.window.eval(source);
  const doc = dom.window.document;
  const input = doc.getElementById('agent-picker');
  const key = name => input.dispatchEvent(new dom.window.KeyboardEvent('keydown', {key: name, bubbles: true, cancelable: true}));
  return {dom, doc, input, key, requests, toasts, navigations, list: doc.getElementById('agent-picker-list'),
          status: doc.getElementById('agent-picker-status')};
}
const byQuery = query => {
  const q = query.get('q').toLowerCase();
  const items = [FORECAST, FORMS].filter(item => item.label.toLowerCase().includes(q) || item.name === query.get('q'));
  return {items, total: q === 'for' ? 37 : items.length, limit: 20};
};

test('typing searches the server and shows the matches as a listbox', async () => {
  const ui = page(byQuery);
  ui.input.focus();
  ui.input.value = 'for';
  ui.input.dispatchEvent(new ui.dom.window.Event('input', {bubbles: true}));
  assert.equal(ui.requests.length, 0, 'searches wait for a pause in typing');
  await tick(200);
  assert.deepEqual(ui.requests, ['/agents/picker?q=for']);
  const options = ui.list.querySelectorAll('[role="option"]');
  assert.equal(options.length, 2);
  assert.equal(options[0].id, 'agent-picker-option-0');
  assert.equal(options[0].getAttribute('aria-selected'), 'false');
  assert.equal(options[0].textContent, 'Forecasting specialistCan start');
  assert.equal(ui.list.hidden, false);
  assert.equal(ui.input.getAttribute('aria-expanded'), 'true');
  assert.equal(ui.status.textContent, '2 of 37 matches. Keep typing to narrow the list.');
  assert.equal(ui.doc.activeElement, ui.input, 'focus stays in the field');
  ui.dom.window.close();
});

test('arrow keys move through the matches and Enter opens the highlighted one', async () => {
  const ui = page(byQuery);
  ui.input.focus();
  ui.input.value = 'for';
  ui.key('ArrowDown');  // a closed list searches at once
  await tick();
  assert.equal(ui.input.getAttribute('aria-activedescendant'), 'agent-picker-option-0');
  assert.equal(ui.list.children[0].getAttribute('aria-selected'), 'true');
  ui.key('ArrowDown');
  assert.equal(ui.input.getAttribute('aria-activedescendant'), 'agent-picker-option-1');
  assert.equal(ui.list.children[0].getAttribute('aria-selected'), 'false');
  ui.key('ArrowDown');  // wraps to the first
  assert.equal(ui.input.getAttribute('aria-activedescendant'), 'agent-picker-option-0');
  ui.key('ArrowUp');
  assert.equal(ui.input.getAttribute('aria-activedescendant'), 'agent-picker-option-1');
  ui.key('Enter');
  assert.equal(ui.input.value, 'Form intake');
  assert.equal(ui.list.hidden, true);
  assert.equal(ui.input.getAttribute('aria-expanded'), 'false');
  assert.equal(ui.input.hasAttribute('aria-activedescendant'), false);
  assert.equal(ui.navigations.length, 1, 'the chosen specialist opens');
  ui.dom.window.close();
});

test('Escape closes the list and keeps the text; leaving the field closes it too', async () => {
  const ui = page(byQuery);
  ui.input.focus();
  ui.input.value = 'for';
  ui.key('ArrowDown');
  await tick();
  ui.key('Escape');
  assert.equal(ui.list.hidden, true);
  assert.equal(ui.input.value, 'for');
  ui.key('ArrowDown');  // the same matches reopen without another request
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.list.hidden, false);
  ui.input.blur();
  assert.equal(ui.list.hidden, true);
  ui.dom.window.close();
});

test('a click opens a match without taking focus from the field first', async () => {
  const ui = page(byQuery);
  ui.input.focus();
  ui.input.value = 'forecast';
  ui.key('ArrowDown');
  await tick();
  const option = ui.list.children[0];
  const down = new ui.dom.window.MouseEvent('mousedown', {bubbles: true, cancelable: true});
  option.dispatchEvent(down);
  assert.equal(down.defaultPrevented, true);
  option.click();
  assert.equal(ui.input.value, 'Forecasting specialist');
  assert.equal(ui.navigations.length, 1);
  ui.dom.window.close();
});

test('Open and Enter open only an exact name, otherwise they explain', async () => {
  const ui = page(byQuery);
  ui.input.value = 'FORECASTING SPECIALIST';
  ui.doc.getElementById('agent-picker-open').click();
  await tick();
  assert.equal(ui.navigations.length, 1);
  ui.input.value = 'fin_forecasting';  // the pack name works as before
  ui.key('Enter');
  await tick();
  assert.equal(ui.navigations.length, 2);
  ui.input.value = 'fore';
  ui.doc.getElementById('agent-picker-open').click();
  await tick();
  assert.equal(ui.navigations.length, 2);
  assert.equal(ui.toasts.at(-1)[0], 'Choose an agent or specialist from the list, or show those needing setup.');
  assert.equal(ui.toasts.at(-1)[1].error, true);
  ui.input.value = '';
  ui.doc.getElementById('agent-picker-open').click();
  await tick();
  assert.equal(ui.toasts.length, 2);
  ui.dom.window.close();
});

test('specialists that need setup are asked for only when shown', async () => {
  const ui = page(query => ({items: query.get('setup') ? [FORECAST] : [], total: query.get('setup') ? 1 : 0, limit: 20}));
  ui.input.focus();
  ui.input.value = 'payable';
  ui.key('ArrowDown');
  await tick();
  assert.equal(ui.status.textContent, 'No ready agents or specialists match. Choose "Show those that need setup" to include the rest.');
  assert.equal(ui.list.hidden, true);
  const box = ui.doc.getElementById('agent-show-needs-setup');
  box.checked = true;
  box.dispatchEvent(new ui.dom.window.Event('change', {bubbles: true}));
  await tick();
  assert.equal(ui.requests.at(-1), '/agents/picker?q=payable&setup=1');
  assert.equal(ui.status.textContent, '1 match.');
  ui.dom.window.close();
});

test('a slower earlier answer never replaces a newer one', async () => {
  let release;
  const ui = page(query => query.get('q') === 'f' ? new Promise(resolve => { release = () => resolve({items: [FORMS], total: 1, limit: 20}); })
    : {items: [FORECAST], total: 1, limit: 20});
  ui.input.focus();
  ui.input.value = 'f';
  ui.key('ArrowDown');
  ui.input.value = 'forecast';
  ui.input.dispatchEvent(new ui.dom.window.Event('input', {bubbles: true}));
  await tick(200);
  release();
  await tick();
  assert.equal(ui.list.children.length, 1);
  assert.equal(ui.list.children[0].firstChild.textContent, 'Forecasting specialist');
  ui.dom.window.close();
});

test('clearing the field closes the list; Down shows the first specialists', async () => {
  const ui = page(query => ({items: query.get('q') ? [FORMS] : [FORECAST, FORMS], total: query.get('q') ? 1 : 1066, limit: 20}));
  ui.input.focus();
  ui.input.value = 'form';
  ui.key('ArrowDown');
  await tick();
  assert.equal(ui.list.hidden, false);
  ui.input.value = '';
  ui.input.dispatchEvent(new ui.dom.window.Event('input', {bubbles: true}));
  assert.equal(ui.list.hidden, true);
  assert.equal(ui.status.textContent, '');
  await tick(200);
  assert.equal(ui.requests.length, 1, 'an empty field does not search by itself');
  ui.key('ArrowDown');
  await tick();
  assert.equal(ui.requests.at(-1), '/agents/picker?q=');
  assert.equal(ui.list.children.length, 2);
  assert.equal(ui.status.textContent, '2 of 1066 matches. Keep typing to narrow the list.');
  ui.dom.window.close();
});

test('a failed search says so and closes the list', async () => {
  const ui = page(() => new Error('offline'));
  ui.dom.window.mvErrorText = (_failure, what) => 'Could not ' + what + '.';
  ui.input.focus();
  ui.input.value = 'for';
  ui.key('ArrowDown');
  await tick();
  assert.equal(ui.status.textContent, 'Could not search the agents and specialists.');
  assert.equal(ui.list.hidden, true);
  assert.equal(ui.input.getAttribute('aria-expanded'), 'false');
  ui.dom.window.close();
});
