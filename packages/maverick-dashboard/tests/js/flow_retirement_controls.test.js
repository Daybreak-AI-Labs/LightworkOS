'use strict';

const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const source = fs.readFileSync(path.resolve(__dirname,
  '../../maverick_dashboard/static/lightwork-flow-retirement.js'), 'utf8');

test('saved flows show their actual status and only published flows can be turned off', async (t) => {
  const dom = new JSDOM(`<ul>
    <li><div data-flow-status="active"></div><button data-flow-retire="off">Turn off</button><button data-flow-retire="delete">Delete flow</button></li>
    <li><div data-flow-status="draft"></div><button data-flow-retire="off">Turn off</button><button data-flow-retire="delete">Delete flow</button></li>
  </ul>`, {url: 'https://lightwork.example/workflows', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const {window} = dom, calls = [], confirms = [], toasts = [];
  const reply = (value) => new Response(JSON.stringify(value), {headers: {'Content-Type': 'application/json'}});
  window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    if (url === '/api/v1/flows') return reply({flows: [
      {id: 'active', published: true}, {id: 'draft', published: false}]});
    if (url === '/api/v1/flows/active/retirement') return reply({
      id: 'active', name: 'Order review', version: 2, revision: 'draft-2', published: true,
      release_id: 'a'.repeat(64), scheduled: true, connected_starts: 1,
      active_runs: 1, pending_forms: 0, published_parent_flows: 0});
    if (url === '/api/v1/flows/active/unpublish') return reply({id: 'active', published: false});
    throw new Error('Unexpected request: ' + url);
  };
  window.mvConfirm = async (message) => { confirms.push(message); return true; };
  window.mvToast = (message) => toasts.push(message);
  window.eval(source);
  window.dispatchEvent(new window.Event('load'));
  const settle = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve)); };
  await settle();

  const labels = window.document.querySelectorAll('[data-flow-status]');
  const off = window.document.querySelectorAll('[data-flow-retire="off"]');
  assert.match(labels[0].textContent, /Published/);
  assert.match(labels[1].textContent, /turned off/);
  assert.equal(off[0].disabled, false);
  assert.equal(off[1].disabled, true);

  const changed = await window.LightworkFlowRetirement.change('active', 'off', {button: off[0]});
  assert.equal(changed, true);
  assert.match(confirms[0], /schedule will stop/i);
  assert.equal(calls.filter(call => call.url.endsWith('/unpublish')).length, 1);
  assert.equal(toasts.at(-1), 'Flow turned off.');
});
