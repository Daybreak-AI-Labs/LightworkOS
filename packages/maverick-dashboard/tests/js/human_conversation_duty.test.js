'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const script = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-human-conversation-handoffs.js'), 'utf8');
const partial = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/_human_conversations.html'), 'utf8');
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };
const UNTIL = Math.floor(Date.now() / 1000) + 3600;

function page() {
  // The duty page: no task, no goal query; keep the duty form branch.
  const html = partial.replace(/\{% if goal is defined %\}[\s\S]*?\{% elif[^%]*%\}/, '').replace(/\{% endif %\}/g, '')
    .replace(/data-context="[^"]*"/, 'data-context="ctx"').replace(/data-goal="[^"]*"/, 'data-goal=""')
    .replace(/\{\{ ui\('([^']*)'[^}]*\}\}/g, '$1').replace(/\{\{[\s\S]*?\}\}/g, '');
  const dom = new JSDOM('<main>' + html + '</main>', {url: 'https://lightwork.invalid/human-conversations', runScripts: 'outside-only'});
  const state = {context: 'ctx', enabled: true, duty: {label: 'Help desk', until: UNTIL}, history: [], people: []};
  dom.window.fetch = async (url, options) => {
    if (url.endsWith('/duty/review')) return {ok: true, status: 200, json: async () => ({context: 'ctx', token: 't', record: 'r', operation: 'o',
      changes: [{label: 'On-duty name', after: 'Help desk'}, {label: 'Availability ends', after: 'In 1 hour'},
                {label: 'Current conversation permission', after: 'Yes'}, {label: 'If the response is lost', after: 'Read the original'}]})};
    if (url.endsWith('/apply')) return {ok: true, status: 200, json: async () => ({context: 'ctx', confirmed: true, message: 'Your reviewed duty declaration is saved.'})};
    return {ok: true, status: 200, json: async () => structuredClone(state)};
  };
  shell(dom.window);
  dom.window.eval(script);
  return dom;
}

test('a duty review asks about availability and closes after the save', async (t) => {
  const dom = page(); const doc = dom.window.document; t.after(() => dom.window.close()); await settle();
  assert.match(doc.querySelector('[data-human-current]').textContent, new RegExp('until ' + dom.window.mvTimeAbsolute(UNTIL).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  doc.querySelector('[data-human-duty-label]').value = 'Help desk';
  doc.querySelector('[data-human-duty-form]').dispatchEvent(new dom.window.Event('submit', {cancelable: true})); await settle();
  const review = doc.querySelector('[data-human-review]');
  assert.doesNotMatch(review.textContent, /selected person, pause and reply/);
  assert.match(review.textContent, /my availability/);
  const box = review.querySelector('input[type=checkbox]'); box.checked = true; box.dispatchEvent(new dom.window.Event('change'));
  [...review.querySelectorAll('button')].find(b => /Confirm/.test(b.textContent)).click(); await settle();
  assert.equal(review.querySelector('button'), null);
});
