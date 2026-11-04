// Run with: node --test packages/maverick-dashboard/tests/js/research_plain_registry.test.js
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');

const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-research-plain.js'), 'utf8');

test('refused reads release their responses so the page can go quiet', async () => {
  const dom = new JSDOM('<div id="research-lab"><p id="research-governed-status"></p>' +
    '<form id="research-run-form"><label><select data-code-project></select></label></form></div>',
    {url:'https://lightwork.test/research', runScripts:'outside-only'});
  const released = [];
  dom.window.fetch = async (url) => ({ok:false, status:403, body:{cancel:async () => { released.push(String(url)); }}});
  shell(dom.window);
  dom.window.eval(source);
  for (let index = 0; index < 10; index += 1) await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(released.sort(), ['/api/v1/code/heads', '/api/v1/research']);
  dom.window.close();
});
