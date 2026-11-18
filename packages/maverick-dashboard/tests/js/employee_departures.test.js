'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const template = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/employee_departures.html'), 'utf8');
const settle = async () => { for (let i = 0; i < 15; i++) await new Promise(resolve => setImmediate(resolve)); };

function page(people) {
  const body = template.replace(/\{%[\s\S]*?%\}/g, '').replace(/\{\{[\s\S]*?\}\}/g, '');
  const script = body.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
  const dom = new JSDOM(body.replace(/<script[\s\S]*?<\/script>/, ''), {url: 'https://lightwork.invalid/users/departures', runScripts: 'outside-only'});
  dom.window.fetch = async () => ({ok: true, status: 200, json: async () => ({enabled: true, people, cases: []})});
  shell(dom.window);
  dom.window.eval(script);
  return dom;
}

test('an empty employee list explains that administrators are not offered', async () => {
  const dom = page([{principal: 'user:a', label: 'Admin', admin: true, active: true, departed: false}]);
  await settle();
  const help = dom.window.document.getElementById('ed-person-help');
  assert.equal(help.hidden, false);
  assert.match(help.textContent, /Administrators are not listed/);
  dom.window.close();
});

test('the explanation stays hidden when someone can be reviewed', async () => {
  const dom = page([{principal: 'user:e', label: 'Employee', admin: false, active: true, departed: false}]);
  await settle();
  assert.equal(dom.window.document.getElementById('ed-person-help').hidden, true);
  dom.window.close();
});
