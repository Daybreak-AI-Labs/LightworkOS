"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");
const {shell} = require('./_shell');
const script = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-model-tests.js"), "utf8");
const template = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/settings.html"), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
const row = {id: "b".repeat(32), model: "openai:synthetic", kind: "generation", state: "prepared", created_at: 1,
  limits: {max_dollars: .05, max_output_tokens: 64, max_wall_seconds: 30}, scope: "Tools remain untested", notice: "One potentially paid request"};
async function setup(queue) {
  const html = template.slice(template.indexOf('<section class="panel" data-settings-group="models" id="model-tests"'), template.indexOf('<div class="section-head" data-settings-group="models"><h2>Default model'))
    .replace(/{%[\s\S]*?%}/g, '').replace(/{{[\s\S]*?}}/g, '');
  const dom = new JSDOM(html, {url: 'https://lightwork.test/settings', runScripts: 'outside-only'});
  const calls = [];
  dom.window.fetch = async (url, options) => { calls.push({url, options}); const next = queue.shift(); if (next instanceof Error) throw next; if (!next) throw new Error('Unexpected request'); return {ok: true, json: async () => next}; };
  shell(dom.window);
  dom.window.eval(script); await tick();
  return {dom, calls, el: suffix => dom.window.document.getElementById('model-test-' + suffix)};
}
const status = {context: 'a'.repeat(64), enabled: true, checks: []};
test('review is free, confirmation is explicit, duplicate click is suppressed and response loss never auto-retries', async t => {
  const ui = await setup([status, {check: row}, new Error('response lost'), {...status, checks: [{...row, state: 'unknown', message: 'Not replayed'}]}]);
  t.after(() => ui.dom.window.close());
  ui.el('model').value = '__custom__'; ui.el('custom-value').value = 'openai:synthetic';
  ui.el('form').dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true})); await tick();
  assert.equal(ui.calls.length, 2); assert.equal(ui.calls[1].url.endsWith('/review'), true);
  assert.match(ui.el('review-text').textContent, /(USD |\$)0\.05/);
  ui.el('confirm').click(); ui.el('confirm').click(); await tick(); await tick();
  assert.equal(ui.calls.filter(call => call.url.endsWith('/execute')).length, 1);
  assert.equal(ui.el('review-card').hidden, true);
  assert.match(ui.el('history').textContent, /Unconfirmed outcome/);
});
test('disabled policy and stale account reset review; receipt text cannot inject markup', async t => {
  const ui = await setup([status, {check: row}, {context: 'c'.repeat(64), enabled: false, blocked: 'Disabled', checks: [{...row, state: 'unknown', model: '<img src=x onerror=alert(1)>'}]}]);
  t.after(() => ui.dom.window.close());
  ui.el('form').dispatchEvent(new ui.dom.window.Event('submit', {bubbles: true, cancelable: true})); await tick();
  ui.el('refresh').click(); await tick();
  assert.equal(ui.el('review-card').hidden, true); assert.equal(ui.el('review').disabled, true);
  assert.equal(ui.el('history').querySelector('img'), null);
  assert.match(ui.el('history').textContent, /<img/);
});
