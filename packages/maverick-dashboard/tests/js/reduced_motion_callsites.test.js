// Lightweight fixture/controller validation. Native rendering is covered by
// reduced_motion_acceptance.spec.js; these assertions alone cannot qualify it.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {JSDOM, VirtualConsole} = require('jsdom');
const {shell} = require('./_shell');
const {fixture, reply, setup, names} = require('../browser/motion_fixture');

for (const name of names) test(`${name} actual reveal callsites follow a changed motion preference`, async t => {
  const data = fixture(name), errors = [], calls = [];
  const console = new VirtualConsole(); console.on('jsdomError', error => errors.push(error.message));
  const dom = new JSDOM(data.markup, {url: 'https://lightwork.test/', runScripts: 'outside-only', virtualConsole: console});
  t.after(() => dom.window.close());
  const {window} = dom;
  setup(window, data); window.TextDecoder = TextDecoder;
  shell(window);
  let reduce = true;
  window.matchMedia = () => ({matches: reduce});
  window.Element.prototype.scrollIntoView = function (options) {calls.push({id: this.id, ...options});};
  window.fetch = async (url, options = {}) => new Response(JSON.stringify(reply(name, new URL(url, window.location).pathname, options.method || 'GET')), {headers: {'Content-Type': 'application/json'}});
  window.eval(data.reveal); window.eval(data.helpers); window.eval(data.source);
  async function settle() {for (let i = 0; i < 30; i++) await new Promise(resolve => setImmediate(resolve));}
  await settle();
  assert.ok(window.document.querySelector(data.ready));
  for (const preference of [true, false]) {
    reduce = preference;
    for (const step of data.steps) {
      calls.length = 0;
      const trigger = step.trigger ? window.document.querySelector(step.trigger)
        : [...window.document.querySelectorAll(step.within + ' button')].find(button => button.textContent === step.label);
      assert.ok(trigger, JSON.stringify(step)); trigger.click(); await settle();
      assert.deepEqual(calls, [{id: step.target, behavior: reduce ? 'instant' : 'smooth', block: 'nearest'}]);
      assert.equal(window.document.activeElement, window.document.querySelector(step.focus || '#' + step.target));
    }
  }
  assert.deepEqual(errors, []);
});
