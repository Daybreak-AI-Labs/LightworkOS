'use strict';
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve)); };

test('private task count reaches both chat navigation controls and recovers after a failed check', async t => {
  const link = '<a class="personal-notification-link" data-enabled="true" href="/notifications" aria-label="Your notifications"><span class="notification-count" hidden></span></a>';
  const dom = new JSDOM(link + link, {url:'https://lightwork.example.test/chat', runScripts:'outside-only', pretendToBeVisual:true});
  t.after(() => dom.window.close());
  const links = Array.from(dom.window.document.querySelectorAll('.personal-notification-link'));
  let tick, calls = 0;
  dom.window.setInterval = callback => { tick = callback; return 1; };
  dom.window.fetch = async () => {
    calls += 1;
    if (calls === 2) throw new Error('Offline');
    return {ok:true, json:async()=>({unseen:calls === 1 ? 2 : 0, partial:false})};
  };
  shell(dom.window);
  dom.window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-notification-badge.js'), 'utf8'));
  await settle();
  assert.deepEqual(links.map(node => node.querySelector('.notification-count').textContent), ['2','2']);
  assert.match(links[0].getAttribute('aria-label'), /2 new/);
  tick(); await settle();
  assert.deepEqual(links.map(node => node.querySelector('.notification-count').textContent), ['!','!']);
  assert.match(links[0].getAttribute('aria-label'), /could not be checked/);
  tick(); await settle();
  assert(links.every(node => node.querySelector('.notification-count').hidden));
  assert.equal(links[0].getAttribute('aria-label'), 'Your notifications');
});
