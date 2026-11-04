// Run with: node --test packages/maverick-dashboard/tests/js/web_vitals.test.js
'use strict';
// Field Core Web Vitals: a sampled page load measures LCP, INP and CLS the
// web-vitals way and sends them once, when the page is hidden, with its path
// and a device class only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-web-vitals.js'), 'utf8');

function load({rate = '1', random = 0.1, phone = false, hidden = false} = {}) {
  const dom = new JSDOM(`<!doctype html><html><body><script id="vitals" data-sample-rate="${rate}"></script></body></html>`,
    {url: 'https://lightwork.test/chat/goal/4127?tab=plan#step-2', runScripts: 'outside-only'});
  const w = dom.window, observers = {}, beacons = [];
  w.PerformanceObserver = class {
    constructor(callback) { this.callback = callback; }
    observe(options) { observers[options.type] = this; this.options = options; }
    disconnect() { this.disconnected = true; }
  };
  w.matchMedia = query => ({matches: phone && /max-width|coarse/.test(query)});
  w.Math.random = () => random;
  w.navigator.sendBeacon = (url, blob) => { beacons.push({url, blob}); return true; };
  Object.defineProperty(w.document, 'visibilityState', {configurable: true, get: () => (hidden ? 'hidden' : 'visible')});
  Object.defineProperty(w.document, 'currentScript', {configurable: true, get: () => w.document.getElementById('vitals')});
  w.eval(source);
  const feed = (type, entries) => observers[type] && observers[type].callback({getEntries: () => entries});
  const hide = () => { hidden = true; w.document.dispatchEvent(new w.Event('visibilitychange')); };
  const sent = async () => Promise.all(beacons.map(async b => ({url: b.url, body: JSON.parse(await b.blob.text()), type: b.blob.type})));
  return {w, observers, feed, hide, sent, beacons};
}

test('a measured visit sends LCP, INP and CLS once, with the path and device only', async () => {
  const page = load();
  page.feed('largest-contentful-paint', [{startTime: 900}, {startTime: 1450}]);
  page.feed('layout-shift', [{value: 0.02, startTime: 100, hadRecentInput: false}, {value: 0.03, startTime: 600, hadRecentInput: false},
    {value: 0.5, startTime: 700, hadRecentInput: true}, {value: 0.01, startTime: 9000, hadRecentInput: false}]);
  page.feed('event', [{interactionId: 1, duration: 80}, {interactionId: 1, duration: 120}, {interactionId: 2, duration: 64}, {interactionId: 0, duration: 400}]);
  page.hide(); page.hide();
  page.w.dispatchEvent(new page.w.Event('pagehide'));
  const sent = await page.sent();
  assert.equal(sent.length, 1, 'sent once');
  assert.equal(sent[0].url, '/api/v1/telemetry/vitals');
  assert.equal(sent[0].type, 'application/json');
  assert.deepEqual(sent[0].body, {path: '/chat/goal/4127', device: 'desktop', lcp: 1450, cls: 0.05, inp: 120});
  page.w.close();
});

test('a phone is reported as a phone, and an input stops LCP', async () => {
  const page = load({phone: true});
  page.feed('largest-contentful-paint', [{startTime: 1200}]);
  page.w.dispatchEvent(new page.w.Event('keydown'));
  page.feed('largest-contentful-paint', [{startTime: 5000}]);
  page.hide();
  const [beacon] = await page.sent();
  assert.equal(beacon.body.device, 'phone');
  assert.equal(beacon.body.lcp, 1200);
  assert.equal('inp' in beacon.body, false, 'no interaction, no INP');
  page.w.close();
});

test('an unsampled visit, a background tab or a zero rate measures nothing', async () => {
  for (const options of [{random: 0.9, rate: '0.5'}, {rate: '0'}, {rate: ''}]) {
    const page = load(options);
    assert.deepEqual(Object.keys(page.observers), []);
    page.hide();
    assert.equal(page.beacons.length, 0);
    page.w.close();
  }
  const background = load({hidden: true});
  background.feed('largest-contentful-paint', [{startTime: 300}]);
  background.w.dispatchEvent(new background.w.Event('pagehide'));
  const [beacon] = await background.sent();
  assert.equal('lcp' in beacon.body, false, 'a page loaded in the background has no meaningful LCP');
  background.w.close();
});
