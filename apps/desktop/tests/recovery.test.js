const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../ui/recovery.js'), 'utf8');

function harness(invoke, overrides = {}, readiness = async () => ({service: "lightwork-dashboard", state: "ready"})) {
  const nodes = new Map(), destinations = [];
  function get(id) { if (!nodes.has(id)) nodes.set(id, { disabled: false, textContent: '', listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; } }); return nodes.get(id); }
  vm.runInNewContext(source, { document: { getElementById: get }, window: { __TAURI__: { core: { invoke: (command, args) => command === "dashboard_readiness" ? readiness() : invoke(command, args) } }, location: { replace(url) { destinations.push(url); } } }, fetch: async () => ({}), setTimeout, clearTimeout, AbortController, ...overrides });
  return { get, destinations };
}

test('recovery mode starts only on explicit action and uses fixed destination', async () => {
  const calls = [];
  const h = harness(async (command, args) => calls.push({ command, ...args }));
  assert.equal(calls.length, 0);
  await h.get('enter-recovery').listeners.click();
  assert.equal(calls[0].command, 'switch_recovery_mode');
  assert.equal(calls[0].recovery, true);
  assert.equal(calls[0].confirm, true);
  assert.deepEqual(h.destinations, ['http://127.0.0.1:8765/workspace/recovery']);
});

test('an independent service refusal stays visible and never navigates as if isolated', async () => {
  const h = harness(async () => { throw new Error('The workspace is managed outside this app.'); });
  await h.get('enter-recovery').listeners.click();
  assert.equal(h.destinations.length, 0);
  assert.match(h.get('details').textContent, /managed outside/);
  assert.equal(h.get('enter-recovery').disabled, false);
});

test('return to work chooses the fixed normal mode', async () => {
  const calls = [];
  const h = harness(async (command, args) => calls.push(args.recovery));
  await h.get('leave-recovery').listeners.click();
  assert.deepEqual(calls, [false]);
  assert.deepEqual(h.destinations, ['http://127.0.0.1:8765/']);
});

test('hung readiness fetches hit the overall deadline, abort, and allow retry', async () => {
  let now = 0, sequence = 0;
  const timers = new Map(), probes = [];
  const h = harness(async () => {}, {
    Date: { now: () => now },

    setTimeout(fn, ms) { timers.set(++sequence, {fn, at: now + ms}); return sequence; },
    clearTimeout(id) { timers.delete(id); },
  }, () => { probes.push(true); return new Promise(() => {}); });
  const request = h.get('enter-recovery').listeners.click();
  for (let step = 0; step < 40; step++) {
    for (let tick = 0; tick < 8; tick++) await Promise.resolve();
    if (!timers.size) break;
    const [id, timer] = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
    timers.delete(id); now = timer.at; timer.fn();
  }
  await request;
  assert.equal(now, 60000); assert.ok(probes.length > 0);
  assert.equal(timers.size, 0);
  assert.equal(h.get('enter-recovery').disabled, false);
  assert.equal(h.get('leave-recovery').disabled, false);
  assert.match(h.get('status').textContent, /switched modes, but your workspace isn't answering yet/);
  assert.match(h.get('details').textContent, /60 seconds/);
  assert.equal(h.destinations.length, 0);
});

test('recovery page speaks plainly and offers a copy button for support details', async () => {
  const h = harness(async () => { throw new Error('private fixture reason'); });
  await h.get('enter-recovery').listeners.click();
  assert.match(h.get('status').textContent, /couldn't switch modes\. Nothing was changed/);
  assert.doesNotMatch(h.get('status').textContent, /private fixture/);
  await h.get('details-copy').listeners.click();
  assert.match(h.get('details-copied').textContent, /Couldn't copy/);
  const page = fs.readFileSync(path.join(__dirname, '../ui/recovery.html'), 'utf8');
  assert.match(page, /Details for support/);
  assert.doesNotMatch(page, /external stores|Separately managed/);
});
