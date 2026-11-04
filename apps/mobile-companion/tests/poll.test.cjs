const { test } = require('node:test');
const assert = require('node:assert/strict');
const { React, act, create, source, deferred } = require('./helpers.cjs');

function hook() {
  const timers = new Map();
  let next = 0;
  const { usePolling } = source('src/poll.ts', {
    setInterval: fn => { timers.set(++next, fn); return next; },
    clearInterval: id => timers.delete(id),
  });
  function Probe({ fetcher }) { return React.createElement('snapshot', usePolling(fetcher, 10000)); }
  return { Probe, timers };
}
const snapshot = app => app.root.findByType('snapshot').props;

test('changing dashboards clears previous data while the replacement request loads', async () => {
  const { Probe } = hook();
  const pending = deferred();
  let app;
  await act(async () => { app = create(React.createElement(Probe, { fetcher: async () => 'OLD' })); });
  assert.equal(snapshot(app).data, 'OLD');
  await act(async () => { app.update(React.createElement(Probe, { fetcher: () => pending.promise })); });
  assert.equal(snapshot(app).data, null);
  await act(async () => { pending.resolve('NEW'); });
  assert.equal(snapshot(app).data, 'NEW');
  app.unmount();
});

for (const failure of [false, true]) {
  test(`obsolete dashboard ${failure ? 'failure' : 'response'} cannot replace a newer generation`, async () => {
    const { Probe } = hook();
    const old = deferred();
    let app;
    await act(async () => { app = create(React.createElement(Probe, { fetcher: () => old.promise })); });
    await act(async () => { app.update(React.createElement(Probe, { fetcher: async () => 'NEW' })); });
    await act(async () => { failure ? old.reject(new Error('old server failed')) : old.resolve('OLD'); });
    assert.equal(snapshot(app).data, 'NEW');
    assert.equal(snapshot(app).error, null);
    app.unmount();
  });
}

test('out-of-order responses within the same dashboard preserve the latest refresh', async () => {
  const { Probe } = hook();
  const old = deferred();
  let calls = 0, app;
  const fetcher = () => ++calls === 1 ? old.promise : Promise.resolve('LATEST');
  await act(async () => { app = create(React.createElement(Probe, { fetcher })); });
  await act(async () => { snapshot(app).refresh(); });
  await act(async () => { old.resolve('OLDER'); });
  assert.equal(snapshot(app).data, 'LATEST');
  app.unmount();
});

test('latest refresh failure keeps the last good data and rejects older pending success', async () => {
  const { Probe } = hook();
  const old = deferred();
  let calls = 0, app;
  const fetcher = () => ++calls === 1 ? Promise.resolve('COMMITTED') : calls === 2 ? old.promise : Promise.reject(new Error('latest failure'));
  await act(async () => { app = create(React.createElement(Probe, { fetcher })); });
  await act(async () => { snapshot(app).refresh(); });
  await act(async () => { snapshot(app).refresh(); });
  await act(async () => { old.resolve('OLDER'); });
  assert.equal(snapshot(app).data, 'COMMITTED');
  assert.match(snapshot(app).error, /Could not reach the dashboard/);
  app.unmount();
});

test('unmount stops timers and stale refresh callbacks cannot start work', async () => {
  const { Probe, timers } = hook();
  const pending = deferred();
  let calls = 0, app;
  await act(async () => { app = create(React.createElement(Probe, { fetcher: () => { calls++; return pending.promise; } })); });
  const refresh = snapshot(app).refresh;
  await act(async () => { app.unmount(); });
  assert.equal(timers.size, 0);
  await act(async () => { refresh(); pending.resolve('late'); });
  assert.equal(calls, 1);
});

test('slow automatic polls do not pile up or starve a response beyond the interval', async () => {
  const { Probe, timers } = hook();
  const pending = deferred();
  let calls = 0, app;
  await act(async () => { app = create(React.createElement(Probe, { fetcher: () => { calls++; return pending.promise; } })); });
  const interval = [...timers.values()][0];
  await act(async () => { interval(); interval(); interval(); });
  assert.equal(calls, 1);
  await act(async () => { pending.resolve('slow success'); });
  assert.equal(snapshot(app).data, 'slow success');
  await act(async () => { interval(); });
  assert.equal(calls, 2);
  app.unmount();
});
