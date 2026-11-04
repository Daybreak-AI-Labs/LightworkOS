const { test } = require('node:test');
const assert = require('node:assert/strict');
const { React, act, create, source, connection, text, button } = require('./helpers.cjs');

// Only what a person sees or hears: Text content and accessibility labels.
const visible = app => [
  ...app.root.findAllByType('Text').flatMap(node => [].concat(node.props.children).filter(v => typeof v === 'string' || typeof v === 'number')),
  ...app.root.findAll(node => typeof node.props.accessibilityLabel === 'string').map(node => node.props.accessibilityLabel),
].join(' | ');
const JARGON = /#\d|snake|_[a-z]|HTTP|\/api\/|undefined|null/;

function polled(value) {
  let refreshes = 0;
  return {
    mock: { usePolling: () => ({ ...value, refresh() { refreshes++; } }) },
    count: () => refreshes,
  };
}
const noCache = { useCachedBundle: () => null, saveBundle: async () => {}, offlineBanner: () => 'offline' };

test('plain labels replace stored code words', () => {
  const f = source('src/format.ts');
  assert.equal(f.statusLabel('active'), 'In progress');
  assert.equal(f.statusLabel('done'), 'Finished');
  assert.equal(f.statusLabel('awaiting_review'), 'Awaiting review');
  assert.equal(f.humanize('tool_call'), 'Used a tool');
  assert.equal(f.humanize('someNewKind'), 'Some new kind');
  assert.equal(f.activityText('tool_call: searched the web'), 'Used a tool: searched the web');
  assert.equal(f.taskTitle(''), 'Untitled task');
  assert.equal(f.agoText(0), 'just now');
  assert.equal(f.agoText(1), '1 minute ago');
  assert.equal(f.agoText(125), '2 hours ago');
});

test('task list shows titles and plain statuses, not ids or code words', async () => {
  const p = polled({ data: [{ id: 42, title: 'Draft the weekly report', status: 'blocked', result: null }], error: null });
  const { RunsListScreen } = source('src/screens/RunsListScreen.tsx', { '../poll': p.mock, '../offlineCache': noCache });
  let opened = null, app;
  await act(async () => { app = create(React.createElement(RunsListScreen, { settings: connection, onOpenRun: (id, title) => { opened = [id, title]; } })); });
  assert.match(text(app), /Draft the weekly report/);
  assert.match(text(app), /Needs attention/);
  assert.doesNotMatch(visible(app), JARGON);
  await act(async () => { button(app, 'Draft the weekly report').props.onPress(); });
  assert.deepEqual(opened, [42, 'Draft the weekly report']);
  app.unmount();
});

test('empty task list says what happens next and offers a refresh', async () => {
  const p = polled({ data: [], error: null });
  const { RunsListScreen } = source('src/screens/RunsListScreen.tsx', { '../poll': p.mock, '../offlineCache': noCache });
  let app;
  await act(async () => { app = create(React.createElement(RunsListScreen, { settings: connection, onOpenRun() {} })); });
  assert.match(text(app), /No tasks yet/);
  await act(async () => { button(app, 'Refresh now').props.onPress(); });
  assert.equal(p.count(), 1);
  app.unmount();
});

test('unreachable dashboard shows a plain notice with Try again', async () => {
  const api = source('src/api.ts');
  const p = polled({ data: null, error: api.NETWORK_TROUBLE, accessDenied: false, unsupported: false });
  const { RunsListScreen } = source('src/screens/RunsListScreen.tsx', { '../poll': p.mock, '../offlineCache': noCache });
  let app;
  await act(async () => { app = create(React.createElement(RunsListScreen, { settings: connection, onOpenRun() {} })); });
  assert.match(text(app), /Could not reach the dashboard/);
  await act(async () => { button(app, 'Try again').props.onPress(); });
  assert.equal(p.count(), 1);
  app.unmount();
});

test('overview labels counts plainly and describes the latest step', async () => {
  const p = polled({ data: { active: [{ id: 7, title: 'Reconcile invoices', status: 'active', updated_at: 0, activity: 'tool_call: opened the ledger' }], spend: { dollars: 3.5, runs: 1, input_tokens: 0, output_tokens: 0 } }, error: null });
  const { GlanceScreen } = source('src/screens/GlanceScreen.tsx', { '../poll': p.mock, '../offlineCache': noCache });
  let app;
  await act(async () => { app = create(React.createElement(GlanceScreen, { settings: connection })); });
  const body = text(app);
  assert.match(body, /Tasks in progress/);
  assert.match(body, /\$3\.50/);
  assert.match(body, /Across 1 task"/);
  assert.match(body, /Used a tool: opened the ledger/);
  assert.doesNotMatch(visible(app), JARGON);
  app.unmount();
});

test('task detail uses the task title and plain activity labels', async () => {
  const p = polled({ data: { status: 'done', result: 'Report sent', events: [{ id: 1, agent: 'supervisor', kind: 'tool_result', content: 'ok', ts: 0 }], next_id: 1, has_more: false, terminal: true }, error: null });
  const { RunDetailScreen } = source('src/screens/RunDetailScreen.tsx', { '../poll': p.mock, '../runReplay': { runReplay: () => ({ poll: async () => null }) } });
  let app;
  await act(async () => { app = create(React.createElement(RunDetailScreen, { settings: connection, runId: 9, title: 'Weekly report', onBack() {} })); });
  const body = text(app);
  assert.match(body, /Weekly report/);
  assert.match(body, /Finished/);
  assert.match(body, /Outcome/);
  assert.match(body, /Supervisor/);
  assert.match(body, /Tool result/);
  assert.doesNotMatch(visible(app), JARGON);
  app.unmount();
});
