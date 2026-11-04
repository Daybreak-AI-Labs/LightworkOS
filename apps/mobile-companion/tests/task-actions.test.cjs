const {test} = require('node:test');
const assert = require('node:assert/strict');
const {React, act, create, source, connection, button, text, native, deferred} = require('./helpers.cjs');

function setup(overrides = {}) {
  const calls = [], applied = [];
  const context = {context: 'a'.repeat(64), title: 'My own task', status: 'blocked',
    answer: {revision: 'b'.repeat(64), blocked: '', questions: [{id: 3, question: 'Which account?'}]},
    stop: {revision: 'c'.repeat(64), blocked: ''}};
  const api = {
    deviceActionContext: async () => context,
    prepareDeviceAction: async (_settings, input) => {
      calls.push(['prepare', input]);
      return {token: 'sealed-review', action: input.action, expires_at: Date.now() / 1000 + 180,
        summary: 'Review the exact change', changes: [{label: 'Answer', after: input.arguments.answer || 'Stop requested'}]};
    },
    executeDeviceAction: async (_settings, token) => {calls.push(['execute', token]); return {status: 'confirmed', message: 'Received'};},
    isAccessDenied: error => error.status === 403,
    ...overrides,
  };
  const {TaskActions} = source('src/components/TaskActions.tsx', {'../api': api});
  const props = {settings: connection, goalId: 1, online: true, onApplied: () => applied.push(true)};
  return {TaskActions, props, calls, applied};
}

async function press(tree, label) {
  await act(async () => {button(tree, label).props.onPress();});
}

test('answer is previewed first and only explicit confirmation sends the reviewed request', async () => {
  const value = setup(); let tree;
  await act(async () => {tree = create(React.createElement(value.TaskActions, value.props));});
  await press(tree, 'Load current task actions');
  await press(tree, 'Answer: Which account?');
  await act(async () => {tree.root.findByType('TextInput').props.onChangeText('Keep this exact draft');});
  await press(tree, 'Review answer');
  assert.equal(value.calls.length, 1);
  assert.equal(value.calls[0][1].arguments.answer, 'Keep this exact draft');
  assert.match(text(tree), /Keep this exact draft/);
  await press(tree, 'Confirm answer');
  assert.deepEqual(value.calls[1], ['execute', 'sealed-review']);
  assert.equal(value.applied.length, 1);
  await act(async () => tree.unmount());
});

test('lost response is retried only by the user with the same sealed review', async () => {
  const tokens = [];
  const value = setup({executeDeviceAction: async (_settings, token) => {
    tokens.push(token); if (tokens.length === 1) throw Error('Network response lost');
    return {status: 'replayed', message: 'Previously received'};
  }}); let tree;
  await act(async () => {tree = create(React.createElement(value.TaskActions, value.props));});
  await press(tree, 'Load current task actions');
  await press(tree, 'Review Stop request');
  await press(tree, 'Confirm Stop request');
  assert.equal(tokens.length, 1);
  assert.match(text(tree), /A reply was not confirmed/);
  await press(tree, 'Check or retry reviewed action');
  assert.deepEqual(tokens, ['sealed-review', 'sealed-review']);
  await act(async () => tree.unmount());
});

test('offline and background transitions discard authority but keep an unsent draft in memory', async () => {
  const value = setup(); let tree;
  await act(async () => {tree = create(React.createElement(value.TaskActions, value.props));});
  await press(tree, 'Load current task actions');
  await act(async () => {tree.root.findByType('TextInput').props.onChangeText('Unsent draft');});
  await act(async () => {native.AppState.emit('background');});
  assert.equal(tree.root.findAllByType('TextInput').length, 0);
  await act(async () => {native.AppState.emit('active');});
  await press(tree, 'Load current task actions');
  assert.equal(tree.root.findByType('TextInput').props.value, 'Unsent draft');
  await act(async () => {tree.update(React.createElement(value.TaskActions, {...value.props, online: false}));});
  assert.equal(button(tree, 'Load current task actions').props.disabled, true);
  assert.equal(value.calls.length, 0);
  await act(async () => tree.unmount());
});

test('late action context is ignored after the app backgrounds', async () => {
  const late = deferred(); const value = setup({deviceActionContext: () => late.promise}); let tree;
  await act(async () => {tree = create(React.createElement(value.TaskActions, value.props));});
  await press(tree, 'Load current task actions');
  await act(async () => {native.AppState.emit('background'); late.resolve({title: 'Private late task'});});
  assert.doesNotMatch(text(tree), /Private late task/);
  await act(async () => {native.AppState.emit('active'); tree.unmount();});
});
