const { test } = require('node:test');
const assert = require('node:assert/strict');
const { source } = require('./helpers.cjs');

test('cancelled write settles with no automatic replay even if transport ignores abort', async () => {
  const contract = require('../../client-contract-tests/contracts/goal-submission-recovery-v1.json');
  let calls = 0, resolveLate;
  const api = source('src/api.ts', {fetch: () => {
    calls++; return new Promise(resolve => { resolveLate = resolve; });
  }});
  const controller = new AbortController();
  const pending = api.beginPairing('https://dashboard.example.test', 'Device', controller.signal);
  const rejected = assert.rejects(pending, error => error.kind === 'cancelled');
  controller.abort();
  await rejected;
  resolveLate(new Response('{"pairing_token":"late"}', {status: 200}));
  await Promise.resolve();
  assert.equal(calls, contract.write_count_after_interruption);
});

test('legacy invalid addresses cannot send a token before settings are corrected', async () => {
  const api = source('src/api.ts', { fetch: () => assert.fail('invalid connection must never request') });
  for (const baseUrl of ['http://remote.example.test', 'ftp://localhost',
    'https://user:password@example.test', // pragma: allowlist secret - synthetic invalid URL fixture
    'https://example.test?redirect=elsewhere']) {
    assert.equal(api.isTokenTransportSafe(baseUrl), false);
    await assert.rejects(api.listGoals({ baseUrl, token: 'synthetic-token' }));
  }
});

test('request guard uses the same secure addresses accepted by connection setup', async () => {
  const calls = [];
  const api = source('src/api.ts', { fetch: async (...args) => {
    calls.push(args);
    return new Response('[]');
  } });
  for (const baseUrl of ['https://dashboard.example.test', 'http://127.0.0.1:8765', 'http://[::1]:8765']) {
    assert.equal(api.isTokenTransportSafe(baseUrl), true);
    await api.listGoals({ baseUrl, token: 'synthetic-token' });
  }
  assert.equal(calls.length, 3);
  assert.equal(calls[0][0], 'https://dashboard.example.test/api/v1/goals?limit=50&offset=0&status=');
  assert.equal(calls[0][1].method, 'GET');
  assert.equal(calls[0][1].headers.Authorization, 'Bearer synthetic-token');
});

test('stable task pagination sends the scoped ID boundary without advancing an offset', async () => {
  const calls = [];
  const api = source('src/api.ts', {fetch: async url => { calls.push(url); return new Response('[]'); }});
  await api.listGoals({baseUrl: 'https://dashboard.example.test', token: 'synthetic-token'}, 50, undefined, 0, 'active', 76);
  assert.equal(calls[0], 'https://dashboard.example.test/api/v1/goals?limit=50&offset=0&status=active&before_id=76');
});

// /api/v1/goals pages by scanned rows and can hide some of them afterwards (a
// copied conversation whose source access ended), so a page shorter than the
// limit is not the end: the server's continuation headers say whether more
// remain and where to continue.
test('a task page carries the server continuation, not just the rows', async () => {
  const api = source('src/api.ts', {fetch: async () => new Response('[{"id":90,"status":"done","title":"T"}]',
    {headers: {'Pagination-Has-More': 'true', 'Pagination-Next-Before-Id': '61'}})});
  // Values made inside the app's own context compare by their JSON.
  const page = JSON.parse(JSON.stringify(await api.listGoals({baseUrl: 'https://dashboard.example.test', token: 'synthetic-token'})));
  assert.deepEqual(page, {goals: [{id: 90, status: 'done', title: 'T'}], hasMore: true, nextBeforeId: 61});
  const last = source('src/api.ts', {fetch: async () => new Response('[]', {headers: {'Pagination-Has-More': 'false'}})});
  assert.deepEqual(JSON.parse(JSON.stringify(await last.listGoals({baseUrl: 'https://dashboard.example.test', token: 'synthetic-token'}))),
    {goals: [], hasMore: false, nextBeforeId: null});
});

test('missing or unreadable continuation headers are reported as unknown, never guessed', async () => {
  for (const headers of [{}, {'Pagination-Has-More': 'maybe', 'Pagination-Next-Before-Id': '-4'},
    {'Pagination-Has-More': 'true', 'Pagination-Next-Before-Id': '9007199254740993'}]) {
    const api = source('src/api.ts', {fetch: async () => new Response('[]', {headers})});
    const page = await api.listGoals({baseUrl: 'https://dashboard.example.test', token: 'synthetic-token'});
    assert.equal(page.nextBeforeId, null, JSON.stringify(headers));
    assert.equal(page.hasMore, headers['Pagination-Has-More'] === 'true' ? true : null, JSON.stringify(headers));
  }
});

test('a dashboard from before ID cursors: Has-More and Next-Offset without a before-id cursor', async () => {
  const api = source('src/api.ts', {fetch: async () => new Response('[]',
    {headers: {'Pagination-Limit': '50', 'Pagination-Offset': '0', 'Pagination-Has-More': 'true', 'Pagination-Next-Offset': '50'}})});
  const page = JSON.parse(JSON.stringify(await api.listGoals({baseUrl: 'https://dashboard.example.test', token: 'synthetic-token'})));
  assert.deepEqual(page, {goals: [], hasMore: true, nextBeforeId: null});
});
