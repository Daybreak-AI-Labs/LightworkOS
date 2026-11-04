// The one run-status vocabulary shared by the chat badge, composer and recents.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const pkg = path.resolve(__dirname, '../../maverick_dashboard');
const script = fs.readFileSync(path.join(pkg, 'static/lightwork-run-status.js'), 'utf8');
const python = fs.readFileSync(path.join(pkg, 'run_status.py'), 'utf8');

function load(html = '') {
  const dom = new JSDOM(`<body>${html}</body>`, {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only'});
  dom.window.eval(script);
  return {dom, doc: dom.window.document, rs: dom.window.LightworkRunStatus};
}

test('every orchestrator status has a plain word and the raw value never shows', () => {
  const {rs} = load();
  const expected = {
    draft: 'Queued', pending: 'Queued', active: 'Working', running: 'Working', in_progress: 'Working',
    blocked: 'Paused', done: 'Done', completed: 'Done', failed: 'Failed', error: 'Failed', cancelled: 'Stopped',
  };
  for (const [status, label] of Object.entries(expected)) assert.equal(rs.label(status), label, status);
  assert.equal(rs.label('ACTIVE'), 'Working');
  assert.equal(rs.label('something_new'), '');
  assert.equal(rs.label(''), '');
});

test('a run that stopped on a broken AI connection reads Stopped, other pauses read Paused', () => {
  const {rs} = load();
  for (const kind of ['provider_not_ready', 'provider_connection', 'internal_error', 'unpriced_model']) {
    assert.equal(rs.label('blocked', kind), 'Stopped', kind);
  }
  for (const kind of ['spending_limit', 'other', '', undefined]) assert.equal(rs.label('blocked', kind), 'Paused');
  // The stop kind only matters for a paused run.
  assert.equal(rs.label('active', 'internal_error'), 'Working');
});

test('Stop is offered in every working state and hidden once the run is over', () => {
  const {rs} = load();
  const table = [
    // status, waiting for the person's answer, Stop offered, run settled
    ['pending', false, true, false],
    ['active', false, true, false],
    ['running', false, true, false],
    ['in_progress', false, true, false],
    ['blocked', true, true, false],
    ['blocked', false, false, true],
    ['done', false, false, true],
    ['completed', false, false, true],
    ['failed', false, false, true],
    ['error', false, false, true],
    ['cancelled', false, false, true],
    ['draft', false, false, false],
  ];
  for (const [status, asking, stoppable, settled] of table) {
    assert.equal(rs.stoppable(status, asking), stoppable, `stoppable ${status} asking=${asking}`);
    assert.equal(rs.settled(status, asking), settled, `settled ${status} asking=${asking}`);
  }
});

test('recents follow the live status of the open task only', () => {
  const {doc, rs} = load(`
    <ul id="cs-list">
      <li><a data-conversation-root="3" href="/chat/goal/7" aria-current="true" aria-describedby="chat-status-3">Mine</a><span class="cs-list__status cs-list__status--pending" id="chat-status-3">Queued</span></li>
      <li><a data-conversation-root="9" href="/chat/goal/9">Other</a><span class="cs-list__status cs-list__status--active" id="chat-status-9">Working</span></li>
    </ul>`);
  assert.equal(rs.syncRecents(doc, 7, 'active'), true);
  const mine = doc.getElementById('chat-status-3');
  assert.equal(mine.textContent, 'Working');
  assert.equal(mine.className, 'cs-list__status cs-list__status--active');
  rs.syncRecents(doc, 7, 'blocked', 'provider_connection');
  assert.equal(mine.textContent, 'Stopped');
  rs.syncRecents(doc, 7, 'done');
  assert.equal(mine.textContent, 'Done');
  assert.equal(doc.getElementById('chat-status-9').textContent, 'Working');
  assert.equal(rs.syncRecents(doc, 42, 'done'), false);
});

test('recents gain a status when the server rendered none', () => {
  const {doc, rs} = load('<ul id="cs-list"><li><a data-conversation-root="5" href="/chat/goal/7">New</a></li></ul>');
  rs.syncRecents(doc, 7, 'pending');
  const span = doc.getElementById('chat-status-5');
  assert.ok(span);
  assert.equal(span.textContent, 'Queued');
  assert.equal(doc.querySelector('a[data-conversation-root="5"]').getAttribute('aria-describedby'), 'chat-status-5');
});

test('the browser table matches the server table word for word', () => {
  const {rs} = load();
  const block = python.match(/LABELS = \{([\s\S]*?)\n\}/);
  assert.ok(block, 'LABELS table found in run_status.py');
  const labels = Object.fromEntries([...block[1].matchAll(/"(\w+)": "([^"]+)"/g)].map(m => [m[1], m[2]]));
  assert.deepEqual(labels, JSON.parse(JSON.stringify(rs.LABELS)));
  const kinds = python.match(/STOPPED_KINDS = frozenset\(\{([\s\S]*?)\}\)/);
  assert.ok(kinds, 'STOPPED_KINDS found in run_status.py');
  assert.deepEqual([...kinds[1].matchAll(/"(\w+)"/g)].map(m => m[1]).sort(), JSON.parse(JSON.stringify(rs.STOPPED_KINDS)).sort());
});
