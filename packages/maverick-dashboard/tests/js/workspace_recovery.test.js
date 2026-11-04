const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const base = path.join(__dirname, '../../maverick_dashboard');
const html = fs.readFileSync(path.join(base, 'templates/workspace_recovery.html'), 'utf8');
const source = fs.readFileSync(path.join(base, 'static/lightwork-workspace-recovery.js'), 'utf8');
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

async function harness(handler, overrides = {}, installationOverrides = {}) {
  const dom = new JSDOM(html, { url: 'http://localhost/workspace/recovery', runScripts: 'outside-only' });
  const calls = [];
  const state = { tenant: 'acme', context: 'account-context', expected_tenant: 'acme', target: 'target-a', application_version: '1.0.0', key_id: 'key-id',
    coverage: ['Local workspace files'], excluded: ['External stores'], restore_blockers: [], live_restore_available: true,
    snapshots: [{ id: 'snapshot-a', bytes: 1024 }], max_archive_bytes: 10000, ...overrides };
  dom.window.fetch = async (url, init) => {
    calls.push({ url, init });
    const body = url.endsWith('/status') ? state : await handler(url, init);
    if (url.endsWith('/installation') && !body.error) Object.assign(body, installationOverrides);
    return { ok: !body.error, status: body.error ? 409 : 200,
      json: async () => body.error ? { detail: body.error } : JSON.parse(JSON.stringify(body)),
      blob: async () => new dom.window.Blob([JSON.stringify(body)], { type: 'application/json' }) };
  };
  dom.window.eval(source);
  await tick(); await tick();
  const get = name => dom.window.document.getElementById('wrec-' + name);
  function select() { get('snapshot').value = 'snapshot-a'; get('snapshot').dispatchEvent(new dom.window.Event('change')); }
  return { dom, calls, get, state, select };
}

function nativeReleaseReview() {
  return { id: 'e'.repeat(32), expires_at: Date.now() / 1000 + 600, release_sha256: 'f'.repeat(64),
    release: { version: '1.0.1', runtime_sha256: '1'.repeat(64), installer_sha256: '2'.repeat(64), signature: 'synthetic-release-signature' } };
}

test('channel review without a current typed form stays unresolved and never exposes editable identities', async () => {
  const template = { schema: 1, namespace: 'channel-deliveries', record_id: 'chd-' + 'a'.repeat(56),
    source_sha256: 'b'.repeat(64), binding_sha256: 'c'.repeat(64), observed_at: null,
    evidence_reference: '', outcome: 'unknown', execution: 'unknown', delivery: 'unknown', chunks: {} };
  const item = reconciliationItem({ category: 'channel_authority', safe_state: 'channel_restore_held',
    requires_external_readback: true, readback_template: template });
  const h = await harness(async url => url.endsWith('/reconciliation') ? reconciliationReport([item]) : {}, {
    recovery_mode: true, bootstrap: { state: 'reconciliation_required' },
  });
  assert.equal(h.get('reconciliation-items').querySelector('textarea'), null);
  assert.equal(h.get('reconciliation-items').querySelector('form'), null);
  assert.doesNotMatch(h.get('reconciliation-items').textContent, /chd-|source_sha256|binding_sha256/);
  assert.match(h.get('reconciliation-items').textContent, /Refresh|refresh/);
  assert.equal(h.calls.some(row => row.init.method === 'POST'), false);
  assert.equal(h.get('reconciliation-complete').disabled, true);
  h.dom.window.close();
});

function channelItem(kind, descriptor = {}, item = {}) {
  return reconciliationItem({ category: 'channel_authority', safe_state: 'channel_restore_held',
    record_id: 'private-record-identity', source: 'private/channel/path', requires_external_readback: true,
    channel_review: { schema: 1, kind, review_token: 'a'.repeat(64), title: 'Review connection', source_label: 'Messages',
      status: 'review_required', restored_at: new Date(Date.now() - 600000).toISOString(),
      ...(kind === 'message' ? { execution_choices: ['absent', 'recorded'], delivery_choices: ['absent', 'recorded'], chunks: [] } : {}),
      ...descriptor }, ...item });
}
function enteredTime(offset = -30000) {
  const time = new Date(Date.now() + offset), pad = value => String(value).padStart(2, '0');
  return `${time.getFullYear()}-${pad(time.getMonth() + 1)}-${pad(time.getDate())}T${pad(time.getHours())}:${pad(time.getMinutes())}:${pad(time.getSeconds())}`;
}
function formOf(h, id = '1'.repeat(32)) { return h.dom.window.document.getElementById('wrec-channel-' + id); }
function enter(h, name, value, id) {
  const input = formOf(h, id).elements.namedItem(name);
  if (input.type === 'checkbox') input.checked = value; else input.value = value;
  input.dispatchEvent(new h.dom.window.Event('change', { bubbles: true })); return input;
}
function completeCommon(h, id) {
  h.dom.window.LightworkChannelReview.select(id || '1'.repeat(32));
  enter(h, 'checked_at', enteredTime(), id); enter(h, 'evidence_reference', 'service-ticket-12345', id);
}
function channelPosts(h) { return h.calls.filter(call => call.url.endsWith('/operations/channel-review')); }
async function channelHarness(items, override) {
  const report = reconciliationReport(items);
  const h = await harness(async (url, init) => {
    if (url.endsWith('/reconciliation')) return report;
    if (url.endsWith('/operations/channel-review')) {
      if (override) return override(url, init, report);
      const body = JSON.parse(init.body), item = report.items.find(row => row.id === body.item_id);
      item.state = 'resolved'; item.channel_review.status = 'recorded'; report.unresolved--;
      return { state: 'resolved', item_id: item.id, disposition: 'channel_readback_confirmed', unresolved: report.unresolved,
        automatic_replay_blocked: true, normal_start_blocked: true };
    }
    return {};
  }, { recovery_mode: true, bootstrap: { state: 'reconciliation_required' } });
  return { ...h, report };
}

for (const kind of ['message', 'delivery_restart', 'imessage_position', 'notification_position', 'poll_time']) {
  test(`${kind} uses typed controls, exact answers and current authenticated context`, async () => {
    const h = await channelHarness([channelItem(kind, kind.includes('position') ? { minimum_position: '2' } : {})]);
    const form = formOf(h); assert.ok(form); assert.equal(form.querySelector('textarea'), null);
    assert.doesNotMatch(h.get('reconciliation-items').textContent, /private-record-identity|private\/channel\/path|Unix|JSON|[a-f0-9]{64}/);
    completeCommon(h);
    const checked = form.elements.checked_at.value, expected = { kind, checked_at: new Date(checked).toISOString(), evidence_reference: 'service-ticket-12345' };
    if (kind === 'message') { enter(h, 'execution', 'recorded'); enter(h, 'delivery', 'absent'); Object.assign(expected, { execution: 'recorded', delivery: 'absent', chunks: {} }); }
    if (kind.includes('position')) { enter(h, 'position', '9007199254740993123456789'); expected.position = '9007199254740993123456789'; }
    if (kind === 'poll_time') { const at = enteredTime(-60000); enter(h, 'resume_time', at); expected.resume_time = new Date(at).toISOString(); }
    form.dispatchEvent(new h.dom.window.Event('submit', { cancelable: true })); await tick();
    assert.equal(channelPosts(h).length, 0, 'form submit cannot bypass explicit confirmation');
    enter(h, 'confirm', true); form.querySelector('[type=submit]').click(); await tick(); await tick();
    assert.equal(channelPosts(h).length, 1);
    assert.deepEqual(JSON.parse(channelPosts(h)[0].init.body), { confirm: true, item_id: '1'.repeat(32), expected_review_token: 'a'.repeat(64), answers: expected });
    assert.equal(channelPosts(h)[0].init.headers['X-Lightwork-Recovery-Context'], 'account-context');
    assert.equal(channelPosts(h)[0].init.headers['X-Lightwork-Expected-Tenant'], 'acme');
    assert.equal(h.calls.some(call => call.url.includes('/reconciliation/items/')), false);
    assert.match(h.get('reconciliation-items').textContent, /Review recorded/);
    assert.equal(h.get('reconciliation-complete').disabled, true);
    assert.equal(h.calls.some(call => call.url.endsWith('/reconciliation/complete')), false);
    h.dom.window.close();
  });
}

test('unknown outcomes, inconsistent delivery and incomplete parts stay unresolved with focused errors', async () => {
  const h = await channelHarness([channelItem('message', { chunks: [{ key: 'opaque-part-key', label: 'Message part 1', choices: ['absent', 'recorded'], receipt_locked: false, receipt: '' }] })]);
  completeCommon(h); enter(h, 'confirm', true);
  let result = await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.equal(result.status, 'needs_input'); assert.equal(channelPosts(h).length, 0);
  assert.equal(h.dom.window.document.activeElement.name, 'execution');
  assert.equal(formOf(h).elements.execution.getAttribute('aria-invalid'), 'true');
  assert.ok(h.dom.window.document.getElementById(formOf(h).elements.execution.getAttribute('aria-describedby').split(' ')[0]).textContent);
  enter(h, 'execution', 'absent'); enter(h, 'delivery', 'recorded'); enter(h, 'chunk_0', 'recorded'); enter(h, 'confirm', true);
  result = await h.dom.window.LightworkChannelReview.submit('1'.repeat(32)); assert.equal(result.status, 'needs_input');
  assert.equal(channelPosts(h).length, 0); assert.equal(h.dom.window.document.activeElement.name, 'execution');
  enter(h, 'execution', 'recorded'); enter(h, 'delivery', 'absent'); enter(h, 'confirm', true);
  await h.dom.window.LightworkChannelReview.submit('1'.repeat(32)); assert.equal(channelPosts(h).length, 0);
  assert.equal(h.dom.window.document.activeElement.name, 'delivery'); h.dom.window.close();
});

test('retained confirmed outcomes and exact message receipts are kept without editable identities', async () => {
  const h = await channelHarness([channelItem('message', { execution_choices: ['recorded'], delivery_choices: ['recorded'],
    chunks: [{ key: '__proto__', label: 'Message part 1', choices: ['recorded'], receipt_locked: true, receipt: 'native-receipt-001' }] })]);
  completeCommon(h); assert.equal(formOf(h).elements.receipt_0.disabled, true);
  assert.deepEqual([...formOf(h).elements.execution.options].map(o => o.value), ['', 'recorded']);
  enter(h, 'execution', 'recorded'); enter(h, 'delivery', 'recorded'); enter(h, 'chunk_0', 'recorded'); enter(h, 'confirm', true);
  await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  const answers = JSON.parse(channelPosts(h)[0].init.body).answers;
  assert.deepEqual(answers.chunks, JSON.parse('{"__proto__":{"outcome":"recorded","provider_id":"native-receipt-001"}}'));
  assert.doesNotMatch(h.get('reconciliation-items').textContent, /__proto__/); h.dom.window.close();
});

for (const value of ['9007199254740992', '1.5', '1e20', '-1', '9,007', '1 2']) test(`invalid or older exact iMessage position ${value} cannot submit`, async () => {
  const h = await channelHarness([channelItem('imessage_position', { minimum_position: '9007199254740993' })]);
  completeCommon(h); enter(h, 'position', value); enter(h, 'confirm', true);
  await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.equal(channelPosts(h).length, 0); assert.equal(h.dom.window.document.activeElement.name, 'position'); h.dom.window.close();
});

test('4096 digit iMessage position preserves every digit and confirmation clears on edits', async () => {
  const h = await channelHarness([channelItem('imessage_position')]); completeCommon(h);
  const exact = '8' + '1'.repeat(4095); enter(h, 'position', exact); enter(h, 'confirm', true);
  enter(h, 'evidence_reference', 'another-evidence-123'); assert.equal(formOf(h).elements.confirm.checked, false);
  enter(h, 'confirm', true); await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.equal(JSON.parse(channelPosts(h)[0].init.body).answers.position, exact); h.dom.window.close();
});

test('stale observations and restart times before restoration require a new source check', async () => {
  const h = await channelHarness([channelItem('poll_time')]); completeCommon(h);
  enter(h, 'checked_at', enteredTime(-1000000)); enter(h, 'resume_time', enteredTime(-700000)); enter(h, 'confirm', true);
  await h.dom.window.LightworkChannelReview.submit('1'.repeat(32)); assert.equal(channelPosts(h).length, 0);
  assert.equal(h.dom.window.document.activeElement.name, 'checked_at');
  enter(h, 'checked_at', enteredTime()); enter(h, 'confirm', true);
  await h.dom.window.LightworkChannelReview.submit('1'.repeat(32)); assert.equal(channelPosts(h).length, 0);
  assert.equal(h.dom.window.document.activeElement.name, 'resume_time'); h.dom.window.close();
});

test('cancel preserves the entered draft without consent or any mutation', async () => {
  const h = await channelHarness([channelItem('delivery_restart')]); completeCommon(h); enter(h, 'confirm', true);
  const form = formOf(h), cancel = [...form.querySelectorAll('button')].find(button => button.textContent === 'Leave unresolved');
  cancel.click(); assert.equal(form.hidden, true); assert.equal(form.elements.confirm.checked, false); assert.equal(channelPosts(h).length, 0);
  h.dom.window.LightworkChannelReview.select('1'.repeat(32)); assert.equal(form.elements.evidence_reference.value, 'service-ticket-12345');
  assert.equal(form.hidden, false); h.dom.window.close();
});

test('safe refresh preserves same-binding work, changed token or authenticated context clears it', async () => {
  const h = await channelHarness([channelItem('imessage_position')]); completeCommon(h); enter(h, 'position', '9007199254740993'); enter(h, 'confirm', true);
  h.get('refresh').click(); await tick(); await tick();
  assert.equal(formOf(h).elements.position.value, '9007199254740993'); assert.equal(formOf(h).elements.confirm.checked, false);
  h.report.items[0].channel_review.review_token = 'b'.repeat(64); h.get('refresh').click(); await tick(); await tick();
  assert.equal(formOf(h).elements.position.value, ''); assert.match(h.get('reconciliation-items').textContent, /item changed/);
  completeCommon(h); enter(h, 'position', '999'); h.state.context = 'new-authenticated-account';
  h.get('refresh').click(); await tick(); await tick(); assert.equal(formOf(h).elements.position.value, '');
  assert.equal(channelPosts(h).length, 0); h.dom.window.close();
});

test('resolving one item retains unfinished entries for another current item', async () => {
  const second = '2'.repeat(32), h = await channelHarness([channelItem('delivery_restart'), channelItem('imessage_position', {}, { id: second })]);
  completeCommon(h, second); enter(h, 'position', '9007199254740993', second); enter(h, 'confirm', true, second);
  completeCommon(h); enter(h, 'confirm', true); await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.equal(formOf(h, second).elements.position.value, '9007199254740993'); assert.equal(formOf(h, second).elements.confirm.checked, false);
  assert.equal(channelPosts(h).length, 1); h.dom.window.close();
});

test('stale refusal keeps work, blocks repeat and needs readback plus a deliberate new confirmation', async () => {
  const h = await channelHarness([channelItem('delivery_restart')], () => ({ error: 'private technical failure must not be exposed' }));
  completeCommon(h); enter(h, 'confirm', true); await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.equal(formOf(h).elements.evidence_reference.value, 'service-ticket-12345'); assert.equal(formOf(h).elements.confirm.checked, false);
  assert.doesNotMatch(h.get('reconciliation-items').textContent, /private technical/);
  assert.equal(h.dom.window.document.activeElement.textContent, 'Refresh status');
  await h.dom.window.LightworkChannelReview.submit('1'.repeat(32)); assert.equal(channelPosts(h).length, 1);
  h.dom.window.document.activeElement.click(); await tick(); await tick();
  assert.equal(formOf(h).elements.evidence_reference.value, 'service-ticket-12345'); assert.equal(formOf(h).elements.confirm.checked, false);
  assert.equal(h.dom.window.document.activeElement.textContent, 'Refresh status');
  assert.equal(channelPosts(h).length, 1); h.dom.window.close();
});

test('network-uncertain commit is reconciled by GET without resending the action', async () => {
  const h = await channelHarness([channelItem('delivery_restart')]); const fetch = h.dom.window.fetch, events = [];
  h.dom.window.addEventListener('lightwork:channel-review', event => events.push(event.detail));
  h.dom.window.fetch = async (url, init) => { const response = await fetch(url, init); if (url.endsWith('/operations/channel-review')) throw new Error('transport lost after commit'); return response; };
  completeCommon(h); enter(h, 'confirm', true); await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.equal(channelPosts(h).length, 1); assert.match(h.get('reconciliation-items').textContent, /could not confirm/);
  h.dom.window.document.activeElement.click(); await tick(); await tick();
  assert.match(h.get('reconciliation-items').textContent, /Review recorded/); assert.equal(channelPosts(h).length, 1);
  assert.equal(h.dom.window.document.activeElement, h.get('reconciliation-status'));
  assert.equal(events.at(-1).status, 'recorded'); assert.equal(events.at(-1).item_id, '1'.repeat(32));
  h.dom.window.close();
});

test('a channel-only refresh detects changed account before retaining or exposing the draft', async () => {
  const h = await channelHarness([channelItem('delivery_restart')]); completeCommon(h);
  const reference = formOf(h).elements.evidence_reference;
  h.state.context = 'another-person';
  [...formOf(h).querySelectorAll('button')].find(button => button.textContent === 'Refresh status').click(); await tick(); await tick();
  assert.equal(reference.value, ''); assert.equal(h.get('reconciliation-items').children.length, 0);
  assert.equal(h.dom.window.LightworkChannelReview.list().length, 0); assert.equal(channelPosts(h).length, 0);
  assert.match(h.get('status').textContent, /account changed/); h.dom.window.close();
});

test('transient GET failure keeps the draft visible but does not leave old mutation authority active', async () => {
  const h = await channelHarness([channelItem('delivery_restart')]); completeCommon(h); const fetch = h.dom.window.fetch;
  let failing = true;
  h.dom.window.fetch = async (url, init) => {
    if (url.endsWith('/reconciliation') && failing) throw new Error('private network error');
    return fetch(url, init);
  };
  [...formOf(h).querySelectorAll('button')].find(button => button.textContent === 'Refresh status').click(); await tick(); await tick();
  assert.equal(formOf(h).elements.evidence_reference.value, 'service-ticket-12345');
  assert.equal(formOf(h).elements.confirm.disabled, true); assert.doesNotMatch(h.get('reconciliation-items').textContent, /private network error/);
  assert.equal(h.dom.window.document.activeElement.textContent, 'Refresh status');
  await h.dom.window.LightworkChannelReview.submit('1'.repeat(32)); assert.equal(channelPosts(h).length, 0);
  failing = false; h.dom.window.document.activeElement.click(); await tick(); await tick();
  assert.equal(formOf(h).elements.evidence_reference.value, 'service-ticket-12345'); assert.equal(formOf(h).elements.confirm.disabled, false);
  assert.equal(formOf(h).elements.confirm.checked, false); h.dom.window.close();
});

for (const override of [
  { kind: 'unknown_family' }, { review_token: 'not-a-token' }, { status: 'maybe_done' },
  { execution_choices: ['unknown'] }, { chunks: [{ key: 'x', label: 'x', choices: ['recorded'], receipt_locked: 1, receipt: '' }] },
  { status: 'recording_incomplete', retry_answers: { kind: 'finish_recording', receipt: 'd'.repeat(64) },
    recorded_review: { kind: 'message', checked_at: new Date().toISOString(), evidence_reference: 'saved-evidence', execution: 'recorded', delivery: 'recorded', chunks: { extra: {} } } },
]) test('malformed channel descriptor fails closed without JSON fallback: ' + JSON.stringify(override), async () => {
  const h = await channelHarness([channelItem('message', override)]);
  assert.equal(formOf(h), null); assert.equal(h.get('reconciliation-items').querySelector('textarea'), null);
  assert.equal(h.dom.window.LightworkChannelReview.list().length, 0); assert.equal(channelPosts(h).length, 0);
  h.dom.window.close();
});

test('malformed success never claims recording complete and cannot replay automatically', async () => {
  const h = await channelHarness([channelItem('delivery_restart')], () => ({ state: 'resolved' }));
  completeCommon(h); enter(h, 'confirm', true); await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.match(h.get('reconciliation-items').textContent, /could not confirm/); assert.doesNotMatch(h.get('status').textContent, /Your review was recorded/);
  assert.equal(channelPosts(h).length, 1); assert.equal(formOf(h).querySelector('[type=submit]').disabled, true); h.dom.window.close();
});

test('an interrupted recording displays saved findings and sends only the exact opaque retry proof', async () => {
  const retry = { kind: 'finish_recording', receipt: 'd'.repeat(64) };
  const h = await channelHarness([channelItem('imessage_position', { status: 'recording_incomplete', retry_answers: retry,
    recorded_review: { kind: 'imessage_position', checked_at: new Date(Date.now() - 7200000).toISOString(), evidence_reference: 'original-service-evidence', position: '9007199254740993123' } })]);
  h.dom.window.LightworkChannelReview.select('1'.repeat(32)); const form = formOf(h);
  assert.equal(form.elements.position.value, '9007199254740993123'); assert.equal(form.elements.position.disabled, true);
  assert.equal(form.elements.checked_at.disabled, true); assert.equal(form.elements.evidence_reference.disabled, true);
  assert.match(form.textContent, /Finish recording this review/); assert.doesNotMatch(form.textContent, /within the last 15 minutes/);
  enter(h, 'confirm', true); await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.deepEqual(JSON.parse(channelPosts(h)[0].init.body).answers, retry); h.dom.window.close();
});

test('direct controls and Copilot share one mounted form, exact draft and explicit confirmation', async () => {
  let release; const blocked = new Promise(resolve => { release = resolve; });
  const h = await channelHarness([channelItem('delivery_restart')], async (_url, init, report) => {
    await blocked; const body = JSON.parse(init.body); report.items[0].state = 'resolved'; report.items[0].channel_review.status = 'recorded'; report.unresolved = 0;
    return { state: 'resolved', item_id: body.item_id, disposition: 'channel_readback_confirmed', unresolved: 0, automatic_replay_blocked: true, normal_start_blocked: true };
  });
  completeCommon(h); const form = formOf(h), api = h.dom.window.LightworkChannelReview;
  assert.equal(api.mount('1'.repeat(32), h.get('assistant-review')), true); assert.equal(formOf(h), form);
  assert.equal(h.get('assistant-review').contains(form), true); assert.equal(h.get('reconciliation-items').contains(form), false);
  assert.equal(api.prepare('1'.repeat(32)).status, 'needs_confirmation'); await api.submit('1'.repeat(32)); assert.equal(channelPosts(h).length, 0);
  enter(h, 'confirm', true); assert.equal(api.prepare('1'.repeat(32)).status, 'ready'); const first = api.submit('1'.repeat(32));
  await api.submit('1'.repeat(32)); api.unmount(); assert.equal(h.get('reconciliation-items').contains(form), true);
  assert.equal(channelPosts(h).length, 1); release(); await first; assert.equal(channelPosts(h).length, 1);
  assert.equal(h.get('assistant-review').children.length, 0); h.dom.window.close();
});

for (const status of [401, 403]) test(`channel ${status} erases mounted private evidence and cannot submit again`, async () => {
  const h = await channelHarness([channelItem('delivery_restart')]); completeCommon(h);
  const api = h.dom.window.LightworkChannelReview; api.mount('1'.repeat(32), h.get('assistant-review'));
  const field = formOf(h).elements.evidence_reference; let parsed = 0;
  h.dom.window.fetch = async () => ({ ok: false, status, json: async () => { parsed++; throw new Error('no JSON'); } });
  enter(h, 'confirm', true); await api.submit('1'.repeat(32));
  assert.equal(parsed, 0); assert.equal(field.value, ''); assert.equal(h.get('assistant-review').children.length, 0);
  assert.match(h.get('status').textContent, /Your recovery access is unavailable/);
  assert.equal(h.dom.window.document.activeElement, h.get('status'));
  assert.equal(api.list().length, 0); assert.equal((await api.submit('1'.repeat(32))).status, 'unavailable'); h.dom.window.close();
});

test('restore needs prepared target-bound review and explicit checkbox; changing selection invalidates it', async () => {
  const h = await harness(async url => url.endsWith('/prepare') ? { review: 'review-a', target: 'target-a', tenant: 'acme', application_version: '1.0.0', file_count: 3, restore_mode: 'ordinary' } : {});
  h.select();
  h.get('prepare').click(); await tick();
  assert.equal(h.get('restore').disabled, true);
  assert.equal(h.calls.some(c => c.url.endsWith('/restore')), false);
  h.get('confirm').checked = true; h.get('confirm').dispatchEvent(new h.dom.window.Event('change'));
  assert.equal(h.get('restore').disabled, false);
  h.select();
  assert.equal(h.get('restore').disabled, true);
  assert.equal(h.get('review').hidden, true);
  h.dom.window.close();
});

test('failed restore consumes displayed review and keeps the failure visible', async () => {
  const h = await harness(async url => url.endsWith('/prepare') ? { review: 'review-a', target: 'target-a', tenant: 'acme', application_version: '1.0.0', file_count: 3, restore_mode: 'ordinary' } : { error: 'Workspace files changed. Prepare a fresh review.' });
  h.select(); h.get('prepare').click(); await tick();
  h.get('confirm').checked = true; h.get('confirm').dispatchEvent(new h.dom.window.Event('change'));
  h.get('restore').click(); await tick();
  assert.match(h.get('status').textContent, /Workspace files changed/);
  assert.equal(h.get('restore').disabled, true);
  const call = h.calls.find(c => c.url.endsWith('/restore'));
  assert.deepEqual(JSON.parse(call.init.body), { review: 'review-a', target: 'target-a', confirm: true });
  assert.equal(call.init.headers['X-Lightwork-Recovery-Context'], 'account-context');
  h.dom.window.close();
});

test('normal dashboard never offers live restore and coverage is text-only', async () => {
  const h = await harness(async () => ({}), { live_restore_available: false, coverage: ['<img src=x onerror=alert(1)>'] });
  h.select();
  assert.equal(h.get('prepare').disabled, true);
  assert.equal(h.get('installation-authorize').disabled, true);
  assert.equal(h.get('coverage').querySelector('img'), null);
  assert.match(h.get('coverage').textContent, /<img/);
  h.dom.window.close();
});

test('whole-home maintenance needs separate consent and returns only bounded private grant', async () => {
  const authorization = 'a'.repeat(32) + ':' + 'b'.repeat(64);
  const h = await harness(async url => url.endsWith('/authorize') ? { authorization } : { recovery_points: [] }, {}, { native_review: nativeReleaseReview() });
  h.get('installation-handoff').checked = false; // Explicit manual-code fallback.
  assert.equal(h.get('installation-authorize').disabled, true);
  h.get('installation-confirm').checked = true;
  h.get('installation-confirm').dispatchEvent(new h.dom.window.Event('change'));
  h.get('installation-authorize').click(); await tick();
  const call = h.calls.find(c => c.url.endsWith('/authorize'));
  assert.deepEqual(JSON.parse(call.init.body), { confirm: true, confirm_all_workspaces: true, native_handoff: false, review_id: 'e'.repeat(32) });
  assert.equal(h.get('installation-code').value, authorization);
  assert.equal(h.get('installation-confirm').checked, false);
  assert.equal(h.calls.some(c => c.url.includes('execute')), false);
  h.state.context = 'different-account';
  h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('installation-code').value, '');
  h.dom.window.close();
});

for (const [label, change] of [
  ['missing', () => null],
  ['expired', row => ({ ...row, expires_at: Date.now() / 1000 - 1 })],
  ['malformed identity', row => ({ ...row, id: 'unreviewed' })],
  ['missing release', row => ({ ...row, release: {} })],
]) test(`${label} native release review cannot authorize an update even through a programmatic click`, async () => {
  const h = await harness(async () => ({}), {}, { native_review: change(nativeReleaseReview()) });
  confirmInstallation(h);
  assert.equal(h.get('installation-authorize').disabled, true);
  h.get('installation-authorize').dispatchEvent(new h.dom.window.Event('click')); await tick();
  assert.equal(h.calls.some(call => call.url.endsWith('/authorize')), false);
  assert.match(h.get('status').textContent, /Check for updates/);
  h.dom.window.close();
});

test('a release expiring while displayed is rechecked before any authorization request', async () => {
  const review = nativeReleaseReview();
  const h = await harness(async () => ({}), {}, { native_review: review });
  confirmInstallation(h); assert.equal(h.get('installation-authorize').disabled, false);
  h.dom.window.Date.now = () => review.expires_at * 1000 + 1;
  h.get('installation-authorize').click(); await tick();
  assert.equal(h.calls.some(call => call.url.endsWith('/authorize')), false);
  assert.equal(h.get('installation-authorize').disabled, true);
  h.dom.window.close();
});

test('failed review refresh removes old authority without changing protected handoff to manual code', async () => {
  const h = await harness(async () => ({}), {}, { native_review: nativeReleaseReview() });
  confirmInstallation(h); assert.equal(h.get('installation-authorize').disabled, false);
  assert.equal(h.get('installation-handoff').checked, true);
  let authorizations = 0;
  h.dom.window.fetch = async url => {
    if (url.endsWith('/authorize')) authorizations++;
    return url.endsWith('/status') ? { ok: true, status: 200, json: async () => h.state }
      : { ok: false, status: 503, json: async () => ({ detail: 'Native release review is unavailable.' }) };
  };
  h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('installation-confirm').checked, false);
  assert.equal(h.get('installation-native-review').textContent, '');
  assert.equal(h.get('installation-handoff').checked, true);
  confirmInstallation(h);
  h.get('installation-authorize').dispatchEvent(new h.dom.window.Event('click')); await tick();
  assert.equal(authorizations, 0);
  assert.equal(h.get('installation-authorize').disabled, true);
  h.dom.window.close();
});

test('protected handoff carries the exact review and keeps the grant out of the page', async () => {
  const h = await harness(async url => url.endsWith('/authorize')
    ? { native_handoff: true, expires_at: Date.now() / 1000 + 60 } : {}, {}, { native_review: nativeReleaseReview() });
  confirmInstallation(h); h.get('installation-authorize').click(); await tick();
  const calls = h.calls.filter(call => call.url.endsWith('/authorize'));
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].init.body), { confirm: true, confirm_all_workspaces: true, native_handoff: true, review_id: 'e'.repeat(32) });
  assert.equal(h.get('installation-code').value, '');
  assert.match(h.get('installation-result').textContent, /Nothing has been installed/);
  assert.equal(h.calls.some(call => call.url.includes('execute')), false);
  h.dom.window.close();
});

test('completed-upgrade rollback uses its selected point independently of an update review and needs fresh consent', async () => {
  const point = 'a'.repeat(32);
  let unavailable = false;
  const h = await harness(async url => url.endsWith('/installation')
    ? unavailable ? { error: 'Installation recovery points are unavailable.' }
      : { recovery_points: [{ id: point, status: 'upgraded', old_version: '1.0.0', new_version: '1.0.1' }] }
    : { native_handoff: true, expires_at: Date.now() / 1000 + 60 });
  confirmInstallation(h);
  h.get('installation-point').value = point;
  h.get('installation-point').dispatchEvent(new h.dom.window.Event('change'));
  assert.equal(h.get('installation-confirm').checked, false);
  assert.equal(h.get('installation-rollback').disabled, true);
  confirmInstallation(h);
  assert.equal(h.get('installation-authorize').disabled, true);
  assert.equal(h.get('installation-rollback').disabled, false);
  h.get('installation-rollback').click(); await tick();
  const call = h.calls.find(row => row.url.endsWith('/authorize'));
  assert.deepEqual(JSON.parse(call.init.body), { confirm: true, confirm_all_workspaces: true, native_handoff: true, rollback_id: point });
  unavailable = true;
  h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('installation-point').options.length, 0);
  confirmInstallation(h);
  h.get('installation-rollback').dispatchEvent(new h.dom.window.Event('click')); await tick();
  assert.equal(h.calls.filter(row => row.url.endsWith('/authorize')).length, 1);
  assert.equal(h.get('installation-rollback').disabled, true);
  h.dom.window.close();
});

test('wrong-target prepare response cannot create actionable restore controls', async () => {
  const h = await harness(async () => ({ review: 'review-a', target: 'other-workspace' }));
  h.select(); h.get('prepare').click(); await tick();
  assert.match(h.get('status').textContent, /does not match/);
  assert.equal(h.get('restore').disabled, true);
  assert.equal(h.get('review').hidden, true);
  h.dom.window.close();
});

test('shared encryption keys need separate consent and unresolved restore remains visible', async () => {
  const h = await harness(async () => ({}), { encryption_custody: { local_export_available: true, detail: 'Shared keys require separate custody.' }, last_restore: { state: 'completion_unconfirmed' } });
  assert.equal(h.get('encryption-download').disabled, true);
  h.get('encryption-confirm').checked = true;
  h.get('encryption-confirm').dispatchEvent(new h.dom.window.Event('change'));
  assert.equal(h.get('encryption-download').disabled, false);
  assert.match(h.get('last-restore').textContent, /does not have a verified completion receipt/);
  assert.match(h.get('encryption-status').textContent, /separate custody/);
  h.dom.window.close();
});

test('installation retirement requires exact selected point and fresh confirmation; refresh clears consent', async () => {
  const points = [
    { id: 'a'.repeat(32), status: 'authorized', old_version: '1.0.0', can_retire: true, record_sha256: 'b'.repeat(64) },
    { id: 'c'.repeat(32), status: 'upgraded', old_version: '1.0.0', new_version: '1.0.1', can_retire: false, retirement_blocker: 'This protects the installed application.' }
  ];
  const h = await harness(async url => url.endsWith('/installation') ? { recovery_points: points } : { retired: true });
  assert.equal(h.get('installation-retire').disabled, true);
  assert.equal(h.get('installation-retire-point').options.length, 2);
  assert.match(h.get('installation-retention-list').textContent, /protects the installed application/);
  h.get('installation-retire-point').value = 'a'.repeat(32);
  h.get('installation-retire-confirm').checked = true;
  h.get('installation-retire-confirm').dispatchEvent(new h.dom.window.Event('change'));
  h.get('installation-retire-point').dispatchEvent(new h.dom.window.Event('change'));
  assert.equal(h.get('installation-retire').disabled, true);
  h.get('installation-retire-confirm').checked = true;
  h.get('installation-retire-confirm').dispatchEvent(new h.dom.window.Event('change'));
  h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('installation-retire-confirm').checked, false);
  h.get('installation-retire-point').value = 'a'.repeat(32);
  h.get('installation-retire-confirm').checked = true;
  h.get('installation-retire-confirm').dispatchEvent(new h.dom.window.Event('change'));
  h.get('installation-retire').click(); h.get('installation-retire').click(); await tick(); await tick();
  const calls = h.calls.filter(call => call.url.includes('/installation/') && call.url.endsWith('/retire'));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/v1/recovery/installation/' + 'a'.repeat(32) + '/retire');
  assert.deepEqual(JSON.parse(calls[0].init.body), { confirm: true, sha256: 'b'.repeat(64) });
  assert.equal(h.get('installation-retire-confirm').checked, false);
  h.dom.window.close();
});

test('retirement failure stays visible and cannot automatically retry destructive action', async () => {
  const h = await harness(async url => url.endsWith('/installation') ? { recovery_points: [{ id: 'a'.repeat(32), status: 'authorized', old_version: '1.0.0', can_retire: true, record_sha256: 'b'.repeat(64) }] } : { error: 'This point became active. Finish recovery first.' });
  h.get('installation-retire-point').value = 'a'.repeat(32);
  h.get('installation-retire-confirm').checked = true;
  h.get('installation-retire-confirm').dispatchEvent(new h.dom.window.Event('change'));
  h.get('installation-retire').click(); await tick();
  assert.match(h.get('status').textContent, /became active/);
  assert.equal(h.get('installation-retire-confirm').checked, false);
  assert.equal(h.get('installation-retire').disabled, true);
  h.dom.window.close();
});

for (const deniedStatus of [401, 403]) {
  test(`HTML ${deniedStatus} removes private recovery state before parsing and blocks further actions`, async () => {
    const authorization = 'a'.repeat(32) + ':' + 'b'.repeat(64);
    const h = await harness(async url => url.endsWith('/authorize') ? { authorization } : { recovery_points: [
      { id: 'c'.repeat(32), status: 'authorized', old_version: '1.0.0', can_retire: true, record_sha256: 'd'.repeat(64) }
    ] }, {}, { native_review: nativeReleaseReview() });
    h.get('installation-handoff').checked = false;
    h.select();
    h.get('installation-confirm').checked = true;
    h.get('installation-confirm').dispatchEvent(new h.dom.window.Event('change'));
    h.get('installation-authorize').click(); await tick();
    assert.equal(h.get('installation-code').value.length, 97);
    h.get('key-input').value = 'synthetic private recovery key';
    h.get('result').textContent = 'Private snapshot verification';
    h.get('retire-confirm').checked = true;
    let requests = 0, parsed = 0;
    h.dom.window.fetch = async () => {
      requests++;
      return { ok: false, status: deniedStatus, json: async () => { parsed++; throw new Error('HTML sign-in response'); } };
    };
    h.get('inspect').click(); await tick();
    assert.equal(parsed, 0, 'Access denial must clear state without parsing an HTML response.');
    for (const field of ['installation-code', 'key-input']) assert.equal(h.get(field).value, '');
    for (const field of ['identity', 'result', 'installation-result', 'installation-retention-list', 'installation-native-review']) assert.equal(h.get(field).textContent, '');
    assert.equal(h.get('snapshot').options.length, 0);
    assert.equal(h.get('installation-retire-point').options.length, 0);
    assert.equal(h.get('retire-confirm').checked, false);
    assert.match(h.get('status').textContent, /reload/i);
    for (const button of h.dom.window.document.querySelectorAll('#workspace-recovery button')) assert.equal(button.disabled, true);
    h.get('refresh').dispatchEvent(new h.dom.window.Event('click'));
    h.get('create').dispatchEvent(new h.dom.window.Event('click'));
    await tick();
    assert.equal(requests, 1, 'Even programmatic clicks cannot reuse cached authority.');
    h.dom.window.close();
  });
}

test('service interruption preserves safe inputs and selection but invalidates all confirmations', async () => {
  const h = await harness(async url => url.endsWith('/prepare') ? { review: 'review-a', target: 'target-a', tenant: 'acme', application_version: '1.0.0', file_count: 3, restore_mode: 'ordinary' } : {});
  h.select(); h.get('prepare').click(); await tick();
  h.get('key-input').value = 'synthetic pending recovery key';
  for (const name of ['confirm', 'retire-confirm', 'encryption-confirm', 'installation-confirm', 'installation-retire-confirm']) h.get(name).checked = true;
  h.dom.window.fetch = async () => ({ ok: false, status: 503, json: async () => ({ detail: 'Synthetic temporary storage interruption' }) });
  h.get('inspect').click(); await tick();
  assert.equal(h.get('key-input').value, 'synthetic pending recovery key');
  assert.equal(h.get('snapshot').value, 'snapshot-a');
  assert.match(h.get('status').textContent, /temporary storage interruption/);
  for (const name of ['confirm', 'retire-confirm', 'encryption-confirm', 'installation-confirm', 'installation-retire-confirm']) assert.equal(h.get(name).checked, false);
  assert.equal(h.get('review').hidden, true);
  assert.equal(h.get('restore').disabled, true);
  assert.equal(h.get('refresh').disabled, false);
  h.dom.window.close();
});

function comparison(offset = 0, overrides = {}) {
  const total = 51, hash = 'a'.repeat(64);
  return { report_id: 'report-a', target: 'target-a', snapshot: { id: 'snapshot-a', sha256: hash, application_version: '1.0.0', compatibility: 'compatible' },
    compared_at: 1700000000, application_version: '1.0.0', total_changes: total, protected_changes: 2,
    live_file_count: 60, snapshot_file_count: 9, live_state_sha256: 'b'.repeat(64), snapshot_state_sha256: 'c'.repeat(64),
    offset, limit: 50, has_more: offset === 0, restore_authorized: false, isolated: false,
    items: Array.from({ length: Math.min(50, total - offset) }, (_, index) => ({
      path: index + offset === 0 ? '<img src=x onerror=alert(1)>.json' : 'records/file-' + (offset + index) + '.json',
      change: 'added', protected: index + offset < 2, snapshot: null, current: { sha256: hash, size: 32 }
    })), ...overrides };
}

test('comparison pages and downloads the exact captured report without enabling restore or treating metadata as HTML', async () => {
  const h = await harness(async (url, init) => {
    if (url.endsWith('/compare')) return comparison();
    if (url.endsWith('/comparison')) return comparison(JSON.parse(init.body).offset);
    return {};
  }, { live_restore_available: false });
  assert.equal(h.get('compare').disabled, true);
  h.select(); h.get('compare').click(); await tick();
  assert.equal(h.get('comparison-report').hidden, false);
  assert.match(h.get('comparison-summary').textContent, /51.*2/);
  assert.equal(h.get('comparison-items').children.length, 50);
  assert.match(h.get('comparison-items').textContent, /<img/);
  assert.equal(h.get('comparison-items').querySelector('img'), null);
  const first = h.get('comparison-items').children[0];
  const plain = [...first.children].filter(node => node.tagName !== 'DETAILS').map(node => node.textContent).join(' ');
  assert.match(plain, /Size in the snapshot: not present · Size now: 32 bytes\./);
  assert.doesNotMatch(plain, /fingerprint|[0-9a-f]{64}/);
  assert.equal(first.querySelector('details summary').textContent, 'Technical details');
  assert.equal(first.querySelector('details').open, false);
  assert.equal(h.get('prepare').disabled, true);
  assert.equal(h.get('comparison-previous').disabled, true);
  h.get('comparison-next').click(); await tick();
  assert.equal(h.get('comparison-items').children.length, 1);
  assert.match(h.get('comparison-status').textContent, /51.*51/);
  assert.equal(h.get('comparison-next').disabled, true);
  const next = h.calls.find(call => call.url.endsWith('/comparison'));
  assert.deepEqual(JSON.parse(next.init.body), { report_id: 'report-a', offset: 50, limit: 50 });
  assert.equal(next.init.headers['X-Lightwork-Recovery-Context'], 'account-context');
  let downloaded = '';
  h.dom.window.URL.createObjectURL = () => 'blob:synthetic-comparison';
  h.dom.window.URL.revokeObjectURL = () => {};
  h.dom.window.HTMLAnchorElement.prototype.click = function () { downloaded = this.download; };
  h.get('comparison-download').click(); await tick();
  assert.match(downloaded, /comparison.*\.json$/);
  const download = h.calls.find(call => call.url.endsWith('/comparison/download'));
  assert.deepEqual(JSON.parse(download.init.body), { report_id: 'report-a' });
  assert.equal(h.calls.some(call => /\/(prepare|restore|authorize)$/.test(call.url)), false);
  h.dom.window.close();
});

test('comparison rejects changed target, report identity or authority claims and cannot download stale evidence', async () => {
  for (const invalid of [{ target: 'other-target' }, { report_id: 'report-b' }, { live_state_sha256: 'd'.repeat(64) }, { restore_authorized: true }]) {
    const h = await harness(async url => url.endsWith('/compare') ? comparison() : url.endsWith('/comparison') ? comparison(50, invalid) : {});
    h.select(); h.get('compare').click(); await tick();
    h.get('comparison-next').click(); await tick();
    assert.equal(h.get('comparison-report').hidden, true);
    assert.equal(h.get('comparison-download').disabled, true);
    assert.equal(h.get('comparison-items').children.length, 0);
    assert.match(h.get('status').textContent, /comparison.*(changed|verified|match)/i);
    h.dom.window.close();
  }
});

test('snapshot edits during a comparison discard the late response and interruptions invalidate a loaded report', async () => {
  let complete;
  const h = await harness(async url => url.endsWith('/compare') ? new Promise(resolve => { complete = resolve; }) : {});
  h.select(); h.get('compare').click(); await tick();
  h.get('snapshot').value = ''; h.get('snapshot').dispatchEvent(new h.dom.window.Event('change'));
  complete(comparison()); await tick();
  assert.equal(h.get('comparison-report').hidden, true);
  assert.equal(h.get('comparison-download').disabled, true);
  h.select(); h.get('compare').click(); await tick(); complete(comparison()); await tick();
  assert.equal(h.get('comparison-report').hidden, false);
  h.dom.window.fetch = async () => ({ ok: false, status: 503, json: async () => ({ detail: 'Synthetic comparison storage interruption' }) });
  h.get('comparison-next').click(); await tick();
  assert.equal(h.get('snapshot').value, 'snapshot-a');
  assert.equal(h.get('comparison-report').hidden, true);
  assert.equal(h.get('comparison-download').disabled, true);
  assert.match(h.get('status').textContent, /storage interruption/);
  h.dom.window.close();
});

test('a late comparison download cannot complete after the selected snapshot changes', async () => {
  const h = await harness(async url => url.endsWith('/compare') ? comparison() : {});
  h.select(); h.get('compare').click(); await tick();
  let complete, downloads = 0;
  h.dom.window.URL.createObjectURL = () => { downloads++; return 'blob:synthetic-comparison'; };
  h.dom.window.URL.revokeObjectURL = () => {};
  h.dom.window.HTMLAnchorElement.prototype.click = function () {};
  h.dom.window.fetch = async () => ({ ok: true, status: 200, blob: () => new Promise(resolve => { complete = resolve; }) });
  h.get('comparison-download').click(); await tick();
  h.get('snapshot').value = ''; h.get('snapshot').dispatchEvent(new h.dom.window.Event('change'));
  complete(new h.dom.window.Blob(['{}'])); await tick();
  assert.equal(downloads, 0);
  assert.equal(h.get('comparison-download').disabled, true);
  assert.match(h.get('status').textContent, /comparison.*changed/i);
  h.dom.window.close();
});

test('auth loss while refreshing installation status clears the comparison and cannot be swallowed as a partial-load warning', async () => {
  const h = await harness(async url => url.endsWith('/compare') ? comparison() : {});
  h.select(); h.get('compare').click(); await tick();
  assert.equal(h.get('comparison-report').hidden, false);
  h.dom.window.fetch = async url => url.endsWith('/status') ? { ok: true, status: 200, json: async () => h.state }
    : { ok: false, status: 403, json: async () => { throw new Error('HTML denial must not be parsed'); } };
  h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('comparison-report').hidden, true);
  assert.equal(h.get('comparison-items').textContent, '');
  assert.equal(h.get('comparison-download').disabled, true);
  assert.equal(h.get('identity').textContent, '');
  assert.equal(h.get('refresh').disabled, true);
  assert.match(h.get('status').textContent, /reload/i);
  h.dom.window.close();
});

function drillReport(overrides = {}) {
  return { state: 'recorded', report_id: 'd'.repeat(32), snapshot: 'snapshot-a', target: 'target-a', archive_sha256: 'a'.repeat(64),
    snapshot_created_at: 1700000000, completed_at: 1700003600, application_version: '0.9.0', application_identity: 'b'.repeat(64),
    current_build_matches: false, file_count: 7, elapsed_seconds: 0.05, restored: true, post_restore_verified: true,
    restore_authorized: false, live_workspace_changed: false, external_stores_tested: false,
    verification_scope: 'File hashes, sizes and SQLite integrity only <img src=x>.', ...overrides };
}

test('saved restore evidence loads explicitly after reload and downloads the exact historical report without enabling restore', async () => {
  const h = await harness(async url => url.endsWith('/drill/report') ? drillReport() : {}, { live_restore_available: false });
  h.select();
  assert.equal(h.calls.some(call => call.url.includes('/drill')), false, 'Loading the page must not run a test or load private evidence automatically.');
  h.get('drill-report-load').click(); await tick();
  assert.equal(h.get('drill-report').hidden, false);
  assert.match(h.get('drill-report-summary').textContent, /7 files/);
  assert.match(h.get('drill-report-summary').textContent, /1 hour/);
  assert.match(h.get('drill-report-build').textContent, /different.*build/i);
  assert.equal(h.get('drill-report-scope').querySelector('img'), null);
  assert.match(h.get('drill-report-scope').textContent, /<img/);
  let downloaded = '';
  h.dom.window.URL.createObjectURL = () => 'blob:synthetic-drill';
  h.dom.window.URL.revokeObjectURL = () => {};
  h.dom.window.HTMLAnchorElement.prototype.click = function () { downloaded = this.download; };
  h.get('drill-report-download').click(); await tick();
  assert.match(downloaded, /restore-test.*\.json$/);
  const call = h.calls.find(call => call.url.endsWith('/drill/report/download'));
  assert.deepEqual(JSON.parse(call.init.body), { report_id: 'd'.repeat(32) });
  assert.equal(call.init.headers['X-Lightwork-Recovery-Context'], 'account-context');
  assert.equal(h.calls.some(call => /\/(drill|prepare|restore|authorize)$/.test(call.url)), false);
  assert.equal(h.get('prepare').disabled, true);
  h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('drill-report').hidden, true);
  assert.equal(h.get('drill-report-download').disabled, true);
  h.dom.window.close();
});

test('missing or invalid restore-test evidence never exposes a usable historical download', async () => {
  for (const body of [{ state: 'not_recorded', snapshot: 'snapshot-a' }, drillReport({ snapshot: 'other-snapshot' }),
    drillReport({ restored: false }), drillReport({ restore_authorized: true }), drillReport({ target: 'other-workspace' }),
    drillReport({ completed_at: 1699999999 })]) {
    const h = await harness(async url => url.endsWith('/drill/report') ? body : {});
    h.select(); h.get('drill-report-load').click(); await tick();
    assert.equal(h.get('drill-report').hidden, true);
    assert.equal(h.get('drill-report-download').disabled, true);
    assert.match(h.get('drill-report-status').textContent + h.get('status').textContent, /not.*recorded|could not be verified/i);
    h.dom.window.close();
  }
});

test('a snapshot change discards late saved-test responses and late signed downloads', async () => {
  let complete;
  const h = await harness(async url => url.endsWith('/drill/report') ? new Promise(resolve => { complete = resolve; }) : {});
  h.select(); h.get('drill-report-load').click(); await tick();
  h.get('snapshot').value = ''; h.get('snapshot').dispatchEvent(new h.dom.window.Event('change'));
  complete(drillReport()); await tick();
  assert.equal(h.get('drill-report').hidden, true);
  h.select(); h.get('drill-report-load').click(); await tick(); complete(drillReport()); await tick();
  let downloads = 0;
  h.dom.window.URL.createObjectURL = () => { downloads++; return 'blob:synthetic-drill'; };
  h.dom.window.fetch = async () => ({ ok: true, status: 200, blob: () => new Promise(resolve => { complete = resolve; }) });
  h.get('drill-report-download').click(); await tick();
  h.get('snapshot').value = ''; h.get('snapshot').dispatchEvent(new h.dom.window.Event('change'));
  complete(new h.dom.window.Blob(['{}'])); await tick();
  assert.equal(downloads, 0);
  assert.equal(h.get('drill-report-download').disabled, true);
  h.dom.window.close();
});

test('temporary failure invalidates saved-test evidence while retaining safe selection and inputs', async () => {
  const h = await harness(async url => url.endsWith('/drill/report') ? drillReport() : {});
  h.select(); h.get('drill-report-load').click(); await tick();
  assert.equal(h.get('drill-report').hidden, false);
  h.get('key-input').value = 'synthetic pending recovery key';
  h.dom.window.fetch = async () => ({ ok: false, status: 503, json: async () => ({ detail: 'Synthetic report interruption' }) });
  h.get('drill-report-download').click(); await tick();
  assert.equal(h.get('drill-report').hidden, true);
  assert.equal(h.get('drill-report-download').disabled, true);
  assert.equal(h.get('snapshot').value, 'snapshot-a');
  assert.equal(h.get('key-input').value, 'synthetic pending recovery key');
  h.dom.window.close();
});

for (const status of [401, 403]) test(`HTML ${status} clears retained drill metadata before parsing`, async () => {
  const h = await harness(async url => url.endsWith('/drill/report') ? drillReport() : {});
  h.select(); h.get('drill-report-load').click(); await tick();
  assert.equal(h.get('drill-report').hidden, false);
  let parsed = 0;
  h.dom.window.fetch = async () => ({ ok: false, status, json: async () => { parsed++; throw new Error('HTML denial'); } });
  h.get('drill-report-download').click(); await tick();
  assert.equal(parsed, 0);
  assert.equal(h.get('drill-report-summary').textContent, '');
  assert.equal(h.get('drill-report-identity').textContent, '');
  assert.equal(h.get('drill-report').hidden, true);
  for (const button of h.dom.window.document.querySelectorAll('#workspace-recovery button')) assert.equal(button.disabled, true);
  h.dom.window.close();
});

const custodyBytes = Buffer.from('synthetic custody zip fixture');
const custodyHash = require('node:crypto').createHash('sha256').update(custodyBytes).digest('hex');
function custodyReport(overrides = {}) {
  return { schema: 1, kind: 'workspace-custody-test', state: 'recorded', report_id: 'e'.repeat(32), snapshot: 'snapshot-a',
    archive_sha256: 'a'.repeat(64), custody_sha256: custodyHash, target: 'target-a', tenant: 'acme', application_version: '1.0.0', application_identity: 'source-sha256:' + 'b'.repeat(64),
    completed_at: 1700003600, snapshot_created_at: 1700000000, elapsed_seconds: 1.5, outcome: 'verified_supported_formats',
    checks: [{ format: 'Binary at-rest v1', detected: 2, verified: 2, failed: 0, unsupported: 0 }],
    files_scanned: 3, sqlite_columns_scanned: 0, unexamined_files: 0, fresh_process: true, key_source: 'uploaded-custody-copy',
    coverage_complete: false, restore_authorized: false, live_workspace_changed: false, external_stores_tested: false,
    limits: ['Custom formats were not tested.'], current_build_matches: true, ...overrides };
}
function chooseCustody(h, size) {
  const input = h.get('custody-file'), file = new h.dom.window.File([custodyBytes], 'separately-retained.zip', { type: 'application/zip' });
  file.arrayBuffer = async () => custodyBytes.buffer.slice(custodyBytes.byteOffset, custodyBytes.byteOffset + custodyBytes.byteLength);
  if (size !== undefined) Object.defineProperty(file, 'size', { value: size });
  let value = 'synthetic-file-selection';
  Object.defineProperty(input, 'value', { configurable: true, get: () => value, set: next => { value = next; } });
  Object.defineProperty(input, 'files', { configurable: true, get: () => value ? [file] : [] });
  Object.defineProperty(h.dom.window.crypto, 'subtle', { configurable: true, value: trackedSubtle() });
  input.dispatchEvent(new h.dom.window.Event('change'));
  return file;
}
function confirmCustody(h) { h.get('custody-confirm').checked = true; h.get('custody-confirm').dispatchEvent(new h.dom.window.Event('change')); }
// Hashing a chosen file uses WebCrypto, which finishes on the thread pool
// rather than within a fixed number of ticks; under load it can take longer.
// Count the page's in-flight WebCrypto calls and wait for them to finish.
const cryptoInFlight = { count: 0 };
function trackedSubtle() {
  const real = require('node:crypto').webcrypto.subtle;
  return new Proxy(real, {
    get(target, key) {
      const value = target[key];
      if (typeof value !== 'function') return value;
      return (...args) => {
        cryptoInFlight.count++;
        return Promise.resolve(value.apply(target, args)).finally(() => { cryptoInFlight.count--; });
      };
    },
  });
}
async function settleCustody() {
  for (let round = 0; round < 3; round++) {
    for (let i = 0; i < 5; i++) await tick();
    const deadline = Date.now() + 5000;
    while (cryptoInFlight.count > 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
  }
  for (let i = 0; i < 5; i++) await tick();
}
async function waitForCustody(predicate) {
  const deadline = Date.now() + 5000;
  while (!predicate() && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
  await settleCustody();
}

test('custody rehearsal requires a user file and fresh consent, binds inspected snapshot and uploaded bytes, and never autoexports keys', async () => {
  const h = await harness(async url => url.endsWith('/inspect') ? { id: 'snapshot-a', sha256: 'a'.repeat(64) } : url.endsWith('/custody-test') ? custodyReport() : {}, { live_restore_available: false });
  h.select();
  assert.equal(h.get('custody-test').disabled, true);
  const file = chooseCustody(h); assert.equal(h.get('custody-test').disabled, true);
  confirmCustody(h); assert.equal(h.get('custody-test').disabled, false);
  h.get('custody-test').click(); h.get('custody-test').click(); await settleCustody();
  const calls = h.calls.filter(call => call.url.endsWith('/custody-test'));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.body, file);
  assert.equal(calls[0].init.headers['Content-Type'], 'application/octet-stream');
  assert.equal(calls[0].init.headers['X-Lightwork-Confirm-Custody-Test'], 'true');
  assert.equal(calls[0].init.headers['X-Lightwork-Snapshot-SHA256'], 'a'.repeat(64));
  assert.equal(calls[0].init.headers['X-Lightwork-Recovery-Context'], 'account-context');
  assert.equal(h.calls.some(call => /encryption-keys|\/(prepare|restore|authorize)$/.test(call.url)), false);
  assert.equal(h.get('custody-file').value, ''); assert.equal(h.get('custody-confirm').checked, false);
  assert.equal(h.get('custody-report').hidden, false); assert.equal(h.get('prepare').disabled, true);
  h.dom.window.close();
});

test('oversized custody uploads and programmatic unconfirmed clicks never inspect or upload and clear the chosen file', async () => {
  const h = await harness(async () => ({})); h.select(); chooseCustody(h);
  h.get('custody-test').dispatchEvent(new h.dom.window.Event('click')); await settleCustody();
  assert.equal(h.calls.some(call => /inspect|custody-test/.test(call.url)), false);
  chooseCustody(h, 4 * 1024 * 1024 + 1); confirmCustody(h);
  h.get('custody-test').click(); await settleCustody();
  assert.equal(h.calls.some(call => /inspect|custody-test/.test(call.url)), false);
  assert.equal(h.get('custody-file').value, ''); assert.match(h.get('status').textContent, /4 MB/);
  h.dom.window.close();
});

test('custody results reject wrong upload/archive/workspace binding and unproven authority claims', async () => {
  for (const invalid of [{ custody_sha256: 'f'.repeat(64) }, { archive_sha256: 'f'.repeat(64) }, { target: 'elsewhere' },
    { tenant: 'other-tenant' }, { fresh_process: false }, { restore_authorized: true }, { coverage_complete: true },
    { key_source: 'host-keys' }, { outcome: 'no_encrypted_records' }, { checks: [{ format: 'v1', detected: 1, verified: 2, failed: 0, unsupported: 0 }] }]) {
    const h = await harness(async url => url.endsWith('/inspect') ? { id: 'snapshot-a', sha256: 'a'.repeat(64) } : url.endsWith('/custody-test') ? custodyReport(invalid) : {});
    h.select(); chooseCustody(h); confirmCustody(h); h.get('custody-test').click(); await settleCustody();
    assert.equal(h.get('custody-report').hidden, true);
    assert.equal(h.get('custody-report-download').disabled, true);
    assert.equal(h.get('custody-file').value, '');
    assert.match(h.get('status').textContent, /could not be verified/i); h.dom.window.close();
  }
});

test('changing the snapshot during custody inspection stops the upload; changing the file discards a late result', async () => {
  let complete;
  const h = await harness(async url => url.endsWith('/inspect') ? new Promise(resolve => { complete = resolve; }) : custodyReport());
  h.select(); chooseCustody(h); confirmCustody(h); h.get('custody-test').click(); await settleCustody();
  h.select(); complete({ id: 'snapshot-a', sha256: 'a'.repeat(64) }); await settleCustody();
  assert.equal(h.calls.some(call => call.url.endsWith('/custody-test')), false);
  h.dom.window.fetch = async url => url.endsWith('/inspect') ? { ok: true, status: 200, json: async () => ({ id: 'snapshot-a', sha256: 'a'.repeat(64) }) }
    : new Promise(resolve => { complete = () => resolve({ ok: true, status: 200, json: async () => custodyReport() }); });
  chooseCustody(h); confirmCustody(h); h.get('custody-test').click(); await settleCustody();
  chooseCustody(h); complete(); await settleCustody();
  assert.equal(h.get('custody-report').hidden, true); assert.equal(h.get('custody-file').value, '');
  h.dom.window.close();
});

test('historical custody reports load without file or autorun, retain explicit incomplete/failed outcomes, and render metadata as text', async () => {
  for (const outcome of ['verified_supported_formats', 'incomplete', 'failed', 'no_encrypted_records']) {
    const counts = outcome === 'no_encrypted_records' ? { detected: 0, verified: 0, failed: 0, unsupported: 0 }
      : { detected: 2, verified: outcome === 'verified_supported_formats' ? 2 : 1, failed: outcome === 'failed' ? 1 : 0, unsupported: outcome === 'incomplete' ? 1 : 0 };
    const row = custodyReport({ outcome, current_build_matches: false, limits: ['<img src=x>'], checks: [{ format: '<script>format</script>', ...counts }] });
    const h = await harness(async url => url.endsWith('/custody-test/report') ? row : {}, { live_restore_available: false });
    h.select(); assert.equal(h.calls.some(call => call.url.includes('/custody-test')), false);
    h.get('custody-report-load').click(); await settleCustody();
    assert.equal(h.get('custody-report').hidden, false);
    assert.equal(h.get('custody-checks').querySelector('script'), null);
    assert.equal(h.get('custody-limits').querySelector('img'), null);
    assert.match(h.get('custody-build').textContent, /different.*build/i);
    if (outcome === 'failed') { assert.match(h.get('custody-status').textContent, /Verification failed/); assert.doesNotMatch(h.get('custody-status').textContent, /formats verified/); }
    if (outcome === 'incomplete') assert.match(h.get('custody-status').textContent, /incomplete/);
    if (outcome === 'no_encrypted_records') assert.match(h.get('custody-status').textContent, /No encrypted records tested/);
    assert.equal(h.calls.some(call => call.url.endsWith('/custody-test')), false);
    let filename = '';
    h.dom.window.URL.createObjectURL = () => 'blob:synthetic-custody'; h.dom.window.URL.revokeObjectURL = () => {};
    h.dom.window.HTMLAnchorElement.prototype.click = function () { filename = this.download; };
    h.get('custody-report-download').click(); await settleCustody();
    assert.match(filename, /retained-key-test.*\.json$/);
    assert.deepEqual(JSON.parse(h.calls.find(call => call.url.endsWith('/custody-test/report/download')).init.body), { report_id: row.report_id });
    h.dom.window.close();
  }
});

test('recovery summary keeps failed and unsupported coverage visible outside the closed technical details',async()=>{
  const report=custodyReport({outcome:'failed',elapsed_seconds:0.855624,unexamined_files:2,checks:[{format:'raw-v1',detected:3,verified:2,failed:1,unsupported:0},{format:'raw-v2',detected:2,verified:1,failed:0,unsupported:1}]});
  const h=await harness(async()=>report);h.select();h.get('custody-report-load').click();await settleCustody();
  assert.match(h.get('custody-totals').textContent,/3 recognized encrypted records verified; 1 failed; 1 unsupported/);
  assert.match(h.get('custody-totals').textContent,/2 files were not examined/);assert.equal(h.get('custody-totals').closest('details'),null);
  assert.match(h.get('custody-coverage').textContent,/database columns scanned/);assert.doesNotMatch(h.get('custody-coverage').textContent,/SQLite/);
  assert.equal(h.get('custody-checks').closest('details').open,false);assert.match(h.get('custody-summary').textContent,/0.9 seconds/);assert.doesNotMatch(h.get('custody-summary').textContent,/0.855624/);h.dom.window.close();
});

test('custody 503 clears sensitive file and confirmation, retains safe snapshot, and invalidates historical download', async () => {
  const h = await harness(async url => url.endsWith('/custody-test/report') ? custodyReport() : {});
  h.select(); h.get('custody-report-load').click(); await settleCustody();
  chooseCustody(h); confirmCustody(h);
  h.dom.window.fetch = async () => ({ ok: false, status: 503, json: async () => ({ detail: 'Synthetic storage interruption' }) });
  h.get('custody-test').click(); await settleCustody();
  assert.equal(h.get('custody-file').value, ''); assert.equal(h.get('custody-confirm').checked, false);
  assert.equal(h.get('snapshot').value, 'snapshot-a'); assert.equal(h.get('custody-report-download').disabled, true);
  h.dom.window.close();
});

for (const status of [401, 403]) test(`HTML ${status} clears uploaded custody material and all report metadata before parsing`, async () => {
  const h = await harness(async url => url.endsWith('/custody-test/report') ? custodyReport() : {});
  h.select(); chooseCustody(h); h.get('custody-report-load').click(); await settleCustody();
  let parsed = 0;
  h.dom.window.fetch = async () => ({ ok: false, status, json: async () => { parsed++; throw new Error('HTML denial'); } });
  h.get('custody-report-download').click(); await settleCustody();
  assert.equal(parsed, 0); assert.equal(h.get('custody-file').value, '');
  assert.equal(h.get('custody-identity').textContent, ''); assert.equal(h.get('custody-checks').textContent, '');
  for (const button of h.dom.window.document.querySelectorAll('#workspace-recovery button')) assert.equal(button.disabled, true);
  h.dom.window.close();
});

test('a late custody report download is suppressed after snapshot reselection', async () => {
  const h = await harness(async url => url.endsWith('/custody-test/report') ? custodyReport() : {});
  h.select(); h.get('custody-report-load').click(); await settleCustody();
  let complete, downloads = 0;
  h.dom.window.URL.createObjectURL = () => { downloads++; return 'blob:synthetic-custody'; };
  h.dom.window.fetch = async () => ({ ok: true, status: 200, blob: () => new Promise(resolve => { complete = resolve; }) });
  h.get('custody-report-download').click(); await settleCustody();
  h.select(); complete(new h.dom.window.Blob(['{}'])); await settleCustody();
  assert.equal(downloads, 0); assert.equal(h.get('custody-report-download').disabled, true); h.dom.window.close();
});

function transitionSummary() {
  return { sha256: 'a'.repeat(64), from_version: '1.0.0', to_version: '1.0.1',
    from_publisher: '<img src=x>', to_publisher: 'B'.repeat(40), from_key_sha256: 'c'.repeat(64),
    to_key_sha256: 'd'.repeat(64), expires_at: 2000000000, publisher_os_trust_checked: false };
}
function chooseTransition(h, size = 20) {
  const input = h.get('installation-transition-file'), file = new h.dom.window.File(['{"synthetic":true}'], 'bridge.json');
  file.text = async () => '{"synthetic":true}';
  Object.defineProperty(file, 'size', { value: size });
  let value = 'synthetic-bridge-selection';
  Object.defineProperty(input, 'value', { configurable: true, get: () => value, set: next => { value = next; } });
  Object.defineProperty(input, 'files', { configurable: true, get: () => value ? [file] : [] });
  input.dispatchEvent(new h.dom.window.Event('change')); return file;
}
function confirmInstallation(h, transition = false) {
  const id = transition ? 'installation-transition-confirm' : 'installation-confirm';
  h.get(id).checked = true; h.get(id).dispatchEvent(new h.dom.window.Event('change'));
}
test('signing transition grant binds verified uploaded bytes and requires separate fresh consent', async () => {
  const h = await harness(async url => url.endsWith('/identity-transition') ? transitionSummary() : url.endsWith('/authorize') ? { authorization: 'a'.repeat(32) + ':' + 'b'.repeat(64) } : {}, {}, { native_review: nativeReleaseReview() });
  h.get('installation-handoff').checked = false;
  chooseTransition(h); confirmInstallation(h);
  assert.equal(h.get('installation-authorize').disabled, true);
  h.get('installation-authorize').dispatchEvent(new h.dom.window.Event('click')); await tick();
  assert.equal(h.calls.some(call => call.url.endsWith('/authorize')), false);
  h.get('installation-transition-review').click(); await settleCustody();
  assert.equal(h.get('installation-authorize').disabled, true);
  assert.equal(h.get('installation-transition-details').querySelector('img'), null);
  assert.match(h.get('installation-transition-details').textContent, /Windows verifies each installer/);
  confirmInstallation(h, true); h.get('installation-authorize').click(); await settleCustody();
  const call = h.calls.find(call => call.url.endsWith('/authorize'));
  assert.deepEqual(JSON.parse(call.init.body), { confirm: true, confirm_all_workspaces: true, native_handoff: false, review_id: 'e'.repeat(32),
    identity_transition: '{"synthetic":true}', transition_sha256: 'a'.repeat(64), confirm_identity_transition: true });
  assert.equal(call.init.headers['X-Lightwork-Recovery-Context'], 'account-context');
  assert.equal(h.get('installation-transition-file').value, '');
  assert.equal(h.get('installation-transition-confirm').checked, false); h.dom.window.close();
});
test('oversized bridge is not uploaded and a changed file cannot use a late transition review', async () => {
  let complete;
  const h = await harness(async url => url.endsWith('/identity-transition') ? new Promise(resolve => { complete = resolve; }) : {});
  chooseTransition(h, 65537); h.get('installation-transition-review').click(); await settleCustody();
  assert.equal(h.calls.some(call => call.url.endsWith('/identity-transition')), false);
  assert.match(h.get('status').textContent, /64 KB/);
  chooseTransition(h); h.get('installation-transition-review').click(); await settleCustody();
  chooseTransition(h); complete(transitionSummary()); await settleCustody();
  assert.equal(h.get('installation-transition-details').textContent, '');
  assert.equal(h.get('installation-transition-confirm').disabled, true);
  assert.equal(h.get('installation-authorize').disabled, true); h.dom.window.close();
});
for (const status of [401, 403]) test(`HTML ${status} revokes bridge review before parsing and clears selected material`, async () => {
  const h = await harness(async url => url.endsWith('/identity-transition') ? transitionSummary() : {}, {}, { native_review: nativeReleaseReview() });
  chooseTransition(h); h.get('installation-transition-review').click(); await settleCustody();
  confirmInstallation(h); confirmInstallation(h, true);
  let parsed = 0;
  h.dom.window.fetch = async () => ({ ok: false, status, json: async () => { parsed++; throw new Error('HTML denial'); } });
  h.get('installation-authorize').click(); await settleCustody();
  assert.equal(parsed, 0); assert.equal(h.get('installation-transition-file').value, '');
  assert.equal(h.get('installation-transition-details').textContent, '');
  assert.equal(h.get('installation-transition-confirm').checked, false);
  assert.equal(h.get('installation-authorize').disabled, true); h.dom.window.close();
});

function reconciliationItem(overrides = {}) {
  return {
    id: '1'.repeat(32), category: 'queued_work', source: 'jobs.sqlite', record_id: 'job-1',
    prior_state: 'queued', safe_state: 'reconciliation_required', requires_external_readback: false,
    state: 'unresolved', ...overrides,
  };
}

function reconciliationReport(items, overrides = {}) {
  return {
    state: 'reconciliation_required', items, unresolved: items.filter(item => item.state === 'unresolved').length,
    protected_authority: {
      classification_complete: true, file_count: 12, classified_count: 12, state_sha256: '9'.repeat(64),
    },
    ...overrides,
  };
}

function chooseCustodyInstall(h, bytes = custodyBytes) {
  const input = h.get('custody-install-file');
  const file = new h.dom.window.File([bytes], 'exact-tested-keys.zip', { type: 'application/zip' });
  file.arrayBuffer = async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  let value = 'synthetic-install-selection';
  Object.defineProperty(input, 'value', { configurable: true, get: () => value, set: next => { value = next; } });
  Object.defineProperty(input, 'files', { configurable: true, get: () => value ? [file] : [] });
  Object.defineProperty(h.dom.window.crypto, 'subtle', { configurable: true, value: trackedSubtle() });
  input.dispatchEvent(new h.dom.window.Event('change'));
  return file;
}

test('new-install recovery requires the source-offline declaration and sends only the bounded bootstrap request', async () => {
  const h = await harness(async url => url.endsWith('/bootstrap/prepare')
    ? { state: 'prepared', bootstrap_id: 'a'.repeat(32) } : {}, { recovery_mode: true });
  assert.equal(h.get('bootstrap-prepare').disabled, true);
  h.get('bootstrap-prepare').dispatchEvent(new h.dom.window.Event('click')); await tick();
  assert.equal(h.calls.some(call => call.url.endsWith('/bootstrap/prepare')), false);
  h.get('bootstrap-source-offline').checked = true;
  h.get('bootstrap-source-offline').dispatchEvent(new h.dom.window.Event('change'));
  assert.equal(h.get('bootstrap-prepare').disabled, false);
  h.get('bootstrap-prepare').click(); await tick(); await tick();
  const calls = h.calls.filter(call => call.url.endsWith('/bootstrap/prepare'));
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].init.body), { confirm: true, source_offline: true });
  assert.equal(calls[0].init.headers['X-Lightwork-Recovery-Context'], 'account-context');
  assert.equal(calls[0].init.headers['X-Lightwork-Expected-Tenant'], 'acme');
  assert.equal(h.get('bootstrap-source-offline').checked, false);
  h.dom.window.close();
});

test('interrupted bootstrap recovery resumes once and exposes held work without automatic completion', async () => {
  const bootstrap = { state: 'restore_pending' };
  const held = reconciliationReport([reconciliationItem()]);
  const h = await harness(async (url, init) => {
    if (url.endsWith('/bootstrap/resume')) { bootstrap.state = 'reconciliation_required'; return { state: 'reconciliation_required' }; }
    if (url.endsWith('/reconciliation')) return bootstrap.state === 'restore_pending'
      ? { state: 'restore_pending', items: [], unresolved: 0 } : held;
    return {};
  }, { recovery_mode: true, bootstrap });
  assert.equal(h.get('bootstrap-resume').disabled, false);
  h.get('bootstrap-resume').click(); h.get('bootstrap-resume').click(); await tick(); await tick();
  const calls = h.calls.filter(call => call.url.endsWith('/bootstrap/resume'));
  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(calls[0].init.body), { confirm: true });
  assert.equal(h.get('reconciliation').hidden, false);
  assert.match(h.get('reconciliation-status').textContent, /1 restored item remains unresolved/);
  assert.equal(h.calls.some(call => call.url.endsWith('/reconciliation/complete')), false);
  h.dom.window.close();
});

test('key installation rechecks the exact tested ZIP and binds snapshot, report and fresh consent', async () => {
  const bootstrap = { state: 'prepared', retained_keys: { state: 'not_installed' } };
  const h = await harness(async (url, init) => {
    if (url.endsWith('/reconciliation')) return { state: 'prepared', items: [], unresolved: 0 };
    if (url.endsWith('/custody-test/report')) return custodyReport();
    if (url.endsWith('/retained-keys/install')) {
      bootstrap.retained_keys = { state: 'installed' };
      return { state: 'installed', file_count: 2, key_set_sha256: '8'.repeat(64) };
    }
    return {};
  }, { recovery_mode: true, bootstrap });
  h.select(); h.get('custody-report-load').click(); await settleCustody();
  assert.equal(h.get('custody-install-panel').hidden, false);
  const file = chooseCustodyInstall(h);
  assert.equal(h.get('custody-install').disabled, true);
  h.get('custody-install').dispatchEvent(new h.dom.window.Event('click')); await settleCustody();
  assert.equal(h.calls.some(call => call.url.endsWith('/retained-keys/install')), false);
  h.get('custody-install-confirm').checked = true;
  h.get('custody-install-confirm').dispatchEvent(new h.dom.window.Event('change'));
  h.get('custody-install').click(); h.get('custody-install').click();
  await waitForCustody(() => h.calls.some(call => call.url.endsWith('/retained-keys/install')));
  const calls = h.calls.filter(call => call.url.endsWith('/retained-keys/install'));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.body, file);
  assert.equal(calls[0].init.headers['Content-Type'], 'application/octet-stream');
  assert.equal(calls[0].init.headers['X-Lightwork-Confirm-Key-Install'], 'true');
  assert.equal(calls[0].init.headers['X-Lightwork-Snapshot-SHA256'], 'a'.repeat(64));
  assert.equal(calls[0].init.headers['X-Lightwork-Custody-Report'], 'e'.repeat(32));
  assert.equal(h.get('custody-install-file').value, '');
  assert.equal(h.get('custody-install-confirm').checked, false);
  h.dom.window.close();
});

test('a different key ZIP cannot reuse retained-key evidence or send an install request', async () => {
  const h = await harness(async url => url.endsWith('/reconciliation')
    ? { state: 'prepared', items: [], unresolved: 0 }
    : url.endsWith('/custody-test/report') ? custodyReport() : {}, {
    recovery_mode: true, bootstrap: { state: 'prepared', retained_keys: { state: 'not_installed' } },
  });
  h.select(); h.get('custody-report-load').click(); await settleCustody();
  chooseCustodyInstall(h, Buffer.from('different key bytes'));
  h.get('custody-install-confirm').checked = true;
  h.get('custody-install-confirm').dispatchEvent(new h.dom.window.Event('change'));
  h.get('custody-install').click();
  await waitForCustody(() => /does not match/.test(h.get('status').textContent));
  assert.equal(h.calls.some(call => call.url.endsWith('/retained-keys/install')), false);
  assert.match(h.get('status').textContent, /does not match the signed retained-key test/);
  assert.equal(h.get('custody-install-file').value, '');
  assert.equal(h.get('custody-install-confirm').checked, false);
  h.dom.window.close();
});

test('restored work renders as text and records each disposition without completing recovery', async () => {
  const report = reconciliationReport([
    reconciliationItem({ category: '<img src=x onerror=alert(1)>', source: '<script>source</script>' }),
    reconciliationItem({ id: '2'.repeat(32), category: 'external_action', source: 'provider/<img src=x>', record_id: 'attempt-2',
      prior_state: 'executing', safe_state: 'failed', requires_external_readback: true }),
  ]);
  const h = await harness(async (url, init) => {
    if (url.endsWith('/reconciliation')) return report;
    if (url.includes('/reconciliation/items/')) {
      const id = url.split('/').pop(), item = report.items.find(row => row.id === id);
      item.state = 'resolved'; item.disposition = JSON.parse(init.body).disposition; report.unresolved--;
      return { state: 'resolved', unresolved: report.unresolved };
    }
    return {};
  }, { recovery_mode: true, bootstrap: { state: 'reconciliation_required' } });
  assert.equal(h.get('reconciliation-items').querySelector('img'), null);
  assert.equal(h.get('reconciliation-items').querySelector('script'), null);
  assert.match(h.get('reconciliation-items').textContent, /<img/);
  let retire = [...h.get('reconciliation-items').querySelectorAll('button')].find(button => /Retire restored request/.test(button.textContent));
  retire.click(); await tick(); await tick();
  let call = h.calls.find(row => row.url.endsWith('/' + '1'.repeat(32)));
  assert.deepEqual(JSON.parse(call.init.body), { confirm: true, disposition: 'retire_and_create_new_request', evidence_reference: null });
  const evidence = h.get('reconciliation-items').querySelector('input[type="text"]');
  evidence.value = 'ticket-12345';
  const record = [...h.get('reconciliation-items').querySelectorAll('button')].find(button => /It did happen: record it/.test(button.textContent));
  record.click(); await tick(); await tick();
  call = h.calls.find(row => row.url.endsWith('/' + '2'.repeat(32)));
  assert.deepEqual(JSON.parse(call.init.body), { confirm: true, disposition: 'external_effect_recorded', evidence_reference: 'ticket-12345' });
  assert.equal(report.unresolved, 0);
  assert.equal(h.get('reconciliation-complete').disabled, true);
  assert.equal(h.calls.some(row => row.url.endsWith('/reconciliation/complete')), false);
  h.dom.window.close();
});

test('an unclassified authority keeps startup blocked and offers only in-app support', async () => {
  const report = reconciliationReport([reconciliationItem({
    category: 'unclassified_authority', source: 'unknown.sqlite', record_id: '', prior_state: 'unknown',
    safe_state: 'global_start_blocked', requires_external_readback: false,
  })]);
  const h = await harness(async url => url.endsWith('/reconciliation') ? report : {}, {
    recovery_mode: true, bootstrap: { state: 'reconciliation_required' },
  });
  assert.equal(h.get('reconciliation-blocked').hidden, false);
  assert.equal(h.get('reconciliation-items').querySelectorAll('button').length, 0);
  assert.equal(h.get('reconciliation-confirm').disabled, true);
  assert.equal(h.get('reconciliation-complete').disabled, true);
  assert.equal(h.get('reconciliation-blocked').querySelector('a').getAttribute('href'), '/help');
  assert.equal(h.calls.some(call => call.url.includes('/reconciliation/items/')), false);
  h.dom.window.close();
});

test('malformed restored-work inventory stays fail-closed with no disposition controls', async () => {
  const malformed = reconciliationReport([reconciliationItem()], { unresolved: 0 });
  const h = await harness(async url => url.endsWith('/reconciliation') ? malformed : {}, {
    recovery_mode: true, bootstrap: { state: 'reconciliation_required' },
  });
  assert.equal(h.get('reconciliation-items').children.length, 0);
  assert.equal(h.get('reconciliation-confirm').disabled, true);
  assert.equal(h.get('reconciliation-complete').disabled, true);
  assert.match(h.get('reconciliation-status').textContent, /count changed/);
  h.dom.window.close();
});

for (const status of [401, 403]) test(`HTML ${status} clears reconciliation evidence before parsing and revokes every action`, async () => {
  const report = reconciliationReport([reconciliationItem({ requires_external_readback: true })]);
  const h = await harness(async url => url.endsWith('/reconciliation') ? report : {}, {
    recovery_mode: true, bootstrap: { state: 'reconciliation_required' },
  });
  const evidence = h.get('reconciliation-items').querySelector('input[type="text"]'); evidence.value = 'ticket-private-123';
  let parsed = 0, requests = 0;
  h.dom.window.fetch = async () => { requests++; return { ok: false, status, json: async () => { parsed++; throw new Error('HTML denial'); } }; };
  const actionButton = h.get('reconciliation-items').querySelector('button'); actionButton.click(); await tick(); await tick();
  assert.equal(requests, 1); assert.equal(parsed, 0);
  assert.equal(h.get('reconciliation').hidden, true);
  assert.equal(h.get('reconciliation-items').children.length, 0);
  assert.equal(evidence.value, '');
  for (const button of h.dom.window.document.querySelectorAll('#workspace-recovery button')) assert.equal(button.disabled, true);
  h.dom.window.close();
});

test('held reading positions are recorded with plain fields and exact checkpoint shapes', async () => {
  const base = { schema: 1, record_id: 'cur-1', source_sha256: 'b'.repeat(64), binding_sha256: 'c'.repeat(64),
    observed_at: null, evidence_reference: '', outcome: 'unknown' };
  const cases = [
    [{ ...base, namespace: 'imessage-intake-cursors', checkpoint: { last_rowid: null } }, (items) => { items.querySelector('input[type="number"]').value = '42'; }, { last_rowid: 42 }],
    [{ ...base, namespace: 'channel-delivery-cursors', checkpoint: { cursor: '' } }, () => {}, { cursor: '' }],
    [{ ...base, namespace: 'channel-intake-cursors', checkpoint: { watermark: '' } }, (items) => { items.querySelectorAll('input[type="text"]')[1].value = '1234'; }, { watermark: '1234' }],
  ];
  for (const [template, fill, checkpoint] of cases) {
    const item = reconciliationItem({ category: 'channel_authority', safe_state: 'channel_restore_held',
      requires_external_readback: true, readback_template: template });
    const h = await harness(async url => url.endsWith('/reconciliation') ? reconciliationReport([item]) : {}, {
      recovery_mode: true, bootstrap: { state: 'reconciliation_required' },
    });
    const items = h.get('reconciliation-items');
    assert.equal(items.querySelector('textarea'), null);
    items.querySelector('input[type="text"]').value = 'service-log-2024';
    fill(items);
    [...items.querySelectorAll('button')].find(b => /Confirm what I found/.test(b.textContent)).click(); await tick(); await tick();
    const call = h.calls.find(row => row.url.includes('/reconciliation/items/'));
    const body = JSON.parse(call.init.body).channel_readback;
    assert.deepEqual(body.checkpoint, checkpoint);
    assert.equal(body.outcome, 'confirmed'); assert.equal(body.evidence_reference, 'service-log-2024');
    assert.equal(typeof body.observed_at, 'number');
    h.dom.window.close();
  }
});

test('the private approval code copies in recovery mode with feedback beside its button', async () => {
  const h = await harness(async () => ({}));
  const copied = [];
  Object.defineProperty(h.dom.window.navigator, 'clipboard', { configurable: true,
    value: { writeText: async text => { copied.push(text); } } });
  const button = h.dom.window.document.getElementById('wrec-installation-code-copy');
  const status = h.get('installation-code-copy-status');
  assert.equal(button.textContent, 'Copy code');
  button.click();
  assert.deepEqual(copied, []);
  assert.match(status.textContent, /no approval code yet/);
  h.get('installation-code').value = '  code-123  ';
  button.click(); await tick();
  assert.deepEqual(copied, ['code-123']);
  assert.match(status.textContent, /code copied/);
  h.dom.window.navigator.clipboard.writeText = async () => { throw new Error('clipboard unavailable'); };
  button.click(); await tick();
  assert.match(status.textContent, /selected above/);
  assert.equal(h.dom.window.document.activeElement, h.get('installation-code'));
  h.dom.window.close();
});

test('changed review on item refresh focuses the visible review toggle rather than a hidden control', async () => {
  const h = await channelHarness([channelItem('delivery_restart')]); completeCommon(h);
  h.report.items[0].channel_review.review_token = 'b'.repeat(64);
  [...formOf(h).querySelectorAll('button')].find(button => button.textContent === 'Refresh status').click(); await tick(); await tick();
  assert.equal(formOf(h).hidden, true); assert.equal(formOf(h).elements.evidence_reference.value, '');
  assert.equal(h.dom.window.document.activeElement.textContent, 'Review this connection');
  assert.equal(channelPosts(h).length, 0); h.dom.window.close();
});
