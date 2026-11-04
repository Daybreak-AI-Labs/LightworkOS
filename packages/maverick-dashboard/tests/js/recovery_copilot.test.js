const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const base = path.join(__dirname, '../../maverick_dashboard');
const html = fs.readFileSync(path.join(base, 'templates/workspace_recovery.html'), 'utf8');
const scripts = ['lightwork-workspace-recovery.js', 'lightwork-recovery-copilot.js'].map(name => fs.readFileSync(path.join(base, 'static', name), 'utf8'));
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

async function setup(mode = 'success') {
  const dom = new JSDOM(html, { url: 'http://localhost/workspace/recovery', runScripts: 'outside-only' });
  const id = '1'.repeat(32), calls = [];
  const item = { id, category: 'channel_authority', source: 'channel-delivery-cursors/private.json', record_id: 'private-id',
    prior_state: 'checkpoint/held', safe_state: 'channel_restore_held', requires_external_readback: true, state: 'unresolved',
    channel_review: { schema: 1, kind: 'delivery_restart', review_token: 'a'.repeat(64), title: 'Review collection',
      source_label: 'Connected service', status: 'review_required', restored_at: new Date(Date.now() - 600000).toISOString() } };
  const report = { state: 'reconciliation_required', items: [item], unresolved: 1,
    protected_authority: { classification_complete: true, file_count: 1, classified_count: 1, state_sha256: '9'.repeat(64) } };
  const state = { tenant: 'acme', context: 'current-admin', expected_tenant: 'acme', target: 'target',
    application_version: '1', key_id: 'key', coverage: [], excluded: [], restore_blockers: [],
    live_restore_available: false, snapshots: [], max_archive_bytes: 1000, recovery_mode: true,
    bootstrap: { state: 'reconciliation_required' } };
  let deny = false;
  dom.window.fetch = async (url, init) => {
    calls.push({url, init});
    let payload = {}, status = 200;
    if (deny) { payload = { detail: 'Access changed' }; status = 403; }
    else if (url.endsWith('/status')) payload = state;
    else if (url.endsWith('/reconciliation')) payload = report;
    else if (url.endsWith('/operations/channel-review')) {
      if (mode === 'uncertain') throw new Error('Disconnected after submit');
      item.state = 'resolved'; item.channel_review.status = 'recorded'; report.unresolved = 0;
      payload = { state: 'resolved', item_id: id, disposition: 'channel_readback_confirmed', unresolved: 0,
        automatic_replay_blocked: true, normal_start_blocked: true };
    }
    return { ok: status === 200, status, json: async () => JSON.parse(JSON.stringify(payload)) };
  };
  scripts.forEach(source => dom.window.eval(source));
  await tick(); await tick();
  const get = key => dom.window.document.getElementById('wrec-' + key);
  const form = () => dom.window.document.getElementById('wrec-channel-' + id);
  function enter(key, value) {
    const input = form().elements.namedItem(key);
    if (key === 'confirm') input.checked = value; else input.value = value;
    input.dispatchEvent(new dom.window.Event('change', { bubbles: true }));
  }
  function choose() {
    get('assistant-item').value = id;
    get('assistant-item').dispatchEvent(new dom.window.Event('change'));
    get('assistant-open').click();
  }
  function fill() {
    const now = new Date(Date.now() - 30000), pad = n => String(n).padStart(2, '0');
    enter('checked_at', `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`);
    enter('evidence_reference', 'reviewed-ticket-123');
  }
  const posts = () => calls.filter(row => row.init.method === 'POST');
  return {dom, get, form, enter, choose, fill, posts, calls, state, deny: () => { deny = true; }};
}

test('recovery Copilot hosts the actual review, retains drafts, and records through the same operation only after consent', async () => {
  const h = await setup();
  const original = h.form();
  assert.equal(h.get('assistant').hidden, false);
  assert.equal(h.get('assistant-open').disabled, true);
  h.choose(); h.fill();
  assert.equal(h.get('assistant-review').querySelector('form'), original);
  assert.equal(h.get('reconciliation-items').querySelector('form'), null);
  original.querySelector('[type=submit]').click(); await tick();
  assert.equal(h.posts().length, 0);
  h.get('assistant-close').click();
  assert.equal(h.get('reconciliation-items').querySelector('form'), original);
  assert.equal(original.elements.evidence_reference.value, 'reviewed-ticket-123');
  assert.equal(h.get('assistant-close').disabled, true);
  h.get('assistant-open').click(); h.enter('confirm', true);
  original.querySelector('[type=submit]').click();
  original.dispatchEvent(new h.dom.window.Event('submit', {cancelable: true}));
  await tick(); await tick();
  assert.equal(h.posts().length, 1);
  assert.equal(h.posts()[0].url, '/api/v1/recovery/operations/channel-review');
  assert.equal(JSON.parse(h.posts()[0].init.body).answers.evidence_reference, 'reviewed-ticket-123');
  assert.match(h.get('assistant-status').textContent, /review is recorded/);
  assert.equal(h.calls.some(row => /\/copilot|\/models|\/goals/.test(row.url)), false);
  assert.equal(h.posts().some(row => row.url.endsWith('/complete')), false);
  h.dom.window.close();
});

test('uncertain helper result cannot claim success or replay the submission', async () => {
  const h = await setup('uncertain'); h.choose(); h.fill(); h.enter('confirm', true);
  h.form().querySelector('[type=submit]').click(); await tick(); await tick();
  assert.match(h.get('assistant-status').textContent, /not yet confirmed/);
  assert.equal(h.posts().length, 1);
  h.enter('confirm', true);
  await h.dom.window.LightworkChannelReview.submit('1'.repeat(32));
  assert.equal(h.posts().length, 1);
  h.dom.window.close();
});

test('helper erases private mounted content after a denied refresh', async () => {
  const h = await setup(); h.choose(); h.fill(); h.deny();
  h.get('refresh').click(); await tick(); await tick();
  assert.equal(h.get('assistant').hidden, true);
  assert.equal(h.get('assistant-review').children.length, 0);
  assert.equal(h.get('assistant-item').options.length, 0);
  assert.doesNotMatch(h.get('workspace-recovery')?.textContent || h.dom.window.document.body.textContent, /reviewed-ticket-123/);
  h.dom.window.close();
});
