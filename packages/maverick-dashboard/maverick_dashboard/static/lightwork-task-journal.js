// "Undo this task's recorded file changes": the file journal's list and undo.
// The server checks every recorded change is inside this task's own work
// folder before it will undo anything; this script lists, previews and asks.
(() => {
  'use strict';
  const root = document.getElementById('task-journal');
  if (!root) return;
  const goal = root.dataset.goal || '';
  if (!/^\d+$/.test(goal)) return;
  const $ = id => document.getElementById('tj-' + id);
  const base = '/api/v1/task-files/' + goal + '/journal';
  let context = null, busy = false, plan = null;

  function make(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function say(text) { window.mvStatus($('status'), text); }
  function failText(failure, what) {
    return typeof window.mvErrorText === 'function' ? window.mvErrorText(failure, what)
      : 'Could not ' + what + '. Try again.';
  }
  function count(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function lock(state) {
    busy = state;
    root.setAttribute('aria-busy', String(state));
    ['list', 'preview', 'undo'].forEach(id => { $(id).disabled = state; });
  }
  async function call(path, body) {
    const data = await window.mvFetchJSON(base + path, {
      method: body ? 'POST' : 'GET', cache: 'no-store',
      body: body ? Object.assign({ context: context }, body) : undefined
    });
    if (!data || typeof data !== 'object') throw new Error('unreadable');
    if (typeof data.context === 'string' && /^[a-f0-9]{64}$/.test(data.context)) context = data.context;
    return data;
  }
  function showList(data) {
    const list = $('entries');
    list.replaceChildren();
    if (data.available === false) { say(data.message || 'The file history can’t be shown for this task.'); return; }
    (data.entries || []).forEach(row => {
      const item = make('li', 'mv-row');
      const name = row.unsafe ? 'A change recorded outside this task’s work folder' : row.file;
      item.append(make('span', 'mv-row__title', name),
        make('span', 'muted', row.change === 'created' ? ' · New file made by the task'
          : row.saved ? ' · Changed; the earlier version was kept' : ' · Changed; the earlier version wasn’t kept'));
      list.append(item);
    });
    const notes = [data.count ? count(data.count, 'recorded file change.', 'recorded file changes.')
      : 'No file changes were recorded for this task.'];
    if (data.more > 0) notes.push(data.more + ' more aren’t listed.');
    if (data.incomplete) notes.push('Some later changes weren’t recorded because the history was full.');
    if (!data.recording) notes.push('Recording is off, so future task runs aren’t recorded.');
    notes.push('Commands the task ran aren’t recorded and can’t be undone here.');
    say(notes.join(' '));
  }
  async function run(action) {
    if (busy) return;
    lock(true);
    try { await action(); } catch (failure) { say(failText(failure, 'check this task’s file history')); $('status').focus(); }
    finally { lock(false); }
  }
  async function list() { showList(await call('')); }
  async function preview() {
    if (!context) await list();
    const data = await call('/undo', { preview: true, partial: $('partial').checked });
    plan = null; $('review').hidden = true;
    if (data.available === false || data.message) { say(data.message || 'Nothing can be undone for this task.'); return; }
    plan = data;
    $('plan').textContent = 'Undoing would put back ' + count(data.restored, 'file', 'files')
      + ' as they were before the task and remove ' + count(data.removed, 'new file', 'new files')
      + ' the task made.' + (data.skipped ? ' ' + count(data.skipped, 'change', 'changes') + ' can’t be undone.' : '');
    $('partial-wrap').hidden = data.complete;
    $('review').hidden = false;
    say('Review what would be undone. Nothing has changed yet.');
  }
  async function undo() {
    if (!plan) return;
    const ok = typeof window.mvConfirm === 'function' && await window.mvConfirm(
      'Undo this task’s recorded file changes? Files go back to how they were before the task, and new files it made are removed. This can’t be reversed from here.',
      { okText: 'Undo changes' });
    if (!ok) return;
    const data = await call('/undo', { preview: false, confirm: true, partial: $('partial').checked });
    plan = null; $('review').hidden = true;
    if (data.available === false || data.message) { say(data.message || 'Nothing was undone.'); return; }
    say('Done. Put back ' + count(data.restored, 'file', 'files') + ' and removed '
      + count(data.removed, 'new file', 'new files') + '.' + (data.skipped ? ' '
      + count(data.skipped, 'change', 'changes') + ' couldn’t be undone.' : '') + ' The history was kept as a record.');
    $('entries').replaceChildren();
  }
  $('list').addEventListener('click', () => run(list));
  $('preview').addEventListener('click', () => run(preview));
  $('undo').addEventListener('click', () => run(undo));
  $('partial').addEventListener('change', () => { if (plan) run(preview); });
})();
