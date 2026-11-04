// "What changed during this task": a read-only before/now view of the files
// this task changed inside its own work folder. The server does every safety
// check; this script only asks, validates the shape it gets back, and shows it.
(() => {
  'use strict';
  const root = document.getElementById('task-changes');
  if (!root) return;
  const goal = root.dataset.goal || '';
  if (!/^\d+$/.test(goal)) return;
  const $ = id => document.getElementById('tc-' + id);
  const CHANGE = {
    edited: 'Changed',
    created: 'New file made by this task',
    deleted: 'Removed since the task began',
    binary: 'Changed. This file isn’t text, so its content isn’t shown.',
    too_large: 'Changed, but too large to show here.',
    not_saved: 'Changed, but the earlier version wasn’t saved, so it can’t be compared.',
    unreadable: 'This file can’t be read right now.'
  };
  const LINE = { add: 'Added: ', remove: 'Removed: ', same: '', gap: '' };
  let busy = false;

  function make(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function say(text) { window.mvStatus($('status'), text); }
  function failText(failure) {
    return typeof window.mvErrorText === 'function'
      ? window.mvErrorText(failure, 'show what changed')
      : 'Could not show what changed. Try again.';
  }
  function valid(data) {
    if (!data || typeof data !== 'object' || !Array.isArray(data.files) || data.files.length > 100) return false;
    return data.files.every(row => row && typeof row.name === 'string' && row.name.length <= 1024 &&
      Object.prototype.hasOwnProperty.call(CHANGE, row.change) && Array.isArray(row.lines) && row.lines.length <= 400 &&
      row.lines.every(line => line && Object.prototype.hasOwnProperty.call(LINE, line.kind) && typeof line.text === 'string'));
  }
  function lineNode(line) {
    const node = make('div', 'tc-line tc-line--' + line.kind);
    if (line.kind === 'gap') {
      const dots = make('span', null, '…');
      dots.setAttribute('aria-hidden', 'true');
      node.append(make('span', 'sr-only', 'Unchanged lines skipped'), dots);
      return node;
    }
    if (LINE[line.kind]) node.append(make('span', 'sr-only', LINE[line.kind]));
    const mark = make('span', null, line.kind === 'add' ? '+ ' : line.kind === 'remove' ? '− ' : '  ');
    mark.setAttribute('aria-hidden', 'true');
    node.append(mark, document.createTextNode(line.text));
    return node;
  }
  function card(row) {
    const article = make('article');
    article.append(make('h3', null, row.name), make('p', 'muted', CHANGE[row.change]));
    if (row.lines.length) {
      const diff = make('div', 'tc-diff');
      diff.setAttribute('role', 'group');
      diff.setAttribute('aria-label', 'Changes in ' + row.name);
      row.lines.forEach(line => diff.append(lineNode(line)));
      article.append(diff);
    } else if (row.change === 'edited' || row.change === 'created' || row.change === 'deleted') {
      article.append(make('p', 'muted', 'The file is empty on one side, so there are no lines to show.'));
    }
    if (row.shortened) article.append(make('p', 'muted', 'Only the first part of this file’s changes is shown.'));
    return article;
  }
  function render(data) {
    const files = $('files');
    files.replaceChildren();
    if (data.available === false) {
      say(typeof data.message === 'string' && data.message ? data.message : 'Changes can’t be shown for this task.');
      return;
    }
    data.files.forEach(row => files.append(card(row)));
    const notes = [];
    if (!data.files.length) {
      notes.push('No file changes were recorded for this task. Changes are recorded only while “Keep a copy before files change” is on. If file protection saved originals, use “Review changes to restore” above.');
    } else {
      notes.push(data.files.length === 1 ? 'One file changed.' : data.files.length + ' files changed.');
    }
    if (data.more > 0) notes.push(data.more + ' more changed files aren’t listed.');
    if (data.left_out > 0) notes.push(data.left_out + ' recorded changes point outside this task’s work folder or through a shortcut link, so they aren’t shown.');
    if (data.incomplete) notes.push('Some later changes weren’t recorded because the history was full.');
    say(notes.join(' '));
  }
  async function load() {
    if (busy) return;
    busy = true;
    $('show').disabled = true;
    root.setAttribute('aria-busy', 'true');
    $('files').replaceChildren();
    say('Loading what changed…');
    try {
      const response = await fetch('/api/v1/task-files/' + goal + '/changes', {
        credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' }
      });
      if (!response.ok) { say(failText(response)); return; }
      const raw = await response.text();
      let data = null;
      try { data = raw.length <= 4 * 1024 * 1024 ? JSON.parse(raw) : null; } catch (_) { data = null; }
      if (!valid(data)) { say('The list of changes couldn’t be checked. Refresh the page and try again.'); return; }
      render(data);
    } catch (error) {
      say(failText(error));
    } finally {
      busy = false;
      $('show').disabled = false;
      root.setAttribute('aria-busy', 'false');
      $('status').focus();
    }
  }
  $('show').addEventListener('click', load);
})();
