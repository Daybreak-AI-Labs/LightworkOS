(function () {
  'use strict';
  const API = '/api/v1/specialist-drafts';
  const host = document.getElementById('trial-list');
  const status = document.getElementById('trial-status');
  if (!host || !status) return;

  function node(tag, text, parent, className) {
    const value = document.createElement(tag);
    if (text !== undefined) value.textContent = text;
    if (className) value.className = className;
    if (parent) parent.append(value);
    return value;
  }
  function label(name) { return String(name || '').replace(/_/g, ' ').replace(/-/g, ' '); }
  function when(seconds) {
    if (typeof seconds !== 'number' || !isFinite(seconds)) return 'an earlier time';
    return new Date(seconds * 1000).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'});
  }
  function lines(value, depth) {
    if (depth > 6) return ['(more detail is in the activity record)'];
    if (value === null || value === undefined || value === '') return ['None entered'];
    if (typeof value === 'boolean') return [value ? 'Yes' : 'No'];
    if (typeof value === 'number' || typeof value === 'string') return [String(value)];
    if (Array.isArray(value)) return value.length ? value.flatMap(item => lines(item, depth + 1).map(text => '• ' + text)) : ['None entered'];
    return Object.entries(value).flatMap(([key, item]) => {
      const text = lines(item, depth + 1);
      return [key + ': ' + text[0]].concat(text.slice(1).map(line => '   ' + line));
    });
  }
  function call(path, body) {
    // serverDetail: the server's own plain sentence is shown when it sends one; this is the fallback.
    const options = {cache: 'no-store', serverDetail: 'The request could not be completed. Nothing was changed.'};
    if (body !== undefined) Object.assign(options, {method: 'POST', body});
    return window.mvFetchJSON(API + path, options);
  }

  function table(trial) {
    const versions = trial.versions;
    if (!versions) {
      node('p', 'Its history is too large to summarise here. Nothing was changed.', host, 'muted');
      return;
    }
    const grid = node('table', undefined, host, 'trial-table');
    const head = node('tr', undefined, node('thead', undefined, grid));
    ['Version', 'Goals started', 'Finished', 'Failed', 'Still running or stopped', 'Thumbs up', 'Thumbs down']
      .forEach(text => node('th', text, head, undefined).setAttribute('scope', 'col'));
    const body = node('tbody', undefined, grid);
    [['Trial (changed instructions)', versions.candidate], ['Current version', versions.current]].forEach(([text, tally]) => {
      const row = node('tr', undefined, body);
      node('th', text, row).setAttribute('scope', 'row');
      [tally.goals, tally.done + tally.failed, tally.failed, tally.other, tally.thumbs_up, tally.thumbs_down]
        .forEach(count => node('td', String(count), row));
    });
    if (versions.candidate.feedback_complete === false) {
      node('p', 'Thumbs counts may be too low: this workspace has more feedback than this summary can count. The goal counts are complete.', host, 'muted');
    }
  }

  function reviewBox(name, action, review) {
    const box = node('div', undefined, host, 'trial-review');
    node('h4', action === 'promote' ? 'Review: promote this trial for everyone' : 'Review: roll back this trial', box);
    const list = node('dl', undefined, box);
    review.changes.forEach(row => {
      node('dt', row.label, list);
      const detail = node('dd', undefined, list);
      lines(row.after, 0).forEach(text => node('div', text, detail));
    });
    const actions = node('div', undefined, box, 'trial-actions');
    const confirm = node('button', action === 'promote' ? 'Confirm and promote' : 'Confirm and roll back', actions, 'btn');
    confirm.type = 'button';
    confirm.setAttribute('aria-label', (action === 'promote' ? 'Confirm promotion of ' : 'Confirm roll back of ') + label(name));
    const cancel = node('button', 'Cancel', actions, 'btn btn--ghost');
    cancel.type = 'button';
    const note = node('p', undefined, box, 'muted');
    note.setAttribute('role', 'status');
    cancel.addEventListener('click', () => { box.remove(); });
    confirm.addEventListener('click', async () => {
      confirm.disabled = true;
      try {
        const done = await call('/apply', {token: review.token, confirmed: true});
        note.textContent = done.message || (done.confirmed ? 'Done.' : 'The decision is unconfirmed. Check the activity record before trying again.');
        if (done.confirmed) setTimeout(load, 400);
      } catch (error) {
        note.textContent = error.message;
        confirm.disabled = false;
      }
    });
  }

  function render(value) {
    host.replaceChildren();
    const trials = value.trials || [];
    if (!trials.length) {
      status.textContent = 'No trial versions are live. A changed specialist is tried first only when Lightwork is set to try changes on a share of new goals.';
      return;
    }
    status.textContent = trials.length === 1 ? '1 trial version is live.' : trials.length + ' trial versions are live.';
    trials.forEach(trial => {
      const card = node('article', undefined, host, 'trial-card');
      node('h3', label(trial.name), card);
      node('p', 'Started ' + when(trial.started_at) + '. ' + trial.percent + '% of new goals use the changed version; the rest keep the current version. '
        + (trial.title ? 'Change: ' + trial.title + '. ' : '')
        + (trial.auto_rollback
          ? 'It is rolled back automatically after ' + trial.min_finished + ' finished goals if it fails more than 20 points more often than the current version.'
          : 'It is not rolled back automatically.'), card);
      table(trial);
      const reasonId = 'trial-reason-' + trial.candidate_id.slice(0, 12);
      const reasonLabel = node('label', 'Reason for promoting, only if its saved checks have not all passed (at least 8 characters)', card);
      reasonLabel.setAttribute('for', reasonId);
      const reason = node('input', undefined, card, 'input');
      reason.id = reasonId;
      reason.type = 'text';
      reason.maxLength = 300;
      const actions = node('div', undefined, card, 'trial-actions');
      const promote = node('button', 'Promote for everyone', actions, 'btn');
      promote.type = 'button';
      promote.setAttribute('aria-label', 'Promote the trial of ' + label(trial.name) + ' for everyone');
      const rollback = node('button', 'Roll back trial', actions, 'btn btn--ghost');
      rollback.type = 'button';
      rollback.setAttribute('aria-label', 'Roll back the trial of ' + label(trial.name));
      [[promote, 'promote'], [rollback, 'rollback']].forEach(([button, action]) => {
        button.addEventListener('click', async () => {
          const errorNote = node('p', undefined, card, 'muted');
          errorNote.setAttribute('role', 'status');
          try {
            const history = await call('/history');
            const review = await call('/review', {name: trial.name, action, context: history.context,
              reason: action === 'promote' ? reason.value.trim() : ''});
            card.querySelectorAll('.trial-review').forEach(old => old.remove());
            reviewBox(trial.name, action, review);
          } catch (error) {
            errorNote.textContent = error.message;
          }
        });
      });
    });
  }

  function load() {
    call('/trials').then(render).catch(error => {
      host.replaceChildren();
      status.textContent = error.message || 'Trial versions could not be loaded. Try again shortly.';
    });
  }
  load();
})();
