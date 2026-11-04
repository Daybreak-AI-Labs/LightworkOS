// Prepare and review exact evidence before disclosing it to GitHub.
(() => {
  'use strict';
  const root = document.getElementById('goal-export'), button = document.getElementById('goal-gist');
  if (!root || !button) return;
  const goal = root.dataset.goal || '';
  if (!/^\d+$/.test(goal)) return;
  const base = '/api/v1/goals/' + goal + '/share/gist';
  const msg = document.getElementById('goal-export-msg');
  const review = document.createElement('section'); review.hidden = true;
  const description = document.createElement('p');
  const payload = document.createElement('pre'); payload.tabIndex = 0; payload.style.cssText = 'max-height:24rem;overflow:auto;white-space:pre-wrap';
  const send = document.createElement('button'); send.type = 'button'; send.className = 'btn btn--primary'; send.textContent = 'Upload this reviewed copy';
  const reconcile = document.createElement('button'); reconcile.type = 'button'; reconcile.className = 'btn btn--ghost'; reconcile.textContent = 'Check this attempt on GitHub'; reconcile.hidden = true;
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn--ghost'; cancel.textContent = 'Close review';
  review.append(description, payload, send, reconcile, cancel); root.append(review);
  let prepared = null, busy = false, unresolved = false, attemptsKnown = false;
  const receipts = document.createElement('ul'); receipts.setAttribute('aria-label', 'Previous GitHub sharing attempts'); root.append(receipts);
  async function loadAttempts() {
    try {
      const response = await fetch(base + '/attempts', {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) throw new Error('unavailable');
      const body = await response.json();
      if (!Array.isArray(body.attempts)) throw new Error('unreadable');
      receipts.replaceChildren(); unresolved = false; attemptsKnown = true;
      body.attempts.forEach(attempt => {
        const row = document.createElement('li'); row.textContent = 'GitHub account ' + attempt.account + ': ' + attempt.state + '. ';
        if (['unknown', 'dispatching'].includes(attempt.state)) {
          unresolved = true;
          const check = document.createElement('button'); check.type = 'button'; check.className = 'btn btn--ghost'; check.textContent = 'Check existing attempt';
          check.addEventListener('click', async () => { check.disabled = true; try { outcome(await request(base + '/' + attempt.attempt + '/reconcile')); await loadAttempts(); } catch (error) { msg.textContent = error.message; } finally { check.disabled = false; } }); row.append(check);
        }
        if (/^https:\/\/gist\.github\.com\//.test(attempt.url || '')) { const link = document.createElement('a'); link.href = attempt.url; link.textContent = 'Review or remove copy on GitHub'; link.rel = 'noreferrer noopener'; link.target = '_blank'; row.append(link); }
        receipts.append(row);
      });
      return true;
    } catch (_) { attemptsKnown = false; msg.textContent = 'Previous sharing attempts could not be checked. Retry preparing the review before any new upload.'; return false; }
  }
  loadAttempts();
  async function request(path, body) {
    return window.mvFetchJSON(path, {method: 'POST', cache: 'no-store', body: body || {}, plainDetail: true}, 'share the result');
  }
  function outcome(data) {
    msg.replaceChildren();
    if (data.shared && /^https:\/\/gist\.github\.com\//.test(data.url || '')) {
      const link = document.createElement('a'); link.href = data.url; link.rel = 'noreferrer noopener'; link.target = '_blank'; link.textContent = 'Open the copy on GitHub';
      msg.append(link, '. Anyone with its link can read it. Remove the gist on GitHub to revoke this copy.');
      send.disabled = true; reconcile.hidden = true;
    } else {
      msg.textContent = data.message || 'The upload outcome is unknown. Check this attempt before sending again.';
      send.disabled = true; reconcile.hidden = false;
    }
  }
  button.addEventListener('click', async () => {
    if (busy) return;
    if (!attemptsKnown && !(await loadAttempts())) return;
    if ((unresolved || (prepared && !reconcile.hidden)) && !(await window.mvConfirm('The previous copy may already exist on GitHub. Creating another reviewed copy may result in duplicate disclosure. Continue?', {okText: 'Prepare another copy'}))) return;
    busy = true; button.disabled = true; msg.textContent = 'Preparing a review. Nothing is being uploaded.';
    try {
      prepared = await request(base + '/preview');
      description.textContent = 'Destination account: ' + prepared.account + '. ' + prepared.scope;
      payload.textContent = JSON.stringify(prepared.payload, null, 2);
      review.hidden = false; send.disabled = false; reconcile.hidden = true;
      msg.textContent = 'Review the complete outbound content below. Known secrets are scrubbed; business information may remain. Review expires in ten minutes.';
      payload.focus();
    } catch (error) { msg.textContent = error.message; }
    finally { busy = false; button.disabled = false; }
  });
  send.addEventListener('click', async () => {
    if (busy || !prepared) return;
    busy = true; send.disabled = true; msg.textContent = 'Uploading the reviewed copy…';
    try { outcome(await request(base, {confirm: true, preview_id: prepared.preview_id, sha256: prepared.sha256})); await loadAttempts(); }
    catch (error) { msg.textContent = error.message + ' The response may have been lost; check this attempt.'; reconcile.hidden = false; }
    finally { busy = false; }
  });
  reconcile.addEventListener('click', async () => {
    if (busy || !prepared) return;
    busy = true; reconcile.disabled = true;
    try { outcome(await request(base + '/' + prepared.preview_id + '/reconcile')); }
    catch (error) { msg.textContent = error.message; }
    finally { busy = false; reconcile.disabled = false; }
  });
  cancel.addEventListener('click', () => { if (!busy) { review.hidden = true; button.focus(); } });
})();
