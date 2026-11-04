(function () {
  'use strict';
  var wrap = document.querySelector('.goal-share'); if (!wrap || wrap.dataset.canOperate !== '1') return;
  var goal = wrap.dataset.goal, create = document.getElementById('share-create'), scope = document.getElementById('share-scope'), output = document.getElementById('share-url');
  var copy = document.getElementById('share-copy'), status = document.getElementById('share-msg'), list = document.getElementById('share-list');
  var review = document.createElement('section'); review.hidden = true; review.className = 'share-review'; review.setAttribute('aria-label', 'Review public link'); wrap.append(review);
  var preview = null, denied = false, generation = 0, requests = new Set();
  function syncCreate() {
    if (!create) return;
    var panel = document.getElementById('answer-panel');
    var ready = panel && panel.dataset.status === 'done' && panel.querySelector('#saved-answer-source');
    create.hidden = !ready;
    create.disabled = denied || !ready;
  }
  function accessError() {
    var error = new Error('Your access changed. Reload and sign in before managing this task.'); error.status = 403; return error;
  }
  function clearPrivate() {
    denied = true; generation++; requests.forEach(function (controller) { controller.abort(); });
    list.replaceChildren(); review.replaceChildren(); review.hidden = true; preview = null; output.value = ''; output.style.display = 'none'; copy.hidden = true;
    if (create) { create.hidden = true; create.disabled = true; } status.textContent = accessError().message;
  }
  async function request(path, options) {
    if (denied) throw accessError();
    var ticket = generation, controller = new AbortController();
    requests.add(controller);
    var opts = Object.assign({cache: 'no-store', signal: controller.signal, timeout: 15000, accessStatuses: [401, 403, 404],
      onAccess: clearPrivate}, options);
    opts.headers = Object.assign({'Content-Type': 'application/json'}, options && options.headers);
    try {
      var body = await window.mvFetchJSON('/api/v1/goals/' + goal + '/share' + path, opts, 'manage this link');
      if (denied || ticket !== generation) throw accessError();
      return body || {};
    } catch (error) {
      if (error.accessChanged || denied || ticket !== generation) throw accessError();
      throw error;
    } finally { requests.delete(controller); }
  }
  function text(tag, value) { var node = document.createElement(tag); node.textContent = value; return node; }
  async function refresh() {
    var body = await request(''); list.replaceChildren();
    body.links.forEach(function (link) {
      var row = text('li', link.label + ' — ' + (link.scope === 'conversation' ? 'full conversation' : 'saved answer') + ' — ' + link.state + (link.expires_at ? '; expires ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(link.expires_at) : new Date(link.expires_at * 1000).toLocaleString()) : '; legacy link without expiry') + ' ');
      if (!link.revoked) {
        var revoke = text('button', 'Revoke'); revoke.type = 'button'; revoke.className = 'btn btn--ghost share-revoke'; revoke.dataset.id = link.id;
        row.append(revoke);
      }
      list.append(row);
    });
  }
  if (create) create.addEventListener('click', async function () {
    create.disabled = true; status.textContent = 'Checking the selected content and release requirements.';
    var selectedScope = scope && scope.value === 'conversation' ? 'conversation' : 'result';
    if (scope) scope.disabled = true;
    try {
      preview = await request('/preview?scope=' + encodeURIComponent(selectedScope), {method: 'POST', body: '{}'}); review.replaceChildren();
      review.append(text('h3', 'Review before creating a public link'), text('p', preview.audience), text('p', preview.scope));
      review.append(text('h4', preview.source.title));
      if (selectedScope === 'conversation') {
        preview.source.transcript.forEach(function (turn) {
          if (turn.role === 'clarification') review.append(text('strong', 'Lightwork asked'), text('pre', turn.question), text('strong', 'You answered'), text('pre', turn.answer));
          else review.append(text('strong', turn.role === 'user' ? 'You' : 'Lightwork'), text('pre', turn.text));
        });
      } else {
        review.append(text('pre', preview.source.result));
        preview.source.artifacts.forEach(function (artifact) {
          var details = document.createElement('details'); details.append(text('summary', artifact.title + ' — version ' + artifact.version), text('pre', artifact.content || '')); review.append(details);
        });
      }
      var label = document.createElement('input'); label.id = 'share-label'; label.className = 'input'; label.maxLength = 120; label.value = selectedScope === 'conversation' ? 'Read-only conversation' : 'Read-only deliverable';
      var labelText = text('label', 'Link label'); labelText.htmlFor = label.id;
      var lifetime = document.createElement('select'); lifetime.id = 'share-lifetime'; lifetime.className = 'input';
      preview.allowed_lifetimes.forEach(function (seconds) { var option = text('option', seconds === 3600 ? '1 hour' : seconds === 86400 ? '1 day' : '7 days'); option.value = seconds; lifetime.append(option); });
      lifetime.value = '86400'; var lifetimeText = text('label', 'Link lifetime (maximum 7 days)'); lifetimeText.htmlFor = lifetime.id;
      var confirm = text('button', 'Create this public link'); confirm.id = 'share-confirm'; confirm.className = 'btn btn--primary'; confirm.type = 'button';
      var cancel = text('button', 'Cancel'); cancel.type = 'button'; cancel.className = 'btn btn--ghost';
      cancel.addEventListener('click', function () { preview = null; review.hidden = true; review.replaceChildren(); if (scope) scope.disabled = false; create.focus(); });
      confirm.addEventListener('click', async function () {
        if (!preview || !label.value.trim()) { status.textContent = 'Enter a label for this link.'; return; }
        confirm.disabled = true; cancel.disabled = true; label.disabled = true; lifetime.disabled = true;
        try {
          var body = await request('', {method: 'POST', body: JSON.stringify({confirm: true, scope: selectedScope, source_sha256: preview.source.sha256, lifetime_seconds: Number(lifetime.value), label: label.value.trim()})});
          output.value = body.url; output.dataset.shareId = body.id; output.dataset.localOnly = body.local_only ? '1' : '0';
          output.style.display = ''; copy.hidden = false; output.focus(); output.select();
          status.textContent = (body.local_only ? 'This address is limited to this computer or its private network. Recipients need an address they can reach. ' : '') +
            'Copy this link now; it is shown once. Expires ' + (window.mvTimeAbsolute ? window.mvTimeAbsolute(body.expires_at) : new Date(body.expires_at * 1000).toLocaleString()) + '.';
          preview = null; review.hidden = true; review.replaceChildren(); if (scope) scope.disabled = false; await refresh();
        } catch (error) {
          preview = null; review.hidden = true; review.replaceChildren(); if (scope) scope.disabled = false;
          window.mvRenderError(status, error, 'create this link');
          if (!error.status || error.status >= 500) status.append(document.createTextNode(' A lost response may still have created a link. Check the list and revoke any unwanted link before creating another.'));
          try { await refresh(); } catch (_) { /* Keep the original recovery message. */ }
        }
      });
      review.append(labelText, label, lifetimeText, lifetime, confirm, cancel); review.hidden = false; label.focus(); status.textContent = 'No link has been created. Review the content, audience and lifetime above.';
    } catch (error) { if (scope) scope.disabled = false; window.mvRenderError(status, error, 'review this public link'); }
    finally { syncCreate(); }
  });
  copy.addEventListener('click', async function () {
    if (!output.value) return;
    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error('clipboard unavailable');
      await navigator.clipboard.writeText(output.value);
      status.textContent = output.dataset.localOnly === '1'
        ? 'Link copied. This address is limited to this computer or its private network.'
        : 'Link copied. Anyone who can reach your workspace can read the reviewed content until it expires or you revoke it.';
    } catch (_) {
      output.focus(); output.select(); status.textContent = 'Copy was unavailable. The link is selected; press Ctrl+C or Command+C.';
    }
  });
  list.addEventListener('click', async function (event) {
    var button = event.target.closest('.share-revoke'); if (!button) return;
    if (!(await mvConfirm('Stop future access through this link? Downloaded and forwarded copies cannot be recalled.', {okText: 'Revoke link'}))) return;
    button.disabled = true;
    try {
      await request('/' + button.dataset.id + '/revoke', {method: 'POST', body: '{}'}); await refresh();
      if (output.dataset.shareId === button.dataset.id) {
        output.value = ''; output.style.display = 'none'; copy.hidden = true;
        delete output.dataset.shareId; delete output.dataset.localOnly;
      }
      status.textContent = 'Link revoked. Existing downloaded copies remain outside Lightwork.';
    }
    catch (error) { window.mvRenderError(status, error, 'revoke this link'); button.disabled = denied; }
  });
  function refreshVisible() {
    if (denied || document.hidden) return;
    refresh().catch(function () { if (!denied) status.textContent = 'Link status could not be loaded. Reload to check expiry and revocation before creating another.'; });
  }
  document.addEventListener('lightwork:task-access-lost', clearPrivate);
  document.addEventListener('lightwork:task-projection', function (event) {
    if (create && event.detail && event.detail.status && event.detail.status !== 'done') {
      create.hidden = true; create.disabled = true;
    }
  });
  document.addEventListener('lightwork:answer-panel-updated', syncCreate);
  document.addEventListener('visibilitychange', refreshVisible);
  window.addEventListener('focus', refreshVisible);
  window.addEventListener('pagehide', clearPrivate);
  syncCreate();
  refreshVisible();
}());
