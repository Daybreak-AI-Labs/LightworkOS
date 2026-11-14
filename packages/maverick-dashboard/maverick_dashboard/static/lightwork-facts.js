(function () {
  'use strict';
  var root = document.getElementById('facts-workspace');
  if (!root) return;
  var snapshot = "";
  var context = root.dataset.context, canEdit = root.dataset.canEdit === 'true';
  var form = document.getElementById('fact-editor'), name = document.getElementById('fact-name');
  var detail = document.getElementById('fact-detail'), status = document.getElementById('fact-status');
  var table = document.getElementById('fact-list'), busy = false, offset = 0, revision = 0, currentRevision = 0;
  var prev = document.getElementById('fact-prev'), next = document.getElementById('fact-next');
  var inspector = document.getElementById('fact-inspector'), body = document.getElementById('fact-inspector-body');
  var conflict = document.getElementById('fact-conflict');
  function node(tag, text) { var element = document.createElement(tag); element.textContent = text; return element; }
  function date(value) { return value ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(value) : new Date(value * 1000).toLocaleString()) : 'Not recorded'; }
  function label(value) { return String(value).replace(/_/g, ' ').replace(/^./, function (c) { return c.toUpperCase(); }); }
  function selectFacts(keys) {
    document.dispatchEvent(new CustomEvent('lightwork:copilot-selection', {detail:{selection:keys.length ? {kind:'facts',keys:keys} : {}}}));
  }
  function clearPrivate() {
    table.querySelector('tbody').replaceChildren(); body.replaceChildren(); inspector.hidden = true;
    if (form) form.reset(); if (conflict) conflict.hidden = true;
    selectFacts([]);
  }
  async function request(url, options) {
    var payload;
    try {
      payload = await window.mvFetchJSON(url, Object.assign({cache: 'no-store',
        onAccess: function (error) { clearPrivate(); error.accessChanged = true; }}, options || {}), options && options.method ? 'save the fact' : 'load the facts');
    } catch (error) {
      if (error.status && !error.accessChanged) error.message = 'The request could not be completed. Your draft is preserved. Try again.';
      throw error;
    }
    if (payload === null) return null;  // No Content
    if (payload.context !== context) { clearPrivate(); var changed = new Error('Your account or workspace changed. Reload to continue.'); changed.accessChanged = true; throw changed; }
    return payload;
  }
  function setBusy(value) {
    busy = value;
    root.querySelectorAll('button').forEach(function (button) { button.disabled = value; });
    if (!value) { prev.disabled = offset === 0; next.disabled = next.dataset.more !== 'true'; }
  }
  next.dataset.more = 'false'; next.disabled = true;
  document.addEventListener('lightwork:workspace-changed', clearPrivate);
  function reset() {
    if (!form) return;
    form.reset(); name.readOnly = false; revision = 0; conflict.hidden = true;
    document.getElementById('fact-cancel').hidden = true;
    document.getElementById('fact-editor-title').textContent = 'Add a fact';
    selectFacts([]);
  }
  function render(items) {
    selectFacts([]);
    var tbody = table.querySelector('tbody'); tbody.replaceChildren();
    items.forEach(function (item) {
      var row = document.createElement('tr'); row.dataset.key = item.key; row.dataset.revision = item.revision;
      var selectCell = document.createElement('td'), checkbox = document.createElement('input');
      checkbox.type = 'checkbox'; checkbox.setAttribute('data-select-fact', ''); checkbox.setAttribute('aria-label', 'Select ' + label(item.key)); selectCell.append(checkbox);
      var keyCell = node('td', label(item.key)); keyCell.className = 'fact-key';
      var valueCell = node('td', item.value); valueCell.className = 'fact-value'; valueCell.style.whiteSpace = 'pre-wrap'; valueCell.style.overflowWrap = 'anywhere';
      var actions = document.createElement('td'); actions.className = 'mv-row__actions';
      [['view','Details and history']].concat(canEdit ? [['edit','Edit'],['remove','Remove']] : []).forEach(function (action) {
        var button = node('button', action[1]); button.type = 'button'; button.className = 'btn btn--ghost'; button.setAttribute('data-' + action[0] + '-fact', ''); actions.append(button);
      });
      row.append(selectCell, keyCell, valueCell, node('td', date(item.updated_at)), actions); tbody.append(row);
    });
    table.hidden = items.length === 0; document.getElementById('facts-empty').hidden = items.length > 0;
  }
  async function load() {
    var params = new URLSearchParams({query:document.getElementById('fact-query').value, source:document.getElementById('fact-source').value, tag:document.getElementById('fact-tag').value, offset:offset, limit:50, snapshot:snapshot});
    var before = document.getElementById('fact-before').value;
    if (before) params.set('updated_before', new Date(before + 'T00:00:00').getTime() / 1000);
    var payload = await request('/api/v1/facts/records?' + params);
    snapshot = payload.snapshot;
    render(payload.items); next.dataset.more = payload.has_more ? 'true' : 'false';
    status.textContent = payload.items.length + ' facts on this page. Search covers workspace fact names and source metadata.';
  }
  async function browse(delta) {
    if (busy) return; var prior = offset;
    if (delta === -offset) snapshot = ""; offset = Math.max(0, offset + delta); setBusy(true);
    try { await load(); } catch (error) { offset = prior; status.textContent = error.status === 409 ? 'Facts changed. Select Find facts to start a fresh page sequence; your edit draft is preserved.' : error.message; } finally { setBusy(false); }
  }
  document.getElementById('fact-search').addEventListener('submit', function (event) { event.preventDefault(); browse(-offset); });
  prev.addEventListener('click', function () { browse(-50); }); next.addEventListener('click', function () { browse(50); });
  async function current(key) { return request('/api/v1/facts/record?' + new URLSearchParams({key:key})); }
  async function showConflict(key) {
    try {
      var payload = await current(key); currentRevision = payload.item.revision;
      document.getElementById('fact-current').textContent = 'Current saved detail:\n' + payload.item.value;
      conflict.hidden = false; status.textContent = 'This fact changed. Compare the current detail with your preserved draft.';
    } catch (error) { status.textContent = error.status === 404 ? 'This fact was removed. Your draft is preserved; cancel editing before creating a new fact.' : error.message; }
  }
  function showRecord(payload) {
    var item = payload.item, section = document.createElement('section');
    selectFacts([item.key]);
    section.append(node('h3', label(item.key)), node('p', item.value));
    section.append(node('p', 'Tags: ' + ((item.tags || []).join(', ') || 'None')));
    if (canEdit && payload.tags_enabled) {
      var tagsForm = document.createElement('form'), tagLabel = node('label', 'Tags separated by commas');
      var tagsInput = document.createElement('input'); tagsInput.className = 'input'; tagsInput.value = (item.tags || []).join(', '); tagLabel.append(tagsInput);
      var tagsSave = node('button', 'Save tags'); tagsSave.type = 'submit'; tagsSave.className = 'btn';
      var tagStatus = node('p', 'Tags organize shared facts; they do not change access or sensitivity.'); tagStatus.setAttribute('role','status');
      tagsForm.append(tagLabel,tagsSave,tagStatus); section.append(tagsForm);
      tagsForm.addEventListener('submit', async function(event) {
        event.preventDefault(); if (busy) return;
        setBusy(true);
        try {
          var saved = await request('/api/v1/facts/tags', {method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:item.key,tags:tagsInput.value.split(',').map(function(v){return v.trim();}).filter(Boolean),expected_revision:item.revision,context:context})});
          item.revision = saved.revision; snapshot = ''; offset = 0; await load(); tagStatus.textContent = 'Tags saved.';
        } catch(error) { tagStatus.textContent = error.status === 409 ? 'The fact or policy changed. Your tag draft is preserved; reopen current details before saving again.' : error.message; }
        finally { setBusy(false); }
      });
    } else if (!payload.tags_enabled) section.append(node('p', 'An administrator can enable tag editing in Settings, Memory & learning.'));

    section.append(node('p', 'Updated: ' + date(item.updated_at) + '. Source or author: ' + (item.source || 'Not recorded') + '. Trust: ' + ({0:'External',1:'Agent working note',2:'Learned',3:'First party'}[item.trust_tier] || 'Unknown') + '. Sensitivity: ' + item.sensitivity + '.'));
    if (item.source_episode_id) section.append(node('p', 'Source run reference: ' + item.source_episode_id));
    section.append(node('p', payload.history_notice), node('p', 'Expiry is governed by workspace retention settings; no individual expiry is recorded for this fact.'));
    if (!payload.history.length) section.append(node('p', 'No recorded version history is available.'));
    payload.history.forEach(function (version) {
      var entry = document.createElement('details'); entry.append(node('summary', 'Version from ' + date(version.valid_from) + (version.valid_to ? ' to ' + date(version.valid_to) : ' (current)')));
      var value = node('pre', version.value || ''); value.style.whiteSpace = 'pre-wrap'; value.style.overflowWrap = 'anywhere'; entry.append(value);
      entry.append(node('p', 'Source or author: ' + (version.source || 'Not recorded') + '. Sensitivity: ' + version.sensitivity + '.'));
      if (canEdit) {
        var restore = node('button', 'Use this version as an edit draft'); restore.type = 'button'; restore.className = 'btn btn--ghost';
        restore.addEventListener('click', function () {
          if (busy) return;
          if (name.value && (name.value !== item.key || detail.value !== item.value)) {
            status.textContent = 'Save or cancel your existing draft before restoring a version.'; return;
          }
          name.value = item.key; detail.value = version.value; revision = item.revision; name.readOnly = true;
          document.getElementById('fact-cancel').hidden = false; document.getElementById('fact-editor-title').textContent = 'Review restored version'; conflict.hidden = true;
          status.textContent = 'Review this historical detail against the current value below, then save as a new version. Current permissions and concurrent changes are checked again.'; detail.focus();
        });
        entry.append(restore);
      }
      section.append(entry);
    });
    body.append(section); inspector.hidden = false;
  }
  document.getElementById('fact-review-selection').addEventListener('click', async function () {
    if (busy) return;
    var selected = Array.from(table.querySelectorAll('[data-select-fact]:checked')).map(function (input) { return input.closest('tr').dataset.key; });
    if (!selected.length) { status.textContent = 'Select the facts you want to review on this page.'; return; }
    setBusy(true); body.replaceChildren();
    try { for (var key of selected) showRecord(await current(key)); selectFacts(selected); document.getElementById('fact-inspector-title').focus(); }
    catch (error) { body.replaceChildren(); inspector.hidden = true; status.textContent = error.message; }
    finally { setBusy(false); }
  });
  table.addEventListener('click', async function (event) {
    var button = event.target.closest('button'), row = button && button.closest('tr'); if (!row || busy) return;
    var key = row.dataset.key;
    selectFacts([key]);
    if (button.hasAttribute('data-edit-fact')) {
      name.value = key; detail.value = row.querySelector('.fact-value').textContent; revision = Number(row.dataset.revision); name.readOnly = true;
      document.getElementById('fact-cancel').hidden = false; document.getElementById('fact-editor-title').textContent = 'Edit fact'; conflict.hidden = true; detail.focus(); return;
    }
    if (button.hasAttribute('data-remove-fact')) {
      // One action with a way back: the fact leaves new recall when
      // the Undo time is up. This is not erasure; history follows retention.
      var url = '/api/v1/facts/' + encodeURIComponent(key) + '?' + new URLSearchParams({expected_revision:row.dataset.revision,context:context});
      row.hidden = true;
      window.mvUndo('“{key}” removed from new recall. Recorded versions follow workspace retention; this is not erasure.', { values: {key: key},
        action: 'remove the fact',
        run: async function (keepalive) { await request(url, {method:'DELETE', keepalive:keepalive}); return {ok:true}; },
        undo: function () { row.hidden = false; button.focus(); },
        done: async function () { snapshot = ''; offset = 0; await load(); status.textContent = 'Fact removed from new recall. Retained history follows workspace policy.'; }
      });
      return;
    }
    setBusy(true); body.replaceChildren();
    try { showRecord(await current(key)); document.getElementById('fact-inspector-title').focus(); }
    catch (error) { status.textContent = error.message; } finally { setBusy(false); }
  });
  if (form) {
    document.getElementById('fact-cancel').addEventListener('click', function () { if (!busy) reset(); });
    document.getElementById('fact-rebase').addEventListener('click', function () { revision = currentRevision; conflict.hidden = true; status.textContent = 'Your draft is preserved. Save when you are ready; another change will be checked again.'; detail.focus(); });
    form.addEventListener('submit', async function (event) {
      event.preventDefault(); if (busy || !form.reportValidity()) return;
      var payload = {key:name.value.trim(), value:detail.value, expected_revision:revision, context:context};
      setBusy(true);
      try {
        await request('/api/v1/facts', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
        var confirmed;
        try { confirmed=await current(payload.key); }
        catch (verificationError) {
          if (verificationError.accessChanged) throw verificationError;
          status.textContent='The saved fact could not be confirmed. Your draft is preserved; review the current fact before retrying.'; return;
        }
        if (!confirmed.item || confirmed.item.key!==payload.key || confirmed.item.value!==payload.value ||
            !Number.isInteger(confirmed.item.revision) || confirmed.item.revision<=payload.expected_revision) {
          status.textContent='The saved fact could not be confirmed. Your draft is preserved; review the current fact before retrying.'; return;
        }
        var unchanged=name.value.trim()===payload.key && detail.value===payload.value;
        if (unchanged) reset();
        try { snapshot = ''; offset = 0; await load(); status.textContent = unchanged ? 'Fact saved.' : 'Fact saved. Newer edits are kept as an unsaved draft.'; }
        catch (refreshError) { status.textContent = refreshError.accessChanged ? refreshError.message : 'Fact saved, but this list could not refresh. Refresh the list to see it.'; }
      }
      catch (error) { if (error.status === 409) await showConflict(payload.key); else status.textContent = error.message; }
      finally { setBusy(false); }
    });
  }
  var linkedKey = new URLSearchParams(window.location.search).get('key');
  if (linkedKey && linkedKey.length <= 200) {
    setBusy(true);
    current(linkedKey).then(function(payload){showRecord(payload);document.getElementById('fact-inspector-title').focus();})
      .catch(function(error){status.textContent=error.message;}).finally(function(){setBusy(false);});
  }
})();
