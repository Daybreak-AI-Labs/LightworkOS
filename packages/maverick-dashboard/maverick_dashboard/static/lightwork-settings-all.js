/* Settings > All settings: save, reset, search and module switches.
   The page arrives with the list of groups; a group's settings are loaded
   when it is opened, and a search asks the server for the matching ones. */
(function () {
  'use strict';

  var API = '/api/v1/settings/catalog';
  var MODULES = '/api/v1/features/modules';
  var root = document.getElementById('settings-all-groups');
  if (!root) return;

  // Company sign-in setup uses the address in this browser, which is the
  // public address the identity provider must return to after sign-in.
  var signInGuide = document.getElementById('settings-signin-guide');
  if (signInGuide) {
    var signInGeneration = 0;
    var signInAccessGeneration = 0;
    var signInTry = signInGuide.querySelector('[data-signin-try]');
    var signInProvider = signInGuide.querySelector('[data-signin-provider-link]');
    var signInRefresh = signInGuide.querySelector('[data-signin-refresh]');
    var signInResults = signInGuide.querySelector('[data-signin-results]');
    var signInHistory = signInGuide.querySelector('[data-signin-history]');
    async function refreshSignInResults() {
      var generation = ++signInGeneration;
      signInHistory.replaceChildren();
      signInRefresh.disabled = true;
      signInResults.textContent = 'Reading saved sign-in results…';
      try {
        var response = await fetch('/api/v1/settings/sign-in-tests', {credentials: 'same-origin', cache: 'no-store'});
        var value = await response.json();
        if (generation !== signInGeneration) return;
        if (!response.ok || value.context !== root.dataset.requestContext || !Array.isArray(value.checks)) throw new Error('unavailable');
        signInResults.textContent = value.checks.length ? 'Saved provider sign-in checks. Current sign-in and administrator access were kept.' : 'No verified provider sign-in is saved for your current account and workspace.';
        if (new URLSearchParams(location.search).get('signin_test') === 'unconfirmed') {
          signInResults.textContent = 'The latest attempt was not confirmed. Nothing was enabled. Check the saved details before starting a separate attempt.';
        }
        value.checks.forEach(function (check) {
          var item = document.createElement('li');
          item.textContent = new Date(check.checked_at * 1000).toLocaleString() + ' · ' + check.provider + ' · ' + check.account + ' · ' + (check.current ? 'Matches current saved details' : 'Saved details have changed; check them again');
          signInHistory.appendChild(item);
        });
      } catch (_) {
        if (generation === signInGeneration) signInResults.textContent = 'The saved sign-in results could not be checked. Nothing was enabled.';
      } finally {
        if (generation === signInGeneration) signInRefresh.disabled = false;
      }
    }
    function clearSignInResults() {
      signInGeneration += 1;
      signInAccessGeneration += 1;
      signInTry.disabled = true;
      signInProvider.hidden = true;
      signInProvider.removeAttribute('href');
      signInHistory.replaceChildren();
      signInResults.textContent = 'Your account or workspace changed. Reload Settings before reading private sign-in results.';
      signInRefresh.disabled = true;
    }
    signInTry.addEventListener('click', async function () {
      var access = signInAccessGeneration;
      var providerTab = window.open('about:blank', '_blank');
      if (providerTab) providerTab.opener = null;
      signInTry.disabled = true;
      signInProvider.hidden = true;
      signInProvider.removeAttribute('href');
      signInResults.textContent = 'Preparing a sign-in against your saved provider details…';
      try {
        var response = await fetch('/api/v1/settings/sign-in-tests/start', {method: 'POST', credentials: 'same-origin', headers: {'Accept': 'application/json'}});
        var value = await response.json();
        if (access !== signInAccessGeneration) throw new Error('changed');
        if (!response.ok || value.context !== root.dataset.requestContext || typeof value.authorization_url !== 'string') throw new Error('unavailable');
        var provider = new URL(value.authorization_url);
        if (provider.protocol !== 'https:') throw new Error('unavailable');
        if (providerTab && !providerTab.closed) {
          providerTab.location.href = provider.href;
          signInResults.textContent = 'Continue in your provider tab. Your current Lightwork access is kept.';
        } else {
          signInProvider.href = provider.href;
          signInProvider.hidden = false;
          signInResults.textContent = 'Your browser blocked the new tab. Choose Continue to your sign-in provider to complete this check.';
        }
      } catch (_) {
        if (providerTab && !providerTab.closed) providerTab.close();
        if (access === signInAccessGeneration) signInResults.textContent = 'The sign-in check could not start. Save and check the provider details first. Nothing was enabled.';
      } finally {
        if (access === signInAccessGeneration) signInTry.disabled = false;
      }
    });
    signInRefresh.addEventListener('click', refreshSignInResults);
    document.addEventListener('lightwork:copilot-context-changed', clearSignInResults);
    window.addEventListener('lightwork:draft-context-changed', clearSignInResults);
    refreshSignInResults();
    var secureSignInAddress = window.location.protocol === 'https:';
    var signInAddresses = {
      oidc: window.location.origin + '/auth/callback',
      'saml-return': secureSignInAddress ? window.location.origin + '/saml/acs' : '',
      'saml-name': secureSignInAddress ? window.location.origin + '/saml/metadata' : ''
    };
    signInGuide.querySelectorAll('[data-signin-address]').forEach(function (field) {
      field.value = signInAddresses[field.dataset.signinAddress] || '';
    });
    signInGuide.querySelectorAll('[data-signin-copy]').forEach(function (button) {
      if (!signInAddresses[button.dataset.signinCopy]) {
        button.disabled = true;
        return;
      }
      button.addEventListener('click', async function () {
        var field = signInGuide.querySelector('[data-signin-address="' + button.dataset.signinCopy + '"]');
        if (!field) return;
        try {
          await navigator.clipboard.writeText(field.value);
          button.textContent = 'Copied';
        } catch (_) {
          field.focus(); field.select();
          button.textContent = 'Select the address and copy it';
        }
      });
    });
    if (!secureSignInAddress) {
      signInGuide.querySelector('[data-signin-status="saml"]').textContent =
        'Open Lightwork at its public HTTPS address before copying or registering SAML values.';
    }
    signInGuide.querySelectorAll('[data-signin-check]').forEach(function (button) {
      button.addEventListener('click', async function () {
        var kind = button.dataset.signinCheck;
        var status = signInGuide.querySelector('[data-signin-status="' + kind + '"]');
        button.disabled = true;
        status.textContent = 'Checking saved provider details…';
        try {
          var response = await fetch(API + '/test', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: kind === 'oidc' ? 'auth.oidc.issuer' : 'auth.saml.idp_metadata_url' })
          });
          var result = await response.json();
          if (!response.ok || result.ok !== true) {
            status.textContent = result.message || 'The provider connection could not be checked. Review the saved details and try again.';
          } else {
            status.textContent = result.message + " This checks the provider connection, not a person's sign-in.";
          }
        } catch (_) {
          status.textContent = 'The provider connection could not be checked. Try again.';
        } finally {
          button.disabled = false;
        }
      });
    });
  }

  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : 'Could not ' + action + '. Try again.';
  }
  function rows(scope) {
    return Array.prototype.slice.call((scope || root).querySelectorAll('.settings-all-row[data-setting-id]'));
  }
  function rowById(id) {
    return rows().filter(function (row) { return row.dataset.settingId === id; })[0] || null;
  }
  function say(row, text) {
    var node = row && row.querySelector('[data-row-status]');
    if (node) node.textContent = text || '';
  }
  function announce(text) {
    var box = document.getElementById('settings-all-status');
    if (!box) return;
    box.textContent = text;
    box.hidden = !text;
  }

  // ---- reading a control ---------------------------------------------------
  function read(row) {
    var control = row.dataset.control;
    var input = row.querySelector('[data-input]');
    if (control === 'toggle') return input ? input.checked : null;
    if (control === 'text' && row.querySelector('[data-segment-at]')) return segmentAddress(row);
    if (control === 'select' || control === 'text' || control === 'path' || control === 'fingerprint') {
      return input ? input.value : null;
    }
    if (control === 'picks') {
      return Array.prototype.slice.call(row.querySelectorAll('[data-picks] [data-pick-item]'))
        .map(function (li) { return li.getAttribute('data-value'); });
    }
    if (control === 'document') return row.pendingDocument || null;
    if (control === 'number') {
      if (!input) return null;
      var raw = input.value.trim();
      return raw === '' ? null : Number(raw);
    }
    if (control === 'multiselect') {
      return Array.prototype.slice.call(row.querySelectorAll('[data-choice]'))
        .filter(function (box) { return box.checked; })
        .map(function (box) { return box.value; });
    }
    if (control === 'list') {
      return Array.prototype.slice.call(row.querySelectorAll('[data-list-item]'))
        .map(function (item) { return item.value.trim(); })
        .filter(function (item) { return item; });
    }
    if (control === 'rate') {
      var count = row.querySelector('[data-rate-count]');
      var period = row.querySelector('[data-rate-period]');
      if (!count || count.value.trim() === '') return null;
      return {count: Number(count.value), seconds: Number(period.value)};
    }
    if (control === 'secret') {
      return input && !input.hidden ? input.value : null;
    }
    if (control === 'keys') {
      return Array.prototype.slice.call(row.querySelectorAll('[data-key-item]'))
        .map(function (item) { return item.getAttribute('data-key') || ''; });
    }
    if (row.querySelector('[data-grid]')) return readGrid(row);
    if (control === 'table') {
      var kind = (row.querySelector('[data-table]') || {dataset: {}}).dataset.rowKind;
      return Array.prototype.slice.call(row.querySelectorAll('[data-table-row]')).map(function (tr) {
        if (kind === 'rate') {
          var cnt = tr.querySelector('[data-count]');
          var per = tr.querySelector('[data-period]');
          return {name: tr.dataset.name, count: cnt && cnt.value.trim() !== '' ? Number(cnt.value) : null,
                  seconds: per ? Number(per.value) : 60};
        }
        var risk = tr.querySelector('[data-risk]');
        return {name: tr.dataset.name, risk: risk ? risk.value : 'high'};
      });
    }
    return null;
  }
  function snapshot(row) { return JSON.stringify(read(row)); }
  function changed(row) {
    if (row.dataset.control === 'document') return !!row.pendingDocument;
    if (row.dataset.control === 'secret') {
      var input = row.querySelector('[data-input]');
      return !!(input && !input.hidden && input.value.trim());
    }
    return row.dataset.initial !== undefined && snapshot(row) !== row.dataset.initial;
  }
  function editable(row) { return !!row.querySelector('[data-save]'); }
  function remember(row) { row.dataset.initial = snapshot(row); }

  window.addEventListener('beforeunload', function (event) {
    if (!rows().some(changed)) return;
    event.preventDefault();
    event.returnValue = '';
  });

  // Recovery is opt-in and limited to ordinary, non-policy scalar/list rows.
  var recovery = null;
  var recoveryOpt = document.getElementById('settings-recovery-opt');
  function recoverable(row) {
    return !row.dataset.warning && ['text', 'number', 'toggle', 'select', 'list', 'picks'].indexOf(row.dataset.control) !== -1;
  }
  function recoveryDraft() {
    var fields = {};
    rows().filter(function (row) { return recoverable(row) && changed(row); }).forEach(function (row) {
      fields[row.dataset.settingId] = {value: read(row), revision: row.dataset.revision};
    });
    return {fields: fields};
  }
  function enableRecovery() {
    if (!recoveryOpt || !recoveryOpt.checked || recovery || !window.mvDraftRecovery) return;
    recovery = window.mvDraftRecovery.create({host: root, key: 'settings-all-safe-drafts',
      read: recoveryDraft, restore: async function (draft) {
        for (var id of Object.keys(draft.fields || {})) {
          if (!rowById(id)) await fetchRows('q=' + encodeURIComponent(id.split('.').join(' ')));
          var row = rowById(id);
          if (!row || !recoverable(row)) continue;
          var initial = row.dataset.initial, item = draft.fields[id];
          var control = row.querySelector('[data-input]');
          if (row.dataset.control === 'toggle') control.checked = item.value === true;
          else if (row.dataset.control === 'list') {
            row.querySelector('.settings-all-list-items').textContent = '';
            (item.value || []).forEach(function (value) { addListItem(row, value); });
          } else if (row.dataset.control === 'picks') {
            row.querySelector('[data-pick-list]').textContent = '';
            (item.value || []).forEach(function (value) { addChip(row.querySelector('[data-picks]'), value, value); });
          } else if (control) control.value = item.value == null ? '' : item.value;
          row.dataset.initial = initial;
          row.dataset.revision = item.revision;
          say(row, 'Recovery copy restored. Review and save this draft.');
        }
      }});
  }
  if (recoveryOpt) recoveryOpt.addEventListener('change', function () {
    if (recoveryOpt.checked) enableRecovery();
    else if (recovery) { recovery.dispose(); recovery.panel.remove(); recovery = null; }
  });
  window.addEventListener('lightwork:drafts-ready', enableRecovery);

  // ---- writing a control from the server's state ---------------------------
  function apply(row, data) {
    delete row.dataset.companySigninDefault;
    var control = row.dataset.control;
    var input = row.querySelector('[data-input]');
    if (control === 'toggle' && input) input.checked = data.value === true;
    else if ((control === 'select' || control === 'text' || control === 'path' || control === 'fingerprint') && input) {
      if (input.hasAttribute('data-select-choices-url')) {
        replaceSelectChoices(input, data.choices || [], data.value == null ? '' : String(data.value));
      }
      input.value = data.value == null ? '' : String(data.value);
      var at = row.querySelector('[data-segment-at]');
      if (at) { at.setAttribute('data-at', String(data.segment_at == null ? -1 : data.segment_at)); segmentOptions(row); }
      var printed = row.querySelector('[data-fingerprint-shown]');
      if (printed) printed.textContent = data.value_text;
      var preview = row.querySelector('[data-preview]');
      if (preview) preview.textContent = '';
    }
    else if (control === 'picks') {
      var chips = row.querySelector('[data-picks] [data-pick-list]');
      if (chips) {
        chips.textContent = '';
        (data.picks || []).forEach(function (p) { addChip(row.querySelector('[data-picks]'), p.value, p.label); });
      }
      syncPicks(row);
    } else if (control === 'document') {
      row.pendingDocument = null;
      showDocument(row, data.document);
    }
    else if (control === 'number' && input) input.value = data.value == null ? '' : String(data.value);
    else if (control === 'multiselect') {
      row.querySelectorAll('[data-choice]').forEach(function (box) {
        box.checked = (data.value || []).indexOf(box.value) !== -1;
      });
    } else if (control === 'list') {
      var list = row.querySelector('.settings-all-list-items');
      if (list) {
        list.textContent = '';
        (data.value || []).forEach(function (value) { addListItem(row, value); });
      }
    } else if (control === 'rate') {
      var count = row.querySelector('[data-rate-count]');
      var period = row.querySelector('[data-rate-period]');
      if (count) count.value = data.rate_count === '' || data.rate_count == null ? '' : String(data.rate_count);
      if (period && data.rate_seconds) period.value = String(data.rate_seconds);
    } else if (control === 'keys') {
      var keyList = row.querySelector('[data-key-list]');
      if (keyList) {
        keyList.textContent = '';
        (data.key_items || []).forEach(function (key) { addKeyItem(row, key.value, key.fingerprint); });
      }
      syncEmpty(row);
    } else if (data.grid && row.querySelector('[data-grid]')) {
      buildGrid(row, data.grid);
    } else if (control === 'table') {
      var body = row.querySelector('[data-table-body]');
      if (body) {
        body.textContent = '';
        (data.rows || []).forEach(function (r) { addTableRow(row, r, data); });
      }
      syncEmpty(row);
    } else if (control === 'secret') {
      var state = row.querySelector('[data-secret-state]');
      var replace = row.querySelector('[data-secret-replace]');
      if (state) {
        state.textContent = data.is_set ? 'Set' : 'Not set';
        state.className = 'badge ' + (data.is_set ? 'ok' : 'idle');
      }
      if (replace) replace.textContent = data.is_set ? 'Replace' : 'Add';
      if (input) { input.value = ''; input.hidden = true; }
    }
    var valueText = row.querySelector('[data-value-text]');
    if (valueText) valueText.textContent = data.value_text;
    var source = row.querySelector('[data-source-text]');
    if (source) {
      source.textContent = data.source_text;
      source.className = 'badge ' + (data.source === 'here' ? 'ok' : (data.source === 'deployment' ? 'warn' : 'idle'));
    }
    row.dataset.source = data.source;
    row.dataset.revision = data.revision || row.dataset.revision;
    remember(row);
  }
  function applyAll(payload, savedIds) {
    (payload.groups || []).forEach(function (group) {
      (group.settings || []).forEach(function (data) {
        var row = rowById(data.id);
        if (row && (!changed(row) || savedIds.indexOf(data.id) !== -1)) apply(row, data);
      });
    });
  }

  // ---- saving --------------------------------------------------------------
  function valueChange(row) {
    var defaults = ['auth.oidc.authorization_endpoint', 'auth.oidc.token_endpoint', 'auth.oidc.jwks_uri', 'auth.oidc.end_session_endpoint'];
    if (row.dataset.companySigninDefault === '1' && defaults.indexOf(row.dataset.settingId) !== -1 && read(row) === '') {
      return {id: row.dataset.settingId, reset: true};
    }
    return {id: row.dataset.settingId, value: read(row)};
  }
  // ---- "Test connection" / "Check this location" ------------------------------
  function checkValue(row) {
    var control = row.dataset.control;
    var input = row.querySelector('[data-input]');
    if (control === 'secret') {
      return input && !input.hidden && input.value.trim() ? input.value : null;
    }
    if (control === 'text' || control === 'path' || control === 'select') {
      var value = read(row);
      return value && String(value).trim() ? value : null;
    }
    return null;  // other controls: check what is saved now
  }
  async function runCheck(row, button) {
    say(row, 'Checking…');
    button.disabled = true;
    try {
      var data = await window.mvFetchJSON(API + '/test', {method: 'POST', cache: 'no-store',
        body: {id: row.dataset.settingId, value: checkValue(row)}}, 'run the check');
      say(row, data && typeof data.message === 'string' ? data.message : errorText({status: 0}, 'run the check'));
    } catch (failure) {
      // A refused check still explains itself in plain words.
      var told = failure && failure.payload && failure.payload.message;
      say(row, typeof told === 'string' ? told : errorText(failure, 'run the check'));
    } finally {
      button.disabled = false;
    }
  }
  async function commit(changes, busyRows, action) {
    if (!changes.length) {
      busyRows.forEach(function (row) { say(row, 'Nothing to save.'); });
      return;
    }
    if (root.dataset.saving === '1') return;
    // Reset and inherit replace what was typed, so only a save of values is checked.
    var problems = changes.some(function (c) { return 'value' in c; }) ? cellProblems(busyRows) : [];
    if (problems.length) { showCellProblems(problems); return; }
    clearCellProblems();
    var revision = busyRows.length ? busyRows[0].dataset.revision : '';
    var disabled = [];
    root.dataset.saving = '1';
    busyRows.forEach(function (row) {
      say(row, 'Saving.'); row.setAttribute('aria-busy', 'true');
      row.querySelectorAll('button,input,select,textarea').forEach(function (control) {
        disabled.push([control, control.disabled]); control.disabled = true;
      });
    });
    try {
      if (!window.mvReviewSettings || !window.LightworkSettingsCatalog) throw new Error('The complete protected settings review is unavailable. Your draft is kept; reload this page.');
      var reviewed = await window.mvReviewSettings(changes, revision);
      if (!reviewed) { busyRows.forEach(function (row) { say(row, 'Draft kept. Nothing was changed.'); }); return; }
      changes = reviewed.changes; revision = reviewed.revision;
      var result = await window.LightworkSettingsCatalog.save(reviewed);
      if (!result.response.ok) {
        var message = result.data && typeof result.data.message === 'string'
          ? result.data.message : errorText(result.response, action);
        busyRows.forEach(function (row) { say(row, message); });
        if (window.mvToast) window.mvToast(message, {error: true});
        return;
      }
      if (result.response.status === 202 && typeof result.data.message === 'string') {
        // Held for approval by other administrators: nothing was saved yet.
        busyRows.forEach(function (row) { say(row, result.data.message); });
        announce(result.data.message);
        updateFilter();
        return;
      }
      if (result.data.original && (!result.data.groups || !result.data.original.confirmed)) {
        busyRows.forEach(function (row) { say(row, result.data.original.message + ' Your current editable choices were kept.'); });
        return;
      }
      applyAll(result.data || {}, changes.map(function (item) { return item.id; }));
      rows().forEach(function (row) {
        if (!changed(row)) row.dataset.revision = result.data.revision || row.dataset.revision;
      });
      if (recovery) { recovery.changed(); recovery.save(); }
      document.dispatchEvent(new CustomEvent('lightwork:settings-saved', {detail: {ids: result.data.changed || []}}));
      var done = (result.data.changed || []).length;
      var text = done ? 'Saved.' : 'Nothing changed.';
      if (result.data.restart) text += ' Check configuration status below for the services that need a restart.';
      busyRows.forEach(function (row) { say(row, text); });
      announce(done ? (done === 1 ? '1 setting saved.' : done + ' settings saved.') + (result.data.restart ? ' Check configuration status below for the services that need a restart.' : '') : '');
      updateFilter();
    } catch (failure) {
      // A refused review (a lock-out, say) carries the server's own sentence,
      // as a refused save does above.
      var told = failure && failure.data && typeof failure.data.message === 'string' ? failure.data.message : '';
      var text2 = told || errorText(failure, action);
      busyRows.forEach(function (row) { say(row, text2); });
    } finally {
      root.dataset.saving = '0';
      disabled.forEach(function (item) { item[0].disabled = item[1]; });
      busyRows.forEach(function (row) { row.removeAttribute('aria-busy'); });
    }
  }

  function saveRows(list) {
    var pending = list.filter(function (row) { return editable(row) && changed(row); });
    var changes = pending.map(valueChange);
    if (!pending.length) {
      list.forEach(function (row) { if (editable(row)) say(row, ''); });
      announce('There are no changes to save in this group.');
      return Promise.resolve();
    }
    return commit(changes, pending, 'save the setting');
  }

  root.addEventListener('click', async function (event) {
    var target = event.target.closest('button');
    if (!target) return;
    var row = target.closest('.settings-all-row');
    if (target.hasAttribute('data-save') && row) {
      var needsNew = row.dataset.control === 'secret' || row.dataset.control === 'document';
      var single = needsNew && !changed(row)
        ? [] : [valueChange(row)];
      if (!single.length) {
        say(row, row.dataset.control === 'document' ? 'Choose the file to import first.'
          : 'Choose Replace and enter a value first.');
        return;
      }
      await commit(single, [row], 'save the setting');
    } else if (target.hasAttribute('data-test') && row) {
      await runCheck(row, target);
    } else if (target.hasAttribute('data-inherit') && row) {
      await commit([{id: row.dataset.settingId, inherit: true}], [row], 'use the inherited value');
    } else if (target.hasAttribute('data-reset') && row) {
      if (row.dataset.source === 'default' && !changed(row)) {
        say(row, 'Already using the default.');
        return;
      }
      await commit([{id: row.dataset.settingId, reset: true}], [row], 'reset the setting');
    } else if (target.dataset.saveGroup) {
      await saveRows(rows(target.closest('.settings-all-group')));
    } else if (target.dataset.saveSubgroup) {
      var part = target.dataset.saveSubgroup;
      await saveRows(rows(target.closest('.settings-all-group')).filter(function (r) {
        return r.dataset.subgroup === part;
      }));
    } else if (target.hasAttribute('data-key-remove') && row) {
      var keyItem = target.closest('li');
      if (keyItem) keyItem.remove();
      syncEmpty(row);
      say(row, 'Removed from the list. Choose Save to stop trusting this publisher.');
      var fileBox = row.querySelector('[data-key-file]');
      if (fileBox) fileBox.focus();
    } else if (target.hasAttribute('data-key-add') && row) {
      var paste = row.querySelector('[data-key-paste]');
      var text = paste ? paste.value.trim() : '';
      if (!text) { say(row, 'Paste the publisher key first.'); return; }
      addKeyItem(row, text, '');
      if (paste) paste.value = '';
      syncEmpty(row);
      say(row, 'Key added to the list. Choose Save to trust this publisher.');
    } else if (target.hasAttribute('data-table-remove') && row) {
      var tr = target.closest('tr');
      if (tr) tr.remove();
      syncEmpty(row);
      var focusTo = row.querySelector('[data-table-search], [data-table-newname]');
      if (focusTo) focusTo.focus();
    } else if (target.hasAttribute('data-table-add') && row) {
      addFromTableForm(row);
    } else if (target.hasAttribute('data-grid-add') && row) {
      addFromGridForm(row);
    } else if (target.hasAttribute('data-grid-remove') && row) {
      var gridTr = target.closest('tr');
      if (gridTr) gridTr.remove();
      syncGrid(row);
      var addControl = row.querySelector('[data-grid-newkey], [data-grid-add]');
      if (addControl) addControl.focus();
      say(row, 'Removed from the list. Choose Save to keep this change.');
    } else if (target.hasAttribute('data-pick-add') && row) {
      addPick(row, target.closest('td, [data-picks]'));
      syncPicks(row);
    } else if (target.hasAttribute('data-pick-remove') && row) {
      var pickCell = target.closest('td, [data-picks]');
      var pickItem = target.closest('li');
      if (pickItem) pickItem.remove();
      syncPicks(row);
      var pickSelect = pickCell && pickCell.querySelector('[data-pick-select]');
      if (pickSelect) pickSelect.focus();
    } else if (target.hasAttribute('data-fingerprint-server') && row) {
      await fingerprintFrom(row, null, target);
    } else if (target.dataset.inheritGroup) {
      var inheritedGroup = target.closest('.settings-all-group');
      if (!(await loadGroup(target.dataset.inheritGroup))) return;
      var inheritedRows = rows(inheritedGroup).filter(function (r) { return editable(r) && r.dataset.source === 'here'; });
      if (!inheritedRows.length) { announce('This group has no editable dashboard overrides to remove.'); return; }
      await commit(inheritedRows.map(function (r) { return {id:r.dataset.settingId,inherit:true}; }), inheritedRows, 'use inherited values');
    } else if (target.dataset.resetGroup) {
      var group = target.closest('.settings-all-group');
      // Every setting of the group, not only those shown so far.
      if (!(await loadGroup(target.dataset.resetGroup))) return;
      var name = group.querySelector('h2') ? group.querySelector('h2').textContent : 'this group';
      var list = rows(group).filter(function (r) { return editable(r) && r.dataset.source !== 'default'; });
      if (!list.length) { announce('Everything in ' + name + ' already uses its default.'); return; }
      var ok = await window.mvConfirm('Put every setting in ' + name + ' back to its product default? Deployment-locked rows are excluded.', {okText: 'Review product defaults'});
      if (!ok) return;
      await commit(list.map(function (r) { return {id: r.dataset.settingId, reset: true}; }), list, 'reset the settings');
    } else if (target.hasAttribute('data-signin-key-create') && row) {
      if (row.dataset.settingId !== 'auth.oidc.session_secret' || !editable(row) || root.dataset.saving === '1' || target.disabled) return;
      var keyInput = row.querySelector('[data-input]');
      if (!keyInput || keyInput.value.trim()) { say(row, 'Your entered key has been kept. Clear that draft before creating a different one.'); return; }
      try {
        var randomKey = window.crypto.getRandomValues(new Uint8Array(32));
        keyInput.value = Array.from(randomKey, function (byte) { return byte.toString(16).padStart(2, '0'); }).join('');
        randomKey.fill(0);
        keyInput.hidden = false;
        keyInput.dispatchEvent(new Event('input', {bubbles: true}));
        say(row, 'A secure sign-in key is ready as an unsaved draft. Review Save setting before it changes sign-in.');
        keyInput.focus();
      } catch (_) { say(row, 'A secure key could not be created. Nothing was saved.'); }
    } else if (target.hasAttribute('data-secret-replace') && row) {
      var input = row.querySelector('[data-input]');
      if (input) { input.hidden = false; input.focus(); }
    } else if (target.hasAttribute('data-list-add') && row) {
      var added = addListItem(row, '');
      if (added) added.focus();
    } else if (target.hasAttribute('data-list-remove')) {
      var item = target.closest('li');
      var owner = item && item.closest('.settings-all-row');
      if (item) item.remove();
      if (owner) { var add = owner.querySelector('[data-list-add]'); if (add) add.focus(); }
    }
  });

  function safeId(row) { return 'sa-' + row.dataset.settingId.replace(/[^A-Za-z0-9_-]/g, '-'); }
  function addListItem(row, value) {
    var list = row.querySelector('.settings-all-list-items');
    if (!list) return null;
    var box = row.querySelector('[data-list]');
    var noun = (box && box.dataset.itemLabel) || 'Address';
    var index = list.children.length + 1;
    var li = document.createElement('li');
    var id = safeId(row) + '-item-new-' + index + '-' + Date.now();
    var label = document.createElement('label');
    label.className = 'sr-only';
    label.htmlFor = id;
    label.textContent = noun + ' ' + index;
    var input = document.createElement('input');
    input.className = 'input';
    input.type = 'text';
    input.id = id;
    input.maxLength = Number((box && box.dataset.maxLength) || 300);
    input.placeholder = (box && box.dataset.itemHint) || '';
    input.setAttribute('data-list-item', '');
    input.value = value || '';
    var remove = document.createElement('button');
    remove.className = 'btn btn--ghost';
    remove.type = 'button';
    remove.textContent = 'Remove';
    remove.setAttribute('data-list-remove', '');
    li.appendChild(label); li.appendChild(input); li.appendChild(remove);
    list.appendChild(li);
    return input;
  }

  // ---- publisher keys --------------------------------------------------------
  function addKeyItem(row, value, fingerprint) {
    var list = row.querySelector('[data-key-list]');
    if (!list) return null;
    var li = document.createElement('li');
    li.setAttribute('data-key-item', '');
    li.setAttribute('data-key', value);
    var text = document.createElement('span');
    if (fingerprint) {
      text.appendChild(document.createTextNode('Publisher key, fingerprint '));
      var strong = document.createElement('strong');
      strong.textContent = fingerprint;
      text.appendChild(strong);
    } else {
      text.textContent = 'New publisher key (its fingerprint is shown after saving)';
    }
    var remove = document.createElement('button');
    remove.className = 'btn btn--ghost';
    remove.type = 'button';
    remove.textContent = 'Remove';
    remove.setAttribute('data-key-remove', '');
    li.appendChild(text); li.appendChild(remove);
    list.appendChild(li);
    return li;
  }
  function syncEmpty(row) {
    var keysEmpty = row.querySelector('[data-keys-empty]');
    if (keysEmpty) keysEmpty.hidden = !!row.querySelector('[data-key-item]');
    var tableEmpty = row.querySelector('[data-table-empty]');
    if (tableEmpty) tableEmpty.hidden = !!row.querySelector('[data-table-row]');
  }
  root.addEventListener('change', async function (event) {
    var file = event.target.closest('[data-key-file]');
    if (!file || !file.files || !file.files.length) return;
    var row = file.closest('.settings-all-row');
    var chosen = file.files[0];
    if (chosen.size > 4096) {
      say(row, 'That file is too large to be a publisher key. Ask the publisher for their public key file.');
      file.value = '';
      return;
    }
    try {
      var text = await chosen.text();
      addKeyItem(row, text.trim(), '');
      syncEmpty(row);
      say(row, 'Key added to the list. Choose Save to trust this publisher.');
    } catch (failure) {
      say(row, 'That file could not be read. Try again or paste the key instead.');
    }
    file.value = '';
  });

  // ---- tables (usage limits, reviewed tools) -------------------------------
  function periodOptions(select, periods, seconds) {
    (periods || [{value: 60, label: 'Every minute'}, {value: 3600, label: 'Every hour'},
                 {value: 86400, label: 'Every day'}]).forEach(function (p) {
      var option = document.createElement('option');
      option.value = String(p.value);
      option.textContent = p.label;
      if (Number(p.value) === Number(seconds)) option.selected = true;
      select.appendChild(option);
    });
  }
  function riskOptions(select, risks, value) {
    (risks || [{value: 'low', label: 'Low risk'}, {value: 'medium', label: 'Medium risk'},
               {value: 'high', label: 'High risk'}]).forEach(function (k) {
      var option = document.createElement('option');
      option.value = k.value;
      option.textContent = k.label;
      if (k.value === value) option.selected = true;
      select.appendChild(option);
    });
  }
  function addTableRow(row, r, data) {
    var body = row.querySelector('[data-table-body]');
    var kind = row.querySelector('[data-table]').dataset.rowKind;
    if (!body) return null;
    var tr = document.createElement('tr');
    tr.setAttribute('data-table-row', '');
    tr.dataset.name = r.name;
    var name = document.createElement('td');
    name.setAttribute('data-row-label', '');
    name.textContent = r.label || r.name;
    tr.appendChild(name);
    if (kind === 'rate') {
      var countCell = document.createElement('td');
      var count = document.createElement('input');
      count.className = 'input'; count.type = 'number'; count.min = '1'; count.max = '100000'; count.step = '1';
      count.setAttribute('data-count', '');
      count.setAttribute('aria-label', 'How many times for ' + (r.label || r.name));
      count.value = r.count == null ? '' : String(r.count);
      countCell.appendChild(count);
      var periodCell = document.createElement('td');
      var period = document.createElement('select');
      period.className = 'select';
      period.setAttribute('data-period', '');
      period.setAttribute('aria-label', 'How often for ' + (r.label || r.name));
      periodOptions(period, data && data.periods, r.seconds || 60);
      periodCell.appendChild(period);
      tr.appendChild(countCell); tr.appendChild(periodCell);
    } else {
      var riskCell = document.createElement('td');
      var risk = document.createElement('select');
      risk.className = 'select';
      risk.setAttribute('data-risk', '');
      risk.setAttribute('aria-label', 'Risk level for ' + (r.label || r.name));
      riskOptions(risk, data && data.risks, r.risk || 'high');
      riskCell.appendChild(risk);
      tr.appendChild(riskCell);
    }
    var removeCell = document.createElement('td');
    var remove = document.createElement('button');
    remove.className = 'btn btn--ghost'; remove.type = 'button'; remove.textContent = 'Remove';
    remove.setAttribute('data-table-remove', '');
    removeCell.appendChild(remove);
    tr.appendChild(removeCell);
    body.appendChild(tr);
    return tr;
  }
  function hasRow(row, name) {
    return Array.prototype.slice.call(row.querySelectorAll('[data-table-row]'))
      .some(function (tr) { return tr.dataset.name === name; });
  }
  function addFromTableForm(row) {
    var kind = row.querySelector('[data-table]').dataset.rowKind;
    if (kind === 'rate') {
      var pick = row.querySelector('[data-table-pick]');
      var chosen = pick && pick.value;
      if (!chosen) { say(row, 'Find and choose a tool first.'); return; }
      if (hasRow(row, chosen)) { say(row, 'That tool already has a limit. Change it in the list.'); return; }
      var label = pick.options[pick.selectedIndex].textContent;
      var tr = addTableRow(row, {name: chosen, label: label, count: 10, seconds: 60}, null);
      syncEmpty(row);
      say(row, 'Limit added. Set how many and how often, then choose Save.');
      if (tr) tr.querySelector('[data-count]').focus();
      return;
    }
    var nameBox = row.querySelector('[data-table-newname]');
    var riskBox = row.querySelector('[data-table-newrisk]');
    var name = nameBox ? nameBox.value.trim() : '';
    if (!name) { say(row, 'Type the tool name first.'); return; }
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(name) || name.indexOf('__') !== -1) {
      say(row, 'A tool name uses letters, numbers, dots, dashes and single underscores only.');
      return;
    }
    if (hasRow(row, name)) { say(row, 'That tool is already in the list.'); return; }
    addTableRow(row, {name: name, label: name, risk: riskBox ? riskBox.value : 'high'}, null);
    nameBox.value = '';
    syncEmpty(row);
    say(row, 'Tool added. Choose Save to offer it.');
  }
  var loadedChoices = {};
  async function loadChoices(row) {
    var box = row.querySelector('[data-table]');
    var url = box && box.dataset.choicesUrl;
    if (!url) return [];
    if (loadedChoices[url]) return loadedChoices[url];
    try {
      var data = await window.mvFetchJSON(url, {cache: 'no-store'});
      loadedChoices[url] = data.choices || [];
    } catch (failure) {
      say(row, errorText(failure, 'load the list of tools'));
      return [];
    }
    return loadedChoices[url];
  }
  async function filterChoices(row) {
    var search = row.querySelector('[data-table-search]');
    var pick = row.querySelector('[data-table-pick]');
    if (!search || !pick) return;
    var words = search.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    var choices = await loadChoices(row);
    var matches = choices.filter(function (c) {
      var text = (c.label + ' ' + c.value).toLowerCase();
      return words.every(function (w) { return text.indexOf(w) !== -1; });
    });
    pick.textContent = '';
    var first = document.createElement('option');
    first.value = '';
    first.textContent = matches.length
      ? (matches.length > 50 ? 'Showing 50 of ' + matches.length + ' tools: search to narrow' : 'Choose a tool')
      : 'No tools match that search';
    pick.appendChild(first);
    matches.slice(0, 50).forEach(function (c) {
      var option = document.createElement('option');
      option.value = c.value;
      option.textContent = c.label;
      pick.appendChild(option);
    });
  }
  root.addEventListener('input', function (event) {
    var search = event.target.closest('[data-table-search]');
    if (search) filterChoices(search.closest('.settings-all-row'));
    var pickSearch = event.target.closest('[data-pick-search]');
    if (pickSearch) filterPick(pickSearch.closest('.settings-all-row'), pickSearch.closest('td, [data-picks]'));
    var keySearch = event.target.closest('[data-grid-keysearch]');
    if (keySearch) filterGridKeys(keySearch.closest('.settings-all-row'));
    var address = event.target.closest('.settings-all-row[data-control="text"] [data-input]');
    if (address && address.closest('.settings-all-row').querySelector('[data-segment-at]')) {
      segmentOptions(address.closest('.settings-all-row'));
    }
  });
  root.addEventListener('focusin', function (event) {
    var pick = event.target.closest('[data-table-pick], [data-table-search]');
    if (pick && pick.closest('.settings-all-row').querySelector('[data-table-pick]').options.length <= 1) {
      filterChoices(pick.closest('.settings-all-row'));
    }
    var cellPick = event.target.closest('[data-pick-search], [data-pick-select]');
    var cell = cellPick && cellPick.closest('td, [data-picks]');
    if (cell && !cell.dataset.loaded) {
      cell.dataset.loaded = '1';
      filterPick(cellPick.closest('.settings-all-row'), cell);
    }
    var keyPick = event.target.closest('[data-grid-keysearch], [data-grid-newkey]');
    var keyRow = keyPick && keyPick.closest('.settings-all-row');
    if (keyRow && keyRow.querySelector('[data-grid-keysearch]') && !keyRow.dataset.keysLoaded) {
      keyRow.dataset.keysLoaded = '1';
      filterGridKeys(keyRow);
    }
  });

  // ---- grids and rules (tools per chat app, spending per service, rules) ---
  var columnChoiceCache = {};
  function gridState(row) {
    var box = row.querySelector('[data-grid]');
    if (!box) return null;
    if (!box.gridState) {
      try { box.gridState = JSON.parse(box.getAttribute('data-grid-state') || '{}'); } catch (ignore) { box.gridState = {}; }
    }
    box.gridState.columns = box.gridState.columns || [];
    return box.gridState;
  }
  function columnFor(row, td) {
    if (td && td.hasAttribute('data-picks')) {
      var inline = [];
      try { inline = JSON.parse(td.getAttribute('data-choices') || '[]'); } catch (ignore) { inline = []; }
      return {kind: 'picks', label: td.dataset.label || 'Choice', choices: inline,
              choices_url: td.dataset.choicesUrl || ''};
    }
    var key = td && td.getAttribute('data-cell');
    return (gridState(row).columns || []).filter(function (c) { return c.key === key; })[0] || null;
  }
  function addOption(select, value, label, selected) {
    var option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    if (selected) option.selected = true;
    select.appendChild(option);
    return option;
  }
  // A local environment list is read only on an explicit Load/Refresh. A slow
  // reply must never replace a newer draft, select a default or survive a
  // changed account. The current immutable value stays separate from labels.
  var lazySelectRows = [], lazySelectGeneration = 0;
  function replaceSelectChoices(select, choices, keep) {
    select.textContent = '';
    choices.forEach(function (choice) {
      addOption(select, choice.value, choice.label, choice.value === keep);
    });
    if (!choices.some(function (choice) { return choice.value === keep; })) {
      addOption(select, keep, keep ? 'Previously selected practice environment · unavailable in this list'
        : 'No practice environment selected', true);
    }
    select.value = keep;
  }
  function prepareSelectChoices(row) {
    var select = row.querySelector('[data-select-choices-url]');
    var button = row.querySelector('[data-select-choices-load]');
    if (!select || !button || row.localChoices) return;
    var state = {generation: 0, controller: null, loaded: false};
    row.localChoices = state; lazySelectRows.push(row);
    button.addEventListener('click', async function () {
      if (state.controller || root.dataset.saving === '1') return;
      var keep = select.value, ticket = ++state.generation;
      var controller = new AbortController(); state.controller = controller;
      var deadline = setTimeout(function () { controller.abort(); }, 20000);
      var notice = row.querySelector('[data-select-choices-notice]');
      button.disabled = true;
      notice.textContent = 'Reading already installed environments…';
      try {
        var response = await fetch(select.dataset.selectChoicesUrl + (state.loaded ? '?refresh=true' : ''), {
          credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
          headers: {Accept: 'application/json'}
        });
        var body = await response.text();
        if (body.length > 160000) throw new Error('This environment list is too large. Your choice has been kept.');
        var data = JSON.parse(body);
        if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail
          : 'The installed environments could not be read. Keep your current choice and try again.');
        if (!Array.isArray(data.choices) || data.choices.length > 129 ||
            !data.choices.every(function (choice) { return choice && typeof choice.value === 'string' &&
              (choice.value === '' || /^sha256:[a-f0-9]{64}$/.test(choice.value)) &&
              typeof choice.label === 'string' && choice.label.length <= 1000; }) ||
            typeof data.notice !== 'string' || data.notice.length > 2000)
          throw new Error('This installed list could not be verified. Your choice has been kept.');
        if (ticket !== state.generation || !row.isConnected) return;
        // Preserve a choice changed while the read was in flight.
        keep = select.value;
        replaceSelectChoices(select, data.choices, keep);
        notice.textContent = data.notice + (data.choices.length === 1
          ? ' No eligible installed practice environment was found. Ask your installation administrator to provide one.' : '');
        state.loaded = true; button.textContent = 'Refresh installed environments';
      } catch (error) {
        if (ticket === state.generation && row.isConnected) notice.textContent =
          error.name === 'AbortError' ? 'Reading the list timed out. Your choice has been kept. Try refreshing later.'
            : error.message || 'The installed list could not be read. Your choice has been kept.';
      } finally {
        clearTimeout(deadline);
        if (state.controller === controller) state.controller = null;
        if (ticket === state.generation && root.dataset.saving !== '1') button.disabled = false;
      }
    });
  }
  function clearSelectChoices() {
    lazySelectGeneration++;
    lazySelectRows = lazySelectRows.filter(function (row) { return row.isConnected; });
    lazySelectRows.forEach(function (row) {
      var state = row.localChoices, select = row.querySelector('[data-select-choices-url]');
      state.generation++; if (state.controller) state.controller.abort(); state.controller = null; state.loaded = false;
      var keep = select.value;
      replaceSelectChoices(select, [{value: '', label: 'No practice environment selected'},
        ...(keep ? [{value: keep, label: 'Previously selected practice environment · availability not checked'}] : [])], keep);
      row.querySelector('[data-select-choices-load]').textContent = 'Load installed environments';
      row.querySelector('[data-select-choices-load]').disabled = root.dataset.saving === '1';
      row.querySelector('[data-select-choices-notice]').textContent = 'Your account or workspace changed. Load current installed choices before reviewing a change.';
    });
  }
  document.addEventListener('lightwork:copilot-context-changed', clearSelectChoices);
  window.addEventListener('lightwork:draft-context-changed', clearSelectChoices);
  function gridRows(row) {
    return Array.prototype.slice.call(row.querySelectorAll('[data-grid-row]'));
  }
  function syncGrid(row) {
    var empty = row.querySelector('[data-grid-empty]');
    if (empty) empty.hidden = gridRows(row).length > 0;
  }
  function addChip(td, value, label) {
    var list = td.querySelector('[data-pick-list]');
    if (!list) return;
    var li = document.createElement('li');
    li.setAttribute('data-pick-item', '');
    li.setAttribute('data-value', value);
    var text = document.createElement('span');
    text.textContent = label || value;
    var remove = document.createElement('button');
    remove.className = 'btn btn--ghost';
    remove.type = 'button';
    remove.textContent = 'Remove';
    remove.setAttribute('data-pick-remove', '');
    remove.setAttribute('aria-label', 'Remove ' + (label || value));
    li.appendChild(text); li.appendChild(remove);
    list.appendChild(li);
  }
  function searchBox(td, column, where) {
    var search = document.createElement('input');
    search.className = 'input';
    search.type = 'search';
    search.maxLength = 80;
    search.placeholder = 'Search';
    search.setAttribute('data-pick-search', '');
    search.setAttribute('aria-label', 'Find ' + column.label.toLowerCase() + ' ' + where);
    td.appendChild(search);
  }
  function buildCell(td, column, value, where) {
    var kind = column.kind;
    var input;
    if (kind === 'select' || kind === 'pick') {
      var current = value && typeof value === 'object' ? value : {value: column.default || '', label: ''};
      if (kind === 'pick') searchBox(td, column, where);
      input = document.createElement('select');
      input.className = 'select';
      var seen = false;
      (column.choices || []).slice(0, kind === 'pick' ? 50 : 1000).forEach(function (c) {
        if (c.value === current.value) seen = true;
        addOption(input, c.value, c.label, c.value === current.value);
      });
      if (!seen) {
        var label = current.label;
        if (!label) label = current.value === '*' ? 'Any tool' : (current.value ? current.value : 'Choose one');
        var first = addOption(input, current.value, label, true);
        input.insertBefore(first, input.firstChild);
      }
      if (kind === 'pick') input.setAttribute('data-pick-select', '');
    } else if (kind === 'picks') {
      var list = document.createElement('ul');
      list.className = 'settings-all-list-items';
      list.setAttribute('data-pick-list', '');
      list.setAttribute('aria-label', column.label + ' ' + where);
      td.appendChild(list);
      (Array.isArray(value) ? value : []).forEach(function (item) { addChip(td, item.value, item.label); });
      if (!column.choices || !column.choices.length || column.choices.length > 20) searchBox(td, column, where);
      input = document.createElement('select');
      input.className = 'select';
      input.setAttribute('data-pick-select', '');
      addOption(input, '', 'Choose one to add', true);
      (column.choices || []).slice(0, 50).forEach(function (c) { addOption(input, c.value, c.label, false); });
      input.setAttribute('aria-label', 'Choose ' + column.label.toLowerCase() + ' to add ' + where);
      td.appendChild(input);
      var add = document.createElement('button');
      add.className = 'btn btn--ghost';
      add.type = 'button';
      add.textContent = 'Add';
      add.setAttribute('data-pick-add', '');
      add.setAttribute('aria-label', 'Add to ' + column.label.toLowerCase() + ' ' + where);
      td.appendChild(add);
      return;
    } else if (kind === 'number') {
      input = document.createElement('input');
      input.className = 'input';
      input.type = 'number';
      if (column.minimum != null) input.min = String(column.minimum);
      if (column.maximum != null) input.max = String(column.maximum);
      input.step = String(column.step || 'any');
      input.value = value == null ? '' : String(value);
    } else if (kind === 'switch') {
      input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = value === true;
    } else if (kind === 'color') {
      // A colour picker; an optional colour can be left out with its switch.
      input = document.createElement('input');
      input.type = 'color';
      input.value = typeof value === 'string' && /^#[0-9a-fA-F]{6}$/.test(value) ? value.toLowerCase()
        : (typeof value === 'string' && /^#[0-9a-fA-F]{3}$/.test(value)
          ? '#' + value.slice(1).split('').map(function (c) { return c + c; }).join('').toLowerCase()
          : '#888888');
      if (!column.required) {
        var use = document.createElement('input');
        use.type = 'checkbox';
        use.checked = typeof value === 'string' && value !== '';
        use.setAttribute('data-cell-use', '');
        use.setAttribute('aria-label', 'Use ' + column.label.toLowerCase() + ' ' + where);
        td.appendChild(use);
      }
    } else if (kind === 'path' || kind === 'program') {
      // A file on the server: the server checks it when the row is saved.
      input = document.createElement('input');
      input.className = 'input';
      input.type = 'text';
      input.maxLength = 1024;
      input.spellcheck = false;
      input.autocomplete = 'off';
      input.placeholder = kind === 'program' ? 'Full location of the program on the server'
        : 'Full location of the file on the server';
      input.value = value == null ? '' : String(value);
    } else if (kind === 'secret') {
      // A saved password is never sent to the page: leave empty to keep it.
      input = document.createElement('input');
      input.className = 'input';
      input.type = 'password';
      input.autocomplete = 'new-password';
      input.maxLength = Number(column.max_length || 512);
      input.placeholder = value && value.is_set ? 'Saved. Leave empty to keep it' : 'Not set';
      input.value = '';
    } else {
      input = document.createElement('input');
      input.className = 'input';
      input.type = 'text';
      input.maxLength = 2000;
      input.value = value == null ? '' : String(value);
    }
    input.setAttribute('data-cell-input', '');
    input.setAttribute('aria-label', column.label + ' ' + where + (column.unit ? ' (' + column.unit + ')' : ''));
    input.setAttribute('data-cell-label', '\u201c' + column.label + '\u201d ' + where);
    if (column.required && /^(select|pick|number|path|program)$|^$/.test(kind || '') && input.type !== 'checkbox') input.required = true;
    if (kind === 'number' && column.integer) input.step = '1';
    td.appendChild(input);
  }
  // A value in a table that can't be saved (missing, out of range, not
  // a whole number) is named next to its row and in a summary at the top that
  // takes focus; the page title starts with "Error: " while it remains, and
  // nothing typed is cleared.
  var ERROR_PREFIX = 'Error: ';
  function cellMessage(c) {
    var label = c.getAttribute('data-cell-label') || c.getAttribute('aria-label') || 'this value';
    var v = c.validity || {};
    if (v.valueMissing) return (c.tagName === 'SELECT' ? 'Choose ' : 'Fill in ') + label + '.';
    if (v.badInput) return 'Enter ' + label + ' as a number.';
    if ((v.rangeUnderflow || v.rangeOverflow) && c.min && c.max) return 'Enter ' + label + ' from ' + c.min + ' to ' + c.max + '.';
    if (v.rangeUnderflow) return 'Enter ' + label + ' of at least ' + c.min + '.';
    if (v.rangeOverflow) return 'Enter ' + label + ' of no more than ' + c.max + '.';
    if (v.stepMismatch) return 'Enter a whole number for ' + label + '.';
    return 'Check ' + label + '.';
  }
  function cellProblems(list) {
    var found = [];
    list.forEach(function (row) {
      row.querySelectorAll('[data-cell-input]').forEach(function (c) {
        if (c.disabled || !c.checkValidity || c.checkValidity()) return;
        found.push({row: row, control: c, message: cellMessage(c)});
      });
    });
    return found;
  }
  var cellIds = 0;
  function clearCellProblems() {
    var box = document.getElementById('settings-all-errors');
    if (box) { box.hidden = true; box.replaceChildren(); }
    root.querySelectorAll('[data-cell-input][aria-invalid="true"]').forEach(function (c) { c.removeAttribute('aria-invalid'); });
    if (document.title.indexOf(ERROR_PREFIX) === 0) document.title = document.title.slice(ERROR_PREFIX.length);
  }
  function showCellProblems(found) {
    clearCellProblems();
    var box = document.getElementById('settings-all-errors');
    if (!box) {
      box = document.createElement('div');
      box.id = 'settings-all-errors'; box.className = 'mv-error-summary'; box.tabIndex = -1;
      box.setAttribute('data-mv-error-summary', ''); box.setAttribute('aria-labelledby', 'settings-all-errors-title');
      var groups = document.getElementById('settings-all-groups');
      if (groups && groups.parentNode) groups.parentNode.insertBefore(box, groups); else root.insertBefore(box, root.firstChild);
    }
    var title = document.createElement('h2');
    title.className = 'mv-error-summary__title'; title.id = 'settings-all-errors-title'; title.textContent = 'There is a problem';
    var list = document.createElement('ul');
    list.className = 'mv-error-summary__list';
    var byRow = [];
    found.forEach(function (problem) {
      var c = problem.control;
      if (!c.id) { cellIds += 1; c.id = 'settings-all-cell-' + cellIds; }
      c.setAttribute('aria-invalid', 'true');
      var status = problem.row.querySelector('[data-row-status]');
      if (status) {
        if (!status.id) { cellIds += 1; status.id = 'settings-all-row-status-' + cellIds; }
        var described = (c.getAttribute('aria-describedby') || '').split(' ').filter(Boolean);
        if (described.indexOf(status.id) < 0) c.setAttribute('aria-describedby', described.concat(status.id).join(' '));
      }
      var entry = byRow.filter(function (item) { return item.row === problem.row; })[0];
      if (entry) entry.messages.push(problem.message); else byRow.push({row: problem.row, messages: [problem.message]});
      var item = document.createElement('li'), link = document.createElement('a');
      link.href = '#' + c.id; link.textContent = problem.message;
      item.appendChild(link); list.appendChild(item);
    });
    byRow.forEach(function (entry) { say(entry.row, entry.messages.join(' ') + ' Nothing was saved.'); });
    box.replaceChildren(title, list);
    box.hidden = false;
    if (document.title.indexOf(ERROR_PREFIX) !== 0) document.title = ERROR_PREFIX + document.title;
    box.focus();
  }
  function addGridRow(row, entry) {
    var state = gridState(row);
    var body = row.querySelector('[data-grid-body]');
    if (!body) return null;
    var tr = document.createElement('tr');
    tr.setAttribute('data-grid-row', '');
    var where;
    if (state.kind === 'grid' || state.kind === 'named') {
      tr.dataset.name = entry.name;
      where = 'for ' + (entry.label || entry.name);
      var name = document.createElement('td');
      name.setAttribute('data-row-label', '');
      name.textContent = entry.label || entry.name;
      tr.appendChild(name);
    } else {
      where = 'in ' + (state.item_label || 'Rule').toLowerCase() + ' ' + (body.children.length + 1);
    }
    state.columns.forEach(function (column) {
      var td = document.createElement('td');
      td.setAttribute('data-cell', column.key);
      buildCell(td, column, entry.cells ? entry.cells[column.key] : undefined, where);
      tr.appendChild(td);
    });
    var removeCell = document.createElement('td');
    var remove = document.createElement('button');
    remove.className = 'btn btn--ghost'; remove.type = 'button'; remove.textContent = 'Remove';
    remove.setAttribute('data-grid-remove', '');
    remove.setAttribute('aria-label', 'Remove ' + where.replace(/^(for|in) /, ''));
    removeCell.appendChild(remove);
    tr.appendChild(removeCell);
    body.appendChild(tr);
    return tr;
  }
  function buildGrid(row, state) {
    var box = row.querySelector('[data-grid]');
    if (!box) return;
    box.gridState = state;
    state.columns = state.columns || [];
    var body = row.querySelector('[data-grid-body]');
    if (body) body.textContent = '';
    (state.rows || []).forEach(function (entry) { addGridRow(row, entry); });
    var keys = row.querySelector('[data-grid-newkey]');
    if (keys && state.key_choices) {
      keys.textContent = '';
      addOption(keys, '', 'Choose one', true);
      state.key_choices.forEach(function (k) { addOption(keys, k.value, k.label, false); });
    }
    syncGrid(row);
  }
  function readCell(td, column) {
    if (!td) return null;
    if (column.kind === 'picks') {
      return Array.prototype.slice.call(td.querySelectorAll('[data-pick-item]'))
        .map(function (li) { return li.getAttribute('data-value'); });
    }
    var input = td.querySelector('[data-cell-input]');
    if (!input) return null;
    if (column.kind === 'switch') return input.checked;
    if (column.kind === 'color') {
      var use = td.querySelector('[data-cell-use]');
      return use && !use.checked ? '' : input.value;
    }
    if (column.kind === 'number') return input.value.trim() === '' ? null : Number(input.value);
    return input.value;
  }
  function readGrid(row) {
    var state = gridState(row);
    return gridRows(row).map(function (tr) {
      var out = state.kind === 'grid' || state.kind === 'named' ? {name: tr.dataset.name} : {};
      state.columns.forEach(function (column) {
        out[column.key] = readCell(tr.querySelector('[data-cell="' + column.key + '"]'), column);
      });
      return out;
    });
  }
  function addFromGridForm(row) {
    var state = gridState(row);
    var tr;
    if (state.kind === 'named') {
      var box = row.querySelector('[data-grid-newname]');
      var typed = box ? box.value.trim() : '';
      if (!typed) { say(row, 'Type a name first.'); if (box) box.focus(); return; }
      var used = gridRows(row).some(function (r) { return r.dataset.name === typed; });
      if (used) { say(row, 'That name is already in the list. Change it there.'); return; }
      tr = addGridRow(row, {name: typed, label: typed, cells: {}});
      box.value = '';
    } else if (state.kind === 'grid') {
      var pick = row.querySelector('[data-grid-newkey]');
      var chosen = pick && pick.value;
      if (!chosen) { say(row, 'Choose one from the list first.'); return; }
      var taken = gridRows(row).some(function (r) { return r.dataset.name === chosen; });
      if (taken) { say(row, 'That one is already in the list. Change it there.'); return; }
      tr = addGridRow(row, {name: chosen, label: pick.options[pick.selectedIndex].textContent, cells: {}});
      pick.value = '';
    } else {
      tr = addGridRow(row, {cells: {}});
    }
    syncGrid(row);
    say(row, 'Added. Fill in the row, then choose Save.');
    var first = tr && tr.querySelector('select, input, button');
    if (first) first.focus();
  }
  async function columnChoices(row, column) {
    if (!column.choices_url) return column.choices || [];
    if (columnChoiceCache[column.choices_url]) return columnChoiceCache[column.choices_url];
    try {
      var data = await window.mvFetchJSON(column.choices_url, {cache: 'no-store'});
      columnChoiceCache[column.choices_url] = data.choices || [];
    } catch (failure) {
      say(row, errorText(failure, 'load the list of options'));
      return [];
    }
    return columnChoiceCache[column.choices_url];
  }
  async function filterPick(row, td) {
    var column = columnFor(row, td);
    var select = td && td.querySelector('[data-pick-select]');
    if (!column || !select) return;
    var search = td.querySelector('[data-pick-search]');
    var words = (search ? search.value : '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    var choices = await columnChoices(row, column);
    var matches = choices.filter(function (c) {
      var text = (c.label + ' ' + c.value).toLowerCase();
      return words.every(function (w) { return text.indexOf(w) !== -1; });
    });
    var keep = column.kind === 'pick' ? select.value : '';
    var keepLabel = column.kind === 'pick' && select.selectedIndex >= 0
      ? select.options[select.selectedIndex].textContent : '';
    select.textContent = '';
    if (column.kind === 'pick') {
      addOption(select, keep, keepLabel || keep, true);
    } else {
      addOption(select, '', matches.length
        ? (matches.length > 50 ? 'Showing 50 of ' + matches.length + ': search to narrow' : 'Choose one to add')
        : 'Nothing matches that search', true);
    }
    matches.slice(0, 50).forEach(function (c) {
      if (column.kind === 'pick' && c.value === keep) return;
      addOption(select, c.value, c.label, false);
    });
  }
  function addPick(row, td) {
    var select = td && td.querySelector('[data-pick-select]');
    if (!select || !select.value) { say(row, 'Choose one to add first.'); return; }
    var value = select.value;
    var exists = Array.prototype.slice.call(td.querySelectorAll('[data-pick-item]'))
      .some(function (li) { return li.getAttribute('data-value') === value; });
    if (exists) { say(row, 'That one is already in the list.'); return; }
    addChip(td, value, select.options[select.selectedIndex].textContent);
    select.value = '';
    say(row, 'Added. Choose Save to keep this change.');
  }

  // ---- rows named from a long list (people who write from a chat app) ------
  async function filterGridKeys(row) {
    var state = gridState(row);
    var search = row.querySelector('[data-grid-keysearch]');
    var pick = row.querySelector('[data-grid-newkey]');
    if (!state || !pick || !state.key_choices_url) return;
    var words = (search ? search.value : '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    var choices = await columnChoices(row, {choices_url: state.key_choices_url, choices: []});
    var matches = choices.filter(function (c) {
      var text = (c.label + ' ' + c.value).toLowerCase();
      return words.every(function (w) { return text.indexOf(w) !== -1; });
    });
    pick.textContent = '';
    addOption(pick, '', matches.length
      ? (matches.length > 50 ? 'Showing 50 of ' + matches.length + ': search to narrow' : 'Choose one')
      : 'Nothing matches that search', true);
    matches.slice(0, 50).forEach(function (c) { addOption(pick, c.value, c.label, false); });
  }

  // ---- several choices from a long list -----------------------------------
  function syncPicks(row) {
    var empty = row.querySelector('[data-picks-empty]');
    if (empty) empty.hidden = !!row.querySelector('[data-picks] [data-pick-item]');
  }

  // ---- an address with one part for each workspace -------------------------
  function addressParts(text) {
    var match = /^https:\/\/([^\/?#\s]+)(\/[^?#\s]*)?$/.exec((text || '').trim());
    if (!match) return null;
    return {host: match[1], parts: (match[2] || '').split('/').filter(Boolean)};
  }
  function segmentOptions(row) {
    var select = row.querySelector('[data-segment-at]');
    var input = row.querySelector('[data-input]');
    if (!select || !input) return;
    var address = addressParts(input.value);
    var parts = address ? address.parts : [];
    var wanted = select.value !== '' ? Number(select.value) : Number(select.getAttribute('data-at'));
    if (!(wanted >= 0 && wanted <= parts.length)) wanted = parts.length;
    select.textContent = '';
    for (var i = 0; i <= parts.length; i += 1) {
      var label = i === parts.length ? 'At the end of the address'
        : 'Before “' + parts[i] + '”';
      addOption(select, String(i), label, i === wanted);
    }
  }
  function segmentAddress(row) {
    var input = row.querySelector('[data-input]');
    var select = row.querySelector('[data-segment-at]');
    var text = input ? input.value.trim() : '';
    if (!text) return '';
    var address = addressParts(text);
    if (!address) return text;  // the server explains what is wrong with it
    var at = select && select.value !== '' ? Number(select.value) : address.parts.length;
    var parts = address.parts.slice();
    parts.splice(Math.min(Math.max(at, 0), parts.length), 0, '{tenant_sha256}');
    return 'https://' + address.host + '/' + parts.join('/');
  }

  // ---- fingerprints from an uploaded file ----------------------------------
  async function fingerprintFrom(row, file, button) {
    var url = API + '/fingerprint?setting_id=' + encodeURIComponent(row.dataset.settingId) +
      (file ? '' : '&server=true');
    say(row, file ? 'Working out the fingerprint…' : 'Reading the files on this server…');
    if (button) button.disabled = true;
    try {
      var data;
      try {
        data = await window.mvFetchJSON(url, {method: 'POST', cache: 'no-store',
          headers: {'Content-Type': 'application/octet-stream'}, body: file || new Blob([])}, 'work out the fingerprint');
      } catch (refused) {
        var told = refused && refused.payload && refused.payload.message;
        say(row, typeof told === 'string' ? told : errorText(refused, 'work out the fingerprint'));
        return;
      }
      if (!data || !data.fingerprint) {
        say(row, data && typeof data.message === 'string' ? data.message : errorText({status: 0}, 'work out the fingerprint'));
        return;
      }
      row.querySelector('[data-input]').value = data.fingerprint;
      var printed = row.querySelector('[data-fingerprint-shown]');
      if (printed) printed.textContent = data.shown;
      say(row, 'Fingerprint worked out. Choose Save to trust it.');
    } catch (failure) {
      say(row, errorText(failure, 'work out the fingerprint'));
    } finally {
      if (button) button.disabled = false;
    }
  }

  // ---- documents imported from a file --------------------------------------
  function showDocument(row, doc) {
    var text = row.querySelector('[data-document-text]');
    var items = row.querySelector('[data-document-items]');
    if (text) text.textContent = doc ? doc.text : 'Nothing imported yet. Import a document below.';
    if (!items) return;
    items.textContent = '';
    ((doc && doc.items) || []).forEach(function (item) {
      var li = document.createElement('li');
      li.appendChild(document.createTextNode(item.label + ', fingerprint '));
      var strong = document.createElement('strong');
      strong.textContent = item.fingerprint;
      li.appendChild(strong);
      items.appendChild(li);
    });
  }
  root.addEventListener('change', async function (event) {
    var print = event.target.closest('[data-fingerprint-file]');
    if (print && print.files && print.files.length) {
      await fingerprintFrom(print.closest('.settings-all-row'), print.files[0], null);
      print.value = '';
      return;
    }
    var doc = event.target.closest('[data-document-file]');
    if (doc && doc.files && doc.files.length) {
      var owner = doc.closest('.settings-all-row');
      var chosen = doc.files[0];
      if (chosen.size > 65536) {
        say(owner, 'That file is too large to be this kind of document. Choose a file under 64 KB.');
      } else {
        try {
          owner.pendingDocument = await chosen.text();
          say(owner, 'Ready to import “' + chosen.name + '”. Choose Save to check and use it.');
        } catch (failure) {
          say(owner, 'That file could not be read. Try again.');
        }
      }
      doc.value = '';
      return;
    }
    var level = event.target.closest('select[data-preview-url], input[data-preview-url]');
    if (level) await showPreview(level.closest('.settings-all-row'), level);
  });

  // ---- what an approval threshold would have needed --------------------------
  // Report only, from the recorded approval checks (approval_threshold_preview).
  function count(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function approvalPreview(box, data) {
    var days = data.days || 30, lead = document.createElement('p');
    if (!data.enough) {
      var title = document.createElement('strong');
      title.textContent = 'Not enough recorded checks yet:';
      lead.appendChild(title);
      if (data.recording_started_at) {
        var when = document.createElement('time');
        when.setAttribute('data-mv-time', String(data.recording_started_at));
        when.setAttribute('data-mv-time-mode', 'date');
        when.textContent = new Date(data.recording_started_at * 1000).toLocaleDateString(undefined, {day: 'numeric', month: 'short', year: 'numeric'});
        lead.appendChild(document.createTextNode(' recording started '));
        lead.appendChild(when);
        lead.appendChild(document.createTextNode('; a preview needs ' + days + ' days' + (data.reason === 'count'
          ? ' and at least ' + data.minimum + ' checks (' + data.checks + ' so far in the last ' + days + ' days).' : '.')));
      } else {
        lead.appendChild(document.createTextNode(' none have been recorded; a preview needs ' + days + ' days.'));
      }
      box.appendChild(lead);
      if (data.recording_on === false) {
        var off = document.createElement('p');
        off.className = 'muted';
        off.textContent = 'Keep a record of approval checks is off, so no new checks are recorded.';
        box.appendChild(off);
      }
      if (window.mvFormatTimes) window.mvFormatTimes(box);
    } else {
      var needed = data.actions
        ? count(data.actions, 'action', 'actions') + ' by ' + (data.agents === 1 ? '1 agent or specialist' : data.agents + ' agents and specialists')
        : 'no actions';
      lead.textContent = 'In the last ' + days + ' days, ' + needed + ' would have needed approval at this level.' +
        (data.refused ? ' ' + data.refused + ' would have been refused.' : '');
      box.appendChild(lead);
      var recorded = data.recorded || {}, basis = document.createElement('p');
      basis.className = 'muted';
      basis.textContent = 'Counted from the ' + count(data.checks, 'approval check', 'approval checks') + ' recorded in that time: ' +
        (recorded.asked || 0) + ' went to a person, ' + (recorded.allowed || 0) + ' went ahead without asking and ' +
        (recorded.refused || 0) + ' were refused. An action someone chose to always allow still goes ahead.';
      box.appendChild(basis);
    }
    var only = document.createElement('p');
    var strong = document.createElement('strong');
    strong.textContent = 'Preview only. Nothing changes until you save.';
    only.appendChild(strong);
    box.appendChild(only);
  }

  // ---- what a shorter keep period would delete -------------------------------
  // Report only, from a trial run of the clean-up (maverick.policy_preview).
  function retentionPreview(box, data) {
    var lead = document.createElement('p');
    // The server names the unit in the right number ("1 message", "3 messages").
    lead.textContent = data.days == null ? data.basis
      : 'At the next clean-up, ' + data.count + ' ' + data.unit + ' older than ' +
        count(data.days, 'day', 'days') + ' would be deleted.';
    box.appendChild(lead);
    if (data.days != null) {
      var basis = document.createElement('p'); basis.className = 'muted'; basis.textContent = data.basis;
      box.appendChild(basis);
    }
    var only = document.createElement('p'), strong = document.createElement('strong');
    strong.textContent = 'Preview only. Nothing changes until you save.';
    only.appendChild(strong); box.appendChild(only);
  }

  // ---- what saving a choice would also change -------------------------------
  async function showPreview(row, select) {
    var box = row.querySelector('[data-preview]');
    if (!box) return;
    box.textContent = '';
    if (!select.value && !select.hasAttribute('data-preview-any')) return;
    box.textContent = 'Working out what this changes…';
    try {
      var response = await window.fetch(select.getAttribute('data-preview-url') + '?value=' +
        encodeURIComponent(select.value), {cache: 'no-store', credentials: 'same-origin',
                                          headers: {Accept: 'application/json'}});
      var data = null;
      try { data = await response.json(); } catch (ignore) { data = null; }
      box.textContent = '';
      if (!response.ok || !data) {
        box.textContent = data && typeof data.message === 'string' ? data.message : errorText(response, 'work out what this changes');
        return;
      }
      if (data.kind === 'approval_checks') { approvalPreview(box, data); return; }
      if (data.kind === 'retention') { retentionPreview(box, data); return; }
      var lead = document.createElement('p');
      lead.textContent = (data.items || []).length
        ? 'Saving this also changes:' : 'Saving this changes nothing else: every setting it covers already matches.';
      box.appendChild(lead);
      if ((data.items || []).length) {
        var list = document.createElement('ul');
        data.items.forEach(function (item) {
          var li = document.createElement('li');
          li.textContent = item.label + ': ' + item.now + ' → ' + item.new + (item.lowers ? ' (lowers a protection)' : '');
          list.appendChild(li);
        });
        box.appendChild(list);
      }
      if ((data.kept || []).length) {
        var kept = document.createElement('p');
        kept.className = 'muted';
        kept.textContent = 'Left as they are (set by your server): ' + data.kept.join(', ') + '.';
        box.appendChild(kept);
      }
    } catch (failure) {
      box.textContent = errorText(failure, 'work out what this changes');
    }
  }

  // ---- module switches -----------------------------------------------------
  root.addEventListener('change', async function (event) {
    var toggle = event.target.closest('[data-module-toggle]');
    if (!toggle) return;
    var row = toggle.closest('.settings-all-row');
    var label = row.querySelector('.settings-all-label').textContent;
    var on = toggle.checked;
    if (!on) {
      var ok = await window.mvConfirm('Turn off ' + label + '? Its pages stop working until it is turned on again.', {okText: 'Turn off'});
      if (!ok) { toggle.checked = true; return; }
    }
    toggle.disabled = true;
    say(row, on ? 'Turning on…' : 'Turning off…');
    try {
      var response = await window.fetch(MODULES, {
        method: 'POST', cache: 'no-store', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', Accept: 'application/json'},
        body: JSON.stringify({section: row.dataset.module, enabled: on})
      });
      if (!response.ok) throw response;
      var data = await response.json();
      toggle.checked = data.enabled === true;
      row.querySelector('[data-value-text]').textContent = data.enabled ? 'On' : 'Off';
      say(row, data.enabled ? 'Turned on.' : 'Turned off.');
    } catch (failure) {
      toggle.checked = !on;
      say(row, errorText(failure, on ? 'turn this on' : 'turn this off'));
    } finally {
      toggle.disabled = false;
    }
  });

  // ---- a row put in the page (with the page, or loaded later) ---------------
  function prepareRow(row) {
    prepareSelectChoices(row);
    if (row.querySelector('[data-grid]')) buildGrid(row, gridState(row));
    var select = row.querySelector('[data-segment-at]');
    if (select) {
      segmentOptions(row);
      select.addEventListener('change', function () {
        select.setAttribute('data-at', select.value);
      });
    }
    remember(row);
  }

  // ---- loading a group's settings, or the settings a search finds ----------
  var ROWS = root.getAttribute('data-rows-url') || '/settings/all/rows';
  var fetched = {};
  function section(slug) {
    return Array.prototype.slice.call(root.querySelectorAll('.settings-all-group'))
      .filter(function (group) { return group.dataset.group === slug; })[0] || null;
  }
  function complete(group) { return group.dataset.loaded !== '0'; }
  function place(group, part, fragmentPart) {
    // The part's heading, rows and Save button, in the group's part order.
    var box = group.querySelector('[data-rows="' + part + '"]');
    if (box || !fragmentPart) return box;
    var holder = group.querySelector('[data-group-rows]');
    if (!holder) return null;
    var copy = document.importNode(fragmentPart, true);
    copy.querySelector('[data-rows]').textContent = '';
    var order = Number(copy.dataset.partOrder);
    var next = Array.prototype.slice.call(holder.querySelectorAll('[data-part]'))
      .filter(function (other) { return Number(other.dataset.partOrder) > order; })[0] || null;
    holder.insertBefore(copy, next);
    return copy.querySelector('[data-rows]');
  }
  function insertRows(fragment) {
    var have = {};
    rows().forEach(function (row) { have[row.dataset.settingId] = true; });
    var added = [];
    fragment.querySelectorAll('[data-fragment-group]').forEach(function (source) {
      var group = section(source.getAttribute('data-fragment-group'));
      if (!group) return;
      source.querySelectorAll('.settings-all-row[data-setting-id]').forEach(function (incoming) {
        if (have[incoming.dataset.settingId]) return;  // keep what the person is changing
        var part = incoming.dataset.subgroup || '';
        var box = place(group, part, part ? incoming.closest('[data-part]') : null);
        if (!box) return;
        var order = Number(incoming.dataset.order);
        var next = Array.prototype.slice.call(box.children)
          .filter(function (other) { return Number(other.dataset.order) > order; })[0] || null;
        var row = document.importNode(incoming, true);
        box.insertBefore(row, next);
        have[row.dataset.settingId] = true;
        added.push(row);
      });
    });
    added.forEach(prepareRow);
    var done = fragment.querySelector('[data-rows-fragment]');
    var whole = done && section(done.getAttribute('data-complete'));
    if (whole) {
      whole.dataset.loaded = '1';
      var offer = whole.querySelector('[data-group-load]');
      if (offer) offer.hidden = true;
    }
  }
  async function fetchRows(query, beforeInsert) {
    if (fetched[query]) return true;
    try {
      var response = await window.fetch(ROWS + '?' + query, {
        cache: 'no-store', credentials: 'same-origin', headers: {Accept: 'text/html'}
      });
      if (!response.ok) throw response;
      var text = await response.text();
      if (beforeInsert && !await beforeInsert()) return false;
      insertRows(new window.DOMParser().parseFromString(text, 'text/html'));
      fetched[query] = true;
      return true;
    } catch (failure) {
      announce(errorText(failure, 'load these settings'));
      return false;
    }
  }
  async function loadGroup(slug, beforeInsert) {
    var group = section(slug);
    if (!group || complete(group)) return !!group;
    var offer = group.querySelector('[data-load-group]');
    if (offer) offer.setAttribute('aria-busy', 'true');
    var ok = await fetchRows('group=' + encodeURIComponent(slug), beforeInsert);
    if (offer) offer.removeAttribute('aria-busy');
    return ok;
  }
  function incomplete() {
    return Array.prototype.slice.call(root.querySelectorAll('.settings-all-group'))
      .some(function (group) { return !complete(group); });
  }
  function filterQuery() {
    // What the filters need from the server, or '' when the page has it.
    var words = (search && search.value || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    var groupWanted = groupPick ? groupPick.value : '';
    var onlyChanged = changedOnly && changedOnly.checked;
    if (groupWanted) {
      var group = section(groupWanted);
      return group && !complete(group) ? 'group=' + encodeURIComponent(groupWanted) : '';
    }
    if (!(words.length || onlyChanged) || !incomplete()) return '';
    return 'q=' + encodeURIComponent(words.join(' ')) + (onlyChanged ? '&changed=1' : '');
  }
  function waitingFor() {
    // True while the page lacks settings the filters need.
    var query = filterQuery();
    return !!query && !fetched[query];
  }
  var pendingTimer = null;
  async function refresh() {
    var query = filterQuery();
    // Which settings are changed here moves as settings are saved: ask again.
    if (query.indexOf('changed=1') !== -1) delete fetched[query];
    updateFilter();
    if (!query) return;
    await fetchRows(query);
    updateFilter();
  }
  function refreshSoon() {
    window.clearTimeout(pendingTimer);
    updateFilter();
    if (filterQuery()) pendingTimer = window.setTimeout(refresh, 250);
  }
  root.addEventListener('click', async function (event) {
    var link = event.target.closest('[data-load-group]');
    if (!link) return;
    event.preventDefault();
    if (await loadGroup(link.getAttribute('data-load-group'))) updateFilter();
  });

  // ---- search and filters --------------------------------------------------
  var search = document.getElementById('settings-all-search');
  var groupPick = document.getElementById('settings-all-group');
  var changedOnly = document.getElementById('settings-all-changed');
  var status = document.getElementById('settings-all-filter-status');
  var empty = document.getElementById('settings-all-empty');
  window.stageCompanySigninDraft = async function (values, expectedContext, isCurrent) {
    var ids = ['issuer', 'client_id', 'audience', 'redirect_uri', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'end_session_endpoint']
      .map(function (name) { return 'auth.oidc.' + name; });
    if (!values || Object.keys(values).length !== ids.length || ids.some(function (id) {
      return typeof values[id] !== 'string' || values[id].length > 300;
    }) || !/^[a-f0-9]{64}$/.test(expectedContext || '') || root.dataset.saving === '1') return false;
    var ticket = lazySelectGeneration, controller = new AbortController();
    var deadline = setTimeout(function () { controller.abort(); }, 20000);
    async function current() {
      var response = await fetch('/api/v1/settings/sign-in-migration/context', {credentials: 'same-origin',
        cache: 'no-store', redirect: 'error', signal: controller.signal, headers: {Accept: 'application/json'}});
      if (!(response.headers.get('content-type') || '').startsWith('application/json')) return false;
      var text = await response.text(); if (text.length > 4096) return false;
      return response.ok && JSON.parse(text).context === expectedContext && ticket === lazySelectGeneration
        && (!isCurrent || isCurrent()) && root.dataset.saving !== '1';
    }
    try {
      if (!await current() || !await loadGroup('people-access', current) || !await current()) return false;
      var selectedRows = ids.map(rowById);
      if (selectedRows.some(function (row) { return !row || !row.isConnected || !editable(row)
        || changed(row) || row.dataset.control !== 'text' || row.querySelector('[data-segment-at]'); })) {
        announce('Provider fields contain entered work or are controlled by installation policy. Keep that work; review or cancel it before preparing a preset.');
        return false;
      }
      selectedRows.forEach(function (row) {
        var input = row.querySelector('[data-input]'); input.value = values[row.dataset.settingId];
        row.dataset.companySigninDefault = input.value === '' ? '1' : '0';
        input.dispatchEvent(new Event('input', {bubbles: true}));
        say(row, input.value === '' ? 'Unsaved preset: use the provider\'s published details by restoring this field to its product default. Review and save explicitly.'
          : 'Unsaved provider preset. Review and save this choice explicitly.');
      });
      if (search) search.value = ''; if (groupPick) groupPick.value = 'people-access';
      if (changedOnly) changedOnly.checked = false;
      var group = section('people-access'), part = group.querySelector('[data-subgroup-pick]');
      if (part) part.value = selectedRows[0].dataset.subgroup;
      updateFilter(); selectedRows[0].scrollIntoView({block: 'start'});
      selectedRows[0].querySelector('[data-input]').focus({preventScroll: true});
      return true;
    } catch (_) {
      announce('Current provider controls could not be checked. Your entered work was kept; reload the current controls before using a preset.');
      return false;
    } finally { clearTimeout(deadline); }
  };
  window.LightworkInstalledPracticeEnvironment = {open: async function (context) {
    if (!/^[a-f0-9]{64}$/.test(context || '') || root.dataset.saving === '1') return false;
    var ticket = lazySelectGeneration, controller = new AbortController();
    var deadline = setTimeout(function () { controller.abort(); }, 20000);
    async function currentContext() {
      var response = await fetch(API + '?q=plugins%20workbench%20image', {credentials: 'same-origin',
        cache: 'no-store', signal: controller.signal, headers: {Accept: 'application/json'}});
      var text = await response.text(); if (text.length > 160000) return false;
      var value = JSON.parse(text);
      return response.ok && value.context === context && ticket === lazySelectGeneration;
    }
    try {
      if (!await currentContext()) throw new Error('Your account or workspace changed. Reload Settings before choosing an environment.');
      var row = rowById('plugins.workbench_image');
      if (!row) {
        if (!await fetchRows('q=plugins%20workbench%20image')) return false;
        row = rowById('plugins.workbench_image');
        if (!row || !await currentContext()) return false;
      }
      if (ticket !== lazySelectGeneration || !row.isConnected) return false;
      if (search) search.value = 'plugins workbench image';
      if (groupPick) groupPick.value = '';
      if (changedOnly) changedOnly.checked = false;
      var group = row.closest('.settings-all-group'), part = group && group.querySelector('[data-subgroup-pick]');
      if (part) part.value = '';
      root.querySelectorAll('details').forEach(function (section) { section.open = section.contains(row); });
      updateFilter(); row.hidden = false;
      row.scrollIntoView({block: 'start'});
      var target = row.querySelector('[data-select-choices-load], [data-input], .settings-all-label');
      if (target) { if (!target.matches('input,select,textarea,button')) target.tabIndex = -1; target.focus({preventScroll: true}); }
      say(row, 'Choose Load installed environments to read current local choices. Review and save only the change you want.');
      return true;
    } catch (error) {
      if (ticket === lazySelectGeneration) announce(error.name === 'AbortError'
        ? 'Reading the protected setting timed out. Your drafts have been kept.' : error.message);
      return false;
    } finally { clearTimeout(deadline); }
  }};
  function updateFilter() {
    var words = (search && search.value || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    var groupWanted = groupPick ? groupPick.value : '';
    var onlyChanged = changedOnly && changedOnly.checked;
    var shown = 0;
    var waiting = waitingFor() ? 1 : 0;
    root.querySelectorAll('.settings-all-group').forEach(function (group) {
      var inGroup = !groupWanted || group.dataset.group === groupWanted;
      var partPick = group.querySelector('[data-subgroup-pick]');
      var part = partPick ? partPick.value : '';
      var visible = 0;
      var partsShown = {};
      group.querySelectorAll('.settings-all-row').forEach(function (row) {
        var text = row.dataset.search || '';
        var match = inGroup && words.every(function (w) { return text.indexOf(w) !== -1; });
        if (match && part) match = row.dataset.subgroup === part;
        if (match && onlyChanged) match = !!row.dataset.settingId && row.dataset.source === 'here';
        row.hidden = !match;
        if (match) { visible += 1; if (row.dataset.subgroup) partsShown[row.dataset.subgroup] = true; }
      });
      group.querySelectorAll('[data-subgroup-head]').forEach(function (head) {
        head.hidden = !partsShown[head.dataset.subgroupHead];
      });
      group.querySelectorAll('[data-subgroup-actions]').forEach(function (actions) {
        actions.hidden = !partsShown[actions.dataset.subgroupActions];
      });
      // A group not loaded yet stays in the list, with its "Show" button,
      // unless a search or filter is looking for something else.
      var offered = inGroup && !complete(group) && !words.length && !onlyChanged && !part;
      group.hidden = visible === 0 && !offered;
      if (offered) waiting += 1;
      shown += visible;
    });
    var filtering = words.length || groupWanted || onlyChanged;
    if (status) status.textContent = filtering && !waitingFor() ? (shown === 1 ? '1 setting shown.' : shown + ' settings shown.') : '';
    if (empty) empty.hidden = shown !== 0 || waiting !== 0;
  }
  [search, groupPick, changedOnly].forEach(function (node) {
    if (node) node.addEventListener(node === search ? 'input' : 'change', node === search ? refreshSoon : refresh);
  });
  var form = document.getElementById('settings-all-filter-form');
  if (form) {
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      window.clearTimeout(pendingTimer);
      refresh();
    });
  }
  root.querySelectorAll('[data-subgroup-pick]').forEach(function (node) {
    node.addEventListener('change', function () {
      var group = node.closest('.settings-all-group');
      if (node.value && group && !complete(group)) loadGroup(group.dataset.group).then(updateFilter);
      updateFilter();
    });
  });

  rows().forEach(prepareRow);
  if (root.dataset.served === '1') {
    // The server already put this search's matches in the page.
    var served = filterQuery();
    if (served) fetched[served] = true;
  }
  refresh();
  var focus = root.dataset.focus && rowById(root.dataset.focus);
  var hash = /^#group-([a-z0-9-]+)$/.exec(window.location.hash || '');
  if (focus && focus.scrollIntoView) {
    focus.scrollIntoView(); var target = focus.querySelector('[data-input],.settings-all-label');
    if (target) { if (!target.matches('input,select,textarea,button')) target.tabIndex = -1; target.focus({preventScroll:true}); }
  }
  else if (hash && section(hash[1])) {
    // A link to one group (e.g. "Change in All settings"): open it there.
    loadGroup(hash[1]).then(function () {
      updateFilter();
      var head = document.getElementById('group-' + hash[1]);
      if (head && head.scrollIntoView) head.scrollIntoView();
    });
  }
})();
