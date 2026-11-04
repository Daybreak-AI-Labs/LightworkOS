(function () {
  'use strict';
  var root = document.getElementById('webhook-settings');
  if (!root) return;
  var get = function (name) { return document.getElementById('wh-' + name); };
  var current = null, busy = false, context = '';
  var labels = {
    none: 'No signing secret is active.', dashboard: 'Managed here in Lightwork.',
    config: 'A saved installation setting is active. You can replace it here.',
    external_secret: "Managed by your installation's secret service or startup settings.",
    operator: "Managed by your installation's deployment settings.",
    tenant: "Managed by this workspace's deployment settings."
  };
  function valid(value) {
    return value && value.schema === 1 && Object.hasOwn(labels, value.source) &&
      ['configured', 'outbound_configured', 'storage_writable', 'can_set', 'can_remove', 'app_copy_present', 'remove_keeps_configured', 'remove_keeps_outbound_configured'].every(function (key) { return typeof value[key] === 'boolean'; }) &&
      typeof value.context === 'string' && /^[a-f0-9]{64}$/.test(value.context) &&
      value.can_set === (value.storage_writable && ['none', 'dashboard', 'config'].includes(value.source)) &&
      value.can_remove === (value.storage_writable && value.app_copy_present) &&
      typeof value.expected_generation === 'string' && value.expected_generation.startsWith('MVKAR1:') && value.expected_generation.length <= 4096;
  }
  function say(text, focus) { window.mvStatus(get('state'), text); if (focus) get('state').focus(); }
  function controls() {
    var remove = get('action').value === 'remove';
    var permitted = current && (remove ? current.can_remove : current.can_set);
    get('refresh').disabled = busy;
    get('action').disabled = busy || !current || (!current.can_set && !current.can_remove);
    get('secret').disabled = busy || !permitted || remove;
    get('confirm').disabled = busy || !permitted;
    get('save').disabled = busy || !permitted || !get('confirm').checked || (!remove && !get('secret').value.trim());
    get('cancel').disabled = busy;
    get('secret-field').hidden = remove;
    get('help').hidden = remove;
    get('consequence').textContent = remove ? ((current && current.remove_keeps_configured ?
      'Removing this saved copy leaves the installation’s existing secret active. It does not turn off incoming requests. ' :
      'Removing this saved copy stops incoming requests. ') + (current && current.remove_keeps_outbound_configured ?
      'Outgoing notifications will still be signed using the installation’s existing setting.' : 'Outgoing workflow notifications will no longer be signed.')) :
      'Saving replaces the active signing secret. Other systems using the old secret will need the new one.';
  }
  function display(value) {
    if (!valid(value)) throw new Error('invalid status');
    var changed = Boolean(context && context !== value.context);
    if (changed) { get('secret').value = ''; get('confirm').checked = false; }
    context = value.context;
    current = value;
    get('ownership').textContent = labels[value.source];
    get('external').hidden = value.can_set;
    get('external').textContent = value.storage_writable ?
      'Your installation administrator must arrange any transfer of control from the external secret service or deployment settings. Lightwork cannot make that transfer here. Refresh status after the administrator completes it.' :
      'This installation uses a linked location for app settings. Lightwork cannot safely replace that link here. Contact your installation administrator before changing this secret.';
    get('action').querySelector('[value="set"]').disabled = !value.can_set;
    get('action').querySelector('[value="remove"]').disabled = !value.can_remove;
    if (!value.can_set && value.can_remove) get('action').value = 'remove';
    else if (!value.can_remove) get('action').value = 'set';
    say(changed ? 'Your account or workspace changed. The previous entry was cleared. Review the current settings before making a change.' :
      (value.configured ? 'An active signing secret is configured for incoming requests. ' : 'A signing secret is not set. Incoming requests are blocked. ') +
      (value.outbound_configured ? 'Outgoing notifications are signed.' : 'Outgoing notifications are not signed.'));
    return changed;
  }
  function denied() {
    current = null; get('secret').value = ''; get('confirm').checked = false;
    get('ownership').textContent = ''; get('external').hidden = true;
    say('Your administrator access changed. Sign in with an installation administrator account and refresh status.', true);
  }
  async function read() {
    var lost = false, data;
    try { data = await window.mvFetchJSON('/settings/webhooks', {cache: 'no-store', onAccess: function () { lost = true; denied(); }}, 'check the webhook secret'); }
    catch (error) { if (lost) return false; throw error; }
    return display(data) ? 'context' : 'ok';
  }
  async function refresh(focus) {
    if (busy) return;
    busy = true; get('confirm').checked = false; controls();
    try { await read(); }
    catch (_) { current = null; say('The active secret could not be checked. Your entry is still here. Refresh status before making a change.'); }
    finally { busy = false; controls(); if (focus && document.activeElement !== get('state')) get('refresh').focus(); }
  }
  get('refresh').addEventListener('click', function () { refresh(true); });
  get('cancel').addEventListener('click', function () {
    if (busy) return;
    get('secret').value = ''; get('confirm').checked = false; controls();
    say('The entry was cleared. No change was sent.'); get('refresh').focus();
  });
  get('action').addEventListener('change', function () { get('confirm').checked = false; controls(); });
  get('secret').addEventListener('input', function () { get('confirm').checked = false; controls(); });
  get('confirm').addEventListener('change', controls);
  get('form').addEventListener('submit', async function (event) {
    event.preventDefault();
    if (busy || get('save').disabled || !current) return;
    var action = get('action').value;
    var body = new URLSearchParams({ action: action, secret: action === 'set' ? get('secret').value : '', expected_generation: current.expected_generation });
    busy = true; get('confirm').checked = false; controls();
    var followup = '';
    try {
      var response = await fetch('/settings/webhooks', { method: 'POST', credentials: 'same-origin', body: body });
      if (response.status === 401 || response.status === 403) { denied(); return; }
      if (!response.ok) {
        followup = response.status === 409 ? 'The settings changed. This change was not confirmed. Check the current status and confirm again.' :
          response.status === 400 ? 'Check the new secret. It cannot be blank or a saved secret reference. Review it before trying again.' :
          'The change was not confirmed. Check the current status before deciding whether to try again.';
        throw new Error('unconfirmed');
      }
      var result = await response.json();
      if (!valid(result) || result.result !== (action === 'set' ? 'active' : 'app_copy_removed') ||
          (action === 'set' && (!result.configured || !result.outbound_configured || result.source !== 'dashboard')) ||
          (action === 'remove' && result.app_copy_present)) throw new Error('unconfirmed');
      if (display(result)) { get('state').focus(); return; }
      get('secret').value = '';
      say(action === 'set' ? 'The new signing secret is active. Update the other systems that use it. No outside system was contacted.' :
        'The app’s saved copy was removed. ' + (result.configured ? 'The installation’s existing secret remains active for incoming requests. ' :
          'Incoming requests are now blocked. ') + (result.outbound_configured ? 'Outgoing notifications remain signed.' : 'Outgoing notifications are no longer signed.'), true);
    } catch (_) {
      current = null;
      followup = followup || 'The result is uncertain. Your entry is still here. No change will be sent again automatically.';
      try { if (await read() === 'ok') say(followup + ' Current status has been refreshed.', true); }
      catch (_) { say(followup + ' Refresh status when the connection is available.', true); }
    } finally { busy = false; controls(); window.dispatchEvent(new CustomEvent('lightwork:product-state-changed')); }
  });
  controls(); refresh(false);
})();
