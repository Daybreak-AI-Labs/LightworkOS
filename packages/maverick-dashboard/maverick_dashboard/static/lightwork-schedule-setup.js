/* A protected handoff to the ordinary schedule form. It never submits work. */
(function (root) {
  'use strict';
  var PAGE = '/automations', serial = 0;
  function stamp(form) {
    return JSON.stringify(Array.from(form.querySelectorAll('input,select,textarea')).map(function (field) {
      return [field.id, field.name, field.value, field.checked, field.disabled];
    }));
  }
  async function openReview(descriptor, options) {
    if (!descriptor || Object.keys(descriptor).length || !options || typeof options.isCurrent !== 'function'
        || !/^[0-9a-f]{64}$/.test(options.context) || !options.isCurrent() || root.location.pathname !== PAGE) return false;
    var form = root.document.getElementById('auto-new-form'), section = root.document.getElementById('auto-new-sched');
    if (!form || !section || typeof root.mvFetchJSON !== 'function') return false;
    var turn = ++serial, before = stamp(form);
    var current = function () { return serial === turn && options.isCurrent() && root.location.pathname === PAGE
      && form.isConnected && section.isConnected && stamp(form) === before; };
    if (Array.from(root.document.querySelectorAll('dialog[open]')).some(function (dialog) { return !dialog.closest('#mv-copilot'); })) return false;
    var catalog = await root.mvFetchJSON('/api/v1/copilot/product-operations/catalog',
      {method: 'POST', cache: 'no-store', body: {page: PAGE, selection: {}}});
    if (!current() || catalog.context !== options.context || !(catalog.operations || []).some(function (entry) {
      return entry.id === 'schedules.creation_controls' && entry.available;
    })) return false;
    if (Array.from(root.document.querySelectorAll('dialog[open]')).some(function (dialog) { return !dialog.closest('#mv-copilot'); })) return false;
    var field = form.querySelector('input[name="what"]:checked');
    if (!field || field.disabled) return false;
    section.open = true; section.scrollIntoView({block: 'start'}); field.focus();
    return current() && root.document.activeElement === field;
  }
  ['lightwork:workspace-changed', 'lightwork:connection-access-lost'].forEach(function (event) {
    root.document.addEventListener(event, function () { serial++; });
  });
  root.LightworkScheduleSetup = {openReview: openReview};
})(window);
