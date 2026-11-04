// Editable history preserves unfinished work and binds save receipts to the right generation.
var FDHistory = (function () {
  'use strict';
  var receipts = ['version', 'revision', 'published', 'published_version', 'published_revision'];
  var controls = [['fd-maxsec', 'max_seconds'], ['fd-maxdollars', 'max_dollars'], ['fd-schedule', 'schedule'],
    ['fd-tz', 'timezone'], ['fd-maxconc', 'max_concurrent']];

  function snapshot(context) {
    var result = JSON.parse(JSON.stringify(context.rootFlow));
    result._editorSettings = { id: context.idInput.value, name: context.nameInput.value,
      inputs: JSON.parse(JSON.stringify(context.flowInputs)) };
    controls.forEach(function (pair) {
      var field = context.document.getElementById(pair[0]);
      result._editorSettings[pair[1]] = field ? field.value : '';
    });
    var notify = context.document.getElementById('fd-notify');
    result._editorSettings.notify = !!(notify && notify.checked);
    result._editorSettings.notify_on = (context.document.getElementById('fd-notify-on') || {}).value || 'all';
    return context.recipeInputs.flowText(result);
  }

  function restore(snapshotText, rootFlow, firstSaveHistory, recipeInputs) {
    var flow = recipeInputs.parseText(snapshotText);
    var settings = flow._editorSettings || flow;
    delete flow._editorSettings;
    if (firstSaveHistory && firstSaveHistory.snapshots.indexOf(snapshotText) >= 0 &&
        !(flow.version || 0) && !flow.revision && flow.id === firstSaveHistory.sourceId) {
      flow.id = firstSaveHistory.receipt.id;
      settings.id = flow.id;
      receipts.forEach(function (key) { flow[key] = firstSaveHistory.receipt[key]; });
    }
    // A matching saved generation keeps its latest server receipts. A same-id
    // replacement or another workflow must never inherit those receipts.
    if (flow.id && flow.id === rootFlow.id && flow.revision && flow.revision === rootFlow.revision &&
        Number.isInteger(rootFlow.version) && rootFlow.version > 0) {
      receipts.forEach(function (key) { if (rootFlow[key] !== undefined) flow[key] = rootFlow[key]; });
    }
    return { flow: flow, settings: settings };
  }

  return { snapshot: snapshot, restore: restore };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDHistory;
