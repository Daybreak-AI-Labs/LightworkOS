// Convert the editor's current draft and form controls into its API representation.
var FDWire = (function () {
  'use strict';
  function toApiFlow(context) {
    var document = context.document, rootFlow = context.rootFlow;
    var idInput = context.idInput, nameInput = context.nameInput;
    var flowInputs = context.flowInputs, serializeFlow = context.serializeFlow;
    var notifyEl = document.getElementById('fd-notify');
    var out = serializeFlow({ id: (idInput.value || rootFlow.id || '').trim(),
      name: nameInput.value || rootFlow.name || 'Untitled flow', start: rootFlow.start, nodes: rootFlow.nodes,
      learned_recipe: rootFlow.learned_recipe, recipe_lineage: rootFlow.recipe_lineage,
      recipe_teaching: rootFlow.recipe_teaching, _fdEvidence: rootFlow._fdEvidence });
    out.notify = !!(notifyEl && notifyEl.checked);
    out.notify_on = (document.getElementById('fd-notify-on') || {}).value || 'all';
    out.max_seconds = parseFloat((document.getElementById('fd-maxsec') || {}).value) || 0;
    out.max_dollars = parseFloat((document.getElementById('fd-maxdollars') || {}).value) || 0;
    out.schedule = ((document.getElementById('fd-schedule') || {}).value || '').trim();
    out.timezone = ((document.getElementById('fd-tz') || {}).value || '').trim();
    out.max_concurrent = parseInt((document.getElementById('fd-maxconc') || {}).value, 10) || 0;
    out.inputs = flowInputs.filter(function (i) { return (i.key || '').trim(); });
    out.version = parseInt(rootFlow.version, 10) || 0;
    out.revision = String(rootFlow.revision || '');
    return out;
  }
  return { toApiFlow: toApiFlow };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDWire;
