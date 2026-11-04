// Work with an independent copy of the user's editable draft. Save receipts
// are intentionally excluded while unfinished nested edits remain recoverable.
var FDDraft = (function () {
  'use strict';

  function editableFlow(flow, validActionDetails) {
    var editable = JSON.parse(JSON.stringify(flow));
    (function removeEmptyActionBuffers(graph) {
      (Array.isArray(graph.nodes) ? graph.nodes : Object.values(graph.nodes || {})).forEach(function (node) {
        ['_actionRaw', '_actionErrors', '_actionKinds'].forEach(function (key) {
          if (node[key] && !Object.keys(node[key]).length) delete node[key];
        });
        if (!node._actionRaw && !node._actionErrors && validActionDetails(node)) delete node._actionKinds;
        if (!node._actionRaw && !node._actionErrors && !node._actionKinds) delete node._actionTool;
        if (node.body) removeEmptyActionBuffers(node.body);
        (node.branches || []).forEach(removeEmptyActionBuffers);
      });
    }(editable));
    if (editable._fdEvidence == null) delete editable._fdEvidence;
    ['version', 'revision', 'published', 'published_version', 'published_revision'].forEach(function (key) {
      delete editable[key];
    });
    return editable;
  }

  return { editableFlow: editableFlow };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDDraft;
