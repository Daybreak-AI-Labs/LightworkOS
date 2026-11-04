// Graph queries shared by the friendly Steps view and the canvas editor.
var FDGraph = (function () {
  'use strict';

  function linearOrder(rootFlow, currentFlow) {
    var order = [], seen = {}, id = rootFlow.start;
    while (id && !seen[id]) {
      var node = currentFlow.nodes.find(function (candidate) { return candidate.id === id; });
      if (!node) break;
      seen[id] = 1; order.push(node); id = node.next;
    }
    rootFlow.nodes.forEach(function (node) { if (!seen[node.id]) order.push(node); });
    return order;
  }

  function reachableIds(rootFlow, core) {
    var seen = {}, unreachable = core.unreachableNodeIds(rootFlow);
    rootFlow.nodes.forEach(function (node) { if (unreachable.indexOf(node.id) < 0) seen[node.id] = true; });
    return seen;
  }

  function openEnds(rootFlow, currentFlow, core, stepName) {
    var reach = reachableIds(rootFlow, core), ends = [];
    linearOrder(rootFlow, currentFlow).forEach(function (node) {
      if (!reach[node.id]) return;
      if (node.kind === 'branch') {
        if (node.next) return;
        if (!node.if_true) ends.push({ id: node.id, port: 'if_true', label: 'If yes, after “' + stepName(node) + '”' });
        if (!node.if_false) ends.push({ id: node.id, port: 'if_false', label: 'If no, after “' + stepName(node) + '”' });
      } else if (!node.next) ends.push({ id: node.id, port: 'next', label: 'After “' + stepName(node) + '”' });
    });
    return ends;
  }

  function pathsOf(node) {
    return node.kind === 'branch'
      ? [{ label: 'Yes', to: node.if_true || node.next || null }, { label: 'No', to: node.if_false || node.next || null }] : [];
  }

  return { linearOrder: linearOrder, reachableIds: reachableIds, openEnds: openEnds, pathsOf: pathsOf };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDGraph;
