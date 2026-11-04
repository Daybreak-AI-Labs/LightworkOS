// Presentation of graph nodes and execution status; no DOM or network access.
var FDPresentation = (function () {
  'use strict';
  function truncate(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  function summary(n, context) {
    var human = context.human, conditionText = context.conditionText;
    if (n.kind === 'agent') return truncate(n.brief || 'No instructions yet', 30);
    if (n.kind === 'action') return truncate(n.tool ? human(n.tool) : 'No action chosen yet', 30);
    if (n.kind === 'branch') return truncate(n.condition ? conditionText(n.condition) : 'No question yet', 30);
    if (n.kind === 'switch') return (n.cases || []).length + ' paths by ' + truncate(n.condition ? human(n.condition) : '…', 14);
    if (n.kind === 'foreach') return 'For each of ' + truncate(n.items ? human(n.items) : '…', 18);
    if (n.kind === 'while') return 'While ' + truncate(n.condition ? conditionText(n.condition) : '…', 24);
    if (n.kind === 'parallel') return (n.branches ? n.branches.length : 0) + ' paths at once';
    if (n.kind === 'approval') return truncate(n.prompt || 'No question yet', 30);
    if (n.kind === 'delay') return 'Wait ' + context.durationText(n.seconds || 0);
    if (n.kind === 'wait_event') return truncate(n.prompt || 'Waiting for another app', 30);
    if (n.kind === 'scope') return (((n.body || {}).nodes || []).length) + ' step(s) that might fail';
    if (n.kind === 'subflow') return 'Runs ' + truncate(n.flow_ref ? (context.flowNames[n.flow_ref] || human(n.flow_ref)) : 'another flow', 24);
    if (n.kind === 'setvar') return 'Saves ' + truncate(Object.keys(n.assignments || {}).map(human).join(', ') || '…', 22);
    return context.kindLabel(n.kind);
  }
  function ports(n, width) {
    if (n.kind === 'branch') return [
      { key: 'if_true', x: 50, cls: 't', label: 'Yes' },
      { key: 'if_false', x: width - 50, cls: 'f', label: 'No' }];
    return [{ key: 'next', x: width / 2, cls: '', label: '' }];
  }
  function runClass(id, cursor, state) {
    if (id === cursor) return ' run-active';
    var result = state[id]; if (!result) return '';
    if (result.outcome === 1) return ' run-ok';
    if (result.outcome === 0) return ' run-err';
    return ' run-info';
  }
  function runBadge(id, cursor, state) {
    if (id === cursor) return '⏳';
    var result = state[id]; if (!result) return '';
    if (result.outcome === 1) return '🟢';
    if (result.outcome === 0) return '🔴';
    if (result.status === 'true') return '✓';
    if (result.status === 'false') return '✗';
    return '🟠';
  }
  return { truncate: truncate, summary: summary, ports: ports, runClass: runClass, runBadge: runBadge };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDPresentation;
