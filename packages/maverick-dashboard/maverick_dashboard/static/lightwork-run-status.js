/* One plain-language vocabulary for where a task's run stands.
 *
 * The chat page's status badge, its composer (Stop and Send) and the chat
 * list in the sidebar describe the same run, so they share these words. The
 * orchestrator writes "active" while a task works ("running"/"in_progress"
 * are older spellings), "pending" while it waits for a worker, "blocked" when
 * it pauses for a person or stops on a problem, and done/failed/cancelled
 * when it is over. The server copy of the table is run_status.py; a test
 * keeps the two in step.
 */
(function (root) {
  'use strict';
  // Stops whose cause is a broken AI connection or a fault inside Lightwork:
  // the run is over until someone fixes the cause, so it reads "Stopped".
  var STOPPED_KINDS = [
    'provider_not_ready', 'provider_authentication', 'provider_rate_limit',
    'provider_model_not_found', 'provider_unavailable', 'provider_connection',
    'provider_configuration', 'internal_error', 'unpriced_model', 'process_restart'
  ];
  var LABELS = {
    draft: 'Queued', pending: 'Queued',
    active: 'Working', running: 'Working', in_progress: 'Working',
    blocked: 'Paused',
    done: 'Done', completed: 'Done',
    failed: 'Failed', error: 'Failed',
    cancelled: 'Stopped'
  };
  // Working states: the run is queued or doing work, so Stop applies.
  var WORKING = {pending: 1, active: 1, running: 1, in_progress: 1};
  var FINISHED = {done: 1, completed: 1, failed: 1, error: 1, cancelled: 1};

  function norm(status) { return String(status || '').trim().toLowerCase(); }

  function label(status, stopKind) {
    var s = norm(status);
    if (s === 'blocked' && ['specialist_setup', 'specialist_needs_web_search', 'specialist_needs_connection'].indexOf(stopKind) >= 0) return "Can't start";
    if (s === 'blocked' && STOPPED_KINDS.indexOf(stopKind) >= 0) return 'Stopped';
    return Object.prototype.hasOwnProperty.call(LABELS, s) ? LABELS[s] : '';
  }

  // Stop is offered while the run works, and while it is paused waiting for
  // the person's answer (they may prefer to end it). A paused run with no
  // question has already stopped; a finished run has nothing to stop.
  function stoppable(status, asking) {
    var s = norm(status);
    return !!WORKING[s] || (s === 'blocked' && asking === true);
  }

  // Settled: the run is not working and will not continue by itself.
  function settled(status, asking) {
    var s = norm(status);
    return !!FINISHED[s] || (s === 'blocked' && asking !== true);
  }

  function setText(node, text) {
    if (root.LightworkI18n && typeof root.LightworkI18n.set === 'function') root.LightworkI18n.set(node, text);
    else node.textContent = text;
  }

  // The sidebar's chat list was rendered when the page loaded; keep the open
  // task's row in step with the live status instead of a stale word.
  function syncRecents(doc, goalId, status, stopKind) {
    var list = doc && doc.getElementById('cs-list');
    if (!list) return false;
    var link = list.querySelector('a[href="/chat/goal/' + String(Number(goalId)) + '"]');
    if (!link) return false;
    var text = label(status, stopKind);
    var item = link.parentNode;
    var span = item.querySelector('.cs-list__status');
    if (!text) return true;
    if (!span) {
      span = doc.createElement('span');
      span.id = 'chat-status-' + (link.getAttribute('data-conversation-root') || String(Number(goalId)));
      item.appendChild(span);
      link.setAttribute('aria-describedby', span.id);
    }
    span.className = 'cs-list__status cs-list__status--' + norm(status);
    setText(span, text);
    return true;
  }

  root.LightworkRunStatus = {
    LABELS: LABELS,
    STOPPED_KINDS: STOPPED_KINDS.slice(),
    label: label,
    stoppable: stoppable,
    settled: settled,
    syncRecents: syncRecents
  };
})(typeof window !== 'undefined' ? window : this);
