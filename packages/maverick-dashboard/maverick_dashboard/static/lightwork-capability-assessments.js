/* Protected current-record handoff. Native assessment decisions stay in their own form. */
(function () {
  'use strict';
  var generation = 0, pending = new Set(), hex = /^[0-9a-f]{64}$/;
  function boundary() {
    generation += 1; pending.forEach(function (request) { request.abort(); }); pending.clear();
    if (window.LightworkCapabilityAssessmentView) window.LightworkCapabilityAssessmentView.clear();
  }
  ['workspace-changed', 'account-context-changed'].forEach(function (name) {
    document.addEventListener('lightwork:' + name, boundary);
    window.addEventListener('lightwork:' + name, boundary);
  });
  window.addEventListener('lightwork:context-changed', boundary);
  function problem(message) {
    var target = document.getElementById('as-page-msg');
    if (target) { target.textContent = message; target.style.color = 'var(--danger)'; }
  }
  async function open(context, kind, subject, revision, source, review, isCurrent) {
    var view = window.LightworkCapabilityAssessmentView;
    if (window.location.pathname !== '/assessments' || !view || !hex.test(context || '') ||
        !['agent', 'flow'].includes(kind) || typeof subject !== 'string' || !subject || subject.length > 256 ||
        !Number.isSafeInteger(revision) || revision < 0 || !hex.test(source || '') || typeof review !== 'boolean') return false;
    var started = generation, original = JSON.stringify(view.selection()), controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, 30000); pending.add(controller);
    function active() { return generation === started && (!isCurrent || isCurrent()) && JSON.stringify(view.selection()) === original; }
    try {
      if (!active()) return false;
      var query = new URLSearchParams({kind: kind, subject: subject, expected_context: context,
        expected_revision: String(revision), expected_source: source, review: String(review)});
      var response = await fetch('/api/v1/capability-assessments/selection?' + query,
        {credentials: 'same-origin', cache: 'no-store', headers: {Accept: 'application/json'}, signal: controller.signal});
      if (!active()) return false;
      if (response.redirected || [401, 403].includes(response.status)) {
        boundary(); problem('Your current access does not allow this assessment. Reopen the register after checking your access.'); return false;
      }
      if (!response.ok || !/^application\/json\b/i.test(response.headers.get('Content-Type') || '')) {
        problem('The selected assessment could not be confirmed. Your current work is kept; check the register again.'); return false;
      }
      var text = await response.text(); if (!active()) return false;
      if (text.length > 524288) throw new Error('The complete assessment is too large for this handoff.');
      var value = JSON.parse(text);
      if (value.context !== context) { boundary(); problem('Your account or workspace changed. Reopen the current register.'); return false; }
      if (value.kind !== kind || value.subject !== subject || value.revision !== revision || value.source !== source ||
          !value.record || value.record.kind !== kind || value.record.subject !== subject ||
          (value.record.revision || 0) !== revision || review && value.review_allowed !== true) throw new Error('The selected assessment changed.');
      if (!active()) return false;
      return view.show(value.record, review, value.review_allowed) === true;
    } catch (_) {
      if (active()) problem('The selected assessment could not be confirmed. Your current work is kept; try again.');
      return false;
    } finally { clearTimeout(timer); pending.delete(controller); }
  }
  window.LightworkCapabilityAssessments = {open: open};
})();
