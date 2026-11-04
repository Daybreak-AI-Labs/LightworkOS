// Recheck task authority before a mutable action; the service checks it again.
(function () {
  'use strict';
  var root = document.getElementById('task-authority');
  if (!root) return;
  var allowed = root.dataset.operate === '1', checking = null, reason = '';
  var selector = '#answer-send,#cancel-btn,#edit-toggle,#edit-save,#feedback-up,#feedback-down,#share-create,#share-confirm,.share-revoke,#signoff-approve,#signoff-reject,#attach-add-btn,#reply-attach,#reply-files,#halt-resume,#halt-resume-budget,#ps-run,#ps-passes,#answer-mic,#attach-add,#goal-project-sel,#goal-project-save,#recover-submission-btn';
  var restoring = new WeakMap(), passed = new WeakSet();
  function project() {
    document.querySelectorAll(selector).forEach(function (node) {
      if (node.dataset.permissionDisabled === '1') { restoring.set(node, false); delete node.dataset.permissionDisabled; }
      if (!allowed && !node.disabled) { restoring.set(node, false); node.disabled = true; }
      else if (allowed && restoring.has(node)) { node.disabled = restoring.get(node); restoring.delete(node); }
    });
    var text = allowed ? '' : (reason || 'This task is read-only, or your current permission could not be confirmed. Your draft has been kept.');
    if (root.textContent !== text) root.textContent = text;
  }
  async function refresh() {
    if (checking) return checking;
    checking = (async function () {
      try {
        var body = await window.mvFetchJSON('/api/v1/chat/goal/' + root.dataset.goal + '/permissions', {cache: 'no-store'}).catch(function () { return null; });
        allowed = !!(body && body.can_operate === true);
        reason = body && typeof body.reason === "string" ? body.reason : "";
      } catch (_) { allowed = false; reason = ""; }
      project(); return allowed;
    })();
    try { return await checking; } finally { checking = null; }
  }
  document.addEventListener('click', async function (event) {
    var button = event.target.closest(selector);
    if (!button || button.tagName === 'SELECT') return;
    if (passed.has(button)) { passed.delete(button); return; }
    event.preventDefault(); event.stopImmediatePropagation();
    if (await refresh()) { passed.add(button); button.click(); }
  }, true);
  document.addEventListener('submit', async function (event) {
    var form = event.target;
    if (!form.matches('#answer-form,#halt-resume-form,.goal-project,form[action$="/recover-submission"]')) return;
    if (passed.has(form)) { passed.delete(form); return; }
    event.preventDefault(); event.stopImmediatePropagation();
    if (await refresh()) { passed.add(form); form.requestSubmit(); }
  }, true);
  new MutationObserver(project).observe(document.body, {subtree: true, childList: true, attributes: true, attributeFilter: ['disabled']});
  document.addEventListener('visibilitychange', function () { if (!document.hidden) refresh(); });
  window.addEventListener('focus', refresh);
  project();
}());
