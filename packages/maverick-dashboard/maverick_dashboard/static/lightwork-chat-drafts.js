/* Recovery uses the existing encrypted, account/workspace-bound draft service.
   The page renders the recovery wrapper, a placeholder for the panel and the
   note around each composer (_composer_recovery.html). This script only fills
   them in: it never moves the composer, so a focused message box keeps focus
   and nothing around it shifts once the page has painted. */
(function () {
  'use strict';
  function showNote(note, which) {
    if (!note) return;
    note.querySelectorAll('[data-draft-note-for]').forEach(function (text) {
      if (text.getAttribute('data-draft-note-for') === which) text.removeAttribute('aria-hidden');
      else text.setAttribute('aria-hidden', 'true');
    });
  }
  function initialize() {
    if (!window.mvDraftRecovery) return;
    document.querySelectorAll('form[action="/chat/send"], #answer-form').forEach(function (form) {
      if (form.dataset.draftReady) return;
      form.dataset.draftReady = 'true';
      var fields = Array.from(form.querySelectorAll('[name="title"], [name="description"], [name="message"], [name="connection_references"], [name="task_model"], [name="task_effort"], [name="domain"]'));
      var sent = false;
      function read() {
        var value = {};
        fields.forEach(function (field) { value[field.name] = field.value; });
        return value;
      }
      // Recovery is offered only where the page rendered its wrapper.
      var host = form.closest('[data-draft-host]');
      if (host) {
        var note = host.querySelector('[data-draft-note]');
        var placeholder = host.querySelector('[data-draft-panel]');
        form.mvRecovery = window.mvDraftRecovery.create({host: host,
          compact: true, information: note,
          key: 'chat-composer:' + new URL(form.action).pathname, read: read,
          restore: function (draft) {
            fields.forEach(function (field) {
              if(field.name==="connection_references")field.value="[]";
              if (typeof draft[field.name] !== 'string') return;
              if (field.tagName === 'SELECT' && draft[field.name] && !Array.from(field.options).some(function (item) { return item.value === draft[field.name]; })) {
                var option = document.createElement('option'); option.value = draft[field.name]; option.textContent = 'Restored choice — check availability'; field.append(option);
              }
              field.value = draft[field.name];
            });
            form.dispatchEvent(new Event('lightwork:task-model-restored'));
            showNote(note, 'restored');
            sent = false;
          }});
        // The live panel starts in the placeholder's state and takes its place
        // in the same task, so the swap is never painted as a change.
        if (placeholder) {
          if (form.mvRecovery && form.mvRecovery.panel) placeholder.replaceWith(form.mvRecovery.panel);
          else placeholder.remove();
        }
      }
      window.addEventListener('beforeunload', function (event) {
        if (!sent && fields.some(function (field) { return field.name!=="connection_references" && field.value.trim(); })) {
          event.preventDefault(); event.returnValue = '';
        }
      });
      window.addEventListener('lightwork:composer-sent', function (event) {
        if (event.detail && event.detail.form === form) {
          sent = true;
          if (form.mvRecovery && !event.detail.recoveryCleared) form.mvRecovery.clear();
        }
      });
      form.addEventListener('input', function () { sent = false; });
    });
  }
  window.addEventListener('lightwork:drafts-ready', initialize);
  initialize();
})();
