/* Task-local AI choices. Ordinary submit and Copilot share native admission. */
(function () {
  'use strict';
  document.querySelectorAll('[data-task-model-controls]').forEach(function (host) {
    var form = host.closest('form'), model = host.querySelector('[name="task_model"]');
    var effort = host.querySelector('[name="task_effort"]'), context = host.querySelector('[name="task_model_context"]');
    var status = host.querySelector('[role="status"]'), refresh = host.querySelector('button');
    var generation = 0, rows = [], initial = true, choiceRevision = 0, locked = false, composerState = { asking: false, running: true };
    if (!form || !model || !effort || !context) return;
    // The expanded choices get their own row; keep the message editor usable.
    if (form.id === 'answer-form') form.style.flexWrap = 'wrap';
    function option(value, label) { var item = document.createElement('option'); item.value = value; item.textContent = label; return item; }
    function sync() {
      var old = effort.value, row = rows.find(function (item) { return item.value === model.value; });
      effort.replaceChildren(option('', 'Use the model’s usual thinking depth'));
      (row ? row.efforts : []).forEach(function (item) { effort.append(option(item.value, item.label)); });
      if (old && !Array.from(effort.options).some(function (item) { return item.value === old; })) {
        effort.append(option(old, 'Previous thinking depth — no longer available'));
        status.textContent = 'Your previous thinking depth is kept. Choose a supported option before starting.';
      }
      effort.value = old;
      effort.disabled = locked || !row || (!row.efforts.length && !old);
      if (model.value && !row) status.textContent = 'Your previous model choice is kept. Choose an available model before starting.';
      else if (model.value && !row.efforts.length) status.textContent = 'Thinking depth is not adjustable for this model. Its normal settings still apply.';
    }
    async function load() {
      var current = ++generation, previous = [model.value, effort.value], readRevision = choiceRevision; refresh.disabled = true;
      try {
        var response = await fetch('/api/v1/chat/task-model-choices', { credentials: 'same-origin', cache: 'no-store' });
        var value = await response.json();
        if (current === generation && (response.status === 401 || response.status === 403)) {
          rows = []; context.value = ''; model.replaceChildren(option('', 'Use workspace settings')); effort.replaceChildren(option('', 'Use the model’s usual thinking depth'));
          model.disabled = effort.disabled = true; status.textContent = 'Your access changed. Your message is kept; sign in with task access before choosing AI.'; return;
        }
        if (!response.ok || !value || !/^[a-f0-9]{64}$/.test(value.context) || !Array.isArray(value.models)) throw new Error(typeof value.detail === 'string' ? value.detail : 'AI choices could not be read. Your message is still here.');
        if (current !== generation) return;
        if (readRevision !== choiceRevision) previous = [model.value, effort.value];
        if (context.value && context.value !== value.context) {
          rows = []; context.value = ''; model.replaceChildren(option('', 'Use workspace settings')); effort.replaceChildren(option('', 'Use the model’s usual thinking depth'));
          model.disabled = effort.disabled = true; status.textContent = 'Your account or workspace changed. Reopen Chat before choosing a model.'; return;
        }
        rows = value.models; context.value = value.context;
        if (initial && readRevision === choiceRevision && !choiceRevision && !previous[0] && !previous[1] && value.personal_default) {
          previous = [value.personal_default.model || '', value.personal_default.effort || ''];
        }
        model.replaceChildren(option('', 'Use workspace settings'));
        rows.forEach(function (item) { model.append(option(item.value, item.label)); });
        if (previous[0] && !rows.some(function (item) { return item.value === previous[0]; })) {
          model.append(option(previous[0], 'Previous choice — no longer available')); model.value = previous[0];
          status.textContent = 'Your previous model choice is kept. Choose an available model before starting.';
        } else { model.value = previous[0]; status.textContent = value.notice; }
        model.disabled = locked;
        if (previous[1] && !Array.from(effort.options).some(function (item) { return item.value === previous[1]; })) effort.append(option(previous[1], 'Previous thinking depth — check availability'));
        effort.value = previous[1]; sync();
        if (initial) { initial = false; form.dispatchEvent(new Event('lightwork:task-model-ready')); }
      } catch (error) {
        if (current === generation) { status.textContent = error.message; if (!context.value) { model.disabled = effort.disabled = true; } }
      } finally { if (current === generation) refresh.disabled = false; }
    }
    model.addEventListener('change', function () { choiceRevision += 1; initial = false; effort.value = ''; sync(); });
    effort.addEventListener('change', function () { choiceRevision += 1; initial = false; });
    form.addEventListener('lightwork:task-model-restored', function () { choiceRevision += 1; initial = false; sync(); });
    function privateBoundary() { generation += 1; choiceRevision += 1; initial = false; rows = []; context.value = ''; model.replaceChildren(option('', 'Use workspace settings')); effort.replaceChildren(option('', 'Use the model’s usual thinking depth')); model.disabled = effort.disabled = true; status.textContent = 'Your account or workspace changed. Reopen Chat before choosing a model.'; }
    window.addEventListener('lightwork:copilot-context-changed', privateBoundary);
    document.addEventListener('lightwork:account-context-changed', privateBoundary);
    refresh.addEventListener('click', load);
    // Guidance and answers to a running question do not replace the running
    // task's AI settings. Pending tasks keep their own exact saved choice.
    function mode() {
      var chooser = document.getElementById('conversation-send-mode');
      var authoring = form.querySelector('[name="authoring_kind"]');
      locked = composerState.asking || !!(chooser && composerState.running !== false && chooser.value === 'guidance') || !!(authoring && authoring.value !== 'goal');
      model.disabled = locked || !context.value; sync();
      if (locked) status.textContent = 'This choice is for a new task. Guidance and reusable drafts keep their existing AI settings.';
    }
    var chooser = document.getElementById('conversation-send-mode'), authoring = form.querySelector('[name="authoring_kind"]');
    if (chooser) chooser.addEventListener('change', mode);
    if (authoring) authoring.addEventListener('change', mode);
    form.addEventListener('lightwork:conversation-composer-state', function (event) { composerState = event.detail || composerState; mode(); });
    form.addEventListener('submit', function (event) {
      var row = rows.find(function (item) { return item.value === model.value; });
      if (!locked && (model.value || effort.value) && (!context.value || !row || (effort.value && !row.efforts.some(function (item) { return item.value === effort.value; })))) {
        event.preventDefault(); event.stopImmediatePropagation(); status.textContent = 'Refresh AI choices and choose an available model. Your message is still here.'; host.open = true; model.focus();
      }
    }, true);
    load().then(mode);
  });
}());
