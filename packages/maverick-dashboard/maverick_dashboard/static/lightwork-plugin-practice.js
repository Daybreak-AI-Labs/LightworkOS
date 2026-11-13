/* Ordinary practice forms use exact contracts captured in the restricted image. */
(function () {
  'use strict';
  var owners = new Map(), generation = 0;
  function node(tag, text, parent) { var el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (parent) parent.append(el); return el; }
  function button(text, parent, run) { var el = node('button', text, parent); el.type = 'button'; el.className = 'btn'; el.addEventListener('click', run); return el; }
  function key(context, fingerprint) { return 'lightwork-plugin-practice:' + context + ':' + fingerprint; }
  function remembered(context, fingerprint) { try { return JSON.parse(sessionStorage.getItem(key(context, fingerprint)) || 'null'); } catch (_) { return null; } }
  function remember(context, fingerprint, value) {
    sessionStorage.setItem(key(context, fingerprint), JSON.stringify(value));
    var keys = Object.keys(sessionStorage).filter(function (name) { return name.startsWith('lightwork-plugin-practice:'); });
    keys.slice(0, Math.max(0, keys.length - 20)).forEach(function (name) { if (name !== key(context, fingerprint)) sessionStorage.removeItem(name); });
  }
  async function call(path, body) {
    var F = 'These practice controls could not be confirmed. Your answers are kept.';
    return window.mvFetchJSON('/api/v1/plugins/practice' + path, {method: body ? 'POST' : 'GET', cache: 'no-store', body: body || undefined, timeout: 55000,
      serverDetail: F, messages: {timeout: F, offline: F, unreadable: F}}, 'check the practice');
  }
  async function checkResult(operation) {
    var F = 'The saved check could not be read.';
    var value = await window.mvFetchJSON('/api/v1/plugins/workbench', {cache: 'no-store', serverDetail: F, messages: {offline: F, unreadable: F}}, 'read the saved check');
    return (value.checks || []).find(function (item) { return item.id === operation; });
  }
  function mount(host, plugin, context) {
    var savedGeneration = generation, busy = false, descriptor = null, selected = null, draft = null, answer = null;
    var status = node('p', 'Reading the current practice controls.', host); status.setAttribute('role', 'status');
    var controls = node('div', undefined, host), fields = node('div', undefined, host);
    function current() { return generation === savedGeneration && host.isConnected; }
    function state(row) {
      descriptor = row; controls.replaceChildren(); fields.replaceChildren(); status.textContent = row.notice;
      if (row.state === 'ready') { renderForm(); return; }
      if (row.state === 'unconfirmed') { button('Check original inspection', controls, recoverInspection); return; }
      button(row.state === 'not_read' ? 'Read practice questions' : 'Read practice questions again', controls, inspectQuestions);
    }
    async function recoverInspection() {
      if (busy || !current()) return false;
      var original = remembered(context, plugin.fingerprint); if (!original || !original.inspection) { status.textContent = 'Choose a reviewed question inspection first.'; return false; }
      busy = true;
      try { var row = await call('/inspection/' + encodeURIComponent(original.inspection)); if (!current()) return false; state(row); return row.state === 'ready'; }
      catch (error) { if (current()) status.textContent = error.message; return false; }
      finally { busy = false; }
    }
    async function inspectQuestions() {
      if (busy || !current()) return;
      if (!await mvConfirm('Read the practice questions for ' + plugin.name + ' / ' + plugin.version + ' once in the reviewed restricted image? No tool action runs, no image downloads, and network, credentials and host writes remain unavailable.', {okText: 'Read these questions'})) return;
      if (!current()) return;
      var operation = (window.mvNewId ? window.mvNewId() : crypto.randomUUID()).replace(/-/g, '');
      try { remember(context, plugin.fingerprint, {inspection: operation}); }
      catch (_) { status.textContent = 'The original request could not be saved in this browser. Nothing was submitted. Allow site storage before continuing.'; return; }
      busy = true; controls.querySelectorAll('button').forEach(function (el) { el.disabled = true; });
      try { var row = await call('/inspect', {context: context, fingerprint: plugin.fingerprint, operation_id: operation, confirm: true}); if (current()) state(row); }
      catch (error) { if (current()) { controls.replaceChildren(); button('Check original inspection', controls, recoverInspection); status.textContent = error.name === 'AbortError' ? 'The original inspection reply is unconfirmed. Check its saved outcome before another request.' : error.message; } }
      finally { busy = false; }
    }
    function renderForm() {
      var editor = window.FDActionFields;
      if (!editor || !Array.isArray(descriptor.contracts) || !descriptor.contracts.length) { status.textContent = 'The guided practice form is unavailable. No check has started.'; return; }
      var title = node('h4', 'Complete a practice check', fields); title.tabIndex = -1;
      node('p', 'Use fictional information only. These checks cannot accept credentials or private customer data.', fields);
      var label = node('label', 'Practice action', fields), choice = node('select', undefined, label); choice.className = 'input';
      descriptor.contracts.forEach(function (item, index) { var option = node('option', item.label, choice); option.value = String(index); });
      var questionHost = node('div', undefined, fields), expectedHost = node('div', undefined, fields);
      var modeLabel = node('label', 'What to check', fields), mode = node('select', undefined, modeLabel); mode.className = 'input';
      [['sample', 'Compare the practice answer'], ['timeout', 'Check whether a deliberately slow practice stops on time'], ['cancellation', 'Check whether a deliberately slow practice stops when cancelled']].forEach(function (item) { var option = node('option', item[1], mode); option.value = item[0]; });
      var messages = node('p', undefined, fields); messages.setAttribute('role', 'status');
      var resultStatus = node('p', undefined, fields); resultStatus.setAttribute('role', 'status');
      var resultObservation = node('p', undefined, fields);
      var check = button('Review practice check', fields, async function () {
        if (busy || !current()) return;
        if (!valid()) { messages.textContent = 'Complete the highlighted answers before reviewing this check.'; return; }
        var original = remembered(context, plugin.fingerprint);
        if (original && original.check) { messages.textContent = 'Read the original saved check before starting another one.'; return; }
        var reviewed = {context: context, fingerprint: plugin.fingerprint, operation_id: (window.mvNewId ? window.mvNewId() : crypto.randomUUID()).replace(/-/g, ''), confirm: true,
                        contract: descriptor.receipt, contract_revision: descriptor.revision, tool: selected.name, sample: JSON.parse(JSON.stringify(draft.params)), expected: JSON.parse(JSON.stringify(answer.params.answer)), mode: mode.value};
        fields.querySelectorAll('section.panel').forEach(function (previous) { previous.remove(); });
        var review = node('section', undefined, fields); review.className = 'panel'; node('h4', 'Review this exact practice check', review);
        node('p', plugin.name + ' / ' + plugin.version + ' / ' + selected.label, review); node('p', mode.selectedOptions[0].textContent, review);
        function show(value, parent, depth) {
          if (depth > 10) throw new Error('Use fewer nested practice details.');
          if (value !== null && typeof value === 'object') { var list = node('dl', undefined, parent); Object.entries(value).forEach(function (entry) { node('dt', Array.isArray(value) ? 'Item ' + (Number(entry[0]) + 1) : entry[0].replace(/[_-]/g, ' '), list); var result = node('dd', undefined, list); show(entry[1], result, depth + 1); }); }
          else { var text = node('span', value === null ? 'No value' : typeof value === 'boolean' ? value ? 'Yes' : 'No' : String(value), parent); text.style.whiteSpace = 'pre-wrap'; text.style.overflowWrap = 'anywhere'; }
        }
        node('h5', 'Every practice answer', review); show(reviewed.sample, review, 0); node('h5', 'Exact expected answer', review); show(reviewed.expected, review, 0);
        var consentLabel = node('label', undefined, review), consent = node('input', undefined, consentLabel); consent.type = 'checkbox'; consentLabel.append(document.createTextNode(' I reviewed these answers and want to run this restricted check once.'));
        var submit = button('Run reviewed practice check', review, async function () {
          if (busy || !current() || !consent.checked) return;
          try { remember(context, plugin.fingerprint, {inspection: descriptor.receipt, check: reviewed.operation_id}); }
          catch (_) { messages.textContent = 'The original request could not be saved. Nothing was submitted.'; return; }
          busy = true; submit.disabled = true; check.disabled = true; resultStatus.textContent = 'Running this reviewed practice check once.'; resultObservation.textContent = '';
          try { var result = await call('/check', reviewed); if (current()) renderResult(result); }
          catch (error) { if (current()) { review.replaceChildren(); resultStatus.textContent = 'The original reply is unconfirmed. Check the saved result; no automatic retry will run.'; messages.textContent = error.name === 'AbortError' ? '' : error.message; button('Check original practice result', review, recoverCheck); } }
          finally { busy = false; if (current()) valid(); }
        }); submit.disabled = true; consent.addEventListener('change', function () { submit.disabled = busy || !consent.checked; });
        button('Cancel this review', review, function () { if (!busy) review.remove(); }); review.scrollIntoView({block: 'nearest'}); consent.focus();
      });
      function valid() {
        if (!selected || !draft || !answer || !draft._practicePlan) return false;
        var problem = Object.values(draft._actionErrors || {})[0] || Object.values(answer._actionErrors || {})[0] ||
            editor.issue(draft._practicePlan, draft.params, 'Practice answers') || editor.issue(answer._practicePlan, answer.params, 'Expected answer');
        function count(value) { var stack = [value], total = 0; while (stack.length) { var item = stack.pop(); if (++total > 1024) return total; if (item !== null && typeof item === 'object') Object.values(item).forEach(function (child) { stack.push(child); }); } return total; }
        try { if (count(draft.params) > 1024 || count(answer.params.answer) > 1024 || new TextEncoder().encode(JSON.stringify(draft.params)).length > 16000 || new TextEncoder().encode(JSON.stringify(answer.params.answer)).length > 16384) problem = 'Use fewer practice details.'; }
        catch (_) { problem = 'Check the practice answers.'; }
        var original = remembered(context, plugin.fingerprint);
        messages.textContent = problem || ''; check.disabled = busy || !!problem || !!(original && original.check); return !problem;
      }
      function choose() {
        selected = descriptor.contracts[Number(choice.value)]; questionHost.replaceChildren(); expectedHost.replaceChildren();
        try {
          var plan = editor.compile(selected.schema), expected = editor.compile({type: 'object', properties: {answer: {title: 'Expected answer'}}, required: ['answer'], additionalProperties: false});
          draft = {tool: plugin.fingerprint + ':' + selected.name, params: {}, _practicePlan: plan}; answer = {tool: plugin.fingerprint + ':answer', params: {answer: ''}, _practicePlan: expected};
          editor.mount(questionHost, draft, {plan: plan}, valid); editor.mount(expectedHost, answer, {plan: expected}, valid); valid();
        } catch (error) { draft = null; answer = null; check.disabled = true; messages.textContent = error.message + ' This plugin is not ready for an ordinary practice form; no check was started.'; }
      }
      choice.addEventListener('change', choose); choose();
      var original = remembered(context, plugin.fingerprint); if (original && original.check) { check.disabled = true; button('Check original practice result', fields, recoverCheck); }
      async function recoverCheck() { if (busy || !current()) return; busy = true; try { var saved = remembered(context, plugin.fingerprint), result = saved && saved.check && await checkResult(saved.check); if (current()) { if (result) renderResult(result); else resultStatus.textContent = 'No saved result is currently available. Do not submit the original request again automatically.'; } } catch (error) { if (current()) messages.textContent = error.message; } finally { busy = false; if (current()) valid(); } }
      function renderResult(result) {
        var done = ['passed_scoped_check', 'not_qualified'].includes(result.state);
        resultStatus.textContent = result.state === 'passed_scoped_check' ? 'This restricted practice check passed. External service acceptance remains separate.' : result.state === 'not_qualified' ? 'This check did not establish readiness. Review its saved observations.' : 'The original check is still unconfirmed. No action was repeated.';
        fields.querySelectorAll('section.panel').forEach(function (review) { review.remove(); });
        resultObservation.textContent = result.check_observation || result.reason || 'Check the original saved outcome.';
        if (done) { remember(context, plugin.fingerprint, {inspection: descriptor.receipt}); check.disabled = false; valid(); }
        else { check.disabled = true; button('Check original practice result', fields, recoverCheck); }
      }
    }
    async function load(receipt) {
      if (busy || !current()) return false;
      busy = true;
      try {
        var original = remembered(context, plugin.fingerprint);
        var row = await call(receipt || original && original.inspection ? '/inspection/' + encodeURIComponent(receipt || original.inspection) : '/version/' + encodeURIComponent(plugin.fingerprint));
        if (!current()) return false;
        if (row.receipt) remember(context, plugin.fingerprint, {inspection: row.receipt, ...(original && original.check ? {check: original.check} : {})});
        state(row); return row.state === 'ready';
      } catch (error) { if (current()) status.textContent = error.message; return false; }
      finally { busy = false; }
    }
    owners.set(plugin.fingerprint, {context: context, host: host, load: load}); queueMicrotask(function () { load(); });
  }
  document.addEventListener('lightwork:workspace-changed', function () { generation++; owners.clear(); });
  window.LightworkPluginPractice = {mount: mount, open: async function (fingerprint, receipt) {
    if (location.pathname !== '/plugins' || !/^[a-f0-9]{64}$/.test(fingerprint) || !/^[a-f0-9]{32}$/.test(receipt)) return false;
    var target = owners.get(fingerprint); if (!target || !target.host.isConnected) return false;
    if (!await target.load(receipt)) return false;
    target.host.scrollIntoView({block: 'start'}); var heading = target.host.querySelector('h4'); if (heading) heading.focus(); return true;
  }};
}());
