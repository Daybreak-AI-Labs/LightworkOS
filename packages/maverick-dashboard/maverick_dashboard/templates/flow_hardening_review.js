/* Review one grounded flow rewrite through the same native versioned apply API. */
(function () {
  'use strict';
  var busy = {};
  var replacementDrafts = {}, contextGeneration = 0, activeReplacement = null;
  function clearPrivate(event) {
    if (event && event.detail && event.detail.reason === 'selection') return;
    contextGeneration++; replacementDrafts = {};
    if (activeReplacement) activeReplacement();
  }
  ['lightwork:account-context-changed', 'lightwork:workspace-changed', 'lightwork:copilot-context-changed'].forEach(function (name) {
    document.addEventListener(name, clearPrivate);
  });
  window.addEventListener('lightwork:context-changed', clearPrivate);
  function human(value) { return String(value || '').replace(/[_-]/g, ' '); }
  async function read(url, options) {
    var writing = options && options.method === 'POST';
    try { return await window.mvFetchJSON(url, Object.assign({cache: 'no-store', plainDetail: true, onAccess: clearPrivate}, options || {}), writing ? 'save the flow' : 'check the current flow'); }
    catch (error) {
      if (!error.status || (writing && error.status >= 500)) throw new Error(writing
        ? 'The save result could not be confirmed. Check the flow’s version history before trying again.'
        : 'The current flow could not be checked. Refresh and try again.');
      throw error;
    }
  }
  function replacementForm(current) {
    var key = current.flow_id + ':' + current.node_id, opener = document.activeElement;
    var dialog = document.createElement('dialog'); dialog.className = 'mv-confirm mv-form';
    dialog.style.maxWidth = '44rem'; dialog.style.maxHeight = '85vh'; dialog.style.overflowY = 'auto';
    dialog.setAttribute('aria-labelledby', 'flow-replacement-title');
    var form = document.createElement('form'); form.className = 'mv-confirm__body'; dialog.appendChild(form);
    function text(tag, value, parent) { var element = document.createElement(tag); element.textContent = value;
      element.style.whiteSpace = 'pre-wrap'; element.style.overflowWrap = 'anywhere'; (parent || form).appendChild(element); return element; }
    text('h2', 'Review replacement instructions').id = 'flow-replacement-title';
    text('p', 'Replace “' + current.node_label + '” with an AI task. Its fixed action inputs will no longer run.');
    var fields = document.createElement('dl'); form.appendChild(fields);
    current.current_action.forEach(function (row) { text('dt', row.label, fields);
      text('dd', row.value === '***redacted***' ? 'Credential value hidden' : row.value, fields); });
    current.replacement_consequences.forEach(function (value) { text('p', value); });
    var label = text('label', 'Complete replacement instructions'); label.htmlFor = 'flow-replacement-instructions';
    var instructions = document.createElement('textarea'); instructions.id = label.htmlFor; instructions.className = 'input';
    instructions.rows = 7; instructions.maxLength = 4000; instructions.required = true; instructions.style.width = '100%';
    instructions.value = replacementDrafts[key] || ''; form.appendChild(instructions);
    var consentLabel = document.createElement('label'); consentLabel.className = 'mv-form__check';
    var consent = document.createElement('input'); consent.type = 'checkbox'; consentLabel.appendChild(consent);
    consentLabel.appendChild(document.createTextNode('I reviewed every current action input and these replacement instructions.'));
    form.appendChild(consentLabel);
    var actions = document.createElement('div'); actions.className = 'mv-confirm__row'; form.appendChild(actions);
    var cancel = text('button', 'Cancel', actions); cancel.type = 'button'; cancel.className = 'btn btn--ghost';
    var accept = text('button', 'Review complete change', actions); accept.type = 'submit'; accept.className = 'btn btn--primary';
    function sync() { replacementDrafts[key] = instructions.value; accept.disabled = !consent.checked || !instructions.value.trim(); }
    instructions.addEventListener('input', function () { consent.checked = false; sync(); }); consent.addEventListener('change', sync); sync();
    return new Promise(function (resolve) {
      function finish(value) { if (activeReplacement === stop) activeReplacement = null;
        dialog.close(); dialog.remove(); if (opener && opener.isConnected) opener.focus(); resolve(value); }
      function stop() { finish(null); }
      activeReplacement = stop;
      cancel.addEventListener('click', stop); dialog.addEventListener('cancel', function (event) { event.preventDefault(); stop(); });
      form.addEventListener('submit', function (event) { event.preventDefault(); if (accept.disabled) return;
        finish({brief: instructions.value, replacement_reviewed: true, review_binding: current.review_binding,
          review_context: current.review_context}); });
      document.body.appendChild(dialog); dialog.showModal(); instructions.focus();
    });
  }
  async function prepare(flowId, proposal, preferredTool, expectedReview) {
    var key = flowId + ':' + proposal.node_id;
    if (busy[key]) return null;
    busy[key] = true;
    var generation = contextGeneration;
    try {
      var path = '/api/v1/flows/' + encodeURIComponent(flowId);
      var reviewPath = path + '/apply-review?node_id=' + encodeURIComponent(proposal.node_id);
      var current = await read(reviewPath);
      if (generation !== contextGeneration) throw new Error('The account or workspace changed. Reopen the current workflow.');
      if (!current || current.to_kind !== proposal.to_kind || !current.version || !current.revision) {
        throw new Error('This suggestion changed. Refresh the flow before reviewing it.');
      }
      if (expectedReview && (current.review_binding !== expectedReview.binding || current.review_context !== expectedReview.context)) {
        throw new Error('The workflow or account changed after Copilot checked it. Your work was kept; review the current suggestion again.');
      }
      var body = {node_id: current.node_id, to_kind: current.to_kind,
        version: current.version, revision: current.revision};
      if (current.to_kind === 'action') {
        var names = [];
        var list = await read('/api/v1/flows/tools');
        (list.tools || []).forEach(function (item) { if (item && item.name && names.indexOf(item.name) < 0) names.push(item.name); });
        if (preferredTool && names.indexOf(preferredTool) < 0) names.unshift(preferredTool);
        if (current.tool && current.inferred_tool && names.indexOf(current.inferred_tool) < 0)
          names.unshift(current.inferred_tool);
        if (!names.length) throw new Error('No actions are available. Check your connections and try again.');
        var selected = await window.mvForm('Review the action for ' + human(current.node_label), [{
          key: 'tool', label: 'Action to run for this step', type: 'select', required: true,
          default: preferredTool || current.tool || '',
          options: [{value: '', label: 'Choose an action'}].concat(names.map(function (name) {
            return {value: name, label: human(name)};
          })),
          help: 'The suggested action name comes from past runs. Review its inputs below before changing the flow.'
        }], {okText: 'Review inputs'});
        if (selected === null) return null;
        var tool = selected.tool;
        current = await read(reviewPath + '&tool=' + encodeURIComponent(tool));
        if (current.version !== body.version || current.revision !== body.revision || current.tool !== tool) {
          throw new Error('The flow or action changed during review. Refresh and try again.');
        }
        body.tool = tool; body.params = {};
        var fields = current.fields || [];
        if (fields.length) {
          var sourceOptions = (current.sources || []).filter(function (source) {
            return source && /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(source.key);
          }).map(function (source) {
            return {value: 'source:' + source.key, label: 'Use ' + source.label +
              (source.origin === 'input' ? ' from the start form' : ' from an earlier step')};
          });
          var choices = fields.map(function (field) {
            var options = [{value: '', label: field.required ? 'Choose a value' : 'Leave blank'}];
            if (field.type === 'string') options = options.concat(sourceOptions);
            options.push({value: 'fixed', label: 'Use one fixed value for every run'});
            return {key: field.name, label: field.label, type: 'select', required: field.required,
              options: options, help: field.description || 'Choose where this action gets its value.'};
          });
          var bindings = await window.mvForm('Choose the action inputs', choices, {okText: 'Use these inputs'});
          if (bindings === null) return null;
          var fixedFields = [];
          fields.forEach(function (field) {
            var chosen = bindings[field.name] || '';
            if (chosen.startsWith('source:')) {
              var sourceKey = chosen.slice(7);
              if (!sourceOptions.some(function (option) { return option.value === chosen; })) {
                throw new Error('An input source changed. Refresh and review the action again.');
              }
              body.params[field.name] = '{' + '{' + sourceKey + '}' + '}';
            } else if (chosen === 'fixed') {
              fixedFields.push({key: field.name, label: field.label + ' (same every run)',
                type: field.type === 'boolean' ? 'bool' :
                  (field.type === 'number' || field.type === 'integer' ? 'number' : 'text'),
                required: field.required, help: field.description || ''});
            } else if (field.required) {
              throw new Error('Choose a value for ' + field.label + '.');
            }
          });
          if (fixedFields.length) {
            var fixed = await window.mvForm('Set fixed action values', fixedFields, {okText: 'Review change'});
            if (fixed === null) return null;
            fixedFields.forEach(function (field) {
              var raw = fixed[field.key];
              if (raw === undefined || raw === '') return;
              if (field.type === 'number') {
                var number = Number(raw);
                if (!Number.isFinite(number) ||
                    (fields.find(function (item) { return item.name === field.key; }).type === 'integer' && !Number.isInteger(number)))
                  throw new Error('Enter a whole or decimal number as requested for ' + field.label + '.');
                body.params[field.key] = number;
              } else {
                if (typeof raw === 'string' && (raw.length > 2000 || raw.includes('{' + '{') || raw.includes('}' + '}')))
                  throw new Error('Choose a named flow input for changing values. Fixed values cannot contain a data expression.');
                body.params[field.key] = raw;
              }
            });
          }
          if (fields.some(function (field) { return field.required && !(field.name in body.params); }))
            throw new Error('A required action input is still missing. Review the action again.');
        }
      } else {
        var replacement = await replacementForm(current);
        if (!replacement) return null;
        if (generation !== contextGeneration) throw new Error('The account or workspace changed. Reopen the current workflow.');
        Object.assign(body, replacement);
      }
      var consequence = current.to_kind === 'action'
        ? 'Use ' + human(body.tool) + ' for “' + human(current.node_label) + '” with the inputs you reviewed.'
        : 'Let the AI handle “' + human(current.node_label) + '” again.';
      if (current.to_kind === 'action' && current.description) consequence += ' Action: ' + current.description + '.';
      if (current.approval_added) consequence += ' This adds an approval before the action runs.';
      if (!(await window.mvConfirm(consequence + ' This saves a new draft version. Published runs keep the current version until you publish the draft. No run starts now.',
        {okText: 'Save new draft version'}))) return null;
      if (generation !== contextGeneration) throw new Error('The account or workspace changed. Reopen the current workflow.');
      return body;
    } finally { delete busy[key]; }
  }
  async function review(flowId, proposal) {
    var body = await prepare(flowId, proposal);
    if (body === null) return null;
    var path = '/api/v1/flows/' + encodeURIComponent(flowId);
      var result = await read(path + '/apply', {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
      if (!result || result.id !== flowId || result.node_id !== body.node_id ||
          result.to_kind !== body.to_kind || !Number.isInteger(result.version) || result.version <= body.version) {
        throw new Error('The save result could not be confirmed. Check the flow’s version history before trying again.');
      }
    return result;
  }
  window.LightworkFlowRewrite = {prepare: prepare, review: review};
}());
