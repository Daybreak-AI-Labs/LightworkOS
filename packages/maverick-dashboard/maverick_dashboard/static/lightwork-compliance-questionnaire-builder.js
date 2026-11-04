// Customer questionnaire names and typed conditions stay in the protected native form.
(function () {
  'use strict';
  var panel = document.getElementById('cs-questionnaire-design'), R = window.LwRecords;
  if (!panel || !R || panel.dataset.questionnaireBound === "true") return;
  panel.dataset.questionnaireBound = "true";
  var API = '/api/v1/compliance/questionnaire-builder', work = document.getElementById('cqb-work');
  var status = document.getElementById('cqb-status'), select = document.getElementById('cqb-source');
  var reviewPanel = document.getElementById('cqb-review'), preview = document.getElementById('cqb-preview');
  var prepare = document.getElementById('cqb-prepare'), apply = document.getElementById('cqb-apply');
  var recover = document.getElementById('cqb-recover'), confirm = document.getElementById('cqb-confirm');
  var domains = {organization: 'Your organization', industry: 'Industry', jurisdiction: 'Where you operate',
    data: 'Data you handle', system: 'Your systems', vendor: 'Vendors', ai: 'AI use', operational: 'Operations'};
  var kinds = {boolean: 'Yes or no', integer: 'Whole number', single_choice: 'Choose one', multi_choice: 'Choose several'};
  var dirty = false;
  var source = null, draft = null, fields = {}, pending = null, busy = false, generation = 0, handoff = null;
  var recoveryCopy = null, sourceChecked = false, requests = new Set();
  var studioForms = [], studioPreview = null, studioPin = null;
  var studioChoice = document.getElementById('cqb-studio-source'), studioBody = document.getElementById('cqb-studio-preview-body');
  var studioImport = document.getElementById('cqb-studio-import'), studioLinked = document.getElementById('cqb-studio-linked');
  var storage = 'lightwork.questionnaire.review.v1';
  function el(tag, text, parent, cls) { var node = R.el(tag, cls || '', text); if (parent) parent.appendChild(node); return node; }
  function button(label, parent, handler) { var b = el('button', label, parent, 'btn btn--ghost'); b.type = 'button'; b.addEventListener('click', handler); return b; }
  function say(text) { window.mvStatus ? window.mvStatus(status, text) : (status.textContent = text); }
  function fail(error) { if (error && (error.status === 401 || error.status === 403)) { clearPrivate(); return; } say(error && error.message || R.errorText(error, 'complete this questionnaire request')); }
  function valid(started) { return started === generation && (!handoff || handoff.active()); }
  function lock(on) {
    busy = on;
    panel.querySelectorAll('input,select,textarea,button').forEach(function (control) { control.disabled = on; });
    if (!on) {
      apply.disabled = !sourceChecked || !confirm.checked || !pending || pending.uncertain; prepare.disabled = !sourceChecked || !!(pending && pending.uncertain); select.disabled = !!(pending && pending.uncertain);
      if (pending && pending.uncertain) panel.querySelectorAll('input,select,textarea,button').forEach(function (control) { if (control !== recover && control.id !== 'cqb-close') control.disabled = true; });
      if (studioPin) work.querySelectorAll('[data-design-field^="questions."], [data-source-question]').forEach(function (control) { if (!/\.domain$/.test(control.dataset.designField || '')) control.disabled = true; });
    }
  }
  async function call(method, url, body) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 30000);
    requests.add(controller);
    var options = {method: method, credentials: 'same-origin', signal: controller.signal, headers: {Accept: 'application/json'}};
    if (body !== undefined) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
    try {
      var response = await fetch(url, options);
      if (response.redirected || response.status === 401 || response.status === 403) { var denied = new Error('Sign in with current access before opening private questionnaire details.'); denied.status = response.status === 403 ? 403 : 401; throw denied; }
      var result = await response.json();
      if (!response.ok) { var error = new Error(window.mvPlainDetail ? window.mvPlainDetail(result.detail) || 'This request could not be completed.' : 'This request could not be completed.'); error.status = response.status; throw error; }
      return result;
    } catch (error) {
      if (error && error.status) throw error;
      throw new Error(controller.signal.aborted ? 'This check timed out. Keep your draft and check the original save before another attempt.' : 'The reply could not be read. Keep your draft and check the original save before another attempt.');
    } finally { requests.delete(controller); clearTimeout(timer); }
  }
  function cancelRequests() { requests.forEach(function (controller) { controller.abort(); }); requests.clear(); }
  function recoveryReady() {
    if (recoveryCopy || !window.mvDraftRecovery) return;
    recoveryCopy = window.mvDraftRecovery.create({host: document.getElementById('cqb-draft'), key: 'compliance-questionnaire-designer',
      read: function () { return source && draft ? {source: source.source, source_revision: source.source_revision, studio_source: studioPin, design: read()} : {}; },
      restore: function (value) {
        if (!source || !value || !value.design || !Array.isArray(value.design.questions) || !Array.isArray(value.design.rules) || pending && pending.uncertain) { say('Check the original save before restoring this draft.'); return; }
        source.source = value.source || ''; source.source_revision = value.source_revision || ''; studioPin = value.studio_source || null; draft = value.design; select.value = source.source; render(); lock(false);
        say('Draft restored for review. If the saved starting version changed, the native review will refuse to overwrite it.');
      }});
  }
  function keepPending() {
    try { if (pending) sessionStorage.setItem(storage, JSON.stringify({token: pending.token, context: source.context})); else sessionStorage.removeItem(storage); }
    catch (_) { say('This browser could not keep the original request for reload recovery. Keep this page open until the result is confirmed.'); }
  }
  function dropReview() { if (pending && pending.uncertain) return; pending = null; reviewPanel.hidden = true; confirm.checked = false; recover.hidden = true; keepPending(); }
  function field(key, label, type, value, parent, choices) {
    var wrapper = el('label', label, parent); wrapper.style.minWidth = '0';
    var control = el(type === 'lines' ? 'textarea' : type === 'select' ? 'select' : 'input', undefined, wrapper, type === 'select' ? 'select' : 'input');
    control.setAttribute('data-design-field', key); control.style.width = '100%'; control.style.minWidth = '0';
    if (type === 'select') Object.keys(choices).forEach(function (id) { var option = el('option', choices[id], control); option.value = id; });
    else if (type !== 'lines') control.type = type;
    if (type === 'checkbox') control.checked = value; else control.value = value == null ? '' : String(value);
    if (type === 'text') control.maxLength = 120;
    if (type === 'number') { control.min = '0'; control.max = '1000000000'; control.step = '1'; }
    if (type === 'lines') { control.rows = 3; control.style.minHeight = '0'; control.style.fontFamily = 'inherit'; control.maxLength = 31000; }
    fields[key] = control;
    return control;
  }
  function lines(key) { return fields[key].value.split(/\r?\n/).map(function (value) { return value.trim(); }).filter(Boolean); }
  function value(key) { return fields[key].value.trim(); }
  function conditionFields(prefix, item, before, parent) {
    var choices = {'-1': 'Always'}, c = item || {question: -1, operator: 'equals', value: true};
    draft.questions.slice(0, before).forEach(function (q, i) { choices[String(i)] = (i + 1) + '. ' + (q.name || domains[q.domain] + ' question'); });
    var question = field(prefix + '.question', 'When', 'select', c.question, parent, choices);
    question.addEventListener('change', function () { read(); render(); });
    if (c.question < 0 || c.question >= before) return;
    var q = draft.questions[c.question], operators = q.kind === 'integer' ? {equals: 'is', not_equals: 'is not', greater_or_equal: 'is at least', less_or_equal: 'is at most'} :
      q.kind === 'multi_choice' ? {contains: 'includes this choice', equals: 'matches exactly', not_equals: 'does not match exactly'} :
      q.kind === 'single_choice' ? {equals: 'is this choice', not_equals: 'is not this choice', in: 'is any of these choices'} : {equals: 'is', not_equals: 'is not'};
    if (!operators[c.operator]) c.operator = Object.keys(operators)[0];
    var operator = field(prefix + '.operator', 'Answer condition', 'select', c.operator, parent, operators);
    operator.addEventListener('change', function () { read(); render(); });
    if (q.kind === 'boolean') field(prefix + '.value', 'Answer', 'select', c.value === false ? 'false' : 'true', parent, {true: 'Yes', false: 'No'});
    else if (q.kind === 'integer') field(prefix + '.value', 'Number', 'number', typeof c.value === 'number' ? c.value : 0, parent);
    else {
      var options = {}; q.options.forEach(function (option, i) { options[String(i)] = option || 'Unnamed choice ' + (i + 1); });
      if (c.operator === 'in' || (q.kind === 'multi_choice' && c.operator !== 'contains')) {
        var group = el('fieldset', undefined, parent); el('legend', 'Matching choices', group);
        Object.keys(options).forEach(function (id) { field(prefix + '.choices.' + id, options[id], 'checkbox', Array.isArray(c.value) && c.value.includes(Number(id)), group); });
      } else field(prefix + '.value', 'Matching choice', 'select', typeof c.value === 'number' ? c.value : 0, parent, options);
    }
  }
  function readCondition(prefix) {
    var index = Number(value(prefix + '.question'));
    if (index < 0) return null;
    var q = draft.questions[index], operator = fields[prefix + '.operator'] ? value(prefix + '.operator') : 'equals', result;
    if (!q) return null;
    if (q.kind === 'boolean') result = !fields[prefix + '.value'] || value(prefix + '.value') !== 'false';
    else if (q.kind === 'integer') result = fields[prefix + '.value'] ? Number(value(prefix + '.value')) : 0;
    else if (operator === 'in' || (q.kind === 'multi_choice' && operator !== 'contains')) result = q.options.map(function (_, i) { return i; }).filter(function (i) { return fields[prefix + '.choices.' + i] && fields[prefix + '.choices.' + i].checked; });
    else result = fields[prefix + '.value'] ? Number(value(prefix + '.value')) : 0;
    return {question: index, operator: operator, value: result};
  }
  function read() {
    if (!draft || !fields.name) return draft;
    draft.name = value('name');
    draft.questions.forEach(function (q, i) {
      var prefix = 'questions.' + i;
      q.name = value(prefix + '.name'); q.domain = value(prefix + '.domain'); q.kind = value(prefix + '.kind');
      q.options = fields[prefix + '.options'] ? lines(prefix + '.options') : []; q.required = fields[prefix + '.required'].checked;
      q.condition = studioPin ? null : readCondition(prefix + '.condition');
    });
    draft.rules.forEach(function (rule, i) {
      var prefix = 'rules.' + i;
      rule.framework = value(prefix + '.framework'); rule.controls = lines(prefix + '.controls');
      rule.overlaps = lines(prefix + '.overlaps'); rule.reason = value(prefix + '.reason');
      rule.conditions = rule.conditions.map(function (_, j) { return readCondition(prefix + '.conditions.' + j); }).filter(Boolean);
    });
    return draft;
  }
  function render() {
    fields = {}; work.textContent = ''; dropReview();
    field('name', 'Questionnaire name', 'text', draft.name, work);
    el('h3', 'Questions', work);
    draft.questions.forEach(function (q, i) {
      var card = el('fieldset', undefined, work, 'panel cs-stack'); el('legend', 'Question ' + (i + 1), card);
      var prefix = 'questions.' + i;
      field(prefix + '.name', 'Question name', 'text', q.name, card);
      field(prefix + '.domain', 'Topic', 'select', q.domain, card, Object.assign({'': 'Choose a topic'}, domains));
      field(prefix + '.kind', 'Answer format', 'select', q.kind, card, kinds).addEventListener('change', function () { read(); render(); });
      if (q.kind === 'single_choice' || q.kind === 'multi_choice') field(prefix + '.options', 'Choices · one name per line', 'lines', q.options.join('\n'), card);
      field(prefix + '.required', 'An answer is required when this question appears', 'checkbox', q.required, card);
      if (!studioPin) conditionFields(prefix + '.condition', q.condition, i, card);
      var removeQuestion = button('Remove question ' + (i + 1), card, function () {
        read(); draft.questions.splice(i, 1);
        function shift(c) { if (!c || c.question === i) return null; if (c.question > i) c.question--; return c; }
        draft.questions.forEach(function (row) { row.condition = shift(row.condition); });
        draft.rules.forEach(function (row) { row.conditions = row.conditions.map(shift).filter(Boolean); });
        render(); say('Question removed. Conditions that referred to it were removed too. Review the remaining rules before saving.');
      });
      removeQuestion.setAttribute('data-source-question', 'true');
    });
    button('Add a question', work, function () { read(); if (draft.questions.length >= 256) { say('A questionnaire can contain up to 256 questions.'); return; } draft.questions.push({name: '', domain: 'organization', kind: 'boolean', options: [], required: true, condition: null}); render(); }).setAttribute('data-source-question', 'true');
    el('h3', 'Scope rules', work); el('p', 'A rule applies its named controls when every listed condition matches. A rule with no conditions always applies. Names identify your team’s approved requirements; enter no evidence or licensed framework paragraphs.', work, 'muted');
    draft.rules.forEach(function (rule, i) {
      var card = el('fieldset', undefined, work, 'panel cs-stack'); el('legend', 'Scope rule ' + (i + 1), card);
      var prefix = 'rules.' + i;
      field(prefix + '.framework', 'Framework name', 'text', rule.framework, card);
      field(prefix + '.controls', 'Control names · one per line', 'lines', rule.controls.join('\n'), card);
      field(prefix + '.overlaps', 'Shared requirement names · one per line, optional', 'lines', rule.overlaps.join('\n'), card);
      field(prefix + '.reason', 'Reason this rule applies', 'text', rule.reason, card);
      rule.conditions.forEach(function (c, j) { var group = el('fieldset', undefined, card); el('legend', 'Condition ' + (j + 1), group); conditionFields(prefix + '.conditions.' + j, c, draft.questions.length, group); button('Remove condition', group, function () { read(); rule.conditions.splice(j, 1); render(); }); });
      button('Add a condition', card, function () { read(); if (rule.conditions.length >= 32) { say('Each rule can have up to 32 conditions.'); return; } rule.conditions.push({question: 0, operator: 'equals', value: true}); render(); });
      button('Remove rule ' + (i + 1), card, function () { read(); draft.rules.splice(i, 1); render(); });
    });
    button('Add a scope rule', work, function () { read(); if (draft.rules.length >= 512) { say('A questionnaire can contain up to 512 scope rules.'); return; } draft.rules.push({framework: '', controls: [], overlaps: [], reason: '', conditions: []}); render(); });
    studioLinked.textContent = studioPin ? 'Questions are linked to the reviewed live studio form. Change questions in Compliance studio; assign topics and scope rules here. The live source is checked again before saving.' : '';
    lock(busy);
  }
  function conditionText(c, design) {
    if (!c) return 'Always shown';
    var q = design.questions[c.question], answer;
    if (q.kind === 'boolean') answer = c.value ? 'Yes' : 'No';
    else if (q.kind === 'integer') answer = String(c.value);
    else answer = (Array.isArray(c.value) ? c.value : [c.value]).map(function (i) { return q.options[i]; }).join(', ');
    var operators = {equals: 'is', not_equals: 'is not', contains: 'includes', in: 'is any of', greater_or_equal: 'is at least', less_or_equal: 'is at most'};
    return q.name + ' ' + operators[c.operator] + ' ' + answer;
  }
  function showDesign(parent, design) {
    design.questions.forEach(function (q, i) { var group = el('section', undefined, parent, 'panel'); el('h4', (i + 1) + '. ' + q.name, group); el('p', domains[q.domain] + ' · ' + kinds[q.kind] + ' · ' + (q.required ? 'Answer required' : 'Optional answer'), group); if (q.options.length) el('p', 'Choices: ' + q.options.join(' · '), group); el('p', 'Appears: ' + conditionText(q.condition, design), group); });
    design.rules.forEach(function (rule, i) { var group = el('section', undefined, parent, 'panel'); el('h4', 'Rule ' + (i + 1) + ' · ' + rule.framework, group); el('p', 'Controls: ' + rule.controls.join(' · '), group); if (rule.overlaps.length) el('p', 'Shared requirements: ' + rule.overlaps.join(' · '), group); el('p', 'Reason: ' + rule.reason, group); el('p', 'Applies: ' + (rule.conditions.length ? rule.conditions.map(function (c) { return conditionText(c, design); }).join(' AND ') : 'Always'), group); });
  }
  function showReview(body) {
    preview.textContent = '';
    el('p', body.preview.name + ' · new version ' + body.version, preview); el('p', body.message, preview, 'muted');
    if (body.studio_form) el('p', 'Imported questions are bound to the exact live studio form you selected. This save creates a separate questionnaire for independent approval.', preview, 'muted');
    showDesign(preview, body.preview);
    reviewPanel.hidden = false; confirm.checked = false; apply.disabled = true; reviewPanel.scrollIntoView({block: 'start'});
  }
  async function loadSource(identity, started) {
    var body = await call('GET', API + '/source?identity=' + encodeURIComponent(identity || ''));
    if (!valid(started)) return;
    var saved;
    try { saved = JSON.parse(sessionStorage.getItem(storage) || 'null'); } catch (_) { saved = null; }
    dirty = false; studioPin = null; studioPreview = null; studioBody.replaceChildren(); studioImport.hidden = true; source = body; draft = body.design; select.value = body.source; sourceChecked = true;
    if (saved) pending = {token: saved.token, uncertain: true};
    render(); recoveryReady();
    document.getElementById("cqb-update-source").hidden = !source.source;
    document.getElementById("cqb-latest").hidden = true;
    if (saved) {
      if (saved.context !== source.context) { clearPrivate(); say('An original save belongs to another account or workspace. Return to that account before checking it.'); return; }
      pending = {token: saved.token, uncertain: true}; recover.hidden = false; prepare.disabled = true; select.disabled = true;
      say('A previous save needs confirmation. Check its original result before creating another version.');
    }
  }
  async function open(identity, expectedContext) {
    if (busy || (pending && pending.uncertain)) { panel.hidden = false; say('Check the original save before another request.'); return; }
    var started = ++generation; panel.hidden = false; lock(true);
    try {
      var current = await call('GET', API + '/catalog');
      if (!valid(started)) return;
      if (expectedContext && current.context !== expectedContext) throw new Error('Your account, workspace or access changed. Refresh current controls.');
      if (source && draft && dirty && source.context === current.context && (expectedContext || !identity || identity === source.source)) {
        say('Your current questionnaire draft and linked studio form are kept. Review these existing questions before saving or changing the starting point.');
        panel.scrollIntoView({block: 'start'}); if (fields.name) fields.name.focus({preventScroll: true}); return;
      }
      select.textContent = ''; var fresh = el('option', 'New questionnaire', select); fresh.value = '';
      current.sources.forEach(function (q) { var option = el('option', q.name + ' · version ' + q.version, select); option.value = q.id; });
      document.getElementById('cqb-notice').textContent = current.notice;
      await loadSource(identity || '', started); if (valid(started) && !(pending && pending.uncertain)) say('Name your questions and rules, then review the complete new version.');
      panel.scrollIntoView({block: 'start'});
      if (valid(started) && fields.name) fields.name.focus({preventScroll: true});
    } catch (error) { if (valid(started)) fail(error); }
    finally { if (valid(started)) lock(false); }
  }
  document.getElementById('cqb-update-source').addEventListener('click', async function () {
    if (busy || !source || !source.source || pending && pending.uncertain) return;
    var started = generation, original = source.context; read(); lock(true);
    try {
      var fresh = await call('GET', API + '/source?identity=' + encodeURIComponent(source.source));
      if (!valid(started)) return;
      if (fresh.context !== original) { clearPrivate(); return; }
      dropReview(); source.source_revision = fresh.source_revision; source.source_version = fresh.source_version; sourceChecked = true;
      var current = document.getElementById('cqb-latest-preview'); current.replaceChildren();
      el('p', fresh.design.name + ' · version ' + fresh.source_version, current);
      el('p', 'Your draft has been kept. Changes from this current version are not merged automatically. Compare all questions and rules below before preparing your new version. Existing versions and assessments will remain unchanged.', current, 'muted');
      showDesign(current, fresh.design); document.getElementById('cqb-latest').hidden = false;
      say('Current starting version loaded. Your draft is unchanged. Compare it with this saved version, then prepare a full new review.');
      document.getElementById('cqb-latest').scrollIntoView({block: 'start'});
    } catch (error) { if (valid(started)) fail(error); }
    finally { if (valid(started)) lock(false); }
  });
  select.addEventListener('change', async function () { if (busy || pending && pending.uncertain) return; var selected = select.value, previous = source && source.source || ''; if (dirty && !(await R.confirm('Change the starting questionnaire? The current draft will be replaced. Its private recovery copy is kept until you save or discard it.', 'Change questionnaire'))) { select.value = previous; return; } var started = generation; lock(true); try { await loadSource(selected, started); } catch (error) { if (valid(started)) fail(error); } finally { if (valid(started)) lock(false); } });
  work.addEventListener('input', function () { dirty = true; dropReview(); if (recoveryCopy) document.getElementById('cqb-draft').dispatchEvent(new Event('input', {bubbles: true})); });
  prepare.addEventListener('click', async function () {
    if (busy || !sourceChecked || !source || pending && pending.uncertain) return;
    var started = generation; read(); lock(true);
    try {
      var body = await call('POST', API + '/review', {context: source.context, source: source.source, source_revision: source.source_revision, studio_source: studioPin, design: draft});
      if (!valid(started)) return;
      pending = {token: body.token, uncertain: false}; keepPending(); showReview(body); say('Review every question and rule. Nothing has been saved yet.');
    } catch (error) { if (valid(started)) fail(error); }
    finally { if (valid(started)) lock(false); }
  });
  confirm.addEventListener('change', function () { apply.disabled = !sourceChecked || !confirm.checked || busy || !pending || pending.uncertain; });
  document.getElementById('cqb-edit').addEventListener('click', function () { if (busy || pending && pending.uncertain) return; dropReview(); work.scrollIntoView({block: 'start'}); });
  function accepted(body) {
    dirty = false; pending = null; keepPending(); reviewPanel.hidden = true; recover.hidden = true; say(body.message);
    if (recoveryCopy) recoveryCopy.clear();
    document.dispatchEvent(new CustomEvent('lightwork:questionnaire-saved'));
    if (handoff) finish({status: 'accepted', confirmed: true, result: body.result});
  }
  apply.addEventListener('click', async function () {
    if (busy || !sourceChecked || !pending || !confirm.checked || pending.uncertain) return;
    var started = generation; pending.uncertain = true; keepPending(); lock(true);
    try { var body = await call('POST', API + '/apply', {token: pending.token, confirmed: true}); if (valid(started)) accepted(body); }
    catch (error) { if (valid(started)) { reviewPanel.hidden = true; recover.hidden = false; say('The save response is not confirmed. Check the original save before another attempt. ' + R.errorText(error, 'confirm the saved version')); } }
    finally { if (valid(started)) lock(false); }
  });
  recover.addEventListener('click', async function () {
    if (busy || !pending) return; var started = generation; lock(true);
    try { var body = await call('POST', API + '/receipt', {token: pending.token}); if (!valid(started)) return;
      if (body.confirmed) accepted(body); else { say(body.message); button('I confirmed the original request is no longer running · keep my draft', status, function () { if (busy) return; pending = null; keepPending(); recover.hidden = true; lock(false); say('Draft kept. A fresh review is required; the original request was not retried.'); }); }
    } catch (error) { if (valid(started)) fail(error); }
    finally { if (valid(started)) lock(false); }
  });
  function finish(result) { var current = handoff; handoff = null; if (!current) return; current.parent.insertBefore(panel, current.next && current.next.parentNode === current.parent ? current.next : null); panel.hidden = true; current.resolve(result); }
  document.getElementById('cqb-close').addEventListener('click', function () { if (busy) return; if (handoff) finish(pending && pending.uncertain ? {status: 'unconfirmed'} : null); else panel.hidden = true; });
  function clearPrivate() {
    generation++; cancelRequests();
    if (recoveryCopy) recoveryCopy.dispose(); recoveryCopy = null;
    document.getElementById('cqb-draft').replaceChildren(); document.getElementById('cqb-latest-preview').replaceChildren(); document.getElementById('cqb-latest').hidden = true;
    work.replaceChildren(); preview.replaceChildren(); select.replaceChildren(); document.getElementById('cqb-notice').textContent = '';
    reviewPanel.hidden = true; recover.hidden = true; confirm.checked = false;
    studioPin = null; studioPreview = null; studioForms = []; studioChoice.replaceChildren(); studioBody.replaceChildren(); studioLinked.textContent = ''; studioImport.hidden = true;
    source = null; draft = null; fields = {}; pending = null; sourceChecked = false; dirty = false; lock(false);
    // Keep the sealed original request in this tab for its original account.
    say('Your account, workspace or access changed. Private questionnaire details were cleared. Return to the original account to check a pending save.');
    if (handoff) finish({status: 'unconfirmed'});
  }
  async function checkSelection() {
    if (!source) return;
    var original = source, started = ++generation; cancelRequests();
    if (handoff && !handoff.active()) { finish(pending && pending.uncertain ? {status: 'unconfirmed'} : null); panel.hidden = false; }
    sourceChecked = false; lock(true); say('Checking your current account and starting version. Your draft is kept.');
    try {
      var fresh = await call('GET', API + '/source?identity=' + encodeURIComponent(original.source));
      if (!valid(started)) return;
      if (fresh.context !== original.context) { clearPrivate(); return; }
      if (studioPin) {
        var live = await call('GET', API + '/studio-form?studio=' + encodeURIComponent(studioPin.studio) + '&form=' + encodeURIComponent(studioPin.form));
        if (!valid(started)) return;
        if (live.context !== original.context) { clearPrivate(); return; }
        if (JSON.stringify(live.studio_source) !== JSON.stringify(studioPin) || live.incompatibilities.length) throw new Error('The linked studio form changed. Your draft is kept; saving is paused until you review and import its current form.');
      }
      recoveryReady();
      if (fresh.source !== original.source || fresh.source_revision !== original.source_revision || fresh.source_version !== original.source_version) {
        dropReview();
        say('The starting questionnaire changed. Your editable draft is kept. Review the current starting version before preparing another save.');
      } else { sourceChecked = true; say('Your current account and starting version are checked. Your draft and recovery copy are kept.'); }
      if (pending && pending.uncertain) { reviewPanel.hidden = true; recover.hidden = false; say('Your draft and original request are kept. Check the original save before another attempt.'); }
    } catch (error) {
      if (!valid(started)) return;
      if (error.status === 401 || error.status === 403) { clearPrivate(); return; }
      // A missing/replaced source may still have an accepted historical receipt.
      // Check the current account before leaving its private draft visible.
      if (error.status === 404 || error.status === 409) {
        try { var scope = await call('GET', API + '/catalog'); if (!valid(started)) return; if (scope.context !== original.context) { clearPrivate(); return; } }
        catch (denied) { if (!valid(started)) return; if (denied.status === 401 || denied.status === 403) { clearPrivate(); return; } }
      }
      if (!valid(started)) return;
      say('Your draft is kept, but current access and the starting version could not be confirmed. Saving is paused. Check the current details before continuing.');
      button('Check current account and starting version', status, checkSelection);
      if (pending && pending.uncertain) { reviewPanel.hidden = true; recover.hidden = false; }
    } finally { if (valid(started)) lock(false); }
  }
  document.addEventListener('lightwork:copilot-context-changed', function (event) { if (event.detail && event.detail.reason === 'selection') checkSelection(); else clearPrivate(); });
  document.addEventListener('lightwork:account-context-changed', clearPrivate);
  document.addEventListener('lightwork:workspace-changed', clearPrivate);
  window.addEventListener('lightwork:context-changed', clearPrivate);
  window.addEventListener('pagehide', function () { generation++; cancelRequests(); });
  window.LightworkComplianceQuestionnaire = {open: open, openCreate: function (options) {
    if (busy || handoff || !options || typeof options.active !== 'function' || !options.active()) return Promise.reject(new Error('The questionnaire form is unavailable.'));
    return new Promise(function (resolve, reject) { handoff = {parent: panel.parentNode, next: panel.nextSibling, resolve: resolve, active: options.active}; options.host.appendChild(panel); open('', options.context).catch(function (error) { finish({status: 'unconfirmed'}); reject(error); }); });
  }};
  document.getElementById('cqb-studio-load').addEventListener('click', async function () {
    if (busy || !source || pending && pending.uncertain) return;
    var started = generation; lock(true);
    try {
      var body = await call('GET', API + '/studio-sources');
      if (!valid(started)) return;
      if (body.context !== source.context) { clearPrivate(); return; }
      studioForms = body.forms; studioChoice.replaceChildren(); el('option', 'Choose a form', studioChoice).value = '';
      studioForms.forEach(function (row, index) { el('option', row.name + ' · version ' + row.version, studioChoice).value = String(index); });
      say(studioForms.length ? body.notice : 'There are no live forms yet. Build a form in Compliance studio and complete its review, approval and publication first. Your draft is kept.');
    } catch (error) { if (valid(started)) fail(error); }
    finally { if (valid(started)) lock(false); }
  });
  studioChoice.addEventListener('change', function () { studioPreview = null; studioBody.replaceChildren(); studioImport.hidden = true; });
  document.getElementById('cqb-studio-preview').addEventListener('click', async function () {
    if (busy || !source || pending && pending.uncertain) return;
    var row = studioChoice.value === '' ? null : studioForms[Number(studioChoice.value)];
    if (!row) { say('Choose a live form first. Your draft is kept.'); return; }
    var started = generation; lock(true); studioPreview = null; studioImport.hidden = true;
    try {
      var body = await call('GET', API + '/studio-form?studio=' + encodeURIComponent(row.studio) + '&form=' + encodeURIComponent(row.form));
      if (!valid(started)) return;
      if (body.context !== source.context) { clearPrivate(); return; }
      studioBody.replaceChildren(); el('h4', body.name + ' · version ' + body.source_version, studioBody); el('p', body.notice, studioBody);
      body.questions.forEach(function (q, index) { el('p', (index + 1) + '. ' + q.name + ' · ' + (kinds[q.kind] || 'Unsupported answer format') + ' · ' + (q.required ? 'Required' : 'Optional') + (q.options.length ? ' · Choices: ' + q.options.join(' / ') : ''), studioBody); });
      if (body.incompatibilities.length) {
        el('h4', 'Resolve these before importing', studioBody); var list = el('ul', undefined, studioBody);
        body.incompatibilities.forEach(function (issue) { el('li', issue, list); });
        say('This form cannot be imported yet. Its questions and your draft have not changed.');
      } else { studioPreview = body; studioImport.hidden = false; say('Review every question and choice before importing. Nothing has been saved.'); }
    } catch (error) { if (valid(started)) fail(error); }
    finally { if (valid(started)) lock(false); }
  });
  studioImport.addEventListener('click', async function () {
    if (busy || !studioPreview || !source || pending && pending.uncertain) return;
    var reviewed = studioPreview, started = generation;
    var ok = await R.confirm('Replace the draft questions and scope rules with these reviewed form questions? Assign all eight topics and add your team’s real framework and control rules afterward. The saved starting questionnaire and studio remain unchanged.', 'Import questions');
    if (!ok || !valid(started) || studioPreview !== reviewed || busy || pending && pending.uncertain) return;
    read(); studioPin = reviewed.studio_source;
    draft = {name: reviewed.name, questions: JSON.parse(JSON.stringify(reviewed.questions)), rules: [{framework: '', controls: [], overlaps: [], reason: '', conditions: []}]};
    dirty = true; render(); say('Questions imported into your draft. Assign all eight topics, add scope rules, then review and save for independent approval.');
    if (recoveryCopy) document.getElementById('cqb-draft').dispatchEvent(new Event('input', {bubbles: true}));
  });
  if (window.location.hash === '#cs-questionnaire-design') open();
}());
