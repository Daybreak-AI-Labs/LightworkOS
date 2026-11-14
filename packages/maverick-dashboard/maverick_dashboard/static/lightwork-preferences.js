(function () {
  'use strict';
  var form = document.getElementById('preference-form'); if (!form) return;
  var model = JSON.parse(document.getElementById('preference-data').textContent);
  var thread = JSON.parse(document.getElementById('preference-thread').textContent);
  var styles = JSON.parse(document.getElementById('preference-styles').textContent);
  var scope = document.getElementById('preference-scope'), status = document.getElementById('preference-status');
  function copy(node,source,values){if(window.LightworkI18n)window.LightworkI18n.set(node,source,values);else node.textContent=text(source,values);}
  function text(source,values){return window.LightworkI18n?window.LightworkI18n.text(source,values):String(source||'').replace(/\{(\w+)\}/g,function(whole,key){return values&&Object.prototype.hasOwnProperty.call(values,key)?String(values[key]):whole;});}
  function appendCopy(node,source,values){var span=document.createElement('span');copy(span,source,values);node.append(' ',span);}
  // Messages this page writes itself are product copy even where no catalog
  // is loaded (English pages); other text needs a catalog entry to be shown.
  function productError(message){var error=new Error(message);error.productCopy=true;return error;}
  function knownError(error,fallback){var message=error&&error.message;return error&&error.productCopy||window.LightworkI18n&&window.LightworkI18n.has(message)?message:fallback;}
  function sourceLabel(source){return text({'personal':'Personal','workspace':'Workspace','organization':'Organization','conversation':'Conversation','product default':'Product default','installation settings':'Installation settings','organization style':'Organization style','organization policy':'Organization policy'}[source]||source);}
  function fieldLabel(key){return text({chat_specialist:'Default Chat specialist',chat_model:'Default Chat model',chat_effort:'Default Chat thinking depth',preferred_name:'What Lightwork calls you',tone:'Writing tone',verbosity:'Detail',language:'Response language',interface_language:'Interface language',output_style:'Output style',custom_style_name:'Style name',custom_style:'Style guidance',start_page:'Starting page',navigation:'Sidebar',theme:'Theme',font:'Font',density:'Page spacing',text_size:'Text size',glass:'Glass effects',favorites:'Pinned pages',today_days:'Today period',today_cards:'Today cards',conversation_mode:'While a task runs',conversation_detail:'Inbox detail'}[key]||key);}
  var changes = {}, pins = [], busy = false;
  var compare = document.getElementById('preference-compare');
  var aiModel = document.getElementById('preference-chat_model'), aiEffort = document.getElementById('preference-chat_effort');
  var specialist = document.getElementById('preference-chat_specialist');
  var modelDefault = aiModel && aiModel.querySelector('option[value=""]');
  var effortDefault = aiEffort && aiEffort.querySelector('option[value=""]');
  var specialistDefault = specialist && specialist.querySelector('option[value=""]');
  var originalPanel = document.getElementById('preference-original'), originalStatus = document.getElementById('preference-original-status');
  var originalRead = document.getElementById('preference-original-read'), originalNew = document.getElementById('preference-original-new');
  var original = null, recoveryKey = 'lightwork-preference-original:' + (thread || 'account'), editRevision = 0;
  function option(value, label) { var item = document.createElement('option'); item.value = value; item.textContent = label; return item; }
  function syncAI(wanted) {
    if (!aiModel || !aiEffort) return;
    var row = (model.chat_models || []).find(function (item) { return item.value === aiModel.value; });
    aiEffort.replaceChildren(effortDefault);
    (row ? row.efforts : []).forEach(function (item) { aiEffort.append(option(item.value, item.label)); });
    if (wanted && !Array.from(aiEffort.options).some(function (item) { return item.value === wanted; })) aiEffort.append(option(wanted, 'Saved thinking depth — no longer available'));
    aiEffort.value = wanted || '';
    aiEffort.disabled = busy || scope.value !== 'personal' || !row || !row.efforts.length;
    document.getElementById('preference-chat-status').textContent = aiModel.value && !row ? 'Your saved model is no longer available. Choose a current model or workspace settings before starting new Chat work.' : 'New Chat tasks start with these choices. You can change them in each task.';
  }
  function savedValue(key, value) {
    if (key === 'chat_specialist') { var selected = (model.chat_specialists || []).find(function (row) { return row.value === value; }); return selected ? selected.label : value ? 'Saved specialist — no longer available' : 'Let Lightwork choose the team'; }
    if (key === 'chat_model') { var row = (model.chat_models || []).find(function (item) { return item.value === value; }); return row ? row.label : value ? 'Saved model — no longer available' : 'Use workspace settings'; }
    if (key === 'chat_effort') { var item = (model.chat_models || []).flatMap(function (row) { return row.efforts; }).find(function (row) { return row.value === value; }); return item ? item.label : value || 'Use the model’s usual thinking depth'; }
    return JSON.stringify(value);
  }
  function syncSpecialist() {
    if (!specialist) return;
    var available = !specialist.value || (model.chat_specialists || []).some(function (row) { return row.value === specialist.value; });
    document.getElementById('preference-specialist-status').textContent = available ? 'New Chat tasks use this published specialist unless you choose a different team. Its current publication, permitted actions and required approvals still apply.' : 'Your saved specialist is no longer available. Choose a current specialist or let Lightwork choose the team before starting new Chat work.';
  }
  function originalMessage(message) { originalPanel.hidden = !original; originalStatus.textContent = message; }
  function clearPrivate() {
    form.querySelectorAll('input,textarea,select').forEach(function (field) { if (field.tagName === 'SELECT') field.replaceChildren(); else field.value = ''; field.disabled = true; });
    changes = {}; pins = []; model = {context:'',values:{},chat_models:[]};
    document.getElementById('preference-pins')?.replaceChildren(); document.getElementById('preference-preview').textContent = '';
    form.querySelectorAll('[data-source-for]').forEach(function (field) { field.textContent = ''; });
    status.textContent = 'Your account, workspace or access changed. Private preference details were cleared. Reopen your preferences in the current account.';
  }
  try { var retained = JSON.parse(sessionStorage.getItem(recoveryKey) || 'null'); if (retained && retained.context === model.context && typeof retained.operation_id === 'string') original = retained; } catch (_) {}
  if (original) originalMessage('A previous save is retained. Check its original result before another save.');
  function renderPins() {
    var list = document.getElementById('preference-pins'); if (!list) return;
    list.replaceChildren();
    pins.forEach(function (href, index) {
      var row = document.createElement('li'); copy(row,model.destinations[href] || 'Unavailable page');
      [['Move up', -1], ['Move down', 1], ['Remove', 0]].forEach(function (action) {
        var button = document.createElement('button'); button.type = 'button'; button.className = 'btn btn--ghost'; copy(button,action[0]);
        button.disabled = busy || scope.value !== 'personal' || (action[1] === -1 && !index) || (action[1] === 1 && index === pins.length - 1);
        button.addEventListener('click', function () {
          if (action[1] === 0) pins.splice(index, 1);
          else { var swap = pins[index + action[1]]; pins[index + action[1]] = href; pins[index] = swap; }
          changes.favorites = pins.slice(); renderPins();
        }); row.appendChild(button);
      }); list.appendChild(row);
    });
  }
  function preview() {
    var field = form.querySelector('[data-pref="output_style"]'), custom = form.querySelector('[data-pref="custom_style"]');
    var target=document.getElementById('preference-preview');
    if(field.value==='custom'||styles[field.value]){target.lang='und';target.dir='auto';target.dataset.userContent='';delete target.dataset.productCopy;target.textContent=field.value==='custom'?custom.value:styles[field.value];}
    else {delete target.dataset.userContent;copy(target,'Ordinary response style.');}
  }
  function render() {
    var effective = model.effective_by_scope[thread ? "conversation" : scope.value] || model;
    if (aiModel) { aiModel.replaceChildren(modelDefault); (model.chat_models || []).forEach(function (row) { aiModel.append(option(row.value, row.label)); }); }
    if (specialist) { specialist.replaceChildren(specialistDefault); (model.chat_specialists || []).forEach(function (row) { var item = option(row.value, row.label); item.dataset.revision = row.revision; specialist.append(item); }); }
    form.querySelectorAll('[data-pref]').forEach(function (field) {
      var key = field.dataset.pref;
      if (key === 'chat_model' && effective.values[key] && !Array.from(field.options).some(function (item) { return item.value === effective.values[key]; })) field.append(option(effective.values[key], 'Saved model — no longer available'));
      if (key === 'chat_specialist' && effective.values[key] && !Array.from(field.options).some(function (item) { return item.value === effective.values[key]; })) field.append(option(effective.values[key], 'Saved specialist — no longer available'));
      field.value = effective.values[key];
      field.disabled = model.locked.indexOf(key) !== -1 || (scope.value !== 'personal' && ['preferred_name','start_page','today_days','chat_model','chat_effort','chat_specialist'].indexOf(key) !== -1);
      var source = form.querySelector('[data-source-for="' + key + '"]');
      if(source)copy(source,model.locked.indexOf(key)!==-1?'Effective source: {source} — Set by organization policy':'Effective source: {source}',{source:sourceLabel(effective.sources[key])});
    });
    form.querySelectorAll('[data-inherit-pref]').forEach(function (box) { box.checked = false; box.disabled = model.locked.indexOf(box.dataset.inheritPref) !== -1 || (scope.value !== 'personal' && ['preferred_name','start_page','today_days','chat_model','chat_effort','chat_specialist'].indexOf(box.dataset.inheritPref) !== -1); });
    form.querySelectorAll('[data-today-card]').forEach(function (box) { box.checked = model.values.today_cards.indexOf(box.dataset.todayCard) !== -1; box.disabled = scope.value !== 'personal'; });
    orderCards(model.values.today_cards);
    form.querySelectorAll('[data-card-move]').forEach(function (button) { button.disabled = scope.value !== 'personal'; });
    form.querySelectorAll('[data-inherit-list]').forEach(function (button) { var key = button.dataset.inheritList; button.disabled = scope.value !== 'personal'; var source = form.querySelector('[data-source-for="' + key + '"]'); if(source)copy(source,'Effective source: {source}',{source:sourceLabel(model.sources[key])}); });
    pins = model.values.favorites.slice(); renderPins(); preview(); changes = {};
    syncAI(effective.values.chat_effort);
    syncSpecialist();
    if (compare) compare.hidden = true;
  }
  function orderCards(order) {
    var rows = Array.from(form.querySelectorAll('[data-today-row]'));
    rows.sort(function (a, b) { var ai = order.indexOf(a.dataset.todayRow), bi = order.indexOf(b.dataset.todayRow); return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi); });
    rows.forEach(function (row) { row.parentNode.appendChild(row); });
  }
  form.querySelectorAll('[data-card-move]').forEach(function (button) { button.addEventListener('click', function () {
    if (busy || scope.value !== 'personal') return;
    var row = button.closest('[data-today-row]'), other = button.dataset.cardMove === 'up' ? row.previousElementSibling : row.nextElementSibling;
    if (!other || !other.hasAttribute('data-today-row')) return;
    if (button.dataset.cardMove === 'up') row.parentNode.insertBefore(row, other); else row.parentNode.insertBefore(other, row);
    changes.today_cards = Array.from(form.querySelectorAll('[data-today-card]:checked')).map(function (box) { return box.dataset.todayCard; }); button.focus();
  }); });
  form.addEventListener('input', function (event) { if (event.target.dataset.pref) { changes[event.target.dataset.pref] = event.target.value; var inherited = form.querySelector('[data-inherit-pref="' + event.target.dataset.pref + '"]'); if (inherited) inherited.checked = false; preview(); } });
  form.addEventListener('change', function (event) {
    var target = event.target;
    if (target.dataset.pref) changes[target.dataset.pref] = target.value;
    if (target.dataset.inheritPref) {
      var key = target.dataset.inheritPref, field = form.querySelector('[data-pref="' + key + '"]');
      changes[key] = target.checked ? null : field.value;
    }
    if (target.dataset.todayCard) changes.today_cards = Array.from(form.querySelectorAll('[data-today-card]:checked')).map(function (box) { return box.dataset.todayCard; });
    if (target === aiModel || target.dataset.inheritPref === 'chat_model') {
      if (target.dataset.inheritPref && target.checked) aiModel.value = '';
      changes.chat_effort = ''; syncAI('');
    }
    if (target === specialist || target.dataset.inheritPref === 'chat_specialist') { if (target.dataset.inheritPref && target.checked) specialist.value = ''; syncSpecialist(); }
  });
  form.addEventListener('input', function () { editRevision += 1; });
  form.addEventListener('change', function () { editRevision += 1; });
  form.querySelectorAll('[data-inherit-list]').forEach(function (button) { button.addEventListener('click', function () { if (scope.value !== 'personal') return; changes[button.dataset.inheritList] = null; copy(status,'Product default selected for {preference}. Review and save to apply it.',{preference:fieldLabel(button.dataset.inheritList)}); }); });
  var previousScope = scope.value;
  scope.addEventListener('change', async function () {
    if (Object.keys(changes).length && !(await window.mvConfirm('Discard these preference drafts before changing scope? Unsaved changes are lost.',{productCopy:true,okText:'Discard drafts'}))) { scope.value = previousScope; return; }
    previousScope = scope.value; render();
  });
  var add = document.getElementById('pin-add'); if (add) add.addEventListener('click', function () {
    if (scope.value !== 'personal') { copy(status,'Choose Personal to edit your pinned pages.'); return; }
    var href = document.getElementById('pin-choice').value;
    if (pins.indexOf(href) === -1) pins.push(href);
    changes.favorites = pins.slice(); renderPins();
  });
  var migration = document.getElementById('migrate-name'); if (migration) migration.addEventListener('click', function () {
    if (scope.value !== 'personal') return;
    form.querySelector('[data-pref="preferred_name"]').value = migration.dataset.name;
    changes.preferred_name = migration.dataset.name; copy(status,'Name filled for your account. Review and save to migrate it.');
  });
  function describe(draft, state) {
    var effective = state.effective_by_scope[thread ? 'conversation' : scope.value] || state;
    return Object.keys(draft).map(function (key) {
      return fieldLabel(key) + ': ' + savedValue(key,effective.values[key]) + ' (' + sourceLabel(effective.sources[key]) + ') -> ' +
        (draft[key] === null ? text('Use inherited value') : savedValue(key,draft[key]));
    }).join('\n');
  }
  function applyDraft(draft) {
    changes = draft;
    Object.keys(draft).forEach(function (key) {
      var field = form.querySelector('[data-pref="' + key + '"]'), inherit = form.querySelector('[data-inherit-pref="' + key + '"]');
      if (field && draft[key] !== null) {
        if (key === 'chat_model' && draft[key] && !Array.from(field.options).some(function (item) { return item.value === draft[key]; })) field.append(option(draft[key], 'Your draft model — no longer available'));
        if (key === 'chat_specialist' && draft[key] && !Array.from(field.options).some(function (item) { return item.value === draft[key]; })) field.append(option(draft[key], 'Your draft specialist — no longer available'));
        field.value = draft[key];
      }
      if (inherit) inherit.checked = draft[key] === null;
    });
    if (draft.favorites) { pins = draft.favorites.slice(); renderPins(); }
    if (draft.today_cards) { orderCards(draft.today_cards); form.querySelectorAll('[data-today-card]').forEach(function (box) { box.checked = draft.today_cards.indexOf(box.dataset.todayCard) !== -1; }); }
    preview();
    syncAI(changes.chat_effort !== undefined ? changes.chat_effort : model.values.chat_effort);
    syncSpecialist();
  }
  if (compare) compare.addEventListener('click', async function () {
    if (busy) return;
    busy = true;
    try {
      var response = await fetch('/api/v1/preferences' + (thread ? '?thread=' + encodeURIComponent(thread) : ''), {cache:'no-store'});
      if (!response.ok) throw productError('Current preferences could not be read. Your draft remains available. Refresh the page and try again.');
      var current = await response.json(), draft = Object.assign({}, changes);
      if (current.context !== model.context) throw productError('Your account or workspace changed. Save this draft separately before reloading.');
      var locked = Object.keys(draft).filter(function (key) { return current.locked.indexOf(key) !== -1; });
      var policy=locked.length?text('Policy now controls {fields}. These proposed edits will be removed; other drafts remain.',{fields:locked.map(fieldLabel).join(', ')}):'';
      if (!(await window.mvConfirm('Compare current saved values with your retained draft: {changes} {policy} Use these current values as the basis for a new review? Nothing is saved by this step.', {okText:'Keep draft for review',productCopy:true,values:{changes:describe(draft,current),policy:policy}}))) return;
      locked.forEach(function (key) { delete draft[key]; });
      model = current; render(); applyDraft(draft);
      window.LightworkI18n ? window.LightworkI18n.set(status, 'Current values loaded. Review and save your remaining draft when ready.') : copy(status,'Current values loaded. Review and save your remaining draft when ready.');
    } catch (failure) { copy(status,knownError(failure,'Current preferences could not be read. Your draft remains available. Refresh the page and try again.')); }
    finally { busy = false; renderPins(); }
  });
  form.addEventListener('submit', async function (event) {
    event.preventDefault(); if (busy || !Object.keys(changes).length) return;
    if (original) { originalMessage('Check the retained original save before another review. Nothing was repeated.'); originalRead.focus(); return; }
    var submitted = Object.assign({}, changes);
    var reviewedScope = scope.value, reviewedContext = model.context, reviewedRevision = model.revision, submittedRevision = editRevision;
    var specialistRevision;
    if (Object.prototype.hasOwnProperty.call(submitted,'chat_specialist')) { var reviewed = (model.chat_specialists || []).find(function (row) { return row.value === submitted.chat_specialist; }); specialistRevision = reviewed ? reviewed.revision : ''; }
    if (!(await window.mvConfirm('Apply to {scope}: {changes}', {okText:'Save preferences',productCopy:true,values:{scope:sourceLabel(thread?'conversation':reviewedScope),changes:describe(submitted,model)}}))) return;
    if (!model.context || scope.value !== reviewedScope || model.context !== reviewedContext || model.revision !== reviewedRevision || editRevision !== submittedRevision) { copy(status,'Your draft, account or saved preferences changed while the review was open. Nothing was saved. Review your retained choices again.'); return; }
    busy = true; window.LightworkI18n ? window.LightworkI18n.set(status, 'Saving preferences.') : copy(status,'Saving preferences.');
    var controls = Array.from(form.querySelectorAll('input,select,textarea,button')).map(function (field) { var old = field.disabled; field.disabled = true; return [field,old]; });
    var confirmed = false;
    var bytes = crypto.getRandomValues(new Uint8Array(16));
    var envelope = {scope:reviewedScope, thread:thread, context:reviewedContext, expected_revision:reviewedRevision, changes:submitted,
      operation_id:Array.from(bytes).map(function (item) { return item.toString(16).padStart(2,'0'); }).join('')};
    if (specialistRevision !== undefined) envelope.specialist_revision = specialistRevision;
    try {
      // Keeping the reference across a reload is a courtesy; a browser that refuses storage must not turn a request that was never sent into an "unconfirmed save".
      try { sessionStorage.setItem(recoveryKey, JSON.stringify(envelope)); } catch (_) { /* this page still holds the original */ }
      original = envelope; originalNew.hidden = true;
      originalMessage('Saving the reviewed preferences. If the reply is interrupted, check this original request before another save.');
      var response = await fetch('/api/v1/preferences', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify(envelope)});
      var result = await response.json();
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) clearPrivate();
        if (compare) compare.hidden = response.status !== 409;
        originalMessage('This save is unconfirmed. Check its original result; it will never be repeated automatically.');
        if (response.status !== 401 && response.status !== 403) copy(status,'This save could not be confirmed. Your entered choices are kept. Check the original result before another review.'); return;
      }
      model = result; confirmed = true;
      originalMessage('Your preference save is confirmed.'); originalNew.hidden = false;
      if (!thread) {
        var revision = document.querySelector('meta[name="lightwork-preference-revision"]');
        if (revision) revision.content = model.revision;
        Object.keys(submitted).forEach(function (key) {
          if (['theme','font','density','text_size','glass','interface_language'].indexOf(key) === -1) return;
          if (key!=='interface_language'&&window.mvApplyDisplayPreference) window.mvApplyDisplayPreference(key, model.values[key]);
          var picker = document.querySelector('[data-ui-preference="' + key + '"]');
          if (picker) {picker.value=model.values[key];picker.dataset.savedValue=model.values[key];}
        });
      }
      copy(status,'Preferences saved for {scope}. Future work uses these defaults; running work is unchanged.',{scope:sourceLabel(thread?'conversation':scope.value)});
      if(Object.prototype.hasOwnProperty.call(submitted,'interface_language'))appendCopy(status,'Interface language saved. It applies on your next page load. Save any other drafts before reloading.');
    } catch (error) { copy(status,'Could not confirm this save. Your draft is kept. Check the original result without saving again.'); if (original) originalMessage('This save is unconfirmed. Nothing was repeated.'); if (compare) compare.hidden = false; }
    finally {
      busy = false; controls.forEach(function (item) { item[0].disabled = !model.context || item[1]; });
      if (confirmed) { var newer = editRevision !== submittedRevision ? Object.assign({},changes) : null; render(); if (newer) applyDraft(newer); }
    }
  });
  originalRead.addEventListener('click', async function () {
    if (busy || !original) return;
    busy = true; var selected = original;
    try {
      var response = await fetch('/api/v1/preferences/original', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(selected)});
      var value = await response.json();
      if (selected !== original) return;
      if (response.status === 401 || response.status === 403 || value.state && value.state.context !== selected.context) { clearPrivate(); throw productError('Private preference details were cleared. Reopen this page in the current account.'); }
      if (!response.ok) throw productError('The original save could not be verified. Nothing was repeated.');
      originalMessage(value.message); originalNew.hidden = false;
      var draft = Object.assign({},changes); model = value.state; render(); applyDraft(draft);
    } catch (error) { originalMessage(error.message || 'The original save could not be read. Nothing was repeated.'); }
    finally { busy = false; syncAI(aiEffort && aiEffort.value); }
  });
  originalNew.addEventListener('click', async function () { if (busy || originalNew.hidden) return; if (!(await window.mvConfirm('Keep this original result as read and begin a separate review of your entered choices against the current saved preferences? An unconfirmed earlier save will not be repeated.', {productCopy:true,okText:'Start a fresh review'}))) return; original = null; try { sessionStorage.removeItem(recoveryKey); } catch (_) { /* nothing was kept */ } originalPanel.hidden = true; originalNew.hidden = true; copy(status,'Your entered choices are kept. Review them separately before another save.'); });
  var profileStatus = document.getElementById('personal-profile-status');
  var exportButton = document.getElementById('personal-profile-export'), importButton = document.getElementById('personal-profile-import');
  function profileBusy(value) { if (exportButton) exportButton.disabled = value; if (importButton) importButton.disabled = value; }
  if (exportButton) exportButton.addEventListener('click', async function () {
    if (busy) return; busy = true; profileBusy(true);
    try {
      var response = await fetch('/api/v1/preferences/profile', {cache:'no-store'}), data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Profile could not be exported. Try again.');
      var url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type:'application/json'}));
      var link = document.createElement('a'); link.href = url; link.download = 'lightwork-personal-style-profile.json'; link.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      copy(profileStatus,'Saved preferences exported. Unsaved drafts were excluded.');if(data.excluded.length)appendCopy(profileStatus,'Credential-like guidance was omitted: {fields}.',{fields:data.excluded.map(fieldLabel).join(', ')});
    } catch (error) { copy(profileStatus,knownError(error,'Profile could not be exported. Try again.')); }
    finally { busy = false; profileBusy(false); }
  });
  if (importButton) importButton.addEventListener('click', async function () {
    if (busy) return;
    if (scope.value !== 'personal') { copy(profileStatus,'Choose Personal scope before loading a personal style profile.'); return; }
    var input = document.getElementById('personal-profile-file'), file = input.files[0];
    if (!file) { copy(profileStatus,'Choose a profile file first.'); return; }
    if (file.size > 262144) { copy(profileStatus,'Use a profile smaller than 256 KB.'); return; }
    if (Object.keys(changes).length && !(await window.mvConfirm('Replace your current preference draft with this profile? Nothing saved will change until review.',{productCopy:true,okText:'Replace draft'}))) return;
    busy = true; profileBusy(true); form.inert = true;
    try {
      var response = await fetch('/api/v1/preferences/profile/import', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({profile:JSON.parse(await file.text())})});
      var data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'This profile could not be loaded. Refresh the page and try again.');
      if (data.state.context !== model.context) throw productError('Your account or workspace changed. Reload before importing.');
      model = data.state; render(); applyDraft(data.changes);
      copy(profileStatus,'Profile loaded as a personal draft. Review the before/after changes and save when ready.');
      form.inert = false; form.querySelector('[type="submit"]').focus();
    } catch (error) { copy(profileStatus,knownError(error,'This profile could not be loaded. Refresh the page and try again.')); }
    finally { busy = false; profileBusy(false); form.inert = false; renderPins(); }
  });
  window.addEventListener('beforeunload', function (event) { if (Object.keys(changes).length) { event.preventDefault(); event.returnValue = ''; } });
  render();
  var focusId = window.location.hash.slice(1), focusTarget = document.getElementById(focusId);
  if (focusTarget && form.contains(focusTarget)) { focusTarget.focus(); focusTarget.scrollIntoView({block:'center'}); }
})();
