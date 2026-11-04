// Current native records and file fingerprints stay in the protected ordinary form.
(function () {
  'use strict';
  var app = document.getElementById('pnp-app'), R = window.LwRecords;
  if (!app || !R) return;
  var API = '/api/v1/privacy/notice-proposals', form = document.getElementById('pnp-form');
  var status = document.getElementById('pnp-status'), review = document.getElementById('pnp-review');
  var preview = document.getElementById('pnp-preview'), confirm = document.getElementById('pnp-confirm');
  var save = document.getElementById('pnp-save'), recover = document.getElementById('pnp-readback');
  var source = null, pending = null, busy = false, generation = 0, controllers = new Set();
  var storage = 'lightwork.privacy-notice-proposal.original.v1';
  function say(text) { window.mvStatus ? window.mvStatus(status, text) : (status.textContent = text); }
  function add(tag, text, parent) { var node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (parent) parent.appendChild(node); return node; }
  function valid(start) { return start === generation; }
  function keep() { try { if (pending) sessionStorage.setItem(storage, JSON.stringify({token: pending.token, context: source.context})); else sessionStorage.removeItem(storage); } catch (_) { say('This browser could not keep the original request after reload. Keep this page open until its result is confirmed.'); } }
  function lock(on) {
    busy = on;
    app.querySelectorAll('input,select,button').forEach(function (node) { node.disabled = on; });
    if (!on) { save.disabled = !pending || pending.uncertain || !confirm.checked; document.getElementById('pnp-review-button').disabled = !!(pending && pending.uncertain) || !source; document.getElementById('pnp-refresh').disabled = !!(pending && pending.uncertain); }
  }
  async function call(method, path, body) {
    var controller = new AbortController(), timer = setTimeout(function () { controller.abort(); }, 30000);
    controllers.add(controller);
    try {
      var options = {method: method, credentials: 'same-origin', signal: controller.signal, headers: {Accept: 'application/json'}};
      if (body !== undefined) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
      var response = await fetch(API + path, options);
      if (response.redirected || response.status === 401 || response.status === 403) { clear(); throw new Error('Access changed. Private draft choices were cleared. Return to the original account to check its save.'); }
      var value = await response.json();
      if (!response.ok) { var error = new Error(window.mvPlainDetail && window.mvPlainDetail(value.detail) || 'This request could not be completed. Keep your draft and review the current records.'); error.status = response.status; throw error; }
      return value;
    } finally { clearTimeout(timer); controllers.delete(controller); }
  }
  function fail(error) { say(error && error.status ? error.message : 'The reply could not be confirmed. Keep this page open and check the original save before another attempt.'); }
  function select(id, choices, placeholder) {
    var node = document.getElementById(id), old = node.value; node.replaceChildren(); add('option', placeholder, node).value = '';
    choices.forEach(function (choice) { add('option', choice.label, node).value = choice.value; });
    if (old && !choices.some(function (row) { return row.value === old; })) { var unavailable = add('option', 'Previous choice changed — choose a current record', node); unavailable.value = old; unavailable.disabled = true; }
    node.value = old;
  }
  function checks(id, rows) {
    var group = document.getElementById(id), selected = Array.from(group.querySelectorAll('input:checked')).map(function (node) { return node.value; });
    var legend = group.querySelector('legend'); group.replaceChildren(legend);
    rows.forEach(function (row) { var label = add('label', undefined, group), input = add('input', undefined, label); input.type = 'checkbox'; input.value = row.value; input.checked = selected.includes(row.value); label.appendChild(document.createTextNode(' ' + row.label)); });
    selected.filter(function (value) { return !rows.some(function (row) { return row.value === value; }); }).forEach(function (value) { var label = add('label', undefined, group), input = add('input', undefined, label); input.type = 'checkbox'; input.value = value; input.checked = true; label.appendChild(document.createTextNode(' Previous reference changed — uncheck it and choose a current reference')); });
  }
  async function refresh(expected) {
    if (busy || pending && pending.uncertain) throw new Error('Check the original save before refreshing.');
    var start = generation; lock(true);
    try {
      var state = await call('GET', ''); if (!valid(start)) return false;
      if (expected && expected !== state.context || source && source.context !== state.context) { clear(); throw new Error('Your account or workspace changed. Private draft choices were cleared.'); }
      source = state; select('pnp-notice', state.notices, 'Choose a current notice'); select('pnp-publication', state.publications, 'Choose a current release for this notice');
      checks('pnp-references', state.references.map(function (row) { return {value: row.value, label: row.label + ' · version ' + row.version + ' · ' + row.source_name}; }));
      checks('pnp-reasons', Object.keys(state.reasons).map(function (key) { return {value: key, label: state.reasons[key]}; }));
      if (!document.getElementById('pnp-keep').value) document.getElementById('pnp-keep').value = R.isoDateIn(365);
      say(state.listing_notice + (!state.notices.length ? ' Add a current notice version first.' : !state.references.length ? ' Add material from a currently approved research source first.' : !state.publications.length ? ' Publish consent records for this website or app first.' : ''));
      if (!pending) {
        try { var retained = JSON.parse(sessionStorage.getItem(storage) || 'null'); if (retained && retained.context === state.context && typeof retained.token === 'string') { pending = {token: retained.token, uncertain: true}; recover.hidden = false; say('A previous proposal save needs confirmation. Check the original save before starting another.'); } } catch (_) {}
      }
      return true;
    } finally { if (valid(start)) lock(false); }
  }
  function fullReview(value) {
    preview.replaceChildren(); var d = value.details;
    add('p', d.notice + ' · from version ' + d.base_version, preview); add('p', 'Consent release: ' + d.publication, preview);
    d.files.forEach(function (file) { add('p', file.purpose + ': ' + file.name + ' · ' + file.size + ' bytes · fingerprint only', preview); });
    d.references.forEach(function (ref) { var box = add('article', undefined, preview); add('h4', ref.label + ' · version ' + ref.version, box); add('p', ref.source_name + '. ' + ref.source_notice, box); var list = add('ul', undefined, box); ref.citation_labels.forEach(function (label) { add('li', label, list); }); });
    add('p', 'Reasons: ' + d.reasons.join('; '), preview); add('p', 'Keep until ' + R.day(d.retained_until), preview); add('p', value.message, preview);
    review.hidden = false; confirm.checked = false; recover.hidden = true;
  }
  function drop() { if (pending && pending.uncertain) return; pending = null; review.hidden = true; confirm.checked = false; keep(); lock(false); }
  form.addEventListener('input', function () { if (!busy) drop(); });
  form.addEventListener('submit', async function (event) {
    event.preventDefault(); if (busy || !source || pending && pending.uncertain) return;
    var start = generation; lock(true);
    try {
      var body = {context: source.context, revision: source.revision, notice: document.getElementById('pnp-notice').value, publication: document.getElementById('pnp-publication').value,
        references: Array.from(document.querySelectorAll('#pnp-references input:checked')).map(function (node) { return node.value; }), reasons: Array.from(document.querySelectorAll('#pnp-reasons input:checked')).map(function (node) { return node.value; }), retained_until: R.toEpoch(document.getElementById('pnp-keep').value)};
      for (var key of ['content', 'policy', 'configuration']) { var file = document.getElementById('pnp-' + key).files[0]; if (!file || file.size > 67108864) throw new Error('Choose all three files, each up to 64 MB.'); var fingerprint = await R.fingerprint(file); if (!valid(start)) return; body[key] = {name: file.name, size: file.size, sha256: fingerprint.sha256}; }
      var value = await call('POST', '/review', body); if (!valid(start)) return;
      pending = {token: value.token, uncertain: false}; fullReview(value); say(value.message);
    } catch (error) { if (valid(start)) fail(error); } finally { if (valid(start)) lock(false); }
  });
  confirm.addEventListener('change', function () { lock(false); });
  document.getElementById('pnp-back').addEventListener('click', drop);
  document.getElementById('pnp-refresh').addEventListener('click', function () { drop(); refresh().catch(fail); });
  async function accepted(value) {
    say(value.message); if (value.status !== 'confirmed') return;
    pending = null; keep(); recover.hidden = true; review.hidden = true; form.reset();
    document.dispatchEvent(new CustomEvent('lightwork:notice-proposal-saved')); lock(false);
  }
  save.addEventListener('click', async function () {
    if (busy || !pending || pending.uncertain || !confirm.checked) return;
    var start = generation; pending.uncertain = true; keep(); lock(true); recover.hidden = false;
    try { var value = await call('POST', '/apply', {token: pending.token, confirmed: true}); if (valid(start)) await accepted(value); }
    catch (error) { if (valid(start)) { if (error.status && error.status < 500) { pending.uncertain = false; keep(); review.hidden = true; say(error.message + ' Keep the files and refresh current choices before a new review.'); } else fail(error); } }
    finally { if (valid(start)) lock(false); }
  });
  recover.addEventListener('click', async function () {
    if (busy || !pending) return; var start = generation; lock(true);
    try { var value = await call('POST', '/readback', {token: pending.token}); if (valid(start)) { await accepted(value); if (value.status === 'not_found') { pending = null; keep(); review.hidden = true; recover.hidden = true; } } }
    catch (error) { if (valid(start)) fail(error); } finally { if (valid(start)) lock(false); }
  });
  function clear() { generation++; controllers.forEach(function (c) { c.abort(); }); form.reset(); preview.replaceChildren(); ['pnp-notice','pnp-publication'].forEach(function (id) { document.getElementById(id).replaceChildren(add('option','Choose a current record')); }); document.getElementById('pnp-references').replaceChildren(add('legend', 'Current research references')); document.getElementById('pnp-reasons').replaceChildren(add('legend','Why this changes')); source = null; pending = null; review.hidden = true; recover.hidden = true; lock(false); say('Your account or workspace changed. Private proposal choices were cleared. Return to the original account to check its original save.'); }
  document.addEventListener('lightwork:copilot-context-changed', async function () { if (!source) return; var start = generation; try { var scope = await call('GET','/version-context'); if (valid(start) && source && scope.context !== source.context) clear(); } catch (_) { if (valid(start)) say('Current access could not be checked. The draft is kept; verify your account before continuing.'); } }); window.addEventListener('lightwork:context-changed', clear);
  window.LightworkPrivacyNoticeProposals = {open: async function (context) { if (!/^[a-f0-9]{64}$/.test(context || '')) return false; var ok = await refresh(context); if (ok) { app.scrollIntoView({block: 'start'}); document.getElementById('pnp-notice').focus(); } return ok; }};
  refresh().catch(fail);
}());


// Accepted updates create a separately confirmed native draft version.
(function () {
  'use strict';
  var R=window.LwRecords, form=document.getElementById('png-release-form'); if(!R||!form)return;
  var API='/api/v1/privacy/notice-proposals', select=document.getElementById('png-accepted-proposal'), recover=document.getElementById('png-version-readback');
  var info=document.getElementById('png-accepted-status'), selected=null, records=null, pending=null, busy=false, generation=0;
  var storage='lightwork.notice-version.original.v1';
  function say(text){window.mvStatus(document.getElementById('png-status'),text);}
  function keep(){try{if(pending)sessionStorage.setItem(storage,JSON.stringify(pending));else sessionStorage.removeItem(storage);}catch(_){say('Keep this page open: this browser could not keep the original save after reload.');}}
  function choices(){
    var notice=document.getElementById('png-notice').value,current=records.releases.filter(function(r){return r.notice_id===notice;}).reduce(function(n,r){return Math.max(n,r.version);},0);
    select.replaceChildren();var none=R.el('option','','Create without a suggested update');none.value='';select.appendChild(none);
    records.proposals.filter(function(p){return p.status==='approved'&&p.notice_id===notice&&p.base_version===current;}).forEach(function(p,i){var option=R.el('option','','Accepted update '+(i+1)+' · from version '+p.base_version+' · '+p.reason_codes.map(R.human).join(', '));option.value=p.proposal_id;select.appendChild(option);});
    selected=null;document.getElementById('png-property').readOnly=false;document.getElementById('png-publication').readOnly=false;info.textContent='';
  }
  async function load(){
    var start=generation,state=await R.call('GET','/api/v1/privacy/notices/records');if(start!==generation)return;
    records=state;choices();
    if(!pending){try{var original=JSON.parse(sessionStorage.getItem(storage)||'null');if(original&&original.body&&/^[a-f0-9]{64}$/.test(original.context)){pending=original;recover.hidden=false;say('A previous version save needs confirmation. Check the original version save before starting another.');}}catch(_){}}
  }
  document.getElementById('png-new-version').addEventListener('click',function(){load().catch(function(e){say(R.errorText(e,'load accepted updates'));});});
  document.getElementById('png-notice').addEventListener('change',function(){if(records)choices();});
  select.addEventListener('change',async function(){
    var identity=select.value,start=++generation;selected=null;if(!identity){choices();return;}
    try{var card=await R.call('GET',API+'/proposal?identity='+encodeURIComponent(identity));if(start!==generation||identity!==select.value)return;
      if(card.status!=='approved'||card.notice_id!==document.getElementById('png-notice').value){info.textContent='Choose a current accepted update.';return;}
      selected={id:identity,card:card};document.getElementById('png-property').value=R.human(card.property_id);document.getElementById('png-property').readOnly=true;
      document.getElementById('png-publication').value='The accepted update’s recorded consent release';document.getElementById('png-publication').readOnly=true;
      info.textContent='Choose the exact three original files. Their fingerprints must match this accepted update. Saving creates a draft version; its own role approvals and publishing are separate.';
    }catch(error){if(start===generation)info.textContent=R.errorText(error,'read the accepted update');}
  });
  recover.addEventListener('click',async function(){
    if(!pending||busy)return;var start=generation;busy=true;
    try{var value=await R.call('POST',API+'/version-readback',Object.assign({context:pending.context,notice_id:pending.notice},pending.body));if(start!==generation)return;say(value.message);
      if(value.status==='confirmed'||value.status==='not_found'){pending=null;keep();recover.hidden=true;document.dispatchEvent(new CustomEvent('lightwork:notice-proposal-saved'));}}
    catch(error){if(start===generation)say(R.errorText(error,'check the original version save'));}finally{busy=false;}
  });
  function checked(name){return Array.from(form.querySelectorAll('input[name="'+name+'"]:checked')).map(function(node){return node.value;});}
  window.LightworkPrivacyNoticeVersions={save:async function(){
    if(busy)return;if(pending){say('Check the original version save before saving another.');return;}
    var existing=document.getElementById('png-notice').value,newName=(document.getElementById('png-notice-name').value||'').trim();
    if(!existing&&!newName){say('Choose a notice or name the new notice.');return;}
    var notice=existing||R.slug(newName,'privacy-notice'),jur=checked('jurisdiction'),loc=checked('locale');
    var from=R.toEpoch(document.getElementById('png-from').value),until=R.toEpoch(document.getElementById('png-until').value),keepUntil=R.toEpoch(document.getElementById('png-keep').value);
    if(!jur.length||!loc.length||!from||!until||!keepUntil||until<=from||keepUntil<until){say('Choose jurisdictions and languages, then check the effective and keep-until dates.');return;}
    var files=['png-file-content','png-file-policy','png-file-config'].map(function(id){return document.getElementById(id).files[0];});
    if(files.some(function(file){return !file||file.size>67108864;})){say('Choose all three files, each up to 64 MB.');return;}
    if(select.value&&!selected){say('Wait for the accepted update to be read.');return;}
    var start=generation,update=selected;busy=true;
    try{
      var context=await R.call('GET',API+'/version-context'),fps=await Promise.all(files.map(R.fingerprint));if(start!==generation)return;
      if(update&&(update.card.context!==context.context||update.card.content_sha256!==fps[0].sha256||update.card.policy_sha256!==fps[1].sha256||update.card.configuration_sha256!==fps[2].sha256)){say('The account or selected files do not match the accepted update. Keep the originals and select the correct files.');return;}
      var latest=(records?records.releases:[]).filter(function(r){return r.notice_id===notice;}).reduce(function(n,r){return Math.max(n,r.version);},0);
      var body={expected_context:context.context,property_id:update?update.card.property_id:R.slug(document.getElementById('png-property').value,'website'),jurisdictions:jur,locales:loc,content_sha256:fps[0].sha256,policy_sha256:fps[1].sha256,configuration_sha256:fps[2].sha256,consent_publication_ref:update?update.card.publication:R.slug(document.getElementById('png-publication').value,'consent-release'),approval_policy_id:document.getElementById('png-policy').value,effective_from:from-86399,effective_until:until,retained_until:keepUntil,update_proposal_ref:update?update.id:null,expected_latest_version:latest,idempotency_key:R.newKey()};
      var ok=await R.confirm('Save '+R.human(notice)+' as draft version '+(latest+1)+'? Files: '+files.map(function(file){return file.name;}).join('; ')+'. Applies in '+jur.map(R.human).join(', ')+'; languages '+loc.join(', ')+'. Effective '+R.day(from)+' through '+R.day(until)+'. Keep until '+R.day(keepUntil)+'. '+(update?'Uses the selected accepted proposal and its exact recorded fingerprints. ':'')+'Original files are not retained. This does not approve or publish the version.','Save draft version');
      if(!ok||start!==generation)return;
      pending={context:context.context,notice:notice,body:body};keep();recover.hidden=false;
      await R.call('PUT','/api/v1/privacy/notices/releases/'+encodeURIComponent(notice)+'/versions',body);if(start!==generation)return;
      pending=null;keep();recover.hidden=true;document.getElementById('png-release-panel').hidden=true;form.reset();say('Version saved as a draft. Its own approvals and publishing are separate.');document.dispatchEvent(new CustomEvent('lightwork:notice-proposal-saved'));
    }catch(error){if(start!==generation)return;if(error&&error.status>=400&&error.status<500){pending=null;keep();recover.hidden=true;}say(R.errorText(error,'save the version')+(pending?' Check the original version save before another attempt.':''));}finally{busy=false;}
  }};
  function clear(){generation++;selected=null;pending=null;form.reset();select.replaceChildren();recover.hidden=true;info.textContent='Your account or workspace changed. Private version choices were cleared. Return to the original account to check its pending save.';}
  window.addEventListener('lightwork:context-changed',clear);
}());
