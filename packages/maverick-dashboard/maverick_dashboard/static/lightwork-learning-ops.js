// Learning page: run, check and review controls for each learning system
// (improvement flywheel, agent-building guidance, practising code changes,
// specialist model planning, the reward model, the agents' shorthand, and
// task outlines waiting to be shared). Long work runs as a background job.
(function () {
  'use strict';
  var root = document.getElementById('lo-root');
  if (!root || !window.LWJobs) return;
  var J = window.LWJobs;
  var el = J.el, plural = J.plural;
  var admin = root.getAttribute('data-admin') === '1';
  var LO = '/api/v1/learning-ops', TO = '/api/v1/training-ops';
  function $(id) { return document.getElementById(id); }
  function ui(prefix, action, render, after) {
    return { status: $(prefix + '-status'), out: $(prefix + '-out'), action: action, render: render, after: after };
  }
  function fill(id, nodes) {
    var box = $(id);
    if (!box) return;
    box.textContent = '';
    (Array.isArray(nodes) ? nodes : [nodes]).forEach(function (n) { if (n) box.appendChild(n); });
  }
  function list(items) {
    var ul = el('ul');
    items.forEach(function (t) { ul.appendChild(el('li', null, t)); });
    return ul;
  }
  function options(select, items, chosen) {
    if (!select) return;
    select.textContent = '';
    items.forEach(function (it) {
      var o = el('option', null, it.label);
      o.value = String(it.value);
      if (chosen != null && String(it.value) === String(chosen)) o.selected = true;
      select.appendChild(o);
    });
  }
  function radio(name) {
    var picked = root.querySelector('input[name="' + name + '"]:checked');
    return picked ? picked.value : '';
  }
  async function fileBody(input, missing) {
    var file = input && input.files && input.files[0];
    if (!file) { window.mvToast(missing, { error: true }); return null; }
    return J.readFile(file);
  }

  // ---- complete factory comparison and separately reviewed adoption ------------
  var fa = $('lo-factory'), faCurrent = null, faRestore = null, faReview = null, faOriginal = '', faResult = null;
  var faBusy = false, faGeneration = 0, faHeld = false, faPoll = null, faRequests = new Set();
  function faSay(text) { $('lo-fa-status').textContent = text; }
  function faSync() {
    if (!$('lo-fa-form')) return;
    $('lo-fa-preview').disabled = faBusy;
    $('lo-fa-compare').disabled = faBusy || faHeld || faResult?.job?.worker_available || !faCurrent?.enabled || !$('lo-fa-suggestion').value || !$('lo-fa-consent').checked;
    $('lo-fa-apply').disabled = faBusy || faHeld && faReview?.action!=='restore' || faResult?.job?.worker_available || !faReview || !$('lo-fa-reviewed').checked;
    $('lo-fa-read').disabled = faBusy || !faOriginal;
    $('lo-fa-adopt').disabled = faBusy || faHeld || faResult?.job?.worker_available || !faCurrent?.enabled || !faResult?.confirmed || !faResult?.source_visible || !faResult?.result?.pairs;
    $('lo-fa-original').disabled = faBusy;
    $('lo-fa-restore-refresh').disabled = faBusy;
    $('lo-fa-restore-choice').disabled = faBusy;
    $('lo-fa-restore').disabled = faBusy || faResult?.job?.worker_available || !$('lo-fa-restore-choice').value;
  }
  function faInvalidate() {
    faGeneration++; clearTimeout(faPoll); faRequests.forEach(function(controller){controller.abort();});faRequests.clear(); faCurrent = faRestore = faReview = faResult = null; faOriginal = ''; faHeld = false; faBusy = false;
    ['lo-fa-out','lo-fa-review-rows','lo-fa-requests'].forEach(function(id){$(id)?.replaceChildren();});
    $('lo-fa-form')?.reset(); $('lo-fa-suggestion')?.replaceChildren(new Option('Choose current guidance',''));
    $('lo-fa-original')?.replaceChildren(new Option('Choose a recorded decision',''));
    $('lo-fa-restore-choice')?.replaceChildren(new Option('Choose a guidance change to undo',''));$('lo-fa-restore-notice').textContent='';
    if ($('lo-fa-review')) $('lo-fa-review').hidden = true;
    faSay('Your account or workspace changed. Refresh current suggestions.'); faSync();
  }
  async function faRequest(path, body, options) {
    options=options||{};var controller=new AbortController(),timer=setTimeout(function(){controller.abort();},30000);faRequests.add(controller);
    try{var response=await fetch((options.copilot?'/api/v1/copilot/product-operations':LO+'/factory')+path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',signal:controller.signal,
      headers:body?{'Content-Type':'application/json'}:{},body:body?(options.raw?body:JSON.stringify(body)):undefined});
      var text=await response.text();if(text.length>6*1024*1024)throw Error('The complete reply is too large. Read its original before another decision.');
      var value;try{value=JSON.parse(text);}catch(_){value={};}
      if(response.redirected||[401,403].includes(response.status)){faInvalidate();throw Error('Your current permission is unavailable. Ask an administrator.');}
      if(!response.ok)throw Error(typeof value.detail==='string'?value.detail:'The original reply is unavailable. Read the recorded result before a separate decision.');
      if(!options.copilot&&(faCurrent||faRestore)&&value.context&&(faCurrent||faRestore).context!==value.context){faInvalidate();throw Error('Your account or workspace changed. Refresh current choices.');}
      return value;
    }catch(error){if(error.name==='AbortError')throw Error('The reply did not arrive within 30 seconds. Read the original result before another decision.');throw error;}
    finally{clearTimeout(timer);faRequests.delete(controller);}
  }
  function faRenderReview(container, changes) {
    if(!Array.isArray(changes)||changes.length>200||JSON.stringify(changes).length>240000)throw Error('The complete review is too large. Nothing was shortened.');
    container.replaceChildren();
    changes.forEach(function(row){var keys=Object.keys(row||{}).sort().join('|');
      if(!['after|label','after|before|label'].includes(keys)||typeof row.label!=='string'||typeof row.after!=='string'||('before'in row&&typeof row.before!=='string'))throw Error('A complete readable review row is missing. Nothing can be confirmed.');
      var box=el('section'),heading=el('h4',null,row.label);box.append(heading);
      if('before'in row){var before=el('p',null,'Current: '+row.before);before.style.whiteSpace='pre-wrap';box.append(before);}
      var after=el('p',null,('before'in row?'Proposed: ':'')+row.after);after.style.whiteSpace='pre-wrap';after.style.overflowWrap='anywhere';box.append(after);container.append(box);
    });return true;
  }
  function faChanged() { faReview=null;$('lo-fa-review').hidden=true;$('lo-fa-reviewed').checked=false;faSync(); }
  function faStamp(){return JSON.stringify(Array.from($('lo-fa-form').elements).filter(function(input){return ['INPUT','SELECT','TEXTAREA'].includes(input.tagName);}).map(function(input){return [input.id,input.value,input.checked];}).concat([['restoration',$('lo-fa-restore-choice').value]]));}
  function faSelectSuggestion(retain) {
    var item=faCurrent?.corrections.find(function(row){return row.key===$('lo-fa-suggestion').value;});
    var chosen=retain?Array.from($('lo-fa-requests').querySelectorAll('input:checked')).map(function(input){return input.value;}):[];
    $('lo-fa-requests').replaceChildren();$('lo-fa-suggestion-help').textContent=item?(item.guidance+' '+item.why):'Choose one current suggestion.';
    if(item)item.packs.forEach(function(name){var label=el('label'),input=el('input');input.type='checkbox';input.value=name;input.checked=chosen.includes(name);label.append(input,document.createTextNode(' '+(window.mvHuman?window.mvHuman(name):name)));$('lo-fa-requests').append(label);});
    faChanged();
  }
  async function faLoad(preserve) {
    if(faBusy)return false;var started=++faGeneration;faBusy=true;faSync();
    try{var value=await faRequest('/catalog?min_support='+encodeURIComponent($('lo-fa-support').value));if(started!==faGeneration)return false;
      if(faCurrent&&faCurrent.context!==value.context){faInvalidate();return false;}
      var old=$('lo-fa-suggestion').value;faCurrent=value;
      options($('lo-fa-suggestion'),[{value:'',label:'Choose current guidance'}].concat(value.corrections.map(function(row){return {value:row.key,label:row.guidance+(row.supported?'':' / '+row.why)};})),preserve?old:'');
      Array.from($('lo-fa-suggestion').options).forEach(function(option){var row=value.corrections.find(function(item){return item.key===option.value;});if(row&&!row.supported)option.disabled=true;});
      faSelectSuggestion(!!preserve);
      options($('lo-fa-original'),[{value:'',label:'Choose a recorded decision'}].concat(value.requests),faOriginal);
      if(faOriginal&&!value.requests.some(function(row){return row.value===faOriginal;})){$('lo-fa-original').append(new Option('Original awaiting readback',faOriginal));$('lo-fa-original').value=faOriginal;}
      faSay(value.notice+' Current AI service: '+value.model+'. '+(value.enabled?'':'Turn on agent-building improvements to admit new work. Original reads remain available.'));
      return true;
    }catch(error){if(started===faGeneration)faSay(error.message);return false;}
    finally{if(started===faGeneration){faBusy=false;faSync();}}
  }
  function faShow(value){faResult=value;faSay(value.message);var nodes=[];
    var labels={baseline_score:'Current guidance tool-check score',candidate_score:'Proposed guidance tool-check score',samples:'Complete paired requests',effect_ci_low:'Conservative difference estimate',adopted:'Guidance adopted',restored:'Earlier guidance restored'};
    Object.keys(labels).forEach(function(key){if(value.result&&key in value.result)nodes.push(el('p',null,labels[key]+': '+(typeof value.result[key]==='boolean'?(value.result[key]?'Yes':'No'):String(value.result[key]))));});
    if(value.result?.pairs){var rows=value.result.comparison_rows||value.result.pairs.map(function(pair,index){return {label:'Request '+(index+1)+': '+pair.request.replace(/_/g,' '),before:faCapabilities(pair.baseline),after:faCapabilities(pair.candidate)};});var box=el('div');faRenderReview(box,rows);nodes.push(box);}
    if(value.result?.restoration_rows){var restoration=el('div');faRenderReview(restoration,value.result.restoration_rows);nodes.push(restoration);}
    if(value.job?.problem)nodes.push(el('p',null,value.job.problem));
    if(!value.result?.restored&&!value.result?.restoration_rows)nodes.push(el('p','muted','These local checks show whether the expected action remains allowed in an unsaved setup. Reported requests and expected actions do not establish overall quality, business value or independently measured improvement.'));
    if(value.task_href){var link=el('a','btn btn--ghost','Read current progress and stop controls');link.href=value.task_href;nodes.push(link);}fill('lo-fa-out',nodes);faHeld=!value.confirmed;faSync();
  }
  function faCapabilities(value){var names={code_exec:'Run code',shell:'Run a command in the protected work area',browser:'Browse websites',computer:'Control a desktop',clipboard:'Use the clipboard',read_file:'Read a workspace file',write_file:'Create or replace a workspace file',delete_file:'Delete a file',edit_file:'Edit a file',web_search:'Search the web'};function name(key){return names[key]||(window.mvHuman?window.mvHuman(key):key.replace(/_/g,' '));}return 'Expected action: '+(value.passed?'Allowed':'Not allowed')+'\nAllowed actions: '+value.allowed_tools.map(name).join(', ')+'\nActions it cannot use: '+value.denied_tools.map(name).join(', ')+'\nMaximum risk: '+value.maximum_risk;}
  function faRemember(){try{sessionStorage.setItem('lightwork.factory.original.'+(faCurrent||faRestore).context,faOriginal);}catch(_){} }
  async function faRead(){if(faBusy||!faOriginal)return;clearTimeout(faPoll);var started=++faGeneration,operation=faOriginal;faBusy=true;faReview=null;$('lo-fa-review').hidden=true;$('lo-fa-reviewed').checked=false;faSync();
    try{var value=await faRequest('/original/'+encodeURIComponent(operation));if(started!==faGeneration||operation!==faOriginal)return;faShow(value);if(value.job?.worker_available)faPoll=setTimeout(faRead,2000);}
    catch(error){if(started===faGeneration){faSay(error.message);$('lo-fa-out').replaceChildren();faResult=null;}}
    finally{if(started===faGeneration){faBusy=false;faSync();}}
  }
  async function faPrepare(action,values){if(faBusy||faHeld&&action!=='restore')return;var started=++faGeneration,entered=faStamp();clearTimeout(faPoll);faBusy=true;faReview=null;$('lo-fa-reviewed').checked=false;faSync();
    try{var value=await faRequest('/review',{action:action,values:values});if(started!==faGeneration)return;if(entered!==faStamp()){faSay('Your entered work changed. Review it again before continuing.');return;}
      if(value.context!==(faCurrent||faRestore)?.context){faInvalidate();return;}faRenderReview($('lo-fa-review-rows'),value.changes);faReview=value;$('lo-fa-review').hidden=false;
      $('lo-fa-apply').textContent=action==='restore'?'Restore this reviewed guidance':action==='adopt'?'Adopt this reviewed guidance':'Start this reviewed comparison';$('lo-fa-review').focus();faSay('Review every complete request, expected result and consequence. Nothing has started.');
    }catch(error){if(started===faGeneration)faSay(error.message);}finally{if(started===faGeneration){faBusy=false;faSync();}}
  }
  async function faLoadRestores(){
    if(faBusy)return false;var generation=++faGeneration;faBusy=true;faSync();
    try{var value=await faRequest('/restore-options');if(generation!==faGeneration)return false;
      var selected=$('lo-fa-restore-choice').value;faRestore=value;
      options($('lo-fa-restore-choice'),[{value:'',label:'Choose a guidance change to undo'}].concat(value.choices),selected);
      $('lo-fa-restore-notice').textContent=value.notice;
      options($('lo-fa-original'),[{value:'',label:'Choose a recorded decision'}].concat(value.requests),faOriginal);
      if(faOriginal&&!value.requests.some(function(row){return row.value===faOriginal;})){$('lo-fa-original').append(new Option('Original awaiting readback',faOriginal));$('lo-fa-original').value=faOriginal;}
      if(faReview?.action==='restore')faChanged();return true;
    }catch(error){if(generation===faGeneration)$('lo-fa-restore-notice').textContent=error.message;return false;}
    finally{if(generation===faGeneration){faBusy=false;faSync();}}
  }
  async function faOpenAuthor(_details,options){options=options||{};if(typeof options.isCurrent==='function'&&!options.isCurrent())return false;
    if(!fa||!$('lo-fa-form')||faBusy||typeof options.isCurrent!=='function'||!options.isCurrent()||!/^[a-f0-9]{64}$/.test(options.context||''))return false;
    var before=faGeneration,stamp=faStamp();
    var checked=await faRequest('/catalog',{page:'/learning',selection:{}},{copilot:true});
    if(before!==faGeneration||!options.isCurrent()||checked.context!==options.context||!(checked.operations||[]).some(function(row){return row.id==='learning.factory_guidance_form'&&row.available;})||stamp!==faStamp())return false;
    if(!faCurrent&&!await faLoad(true))return false;
    if(!options.isCurrent()||faBusy)return false;
    var generation=faGeneration;var fresh=await faRequest('/catalog?min_support='+encodeURIComponent($('lo-fa-support').value));
    if(generation!==faGeneration||fresh.context!==faCurrent.context||stamp!==faStamp()||typeof options.isCurrent==='function'&&!options.isCurrent())return false;
    if(fresh.revision!==faCurrent.revision){faChanged();faSay('Current source changed. Refresh suggestions; your entered work is kept.');return false;}
    if(!options.isCurrent())return false;$('lo-fa-form').scrollIntoView({block:'start'});$('lo-fa-suggestion').focus();return options.isCurrent();
  }
  window.LWFactoryGuidance={renderReview:faRenderReview,openAuthor:faOpenAuthor};
  if(admin&&$('lo-fa-form')){
    $('lo-fa-preview').addEventListener('click',function(){faChanged();faLoad(true);});
    $('lo-fa-suggestion').addEventListener('change',function(){faSelectSuggestion(false);});
    $('lo-fa-form').addEventListener('input',faChanged);$('lo-fa-support').addEventListener('change',function(){faChanged();faLoad(true);});
    $('lo-fa-form').addEventListener('submit',function(event){event.preventDefault();if(!faCurrent||faHeld)return;
      faPrepare('compare',{context:faCurrent.context,revision:faCurrent.revision,min_support:Number($('lo-fa-support').value),correction:$('lo-fa-suggestion').value,
        packs:Array.from($('lo-fa-requests').querySelectorAll('input:checked')).map(function(input){return input.value;}),dollars:Number($('lo-fa-dollars').value),seconds:Number($('lo-fa-seconds').value),authorize_input_use:$('lo-fa-consent').checked});});
    $('lo-fa-reviewed').addEventListener('change',faSync);$('lo-fa-dismiss').addEventListener('click',faChanged);
    $('lo-fa-apply').addEventListener('click',async function(){if(faBusy||faHeld&&faReview?.action!=='restore'||!faReview||!$('lo-fa-reviewed').checked)return;
      var review=faReview,started=++faGeneration;faReview=null;faBusy=true;faHeld=true;faOriginal=review.operation;faRemember();$('lo-fa-original').append(new Option('Original reviewed decision',faOriginal));$('lo-fa-original').value=faOriginal;
      $('lo-fa-review').hidden=true;$('lo-fa-reviewed').checked=false;faSync();
      try{var value=await faRequest('/apply',{token:review.token,confirmed:true});if(started===faGeneration)faShow(value);}
      catch(error){if(started===faGeneration)faSay(error.message+' Read the original result. This decision will not be submitted again automatically.');}
      finally{if(started===faGeneration){faBusy=false;faSync();faRead();}}});
    $('lo-fa-original').addEventListener('change',function(){faGeneration++;clearTimeout(faPoll);faOriginal=$('lo-fa-original').value;faResult=null;faHeld=false;faChanged();$('lo-fa-out').replaceChildren();if(faOriginal)faRemember();faRead();});
    $('lo-fa-restore-refresh').addEventListener('click',faLoadRestores);
    $('lo-fa-restore-choice').addEventListener('change',faChanged);
    $('lo-fa-restore').addEventListener('click',function(){faPrepare('restore',{adoption:$('lo-fa-restore-choice').value});});
    $('lo-fa-read').addEventListener('click',faRead);$('lo-fa-adopt').addEventListener('click',function(){faPrepare('adopt',{operation:faOriginal});});
    $('lo-fa-import').addEventListener('click',async function(){if(faBusy)return;var generation=++faGeneration,body=await fileBody($('lo-fa-file'),'Choose an existing report first.');if(!body||generation!==faGeneration)return;
      try{var value=await faRequest('/report',body,{raw:true});if(generation!==faGeneration)return;
        faRenderReview($('lo-fa-out'),value.rows);faSay('Imported report inspected only. Its reported scores do not become a native comparison or adopt guidance.');}
      catch(error){if(generation===faGeneration)faSay(error.message);}});
    document.addEventListener('lightwork:workspace-changed',faInvalidate);document.addEventListener('lightwork:account-context-changed',faInvalidate);
    window.addEventListener('lightwork:context-changed',function(event){if(event.detail?.reason!=='selection')faInvalidate();});document.addEventListener('lightwork:copilot-context-changed',function(event){if(event.detail?.reason!=='selection')faInvalidate();});
    window.addEventListener('pagehide',function(){faGeneration++;clearTimeout(faPoll);faRequests.forEach(function(controller){controller.abort();});faRequests.clear();});
    faLoad(false).then(faLoadRestores).then(function(ok){if(!ok&&!faCurrent)return;var requested=new URLSearchParams(location.search).get('factory_original');try{faOriginal=requested||sessionStorage.getItem('lightwork.factory.original.'+(faCurrent||faRestore).context)||'';}catch(_){faOriginal=requested||'';}if(/^[a-f0-9]{32}$/.test(faOriginal)){$('lo-fa-original').append(new Option('Original retained decision',faOriginal));$('lo-fa-original').value=faOriginal;faRead();}else faOriginal='';faSync();});
  }

  // ---- practise changes to its own code -------------------------------------------
  var smGeneration = 0, smLocked = false, smBusy = false, smCurrent = null, smHeld = null, smPending = false, smReader = null;
  function lockCodePractice() {
    smGeneration++; smLocked = true; smCurrent = null;
    var form = $('lo-sm-form');
    if (form) Array.from(form.elements).forEach(function (field) { if ('value' in field && field.tagName !== 'BUTTON') field.value = ''; field.disabled = true; });
    if (form) delete form.dataset.limit;
    ['lo-sm-state', 'lo-sm-results', 'lo-sm-out'].forEach(function (id) { if ($(id)) fill(id, []); });
    if ($('lo-sm-status')) $('lo-sm-status').textContent = 'Your account, workspace or access changed. Reload Learning before reviewing practice work.';
    if (smReader) smReader.disabled = true;
  }
  function practiceStamp() { return JSON.stringify([$('lo-sm-objective')?.value, $('lo-sm-cycles')?.value]); }
  function loadModify() {
    if (!$('lo-sm-state') || smLocked) return Promise.resolve(false);
    var started = smGeneration;
    return Promise.all([J.request(LO + '/self-modify').then(function (d) {
      if (smLocked || started !== smGeneration) return false;
      smCurrent = d;
      var nodes = [];
      var badge = el('span', 'badge' + (d.state === 'ready' ? ' active' : ''), d.state === 'ready' ? 'On and ready' : (d.state === 'blocked' ? 'On, but something is blocking it' : 'Off'));
      var head = el('p');
      head.appendChild(badge);
      nodes.push(head);
      if (d.blockers.length) { nodes.push(el('p', null, 'Before it can run:')); nodes.push(list(d.blockers)); }
      nodes.push(el('p', null, 'It may practise on ' + plural(d.areas, 'area') + ' of its own code' +
        (d.level ? ' (level: ' + d.level + ')' : '') + '. ' + plural(d.results, 'result') + ' kept for review.'));
      nodes.push(el('p', 'muted', d.spending_limit != null ? 'Each run can spend up to ' + J.money(d.spending_limit) + '.'
        : 'No spending limit is set for this experiment, so the general task limits apply.'));
      nodes.push(J.technical(d.technical.areas, 'Technical details: areas it may change'));
      fill('lo-sm-state', nodes);
      var form = $('lo-sm-form');
      if (form) form.dataset.limit = d.spending_limit != null ? String(d.spending_limit) : '';
      if (!smHeld) {
        try { var held = JSON.parse(sessionStorage.getItem('lightwork.code-practice.original.' + d.context) || 'null');
          if (held && /^[a-f0-9]{16}$/.test(held.id) && held.context === d.context) { smHeld = held; smPending = true; }
        } catch (_) { /* an unavailable browser record does not imply a failed task */ }
      }
      if (smReader) smReader.disabled = smBusy || !smHeld;
      if ($('lo-sm-run')) $('lo-sm-run').disabled = smBusy || smPending;
      return true;
    }).catch(async function (failure) {
      if (smLocked || started !== smGeneration) return false;
      if ([401, 403].includes(failure.status)) { lockCodePractice(); return false; }
      var problem = await J.problem(failure, 'load the experiment');
      if (!smLocked && started === smGeneration) fill('lo-sm-state', el('p', null, problem));
      return false;
    }), J.request(LO + '/self-modify/results?limit=20').then(function (d) {
      if (smLocked || started !== smGeneration) return false;
      if (!d.results.length) { fill('lo-sm-results', el('p', 'muted', 'No results yet. Start practice rounds below.')); return true; }
      fill('lo-sm-results', J.table(['When', 'Round', 'Score before', 'Score after', 'What it tried', 'Notes'], d.results.map(function (r) {
        var notes = [];
        if (r.undone) notes.push('undone');
        if (r.widens) notes.push('would need more access');
        return [J.when(r.when), String(r.round), r.before.toFixed(3), r.score.toFixed(3), r.summary, notes.join(', ') || '—'];
      })));
      return true;
    }).catch(async function (failure) {
      if (smLocked || started !== smGeneration) return false;
      if ([401, 403].includes(failure.status)) { lockCodePractice(); return false; }
      var problem = await J.problem(failure, 'load the results');
      if (!smLocked && started === smGeneration) fill('lo-sm-results', el('p', null, problem));
      return false;
    })]).then(function (results) { return !smLocked && started === smGeneration && results.every(Boolean); });
  }
  var smForm = $('lo-sm-form');
  function practiceResult(d) {
    var out = [], rounds = Array.isArray(d.rounds) ? d.rounds : [];
    if (!d.ran) out.push(el('p', null, d.problem || 'The experiment did not report a completed practice run. Read its original result before deciding what to do next.'));
    else out.push(el('p', null, 'Tested ' + plural(d.tested, 'change') + ' across ' + plural(rounds.length, 'round') + '. Spent ' + J.money(d.spent) + '.'));
    if (rounds.length) out.push(J.technical(rounds.map(function (r, i) {
      return 'Round ' + (i + 1) + ': ' + r.ideas + ' idea(s), ' + r.tested + ' tested' + (r.note ? ' — ' + r.note : '');
    })));
    return out;
  }
  function keepPracticeOriginal(id, context) {
    smHeld = {id:id, context:context}; smPending = true;
    try { sessionStorage.setItem('lightwork.code-practice.original.' + context, JSON.stringify(smHeld)); } catch (_) { /* the visible reader remains available */ }
    if (smReader) smReader.disabled = smBusy;
  }
  async function readPracticeOriginal() {
    if (smLocked || smBusy || !smHeld) return;
    var started = smGeneration; smBusy = true; smReader.disabled = true; $('lo-sm-run').disabled = true;
    try {
      var original = await J.request(LO + '/self-modify/original/' + encodeURIComponent(smHeld.id));
      if (smLocked || started !== smGeneration || original.context !== smHeld.context) return;
      var job = await J.follow(original.job, ui('lo-sm', 'read the original practice task', practiceResult));
      if (smLocked || started !== smGeneration) return;
      if (job) {
        smPending = false;
        var review = el('details'); review.append(el('summary', null, 'What this original task was asked to do'),
          el('p', null, original.review.objective), el('p', null, plural(original.review.cycles, 'practice round') + '. Model shown when reviewed: ' + original.review.model + '.'));
        $('lo-sm-out').append(review);
      }
    } catch (failure) {
      if (started !== smGeneration || smLocked) return;
      if ([401,403].includes(failure.status)) { lockCodePractice(); return; }
      $('lo-sm-status').textContent = await J.problem(failure, 'read the original practice task') + ' No work was repeated. An unavailable original does not prove the work failed.';
    } finally {
      smBusy = false; smReader.disabled = smLocked || !smHeld; $('lo-sm-run').disabled = smLocked || smPending;
    }
  }
  if (smForm) {
    smReader = el('button', 'btn btn--ghost', 'Read original practice task'); smReader.type = 'button'; smReader.disabled = true;
    smForm.insertAdjacentElement('afterend', smReader); smReader.addEventListener('click', readPracticeOriginal);
  }
  window.LightworkLearningOps = {
    openCodePractice: async function (context, isCurrent) {
      if (!smForm || !admin || smLocked || smBusy || !/^[a-f0-9]{64}$/.test(context) ||
          typeof isCurrent !== 'function' || !isCurrent()) return false;
      var started = smGeneration, entered = practiceStamp();
      try {
        if (!await loadModify() || !isCurrent() || started !== smGeneration) return false;
        var catalog = await J.request('/api/v1/copilot/product-operations/catalog', {method:'POST', json:{page:'/learning', selection:{}}});
        if (smLocked || !isCurrent() || started !== smGeneration) return false;
        var operation = catalog.operations.find(function (row) { return row.id === 'learning.code_practice_form' && row.available; });
        if (!operation) return false;
        var prepared = await J.request('/api/v1/copilot/product-operations/prepare', {method:'POST', json:{page:'/learning', selection:{},
          operation:operation.id, context:catalog.context, revision:operation.revision, arguments:{}}});
        var checked = prepared.details?.learning_code_practice_form;
        if (smLocked || started !== smGeneration || !isCurrent() || !checked || Object.keys(checked).join(',') !== 'context' || checked.context !== context) return false;
        if (practiceStamp() !== entered) { $('lo-sm-status').textContent = 'Your practice objective or rounds changed while access was checked. They were kept; open the form again when ready.'; return false; }
        for (var section = smForm.parentElement; section && section !== root; section = section.parentElement) if (section.tagName === 'DETAILS') section.open = true;
        $('lo-sm-objective').focus();
        return true;
      } catch (failure) {
        if (!smLocked && started === smGeneration && [401, 403].includes(failure.status)) lockCodePractice();
        return false;
      }
    }
  };
  if (smForm) smForm.addEventListener('submit', async function (ev) {
    ev.preventDefault();
    if (smLocked || smBusy || smPending || !smCurrent) return;
    var objective = $('lo-sm-objective').value;
    if (objective.length < 10) { $('lo-sm-status').textContent = 'Describe what it should try to improve, in a sentence.'; return; }
    var cycles = Number($('lo-sm-cycles').value);
    var started = smGeneration, entered = practiceStamp(), current = smCurrent;
    var body = {objective:objective, cycles:cycles, context:current.context, revision:current.revision};
    var btn = $('lo-sm-run'); smBusy = true; btn.disabled = true; smReader.disabled = true;
    try {
      var reviewed = await J.request(LO + '/self-modify/review', {method:'POST', json:body});
      if (smLocked || started !== smGeneration) return;
      if (practiceStamp() !== entered) { $('lo-sm-status').textContent = 'Your newer objective or rounds were kept. Review them again before starting.'; return; }
      var limit = reviewed.review.spending_limit;
      var cost = limit != null ? ' It can spend up to ' + J.money(limit) + '.' : ' The current task spending limits apply.';
      if (!await window.mvConfirm('Start ' + plural(cycles, 'practice round') + '? Current model: ' + reviewed.review.model + '.\n\n' + objective +
        '\n\nLightwork writes changes to a copy of its own code, tests them in the practice area and keeps the results for review. Nothing is installed.' + cost,
        {okText:'Start rounds'})) return;
      if (smLocked || started !== smGeneration) return;
      if (practiceStamp() !== entered) { $('lo-sm-status').textContent = 'Your newer objective or rounds were kept. Review them again before starting.'; return; }
      keepPracticeOriginal(reviewed.job_id, current.context);
      $('lo-sm-status').textContent = 'Starting this reviewed task. Its original can be read here even if the reply is interrupted.';
      var reply = await J.request(LO + '/self-modify/run', {method:'POST', json:{...body, token:reviewed.token, confirm:true}});
      if (smLocked || started !== smGeneration) return;
      var job = await J.follow(reply.job, ui('lo-sm', 'start the practice rounds', practiceResult));
      if (smLocked || started !== smGeneration) return;
      if (job) { smPending = false; void loadModify(); }
    } catch (failure) {
      if (smLocked || started !== smGeneration) return;
      if ([401,403].includes(failure.status)) { lockCodePractice(); return; }
      var message = window.mvPlainDetail ? window.mvPlainDetail(failure.detail) : '';
      $('lo-sm-status').textContent = (message || 'The practice task reply could not be confirmed.') +
        (smPending ? ' Read the original task before deciding what to do next. Work is never repeated automatically.' : ' Your objective and rounds were kept.');
    } finally {
      smBusy = false; btn.disabled = smLocked || smPending; smReader.disabled = smLocked || !smHeld;
    }
  });

  // ---- plan a specialist model ------------------------------------------------------
  var planningGeneration = 0, planningContext = '', planningLocked = false;
  var planningFields = ['lo-mi-role', 'lo-mi-memory', 'lo-mi-context', 'lo-mi-concurrency'];
  function planningStamp() { return JSON.stringify(planningFields.map(function (id) {
    var field = $(id); return [field.value, Array.from(field.options).map(function (option) { return [option.value, option.text, option.disabled]; })];
  })); }
  function lockPlanning() {
    planningGeneration++; planningLocked = true; planningContext = '';
    planningFields.forEach(function (id) { $(id).replaceChildren(); $(id).disabled = true; });
    if ($('lo-mi-find')) $('lo-mi-find').disabled = true;
    fill('lo-mi-state', el('p', null, 'Your account, workspace or access changed. Reload Learning before reading model choices.'));
    fill('lo-mi-models', []);
  }
  function loadPlanning() {
    var started = ++planningGeneration, entered = planningStamp();
    J.request(TO + '/model-improvement').then(function (d) {
      if (planningLocked || started !== planningGeneration || planningStamp() !== entered) return;
      if (!/^[a-f0-9]{64}$/.test(d.context || '') || planningContext && d.context !== planningContext) { lockPlanning(); lockCodePractice(); return; }
      planningContext = d.context;
      var nodes = [el('p', null, (d.on ? 'Model improvement is on.' : 'Model improvement is off; planning still works.') +
        ' The model list is from ' + d.catalog.as_of + ' and has ' + plural(d.catalog.candidates, 'model') + '.')];
      if (d.task_sets.length) nodes.push(J.table(['Task set', 'Ready to prove a model', 'Practice groups', 'Kept-aside groups'],
        d.task_sets.map(function (t) {
          return [t.label, t.ready ? 'Yes' : 'Not yet: ' + t.why_not.join(' '), String(t.practice_groups), String(t.kept_aside_groups)];
        })));
      fill('lo-mi-state', nodes);
      var c = d.choices;
      options($('lo-mi-role'), c.roles);
      options($('lo-mi-memory'), c.memory_gib.map(function (v) { return { value: v, label: v + ' GB' }; }), 32);
      options($('lo-mi-context'), c.context_tokens.map(function (v) { return { value: v, label: Math.round(v * 0.75).toLocaleString() + ' words' }; }), 16384);
      options($('lo-mi-concurrency'), c.concurrency.map(function (v) { return { value: v, label: String(v) }; }), 1);
      options($('lo-mi-set'), d.task_sets.map(function (t) { return { value: t.value, label: t.label }; }));
      options($('lo-mi-split'), c.splits);
      var scoringChoice = new URL(window.location.href).searchParams;
      if (scoringChoice.get('scoring_task_set')) $('lo-mi-set').value = scoringChoice.get('scoring_task_set');
      if (scoringChoice.get('scoring_split')) $('lo-mi-split').value = scoringChoice.get('scoring_split');
      if (scoringChoice.get('scoring_task_set') && window.LightworkModelAnswerScoring) window.LightworkModelAnswerScoring.loadSelected();
    }).catch(async function (failure) {
      if (planningLocked || started !== planningGeneration) return;
      if ([401, 403, 409].includes(failure.status)) { lockPlanning(); lockCodePractice(); return; }
      var problem = await J.problem(failure, 'load model planning');
      if (!planningLocked && started === planningGeneration) fill('lo-mi-state', el('p', null, problem));
    });
  }
  var find = $('lo-mi-find');
  planningFields.forEach(function (id) { $(id).addEventListener('change', function () {
    planningGeneration++; fill('lo-mi-models', el('p', 'muted', 'Choices changed. Find models again to read their current fit.')); find.disabled = planningLocked;
  }); });
  if (find) find.addEventListener('click', async function () {
    if (find.disabled || planningLocked || !planningContext) return;
    var started = ++planningGeneration, entered = planningStamp(), bound = planningContext;
    var query = {role:$('lo-mi-role').value, memory_gib:Number($('lo-mi-memory').value),
      context_tokens:Number($('lo-mi-context').value), concurrency:Number($('lo-mi-concurrency').value)};
    find.disabled = true;
    fill('lo-mi-models', el('p', 'muted', 'Looking…'));
    try {
      var q = '?role=' + encodeURIComponent($('lo-mi-role').value) + '&memory_gib=' + encodeURIComponent($('lo-mi-memory').value) +
        '&context_tokens=' + encodeURIComponent($('lo-mi-context').value) + '&concurrency=' + encodeURIComponent($('lo-mi-concurrency').value);
      var d = await J.request(TO + '/model-improvement/models' + q);
      if (planningLocked || started !== planningGeneration) return;
      if (planningStamp() !== entered) { fill('lo-mi-models', el('p', 'muted', 'Choices changed. Find models again to read their current fit.')); return; }
      if (d.context !== bound) { lockPlanning(); lockCodePractice(); return; }
      if (!d.query || Object.keys(query).some(function (key) { return query[key] !== d.query[key]; })) {
        fill('lo-mi-models', el('p', null, 'The returned model fit does not match your choices. Find models again.')); return;
      }
      if (!d.models.length) { fill('lo-mi-models', el('p', 'muted', 'No model in the list is meant for this role.')); return; }
      fill('lo-mi-models', [J.table(['Model', 'Fits', 'Memory it needs', 'Licence', 'Status'], d.models.map(function (m) {
        return [m.name, m.fits ? 'Yes' : 'No', m.memory_needed_gib + ' GB', m.licence, m.status];
      })), el('p', 'muted', 'For planning only. No model is switched.')]);
    } catch (failure) {
      if (!planningLocked && planningContext === bound && [401, 403, 409].includes(failure.status)) { lockPlanning(); lockCodePractice(); return; }
      if (planningLocked || started !== planningGeneration) return;
      var problem = await J.problem(failure, 'find models');
      if (!planningLocked && started === planningGeneration && planningStamp() === entered) fill('lo-mi-models', el('p', null, problem));
    } finally { if (!planningLocked && started === planningGeneration) find.disabled = false; }
  });
  function changedLearningContext() { lockPlanning(); lockCodePractice(); }
  document.addEventListener('lightwork:workspace-changed', changedLearningContext);
  document.addEventListener('lightwork:account-context-changed', changedLearningContext);
  window.addEventListener('lightwork:context-changed', function (event) { if (event.detail?.reason !== 'selection') changedLearningContext(); });
  document.addEventListener('lightwork:copilot-context-changed', function (event) { if (event.detail?.reason !== 'selection') changedLearningContext(); });
  J.wire($('lo-mi-score'), async function () {
    var body = await fileBody($('lo-mi-file'), 'Choose the answers file first.');
    if (!body) return null;
    return { url: TO + '/model-improvement/score?task_set=' + encodeURIComponent($('lo-mi-set').value) + '&split=' + encodeURIComponent($('lo-mi-split').value),
      init: { method: 'POST', body: body, type: 'application/json' } };
  }, ui('lo-mi', 'score the answers', function (d) {
    return el('p', null, d.passed + ' of ' + plural(d.questions, 'question') + ' passed (' + Math.round(d.pass_rate * 100) + '%). Score ' +
      Math.round(d.score * 100) + '%.' + (d.unanswered ? ' ' + plural(d.unanswered, 'question') + ' had no answer.' : '') +
      (d.not_in_set ? ' ' + plural(d.not_in_set, 'answer') + ' did not match a question.' : ''));
  }));

  // ---- reward model ------------------------------------------------------------------
  function loadRewardModels() {
    J.request(TO + '/reward-models').then(function (d) {
      var nodes = [el('p', 'muted', plural(d.waiting_outlines, 'task outline') + ' waiting on this server to learn from.')];
      if (!d.models.length) nodes.push(el('p', 'muted', admin ? 'No scoring guide yet. Learn from eligible task approaches below.' : 'No scoring guide yet. It appears here once an administrator trains one.'));
      else nodes.push(J.table(['Trained', 'Comparisons', 'Agreed with the checker', ''], d.models.map(function (m) {
        var link = el('a', 'btn btn--ghost', 'Download');
        link.href = TO + '/reward-models/' + encodeURIComponent(m.name) + '/download';
        link.setAttribute('download', '');
        return [J.when(m.created_at), String(m.pairs), Math.round(m.accuracy * 100) + '%', admin ? link : ''];
      })));
      fill('lo-rm-list', nodes);
      var selected = $('lo-rm-model') && $('lo-rm-model').value;
      options($('lo-rm-model'), d.models.map(function (m, i) { return { value: m.name, label: 'Training ' + (d.models.length - i) + ' · ' + J.when(m.created_at) }; }), selected);
    }).catch(async function (failure) {
      fill('lo-rm-list', el('p', null, await J.problem(failure, 'load saved scoring guides')));
    });
  }
  async function rewardSource() {
    var source = radio('lo-rm-source');
    if (source !== 'file') return { source: 'outbox', init: { method: 'POST', json: {} } };
    var body = await fileBody($('lo-rm-file'), 'Choose the task outline file first.');
    return body ? { source: 'file', init: { method: 'POST', body: body, type: 'application/octet-stream' } } : null;
  }
  J.wire($('lo-rm-file-train') || $('lo-rm-train'), async function () {
    var src = await rewardSource();
    if (!src) return null;
    if ($('lo-rm-file-train') && src.source !== 'file') { window.mvToast('Choose the task-outline file option first.', { error: true }); return null; }
    var q = '?source=' + src.source + '&min_margin=' + $('lo-rm-margin').value + '&max_pairs=' + $('lo-rm-pairs').value +
      '&epochs=' + $('lo-rm-epochs').value + '&lr=' + $('lo-rm-lr').value;
    return { url: TO + '/reward-models/train' + q, init: src.init };
  }, ui('lo-rm', 'learn a scoring guide', function (d) {
    var evidence=d.evidence?el('p',null,d.evidence.eligible+' usable comparisons; '+d.evidence.skipped+' skipped; '+d.evidence.unresolved+' unresolved. Missing steps and identical patterns cannot establish an order.'):null;
    if (!d.trained) return [el('p', null, d.why),evidence].filter(Boolean);
    return [el('p', null, 'Trained on ' + plural(d.pairs, 'comparison') + ' from ' + plural(d.outlines, 'task outline') + '. It agrees with the answer checker ' +
      Math.round(d.accuracy * 100) + '% of the time. These training comparisons do not establish answer quality on new work.'),evidence].filter(Boolean);
  }, loadRewardModels));
  document.addEventListener('lightwork:reward-model-saved', loadRewardModels);
  J.wire($('lo-rm-score'), async function () {
    var model = $('lo-rm-model').value;
    if (!model) { window.mvToast('Learn a scoring guide from eligible task approaches first.', { error: true }); return null; }
    var src = await rewardSource();
    if (!src) return null;
    return { url: TO + '/reward-models/' + encodeURIComponent(model) + '/score?source=' + src.source, init: src.init };
  }, ui('lo-rm', 'score the task outlines', function (d) {
    if (!d.scored) return el('p', 'muted', 'No attempts have recorded steps to score. '+(d.skipped||0)+' attempts were skipped; missing steps are not a low score.');
    return [el('p', null, 'Scored ' + plural(d.scored, 'task outline') + '. '+(d.skipped||0)+' attempts without steps skipped. Highest first:'),el('p','muted',d.notice||'These scores describe step patterns, not answer quality.'),
      J.table(['Rank', 'Result', 'Steps', 'Score'], d.top.map(function (r, i) {
        return [String(i + 1), r.outcome ? (window.mvHuman ? window.mvHuman(r.outcome) : r.outcome) : '—', String(r.steps), r.score.toFixed(3)];
      })), J.technical(d.top.map(function (r, i) { return (i + 1) + ': ' + r.reference; }))];
  }));

  // ---- shorthand between agents --------------------------------------------------------
  function loadCodec() {
    J.request(TO + '/codec').then(function (d) {
      var nodes = [el('p', null, 'Shorthand: ' + plural(d.shorthand.codes, 'code') + (d.shorthand.on ? ' (in use).' : ' (not in use).') +
        ' Token-saving codes: ' + plural(d.token_codes.codes, 'code') + (d.token_codes.on ? ' (being measured live).' : '.'))];
      if (d.shorthand.phrases.length) { nodes.push(el('h4', null, 'Phrases with a code')); nodes.push(list(d.shorthand.phrases)); }
      var exact = $('lo-cd-exact');
      var connected = exact && Array.from(exact.options).find(function (option) { return option.value === '1'; });
      if (exact && d.exact_count_available && !connected) {
        var o = el('option', null, 'Anthropic count estimate (sends these messages to your connected service)');
        o.value = '1';
        exact.appendChild(o);
      } else if (connected && !d.exact_count_available) {
        var wasSelected = exact.value === '1';
        connected.remove();
        if (wasSelected) {
          exact.value = '0';
          nodes.push(el('p', null, 'Connected-service counting is no longer available. The counting method changed to the free estimate.'));
        }
      }
      fill('lo-cd-state', nodes);
    }).catch(async function (failure) {
      fill('lo-cd-state', el('p', null, await J.problem(failure, 'load the shorthand')));
    });
  }
  var codecGeneration = 0;
  function codecBody() { return { how_many: Number($('lo-cd-count').value), exact: $('lo-cd-exact').value === '1' }; }
  function codecChanged(event) { if (event.detail?.reason !== 'selection') codecGeneration++; }
  ['lo-cd-count', 'lo-cd-exact'].forEach(function (id) {
    $(id).addEventListener('input', codecChanged); $(id).addEventListener('change', codecChanged);
  });
  ['lightwork:workspace-changed', 'lightwork:account-context-changed', 'lightwork:copilot-context-changed'].forEach(function (name) { document.addEventListener(name, codecChanged); });
  window.addEventListener('lightwork:context-changed', codecChanged);
  function codecCurrent(body, generation) {
    if (generation === codecGeneration && JSON.stringify(body) === JSON.stringify(codecBody())) return true;
    window.mvToast('Your choices, account or workspace changed while the review was open. Nothing was started. Review your current choices again.', { error: true });
    return false;
  }
  async function exactOk(body) {
    return !body.exact || window.mvConfirm('Ask your connected Anthropic service to estimate token counts? Recent messages between agents are sent to it. This does not generate an answer or establish the cost of future work.',
      { okText: 'Use provider count' });
  }
  J.wire($('lo-cd-learn'), async function () {
    var body = codecBody(), generation = codecGeneration;
    if (!(await window.mvConfirm('Relearn the shorthand from up to ' + body.how_many + ' recent messages between agents? The new codes replace the old ones.',
      { okText: 'Relearn' }))) return null;
    if (!codecCurrent(body, generation)) return null;
    return { url: TO + '/codec/shorthand/learn', init: { method: 'POST', json: body } };
  }, ui('lo-cd', 'relearn the shorthand', function (d) {
    return [el('p', null, 'Learned ' + plural(d.codes, 'code') + ' from ' + plural(d.messages, 'message') + '. Messages would be ' + d.smaller_pct + '% shorter.'),
      d.phrases.length ? list(d.phrases) : null];
  }, loadCodec));
  J.wire($('lo-cd-tokens'), async function () {
    var body = codecBody(), generation = codecGeneration;
    if (!(await exactOk(body))) return null;
    if (!codecCurrent(body, generation)) return null;
    if (!(await window.mvConfirm('Learn token-saving codes from up to ' + body.how_many + ' recent messages and keep them? They replace the current ones.',
      { okText: 'Learn codes' }))) return null;
    if (!codecCurrent(body, generation)) return null;
    return { url: TO + '/codec/token-codes/learn', init: { method: 'POST', json: body } };
  }, ui('lo-cd', 'learn token-saving codes', function (d) {
    if (!d.learned) return el('p', null, d.why);
    return el('p', null, 'Learned ' + plural(d.codes, 'code') + ' from ' + plural(d.messages, 'message') + '. On those messages they would save about ' +
      d.saved_pct + '% of tokens.');
  }, loadCodec));
  J.wire($('lo-cd-measure'), async function () {
    var body = codecBody(), generation = codecGeneration;
    if (!(await exactOk(body))) return null;
    if (!codecCurrent(body, generation)) return null;
    return { url: TO + '/codec/measure', init: { method: 'POST', json: body } };
  }, ui('lo-cd', 'measure the savings', function (d) {
    if (!d.measured) return el('p', null, d.why);
    var lines = [(d.pays_off ? 'It saves tokens: ' : 'It costs more tokens: ') + d.tokens_saved_pct + '% tokens, ' + d.characters_saved_pct +
      '% characters, over ' + plural(d.messages, 'message') + ' with ' + plural(d.codes, 'code') + '.'];
    lines.push(d.break_even_after == null ? 'Explaining the codes to a model would never pay for itself.'
      : 'Explaining the codes costs ' + plural(d.codebook_tokens, 'token') + ', repaid after about ' + plural(d.break_even_after, 'message') + '.');
    return lines.map(function (t) { return el('p', null, t); });
  }));

  // ---- task outlines waiting to be shared ---------------------------------------------------
  function loadDonations() {
    J.request(LO + '/donations').then(function (d) {
      var nodes = [el('p', null, (d.sharing ? 'Sharing is on' + (d.with_text ? ', including task text.' : ', without task text.') : 'Sharing is off.') +
        ' ' + (d.waiting ? plural(d.waiting, 'outline') + ' waiting, not yet sent.' : 'Nothing is waiting.'))];
      if (d.waiting && d.can_clear) {
        var btn = el('button', 'btn btn--danger', 'Delete waiting outlines');
        btn.type = 'button';
        btn.addEventListener('click', async function () {
          if (!(await window.mvConfirm('Delete ' + plural(d.waiting, 'waiting outline') + '? They are removed without being sent and cannot be recovered.',
            { okText: 'Delete outlines' }))) return;
          btn.disabled = true;
          try {
            var r = await J.request(LO + '/donations/clear', { method: 'POST', json: { confirm: true } });
            $('lo-dn-status').textContent = 'Deleted ' + plural(r.cleared, 'outline') + '.';
            loadDonations();
          } catch (failure) {
            $('lo-dn-status').textContent = await J.problem(failure, 'delete the outlines');
            btn.disabled = false;
          }
        });
        nodes.push(btn);
      }
      fill('lo-dn-state', nodes);
    }).catch(async function (failure) {
      fill('lo-dn-state', el('p', null, await J.problem(failure, 'load the waiting outlines')));
    });
  }

  // ---- recent background jobs ----------------------------------------------------------------
  var STATES = { running: 'Running', stopping: 'Stopping', done: 'Finished', stopped: 'Stopped early', failed: 'Could not finish' };
  function loadJobs() {
    J.request(LO + '/jobs').then(function (d) {
      if (!d.jobs.length) { fill('lo-jobs', el('p', 'muted', 'No background tasks since Lightwork last started.')); return; }
      fill('lo-jobs', J.table(['Task', 'Started', 'Status'], d.jobs.map(function (j) {
        return [j.label, J.when(j.started_at), STATES[j.state] + (j.problem ? ': ' + j.problem : '')];
      })));
    }).catch(async function (failure) {
      fill('lo-jobs', el('p', null, await J.problem(failure, 'load the background tasks')));
    });
  }
  var refresh = $('lo-jobs-refresh');
  if (refresh) refresh.addEventListener('click', loadJobs);

  if (admin) loadModify();
  loadPlanning();
  loadRewardModels();
  loadCodec();
  loadDonations();
  loadJobs();
})();
