// Compliance retention: exact reviews and read-only interrupted-result recovery.
(function () {
  'use strict';
  const byId = id => document.getElementById(id), form = byId('cmp-retention-form');
  if (!form) return;
  const result = byId('cmp-retention-result'), review = byId('cmp-retention-review');
  const save = byId('cmp-retention-save'), preview = byId('cmp-retention-apply');
  const confirm = byId('cmp-retention-confirm'), recover = byId('cmp-retention-recover');
  const history = byId('cmp-retention-history'), holds = byId('cmp-retention-holds');
  let context = '', receipt = null, busy = false, dirty = false, pending = null;
  const root = '/api/v1/compliance/retention';
  const states = {review:'Not started',pending:'Not started',running:'Outcome not confirmed',completed:'Completed',partial:'Needs attention',unknown:'Outcome not confirmed',blocked:'Blocked'};
  const say = text => { result.textContent = text; };
  function reference() { const bytes = crypto.getRandomValues(new Uint8Array(16)); return Array.from(bytes, b => b.toString(16).padStart(2,'0')).join(''); }
  function remember() { try { sessionStorage.setItem('lightwork-retention:'+context, JSON.stringify({review:receipt && receipt.id,pending})); } catch (_) {} }
  function controls(value) {
    busy = value;
    [save,preview,recover].forEach(button => { if (button) button.disabled = value; });
    if (history) history.disabled = value;
    if (confirm) confirm.disabled = value || dirty || !!pending || !receipt || !receipt.can_apply;
  }
  async function call(url, body, operation) {
    const expected = context, headers = {Accept:'application/json'};
    if (context) headers['X-Lightwork-Retention-Context'] = context;
    if (operation) headers['X-Lightwork-Retention-Operation'] = operation;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let response, value;
    try {
      response = await fetch(url, {method:body === undefined?'GET':'POST',headers,credentials:'same-origin',cache:'no-store',body:body === undefined?undefined:JSON.stringify(body)});
      value = await response.json();
    } catch (_) { throw new Error('The reply was interrupted. Check the saved result before continuing.'); }
    if (!response.ok) {
      // A refusal can carry {message, effective}: an installation policy that
      // overrides periods that were saved is explained, not reported as a failure.
      const detail = value && value.detail;
      const message = typeof detail === 'string' ? detail
        : detail && typeof detail.message === 'string' ? detail.message
        : 'Retention is unavailable. Check the saved result before continuing.';
      const error = new Error(message); error.status = response.status; throw error;
    }
    const actual = value.context || (value.receipt && value.receipt.context);
    if (expected && actual && expected !== actual) { receipt = null; pending = null; review.hidden = true; throw new Error('Your account or workspace changed. Reload this page before continuing.'); }
    return value;
  }
  function display(value) {
    if (value.context !== context) return;
    receipt = value; review.hidden = false;
    const summary = byId('cmp-retention-summary'); summary.replaceChildren();
    value.targets.forEach(target => {
      const card = document.createElement('div'); card.className = 'panel';
      const title = document.createElement('h4'); title.textContent = target.name; card.appendChild(title);
      value.steps.filter(step => step.tenant === target.tenant).forEach(step => {
        const line = document.createElement('p'); line.textContent = step.label+': keep '+step.days+' days; '+step.eligible+' eligible at preview. '+states[step.status]+'.'+
          (step.removed === undefined?'':' '+step.removed+' removals confirmed.')+(step.skipped?' '+step.skipped+' skipped.':'')+
          (step.audit_record === 'unconfirmed'?' Activity recording is not confirmed.':'')+(step.uncertain_prior?' An earlier outcome remains unknown.':'')+(step.note?' '+step.note:''); card.appendChild(line);
      });
      if (!value.steps.some(step => step.tenant === target.tenant)) { const line=document.createElement('p');line.textContent='No automatic deletion periods.';card.appendChild(line); }
      const gate = document.createElement('p'); gate.textContent = target.preservation.blocked?'Recorded preservation holds block deletion. Confirmation cannot override them.':'No blocking holds found in the recorded privacy-rights ledger. Check external holds separately.';card.appendChild(gate);
      summary.appendChild(card);
    });
    confirm.hidden = !value.can_apply; holds.disabled = !value.can_apply; holds.checked = false;
    if (value.execution_id || pending && pending.kind === 'preview' && pending.review === value.id) pending = null;
    history.value = value.id; remember(); controls(busy); say(value.message);
  }
  async function loadHistory() {
    if (!history) return;
    const value = await call(root+'/reviews');
    if (!context) {
      context = value.context;
      try { const saved=JSON.parse(sessionStorage.getItem('lightwork-retention:'+context)||'null'); if(saved) pending=saved.pending||null; } catch (_) {}
    }
    history.replaceChildren(new Option(value.records.length?'Choose a saved review':'No saved reviews yet',''));
    value.records.forEach(row => history.add(new Option(new Date(row.created_at*1000).toLocaleString()+' · '+row.workspaces+' · '+states[row.status],row.id)));
    if (receipt) history.value = receipt.id;
  }
  async function loadPeriods() {
    const value = await call(root);
    value.fields.forEach(field => {
      const control=byId('cmp-ret-'+field.key); control.replaceChildren(new Option('Keep until I choose',''));
      const choices=Array.from(new Set(value.choices.concat(field.days?[field.days]:[]))).sort((a,b)=>a-b);
      choices.forEach(days=>control.add(new Option(days%365===0?(days/365)+' year'+(days===365?'':'s'):days+' days',String(days))));control.value=field.days?String(field.days):'';
    });dirty=false;
  }
  async function checkSaved() {
    if (busy) return;
    const identity = pending && pending.review || history.value || receipt && receipt.id;
    if (!identity) { say('Choose a saved review first.'); return; }
    controls(true);
    try { display(await call(root+'/runs/'+identity)); await loadHistory(); if(pending) say('No dispatch receipt is recorded yet. Nothing will be retried automatically. Reopen this exact review or preview again before a new decision.'); }
    catch(error) { say(error.message+' No deletion was repeated.'); }
    finally { controls(false); }
  }
  form.addEventListener('change',()=>{dirty=true;receipt=null;if(review)review.hidden=true;say('Unsaved periods. Save them before reviewing deletion.');controls(busy);});
  if (save) save.addEventListener('click',async()=>{
    if(busy)return;const body={};form.querySelectorAll('select').forEach(select=>body[select.name]=select.value?Number(select.value):null);controls(true);
    try {const value=await call(root,body);await loadPeriods();receipt=null;review.hidden=true;say(value.message);}
    catch(error){say(error.message+' Your edited periods are still shown.');}finally{controls(false);}
  });
  if(preview)preview.addEventListener('click',async()=>{
    if(busy)return;if(dirty){say('Save your edited periods before reviewing deletion.');return;}
    const operation=reference();pending={review:operation,operation,kind:'preview'};remember();controls(true);
    try {const value=await call(root+'/preview',{},operation);pending=null;display(value);await loadHistory();review.focus();}
    catch(error){say(error.message+' Check the saved result to recover the original preview. No deletion was requested.');}finally{controls(false);}
  });
  if(confirm)confirm.addEventListener('click',async()=>{
    if(busy||pending||dirty||!receipt||!receipt.can_apply)return;
    if(!holds.checked){say('Confirm external preservation holds with the records owner first.');holds.focus();return;}
    controls(true);
    try {
      const accepted=window.mvConfirm && await window.mvConfirm('Permanently delete the reviewed old records in the listed workspaces? Completed deletions cannot be undone.',{okText:'Delete reviewed records'});
      if(!accepted)return;
      const operation=reference();pending={review:receipt.id,operation,kind:'deletion'};remember();
      const value=await call(root+'/apply',{review_id:receipt.id,context,expected_revision:receipt.revision,operation_id:operation,confirm_no_holds:true});display(value.receipt);await loadHistory();
    }catch(error){say(error.message+(error.status?' Check the saved result for any completed stores. No deletion will repeat automatically.':' The reply was interrupted. Check the saved result; some deletion may already have completed. Nothing will run again automatically.'));}
    finally{controls(false);}
  });
  if(recover)recover.addEventListener('click',checkSaved);
  if(history)history.addEventListener('change',()=>{if(!busy){pending=null;receipt=null;review.hidden=true;remember();checkSaved();}});
  const copilot=byId('cmp-retention-copilot');if(copilot)copilot.addEventListener('click',()=>{const fab=byId('mv-copilot-fab');if(fab)fab.click();else say('Copilot is unavailable here. Use the retention controls above.');});
  document.addEventListener('lightwork:product-operation-complete',event=>{if(String(event.detail.operation).startsWith('preferences.retention_')&&!busy)loadHistory().catch(error=>say(error.message));});
  (async()=>{controls(true);try{await loadPeriods();await loadHistory();if(history){let saved=null;try{saved=JSON.parse(sessionStorage.getItem('lightwork-retention:'+context)||'null');}catch(_){}const identity=pending&&pending.review||saved&&saved.review;if(identity)display(await call(root+'/runs/'+identity));}}catch(error){say(error.message);}finally{controls(false);}})();
}());
