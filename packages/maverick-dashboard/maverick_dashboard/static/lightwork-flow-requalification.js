'use strict';
(function () {
  const host=document.getElementById('rule-requalification'), form=document.getElementById('rule-requalification-form');
  if(!host||!form)return;
  const api='/api/v1/learning/rule-requalification', status=document.getElementById('rq-status'), error=document.getElementById('rq-error');
  const review=document.getElementById('rq-review'), result=document.getElementById('rq-result'), history=document.getElementById('rq-history');
  let context='',state=null,prepared=null,pending=null,busy=false,generation=0,currentFlow='';
  const calls=new Set(), storage='lightwork-rule-requalification-original';
  function text(tag,value,parent){const item=document.createElement(tag);if(value!==undefined)item.textContent=String(value);if(parent)parent.appendChild(item);return item;}
  function date(value){return new Date(value*1000).toLocaleString();}
  function lock(value){busy=value;host.setAttribute('aria-busy',String(value));host.querySelectorAll('input,button,select').forEach(item=>item.disabled=value);if(!value&&prepared){const confirm=review.querySelector('button');if(confirm)confirm.disabled=!review.querySelector('input')?.checked;}}
  function losePrivate(){++generation;calls.forEach(c=>c.abort());context='';currentFlow='';state=prepared=pending=null;form.reset();form.elements.flow.replaceChildren(new Option('Refresh in the current account',''));form.elements.practice.replaceChildren(new Option('Choose a real run',''));form.elements.evidence.replaceChildren(new Option('Choose evidence',''));history.replaceChildren(new Option('Refresh original requests',''));review.replaceChildren();review.hidden=true;result.replaceChildren();result.hidden=true;document.getElementById('rq-components').replaceChildren();document.getElementById('rq-versions').textContent='';status.textContent='Private case details were cleared because your account, workspace or access changed.';lock(false);}
  async function request(path,body,expected=context){
    const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),20000);calls.add(controller);
    try{
      const response=await fetch(api+path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',signal:controller.signal,headers:{'Content-Type':'application/json',...(expected?{'X-Lightwork-Requalification-Context':expected}:{})},body:body?JSON.stringify(body):undefined});
      if(response.redirected||response.status===401||response.status===403){losePrivate();throw new Error('Private details were cleared. Sign in with current permission before continuing.');}
      const reader=response.body.getReader(), chunks=[];let length=0;
      try{while(true){const part=await reader.read();if(part.done)break;length+=part.value.length;if(length>262144){await reader.cancel();throw new Error('The complete response exceeds this form’s supported size. No partial review can be confirmed.');}chunks.push(part.value);}}
      finally{reader.releaseLock();}
      const bytes=new Uint8Array(length);let offset=0;chunks.forEach(part=>{bytes.set(part,offset);offset+=part.length;});const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
      if(!response.ok){const message=typeof value.detail==='string'?value.detail:'The rule check could not be verified. Read its original result before starting another.';if(response.status===409&&message.includes('account, workspace or access changed'))losePrivate();throw new Error(message);}
      if(expected&&value.context&&value.context!==expected){losePrivate();throw new Error('The account or workspace changed. Private details were cleared.');}
      return value;
    }catch(failure){if(failure.name==='AbortError'||failure instanceof TypeError||failure instanceof SyntaxError)throw new Error('The reply could not be confirmed. Check the original result without repeating the work.');throw failure;}
    finally{clearTimeout(timeout);calls.delete(controller);}
  }
  function invalidate(){prepared=null;review.hidden=true;review.replaceChildren();}
  function render(value){
    result.hidden=false;result.replaceChildren();text('h2','Original rule-check result',result);text('p',value.message,result);text('p',value.current?'The current sources still match this recorded check.':'This is historical evidence; current source or reuse permission differs.',result);
    const output=value.result||{};
    if(value.confirmed){
      if(output.withdrawn)text('p','Future reuse of the selected evidence was stopped.',result);
      else{
        text('p',output.agreement?'Both paths finished with exactly the same complete values. This is agreement on this known case.':'The paths did not establish the same complete successful result. Do not treat this as qualified agreement.',result);
        text('p','Rechecked steps: '+(output.selective_state==='completed'?'Finished':output.selective_state==='failed'?'Failed':'Unknown')+'. Complete comparison: '+(output.complete_state==='completed'?'Finished':output.complete_state==='failed'?'Failed':'Unknown')+'.',result);
        text('p',output.reused+' prior step results reused; '+output.recalculated+' work steps checked again.',result);
        const calculation=text('details',undefined,result);text('summary','Work and calculation time',calculation);text('p','Workflow steps: '+output.selective_native_steps+' for rechecked work plus '+output.complete_native_steps+' for the complete comparison. Combined calculation time: '+output.combined_calculation_ms+' ms, plus final receipt and browser overhead. Both calculations count toward total work. This does not establish faster work or customer savings.',calculation);
        (output.components||[]).forEach(item=>{const block=text('div',undefined,result);text('strong',item.label+' · '+(item.reused?'Reused':'Recalculated'),block);text('p',item.reason,block);});
        if(output.selective_result!==undefined){const details=text('details',undefined,result);text('summary','Complete recorded business values',details);text('p',output.selective_result,details).style.whiteSpace='pre-wrap';}
      }
    }
    const scope=text('details',undefined,result);text('summary','What this evidence establishes',scope);text('p',value.notice,scope);
  }
  function renderHistory(value){history.replaceChildren(new Option('Choose original request',''));value.choices.forEach(row=>history.appendChild(new Option(row.name+' · '+date(row.when),row.value)));if(pending?.context===context&&!value.choices.some(row=>row.value===pending.id))history.appendChild(new Option('Original request · check result',pending.id));if(pending?.context===context)history.value=pending.id;}
  async function retained(){renderHistory(await request('/history'));}
  async function refresh(wanted=form.elements.flow.value,mayPublish=()=>true){
    if(busy)return;const kept=wanted===currentFlow?{practice:form.elements.practice.value,evidence:form.elements.evidence.value}:null;const current=++generation;lock(true);error.textContent='';
    try{
      const value=await request(wanted?'?flow='+encodeURIComponent(wanted):'');if(current!==generation||!mayPublish())return;
      const originals=await request('/history',undefined,value.context);if(current!==generation||!mayPublish())return;invalidate();context=value.context;
      form.elements.flow.replaceChildren(new Option('Choose a workflow',''));value.flows.forEach(row=>form.elements.flow.appendChild(new Option(row.label,row.value)));form.elements.flow.value=wanted;
      if(!pending){try{const saved=JSON.parse(sessionStorage.getItem(storage)||'null');if(saved?.context===context)pending=saved;}catch(_){}}
      state=wanted?value:null;currentFlow=wanted;document.getElementById('rq-semantic-choice').hidden=value.semantic_reuse_available!==true;if(value.semantic_reuse_available!==true)form.elements.semantic_reuse.checked=false;const components=document.getElementById('rq-components');components.replaceChildren();
      form.elements.practice.replaceChildren(new Option('Choose a real run',''));form.elements.evidence.replaceChildren(new Option('Choose prior evidence',''));
      if(state){document.getElementById('rq-versions').textContent=state.name+' · published version '+state.baseline_version+' · saved version '+state.version;
        state.changes.forEach(row=>text('p',row.label+' · '+(row.changed?'Changed work step':'Unchanged work step')+(row.dependencies.length?' · follows '+row.dependencies.join(', '):' · independent of prior work steps'),components));
        state.included.forEach(row=>text('p','Included: '+row.name+' · version '+row.version,components));
        state.practices.forEach(row=>form.elements.practice.appendChild(new Option('Original run · '+date(row.when)+' · '+(row.state==='completed'?'Finished':'Failed'),row.value)));
        state.evidence.forEach(row=>form.elements.evidence.appendChild(new Option('Evidence · '+date(row.when)+' · '+(row.available?'Reuse allowed':'Reuse unavailable'),row.value)));}
      if(kept){for(const key of ['practice','evidence'])if(Array.from(form.elements[key].options).some(option=>option.value===kept[key]))form.elements[key].value=kept[key];}
      renderHistory(originals);status.textContent='Current choices are ready. Review the original values and rules before starting a local check.';
    }catch(failure){if(current===generation){state=null;error.textContent=failure.message;}}
    finally{if(current===generation)lock(false);}
  }
  async function prepare(kind){
    if(busy||!state)return;const current=generation;lock(true);error.textContent='';invalidate();
    try{
      const body={context,kind,flow:form.elements.flow.value,practice:kind==='retain'?form.elements.practice.value:'',evidence:kind==='retain'?'':form.elements.evidence.value,semantic_reuse:kind!=='withdraw'&&form.elements.semantic_reuse.checked};
      if(kind==='retain'&&!body.practice||kind!=='retain'&&!body.evidence)throw new Error(kind==='retain'?'Choose an original real run first.':'Choose retained component evidence first.');
      const value=await request('/review',body);if(current!==generation)return;
      if(!Array.isArray(value.changes)||value.changes.length>512||value.changes.some(row=>!row||Object.keys(row).sort().join(',')!=='after,label'||typeof row.label!=='string'||typeof row.after!=='string'))throw new Error('The complete review cannot be displayed. No confirmation is available.');
      prepared=value;review.hidden=false;text('h2','Review the complete local check',review);const list=text('dl',undefined,review);value.changes.forEach(row=>{text('dt',row.label,list);text('dd',row.after,list);});
      const label=text('label',undefined,review);label.style.display='flex';label.style.alignItems='flex-start';const check=text('input',undefined,label);check.type='checkbox';text('span','I reviewed all displayed values, components and the separate case-use permission.',label);
      const confirm=text('button',kind==='retain'?'Confirm complete evidence check':kind==='recheck'?'Confirm recheck and complete comparison':'Confirm withdrawal',review);confirm.className='btn btn--primary';confirm.type='button';confirm.disabled=true;check.addEventListener('change',()=>{confirm.disabled=!check.checked;});confirm.addEventListener('click',()=>void apply());
      const cancel=text('button','Cancel this review',review);cancel.className='btn btn--ghost';cancel.type='button';cancel.addEventListener('click',invalidate);
    }catch(failure){if(current===generation)error.textContent=failure.message;}
    finally{if(current===generation){lock(false);const confirm=review.querySelector('button');if(confirm)confirm.disabled=true;}}
  }
  async function apply(){
    if(busy||!prepared||!review.querySelector('input')?.checked)return;const value=prepared,current=generation;pending={id:value.operation,context};
    try{sessionStorage.setItem(storage,JSON.stringify(pending));}catch(_){}
    lock(true);error.textContent='';
    try{const row=await request('/apply',{token:value.token,confirmed:true});if(current!==generation)return;render(row);invalidate();await retained();}
    catch(failure){if(current===generation){error.textContent=failure.message;status.textContent='The original request may have been accepted. Check the original result; no automatic retry is available.';invalidate();if(!Array.from(history.options).some(row=>row.value===pending.id))history.appendChild(new Option('Original request · check result',pending.id));history.value=pending.id;}}
    finally{if(current===generation)lock(false);}
  }
  document.getElementById('rq-retain').addEventListener('click',()=>void prepare('retain'));document.getElementById('rq-recheck').addEventListener('click',()=>void prepare('recheck'));document.getElementById('rq-withdraw').addEventListener('click',()=>void prepare('withdraw'));document.getElementById('rq-refresh').addEventListener('click',()=>void refresh());form.elements.flow.addEventListener('change',()=>void refresh());form.addEventListener('change',invalidate);
  document.getElementById('rq-read').addEventListener('click',async()=>{if(busy)return;const selected=history.value||pending?.id;if(!selected){error.textContent='Choose an original request first.';return;}const current=generation;lock(true);error.textContent='';try{const value=await request('/original/'+encodeURIComponent(selected));if(current===generation)render(value);}catch(failure){if(current===generation){result.hidden=true;result.replaceChildren();error.textContent=failure.message;}}finally{if(current===generation)lock(false);}});
  document.addEventListener('lightwork:copilot-context-changed',async event=>{if(event.detail?.reason!=='selection'){losePrivate();return;}const selected=prepared,current=generation;try{await request(selected?'/review-status':'',selected?{token:selected.token}:undefined);}catch(failure){if(current===generation){if(prepared===selected)invalidate();error.textContent=failure.message;}}});
  window.addEventListener('lightwork:copilot-context-changed',losePrivate);document.addEventListener('lightwork:account-context-changed',losePrivate);
  window.LightworkRuleRequalification={open:async(expected,workflow,isActive=()=>true)=>{if(busy||!isActive())return false;const current=generation;const value=await request('',undefined,expected);if(current!==generation||!isActive()||value.context!==expected)return false;if(form.elements.flow.value!==workflow){if((prepared||form.elements.practice.value||form.elements.evidence.value||form.elements.semantic_reuse.checked)&&(typeof window.mvConfirm!=='function'||!await window.mvConfirm('Opening a different workflow replaces your selected case and review. Continue?',{okText:'Change workflow'})||current!==generation||!isActive()||busy))return false;await refresh(workflow,isActive);}else if(prepared){await request('/review-status',{token:prepared.token},expected);if(current!==generation||!isActive())return false;}if(!isActive()||!state||context!==expected||form.elements.flow.value!==workflow)return false;host.scrollIntoView({behavior:'smooth',block:'start'});form.elements.practice.focus();return true;}};
  const query=new URLSearchParams(location.search);void refresh(query.get('workflow')||'').then(()=>{if(query.get('original')){history.appendChild(new Option('Original request',query.get('original')));history.value=query.get('original');}});
})();
