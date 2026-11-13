'use strict';
(function () {
  const host=document.getElementById('flow-comparisons'), form=document.getElementById('flow-comparison-form');
  if (!host || !form) return;
  const root='/api/v1/research/flow-comparisons', flow=form.elements.flow, output=form.elements.output;
  const cases=document.getElementById('flow-comparison-cases'), status=document.getElementById('flow-comparison-status'), error=document.getElementById('flow-comparison-error');
  const result=document.getElementById('flow-comparison-result'), history=document.getElementById('flow-comparison-history');
  let state=null, busy=false, generation=0, pending=null, unconfirmed=false;
  const requests=new Set();
  const selected=[];
  function node(tag,text,parent) {const value=document.createElement(tag);if(text!==undefined)value.textContent=String(text);if(parent)parent.appendChild(value);return value;}
  function date(value) {return new Date(value*1000).toLocaleString();}
  function lock(value) {busy=value;host.querySelectorAll('button,input,select').forEach(control=>control.disabled=value);if(!value){form.querySelector('[type=submit]').disabled=!state?.can_compare||unconfirmed;document.getElementById('flow-comparison-add').disabled=!state?.can_compare;}}
  async function request(path,body) {
    const controller=new AbortController(), deadline=setTimeout(()=>controller.abort(),20000);
    requests.add(controller);
    try {
      const response=await fetch(root+path,{method:body?'POST':'GET',cache:'no-store',credentials:'same-origin',signal:controller.signal,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
      if(Number(response.headers.get('content-length')||0)>131072)throw new Error('This comparison response exceeds its supported size. Refresh before relying on it.');
      const reader=response.body.getReader(), chunks=[];let size=0;
      try {while(true){const part=await reader.read();if(part.done)break;size+=part.value.length;if(size>131072){await reader.cancel();throw new Error('This comparison response exceeds its supported size.');}chunks.push(part.value);}}
      finally {reader.releaseLock();}
      const bytes=new Uint8Array(size);let position=0;chunks.forEach(chunk=>{bytes.set(chunk,position);position+=chunk.length;});
      const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
      if(!response.ok)throw new Error(typeof value.detail==='string'?value.detail:'The comparison could not be checked. Refresh and review the original cases again.');
      return value;
    } catch(failure) {if(failure.name==='AbortError'||failure instanceof TypeError||failure instanceof SyntaxError)throw new Error('The reply could not be confirmed. Check the original retained comparison before starting any new work.');throw failure;}
    finally {clearTimeout(deadline);requests.delete(controller);controller.abort();}
  }
  function clear() {selected.length=0;cases.replaceChildren();form.elements.case_use.checked=false;document.getElementById('flow-comparison-included').replaceChildren();result.hidden=true;result.replaceChildren();error.textContent='';}
  function values(parent,data) {Object.entries(data||{}).forEach(([key,value])=>{if(value&&typeof value==='object'){node('strong',key.replace(/_/g,' '),parent);values(parent,value);}else node('p',key.replace(/_/g,' ')+': '+(value===true?'Yes':value===false?'No':value),parent);});}
  function versions(parent, included) {
    parent.replaceChildren();
    ['published','proposed'].forEach(arm=>{
      const workflows=included?.[arm]||[], block=node('div',undefined,parent);
      node('strong',arm==='published'?'Included in the published rules':'Included in the proposed rules',block);
      if(!workflows.length)node('p','No other workflows are included.',block);
      else workflows.forEach(workflow=>node('p',workflow.name+' · saved version '+workflow.version,block));
    });
  }
  function render(record) {
    if(record.id===pending)unconfirmed=!['done','unavailable'].includes(record.state);
    result.hidden=false;result.replaceChildren();
    const summary=record.summary;node('h2',record.state==='done'?'Recorded comparison results':'Original comparison status',result);
    node('p',record.detail+(record.current?'':' This is an earlier saved version; it cannot authorize the current draft.'),result);
    if(record.state!=='done')return;
    node('p',summary.baseline_matches+' of '+summary.cases+' published-rule answers and '+summary.candidate_matches+' of '+summary.cases+' proposed-rule answers match your frozen expectations.',result);
    node('p','Local replay time: published rules '+summary.baseline_elapsed_ms+' ms; proposed rules '+summary.candidate_elapsed_ms+' ms. '+summary.scope,result);
    node('p','Recorded '+date(summary.when)+'.',result);
    versions(node('div',undefined,result),record.included_workflows);
    record.cases.forEach((item,index)=>{
      const card=node('details',undefined,result);card.className='panel';node('summary','Real case '+(index+1)+' · originally run '+date(item.when),card);
      node('p','Frozen expected answer: '+item.expected,card);values(card,item.inputs);
      ['baseline','candidate'].forEach(arm=>{const row=item.results?.[arm];if(!row)return;node('p',(arm==='baseline'?'Published rules':'Proposed rules')+': '+row.result+' · '+(row.matches?'matches expected answer':'does not match')+' · '+row.elapsed_ms.toFixed(3)+' ms',card);
        const link=node('a','Review the recorded '+(arm==='baseline'?'published-rule':'proposed-rule')+' replay',card);link.className='btn btn--ghost';link.href='/flows/'+encodeURIComponent(record.flow_id)+'/runs/'+encodeURIComponent(row.run_id);});
    });
    document.getElementById('flow-comparison-release').href='/research?release_flow='+encodeURIComponent(record.flow_id)+'#local-flow-release';
  }
  async function refresh() {
    if(busy)return;lock(true);const current=++generation, chosen=flow.value||new URLSearchParams(location.search).get('workflow')||'';clear();
    try {
      if(!chosen) {const listing=await request('');flow.replaceChildren(new Option('Choose a saved workflow',''));listing.flows.forEach(row=>flow.appendChild(new Option(row.name,row.id)));status.textContent='Choose a changed saved rule-only workflow with an exact published baseline.';state=null;return;}
      const retained=await request('/history?flow_id='+encodeURIComponent(chosen));if(current!==generation)return;
      history.replaceChildren(new Option('Choose a retained comparison',''));retained.comparisons.forEach(row=>history.appendChild(new Option(date(row.when)+' · '+({done:'Completed',running:'Result not yet recorded',prepared:'Authorized',unavailable:'Complete result unavailable'}[row.state]||'Check original result'),row.id)));
      if(pending&&!Array.from(history.options).some(item=>item.value===pending))history.appendChild(new Option('Original request · check saved result',pending));
      const checked=await request('?flow_id='+encodeURIComponent(chosen));if(current!==generation)return;if(checked.context!==retained.context)throw new Error('Your account or workspace changed. Refresh before reviewing original work.');state=checked;
      if(!Array.from(flow.options).some(item=>item.value===chosen))flow.appendChild(new Option(checked.name,chosen));flow.value=chosen;
      document.getElementById('flow-comparison-version').textContent=checked.name+' · published version '+checked.baseline_version+' · proposed saved version '+checked.version;
      versions(document.getElementById('flow-comparison-included'),checked.included_workflows);
      output.replaceChildren(new Option('Choose a final result',''));checked.outputs.forEach(row=>output.appendChild(new Option(row.label,row.value)));
      status.textContent=checked.scope+' '+checked.cases.length+' real retained runs are available for selection.';
      if(!checked.can_compare)status.textContent+=' This draft is already published. Its retained comparisons remain available; save a changed draft before starting another comparison.';
      if(unconfirmed)status.textContent+=' Check the original comparison result before starting another.';
    }catch(failure){state=null;error.textContent=failure.message;status.textContent='Current saved versions could not be verified. Retained comparisons can still be selected; results require their original sources to remain available.';}finally{if(current===generation)lock(false);}
  }
  function addCase() {
    if(busy||!state||!output.value||selected.length>=5){error.textContent='Choose a final result first, then select up to five real cases.';return;}
    form.elements.case_use.checked=false;
    const section=node('fieldset',undefined,cases);section.style.minWidth='0';section.style.marginBlock='var(--space-3)';node('legend','Real case '+(selected.length+1),section);
    const label=node('label','Original actual run',section), select=node('select',undefined,label);select.className='input';select.required=true;select.appendChild(new Option('Choose a real run',''));state.cases.forEach(row=>select.appendChild(new Option('Run '+date(row.when)+' · '+(row.state==='completed'?'Finished':'Stopped with a recorded failure'),row.id)));
    const detail=node('div',undefined,section), expectedLabel=node('label','Expected final answer',section), kind=state.outputs.find(row=>row.value===output.value).kind;
    const expected=node(kind==='boolean'?'select':'input',undefined,expectedLabel);expected.className='input';expected.required=true;expected.style.maxWidth='100%';expected.style.minWidth='0';
    if(kind==='boolean'){expected.append(new Option('Choose expected answer',''),new Option('Yes','true'),new Option('No','false'));}else{expected.type='text';expected.maxLength=kind==='integer'?26:1024;if(kind==='integer'){expected.inputMode='numeric';expected.pattern='-?(0|[1-9][0-9]{0,24})';}}
    const item={section,select,expected,kind,source:null};selected.push(item);
    expected.addEventListener('input',()=>{form.elements.case_use.checked=false;});
    expected.addEventListener('change',()=>{form.elements.case_use.checked=false;});
    select.addEventListener('change',async()=>{const current=generation;item.source=null;detail.replaceChildren();form.elements.case_use.checked=false;lock(true);try{const source=await request('/case?flow_id='+encodeURIComponent(state.flow_id)+'&run_id='+encodeURIComponent(select.value)+'&output='+encodeURIComponent(output.value));if(current!==generation)return;item.source=source;values(detail,source.inputs);node('p','Original recorded result: '+(source.original_result===null?'No result recorded':String(source.original_result)),detail);}catch(failure){error.textContent=failure.message;}finally{if(current===generation)lock(false);}});
    const remove=node('button','Remove case',section);remove.type='button';remove.className='btn btn--ghost';remove.addEventListener('click',()=>{selected.splice(selected.indexOf(item),1);section.remove();form.elements.case_use.checked=false;});
  }
  flow.addEventListener('change',()=>void refresh());output.addEventListener('change',()=>{selected.length=0;cases.replaceChildren();form.elements.case_use.checked=false;});
  document.getElementById('flow-comparison-add').addEventListener('click',addCase);
  document.getElementById('flow-comparison-refresh').addEventListener('click',()=>void refresh());
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy||!state||!state.can_compare||unconfirmed||!form.reportValidity())return;
    if(!selected.length||selected.some(item=>!item.source)){error.textContent='Choose and review at least one original real case.';return;}
    const current=generation;lock(true);error.textContent='';
    try {
      const confirmed=window.mvConfirm?await window.mvConfirm('Freeze these original values and expected answers, and authorize their reuse for this exact local comparison and independent release review? Each version uses the included workflows shown here. No AI or connected action starts.',{okText:'Compare saved rules'}):window.confirm('Freeze the cases and compare saved rules locally?');if(!confirmed||current!==generation||!state)return;
      const operation=(window.mvNewId ? window.mvNewId() : crypto.randomUUID()).replace(/-/g,'');pending='FCP-'+operation;unconfirmed=true;
      const body={context:state.context,confirm:true,authorize_case_use:form.elements.case_use.checked,operation,flow_id:state.flow_id,version:state.version,revision:state.revision,baseline_release:state.baseline_release,bundle:state.bundle,output:output.value,cases:selected.map(item=>({run_id:item.source.run_id,source_version:item.source.version,expected:item.kind==='boolean'?item.expected.value==='true':item.expected.value}))};
      const recorded=await request('',body);if(current!==generation)return;render(recorded);history.appendChild(new Option(date(recorded.summary.when)+' · original request',recorded.id));history.value=recorded.id;status.textContent='The original comparison result was read from native records. No publication changed.';
    }catch(failure){if(current===generation){error.textContent=failure.message;if(pending){history.appendChild(new Option('Original request · check saved result',pending));history.value=pending;}}}finally{if(current===generation)lock(false);}
  });
  document.getElementById('flow-comparison-read').addEventListener('click',async()=>{if(busy)return;const identifier=history.value||pending,current=generation;if(!identifier){error.textContent='Choose a retained comparison first.';return;}lock(true);error.textContent='';try{const saved=await request('/'+encodeURIComponent(identifier));if(current!==generation)return;render(saved);status.textContent='The original saved result was checked. Nothing ran again.';}catch(failure){if(current===generation){result.hidden=true;error.textContent=failure.message;}}finally{if(current===generation)lock(false);}});
  document.addEventListener('lightwork:account-context-changed',()=>{++generation;requests.forEach(controller=>controller.abort());state=null;pending=null;unconfirmed=false;clear();lock(false);history.replaceChildren(new Option('Refresh retained comparisons',''));flow.replaceChildren(new Option('Refresh in the current workspace',''));status.textContent='Your account or workspace changed. Refresh before selecting original work.';});
  void refresh();
})();
