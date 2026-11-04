(() => {
  'use strict';
  const node=(tag,text)=>{const e=document.createElement(tag);if(text)e.textContent=text;return e;};
  let context=null, invalid=false;
  document.addEventListener('lightwork:workspace-changed',()=>{invalid=true;document.querySelectorAll('[data-template-evidence]').forEach(e=>e.replaceChildren(node('p','Workspace changed. Reload Templates.')));});
  for(const card of document.querySelectorAll('[data-template-name]')){
    const box=node('details'),summary=node('summary','Measured outcomes and reviewed samples'),body=node('div');box.dataset.templateEvidence='';box.append(summary,body);card.append(box);
    let loaded=false,busy=false;
    async function load(){
      if(busy||invalid)return;busy=true;body.replaceChildren(node('p','Loading account-scoped evidence.'));
      const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
      try{
        const response=await fetch('/api/v1/templates/'+encodeURIComponent(card.dataset.templateName)+'/outcomes',{cache:'no-store',signal:controller.signal});
        const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'Evidence is unavailable. Refresh the page and try again.');
        if(invalid)return;if(context&&data.context!==context){invalid=true;throw new Error('Account changed. Reload Templates.');}context=data.context;
        body.replaceChildren(node('p',data.note));
        for(const evidence of data.evidence){
          const article=node('article');article.append(node('h4',evidence.title+(evidence.stale?' · older template version':'')),node('p','Reviewed scope: '+evidence.workflow_scope),node('p','Acceptance criteria: '+evidence.criteria),node('p','Exceptions: '+evidence.exceptions));
          article.append(node('p',evidence.accepted_cases+' accepted of '+evidence.planned_cases+' planned cases, including '+evidence.failed_cases+' failed and '+evidence.cancelled_cases+' cancelled. '+evidence.unavailable_cases+' cases are currently unavailable.'));
          article.append(node('p',evidence.corrected_cases+' cases required corrections; current observations cover '+evidence.correction_observed_cases+' of '+evidence.planned_cases+' planned cases.'));
          article.append(node('p',evidence.reported_cost_complete?'Complete reported cost difference: '+evidence.reported_cost_difference+' '+evidence.currency+'. Provider invoices are unverified.':'Cost coverage is incomplete or unknown. No total savings amount is claimed.'));
          article.append(node('p',evidence.scope),node('p',evidence.binding_basis));body.append(article);
        }
        if(!data.evidence.length)body.append(node('p','No pilot has been explicitly associated with this template in your account. Ratings are not measured outcomes.'));
        if(data.partial)body.append(node('p','This view covers the first 200 accessible pilots. Open Workflow pilots to review additional records.'));
        const link=node('a','Review or create a workflow pilot');link.href='/outcome-pilots';body.append(link);
        const trial=node('button','Review a sample draft');trial.type='button';trial.className='btn';trial.addEventListener('click',()=>{const use=card.querySelector('[data-prepare-template]');if(use)use.click();});if(card.querySelector('[data-prepare-template]'))body.append(trial);
        if(data.pilot_choices.length){
          const form=node('form'),label=node('label','Associate a pilot you reviewed for this version'),select=node('select');select.className='input';
          for(const pilot of data.pilot_choices){const option=node('option',pilot.title+' — '+pilot.workflow);option.value=pilot.id;select.append(option);}label.append(select);form.append(label);
          const exceptionsLabel=node('label','Intended exceptions and limits'),exceptions=node('textarea');exceptions.required=true;exceptions.maxLength=2000;exceptions.className='input';exceptionsLabel.append(exceptions);form.append(exceptionsLabel);
          const confirmLabel=node('label','I reviewed that this pilot concerns this saved template version; this attribution is not independent execution proof.'),confirm=node('input');confirm.type='checkbox';confirm.required=true;confirmLabel.prepend(confirm);form.append(confirmLabel);
          const submit=node('button','Save reviewed association');submit.className='btn';submit.type='submit';form.append(submit);const status=node('p');status.setAttribute('role','status');form.append(status);
          form.addEventListener('submit',async event=>{
            event.preventDefault();if(busy||invalid)return;busy=true;submit.disabled=true;
            const abort=new AbortController(),timeout=setTimeout(()=>abort.abort(),15000);
            try{
              const pilot=data.pilot_choices.find(row=>row.id===select.value);
              const response=await fetch('/api/v1/templates/'+encodeURIComponent(card.dataset.templateName)+'/outcomes/bind',{method:'POST',headers:{'Content-Type':'application/json'},signal:abort.signal,body:JSON.stringify({context,version:data.version,pilot_id:pilot.id,expected_revision:pilot.revision,exceptions:exceptions.value,confirm:confirm.checked})});
              const result=await response.json().catch(()=>({}));if(!response.ok)throw new Error(typeof result.detail==='string'?result.detail:'The association was not confirmed.');
              status.textContent='Association saved. Close and reopen this panel to refresh evidence.';loaded=false;
            }catch(error){status.textContent=error.name==='AbortError'?'The result is unknown. Reload before retrying.':error.message;}
            finally{clearTimeout(timeout);busy=false;submit.disabled=false;}
          });body.append(form);
        }
        loaded=true;
      }catch(error){if(!invalid)body.replaceChildren(node('p',error.message));}
      finally{clearTimeout(timer);busy=false;}
    }
    box.addEventListener('toggle',()=>{if(box.open&&!loaded)load();});
  }
})();
