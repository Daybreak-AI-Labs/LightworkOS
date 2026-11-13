(function () {
  'use strict';
  const node = (tag, text) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; return e; };
  function coverageReview(panel, data, coverage, request, reload, mutation) {
    if(!coverage)return;
    const box=node('section');box.id='op-cost-coverage';box.append(node('h3','Provider cost per accepted outcome'));
    const metric=coverage.provider_cost_per_accepted_outcome;
    box.append(node('p',metric ? metric.currency+' '+metric.amount+' per accepted outcome — '+metric.provider_cost_total+' allocated across all '+metric.planned_cases+' planned cases, divided by '+metric.accepted_outcomes+' accepted outcomes. Attribution and completeness are operator reviewed; the result is rounded to nine decimal places.' : 'Not measured. Complete planned-case cost coverage must be reviewed, with one currency and at least one accepted outcome. Missing costs are not zero.'));
    box.append(node('p',coverage.covered_cases+' / '+coverage.planned_cases+' cases have current eligible cost coverage. '+coverage.explanation));
    if(coverage.review){const details=node('details');details.append(node('summary','Recorded coverage review'));details.append(node('p',coverage.review.note));box.append(details);}
    const form=node('form');form.id='op-cost-coverage-form';form.dataset.draftRecovery='off';
    const label=node('label','How all attempts, failures and rejected cases were accounted for'),note=node('textarea');note.className='input';note.required=true;note.rows=3;note.maxLength=4000;label.append(note);form.append(label);
    const confirmed=node('label'),checkbox=node('input');checkbox.type='checkbox';checkbox.required=true;confirmed.append(checkbox,node('span',' I reviewed every planned case. All provider costs for those cases, including failed attempts and rejected results, are in the current allocations.'));form.append(confirmed);
    const button=node('button','Confirm complete provider cost coverage');button.type='submit';button.className='btn';button.disabled=!coverage.can_confirm;form.append(button);box.append(form);panel.append(box);
    form.addEventListener('input',event=>{if(event.target!==checkbox){checkbox.checked=false;delete form.dataset.operation;}});
    form.addEventListener('submit',event=>{event.preventDefault();if(!coverage.can_confirm||!checkbox.checked||!form.reportValidity())return;
      const body={expected_revision:data.revision,operation_id:form.dataset.operation||(window.mvNewId ? window.mvNewId() : crypto.randomUUID()),coverage_version:coverage.version,currency:coverage.currency,note:note.value.trim(),confirm:true};form.dataset.operation=body.operation_id;
      mutation(async()=>{try{await request('/'+data.id+'/provider-costs/coverage','PUT',body);}catch(error){if([401,403,404].includes(error.status))panel.replaceChildren(node('h2','Provider billing unavailable'),node('p',error.message));throw error;}delete form.dataset.operation;await reload(data.id);});
    });
  }
  window.LightworkPilotCosts = {render({host, data, request, reload, mutation}) {
    const panel = node('section'); panel.className = 'panel'; panel.id = 'op-provider-costs';
    panel.append(node('h2', 'Admitted provider costs'));
    const costs = data.provider_costs;
    if (!costs || !['current','partial'].includes(costs.status)) { panel.append(node('p', costs && costs.reason || 'Provider billing is unavailable. Refresh the page and try again.')); host.append(panel); return; }
    if(costs.status==='partial')panel.append(node('p','Cost coverage is partial: changed or unavailable allocations are excluded from current totals. Review the flagged sources below.'));
    panel.append(node('p', 'Provider amounts are separate from your reported total workflow, human and rework costs. Allocation to cases is your reviewed attribution; invoice authenticity is not independently verified.'));
    const setup=node('a','Open AI cost collection and receipt setup');setup.href='/security/assurance';panel.append(setup);
    const totals = Object.entries(costs.current_totals_by_currency || {});
    panel.append(node('p', totals.length ? 'Current allocated provider cost: ' + totals.map(([currency,amount]) => currency + ' ' + amount).join(' · ') : 'No current provider cost allocation. Unknown costs are not zero.'));
    coverageReview(panel,data,costs.coverage,request,reload,mutation);
    (costs.allocations || []).forEach(allocation => {
      const details = node('details'); details.append(node('summary', allocation.source ? allocation.source.provider + ' · ' + allocation.source.source_record_id + ' · ' + allocation.status.replaceAll('_',' ') : 'Source unavailable'));
      if (allocation.source) {
        details.append(node('p', 'Source net cost: ' + allocation.source.currency + ' ' + allocation.source.net_cost + '. Unallocated: ' + allocation.unallocated_cost + '. ' + allocation.note));
        allocation.allocated.forEach(share => details.append(node('p', 'Case ' + share.case_id + ': ' + allocation.currency + ' ' + share.amount)));
        const evidence = node('details'); evidence.append(node('summary', 'Technical details: source, corrections and allocation history')); const pre = node('pre', JSON.stringify(allocation,null,2)); pre.style.whiteSpace='pre-wrap'; evidence.append(pre); details.append(evidence);
      }
      panel.append(details);
    });
    const form = node('form'); form.id='op-cost-form';form.dataset.draftRecovery='off';
    const searchLabel=node('label','Find an admitted provider line'), search=node('input');search.type='search';search.className='input';search.maxLength=200;searchLabel.append(search);form.append(searchLabel);
    const searchButton=node('button','Find billing receipts');searchButton.type='button';searchButton.className='btn';form.append(searchButton);
    const sourceLabel=node('label','Original provider line and all admitted corrections'), select=node('select');select.className='input';select.required=true;select.append(new Option('Find and choose a source',''));sourceLabel.append(select);form.append(sourceLabel);
    const previous=node('button','Previous sources'), next=node('button','More sources');for(const button of [previous,next]){button.type='button';button.className='btn';button.hidden=true;form.append(button);}
    const sourceDetails=node('div');form.append(sourceDetails);
    const grid=node('div');grid.className='op-grid';const shares=[];
    data.cases.filter(c=>c.source && !c.source.sample && c.status!=='inputs_changed' && c.status!=='started_before_plan').forEach(c=>{
      const label=node('label','Case '+c.id+(c.label ? ': '+c.label : '')+' — share (%)'),input=node('input');input.type='number';input.className='input';input.min='0';input.max='100';input.step='0.01';input.value='0';label.append(input);grid.append(label);shares.push({case:c,input});
    });form.append(grid);
    form.append(node('p','Shares may total at most 100%. The remainder stays unallocated. Saving replaces this provider line’s prior case shares in this pilot; a zero total withdraws the allocation.'));
    const noteLabel=node('label','Attribution method and evidence'),note=node('textarea');note.className='input';note.required=true;note.maxLength=4000;note.rows=3;noteLabel.append(note);form.append(noteLabel);
    const confirmation=node('label'),checkbox=node('input');checkbox.type='checkbox';checkbox.required=true;confirmation.append(checkbox,node('span',' I reviewed the provider line, corrections and case shares.'));form.append(confirmation);
    const submit=node('button','Save reviewed allocation');submit.type='submit';submit.className='btn';submit.disabled=true;form.append(submit);
    const status=node('p');status.role='status';status.setAttribute('aria-live','polite');form.append(status);panel.append(form);host.append(panel);
    let catalogue=[],selected=null,offset=0,nextOffset=null,loading=false;
    function reset(){delete form.dataset.operation;checkbox.checked=false;}
    function choose(){
      reset();selected=catalogue.find(row=>row.id===select.value)||null;sourceDetails.replaceChildren();submit.disabled=!selected;
      shares.forEach(({input})=>{input.value='0';});note.value='';
      if(!selected)return;
      sourceDetails.append(node('p',selected.provider+' · '+selected.source_account_id+' · '+selected.source_record_id+' · '+selected.period_start+' to '+selected.period_end));
      sourceDetails.append(node('p','Net admitted amount: '+selected.currency+' '+selected.net_cost+' including '+selected.correction_count+' corrections.'));
      const evidence=node('details');evidence.append(node('summary','Technical details: source citations and correction evidence'));const pre=node('pre',JSON.stringify(selected,null,2));pre.style.whiteSpace='pre-wrap';evidence.append(pre);sourceDetails.append(evidence);
      const prior=(costs.allocations||[]).find(row=>row.source&&row.source.id===selected.id);
      if(prior){shares.forEach(({case:c,input})=>{const share=prior.shares.find(s=>s.case_id===c.id);input.value=share?String(share.basis_points/100):'0';});note.value=prior.note;}
    }
    async function find(start){
      if(loading)return;loading=true;searchButton.disabled=true;previous.disabled=true;next.disabled=true;status.textContent='Loading admitted billing sources…';
      try{
        const found=await request('/'+data.id+'/provider-costs?offset='+start+'&limit=50&query='+encodeURIComponent(search.value.trim()));
        if(!panel.isConnected)return;catalogue=found.items;offset=start;nextOffset=found.next_offset;select.replaceChildren(new Option('Choose a source',''));catalogue.forEach(row=>select.append(new Option(row.provider+' · '+row.source_record_id+' · '+row.currency+' '+row.net_cost,row.id)));choose();previous.hidden=offset===0;next.hidden=nextOffset===null;status.textContent=found.total+' matching source lines. Completed receipts only; no provider was contacted.';
      }catch(error){if(panel.isConnected){if([401,403,404,409].includes(error.status)){panel.replaceChildren(node('h2','Provider billing unavailable'),node('p',error.message));}else{status.textContent=error.message+' Your current attribution is still here.';}}}
      finally{loading=false;searchButton.disabled=false;previous.disabled=false;next.disabled=false;}
    }
    searchButton.addEventListener('click',()=>find(0));previous.addEventListener('click',()=>find(Math.max(0,offset-50)));next.addEventListener('click',()=>find(nextOffset));select.addEventListener('change',choose);
    form.addEventListener('input',event=>{if(event.target!==checkbox)reset();});
    form.addEventListener('submit',event=>{
      event.preventDefault();if(!form.reportValidity()||!selected||!checkbox.checked)return;
      const selectedShares=[];let total=0;
      for(const {case:c,input} of shares){const text=input.value.trim();if(!/^\d{1,3}(?:\.\d{1,2})?$/.test(text)){status.textContent='Use a percentage from 0 to 100 with at most two decimal places.';return;}const [whole,decimal='']=text.split('.'),points=Number(whole)*100+Number(decimal.padEnd(2,'0'));if(points>10000){status.textContent='Each share must be between 0 and 100%.';return;}if(points)selectedShares.push({case_id:c.id,basis_points:points,source_version:c.source.version});total+=points;}
      if(total>10000){status.textContent='Case shares exceed 100%. Adjust them before saving.';return;}
      const body={expected_revision:data.revision,operation_id:form.dataset.operation||(window.mvNewId ? window.mvNewId() : crypto.randomUUID()),observation_id:selected.id,billing_version:selected.version,shares:selectedShares,note:note.value.trim(),confirm:true};form.dataset.operation=body.operation_id;
      mutation(async()=>{try{await request('/'+data.id+'/provider-costs','PUT',body);}catch(error){if([401,403,404].includes(error.status))panel.replaceChildren(node('h2','Provider billing unavailable'),node('p',error.message));throw error;}delete form.dataset.operation;await reload(data.id);});
    });
  }};
})();
