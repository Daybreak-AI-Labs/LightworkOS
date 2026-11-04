(() => {
  'use strict';
  const root=document.getElementById('plugin-workbench');if(!root)return;
  const status=root.querySelector('[role=status]'),list=root.querySelector('[data-workbench-list]');
  let context=null,serial=0,lost=false,busy=false,active=null;
  const node=(tag,text)=>{const item=document.createElement(tag);item.textContent=text||'';return item;};
  const clear=()=>{lost=true;serial++;list.replaceChildren();status.textContent='Access changed. Reload Plugins in the current workspace.';};
  document.addEventListener('lightwork:workspace-changed',clear);
  async function call(path,body){
    return window.mvFetchJSON('/api/v1/plugins/workbench'+path,{method:body?'POST':'GET',body,cache:'no-store',timeout:55000,plainDetail:true,onAccess:clear,
      messages:{401:'Permission is unavailable. Refresh the page and try again.',403:'Permission is unavailable. Refresh the page and try again.'}},
      body?'finish the workbench step':'load the workbench');
  }
  function button(label,fn){const item=node('button',label);item.type='button';item.className='btn';item.addEventListener('click',fn);return item;}
  async function mutate(control,path,body,question){
    if(lost||busy)return;busy=true;control.disabled=true;
    try{if(!await mvConfirm(question,{okText:'Apply reviewed action'}))return;
      active=body.operation_id||null;const result=await call(path,{...body,context,confirm:true});if(lost)return;
      status.textContent=(result.state||'Change recorded')+'. No task was resumed and no historical work was replayed.';await refresh();
    }catch(error){status.textContent=error.name==='AbortError'?'The result is unconfirmed. Refresh the ledger; do not repeat this operation.':error.message;}
    finally{active=null;busy=false;control.disabled=lost;}
  }
  root.querySelector('[data-workbench-cancel]').addEventListener('click',async()=>{
    if(!active||lost)return;try{await call('/'+active+'/cancel',{context});status.textContent='Cancellation requested. Refresh to verify container cleanup; the outcome remains unknown until recorded.';}catch(error){status.textContent=error.message;}
  });
  async function refresh(){
    if(lost)return;const attempt=++serial;status.textContent='Reading version-specific qualification evidence.';
    try{
      const value=await call('');if(attempt!==serial||lost)return;if(context&&context!==value.context){clear();return;}context=value.context;
      list.replaceChildren();
      for(const plugin of value.plugins){
        const panel=node('section');panel.className='panel';panel.append(node('h3',plugin.name+' / '+plugin.distribution+' / '+plugin.version),node('p',plugin.scope),node('p',plugin.blocked||''));
        panel.append(node('p',plugin.eligible?(['maverick.ts','maverick.grpc'].includes(plugin.group)?'Configured source is inspectable. Its manifest and schema will be checked inside the restricted image.':'Manifest and current admission policy permit sandbox checks.'):'Qualification blocked: inspect the manifest, version, permissions or plugin kind below.'));
        const metadata=node('details');metadata.append(node('summary','Declared contract and permissions'),node('pre',JSON.stringify({manifest:plugin.manifest,missing_permissions:plugin.missing_permissions,policy_allowed:plugin.policy_allowed},null,2)));panel.append(metadata);
        const affected=value.dependencies.flows.filter(flow=>flow.tools.includes(plugin.name));
        for(const flow of affected){const link=node('a','Review affected workflow: '+flow.name);link.href=flow.href;panel.append(link,node('br'));}
        for(const pin of value.dependencies.tasks.filter(row=>row.distribution===plugin.distribution&&row.name===(plugin.pin_name||plugin.name)&&(row.group||'maverick.tools')===plugin.group)){
          const label=node('p','Task '+pin.goal_id+' - '+pin.title+' - '+(pin.fingerprint===plugin.content_sha256?'pinned to current bytes':'retains earlier bytes; dispatch blocked after drift'));
          const link=node('a','Review this task');link.href=pin.href;label.append(link);panel.append(label);
          const migrate=button('Review task version migration',()=>mutate(migrate,'/migrate',{goal_id:pin.goal_id,fingerprint:plugin.fingerprint,previous:pin.fingerprint},'Change this stopped task to the currently qualified version? No work is resumed. Unknown earlier effects require separate reconciliation.'));panel.append(migrate);
        }
        for(const pin of (value.dependencies.runs||[]).filter(row=>row.distribution===plugin.distribution&&row.name===(plugin.pin_name||plugin.name)&&(row.group||'maverick.tools')===plugin.group)){
          const label=node('p','Workflow run '+pin.run_id+' / '+pin.title+' / '+pin.state+' / '+(pin.fingerprint===plugin.content_sha256?'pinned to current bytes':'earlier bytes retained; dispatch blocked'));
          const link=node('a','Review workflow');link.href=pin.href;label.append(link);panel.append(label);
          const migrate=button('Review workflow version migration',()=>mutate(migrate,'/migrate-flow',{run_id:pin.run_id,fingerprint:plugin.fingerprint,previous:pin.fingerprint},'Migrate this stopped workflow to the qualified version? Review prior outcomes first. This does not resume it or replay an action.'));panel.append(migrate);
        }
        const practice=node('section');practice.className='plg-practice';panel.append(practice);
        if(plugin.eligible&&window.LightworkPluginPractice)window.LightworkPluginPractice.mount(practice,plugin,context);
        else practice.append(node('p','Approve this installed version and its declared access before reading its ordinary practice questions. No check has started.'));
        const rollbackLabel=node('label','Affected-work review and rollback plan'),rollback=node('textarea');rollback.className='input';rollback.maxLength=2000;rollbackLabel.append(rollback);panel.append(rollbackLabel);
        const publish=button('Publish scoped readiness',()=>mutate(publish,'/publish',{fingerprint:plugin.fingerprint,rollback:rollback.value},'Publish sandbox-only readiness for this exact plugin version after reviewing affected work and the rollback plan? External service acceptance remains unverified.'));panel.append(publish);
        for(const receipt of value.publications.filter(row=>row.fingerprint===plugin.fingerprint))panel.append(node('p','Published scope: '+receipt.scope+'. Check observations: '+JSON.stringify(receipt.observations||[])+'. Rollback: '+receipt.rollback));
        list.append(panel);
      }
      const records=node('details');records.open=true;records.append(node('summary','Check ledger (completed, interrupted, and obsolete versions)'));
      for(const row of value.checks)records.append(node('p',row.plugin+' / '+row.version+' / '+row.mode+' - '+row.state+(row.current?'':' (version or policy changed)')+'. '+(row.check_observation||row.reason||'Result unconfirmed; refresh, never replay the same operation.')+' / '+row.id));list.append(records);
      status.textContent=value.dependencies.coverage.join(' ')+(value.plugins.length?'':' No installed plugin entry points were found; nothing was qualified.');
    }catch(error){if(attempt===serial){list.replaceChildren();status.textContent=error.message+' Open Settings to review workbench and immutable-image configuration.';}}
  }
  root.querySelector('[data-workbench-refresh]').addEventListener('click',refresh);refresh();
})();
