(() => {
  'use strict';
  let context=null,lost=false,serial=0,busy=false;
  const node=(tag,text)=>{const item=document.createElement(tag);if(text)item.textContent=text;return item;};
  const panel=node('section');panel.className='panel';panel.hidden=true;panel.id='connection-impact-review';
  document.querySelector('main')?.append(panel);
  const clear=()=>{lost=true;serial++;panel.replaceChildren(node('p','Access or workspace changed. Reload Connections.'));};
  document.addEventListener('lightwork:workspace-changed',clear);document.addEventListener('lightwork:connection-access-lost',clear);
  async function request(name,path,body){
    return window.mvFetchJSON('/api/v1/connections/'+encodeURIComponent(name)+path,{method:body?'POST':'GET',body,cache:'no-store',timeout:20000,plainDetail:true,
      onAccess:()=>{clear();document.dispatchEvent(new Event('lightwork:connection-access-lost'));}},body?'review the connection change':'load the connection review');
  }
  function button(label,fn){const item=node('button',label);item.className='btn';item.type='button';item.addEventListener('click',fn);return item;}
  function render(value){
    panel.replaceChildren(node('h2','Review work using '+value.name),node('p',value.note));panel.hidden=false;
    const list=node('ul');
    for(const item of value.items){const row=node('li',item.title+' — '+item.state+'. '+item.binding+' ');const link=node('a','Review saved work');link.href=item.href;row.append(link);list.append(row);}panel.append(list);
    if(!value.items.length)panel.append(node('p','No declared affected work was found in the inspected sources. Review the coverage limits below.'));
    const coverage=node('ul');for(const item of value.coverage)coverage.append(node('li',item.kind+': '+item.state));panel.append(coverage);
    const receipts=node('details');receipts.append(node('summary','Earlier service checks (up to the retained 100 checks)'));
    for(const receipt of value.receipts)receipts.append(node('p',(window.mvTimeAbsolute ? window.mvTimeAbsolute(receipt.tested_at) : new Date(receipt.tested_at*1000).toLocaleString())+' — '+(receipt.outcome||'earlier check')+' — '+(receipt.capability||'service check')));panel.append(receipts);
    const label=node('label','Choose a reviewed replacement connection'),select=node('select');select.className='input';
    const self=node('option','Current saved credential (repair its exact source binding)');self.value=value.name;select.append(self);
    for(const record of value.replacements){const option=node('option',record.name+' — '+record.connector);option.value=record.name;select.append(option);}label.append(select);panel.append(label);
    panel.append(node('p','For API-key rotation, first save a separate connection with the same service address and adapter, then verify its authentication. Switching keeps this connection’s reviewed sharing. Renewable accounts reconnect through provider consent.'));
    const status=node('p');status.setAttribute('role','status');panel.append(status);
    function body(){const replacement=value.replacements.find(row=>row.name===select.value);return {context:value.context,expected_revision:value.revision,impact_version:value.impact_version,replacement:select.value,replacement_revision:replacement?replacement.revision:value.revision,confirm:true};}
    async function mutate(control,path,payload,question){
      if(busy||lost)return;busy=true;control.disabled=true;
      try{
        if(!await mvConfirm(question,{okText:'Apply reviewed change'})){control.disabled=false;return;}
        const result=await request(value.name,path,payload);if(lost)return;
        status.textContent=result.next_action||'Change recorded. Review the current connection before continuing.';
        // A successful mutation invalidates every review token shown here.
        panel.querySelectorAll('button,select').forEach(item=>item.disabled=true);
        document.dispatchEvent(new Event('lightwork:connection-saved'));
      }catch(error){status.textContent=error.name==='AbortError'?'Result not confirmed. Refresh the review before any retry. No action will be replayed.':error.message;panel.querySelectorAll('button,select').forEach(item=>item.disabled=true);}
      finally{busy=false;}
    }
    const replace=button('Switch to staged API key',()=>mutate(replace,'/replace-staged',body(),'Switch the saved credential after reviewing this impact? Sharing stays as currently configured; pinned sources and approvals need fresh review. No historical work will be replayed.'));if(value.can_manage)panel.append(replace);
    for(const item of value.items.filter(row=>value.can_rebind&&row.kind==='discovery_source')){
      const repair=button('Rebind '+item.title,()=>mutate(repair,'/rebind-source',{...body(),source_id:item.id,source_revision:item.revision,operation_id:crypto.randomUUID().replace(/-/g,'')},'Rebind this exact source to the selected current credential? Its resource and evidence settings stay fixed. No scan or historical action starts.'));panel.append(repair);
    }
    const capabilities=node('fieldset');capabilities.append(node('legend','Check the exact read your task needs'));
    if(!value.capabilities.length)capabilities.append(node('p','This connection has no built-in read check here. A general service check does not prove a task can read the data. Use the source access check where available, or review the provider permissions for the task.'));
    for(const capability of value.capabilities){
      const row=node('div');row.append(node('h3',capability.label),node('p','Minimum access: '+capability.minimum_scope+'. No write permission is tested.'));
      const label=node('label',capability.resource_label),resource=node('input');resource.className='input';resource.maxLength=256;label.append(resource);row.append(label);
      const check=button('Review read-only check',async()=>{
        if(busy||lost||!resource.value.trim())return;busy=true;check.disabled=true;
        try{
                    const result=await request(value.name,'/capability-check',{context:value.context,expected_revision:value.revision,capability:capability.id,resource:resource.value.trim(),confirm:true});
          status.textContent=result.verified?'This exact resource read was verified at '+(window.mvTimeAbsolute ? window.mvTimeAbsolute(result.tested_at) : new Date(result.tested_at*1000).toLocaleTimeString())+'. Write access and future access remain unverified. No task was resumed.':'The exact resource read was not verified: '+result.outcome.replace(/_/g,' ')+'. Other connections remain available.';
        }catch(error){status.textContent=error.message;}
        finally{busy=false;check.disabled=false;}
      });row.append(check);capabilities.append(row);
    }
    for(const receipt of value.capability_receipts||[])capabilities.append(node('p',receipt.label+' — '+(receipt.revision!==value.revision?'older credential':Date.now()-receipt.tested_at*1000>86400000?'stale check':receipt.verified?'verified exact resource read':'not verified')+' — '+(window.mvTimeAbsolute ? window.mvTimeAbsolute(receipt.tested_at) : new Date(receipt.tested_at*1000).toLocaleString())+'. Write access was not checked.'));
    panel.append(capabilities);
    panel.append(node('p','Local removal does not revoke upstream authorization. Review the provider’s connected-app controls separately, without revoking another application’s access.'));
    for(const [provider,url] of Object.entries(value.provider_revocation||{})){const link=node('a','Review '+provider+' connected apps');link.href=url;link.target='_blank';link.rel='noopener noreferrer';panel.append(link,node('br'));}
    panel.scrollIntoView({block:'nearest'});
  }
  async function load(name,revision){
    if(lost)throw new Error('Reload Connections after restoring access.');const attempt=++serial;
    const value=await request(name,'/impact');if(attempt!==serial||lost)throw new Error('Review was replaced.');
    if(context&&context!==value.context){clear();throw new Error('Workspace changed. Reload Connections.');}context=value.context;
    if(revision&&value.revision!==revision)throw new Error('The saved connection changed. Reload it before continuing.');
    render(value);return value;
  }
  window.lightworkConnectionImpact={review:async(name,revision,action,expectedContext)=>{
    const value=await load(name,revision);
    if(value.context!==expectedContext)throw new Error('Workspace changed. Reload Connections before changing it.');
    const details=value.items.map(item=>item.title+' — '+item.state).join('\n')||'No declared affected objects were found; coverage is shown on the page.';
    if(!await mvConfirm((action==='remove'?'Remove this local connection?':'Apply this connection change?')+'\n'+details+'\n\n'+value.note+' Review incomplete and dynamic coverage before proceeding.',{okText:action==='remove'?'Remove local connection':'Apply reviewed change'}))return null;
    return value.impact_version;
  }};
  const initial=new URLSearchParams(location.search).get("review");if(initial)load(initial).catch(error=>{panel.hidden=false;panel.replaceChildren(node("p",error.message));});
  document.addEventListener('click',event=>{const target=event.target.closest('[data-connection-impact]');if(target)load(target.dataset.connectionImpact,target.dataset.connectionRevision).catch(error=>{panel.hidden=false;panel.replaceChildren(node('p',error.message));});});
})();
