(() => {
  'use strict';
  const list=document.getElementById('account-inventory-list'), status=document.getElementById('account-inventory-status');
  if (!list) return;
  let serial=0, context=null, lost=false;
  const node=(tag,text)=>{ const item=document.createElement(tag); item.textContent=text; return item; };
  const clear=()=>{serial++;lost=true;list.replaceChildren();document.getElementById('account-qualification-list')?.replaceChildren();status.textContent='Account access changed. Reload after selecting your workspace.';};
  document.addEventListener('lightwork:connection-access-lost',clear);
  document.addEventListener('lightwork:workspace-changed',clear);
  async function refresh() {
    if(lost)return;
    const attempt=++serial, controller=new AbortController(), timer=setTimeout(()=>controller.abort(),15000);
    status.textContent='Checking account inventory.';
    try {
      const response=await fetch('/api/v1/connections/inventory',{cache:'no-store',signal:controller.signal});
      if(attempt!==serial)return;
      if([401,403].includes(response.status)){clear();return;}
      if(!response.ok)throw new Error();
      const data=await response.json();
      if(attempt!==serial)return;
      if(!Array.isArray(data.accounts)||!Array.isArray(data.coverage)||typeof data.context!=='string')throw new Error();
      if(context&&context!==data.context){clear();return;} context=data.context;
      list.replaceChildren();
      data.accounts.forEach(account=>{
        const item=node('li',''); item.className='mv-row';
        item.append(node('strong',account.name),node('p',account.domain+' · '+account.owner+' · '+account.sharing),node('p',account.identity));
        if(account.expires_at)item.append(node('p',(account.expired?'Expired at ':'Expires at ')+(window.mvTimeAbsolute ? window.mvTimeAbsolute(account.expires_at) : new Date(account.expires_at*1000).toLocaleString())+(account.renews?' · renewal configured':'')));
        if(account.workspace&&account.workspace.name)item.append(node('p','Workspace: '+account.workspace.name));
        if(account.site_url)item.append(node('p','Connected site: '+account.site_url));
        if(account.renewal_state)item.append(node('p','Renewal: '+account.renewal_state.replace(/_/g,' ')));
        if(account.recovery_action)item.append(node('p',account.recovery_action));
        if(account.granted_scopes&&account.granted_scopes.length){const details=node('details',''),summary=node('summary','Provider access details');details.append(summary,node('p',account.granted_scopes.join(', ')));item.append(details);}
        if(account.usage_coverage)item.append(node('p',account.usage_coverage));
        const dependencies=node('a','Review used-by information');dependencies.href=account.used_by_href||'/connections';item.append(dependencies,node('br',''));
        const link=node('a','Review or repair this account'); link.href=account.credential_kind==='automation'?'/automations#oauth-connect':'/connections';item.append(link);list.append(item);
      });
      const gaps=data.coverage.filter(item=>item.state!=='available');
      status.textContent=(data.accounts.length ? data.accounts.length+' accounts listed. ' : gaps.length ? 'Account coverage is incomplete. ' : 'No accounts are connected. ')+gaps.map(item=>item.domain+': '+item.state.replace(/-/g,' ')).join('; ');
    }catch(_){if(attempt===serial){list.replaceChildren();status.textContent='Account inventory is unavailable. Refresh before setting up a replacement account.';}}
    finally{clearTimeout(timer);}
  }
  const qualification=document.getElementById('account-qualification');
  if(qualification)qualification.addEventListener('toggle',async()=>{
    if(!qualification.open||lost)return;
    const output=document.getElementById('account-qualification-list'),notice=document.getElementById('account-qualification-status');
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000),attempt=serial;
    notice.textContent='Loading qualification evidence.';output.replaceChildren();
    try{
      const response=await fetch('/api/v1/connections/qualification',{cache:'no-store',signal:controller.signal});
      if(!response.ok)throw new Error();const data=await response.json();
      if(lost||attempt!==serial)return;if(context&&context!==data.context){clear();return;}
      notice.textContent=data.note;
      for(const row of data.rows){const item=node('li',row.label+' — '+row.surface+' — '+row.qualification+'. Synthetic: '+row.synthetic+'. Native: '+row.native+'. Live provider: '+row.live_provider+'. '+row.recovery);output.append(item);}
    }catch(_){notice.textContent='Qualification evidence is unavailable; support must not be assumed.';}
    finally{clearTimeout(timer);}
  });
  document.getElementById('account-inventory-refresh').addEventListener('click',refresh);
  document.addEventListener('lightwork:connection-saved',refresh);refresh();
})();
