(() => {
  'use strict';
  const copy=(node,text)=>window.LightworkI18n?window.LightworkI18n.set(node,text):(node.textContent=text);
  const mounted=new Set();
  function mount(select) {
    if(select.dataset.connectionMounted)return;
    select.dataset.connectionMounted='true';
    const status=document.createElement('span'), retry=document.createElement('button'), link=document.createElement('a');
    status.setAttribute('role','status');retry.type='button';retry.className='btn btn--ghost';copy(retry,'Refresh accounts');
    link.href='/connections';copy(link,'Open Connections');select.after(status,retry,link);
    let serial=0, context=null, lost=false;
    function clear(){serial++;lost=true;select.replaceChildren();select.value='';select.disabled=false;select.setCustomValidity('Account selection is unavailable. Refresh the page and try again.');copy(status,'Account or workspace changed. Reload to continue.');retry.disabled=true;}
    mounted.add(clear);
    async function load(){
      if(lost)return;const attempt=++serial, previous=select.value;
      retry.disabled=true;select.disabled=false;select.setCustomValidity('Account selection is unavailable. Refresh the page and try again.');
      const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
      try {
        const response=await fetch('/api/v1/templates/connection-choices',{cache:'no-store',signal:controller.signal});
        if(response.status===401||response.status===403||response.redirected){clear();return;}
        const data=await response.json();
        if(!response.ok||!data||typeof data.context!=='string'||!Array.isArray(data.choices)||data.choices.some(x=>!x||typeof x.value!=='string'||typeof x.name!=='string'||typeof x.connector!=='string'))throw new Error();
        if(attempt!==serial||lost)return;
        if(context!==null&&context!==data.context){clear();return;}context=data.context;
        select.replaceChildren();const empty=new Option('','');copy(empty,'Choose a connected account');select.append(empty);
        data.choices.forEach(item=>{const option=new Option(item.name+' ('+item.connector+')',item.value);option.lang='und';option.dir='auto';option.dataset.userContent='';select.append(option);});
        // Preserve only the identical saved generation. Never choose another account.
        select.value=data.choices.some(item=>item.value===previous)?previous:'';
        select.disabled=Boolean(select.closest('[data-parameter-row]')?.hidden);select.setCustomValidity('');
        copy(status,data.choices.length?'Account selections must be renewed after the account or its permissions change.':'No eligible connected accounts. Open Connections to connect your own account.');
        select.dispatchEvent(new Event('change',{bubbles:true}));
      }catch(_){if(attempt===serial&&!lost){select.replaceChildren();select.value='';copy(status,'Connected accounts could not be loaded. Retry or open Connections.');}}
      finally{clearTimeout(timer);if(attempt===serial&&!lost)retry.disabled=false;}
    }
    retry.addEventListener('click',load);load();
  }
  document.addEventListener('lightwork:workspace-changed',()=>mounted.forEach(clear=>clear()));
  window.LightworkTemplateConnections={mount};
  document.querySelectorAll('[data-connected-account]').forEach(mount);
})();
