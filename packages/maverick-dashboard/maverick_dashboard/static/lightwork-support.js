(function(root){
  'use strict';
  var doc=root.document,host=doc.getElementById('support-center');if(!host)return;
  var prepare=doc.getElementById('support-prepare'),download=doc.getElementById('support-download'),status=doc.getElementById('support-status');
  var result=doc.getElementById('support-result'),preview=doc.getElementById('support-preview'),confirm=doc.getElementById('support-confirm');
  var reference=doc.getElementById('support-reference'),readiness=doc.getElementById('support-readiness'),current=null,busy=false;
  var readable=doc.getElementById('support-readable');
  function human(v){return root.mvHuman?root.mvHuman(v):String(v).replace(/_/g,' ');}
  // The file service explains refusals in sentences written for people; anything else gets a plain fallback.
  function value(v){if(v===true)return'Yes';if(v===false)return'No';if(v===null||v===undefined||v==='')return'Not set';return String(v);}
  // A readable view of the same report: sections as headings, values as label/value rows.
  function render(node,data,depth){
    var list=doc.createElement('dl');
    Object.keys(data).forEach(function(key){
      var v=data[key];
      if(v&&typeof v==='object'&&!Array.isArray(v)&&depth<2){var h=doc.createElement('h4');h.textContent=human(key);node.append(h);render(node,v,depth+1);return;}
      var dt=doc.createElement('dt'),dd=doc.createElement('dd');dt.textContent=human(key);
      dd.textContent=Array.isArray(v)?(v.length?v.map(function(x){return typeof x==='object'?JSON.stringify(x):value(x);}).join(', '):'None'):(v&&typeof v==='object'?JSON.stringify(v):value(v));
      list.append(dt,dd);
    });
    if(list.children.length)node.append(list);
  }
  function controls(){prepare.disabled=busy;download.disabled=busy||!current||!confirm.checked;confirm.disabled=busy||!current;}
  function clear(){current=null;preview.textContent='';if(readable)readable.replaceChildren();reference.textContent='';readiness.replaceChildren();confirm.checked=false;result.hidden=true;controls();}
  async function call(path,body){
    // The response itself: a download is read by its caller.
    return root.mvFetchJSON('/api/v1/support/'+path,{method:'POST',cache:'no-store',raw:true,plainDetail:true,body,
      headers:{'X-Lightwork-Support-Context':host.dataset.context},onAccess:clear,
      messages:{401:'Your access changed. Sign in again before preparing or downloading a support report.',403:'Your access changed. Sign in again before preparing or downloading a support report.',409:'The report could not be confirmed. Prepare a new report before trying again.'}},'prepare the support report');
  }
  prepare.addEventListener('click',async function(){
    if(busy)return;clear();busy=true;controls();status.textContent='Preparing the support report…';
    try{
      var failure=new URLSearchParams(root.location.search).get('failure');
      var input=/^lw-failure-[0-9a-f]{32}$/.test(failure||'')?{failure_reference:failure}:{};
      var response=await call('preview',input),data=await response.json();
      if(!data||data.context!==host.dataset.context||!/^[0-9a-f]{32}$/.test(data.preview_id)||!/^[0-9a-f]{64}$/.test(data.sha256)||!data.bundle||typeof data.bundle!=='object')throw new Error('The report could not be verified for this account. Refresh the page and try again.');
      current=data;preview.textContent=JSON.stringify(data.bundle,null,2);if(readable)render(readable,data.bundle,0);reference.textContent='Support reference: '+String(data.bundle.correlation_id||'Unavailable')+' · Prepared '+String(data.bundle.generated_at||'just now');
      var labels={client_binding:'Workspace identity',shield:'Safety controls',agent_trust:'Trusted agents'};
      var checks=data.bundle.readiness||{};Object.keys(checks).forEach(function(key){var item=doc.createElement('li');item.textContent=(labels[key]||human(key))+': '+(checks[key]==='ok'?'ready':human(checks[key]).toLowerCase());readiness.append(item);});
      if(!readiness.children.length){var item=doc.createElement('li');item.textContent='Readiness details were unavailable. Review the report for the sections that were collected.';readiness.append(item);}
      result.hidden=false;status.textContent='Report ready for review. The download is available for ten minutes.';
    }catch(error){clear();status.textContent=error.message||'Support report unavailable. Try again in a minute.';}finally{busy=false;controls();}
  });
  confirm.addEventListener('change',controls);
  download.addEventListener('click',async function(){
    if(busy||!current||!confirm.checked)return;busy=true;controls();var selected=current;
    try{
      var response=await call('download',{preview_id:selected.preview_id,sha256:selected.sha256,confirm:true}),blob=await response.blob();
      var bytes=await blob.arrayBuffer(),digest=await root.crypto.subtle.digest('SHA-256',bytes);
      var actual=Array.from(new Uint8Array(digest),function(value){return value.toString(16).padStart(2,'0');}).join('');
      if(actual!==selected.sha256)throw new Error('The download did not match the report you reviewed. Prepare a fresh report.');
      var url=root.URL.createObjectURL(blob),link=doc.createElement('a');link.href=url;link.download='Lightwork-support-'+selected.preview_id+'.json';link.click();root.setTimeout(function(){root.URL.revokeObjectURL(url);},1000);
      status.textContent='The reviewed report was downloaded. Nothing was sent to a support service.';
    }catch(error){clear();status.textContent=error.message||'Download unavailable. Prepare a fresh report.';}finally{busy=false;controls();}
  });
  controls();
})(window);
