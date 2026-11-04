(function () {
  'use strict';
  var root=document.getElementById('task-diagnostics'); if(!root)return;
  var button=document.getElementById('diagnostic-prepare'), status=document.getElementById('diagnostic-status'), preview=document.getElementById('diagnostic-preview'), review=document.getElementById('diagnostic-reviewed'), download=document.getElementById('diagnostic-download');
  var controller=null, generation=0, expires=0, timer=null;
  function clear() {review.checked=false;review.disabled=true;download.hidden=true;download.removeAttribute('href');preview.textContent='';expires=0;clearTimeout(timer);}
  review.addEventListener('change',function(){download.hidden=!review.checked||Date.now()>=expires;});
  button.addEventListener('click',async function(){
    var token=++generation;if(controller)controller.abort();controller=new AbortController();var own=controller,timeout=setTimeout(function(){own.abort();},20000);
    clear();button.disabled=true;status.textContent='Preparing a local diagnostic preview…';
    try{
      var response=await fetch('/api/v1/tasks/'+root.dataset.goal+'/diagnostics',{method:'POST',credentials:'same-origin',cache:'no-store',signal:own.signal,headers:{'Content-Type':'application/json'},body:JSON.stringify({context:root.dataset.context})});
      var value=await response.json();if(!response.ok)throw new Error(value.detail&&(value.detail.message||value.detail)||'The diagnostic report could not be prepared. Try again.');
      if(token!==generation||own.signal.aborted)return;
      preview.textContent=value.preview;download.href=value.download_href;expires=value.expires_at*1000;
      review.disabled=!!value.audit_pending;status.textContent=value.audit_pending?'The report is retained but its audit receipt is pending. Prepare again when audit storage is available.':'SHA-256 '+value.sha256+'. Link expires '+(window.mvTimeAbsolute ? window.mvTimeAbsolute(expires) : new Date(expires).toLocaleString())+'. Review before downloading.';
      timer=setTimeout(function(){review.checked=false;review.disabled=true;download.hidden=true;status.textContent='This report link expired. Prepare a fresh preview.';},Math.max(0,expires-Date.now()));
    }catch(error){if(token===generation)status.textContent=own.signal.aborted?'Preparing the report timed out; nothing was shared.':error.message;}
    finally{clearTimeout(timeout);if(token===generation)button.disabled=false;}
  });
  window.addEventListener('pagehide',function(){generation++;if(controller)controller.abort();clear();});
  window.addEventListener('pageshow',function(event){if(event.persisted){button.disabled=false;status.textContent='Prepare a fresh preview after returning to this page.';}});
}());
