/* Current, authority-scoped metadata results for the existing keyboard finder. */
(function (global) {
  "use strict";
  function errText(failure,action){return global.mvErrorText?global.mvErrorText(failure,action):'Could not '+action+'. Try again.';}
  function plainError(text){var error=new Error(text);error.plain=true;return error;}
  function init() {
    var doc=global.document, meta=doc.querySelector('meta[name="lightwork-search-context"]');
    var dialog=doc.getElementById('navfinder-dialog'), kind=doc.getElementById('navfinder-kind');
    if(!meta||!dialog||!dialog.lightworkFinder||!kind||dialog.dataset.recordSearchReady)return;
    dialog.dataset.recordSearchReady='true';
    var context=meta.content, finder=dialog.lightworkFinder, input=doc.getElementById('navfinder-input');
    var status=doc.getElementById('navfinder-record-status'), more=doc.getElementById('navfinder-more'), coverage=doc.getElementById('navfinder-coverage');
    var purpose=doc.getElementById('navfinder-purpose'), purposeLabel=doc.getElementById('navfinder-purpose-label');
    var history=doc.getElementById('navfinder-history'), source=doc.getElementById('navfinder-source'), after=doc.getElementById('navfinder-after'), before=doc.getElementById('navfinder-before'), order=doc.getElementById('navfinder-order'), pageSize=doc.getElementById('navfinder-page-size');
    var cursor=null, timer=null, generation=0, next=null, snapshot='', rows=[], activeQuery='', activeKind='';
    function clear(){generation++;clearTimeout(timer);rows=[];next=null;cursor=null;snapshot='';more.hidden=true;coverage.replaceChildren();finder.setRecords([]);}
    function validRow(row){
      if(!row||!['vendor','evidence','assessment','decision','task','report','knowledge','workflow','automation','project','connection','fact'].includes(row.kind)||typeof row.title!=='string'||typeof row.id!=='string'||typeof row.revision!=='string'||typeof row.state!=='string'||typeof row.href!=='string')return false;
      // Only approved app review destinations; a compromised source cannot
      // smuggle a script, remote URL, or protocol-relative result into the UI.
      if(row.kind==='knowledge')return /^\/knowledge-access#source=[A-Za-z0-9%_.~-]+$/.test(row.href);
      return /^\/(?:chat\/goal\/\d+|projects\/\d+|flows\/designer\/[A-Za-z0-9%_.-]+|workflow-builder\?edit=[A-Za-z0-9%_.-]+|automations#schedule-[A-Za-z0-9%_.-]+|connections#connection-[A-Za-z0-9%_.-]+|facts\?key=[A-Za-z0-9%_.~-]+|privacy\/vendors\/[A-Za-z0-9%_.-]+|third-party\/vendor-onboarding\?case=[A-Za-z0-9%_.-]+|(?:privacy|finance|security)\?assessment=[A-Za-z0-9%_.-]+|administration\/document-vault\?document=[A-Za-z0-9%_.-]+|third-party\/executive-reports\?report=[A-Za-z0-9%_.:-]+|project-reviews#packet=PRP-[0-9a-f]{32})$/.test(row.href);
    }
    async function search(append){
      if(kind.value==='pages'){clear();status.textContent='Showing navigation pages only.';return;}
      // Without a scope prefix such as "#" (the finder narrows the search).
      var query=finder.query?finder.query():input.value.trim();
      if(Array.from(query).length>200){clear();status.textContent='Use 200 characters or fewer to search records.';return;}
      if(!query&&kind.value!=='history'){clear();status.textContent='Type a name or reference to search records.';return;}
      if(!append)clear();
      var current=++generation, offset=append?next:0, selectedKind=kind.value;
      if(append&&((next===null&&!cursor)||query!==activeQuery||selectedKind!==activeKind))return;
      if(selectedKind==='knowledge'&&!purpose.value){status.textContent='Choose an approved use before searching knowledge content.';return;}
      more.disabled=true; status.textContent='Searching accessible records…';
      try{
        var response=await global.fetch('/api/v1/records/search',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'Content-Type':'application/json','X-Lightwork-Search-Context':context},body:JSON.stringify({query:query,kind:['knowledge','history'].includes(selectedKind)?'all':selectedKind,mode:selectedKind==='history'?'history':selectedKind==='knowledge'?'knowledge':'metadata',source:selectedKind==='history'?source.value:'',after:selectedKind==='history'?after.value:'',before:selectedKind==='history'?before.value:'',oldest:selectedKind==='history'&&order.value==='oldest',purpose:selectedKind==='knowledge'?purpose.value:'',cursor:append?cursor:null,offset:offset||0,limit:selectedKind==='history'&&pageSize&&pageSize.value==='50'?50:20,snapshot:append?snapshot:''})});
        if(!response.ok){if(current!==generation)return;throw plainError(errText(response,'search records'));}
        var value=await response.json();
        if(current!==generation)return;
        if(value.context!==context)throw plainError('The account or workspace changed. Reload before searching records.');
        if(!Array.isArray(value.items)||!value.items.every(validRow)||!Array.isArray(value.coverage)||!Number.isSafeInteger(value.total)||typeof value.snapshot!=='string'||!(/^[a-f0-9]{64}$/).test(value.snapshot)||!(value.next_offset===null||Number.isSafeInteger(value.next_offset)&&value.next_offset>offset))throw plainError('Search results could not be verified. Try again.');
        rows=append?rows.concat(value.items):value.items;next=value.next_offset;cursor=value.next_cursor||null;snapshot=value.snapshot;activeQuery=query;activeKind=selectedKind;
        finder.setRecords(rows);more.hidden=next===null&&!cursor;
        more.textContent=selectedKind==='history'?'Search next history window':'More records';
        status.textContent=(selectedKind==='history'?rows.length+' historical matches returned. '+(value.notice||'')+' ':selectedKind==='knowledge'?rows.length+' approved content results returned. ':rows.length+' of '+value.total+' matching business records. ')+(value.complete?'All selected sources are current.':'Some sources are partial or unavailable. Check Search coverage.');
        coverage.replaceChildren();value.coverage.forEach(function(source){var li=doc.createElement('li');var human=global.mvHuman||String;li.textContent=human(source.source)+': '+human(source.state).toLowerCase()+(Number.isSafeInteger(source.indexed)?' ('+source.indexed+' accessible records indexed)':'');if(source.href&&/^\/(?:goals|projects|workflows|automations|connections|facts|privacy(?:\/vendors)?|project-reviews|administration\/document-vault|third-party\/(?:executive-reports|vendor-onboarding))$/.test(source.href)){var repair=doc.createElement('a');repair.href=source.href;repair.textContent=' Open workspace';li.appendChild(repair);}coverage.appendChild(li);});
      }catch(error){if(current===generation){rows=[];next=null;cursor=null;snapshot='';more.hidden=true;finder.setRecords([]);status.textContent=error&&error.plain?error.message:errText(error,'search records');}}
      finally{if(current===generation)more.disabled=false;}
    }
    // A search narrowed to commands, pages, people or settings leaves records out.
    var narrowed={actions:'Showing commands only.',pages:'Showing navigation pages only.',people:'Showing people only.',settings:'Showing settings only.',approvals:'Showing requests waiting for your decision.'};
    dialog.addEventListener('lightwork:finder-query',function(event){clear();if(event.detail.reason==='closed')return;if(narrowed[event.detail.scope]){status.textContent=narrowed[event.detail.scope];return;}status.textContent='Type a name or reference to search records.';timer=setTimeout(function(){search(false);},300);});
    kind.addEventListener('change',async function(){
      clear(); purposeLabel.hidden=kind.value!=='knowledge'; if(history)history.hidden=kind.value!=='history';
      if(kind.value==='knowledge'){
        var current=++generation;status.textContent='Loading uses permitted for your account.';
        try{
          var response=await global.fetch('/api/v1/knowledge-access/purposes',{credentials:'same-origin',cache:'no-store'});
          if(!response.ok)throw new Error('Approved content search is unavailable. Sign in with an authorized account and choose a knowledge workspace.');
          var value=await response.json(); if(current!==generation)return;
          if(value.context!==context||!Array.isArray(value.items))throw new Error('Your account or workspace changed. Reload to search.');
          purpose.replaceChildren();value.items.forEach(function(item){if(!/^[a-z][a-z0-9_.-]{0,63}$/.test(item.code))throw new Error('Available uses could not be verified. Refresh the page and try again.');var option=doc.createElement('option');option.value=item.code;option.textContent=global.mvHuman?global.mvHuman(item.code):item.code;purpose.appendChild(option);});
          if(!purpose.options.length){status.textContent='No permitted uses are available for your account.';return;}
        }catch(error){if(current===generation)status.textContent=error.message;return;}
      }
      search(false);
    });
    [source,after,before,order,pageSize].filter(Boolean).forEach(function(control){control.addEventListener('change',function(){search(false);});});
    purpose.addEventListener('change',function(){search(false);});
    doc.getElementById('navfinder-search').addEventListener('click',function(){search(false);});
    more.addEventListener('click',function(){search(true);});
    var requestedHistory=new URLSearchParams(global.location.search).get('find_history');
    if(source&&Array.from(source.options).some(function(option){return option.value===requestedHistory;})){
      source.value=requestedHistory;kind.value='history';finder.open();kind.dispatchEvent(new global.Event('change'));
    }

  }
  if(global.document.readyState==='loading')global.document.addEventListener('DOMContentLoaded',init);else init();
})(window);
