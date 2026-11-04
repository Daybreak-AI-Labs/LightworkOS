(() => {
  'use strict';
  const root=document.getElementById('ai-business-intake-panel');if(!root)return;
  const el=id=>document.getElementById('abi-'+id),base='/api/v1/security/assurance/ai-business-intake';
  const node=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
  let contract=null,current=null,busy=false,expired=false,conflicted=false,offset=0,hasMore=false;
  const controls=new Map(),references=new Map();let savedAnswers='{}';
  const canonical=value=>JSON.stringify(value,(_,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])):item);
  const at=(object,path)=>path.split('.').reduce((value,key)=>value&&Object.hasOwn(value,key)?value[key]:undefined,object);
  function put(object,path,value){const parts=path.split('.');if(parts.length===1)object[path]=value;else{if(!Object.hasOwn(object,parts[0]))object[parts[0]]={};object[parts[0]][parts[1]]=value;}}
  const statusLabel=value=>({draft:'Draft',submitting:'Submitting',pending_review:'Awaiting review'}[value]||(window.mvHuman?window.mvHuman(value):String(value)));
  function readFile(file){if(typeof file.text==='function')return file.text();return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result||''));reader.onerror=()=>reject(new Error('That file could not be read. Nothing was imported.'));reader.readAsText(file);});}
  function say(message){window.mvStatus(el('status'),message);}
  function lock(){expired=true;current=null;contract=null;controls.clear();references.clear();savedAnswers='{}';el('fields').replaceChildren();el('drafts').replaceChildren();el('missing').replaceChildren();for(const id of ['current','progress','validation','list-status'])el(id).textContent='';el('import').value='';update();}
  function update(){const unavailable=busy||expired||!contract;root.setAttribute('aria-busy',String(busy));root.querySelectorAll('button,input,select,textarea').forEach(item=>item.disabled=unavailable);
    el('refresh').disabled=busy||expired;el('refresh').textContent=contract?'Refresh workspace drafts':'Retry loading intake questions';
    const edit=unavailable||!contract?.can_edit||conflicted||(current&&current.status!=='draft');
    el('fields').querySelectorAll('input,select,textarea').forEach(item=>item.disabled=!!edit);
    el('save').disabled=!!edit;el('new').disabled=unavailable||!contract?.can_edit;el('import').disabled=!!edit;el('import-button').disabled=!!edit;el('export').disabled=unavailable||!current;
    el('submit').disabled=!!edit||!current||isDirty()||!!current.progress.missing_fields.length;
    el('open').disabled=unavailable||!el('drafts').value;el('more').hidden=!hasMore;el('save').textContent=current?'Save draft answers':'Start draft';
  }
  async function api(path,method='GET',body){const response=await fetch(base+path,{method,credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json',...(contract?{'X-Lightwork-Intake-Context':contract.context}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
    // A refusal's body is never read: release it so the request ends instead of staying open.
    if([401,403].includes(response.status)){response.body?.cancel().catch(()=>{});lock();throw new Error('Your sign-in or access changed. Sign in again and reload AI business intake.');}
    const friendly=action=>window.mvErrorText?window.mvErrorText(response,action):'Could not '+action+'. Try again.';
    if(response.status>=500)throw new Error('The intake service is unavailable. Your answers are kept; try again.');
    const raw=await response.text();if(new TextEncoder().encode(raw).length>2*1024*1024)throw new Error('The intake response is too large. Narrow the draft search.');
    let data;try{data=JSON.parse(raw);}catch(_){throw new Error('The intake response could not be read. Your unsaved answers are still here. Refresh the page and try again.');}
    if(!response.ok){const detail=typeof data.detail==='string'?data.detail:'';
      if(response.status===409&&/account or workspace changed/i.test(detail)){lock();throw new Error('The account or workspace changed. Reload AI business intake.');}
      else if(response.status===409)conflicted=true;
      const error=new Error(response.status===409?'Someone else changed this intake since you opened it.':friendly('complete the intake request'));error.status=response.status;throw error;}
    if(!data||typeof data!=='object'||Array.isArray(data))throw new Error('The intake reply could not be read. Refresh the page and try again.');
    if(contract&&data.context!==contract.context){lock();throw new Error('The account or workspace changed. Reload AI business intake.');}
    return data;
  }
  async function run(work){if(busy||expired)return;busy=true;update();try{await work();}catch(error){say(error.message+(conflicted&&!expired?' Your unsaved answers are kept. Open the saved intake to review its current version before continuing.':''));el('status').focus();}finally{busy=false;update();}}
  const choiceLabel=value=>({none:'No data',public:'Public information',internal:'Internal',confidential_business:'Confidential business information',personal:'Personal data',sensitive_personal:'Sensitive personal data',both:'Internal and external',assistive:'Assists a person',recommending:'Recommends decisions',automated:'Makes automated decisions',not_applicable:'Not applicable',unknown:'Not yet known'}[value]||value.replace(/_/g,' ').replace(/^./,c=>c.toUpperCase()));
  function build(answers={}){controls.clear();el('fields').replaceChildren();const groups=new Map();
    for(const field of contract.fields){let group=groups.get(field.group);if(!group){group=node(field.group==='Advanced'?'details':'fieldset');group.append(node(field.group==='Advanced'?'summary':'legend',field.group));if(field.group==='Expert review signals')group.append(node('p','These are screening questions, not legal advice or a legal determination. Select what may apply, or leave unanswered for help from a compliance expert. Choose “None of these signals” only after reviewing every choice.'));el('fields').append(group);groups.set(field.group,group);}
      const wrap=node('div');wrap.className='abi-field';wrap.dataset.field=field.path;const value=at(answers,field.path),id='abi-field-'+field.path.replace(/\./g,'-');let read,input;
      if(field.kind==='multiple'){const box=node('fieldset');box.append(node('legend',field.label+(field.required?' (needed before submission)':'')));const options=[...field.choices];if(field.path.startsWith('regulatory_context.'))options.push('');
        for(const option of options){const label=node('label');label.className='abi-choice';const check=node('input');check.type='checkbox';check.value=option;check.checked=Array.isArray(value)&&(option===''?value.length===0:value.includes(option));label.append(check,node('span',option===''?'None of these signals':choiceLabel(option)));box.append(label);
          check.addEventListener('change',()=>{if(check.checked)box.querySelectorAll('input').forEach(other=>{if(other!==check&&(option===''||option==='none'||other.value===''||other.value==='none'))other.checked=false;});});}
        input=box.querySelector('input');read=()=>{const chosen=[...box.querySelectorAll('input:checked')].map(item=>item.value);if(!chosen.length)return undefined;return chosen.includes('')?[]:chosen;};wrap.append(box);
      }else{const label=node('label',field.label+(field.required?' (needed before submission)':''));label.htmlFor=id;wrap.append(label);
        input=node(field.kind==='text'?(field.max_length>500?'textarea':'input'):'select');input.id=id;input.className='input';
        if(field.kind==='text'){input.maxLength=field.max_length;input.value=value??'';if(input.tagName==='TEXTAREA')input.rows=4;read=()=>input.value;}
        else{input.append(new Option('Choose an answer',''));const choices=field.kind==='boolean'?['true','false']:field.choices;for(const option of choices)input.append(new Option(field.kind==='boolean'?(option==='true'?'Yes':'No'):choiceLabel(option),option));input.value=value===undefined?'':String(value);read=()=>input.value===''?undefined:field.kind==='boolean'?input.value==='true':input.value;}
        wrap.append(input);
      }
      const error=node('p');error.id=id+'-error';error.setAttribute('role','status');input.setAttribute('aria-describedby',error.id);wrap.append(error);group.append(wrap);controls.set(field.path,{field,input,read,error});
    }
  }
  function readAnswers(validate=false){const result={};let first=null;for(const [path,control] of controls){const value=control.read(),old=at(current?.submission,path);let message='';
      if(validate){control.error.textContent='';control.input.removeAttribute('aria-invalid');if(value===undefined&&old!==undefined)message='Choose an answer to replace the saved answer.';
        if(control.field.kind==='text'&&typeof value==='string'&&[...value].length>control.field.max_length)message='Shorten this answer to '+control.field.max_length+' characters.';
        if(path==='data_context.source_summary'&&value===''&&old)message='Replace the saved source description with an updated description.';
        if(message){control.error.textContent=message;control.input.setAttribute('aria-invalid','true');first||=control.input;}}
      if(value!==undefined&&(value!==''||old!==undefined))put(result,path,value);
    }
    if(first){first.focus();throw new Error('Check the highlighted intake answers. Nothing was saved.');}
    if(validate&&new TextEncoder().encode(JSON.stringify(result)).length>contract.max_submission_bytes)throw new Error('The combined answers are too long. Shorten the descriptions before saving.');return result;
  }
  function isDirty(){return !!contract&&canonical(readAnswers())!==savedAnswers;}
  function ask(message,okText){return window.mvConfirm?window.mvConfirm(message,{okText}):Promise.resolve(window.confirm(message));}
  async function confirmReplace(){return !isDirty()||await ask('Discard your unsaved intake answers and open a different draft?','Discard changes');}
  function operation(kind,payload){const signature=canonical(payload);let ref=references.get(kind);if(!ref||ref.signature!==signature){ref={signature,id:crypto.randomUUID()};references.set(kind,ref);}return ref.id;}
  function render(row){if(!row||!/^ABI-[a-f0-9]{24}$/.test(row.id)||!Number.isSafeInteger(row.revision)||row.revision<1||!['draft','submitting','pending_review'].includes(row.status)||!Array.isArray(row.progress?.missing_fields))throw new Error('The saved intake could not be verified. Open it again before continuing.');
    current=row;conflicted=false;const answers=row.submission||{};build(answers);savedAnswers=canonical(readAnswers());el('current').textContent=(row.use_case_name||'Untitled intake')+' · '+(row.status==='draft'?'Draft':row.status==='pending_review'?'Awaiting independent review':'Submission in progress');
    const labels=new Map(contract.fields.map(field=>[field.path,field.label]));el('missing').replaceChildren();for(const name of row.progress.missing_fields)el('missing').append(node('li',labels.get(name)||name.replace(/[_\.]/g,' ')));
    el('progress').textContent=row.progress.missing_fields.length?row.progress.missing_fields.length+' answers still needed before submission.':'All required answers are saved. Independent review is still required.';
    el('import').value='';update();
  }
  async function list(more=false){const result=await api('/drafts?'+new URLSearchParams({limit:'100',offset:String(more?offset:0),q:el('search').value.trim()}));if(!Array.isArray(result.intakes)||!Number.isSafeInteger(result.count)||typeof result.has_more!=='boolean')throw new Error('The draft list could not be read. Refresh the page and try again.');
    if(!more){el('drafts').replaceChildren(new Option('Choose a saved intake',''));offset=0;}for(const row of result.intakes){if(!/^ABI-[a-f0-9]{24}$/.test(row.id))throw new Error('The saved intake list has an entry that could not be read. Refresh the page and try again.');el('drafts').append(new Option((row.use_case_name||'Untitled intake')+' · '+statusLabel(row.status),row.id));}offset+=result.intakes.length;hasMore=result.has_more;el('list-status').textContent=result.count?'Showing '+offset+' of '+result.count+' matching workspace intakes.':'No matching workspace intakes. Start a new draft above.';update();}
  el('answers').addEventListener('input',()=>{el('validation').textContent='';update();});el('answers').addEventListener('change',update);el('drafts').addEventListener('change',update);
  el('new').addEventListener('click',()=>run(async()=>{if(!await confirmReplace())return;current=null;conflicted=false;references.clear();build();savedAnswers='{}';el('current').textContent='New intake';el('progress').textContent='Start a draft with what you know, then return to finish it.';el('missing').replaceChildren();say('New intake ready. Nothing has been saved or submitted.');}));
  el('refresh').addEventListener('click',()=>run(()=>contract?list():initialize()));el('find').addEventListener('submit',event=>{event.preventDefault();run(()=>list());});el('more').addEventListener('click',()=>run(()=>list(true)));
  el('open').addEventListener('click',()=>run(async()=>{if(!el('drafts').value||!await confirmReplace())return;render(await api('/drafts/'+encodeURIComponent(el('drafts').value)));references.clear();say('Saved intake loaded. Review its current answers before making changes.');}));
  el('answers').addEventListener('submit',event=>{event.preventDefault();run(async()=>{if(!contract.can_edit||conflicted||(current&&current.status!=='draft'))return;const answers=readAnswers(true);const payload=current?{patch:answers,expected_revision:current.revision}:{initial:answers};const kind=current?'save':'start';payload[current?'operation_id':'idempotency_key']=operation(kind,payload);
    const result=await api('/drafts'+(current?'/'+encodeURIComponent(current.id):''),current?'PATCH':'POST',payload);render(result);references.delete(kind);say('Draft answers saved. You can return through Workspace drafts. Nothing was submitted for review.');await list();});});
  el('submit').addEventListener('click',()=>run(async()=>{if(!current||current.status!=='draft'||conflicted||isDirty()||current.progress.missing_fields.length||!contract.can_edit)return;
    if(!await ask('Submit these saved answers for independent human review? This does not approve or legally classify the use case.','Submit for review'))return;
    const payload={expected_revision:current.revision};payload.operation_id=operation('submit',payload);const result=await api('/drafts/'+encodeURIComponent(current.id)+'/submit','POST',payload);render({...result,submission:current.submission});references.delete('submit');say('Intake routed for independent review. Human inventory and assessment review remain required.');await list();}));
  el('import-button').addEventListener('click',()=>el('import').click());
  el('import').addEventListener('change',()=>run(async()=>{const file=el('import').files&&el('import').files[0];if(!file||!contract.can_edit||conflicted||(current&&current.status!=='draft'))return;const raw=await readFile(file);el('import').value='';if(new TextEncoder().encode(raw).length>contract.max_submission_bytes)throw new Error('That answers file is too large. Nothing was imported.');let value;try{value=JSON.parse(raw);}catch(_){throw new Error('This file isn\'t a Lightwork answers file. Nothing was imported.');}if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('This file isn\'t a Lightwork answers file. Nothing was imported.');
    const paths=new Set(contract.fields.map(field=>field.path)),groups=new Set(contract.fields.filter(field=>field.path.includes('.')).map(field=>field.path.split('.')[0]));for(const [key,item]of Object.entries(value)){if(paths.has(key))continue;if(!groups.has(key)||!item||typeof item!=='object'||Array.isArray(item)||Object.keys(item).some(leaf=>!paths.has(key+'.'+leaf)))throw new Error('The import contains unsupported answer fields. Nothing was imported.');}
    for(const field of contract.fields){const item=at(value,field.path);if(item===undefined)continue;let valid=field.kind==='text'?typeof item==='string'&&[...item].length<=field.max_length:field.kind==='boolean'?typeof item==='boolean':field.kind==='choice'?field.choices.includes(item):Array.isArray(item)&&item.every(option=>field.choices.includes(option));if(field.path==='data_context.categories'&&valid)valid=item.length>0&&!(item.includes('none')&&item.length>1);if(!valid)throw new Error('Check the imported answer for '+field.label+'. Nothing was imported.');}
    if(!await confirmReplace())return;build(value);say('Imported answers are ready for review. Save them explicitly; nothing was submitted.');}));
  el('export').addEventListener('click',()=>{if(!current)return;const blob=new Blob([JSON.stringify(readAnswers(),null,2)],{type:'application/json'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=((current.use_case_name||'ai-intake').replace(/[^A-Za-z0-9]+/g,'-').replace(/^-|-$/g,'')||'ai-intake')+'-answers.json';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(link.href),1000);say('Answers downloaded. You can import this file later to continue.');});
  window.addEventListener('beforeunload',event=>{if(!expired&&isDirty()){event.preventDefault();event.returnValue='';}});
  async function initialize(){const data=await api('/form');if(!/^[a-f0-9]{64}$/.test(data.context)||!Array.isArray(data.fields)||data.fields.length>32||!data.fields.length||data.fields.some(field=>!/^\w+(\.\w+)?$/.test(field.path)||field.path.split('.').some(key=>['__proto__','constructor','prototype'].includes(key))||!['text','boolean','choice','multiple'].includes(field.kind)))throw new Error('The intake questionnaire could not be verified. Reload this page.');contract=data;build();savedAnswers='{}';await list();say(contract.can_edit?'Start with what you know, or open a saved workspace draft.':'You can view saved intakes. An operator can save answers and submit them for review.');}
  run(initialize);
})();
