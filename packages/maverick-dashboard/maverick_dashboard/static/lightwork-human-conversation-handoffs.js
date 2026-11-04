(function () {
  'use strict';
  const API='/api/v1/human-conversations';
  const decisionLabels=['Decision','Complete information shared','Selected person and access','Exact reply','Related AI work','Limits and consequences','If the response is lost'];
  const dutyLabels=['On-duty name','Availability ends','Current conversation permission','If the response is lost'];
  const names={title:'Task name',brief:'Complete task brief',saved_reply:'Saved reply'};
  const states={stopping:'AI work is pausing; a person has not taken over',waiting:'AI work is settled; waiting for the selected person',active:'A person is answering this conversation',returned:'Handed back for future intentional AI messages',unknown:'Outcome unconfirmed; AI admission remains held',unavailable:'Sharing permission is unavailable'};
  const labels={request:'Ask a person to take over',claim:'Take this conversation',reply:'Send this human reply',message:'Send your reply to the person',handback:'Hand back future work to AI',finish_pause:'Finish pausing current AI work'};
  function el(tag,text,parent){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(parent)parent.append(node);return node;}
  function display(host,value,bounds,depth){
    if(--bounds.nodes<0||depth>12)throw new Error('The complete review is too large to display. Nothing can be confirmed.');
    if(Array.isArray(value)){if(!value.length){el('p','None',host);return;}const list=el('ul',undefined,host);value.forEach(item=>display(el('li',undefined,list),item,bounds,depth+1));}
    else if(value&&typeof value==='object'){const list=el('dl',undefined,host);Object.entries(value).forEach(([key,item])=>{if(--bounds.nodes<0)throw new Error('The complete review is unavailable.');el('dt',names[key]||key,list);display(el('dd',undefined,list),item,bounds,depth+1);});}
    else if(value===null||value==='')el('p','None entered',host);
    else if(['string','number','boolean'].includes(typeof value))el('p',typeof value==='boolean'?(value?'Yes':'No'):String(value),host);
    else throw new Error('The complete review is unavailable.');
  }
  function renderReview(host,changes){
    const expected=changes?.length===4?dutyLabels:decisionLabels;
    if(!Array.isArray(changes)||changes.length!==expected.length||JSON.stringify(changes).length>200000||changes.some((row,index)=>!row||Object.keys(row).sort().join('|')!=='after|label'||row.label!==expected[index]))throw new Error('The complete human conversation review is unavailable. Nothing can be confirmed.');
    const fragment=document.createDocumentFragment(),bounds={nodes:8192};
    changes.forEach(row=>{const section=el('section',undefined,fragment);section.className='human-review-row';el('h3',row.label,section);display(section,row.after,bounds,0);});host.replaceChildren(fragment);return true;
  }
  window.LWHumanConversations={renderReview};
  const root=document.querySelector('[data-human-conversations]');if(!root||root.dataset.humanInitialized)return;root.dataset.humanInitialized='1';
  const find=key=>root.querySelector('[data-human-'+key+']');
  const goal=root.dataset.goal||'',context=root.dataset.context;
  const status=find('status'),current=find('current'),review=find('review'),history=find('history'),historyResult=find('history-result');
  let state=null,busy=false,generation=0,submitted=false,privateValid=true;
  const storageKey='lightwork:human-original:'+context+':'+goal;
  let pointer=null;try{pointer=JSON.parse(sessionStorage.getItem(storageKey)||'null');}catch(_){}
  function say(message){window.mvStatus(status,message);}
  function remember(value){pointer={record:value.record,operation:value.operation};try{sessionStorage.setItem(storageKey,JSON.stringify(pointer));}catch(_){say('Keep this page open: this browser cannot retain the original reference across reload.');}}
  function button(host,label,action){const value=el('button',label,host);value.type='button';value.className='btn btn--ghost';value.onclick=action;return value;}
  function cleared(event){if(event?.type==='lightwork:copilot-context-changed'&&event.detail?.reason==='selection')return;generation++;privateValid=false;state=null;review.replaceChildren();current.replaceChildren();history.replaceChildren();historyResult.replaceChildren();root.querySelectorAll('textarea,input,select').forEach(input=>{if(input.type==='checkbox')input.checked=false;else input.value='';});pointer=null;root.querySelectorAll('button').forEach(input=>{input.disabled=true;});say('Your account, workspace or access changed. Reopen this page before sharing private content.');holdComposer(true);}
  async function request(path,body,at=generation){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),45000);let response,value;
    try{response=await fetch(API+path,{credentials:'same-origin',cache:'no-store',method:body?'POST':'GET',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined,signal:controller.signal});value=await response.json();}
    catch(_){throw new Error('The response could not be confirmed. Read the exact original; nothing will be automatically repeated.');}
    finally{clearTimeout(timer);}
    if(at!==generation||!privateValid)throw new Error('Your account or selection changed. Reopen its review.');
    if(response.redirected||[401,403].includes(response.status)){cleared();throw new Error('Current access no longer permits this conversation. Earlier originals remain under their own current read permission.');}
    if(!response.ok){if(response.status===404&&!body){review.replaceChildren();current.replaceChildren();state=null;}throw new Error(typeof value.detail==='string'?value.detail:'This outcome is unavailable. Read its original before a new decision.');}
    if(value.context!==context){cleared();throw new Error('Your current account or workspace changed.');}return value;
  }
  function holdComposer(held){
    const form=document.getElementById('answer-form'),send=document.getElementById('answer-send');if(!form||!send)return;
    form.dataset.humanHeld=held?'1':'0';if(held)send.disabled=true;
    else document.dispatchEvent(new CustomEvent('lightwork:conversation-inbox-ready'));
  }
  const composer=document.getElementById('answer-form'),send=document.getElementById('answer-send');
  if(composer){window.addEventListener('submit',event=>{if(event.target===composer&&composer.dataset.humanHeld==='1'){event.preventDefault();event.stopImmediatePropagation();say('AI is paused for this human conversation. Use the human reply below; your AI draft and files are kept.');}},true);
    if(send)new MutationObserver(()=>{if(composer.dataset.humanHeld==='1'&&!send.disabled)send.disabled=true;}).observe(send,{attributes:true,attributeFilter:['disabled']});}
  function render(next){state=next;current.replaceChildren();holdComposer(Boolean(next.conversation?.held));
    const conversation=next.conversation;
    if(conversation){const session=conversation.session;el('h3',conversation.title,current);el('p',session?states[session.state]||'Outcome unconfirmed':'AI is available under its usual current permissions',current);if(conversation.contact_centre)el('p','Outside contact centre: '+conversation.contact_centre.label+'. '+conversation.contact_centre.reason,current);
      const offer=find('request-form');if(offer)offer.hidden=!next.enabled||Boolean(conversation.held)||conversation.source_unavailable;
      const choice=find('person');if(choice){const selected=choice.value;choice.replaceChildren();el('option','Choose an on-duty person',choice).value='';(next.people||[]).forEach(person=>{el('option',person.label,choice).value=person.owner;});if(Array.from(choice.options).some(option=>option.value===selected))choice.value=selected;}
      if(session){el('p',conversation.source_unavailable?'Current source details and replies are withheld under your current permissions. '+(session.state==='returned'?'Your recorded AI hold is released.':'You can release only your recorded AI hold.'):session.state==='returned'?'The selected person’s access ended when this conversation was handed back.':'Shared with '+session.duty_label+' until '+new Date(session.expires_at*1000).toLocaleString(),current);
        const shared=el('details',undefined,current);el('summary','Review the exact task information shared',shared);display(shared,session.shared,{nodes:8192},0);
        const exchange=el('div',undefined,current);exchange.setAttribute('aria-label','Human conversation messages');
        session.messages.forEach(message=>{const article=el('article',undefined,exchange);article.className='msg human-message';el('h4',message.from==='person'?session.duty_label:'You',article);el('p',message.text,article);el('p',new Date(message.at*1000).toLocaleString(),article);});
        if(!session.messages.length)el('p',conversation.source_unavailable?'Human replies are withheld under your current source permissions.':session.erased?'Private human conversation contents were erased through My data. Original decisions remain.':'No human reply has been sent.',exchange);
        if(conversation.held){if(conversation.is_owner){button(current,labels.handback,()=>decision('handback',conversation.goal_id));if(session.state==='stopping'||session.state==='unknown')button(current,labels.finish_pause,()=>decision('finish_pause',conversation.goal_id));}
          else if(session.state==='waiting')button(current,labels.claim,()=>decision('claim',conversation.goal_id));}
        const reply=find('reply-form');if(reply){reply.hidden=session.state!=='active';reply.dataset.action=conversation.is_owner?'message':'reply';}
      }else{const reply=find('reply-form');if(reply)reply.hidden=true;}
    }else{
      const duty=next.duty;el('p',duty.until>Date.now()/1000?'On duty as '+duty.label+' until '+new Date(duty.until*1000).toLocaleString():'Off duty',current);
      (next.incoming||[]).forEach(row=>{const card=el('article',undefined,current);el('h3',row.title,card);el('p',states[row.state]||row.state,card);if(row.state!=='unavailable'){const link=el('a','Open this human conversation',card);link.href='/human-conversations?goal_id='+row.goal_id;}});
      if(!(next.incoming||[]).length)el('p','No conversation currently awaits you.',current);
    }
    history.replaceChildren();el('option','Choose an original decision',history).value='';(next.history||[]).forEach(row=>{el('option',row.action+' / '+new Date(row.at*1000).toLocaleString()+(row.confirmed?' / Confirmed':' / Unconfirmed'),history).value=row.record+':'+row.operation;});
    const available=find('enabled');if(available)available.hidden=next.enabled;
    const dutyForm=find('duty-form');if(dutyForm)dutyForm.hidden=!next.enabled;
  }
  async function refresh(){if(busy||!privateValid)return;const at=generation;try{const value=await request(goal?'?goal_id='+goal:'',undefined,at);if(at!==generation)return;render(value);if(!pointer)say('Current conversation and original decisions read. Your entered work is kept.');}catch(error){if(at===generation)say(error.message);}}
  async function readOriginal(chosen=pointer){if(!chosen||busy||!privateValid)return;const at=generation;busy=true;try{const value=await request('/originals/'+encodeURIComponent(chosen.record)+'/'+encodeURIComponent(chosen.operation),undefined,at);if(at!==generation)return;historyResult.replaceChildren();el('p',value.message,historyResult);say(value.message);await refresh();}catch(error){if(at===generation)say(error.message);}finally{busy=false;}}
  async function showReview(path,body){if(busy||!privateValid)return;const at=++generation;busy=true;review.replaceChildren();historyResult.replaceChildren();
    try{const value=await request(path,{...body,context},at);if(at!==generation)return;renderReview(review,value.changes);submitted=false;
      const line=el('label',undefined,review),check=el('input',undefined,line);check.type='checkbox';line.append(document.createTextNode(' I reviewed all shared information, the selected person, pause and reply consequences above.'));
      const apply=button(review,'Confirm this reviewed decision',async()=>{if(!check.checked||submitted||busy||at!==generation||!privateValid)return;submitted=true;busy=true;apply.disabled=true;remember(value);find('original').hidden=false;
        try{const result=await request('/apply',{token:value.token,confirmed:true},at);if(at!==generation)return;say(result.message);historyResult.replaceChildren();el('p',result.message,historyResult);if(result.confirmed&&body.message&&find('reply-text').value===body.message)find('reply-text').value='';}
        catch(error){if(at===generation)say(error.message);}finally{busy=false;if(at===generation)await refresh();}});apply.className='btn btn--primary';apply.disabled=true;check.onchange=()=>{apply.disabled=!check.checked||submitted||busy||at!==generation;};
      button(review,'Keep entered work and cancel this review',()=>{if(submitted){say('Read the submitted original before another decision.');return;}generation++;review.replaceChildren();say('Review cancelled. Your entered work is kept.');});check.focus();
    }catch(error){if(at===generation)say(error.message);}finally{busy=false;}
  }
  async function decision(action,goalId,message){return showReview('/review',{goal_id:Number(goalId),action,...(message?{message}:{})});}
  const ask=find('request-form');if(ask)ask.onsubmit=event=>{event.preventDefault();showReview('/review',{goal_id:Number(goal),action:'request',recipient:find('person').value,purpose:find('purpose').value,hours:Number(find('hours').value)});};
  const reply=find('reply-form');if(reply)reply.onsubmit=event=>{event.preventDefault();decision(reply.dataset.action,goal,find('reply-text').value);};
  const duty=find('duty-form');if(duty)duty.onsubmit=event=>{event.preventDefault();showReview('/duty/review',{label:find('duty-label').value,hours:Number(find('duty-hours').value)});};
  find('refresh').onclick=refresh;find('original').onclick=()=>readOriginal();history.onchange=()=>{if(history.value){const [record,operation]=history.value.split(':');readOriginal({record,operation});}};
  ['lightwork:account-context-changed','lightwork:workspace-changed','lightwork:authority-changed','lightwork:copilot-context-changed'].forEach(event=>document.addEventListener(event,cleared));window.addEventListener('lightwork:context-changed',cleared);
  window.addEventListener('focus',refresh);const timer=setInterval(refresh,5000);window.addEventListener('pagehide',()=>clearInterval(timer),{once:true});
  refresh().then(()=>{if(pointer){find('original').hidden=false;readOriginal();}});
}());
