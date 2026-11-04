(() => {
  'use strict';
  const list=document.getElementById('auto-sched-list'); if(!list)return;
  const node=(tag,text)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;};
  let epoch=0,activeContext=null,pending=null,handoffStarted=false,repairBusy=false,feedbackShown=false;
  const reminder=node('section');reminder.className='panel';reminder.hidden=true;list.before(reminder);
  const receiptMessage=node('p');receiptMessage.setAttribute('role','status');receiptMessage.setAttribute('aria-live','polite');reminder.append(node('h3','Check the original schedule repair'),receiptMessage);
  function when(value){return value ? (window.mvTimeAbsolute ? window.mvTimeAbsolute(value) : new Date(value*1000).toLocaleString()) : 'Time not recorded';}
  function occurrence(item){return when(item.scheduled_at)+' · '+({pending:'Waiting',running:'Running',failed:'Needs review',done:'Finished',cancelled:'Cancelled'}[item.status]||'Recorded run');}
  function storageKey(context){return 'lightwork.schedule.repair.original.'+context;}
  function saveOriginal(reference){try{if(reference)sessionStorage.setItem(storageKey(activeContext),reference);else sessionStorage.removeItem(storageKey(activeContext));}catch(_){if(reference)throw new Error('This browser could not save the original request for recovery. No repair was started. Allow storage for this site and review again.');}pending=reference;feedbackShown=false;reminder.hidden=!reference;}
  async function restoreOriginal(){const captured=epoch;try{const value=await request('/api/v1/schedules/recovery-context');if(captured!==epoch)return;if(activeContext!==value.context)feedbackShown=false;activeContext=value.context;try{pending=sessionStorage.getItem(storageKey(activeContext));}catch(_){pending=null;}reminder.hidden=!pending&&!feedbackShown;if(pending)receiptMessage.textContent='An earlier reply may have been interrupted. Check its exact saved receipt before repairing another occurrence.';}catch(_){reminder.hidden=true;}}
  button(reminder,'Check exact saved receipt',async()=>{if(!pending)return;const reference=pending,captured=epoch;try{const result=await request('/api/v1/schedules/recovery/receipt',{reference});if(captured!==epoch||reference!==pending)return;receiptMessage.textContent=result.message+(result.future_occurrence?' Recorded continuation: '+occurrence(result.future_occurrence)+'.':'');if(result.found){saveOriginal(null);feedbackShown=true;reminder.hidden=false;refresh();}}catch(error){if(captured===epoch)receiptMessage.textContent=error.message;}});
  button(reminder,'Check original request with Copilot',()=>{if(!pending)return;document.dispatchEvent(new CustomEvent('lightwork:copilot-selection',{detail:{selection:{kind:'schedule_repair_receipt',reference:pending}}}));const fab=document.getElementById('mv-copilot-fab'),copilot=document.getElementById('mv-copilot');if(fab&&copilot?.hidden)fab.click();});
  button(reminder,'I reviewed current schedules',async()=>{if(!pending||repairBusy)return;const reference=pending,captured=epoch;const ok=await mvConfirm('Clear this interrupted-repair reminder after checking current schedules? This does not confirm the original repair succeeded or undo any future occurrence. Review fresh evidence before another repair.',{okText:'Clear reminder'});if(!ok||repairBusy||captured!==epoch||reference!==pending)return;saveOriginal(null);feedbackShown=true;reminder.hidden=false;receiptMessage.textContent='Reminder cleared. The original outcome has not been reported as successful.';refresh();});
  function contextChanged(){epoch++;activeContext=null;pending=null;feedbackShown=false;reminder.hidden=true;document.querySelectorAll('[data-schedule-editor]').forEach(e=>e.remove());}
  document.addEventListener('lightwork:workspace-changed',contextChanged);
  document.addEventListener('lightwork:connection-access-lost',contextChanged);
  async function request(url,body){
    return window.mvFetchJSON(url,{method:body?'POST':'GET',body,cache:'no-store',timeout:15000,onAccess:contextChanged,
      messages:{401:'Access changed. Sign in again or ask an administrator.',403:'Access changed. Sign in again or ask an administrator.',409:'This schedule or its evidence changed. Refresh and review it again.'}},'update the schedule');
  }
  function refresh(){document.dispatchEvent(new CustomEvent('lightwork:schedules-changed'));}
  function panel(row,title){
    row.classList.add('schedule-management-row');
    row.querySelector('[data-schedule-editor]')?.remove();
    const box=node('section');box.className='panel';box.dataset.scheduleEditor='true';box.append(node('h3',title));
    const message=node('p');message.setAttribute('role','status');message.setAttribute('aria-live','polite');box.append(message);
    const close=node('button','Close');close.type='button';close.className='btn btn--ghost';close.addEventListener('click',()=>{box.remove();row.querySelector('button')?.focus();});
    box.append(close);row.append(box);return {box,message,close};
  }
  function input(box,label,type,value){
    const wrap=node('label',label),field=node(type==='select'?'select':'input');field.className='input';
    if(type!=='select')field.type=type;
    if(type==='checkbox')field.checked=Boolean(value);else field.value=value||'';
    wrap.append(field);box.append(wrap);return field;
  }
  function button(box,label,action){const b=node('button',label);b.type='button';b.className='btn';b.addEventListener('click',action);box.append(b);return b;}
  async function stateChange(row,schedule,state,control){
    if(control.disabled)return;control.disabled=true;const captured=epoch;
    try{
      const verb={paused:'Pause future runs',active:'Resume from the next future time',retired:'Retire this schedule'}[state];
      if(!await mvConfirm(verb+'? Work already admitted continues. Past occurrences will not be replayed.',{okText:verb}))return;
      if(captured!==epoch)return;
      await request('/api/v1/schedules/definitions/'+encodeURIComponent(schedule.definition_id),{expected_revision:schedule.revision,state,confirm:true});
      if(captured===epoch)refresh();
    }catch(error){const p=panel(row,'Schedule change');p.message.textContent=error.message;}
    finally{if(captured===epoch)control.disabled=false;}
  }
  async function edit(row,schedule){
    const {box,message}=panel(row,'Change future runs');const captured=epoch;
    box.append(node('p','Running work keeps its reviewed instructions. Unattempted future occurrences are replaced by this revision; history remains available.'));
    const title=input(box,'Schedule name','text',schedule.title);title.maxLength=200;
    const changeTime=input(box,'Change the timetable','checkbox',false);
    const repeat=input(box,'Repeat','select','');
    [['daily','Every day'],['weekdays','Weekdays'],['weekly','Selected weekdays'],['monthly','Monthly'],['hourly','Every few hours']].forEach(([v,label])=>repeat.append(new Option(label,v)));
    const at=input(box,'Time','time','09:00'),zone=input(box,'Time zone','select','');
    const hours=input(box,'Hours between runs','number','1');hours.min='1';hours.max='12';
    const day=input(box,'Day of month','number','1');day.min='1';day.max='28';
    const days=node('fieldset');days.append(node('legend','Days of the week'));box.append(days);
    const dayFields=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'].map((label,i)=>{const field=input(days,label,'checkbox',false);field.value=String(i);return field;});
    let reviewed=null,busy=false;
    const preview=button(box,'Review future runs',async()=>{
      if(busy)return;busy=true;preview.disabled=true;save.disabled=true;
      try{
        const body={expected_revision:schedule.revision,state:schedule.state,title:title.value.trim(),confirm:true};
        if(!body.title)throw new Error('Give the schedule a name.');
        if(changeTime.checked){
          body.timetable={repeat:repeat.value,at:at.value,zone:zone.value,every_hours:Number(hours.value),day_of_month:Number(day.value),days:dayFields.filter(f=>f.checked).map(f=>Number(f.value))};
          const result=await request('/api/v1/schedules/preview',{timetable:body.timetable});
          if(captured!==epoch)return;
          message.textContent='Next future runs: '+result.next_runs.map(value=>window.mvTimeAbsolute?window.mvTimeAbsolute(value,result.zone):new Date(value*1000).toLocaleString(undefined,{timeZone:result.zone})).join('; ')+'.';
        }else message.textContent='The current timetable is preserved. Only the name or future definition changes.';
        reviewed=body;save.disabled=false;
      }catch(error){message.textContent=error.message;}finally{busy=false;preview.disabled=false;}
    });
    const save=button(box,'Save reviewed change',async()=>{
      if(!reviewed||busy)return;busy=true;save.disabled=true;preview.disabled=true;
      try{await request('/api/v1/schedules/definitions/'+encodeURIComponent(schedule.definition_id),reviewed);if(captured===epoch){box.remove();refresh();}}
      catch(error){message.textContent=error.message;reviewed=null;}
      finally{busy=false;preview.disabled=false;}
    });save.disabled=true;
    box.addEventListener('input',()=>{reviewed=null;save.disabled=true;});
    box.addEventListener('change',()=>{reviewed=null;save.disabled=true;});
    try{const options=await request('/api/v1/schedules/options');if(captured!==epoch)return;options.zones.forEach(value=>zone.append(new Option(value.replace(/_/g,' '),value)));zone.value=schedule.zone||'UTC';}
    catch(error){message.textContent=error.message;preview.disabled=true;}
    title.focus();
  }
  async function recovery(row,schedule,selectedJob){
    const {box,message}=panel(row,'Review future recurrence recovery');const captured=epoch;
    if(pending||repairBusy){message.textContent='Check the original schedule repair above before preparing another repair.';reminder.scrollIntoView({block:'nearest'});return;}
    let parked=selectedJob;
    try{
      if(!parked){
        const choices=await request('/api/v1/schedules/definitions/'+encodeURIComponent(schedule.definition_id)+'/recovery-options');if(captured!==epoch)return;
        if(!choices.occurrences.length){message.textContent='No occurrence currently needs recovery. Refresh schedules.';return;}
        if(choices.occurrences.length>1){
          const selected=input(box,'Occurrence needing review','select','');choices.occurrences.forEach(item=>selected.append(new Option(occurrence(item),String(item.id))));
          message.textContent=choices.complete?'Choose the exact historical occurrence to review.':'The most recent 100 occurrences needing recovery are shown.';
          button(box,'Review selected occurrence',()=>recovery(row,schedule,Number(selected.value)));return;
        }
        parked=choices.occurrences[0].id;
      }
      const review=await request('/api/v1/schedules/recovery/'+parked);if(captured!==epoch)return;
      activeContext=review.context;try{pending=sessionStorage.getItem(storageKey(activeContext));}catch(_){pending=null;}
      if(pending){reminder.hidden=false;message.textContent='Check the original saved receipt above before another repair.';return;}
      const operationId=crypto.randomUUID().replace(/-/g,'');
      message.textContent=review.consequence;
      box.append(node('p',review.title+' · '+when(review.scheduled_at)));
      box.append(node('p','Historical business result: unknown. '+review.problem));
      const choice=input(box,'Future recurrence','select','');choice.append(new Option('Create one next future occurrence','future'));
      review.successors.forEach(item=>choice.append(new Option('Use an existing occurrence · '+occurrence(item),String(item.id))));
      if(!review.successors_complete)box.append(node('p','The first 100 compatible future occurrences are listed. All retained evidence is checked again before a repair.'));
      const rationale=input(box,'Why is this the correct recovery?','text','');rationale.maxLength=1000;
      const stopped=input(box,'I checked the execution evidence and confirmed old workers are stopped','checkbox',false);
      const apply=button(box,'Repair future recurrence',async()=>{
        if(apply.disabled||repairBusy||pending)return;
        if(!stopped.checked||rationale.value.trim().length<5){message.textContent='Describe the reviewed evidence and confirm old workers are stopped.';return;}
        const body={operation_id:operationId,expected_attempts:review.attempts,expected_evidence:review.expected_evidence,context:review.context,
          successor_id:choice.value==='future'?null:Number(choice.value),rearm:choice.value==='future',confirm:true,rationale:rationale.value.trim()};
        repairBusy=true;apply.disabled=true;choice.disabled=true;rationale.disabled=true;stopped.disabled=true;
        let admitted=false;
        try{
          const exact=await request('/api/v1/schedules/recovery/'+parked+'/reference',body);if(captured!==epoch||exact.context!==review.context)return;
          saveOriginal(exact.reference);receiptMessage.textContent='The repair request is underway. Its exact saved receipt can be checked without repeating it.';admitted=true;
          const result=await request('/api/v1/schedules/recovery/'+parked,body);if(captured!==epoch)return;
          if(result.repaired!==true||result.historical_replayed!==false)throw new Error('Repair result was not confirmed. Check the exact saved receipt before continuing.');
          const saved=await request('/api/v1/schedules/recovery/receipt',{reference:exact.reference});if(captured!==epoch)return;
          if(saved.found!==true)throw new Error('The original receipt is not confirmed. Check the exact saved receipt before another repair.');
          saveOriginal(null);feedbackShown=true;message.textContent=saved.message;receiptMessage.textContent=saved.message;reminder.hidden=false;refresh();
        }catch(error){if(captured!==epoch)return;message.textContent=error.message+(admitted?' Use Check exact saved receipt above; no repair will be repeated.':'');if(!admitted){apply.disabled=false;choice.disabled=false;rationale.disabled=false;stopped.disabled=false;}}
        finally{repairBusy=false;}
      });
    }catch(error){if(captured===epoch)message.textContent=error.message;}
  }
  async function history(row,schedule){
    const {box,message}=panel(row,'Schedule history');
    try{
      const data=await request('/api/v1/schedules/definitions/'+encodeURIComponent(schedule.definition_id)+'/history');
      data.versions.forEach(v=>box.append(node('p','Revision '+v.revision+' · '+v.state+' · '+(window.mvTimeAbsolute ? window.mvTimeAbsolute(v.created_at) : new Date(v.created_at*1000).toLocaleString())+' · '+v.rationale)));
      data.schedule.history.forEach(job=>box.append(node('p',occurrence(job))));
      message.textContent=data.schedule.history_total+' retained occurrences; showing the most recent 50. Definition history is retained independently.';
      button(box,'Download audit history',()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download='schedule-history.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
    }catch(error){message.textContent=error.message;}
  }
  function attach(){
    list.querySelectorAll('[data-schedule]').forEach(row=>{
      if(row.dataset.managementAttached)return;row.dataset.managementAttached='true';
      const schedule=JSON.parse(row.dataset.schedule);if(!schedule.definition_id)return;row.id='schedule-'+schedule.definition_id;if(location.hash==='#'+encodeURIComponent(row.id)){row.tabIndex=-1;row.focus();}
      button(row,'History',()=>history(row,schedule));
      if(schedule.state==='parked'){button(row,'Review recovery',()=>recovery(row,schedule));return;}
      if(schedule.state==='retired')return;
      button(row,'Change future runs',()=>edit(row,schedule));
      const toggle=button(row,schedule.state==='paused'?'Resume':'Pause',()=>stateChange(row,schedule,schedule.state==='paused'?'active':'paused',toggle));
      const retire=button(row,'Retire',()=>stateChange(row,schedule,'retired',retire));
    });
  }
  async function handoff(){
    const value=new URLSearchParams(location.search).get('recover_schedule');if(handoffStarted||!value||!/^[1-9]\d*$/.test(value))return;handoffStarted=true;const captured=epoch;
    try{const target=await request('/api/v1/schedules/recovery/'+value);if(captured!==epoch)return;let row=Array.from(list.querySelectorAll('[data-schedule]')).find(item=>JSON.parse(item.dataset.schedule).definition_id===target.definition_id);if(!row){row=node('li');row.className='panel';row.append(node('h3',target.title));list.prepend(row);}row.scrollIntoView({block:'nearest'});await recovery(row,{title:target.title},Number(value));}catch(error){if(captured===epoch){reminder.hidden=false;receiptMessage.textContent=error.message+' Check any saved original request above.';}}
  }
  window.LightworkScheduleRecovery={rememberReview:async(token)=>{
    if(pending||repairBusy)throw new Error('Check the original schedule repair before another submission.');
    const captured=epoch;repairBusy=true;
    try{const exact=await request('/api/v1/schedules/recovery/copilot-reference',{token});if(captured!==epoch)throw new Error('Your account or workspace changed. Reopen Automations before continuing.');activeContext=exact.context;saveOriginal(exact.reference);receiptMessage.textContent='This reviewed repair has an exact saved reference. Check it if the reply is interrupted.';return true;}
    finally{repairBusy=false;}
  }};
  document.addEventListener('lightwork:product-operation-complete',async(event)=>{
    if(event.detail?.operation!=='schedules.repair'||!['confirmed','replayed'].includes(event.detail.status)||!pending)return;
    const captured=epoch,reference=pending;
    try{const result=await request('/api/v1/schedules/recovery/receipt',{reference});if(captured!==epoch||reference!==pending)return;receiptMessage.textContent=result.message;if(result.found){saveOriginal(null);feedbackShown=true;reminder.hidden=false;refresh();}}
    catch(error){if(captured===epoch)receiptMessage.textContent=error.message;}
  });
  document.addEventListener('lightwork:schedules-rendered',()=>{attach();restoreOriginal().then(handoff);});attach();restoreOriginal().then(()=>{if(list.querySelector('[data-schedule]')||document.getElementById('auto-sched-count')?.textContent.trim())handoff();});
})();
