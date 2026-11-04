(function () {
  'use strict';
  if (!document.getElementById('cm-app')) return;
  const API = '/api/v1/compliance/mapping-builder', $ = id => document.getElementById('cm-' + id);
  let current = null, source = null, review = null, pending = null, busy = false, queued = false, generation = 0, detail = null, draft = null, reviewOffset = null, reviewedCount = 0, draftEpoch = 0;
  const requests = new Set();
  const storage = 'lightwork.compliance.mapping.original';
  let recoveryCopy = null, dirty = false, checkingContext = false;
  const labels = {planned:'Planned',not_started:'Not started',not_implemented:'Not in place yet',control_owner:'Control owner',second_line:'Risk and compliance owner',evidence_owner:'Evidence owner',collect:'Collect evidence',refresh:'Refresh evidence',review:'Review evidence',none:'No evidence task',one_time:'Once',monthly:'Every month',quarterly:'Every quarter',annual:'Every year',continuous:'Continuously'};
  const defaultFields = ['control-state','control-owner','evidence-kind','evidence-owner','cadence'];
  function bounded(value) {
    const text = JSON.stringify(value), todo = [[value,0]]; let visited=0;
    if(new TextEncoder().encode(text).length>1048576)throw new Error('This full draft exceeds private recovery storage. Keep this page open and save the mapping through its normal review. No choices were omitted from the draft.');
    while(todo.length){const [item,depth]=todo.pop();if(++visited>20000||depth>25)throw new Error('This full draft is too large for private recovery. Keep this page open and use the normal mapping review. No choices were omitted.');if(item&&typeof item==='object')Object.values(item).forEach(child=>todo.push([child,depth+1]));}
    return value;
  }
  function recoveryValue() {
    if(!current)return {};
    if(dirty&&!draft&&($('scope').value||$('target').value))throw new Error('Load the selected final scope and mapping choices before private recovery can keep this full draft. Your entered work stays here; nothing was omitted or saved.');
    return bounded({format:'compliance_mapping_draft_v1',context:current.context,scope:draft?.scope||'',scope_label:current.scopes.find(row=>row.value===draft?.scope)?.label||'No final scope selected',source:draft?.source||'',target:draft?.target||'',target_label:current.mappings.find(row=>row.value===draft?.target)?.label||'Create a new mapping',mapping_revision:draft?.mapping_revision||'',name:$('name').value,defaults:Object.fromEntries(defaultFields.map(id=>[id,$(id).value])),selected:$('control-picker').value,selected_offset:draft?.rows.get($('control-picker').value)?.offset??null,controls:Array.from(draft?.overrides||[],([control,value])=>({control,label:draft.rows.get(control).label,offset:draft.rows.get(control).offset,params:structuredClone(value.params)}))});
  }
  function comparison(host,saved,entered) {
    if(saved.format!=='compliance_mapping_draft_v1'){host.append(node('p','This recovery copy uses unsupported choices. It is kept; nothing will be restored.'));return;}
    const titles={scope_label:'Final scope',target_label:'Mapping to prepare',name:'Mapping name'}, lines=document.createElement('dl');
    Object.entries(titles).forEach(([key,title])=>{if(saved[key]!==entered[key]){lines.append(node('dt',title),node('dd','Recovery copy: '+(saved[key]||'Empty')),node('dd','Current draft: '+(entered[key]||'Empty')));}});
    const defaultsTitles=['Initial control status','Control responsibility','Evidence work','Evidence responsibility','Evidence frequency'];
    defaultFields.forEach((key,i)=>{if(saved.defaults?.[key]!==entered.defaults?.[key])lines.append(node('dt',defaultsTitles[i]),node('dd','Recovery copy: '+(labels[saved.defaults?.[key]]||'Empty')),node('dd','Current draft: '+(labels[entered.defaults?.[key]]||'Empty')));});host.append(lines);
    const old=new Map((saved.controls||[]).map(row=>[row.control,row])),now=new Map((entered.controls||[]).map(row=>[row.control,row]));
    const differences=[...new Set([...old.keys(),...now.keys()])].filter(key=>JSON.stringify(old.get(key)?.params)!==JSON.stringify(now.get(key)?.params));
    host.append(node('p',differences.length+' individual control choices differ. The entire recovery copy is retained. '+(differences.length>20?'This comparison shows the first 20 changed controls. After restoring, use the named control picker to inspect every retained choice.':'')));
    function describe(row,title){const box=node('div','');box.append(node('h4',title));if(!row){box.append(node('p','Starting or saved choices'));return box;}box.append(node('p',(labels[row.params.control_status]||'Choose a control status')+' · '+(labels[row.params.control_responsibility]||'Choose responsibility')));const work=row.params.evidence_work||[];work.slice(0,10).forEach(item=>box.append(node('p',(item.saved_work?'Existing saved evidence work · ':'New evidence job · ')+(labels[item.work]||'Choose work')+' · '+(labels[item.responsibility]||'Choose responsibility')+' · '+(labels[item.frequency]||'Choose frequency'))));if(work.length>10)box.append(node('p',(work.length-10)+' further evidence jobs are retained. Inspect all jobs in the ordinary control editor after restoring.'));return box;}
    differences.slice(0,20).forEach(key=>{const card=node('article','');card.append(node('h3',old.get(key)?.label||now.get(key)?.label||'Control'),describe(old.get(key),'Recovery copy'),describe(now.get(key),'Current draft'));host.append(card);});
    if(!lines.childNodes.length&&!differences.length)host.append(node('p','The editable choices match. Restoration still checks the current scope and saved mapping.'));
  }
  async function restoreRecovery(value) {
    if(busy||pending||checkingContext)throw new Error('Check the original pending result or wait for the current account check before restoring. Your entered work is kept.');
    const before=JSON.stringify(recoveryValue()),ticket=generation;bounded(value);
    if(value.format!=='compliance_mapping_draft_v1'||value.context!==current?.context||!Array.isArray(value.controls)||value.controls.length>2000||typeof value.name!=='string'||value.name.length>80||!value.defaults||defaultFields.some(id=>!Array.from($(id).options).some(option=>option.value===value.defaults[id])))throw new Error('This recovery copy cannot be restored to supported mapping choices. Current entered work is kept.');
    lock(true);
    try{
      const state=await request('');if(ticket!==generation||state.context!==value.context)throw new Error('The account or workspace changed. Nothing was restored.');
      if(value.scope&&!state.scopes.some(row=>row.supported&&row.value===value.scope)||value.target&&!state.mappings.some(row=>row.latest&&row.value===value.target))throw new Error('The scope or saved mapping changed. Your current entered work and recovery copy are kept; nothing was restored.');
      const restored={scope:value.scope,target:value.target,source:value.source,mapping_revision:value.mapping_revision,context:value.context,rows:new Map(),overrides:new Map(),total:0,next_offset:null};
      if(value.scope){
        const offsets=new Set([0]);if(value.selected&&Number.isInteger(value.selected_offset)&&value.selected_offset>=0&&value.selected_offset<2000)offsets.add(Math.floor(value.selected_offset/8)*8);value.controls.forEach(row=>{if(!Number.isInteger(row.offset)||row.offset<0||row.offset>=2000)throw new Error('A saved control cannot be matched to its original scope. Nothing was restored.');offsets.add(Math.floor(row.offset/8)*8);});
        const pages=[...offsets];for(let i=0;i<pages.length;i+=4){const batch=await Promise.all(pages.slice(i,i+4).map(offset=>request('/editor?scope='+encodeURIComponent(value.scope)+'&mapping='+encodeURIComponent(value.target)+'&offset='+offset)));batch.forEach((page,n)=>{if(page.context!==value.context||page.revision!==value.source||page.mapping_revision!==value.mapping_revision)throw new Error('The current scope or saved mapping differs from this recovery copy. Current entered work is kept; nothing was restored.');restored.total=page.total;page.rows.forEach((row,index)=>restored.rows.set(row.value,{...row,offset:pages[i+n]+index}));});}
        const seen=new Set();value.controls.forEach(row=>{const fresh=restored.rows.get(row.control);if(!fresh||fresh.offset!==row.offset||seen.has(row.control)||!row.params||!Array.isArray(row.params.evidence_work)||row.params.evidence_work.length>64||Object.keys(row.params).some(key=>!['control_status','control_responsibility','evidence_work'].includes(key)))throw new Error('A recovered control or evidence job is unsupported. Nothing was restored; current entered work is kept.');seen.add(row.control);const fields=schema(fresh).properties,allowed=(v,values)=>v===undefined||v===''||typeof v==='string'&&values.includes(v);if(!allowed(row.params.control_status,fields.control_status.enum)||!allowed(row.params.control_responsibility,fields.control_responsibility.enum)||row.params.evidence_work.some(job=>!job||typeof job!=='object'||Array.isArray(job)||Object.keys(job).some(key=>!['saved_work','work','responsibility','frequency'].includes(key))||Object.entries(fields.evidence_work.items.properties).some(([key,field])=>!allowed(job[key],field.enum))))throw new Error('A recovered choice cannot be matched to the current named control. Nothing was restored; current entered work is kept.');restored.overrides.set(row.control,{params:structuredClone(row.params)});});
        const final=await request('/editor?scope='+encodeURIComponent(value.scope)+'&mapping='+encodeURIComponent(value.target)+'&offset=0');if(final.context!==value.context||final.revision!==value.source||final.mapping_revision!==value.mapping_revision)throw new Error('The scope or mapping changed during restoration. Current entered work is kept.');
      }else if(value.controls.length||value.target||value.source||value.mapping_revision)throw new Error('This recovery copy is missing its original scope. Current entered work is kept.');
      const restoredSource=value.scope?await request('/controls?scope='+encodeURIComponent(value.scope)+'&offset=0'):null;if(restoredSource&&(restoredSource.context!==value.context||restoredSource.revision!==value.source))throw new Error('The final scope changed during restoration. Current entered work is kept.');
      if(ticket!==generation||JSON.stringify(recoveryValue())!==before)throw new Error('Your newer entered choices are kept. Review the recovery copy again.');
      current=state;$('scope').value=value.scope;$('target').value=value.target;$('name').value=value.name;defaultFields.forEach(id=>{$(id).value=value.defaults[id];});$('evidence-fields').hidden=value.defaults['evidence-kind']==='none';clearReview();draft=value.scope?restored:null;dirty=true;++draftEpoch;
      $('control-picker').replaceChildren(new Option('Choose a control',''));if(draft){draft.rows.forEach(row=>$('control-picker').append(new Option(row.label,row.value)));if(draft.rows.has(value.selected))$('control-picker').value=value.selected;draft.next_offset=[...Array(Math.ceil(draft.total/8)).keys()].map(i=>i*8).find(offset=>!draft.rows.has(Array.from(draft.rows.values()).find(row=>row.offset===offset)?.value))??null;}
      $('defaults').hidden=!!value.target;$('name').readOnly=!!value.target;$('load-editors').hidden=!draft||draft.next_offset===null;showEditor();say('Private choices restored for review. No mapping was saved or approved.');
      source=restoredSource;
    }finally{lock(false);}
  }
  function recoveryReady(){if(recoveryCopy||!current||!window.mvDraftRecovery)return;const meta=document.querySelector('meta[name="lightwork-draft-context"]');if(!meta||meta.content!==current.context){$('private-note').textContent='Reload this page to enable private recovery for this account and workspace. Current records are available; your entered choices remain on this page.';return;}recoveryCopy=window.mvDraftRecovery.create({host:$('form'),key:'compliance-task-mapping-editor',read:recoveryValue,restore:restoreRecovery,compare:comparison});}
  function edited(){dirty=true;if(recoveryCopy)recoveryCopy.changed();}
  async function replaceDraft(message){if(!dirty)return true;return !!window.mvConfirm&&await window.mvConfirm(message+' Current entered choices will be replaced. This does not save or approve a mapping.',{okText:'Replace entered choices'});}
  function clearPrivate(){++generation;requests.forEach(controller=>controller.abort());if(recoveryCopy){recoveryCopy.dispose();recoveryCopy.panel.remove();recoveryCopy=null;}dirty=false;draft=null;source=null;current=null;detail=null;detachOriginal();clearReview();$('form').reset();$('private-note').textContent='Reload this page to enable private recovery for your current account and workspace.';['mappings','control-list','control-editor','detail-rows'].forEach(id=>$(id).replaceChildren());$('detail').hidden=true;say('Your account, workspace or access changed. Private entered choices were cleared. Refresh to read current records.');}
  function accepted(value,exact){if(exact.draft_bound===false||dirty&&exact.draft_bound!==true)return;if(!value.mapping||!/^[A-Za-z0-9][A-Za-z0-9._:-]*\/[1-9][0-9]*$/.test(value.mapping))return;
    if(draft&&draftEpoch!==exact.draft_epoch)return;
    if(!Array.from($('target').options).some(option=>option.value===value.mapping))$('target').append(new Option(value.details.name+' · version '+value.details.version,value.mapping));
    $('target').value=value.mapping;draft=null;dirty=false;if(recoveryCopy){const exactCopy=recoveryCopy;exactCopy.clear().then(removed=>{if(!removed&&recoveryCopy===exactCopy){const note=exactCopy.panel.querySelector('[role=status]');if(note)note.textContent='The mapping request is confirmed. A separate private recovery copy remains; compare it before restoring, keeping current choices or discarding it.';}});}$('control-editor').replaceChildren();
  }
  try { const earlier=JSON.parse(sessionStorage.getItem(storage)||'null');if(earlier?.token&&/^[0-9a-f]{64}$/.test(earlier.context)){sessionStorage.setItem(storage+'.'+earlier.context,JSON.stringify(earlier));sessionStorage.removeItem(storage);} }catch(_){}
  function originalReference(context){try{const value=JSON.parse(sessionStorage.getItem(storage+'.'+context)||'null');return value?.context===context&&typeof value.token==='string'?value:null;}catch(_){return null;}}
  function detachOriginal(){pending=null;$('recovery').hidden=true;}
  function save(value) { const context=value?.context||pending?.context||current?.context;pending=value;let retained=true;try{if(value){const text=JSON.stringify(value);sessionStorage.setItem(storage+'.'+context,text);retained=sessionStorage.getItem(storage+'.'+context)===text;}else if(context)sessionStorage.removeItem(storage+'.'+context);}catch(_){retained=false;}$('recovery').hidden=!value;return retained;}
  function say(message) { window.mvStatus($('status'), message); }
  function problem(error) { return window.mvPlainDetail?.(error.detail) || window.mvErrorText?.(error, 'check this mapping') || 'The result could not be checked. Read saved records before trying again.'; }
  async function request(path, body) {
    const controller = new AbortController(); requests.add(controller); const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(API + path, {method: body ? 'POST' : 'GET', cache: 'no-store', signal: controller.signal,
        headers: body ? {'Content-Type': 'application/json'} : {}, ...(body ? {body: JSON.stringify(body)} : {})});
      const text = await response.text(); if (text.length > 262144) throw new Error('The reply is too large. Check saved records.');
      const value = JSON.parse(text); if (!response.ok) {if(response.status===401||response.status===403)clearPrivate();throw {status: response.status, detail: value.detail};} return value;
    } finally { clearTimeout(timer); requests.delete(controller); }
  }
  function lock(value) { busy = value; document.querySelectorAll('#cm-app button, #cm-app input, #cm-app select').forEach(el => { el.disabled = value; }); $('review').disabled = value || checkingContext || !source || !draft || draft.stale || !!pending; $('confirm').disabled=value||reviewOffset!==null; $('apply').disabled = value || checkingContext || !review || !$('confirm').checked || reviewOffset !== null || !!pending; }
  function clearReview() { review = null; reviewOffset = null; reviewedCount = 0; $('review-rows').replaceChildren(); $('review-panel').hidden = true; $('confirm').checked = false; }
  function node(tag, text) { const value = document.createElement(tag); value.textContent = text; return value; }
  function button(text, action) { const value = node('button', text); value.type = 'button'; value.className = 'btn btn--ghost'; value.addEventListener('click', action); return value; }
  function summary(value) { const list = document.createElement('dl'); Object.entries(value).forEach(([key, text]) => { if (text && typeof text === 'object') return; list.append(node('dt', key.replaceAll('_', ' ')), node('dd', String(text))); }); return list; }
  function showReview(value, approval) { review = value; reviewOffset = value.control_review?.next_offset ?? null; reviewedCount = value.control_review?.rows.length || 0; $('consequence').textContent = value.message; $('summary').replaceChildren(summary(value.details)); $('review-rows').replaceChildren(); if (value.control_review) addControls(value.control_review.rows, $('review-rows'), true); reviewProgress(value.control_review?.total || 0); $('review-panel').hidden = false; $('confirm').checked = false; $('apply').textContent = approval ? 'Approve reviewed mapping' : 'Save reviewed mapping'; $('review-panel').scrollIntoView({block: 'nearest'}); }
  function reviewProgress(total) { $('more-review').hidden = reviewOffset === null; $('review-count').textContent = total ? reviewedCount + ' of ' + total + ' mapped controls displayed for review.' : ''; $('confirm').disabled = reviewOffset !== null; }
  function defaults() { return {control_status: $('control-state').value, control_responsibility: $('control-owner').value, evidence_work: $('evidence-kind').value === 'none' ? [] : [{saved_work:'', work:$('evidence-kind').value, responsibility:$('evidence-owner').value, frequency:$('cadence').value}]}; }
  function schema(row) { const choice = (title, values) => ({type:'string',title,enum:Object.keys(values),enumNames:Object.values(values)});
    return {type:'object',title:'Control work',additionalProperties:false,required:['control_status','control_responsibility','evidence_work'],properties:{
      control_status:choice('Control status',{planned:'Planned',not_started:'Not started',not_implemented:'Not in place yet'}),
      control_responsibility:choice('Control responsibility',{control_owner:'Control owner',second_line:'Risk and compliance owner'}),
      evidence_work:{type:'array',title:'Evidence jobs',maxItems:64,items:{type:'object',additionalProperties:false,required:['saved_work','work','responsibility','frequency'],properties:{
        saved_work:choice('Saved evidence work',Object.fromEntries([['','New evidence job'],...row.saved_work.map(work=>[work.value,work.label])])),
        work:choice('Work',{collect:'Collect evidence',refresh:'Refresh evidence',review:'Review evidence'}),
        responsibility:choice('Responsibility',{evidence_owner:'Evidence owner',control_owner:'Control owner',second_line:'Risk and compliance owner'}),
        frequency:choice('Frequency',{one_time:'Once',monthly:'Every month',quarterly:'Every quarter',annual:'Every year',continuous:'Continuously'})}}}}}; }
  function editorNotice() { $('edited-count').textContent = (draft?.overrides.size || 0) + ' controls changed individually. Other controls keep their starting or saved choices.'; $('reset-control').hidden = !$('control-picker').value; $('reload-editor').hidden = !draft?.stale; }
  function showEditor() { $('control-editor').replaceChildren(); const key=$('control-picker').value, row=draft?.rows.get(key); if (!row) { editorNotice(); return; }
    const value = draft.overrides.get(key) || {params:structuredClone(row.choices || defaults())}; let mounting=true;
    try { const plan=FDActionFields.compile(schema(row)); FDActionFields.mount($('control-editor'),value,{plan,revision:draft.mapping_revision||draft.source},()=>{const legend=$('control-editor').querySelector('fieldset > legend');if(legend)legend.textContent='Control work';if(mounting)return; ++draftEpoch; draft.overrides.set(key,value);edited();clearReview();editorNotice();lock(false);}); }
    catch(error){say(problem(error));} const legend=$('control-editor').querySelector('fieldset > legend');if(legend)legend.textContent='Control work';mounting=false; editorNotice(); }
  async function loadEditors(more=false,replacement=null) {
    if(busy||!source||!current)return; const scope=$('scope').value,target=replacement?.target??$('target').value,ticket=++generation,pageOffset=more?draft?.next_offset||0:0; lock(true);
    try { const refreshed=replacement?await request('/controls?scope='+encodeURIComponent(scope)+'&offset=0'):null;const value=await request('/editor?scope='+encodeURIComponent(scope)+'&mapping='+encodeURIComponent(target)+'&offset='+pageOffset);
      if(ticket!==generation||value.context!==current.context||scope!==$('scope').value||(!replacement&&target!==$('target').value)||replacement&&draft!==replacement.draft)return;
      if(replacement){if(refreshed.context!==current.context||refreshed.revision!==value.revision)throw {detail:'The final scope changed while reloading. Your entered choices are kept.'};draft=null;source=refreshed;dirty=false;$('target').value=target;}
      if(draft&&(draft.scope!==scope||draft.target!==target))draft=null;
      if(draft&&(draft.source!==value.revision||draft.mapping_revision!==value.mapping_revision)){draft.stale=true;throw {detail:'The saved mapping or scope changed. Your individual draft is kept. Reload current mapping choices before a new review.'};}
      if(!draft)draft={scope,target,source:value.revision,mapping_revision:value.mapping_revision,rows:new Map(),overrides:new Map(),total:value.total};
      value.rows.forEach((row,index)=>draft.rows.set(row.value,{...row,offset:pageOffset+index}));draft.next_offset=value.next_offset;draft.stale=false;
      const keep=$('control-picker').value; $('control-picker').replaceChildren(new Option('Choose a control','')); draft.rows.forEach(row=>$('control-picker').append(new Option(row.label,row.value))); if(draft.rows.has(keep))$('control-picker').value=keep;draft.context=value.context;
      $('load-editors').hidden=draft.next_offset===null;$('defaults').hidden=!!target;$('name').readOnly=!!target;if(target)$('name').value=value.name;
      showEditor();if(dirty&&recoveryCopy)recoveryCopy.changed();
    }catch(error){if(draft)draft.stale=true;say(problem(error));editorNotice();}
    finally{lock(false);if(queued){queued=false;refresh();}}
  }
  async function reloadEditor(){if(busy||!draft||typeof window.mvConfirm!=='function')return;const exact=draft;
    const ok=await window.mvConfirm('Replace the individual draft with the latest saved choices? Nothing is saved or approved by reloading.',{okText:'Reload current choices'});if(!ok||busy||draft!==exact)return;
    let target=exact.target;if(exact.target){const id=exact.target.slice(0,exact.target.lastIndexOf('/')),row=current.mappings.find(item=>item.latest&&item.value.slice(0,item.value.lastIndexOf('/'))===id);if(!row){say('This mapping is unavailable. Your draft is kept.');return;}target=row.value;}
    clearReview();await loadEditors(false,{draft:exact,target});
  }
  async function refresh() {
    if (busy) { queued = true; return; }
    const ticket = ++generation, keep = $('scope').value, target = $('target').value, previousContext=current?.context; clearReview(); source = null; detail = null; $('detail').hidden = true; lock(true);
    try {
      const value = await request(''); if (ticket !== generation) return;if(previousContext&&previousContext!==value.context){clearPrivate();return;}current = value;
      if(pending?.context!==current.context)pending=originalReference(current.context);
      if (draft && draft.context && draft.context !== current.context) {clearPrivate();return;}
      $('scope').replaceChildren(new Option('Choose a final scope', ''));
      current.scopes.forEach(row => { const option = new Option(row.label, row.value); option.disabled = !row.supported; $('scope').append(option); });
      if (current.scopes.some(row => row.value === keep && row.supported)) $('scope').value = keep;
      $('target').replaceChildren(new Option('Create a new mapping','')); current.mappings.filter(row=>row.latest).forEach(row=>$('target').append(new Option(row.label,row.value)));
      if(target&&!current.mappings.some(row=>row.latest&&row.value===target)){const missing=new Option('Earlier selected version · reload current choices',target);missing.disabled=true;$('target').append(missing);} $('target').value=target;
      $('mappings').replaceChildren();
      current.mappings.forEach(row => { const article = node('article', ''); article.append(node('h3', row.label), node('p', row.status));
        const actions = node('div', ''); actions.className = 'cm-actions'; actions.append(button('Review saved choices', () => openMapping(row.value)));
        if(row.latest) actions.append(button('Revise saved choices',async()=>{if(busy||pending||!await replaceDraft('Open this saved mapping instead?'))return;$('target').value=row.value;dirty=false;draft=null;clearReview();$('form').scrollIntoView({block:'start'});if(source)loadEditors();else $('scope').focus();}));
        if (row.can_approve) actions.append(button('Approve for use', () => approve(row.value))); article.append(actions); $('mappings').append(article); });
      if (!current.mappings.length) $('mappings').append(node('p', 'No mappings yet. Build one from a final scope.'));
      $('listing').textContent = current.listing_notice; $('recovery').hidden = !pending;recoveryReady();
      say(current.scopes.length ? 'Choose a final scope and its business choices.' : 'Finalize an assessment scope before building its task mapping.');
    } catch (error) { say(problem(error)); }
    finally { lock(false); if (queued) { queued = false; refresh(); } else if ($('scope').value && current) await loadControls(false); }
  }
  function addControls(rows, target, mapped) {
    rows.forEach(row => { const card = node('article', ''); card.append(node('h3', row.control), node('p', row.framework));
      if (mapped) { card.append(node('p', row.initial_status + ' · ' + row.owner)); row.evidence.forEach(work => card.append(node('p', work.work + ' · ' + work.owner + ' · ' + work.frequency))); }
      else if (row.reason) card.append(node('p', row.reason)); target.append(card); });
  }
  async function loadControls(more) {
    if (busy) return; clearReview(); const scope = $('scope').value, ticket = ++generation;
    if (!scope) { source = null; $('source').textContent = ''; $('control-list').replaceChildren(); lock(false); return; }
    const offset = more ? source?.next_offset : 0; lock(true);
    try {
      const value = await request('/controls?scope=' + encodeURIComponent(scope) + '&offset=' + (offset || 0));
      if (ticket !== generation || value.context !== current.context || scope !== $('scope').value) return;
      if (more && source.revision !== value.revision) throw {detail: 'The scope changed. Refresh its controls before continuing.'};
      source = value; if (!more) $('control-list').replaceChildren(); addControls(value.controls, $('control-list'), false);
      $('source').textContent = value.total + ' controls. Every control will be included; none will be skipped. Control owner: ' + value.responsibilities.control_owner + '. Evidence owner: ' + value.responsibilities.evidence_owner + '. Risk and compliance owner: ' + value.responsibilities.second_line + '.'; $('more-controls').hidden = value.next_offset === null;
    } catch (error) { source = null; say(problem(error)); }
    finally { lock(false); if (queued) { queued = false; refresh(); } else if(!more && source) await loadEditors(); }
  }
  async function openMapping(key, more) {
    if (busy) return; const ticket = ++generation; lock(true);
    try {
      const value = await request('/mapping?mapping=' + encodeURIComponent(key) + '&offset=' + (more ? detail?.next_offset || 0 : 0));
      if (ticket !== generation || value.context !== current.context) return; detail = {...value, key};
      if (!more) $('detail-rows').replaceChildren(); addControls(value.rows, $('detail-rows'), true);
      $('detail-title').textContent = value.name + ' · version ' + value.version; $('detail-status').textContent = value.status + ' · ' + value.controls + ' controls';
      $('detail').hidden = false; $('more-details').hidden = value.next_offset === null;
    } catch (error) { say(problem(error)); }
    finally { lock(false); if (queued) { queued = false; refresh(); } }
  }
  async function approve(key) {
    if (busy || pending) { say('Check the original interrupted request first.'); return; } clearReview(); lock(true); const context = current.context, ticket = ++generation;
    try { const value = await request('/review-approval', {context, mapping: key}); if (ticket === generation && current.context === context && value.context === context) showReview(value, true); }
    catch (error) { say(problem(error)); } finally { lock(false); if (queued) { queued = false; refresh(); } }
  }
  $('form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy || !source || !draft || draft.stale || pending) return;
    for(const [key,value] of draft.overrides){const issue=FDActionFields.issue(FDActionFields.compile(schema(draft.rows.get(key))),value.params)||Object.values(value._actionErrors||{}).find(Boolean);if(issue){$('control-picker').value=key;showEditor();say(issue);return;}}
    clearReview(); lock(true); const context = current.context, ticket = ++generation;
    try { const value = await request('/review', {context, revision: draft.source, scope: $('scope').value, name: $('name').value,mapping:draft.target,mapping_revision:draft.mapping_revision,controls:Array.from(draft.overrides,([control,value])=>({control,...value.params})),
      control_state: $('control-state').value, control_owner: $('control-owner').value, evidence_kind: $('evidence-kind').value, evidence_owner: $('evidence-owner').value, cadence: $('cadence').value});
      if (ticket === generation && current.context === context && value.context === context) showReview(value, false);
    } catch (error) { say(problem(error)); } finally { lock(false); if (queued) { queued = false; refresh(); } }
  });
  $('form').addEventListener('input', event => { if (!busy && !event.target.closest('.draft-recovery') && event.target.id !== 'cm-scope' && event.target.id !== 'cm-target' && event.target.id !== 'cm-control-picker') { edited();++draftEpoch; clearReview(); lock(false); } });
  $('scope').addEventListener('change', async () => {const desired=$('scope').value,previous=draft?.scope||'';if(busy||pending||!await replaceDraft('Change the final scope?')){$('scope').value=previous;return;}$('scope').value=desired;dirty=false;draft=null;$('control-editor').replaceChildren();await loadControls(false);});
  $('target').addEventListener('change',async()=>{const desired=$('target').value,previous=draft?.target||'';if(busy||pending||!await replaceDraft('Change the mapping to prepare?')){$('target').value=previous;return;}$('target').value=desired;dirty=false;draft=null;clearReview();$('control-editor').replaceChildren();if(source)await loadEditors();});
  $('control-picker').addEventListener('change',showEditor);$('load-editors').addEventListener('click',()=>loadEditors(true));$('reload-editor').addEventListener('click',reloadEditor);
  $('reset-control').addEventListener('click',()=>{if(busy||!draft)return;++draftEpoch;draft.overrides.delete($('control-picker').value);edited();clearReview();showEditor();lock(false);});
  $('more-review').addEventListener('click',async()=>{if(busy||!review||reviewOffset===null)return;const exact=review,ticket=++generation;lock(true);try{const value=await request('/read-review',{token:exact.token,offset:reviewOffset});if(ticket!==generation||review!==exact||value.context!==current.context)return;addControls(value.rows,$('review-rows'),true);reviewedCount+=value.rows.length;reviewOffset=value.next_offset;reviewProgress(value.total);}catch(error){clearReview();say(problem(error));}finally{lock(false);}});
  $('evidence-kind').addEventListener('change', () => { $('evidence-fields').hidden = $('evidence-kind').value === 'none'; });
  $('defaults').addEventListener('input',()=>{if(!busy)showEditor();});
  $('confirm').addEventListener('change', () => lock(false)); $('cancel').addEventListener('click', () => { clearReview(); lock(false); });
  $('apply').addEventListener('click', async () => {
    if (busy || !review || !$('confirm').checked || reviewOffset!==null || pending) return; const exact = {token: review.token, context: review.context, draft_epoch:draftEpoch,draft_bound:$('apply').textContent==='Save reviewed mapping'}; if(!save(exact)){say('This browser could not keep the original request reference. Nothing was sent. Keep this page open and enable browser storage before trying again.');return;} clearReview(); lock(true);
    let message;
    try { const value = await request('/apply', {token: exact.token, confirmed: true}); if (current?.context === exact.context) { accepted(value,exact);save(null); message = value.message; } }
    catch (error) { if (error.status && error.status < 500) save(null); message = problem(error) + (pending ? ' Check the original saved result before starting another request.' : ''); }
    finally { lock(false); queued = false; await refresh(); if (current?.context === exact.context && message) say(message); }
  });
  $('readback').addEventListener('click', async () => {
    if (busy || !pending) return; const exact = pending; lock(true); let message;
    try { const value = await request('/readback', {token: exact.token}); if (current?.context === exact.context) { message = value.message;
      if (value.status !== 'not_found') {accepted(value,exact);save(null);} else message += ' If you continue, retry only this exact reviewed request; do not create another mapping while its result is uncertain.'; } }
    catch (error) { message = problem(error); }
    finally { lock(false); queued = false; await refresh(); if (current?.context === exact.context && message) say(message); }
  });
  $('retry').addEventListener('click', async () => {
    if (busy || !pending || typeof window.mvConfirm !== 'function') return;
    const exact = pending, ok = await window.mvConfirm('Continue the exact earlier reviewed request? The same protected request is reused. If it was already saved or approved, Lightwork reads the saved result instead of making another mapping.', {okText: 'Continue exact request'});
    if (!ok || busy || pending !== exact) return; lock(true); let message;
    try { const value = await request('/apply', {token: exact.token, confirmed: true}); if (current?.context === exact.context) { accepted(value,exact);save(null); message = value.message; } }
    catch (error) { message = problem(error); }
    finally { lock(false); queued = false; await refresh(); if (current?.context === exact.context && message) say(message); }
  });
  $('dismiss').addEventListener('click', async () => {
    if (busy || !pending || typeof window.mvConfirm !== 'function') return;
    const exact = pending, ok = await window.mvConfirm('Have you checked the saved mappings and their current review status? Clearing this interrupted-request reminder does not prove the earlier request succeeded or undo any saved mapping.', {okText: 'Clear reminder'});
    if (!ok || busy || pending !== exact) return; save(null); clearReview(); lock(false); say('The reminder is cleared. Saved mappings remain unchanged; the earlier request is not being reported as successful.');
  });
  $('refresh').addEventListener('click', refresh); $('more-controls').addEventListener('click', () => loadControls(true)); $('more-details').addEventListener('click', () => openMapping(detail.key, true));
  window.addEventListener('lightwork:product-state-changed', refresh); document.addEventListener('lightwork:product-operation-complete', refresh);
  document.addEventListener('lightwork:copilot-context-changed',async()=>{if(!current||checkingContext)return;const context=current.context,ticket=generation;checkingContext=true;lock(busy);try{const state=await request('');if(ticket!==generation)return;if(state.context!==context){clearPrivate();return;}say('Current account and workspace checked. Your editable mapping choices are kept.');}catch(error){if(ticket===generation)say(problem(error));}finally{checkingContext=false;lock(busy);}});
  document.addEventListener('lightwork:account-context-changed',clearPrivate);document.addEventListener('lightwork:workspace-changed',clearPrivate);window.addEventListener('lightwork:context-changed',clearPrivate);
  window.addEventListener('beforeunload',event=>{if(dirty||pending){event.preventDefault();event.returnValue='';}});
  window.addEventListener('lightwork:drafts-ready',recoveryReady);
  window.LightworkComplianceMapping={open:async(context,mode)=>{if(busy||pending||!['create','revise'].includes(mode))return false;const value=await request('');if(value.context!==context||current?.context!==context)return false;clearReview();$('form').scrollIntoView({block:'start'});if(mode==='revise')$('target').focus();else $('scope').focus();return true;}};
  save(pending); refresh();
})();
