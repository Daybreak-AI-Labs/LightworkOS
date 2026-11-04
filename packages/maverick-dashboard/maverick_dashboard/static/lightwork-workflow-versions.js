(() => {
  'use strict';
  const panel=document.getElementById('workflow-versions'), content=document.getElementById('workflow-versions-content'), status=document.getElementById('workflow-versions-status');
  if(!panel)return;
  let name=new URLSearchParams(location.search).get('edit')||new URLSearchParams(location.search).get('template'), serial=0, context=null, busy=false, lost=false;
  const copy=(element,text,values)=>{if(window.LightworkI18n)window.LightworkI18n.set(element,text,values);else element.textContent=String(text||'').replace(/\{(\w+)\}/g,(whole,key)=>values&&Object.prototype.hasOwnProperty.call(values,key)?String(values[key]):whole);};
  const text=(source,values)=>window.LightworkI18n?window.LightworkI18n.text(source,values):String(source||'').replace(/\{(\w+)\}/g,(whole,key)=>values&&Object.prototype.hasOwnProperty.call(values,key)?String(values[key]):whole);
  const number=value=>window.LightworkI18n?window.LightworkI18n.number(value):String(value);
  const node=(tag,value,source=false)=>{const e=document.createElement(tag);if(source){e.lang='und';e.dir='auto';e.dataset.userContent='';if(value)e.textContent=value;}else if(value)copy(e,value);return e;};
  const control=(label,fn)=>{const e=node('button',label);e.type='button';e.className='btn';e.addEventListener('click',fn);return e;};
  const field=(parent,label,value='',type='text',source=false)=>{const wrapper=node('label',source?null:label), input=node('input',null,true);if(source)wrapper.append(node('bdi',label,true));input.className='input';input.type=type;input.value=value;wrapper.append(input);parent.append(wrapper);return input;};
  function clear(){lost=true;serial++;content.replaceChildren();copy(status,'Account or workspace changed. Reload to review this workflow.');}
  document.addEventListener('lightwork:workspace-changed',clear);
  async function request(path,body){
    return window.mvFetchJSON('/api/v1/workflows/'+encodeURIComponent(name)+path,{method:body?'POST':'GET',body:body?{...body,context}:undefined,
      cache:'no-store',timeout:15000,plainDetail:true,onAccess:clear,accessStatuses:[401],messages:{401:'Sign in before continuing.'}},'review the workflow versions');
  }
  async function mutate(button,path,body,success){
    if(busy||lost)return;busy=true;button.disabled=true;
    try{const data=await request(path,body);if(lost)return;await success(data);}
    catch(error){copy(status,error.name==='AbortError'?'The result is unknown. Refresh the version review before trying again.':error.message);}
    finally{busy=false;if(button.isConnected)button.disabled=false;}
  }
  async function refresh(){
    if(!name||lost||busy)return;panel.hidden=false;const attempt=++serial;copy(status,'Loading saved versions.');
    content.replaceChildren();
    try{
      const data=await request('/versions');if(attempt!==serial||lost)return;
      if(context&&context!==data.context){clear();return;}context=data.context;
      content.append(node('p',data.published===data.current?'This saved draft is published.':'This saved draft is not the published version.'));
      const samples=node('fieldset');samples.append(node('legend','Review a sample without executing the workflow'));
      const sampleName=field(samples,'Sample name',text('Reviewed sample')), inputs={};
      for(const key of data.params){
        const spec=(data.parameter_schema.fields||{})[key]||{},label=spec.label||key;
        if(spec.type==='connection'){
          const wrapper=node('label'), select=node('select');wrapper.append(node('bdi',label,true),select);samples.append(wrapper);inputs[key]=select;window.LightworkTemplateConnections.mount(select);
        }else if(spec.type==='enum'){
          const wrapper=node('label'),select=node('select',null,true);wrapper.append(node('bdi',label,true));select.className='input';select.append(node('option','Choose an option'));
          for(const choice of spec.choices||[]){const option=node('option',choice,true);option.value=choice;select.append(option);}select.value=spec.default||'';wrapper.append(select);samples.append(wrapper);inputs[key]=select;
        }else inputs[key]=field(samples,label,spec.default||'',spec.type==='date'?'date':spec.type==='number'?'number':spec.type==='email'?'email':'text',true);
        inputs[key].required=spec.required===true;if(spec.help)samples.append(node('p',spec.help,true));
      }
      function conditions(){
        for(const [key,input] of Object.entries(inputs)){
          const when=((data.parameter_schema.fields||{})[key]||{}).show_when;
          const hidden=!!when&&inputs[when.field]&&inputs[when.field].value!==when.value;
          input.disabled=hidden;input.closest('label').hidden=hidden;
        }
      }
      samples.addEventListener('change',conditions);samples.addEventListener('input',conditions);conditions();
      if(window.LightworkI18n)window.LightworkI18n.validation(samples);
      const expected=field(samples,'Expected phrase in the rendered instructions (optional)'), output=node('pre',null,true);output.style.whiteSpace='pre-wrap';
      const check=control('Check reviewed sample',()=>{
        if(!Object.values(inputs).every(input=>input.reportValidity()))return;
        mutate(check,'/fixtures',{expected_version:data.current,inputs:Object.fromEntries(Object.entries(inputs).map(([key,value])=>[key,value.value])),label:sampleName.value,expected_contains:expected.value},result=>{
          output.textContent=result.title+'\n\n'+result.body;copy(status,result.passed?'Sample inputs passed. Review the instructions below. No work was executed.':'The expected phrase was not present. No work was executed.');
        });
      });samples.append(check,output);content.append(samples);
      const publication=node('fieldset');publication.append(node('legend','Publish for new schedules'),node('p',data.effect));
      if(data.schedules.length){const list=node('ul');for(const schedule of data.schedules){const item=node('li');copy(item,'{name} — {state} — keeps its current version',{name:schedule.title,state:window.mvState?window.mvState(schedule.state):schedule.state});list.append(item);}publication.append(list);}
      else publication.append(node('p','No schedules refer to this workflow.'));
      const label=field(publication,'Publication name',text('Reviewed version {number}',{number:number(data.generation)}));
      const publish=control('Review publication',async()=>{
        if(!await mvConfirm('Publish this checked draft for new schedules? {effect}',{okText:'Publish version',productCopy:true,values:{effect:text(data.effect)}}))return;
        mutate(publish,'/publish',{expected_version:data.current,impact_version:data.impact_version,label:label.value,confirm:true},()=>{copy(status,'Published. Existing schedules retain their versions.');});
      });publish.disabled=!data.can_publish;if(!data.can_publish)publication.append(node('p','Publishing your reviewed workflow requires current permission to operate.'));publication.append(publish);content.append(publication);
      content.append(node('h3','Version history and comparison with the current draft'));
      for(const version of [...data.versions].reverse()){
        const box=node('details'),summary=node('summary');summary.append(node('bdi',version.label,true));if(version.current)summary.append(node('span',' · current draft'));if(version.published)summary.append(node('span',' · published'));box.append(summary);
        const diff=node('pre');diff.style.whiteSpace='pre-wrap';
        if(!version.diff.length)copy(diff,'No content changes.');
        else {diff.lang='und';diff.dir='auto';diff.dataset.userContent='';for(const line of version.diff){const span=node(line.startsWith('+')?'ins':line.startsWith('-')?'del':'span',line+'\n',true);diff.append(span);}}box.append(diff);
        const copy=field(box,'Name for a new copy','');
        const clone=control('Clone as new draft',()=>mutate(clone,'/restore',{version:version.version,expected_generation:data.generation,new_name:copy.value},result=>{location.assign('/workflow-builder?edit='+encodeURIComponent(result.name));}));
        const restore=control('Restore as draft',async()=>{
          if(!await mvConfirm('Restore this content as a new draft? The published version and existing schedules stay pinned.',{okText:'Restore draft',productCopy:true}))return;
          mutate(restore,'/restore',{version:version.version,expected_generation:data.generation},result=>location.assign('/workflow-builder?edit='+encodeURIComponent(result.name)));
        });restore.disabled=version.current;box.append(clone,restore);content.append(box);
      }
      copy(status,data.fixtures.length===1?'Version review loaded. {count} recent sample check recorded. Rendering checks do not qualify live execution.':'Version review loaded. {count} recent sample checks recorded. Rendering checks do not qualify live execution.',{count:number(data.fixtures.length)});
    }catch(error){if(attempt===serial)copy(status,error.message);}
  }
  document.getElementById('workflow-versions-refresh').addEventListener('click',refresh);
  document.addEventListener('lightwork:workflow-saved',event=>{name=event.detail.name;refresh();});
  refresh();
})();
