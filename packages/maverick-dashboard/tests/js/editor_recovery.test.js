'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const templates=path.resolve(__dirname,'../../maverick_dashboard/templates');
function flowFixture(fetchImpl){
  const dom=new JSDOM('<input id="fd-nl" value="current brief"><input id="fd-name"><input id="fd-id"><input id="fd-notify" type="checkbox">'),d=dom.window.document;
  const root={id:'saved',name:'Current flow',version:2,revision:'revision-two',start:'first',nodes:[{id:'first',kind:'agent',label:'current'}]};
  const context={rootFlow:root,flow:root,document:d,idInput:d.getElementById('fd-id'),nameInput:d.getElementById('fd-name'),flowInputs:[],
    apiFetch:fetchImpl||(async()=>({ok:true,json:async()=>({id:'saved',version:2,revision:'revision-two'})})),pushHistory(){},renderCrumbs(){},syncScheduleControls(){},render(){},renderProps(){},
    draftSnapshot(){return JSON.stringify({flow:context.rootFlow,id:context.idInput.value,name:context.nameInput.value,inputs:context.flowInputs});}};
  const source=fs.readFileSync(path.join(templates,'flow_designer.js'),'utf8');
  // flow_designer.html loads the recipe-inputs helpers before the designer.
  vm.runInNewContext(fs.readFileSync(path.join(templates,'flow_designer_inputs.js'),'utf8'),context);
  vm.runInNewContext(source.slice(source.indexOf('  function recoveryPayload('),source.indexOf('  function initializeRecovery(')),context);
  const payload={format:1,base:{id:'saved',version:2,revision:'revision-two'},brief:'Recovered brief',editor:{flow:{id:'saved',name:'Recovered',start:'loop',nodes:[{id:'loop',kind:'foreach',body:{nodes:[{id:'child',kind:'action',paramsRaw:'{unfinished',params:{}}]}}]},id:'saved',name:'Recovered',inputs:[],notify:false}};
  return {dom,d,context,payload};
}

test('flow recovery retains nested unfinished parameter JSON without saving or running',async()=>{
  const calls=[];const ui=flowFixture(async url=>{calls.push(url);return {ok:true,json:async()=>({id:'saved',version:2,revision:'revision-two'})};});
  await ui.context.restoreRecovery(ui.payload);
  assert.equal(ui.context.rootFlow.nodes[0].body.nodes[0].paramsRaw,'{unfinished');assert.equal(ui.context.rootFlow.revision,'revision-two');assert.equal(ui.d.getElementById('fd-nl').value,'Recovered brief');assert.deepEqual(calls,['/api/v1/flows/saved']);ui.dom.window.close();
});

test('flow recovery refuses newer saved state and preserves the current editor',async()=>{
  const ui=flowFixture(async()=>({ok:true,json:async()=>({id:'saved',version:3,revision:'revision-three'})}));const before=ui.context.rootFlow;
  await assert.rejects(ui.context.restoreRecovery(ui.payload),/saved flow changed/);assert.equal(ui.context.rootFlow,before);assert.equal(ui.d.getElementById('fd-nl').value,'current brief');ui.dom.window.close();
});

test('typing a brief during source verification prevents a late flow restore',async()=>{
  const ui=flowFixture(async()=>{ui.d.getElementById('fd-nl').value='New typing';return {ok:true,json:async()=>({id:'saved',version:2,revision:'revision-two'})};});const before=ui.context.rootFlow;
  await assert.rejects(ui.context.restoreRecovery(ui.payload),/newer canvas edits/);assert.equal(ui.context.rootFlow,before);assert.equal(ui.d.getElementById('fd-nl').value,'New typing');ui.dom.window.close();
});

test('malformed flow recovery cannot partially replace an editor',async()=>{
  const ui=flowFixture();const before=ui.context.rootFlow;ui.payload.editor.flow.nodes=[null];
  await assert.rejects(ui.context.restoreRecovery(ui.payload),/steps that could not be read/);assert.equal(ui.context.rootFlow,before);ui.dom.window.close();
});

function workflowFixture(){
  const dom=new JSDOM('<div class="wf"><textarea id="wf-brief">brief</textarea><input id="wf-name" value="workflow"><textarea id="wf-steps">  unfinished steps  </textarea><input id="pb-name" value="agent"><input id="pb-risk" value="medium"><input id="wf-file" type="file"><div id="pb-steps"></div><div id="wf-input-fields"></div><button id="wf-add-input"></button></div>'),d=dom.window.document;
  const context={document:d,Option:dom.window.Option,productText(node,source){node.textContent=source;},mode:'playbook',templateWorkspaceStarted:true,playbookWorkspaceStarted:true,wfEditingName:'workflow',wfEditGeneration:3,wfEditWall:90,pbEditingName:'agent',pbEditGeneration:'a'.repeat(64),pbEditPreserve:{compartment:'trusted'},pbSteps:d.getElementById('pb-steps'),pbName:d.getElementById('pb-name'),
    addStep(){const row=d.createElement('div');row.className='pb-step';for(const key of ['name','inst','tools','gate']){const input=d.createElement('input');input.className='pb-step__'+key;row.append(input);}context.pbSteps.append(row);},
    paintGate(){},renumber(){},renderToolSelections(){},schedulePbLint(){},setStatus(){},setForm(mode){context.mode=mode;},collectPlaybook(){return {workflow:[]};}};
  context.addStep();context.pbSteps.querySelector('.pb-step__inst').value='  Work without a step name yet  ';
  const source=fs.readFileSync(path.join(templates,'workflow_builder.html'),'utf8');
  context.window=dom.window;
  vm.runInNewContext(source.slice(source.indexOf('    function productText('),source.indexOf('    function appendSource(')),context);
  vm.runInNewContext(source.slice(source.indexOf('    var inputFields ='),source.indexOf('    function renderDraft(')),context);
  vm.runInNewContext(source.slice(source.indexOf('    function recoveryFields('),source.indexOf('    var existingNames',source.indexOf('    function recoveryFields('))),context);
  vm.runInNewContext(source.slice(source.indexOf('    function playbookPayload('),source.indexOf('    // --- live governance feedback',source.indexOf('    function playbookPayload('))),context);
  return {dom,d,context};
}

test('workflow restoration keeps incomplete steps, raw whitespace and original overwrite tokens',()=>{
  const ui=workflowFixture(),saved=JSON.parse(JSON.stringify(ui.context.recoveryPayload()));
  ui.d.getElementById('wf-steps').value='new blank';ui.context.pbSteps.textContent='';ui.context.pbEditGeneration='b'.repeat(64);ui.context.wfEditGeneration=8;
  ui.context.restoreRecovery(saved);
  assert.equal(ui.d.getElementById('wf-steps').value,'  unfinished steps  ');assert.equal(ui.context.pbSteps.querySelector('.pb-step__name').value,'');assert.equal(ui.context.pbSteps.querySelector('.pb-step__inst').value,'  Work without a step name yet  ');
  assert.equal(ui.context.wfEditGeneration,3);assert.equal(ui.context.playbookPayload().expected_generation,'a'.repeat(64));assert.equal(saved.fields['wf-file'],undefined);ui.dom.window.close();
});

test('workflow restoration refuses missing version bindings before replacing user work',()=>{
  const ui=workflowFixture(),saved=JSON.parse(JSON.stringify(ui.context.recoveryPayload()));saved.agent_generation=null;ui.d.getElementById('wf-steps').value='newer work';
  assert.throws(()=>ui.context.restoreRecovery(saved),/incomplete fields or saved-version/);assert.equal(ui.d.getElementById('wf-steps').value,'newer work');ui.dom.window.close();
});


test('workflow recovery preserves unfinished typed fields and raw choices without save-time validation',()=>{
  const ui=workflowFixture();ui.context.addInputField('',{});
  const row=ui.d.querySelector('#wf-input-fields fieldset');
  row.querySelector('[data-input-key="name"]').value='  unfinished name  ';
  row.querySelector('[data-input-key="choices"]').value=' Alpha, , Beta  ';
  const saved=JSON.parse(JSON.stringify(ui.context.recoveryPayload()));
  assert.throws(()=>ui.context.collectInputFields(),/unique name/);
  ui.d.getElementById('wf-input-fields').replaceChildren();ui.context.restoreRecovery(saved);
  assert.equal(ui.d.querySelector('[data-input-key="name"]').value,'  unfinished name  ');
  assert.equal(ui.d.querySelector('[data-input-key="choices"]').value,' Alpha, , Beta  ');
  assert.throws(()=>ui.context.collectInputFields(),/unique name/);ui.dom.window.close();
});
