'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const fs=require('node:fs'), path=require('node:path'), {webcrypto}=require('node:crypto');
const {JSDOM}=require('jsdom');
const {shell} = require('./_shell');
const template=fs.readFileSync(path.join(__dirname,'../../maverick_dashboard/templates/graph_editor.html'),'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const script=template.slice(template.indexOf('<script>')+8,template.lastIndexOf('</script>'));
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function until(condition){
  for(let i=0;i<500;i++){
    if(condition())return;
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  assert.ok(condition(),'the expected task-map state did not arrive');
}
const result=(body,status=200)=>({ok:status>=200&&status<300,status,json:async()=>body});
function page(handler) {
  const dom=new JSDOM(template.slice(template.indexOf('<style>'),template.indexOf('<script>')),
    {url:'https://local.test/graph-editor',runScripts:'outside-only'});
  const w=dom.window,doc=w.document,calls=[],timers=new Map();let timer=0;
  w.matchMedia=()=>({matches:true,addEventListener(){}});w.TextEncoder=TextEncoder;
  Object.defineProperty(w,'crypto',{value:webcrypto});
  w.setTimeout=callback=>{timers.set(++timer,callback);return timer;};w.clearTimeout=id=>timers.delete(id);
  const tree={nodes:[{id:1,title:'Current task',parent_id:null,status:'pending',updated_at:1},
                     {id:2,title:'Other own task',parent_id:null,status:'pending',updated_at:1}],edges:[]};
  w.fetch=async(url,options={})=>{calls.push({url,options});return handler?handler(url,options,tree):result(tree);};
  const selections=[];doc.addEventListener('lightwork:copilot-selection',event=>selections.push(event.detail.selection));
  shell(w);
  w.eval(script);
  return {dom,w,doc,calls,tree,selections,
    select(id){const input=doc.getElementById('ge-select');input.value=String(id);input.dispatchEvent(new w.Event('change'));},
    expire(){assert.ok(timers.size);[...timers.values()].at(-1)();}};
}

test('real task selection binds Copilot and clearing the selection clears its target',async()=>{
  const ui=page();await tick();ui.select(1);
  assert.deepEqual(JSON.parse(JSON.stringify(ui.selections.at(-1))),{kind:'goal',id:1,goal_id:1});
  ui.select('');assert.deepEqual(JSON.parse(JSON.stringify(ui.selections.at(-1))),{});
  ui.dom.window.close();
});

test('duplicate title clicks stay fenced and submitted fields remain locked',async()=>{
  let release;
  const ui=page((url,options,tree)=>options.method?new Promise(resolve=>{release=resolve;}):result(tree));
  await tick();ui.select(1);const title=ui.doc.getElementById('ge-title');title.value='Draft title';
  const save=ui.doc.getElementById('ge-retitle');save.click();save.click();await tick();
  assert.equal(ui.calls.filter(row=>row.options.method).length,1);
  assert.equal(title.disabled,true);assert.equal(ui.doc.getElementById('ge-select').disabled,true);
  assert.equal(ui.doc.getElementById('ge-parent').disabled,true);
  release(result(null,204));await tick();await tick();
  assert.equal(title.disabled,false);assert.equal(title.value,'Draft title');
  ui.dom.window.close();
});

test('unknown child acknowledgement keeps draft and operation across explicit retry without automatic sends',async()=>{
  let attempts=0;
  const ui=page((url,options,tree)=>{
    if(!options.method)return result(tree);
    attempts++;if(attempts===1)return new Promise(()=>{});
    tree.nodes.push({id:3,title:'Smaller task',parent_id:1,status:'pending',updated_at:2});tree.edges.push([1,3]);
    return result({id:3,title:'Smaller task'},201);
  });
  await tick();ui.select(1);const input=ui.doc.getElementById('ge-child-title');input.value='Smaller task';
  ui.doc.getElementById('ge-add-child').click();
  await until(()=>attempts===1);
  assert.equal(attempts,1);ui.expire();await tick();
  await until(()=>!input.disabled&&/not confirmed/.test(ui.doc.getElementById('ge-error').textContent));
  assert.equal(input.value,'Smaller task');assert.equal(input.disabled,false);
  assert.match(ui.doc.getElementById('ge-error').textContent,/not confirmed/);
  assert.equal(attempts,1);
  ui.doc.getElementById('ge-add-child').click();
  await until(()=>input.value==='');
  const bodies=ui.calls.filter(row=>row.options.method).map(row=>JSON.parse(row.options.body));
  assert.equal(bodies.length,2);assert.equal(bodies[0].operation_id,bodies[1].operation_id);
  assert.equal(input.value,'');assert.match(ui.doc.getElementById('ge-status').textContent,/Smaller task.*not started/);
  assert.equal(ui.selections.at(-1).id,3);ui.dom.window.close();
});

test('stale rename shows current map while retaining the draft for explicit fresh review',async()=>{
  const ui=page((url,options,tree)=>{
    if(!options.method)return result(tree);
    tree.nodes[0].title='New saved title';tree.nodes[0].updated_at=2;return result({},409);
  });
  await tick();ui.select(1);ui.doc.getElementById('ge-title').value='My unsaved draft';
  ui.doc.getElementById('ge-retitle').click();await tick();await tick();
  assert.equal(ui.doc.getElementById('ge-title').value,'My unsaved draft');
  assert.match(ui.doc.getElementById('ge-select').selectedOptions[0].textContent,/New saved title/);
  assert.match(ui.doc.getElementById('ge-error').textContent,/draft is kept.*current state/);
  assert.equal(ui.calls.filter(row=>row.options.method).length,1);ui.dom.window.close();
});

test('workspace change aborts a pending edit and never reenables stale controls',async()=>{
  let release;const ui=page((url,options,tree)=>options.method?new Promise(resolve=>{release=resolve;}):result(tree));
  await tick();ui.select(1);ui.doc.getElementById('ge-title').value='Local draft';ui.doc.getElementById('ge-retitle').click();await tick();
  ui.w.dispatchEvent(new ui.w.Event('lightwork:context-changed'));release(result(null,204));await tick();
  assert.equal(ui.doc.getElementById('ge-title').disabled,true);assert.equal(ui.doc.getElementById('ge-title').value,'Local draft');
  assert.deepEqual(JSON.parse(JSON.stringify(ui.selections.at(-1))),{});
  assert.equal(ui.calls.filter(row=>row.options.method).length,1);ui.dom.window.close();
});
