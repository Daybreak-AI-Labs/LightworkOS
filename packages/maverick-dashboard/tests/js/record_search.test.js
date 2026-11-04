'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const read=name=>fs.readFileSync(path.resolve(__dirname,'../../maverick_dashboard/static/'+name),'utf8');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const context='a'.repeat(64),snapshot='b'.repeat(64);
function row(id,title='Acme'){return {kind:'vendor',id,title,revision:'2',state:'approved',href:'/privacy/vendors/'+id};}
function result(items,extra={}){return {context,snapshot,items,total:items.length,next_offset:null,complete:true,coverage:[{source:'vendors',state:'current',indexed:items.length}],...extra};}
async function fixture(){
  const dom=new JSDOM(`<meta name="lightwork-search-context" content="${context}"><button id="navfinder-open">Find</button><dialog id="navfinder-dialog"><button id="navfinder-close">Close</button><input id="navfinder-input"><p id="navfinder-count"></p><ul id="navfinder-results"><li><a id="page" href="/privacy" data-navfinder-target data-search="Privacy">Privacy</a></li></ul><p id="navfinder-empty" hidden></p><select id="navfinder-kind"><option value="all">All</option><option value="knowledge">Approved content</option><option value="history">History</option><option value="task">Tasks</option><option value="pages">Pages</option></select><label id="navfinder-purpose-label" hidden><select id="navfinder-purpose"></select></label><fieldset id="navfinder-history" hidden><select id="navfinder-source"><option value="tasks">Tasks</option><option value="facts">Facts</option></select><input id="navfinder-after"><input id="navfinder-before"><select id="navfinder-order"><option value="newest">Newest</option><option value="oldest">Oldest</option></select></fieldset><button id="navfinder-search">Search records</button><p id="navfinder-record-status"></p><button id="navfinder-more" hidden>More</button><ul id="navfinder-coverage"></ul></dialog>`,{url:'https://lightwork.test/',runScripts:'outside-only'});
  const w=dom.window,d=w.document,dialog=d.getElementById('navfinder-dialog'),calls=[];
  dialog.showModal=()=>{dialog.open=true;};dialog.close=()=>{dialog.open=false;dialog.dispatchEvent(new w.Event('close'));};
  let handler=async()=>({ok:true,json:async()=>result([row('v1')])});
  w.fetch=async(url,options)=>{calls.push({url,...options,body:options.body?JSON.parse(options.body):null});return handler(url,options);};
  w.eval(read('lightwork-navfinder.js'));w.eval(read('lightwork-record-search.js'));await tick();
  d.getElementById('navfinder-open').click();
  const input=d.getElementById('navfinder-input');
  function query(value){input.value=value;input.dispatchEvent(new w.Event('input',{bubbles:true}));}
  async function search(value){query(value);d.getElementById('navfinder-search').click();await tick();}
  return {dom,w,d,dialog,input,calls,query,search,set handler(value){handler=value;}};
}

test('record results use existing keyboard selection and text-only labels',async()=>{
  const ui=await fixture();ui.handler=async()=>({ok:true,json:async()=>result([row('v1','<img src=x onerror=alert(1)>'),row('v2')])});
  await ui.search('Acme');
  assert.equal(ui.calls[0].method,'POST');assert.equal(ui.calls[0].headers['X-Lightwork-Search-Context'],context);
  assert.equal(ui.d.querySelectorAll('#navfinder-results img').length,0);
  assert.equal(ui.input.getAttribute('aria-activedescendant'),'navfinder-record-0');
  ui.input.dispatchEvent(new ui.w.KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true}));
  assert.equal(ui.input.getAttribute('aria-activedescendant'),'navfinder-record-1');
  assert.equal(ui.d.querySelectorAll('[aria-selected="true"]').length,1);
  let activated=false;ui.d.getElementById('navfinder-record-1').addEventListener('click',event=>{event.preventDefault();activated=true;});
  ui.input.dispatchEvent(new ui.w.KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
  assert.equal(activated,true);assert.equal(ui.dialog.open,false);assert.equal(ui.input.hasAttribute('aria-activedescendant'),false);
  ui.dom.window.close();
});

test('new query and closing the dialog reject stale in-flight results',async()=>{
  const ui=await fixture();let resolve;
  ui.handler=()=>new Promise(done=>{resolve=done;});
  await ui.search('Old');ui.query('New');
  resolve({ok:true,json:async()=>result([row('old')])});await tick();
  assert.equal(ui.d.querySelectorAll('[id^="navfinder-record-"]').length,1); // status only
  ui.d.getElementById('navfinder-search').click();await tick();
  ui.d.getElementById('navfinder-close').click();resolve({ok:true,json:async()=>result([row('closed')])});await tick();
  assert.equal(ui.d.getElementById('navfinder-record-0'),null);
  ui.dom.window.close();
});

test('paging sends the verified snapshot and clears stale results on conflict',async()=>{
  const ui=await fixture();ui.handler=async()=>({ok:true,json:async()=>result([row('v1')],{total:2,next_offset:1,complete:false,coverage:[{source:'vendors',state:'partial',indexed:2}]})});
  await ui.search('Acme');assert.equal(ui.d.getElementById('navfinder-more').hidden,false);
  assert.match(ui.d.getElementById('navfinder-record-status').textContent,/partial or unavailable/);
  ui.w.mvErrorText=(failure,action)=>'Could not '+action+'. '+(failure.status===409?'This was changed since you opened it. Refresh the page and try again.':'Please try again.');
  ui.handler=async()=>({ok:false,status:409,json:async()=>({detail:'snapshot_mismatch: records or access changed while paging'})});
  ui.d.getElementById('navfinder-more').click();await tick();
  assert.equal(ui.calls[1].body.snapshot,snapshot);assert.equal(ui.calls[1].body.offset,1);
  assert.equal(ui.d.getElementById('navfinder-record-0'),null);
  assert.match(ui.d.getElementById('navfinder-record-status').textContent,/Could not search records\. This was changed since you opened it/);
  assert.doesNotMatch(ui.d.getElementById('navfinder-record-status').textContent,/snapshot_mismatch|while paging/);
  ui.dom.window.close();
});

test('workspace mismatch and unapproved destinations fail closed with visible feedback',async()=>{
  const ui=await fixture();ui.handler=async()=>({ok:true,json:async()=>result([row('v1')],{context:'c'.repeat(64)})});
  await ui.search('Acme');assert.match(ui.d.getElementById('navfinder-record-status').textContent,/workspace changed/);assert.equal(ui.d.getElementById('navfinder-record-0'),null);
  ui.handler=async()=>({ok:true,json:async()=>result([{...row('v1'),href:'//evil.test/'}])});
  await ui.search('Acme');assert.match(ui.d.getElementById('navfinder-record-status').textContent,/could not be verified/);assert.equal(ui.d.getElementById('navfinder-record-0'),null);
  ui.dom.window.close();
});

test('page-only mode remains local and record type changes reset pagination',async()=>{
  const ui=await fixture();await ui.search('Acme');
  const kind=ui.d.getElementById('navfinder-kind');kind.value='pages';kind.dispatchEvent(new ui.w.Event('change'));await tick();
  assert.equal(ui.calls.length,1);assert.equal(ui.d.getElementById('navfinder-record-0'),null);
  kind.value='task';kind.dispatchEvent(new ui.w.Event('change'));await tick();
  assert.equal(ui.calls[1].body.kind,'task');assert.equal(ui.calls[1].body.offset,0);assert.equal(ui.calls[1].body.snapshot,'');
  ui.dom.window.close();
});

test('review packet search accepts only a bounded exact packet fragment',async()=>{
  const ui=await fixture(),href='/project-reviews#packet=PRP-'+'a'.repeat(32);
  ui.handler=async()=>({ok:true,json:async()=>result([{...row('packet'),kind:'decision',href}])});
  await ui.search('Acme');assert.equal(ui.d.getElementById('navfinder-record-0').getAttribute('href'),href);
  ui.handler=async()=>({ok:true,json:async()=>result([{...row('packet'),kind:'decision',href:href+'&redirect=https://other.test/'}])});
  await ui.search('Acme');assert.equal(ui.d.getElementById('navfinder-record-0'),null);assert.match(ui.d.getElementById('navfinder-record-status').textContent,/could not be verified/);ui.dom.window.close();
});


test('approved-content mode requires current purposes and keeps metadata separate',async()=>{
  const ui=await fixture();
  ui.handler=async(url)=>url.endsWith('/purposes')?{ok:true,json:async()=>({context,items:[{code:'business'}]})}:{ok:true,json:async()=>result([{kind:'knowledge',id:'source',title:'Acme source',revision:'v1',state:'eligible',href:'/knowledge-access#source=%7B%7D'}],{mode:'knowledge',next_cursor:null})};
  ui.input.value='Acme';const kind=ui.d.getElementById('navfinder-kind');kind.value='knowledge';kind.dispatchEvent(new ui.w.Event('change'));await tick();await tick();
  assert.equal(ui.calls[0].url,'/api/v1/knowledge-access/purposes');assert.equal(ui.calls[1].body.mode,'knowledge');assert.equal(ui.calls[1].body.purpose,'business');
  assert.match(ui.d.getElementById('navfinder-record-status').textContent,/approved content/);
  kind.value='all';kind.dispatchEvent(new ui.w.Event('change'));await tick();assert.equal(ui.calls[2].body.mode,'metadata');assert.equal(ui.calls[2].body.purpose,'');ui.dom.window.close();
});


test('history continues through empty windows and resets cursor when dates change',async()=>{
  const ui=await fixture(),kind=ui.d.getElementById('navfinder-kind');
  ui.handler=async()=>({ok:true,json:async()=>result([],{mode:'history',complete:false,next_cursor:'opaque-next',notice:'Continue through remaining windows.',coverage:[{source:'Tasks',state:'partial',href:'/goals'}]})});
  kind.value='history';kind.dispatchEvent(new ui.w.Event('change'));await tick();
  assert.equal(ui.calls[0].body.mode,'history');assert.equal(ui.calls[0].body.source,'tasks');assert.equal(ui.calls[0].body.query,'');
  assert.equal(ui.d.getElementById('navfinder-history').hidden,false);
  assert.equal(ui.d.getElementById('navfinder-more').hidden,false);
  assert.equal(ui.d.querySelector('#navfinder-coverage a').getAttribute('href'),'/goals');
  ui.d.getElementById('navfinder-more').click();await tick();assert.equal(ui.calls[1].body.cursor,'opaque-next');
  const after=ui.d.getElementById('navfinder-after');after.value='2026-01-01';after.dispatchEvent(new ui.w.Event('change'));await tick();
  assert.equal(ui.calls[2].body.cursor,null);assert.equal(ui.calls[2].body.after,'2026-01-01');
  ui.dom.window.close();
});

test('new metadata families accept only their native exact record destinations',async()=>{
  const ui=await fixture();
  const values=[['project','/projects/4'],['workflow','/flows/designer/my-flow'],['workflow','/workflow-builder?edit=template-one'],['automation','/automations#schedule-abc'],['connection','/connections#connection-work'],['fact','/facts?key=shared%3Atag']];
  for(const [kind,href] of values){ui.handler=async()=>({ok:true,json:async()=>result([{...row('x'),kind,href}])});await ui.search('x');assert.equal(ui.d.getElementById('navfinder-record-0').getAttribute('href'),href);}
  ui.handler=async()=>({ok:true,json:async()=>result([{...row('x'),kind:'fact',href:'/facts?key=x&redirect=//evil.test'}])});await ui.search('x');assert.equal(ui.d.getElementById('navfinder-record-0'),null);ui.dom.window.close();
});
