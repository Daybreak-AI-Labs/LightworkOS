"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const repo = path.resolve(__dirname,"../../../..");
const {JSDOM} = require("jsdom");
const {shell} = require('./_shell');
const source = fs.readFileSync(path.join(repo,"packages/maverick-dashboard/maverick_dashboard/static/lightwork-guided-actions.js"),"utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
async function fixture(schema, payload, options={}) {
  const dom = new JSDOM('<select id="test-operation" data-guided-api="/api/x"><option data-path="/items" data-method="POST">Write</option><option data-path="/items" data-method="GET">Read</option></select><label>References<input id="test-path-values" value="{}"></label><label>Body<textarea id="test-body"></textarea></label><button type="button" id="test-submit">Run</button><pre id="test-output">No operation run.</pre>', {url:"https://lightwork.test",runScripts:"outside-only"});
  const w = dom.window, d = w.document, calls = [];
  d.getElementById("test-operation").options[0].dataset.guidedProvidedFields = options.provided || "";
  d.getElementById("test-body").value = JSON.stringify(payload);
  d.getElementById("test-submit").addEventListener("click", () => {
    const method = d.getElementById("test-operation").selectedIndex === 0 ? "POST" : "GET";
    calls.push({method,body:method === "GET" ? undefined : JSON.parse(d.getElementById("test-body").value)});
  });
  w.fetch = async () => {
    if (options.schemaFailure) throw new Error("offline");
    return {ok:true,json:async () => ({paths:{"/api/x/items":{post:{requestBody:{content:{"application/json":{schema}}}}}},components:{schemas:{}}})};
  };
  shell(w);
  w.eval(source); await tick();
  function field(name) { return [...d.querySelectorAll("fieldset")].find(node => node.querySelector(":scope > legend")?.textContent.startsWith(name)); }
  function fire(node,type="input") { node.dispatchEvent(new w.Event(type,{bubbles:true})); }
  return {dom,w,d,calls,field,fire,submit:() => d.getElementById("test-submit").click()};
}

test("editing a sibling preserves an existing empty-string value", async () => {
  const ui = await fixture({type:"object",properties:{empty:{type:"string"},sibling:{type:"string"}},additionalProperties:false},{empty:"",sibling:"before"});
  const input=ui.field("Sibling").querySelector("input:not([type=checkbox])"); input.value="after"; ui.fire(input); ui.submit();
  assert.deepEqual(ui.calls[0]?.body,{empty:"",sibling:"after"}); ui.dom.window.close();
});
test("required nullable field preserves valid explicit null", async () => {
  const ui=await fixture({type:"object",required:["cleared"],properties:{cleared:{anyOf:[{type:"string"},{type:"null"}]}}},{cleared:null});
  ui.submit(); assert.equal(ui.calls.length,1); assert.deepEqual(ui.calls[0].body,{cleared:null}); ui.dom.window.close();
});
test("optional parent toggle does not enable required fields inside an excluded child", async () => {
  const ui=await fixture({type:"object",properties:{parent:{type:"object",properties:{child:{type:"object",required:["value"],properties:{value:{type:"string",minLength:1}}}}}}},{parent:{}});
  const toggle=ui.field("Parent").querySelector("input[type=checkbox]"); toggle.checked=false; ui.fire(toggle,"change"); toggle.checked=true; ui.fire(toggle,"change"); ui.submit();
  assert.equal(ui.calls.length,1); assert.deepEqual(ui.calls[0].body,{parent:{}}); ui.dom.window.close();
});
test("schema failure keeps explicit technical action details usable", async () => {
  const ui=await fixture({}, {name:"existing"},{schemaFailure:true}); ui.submit();
  assert.equal(ui.calls.length,1); assert.deepEqual(ui.calls[0].body,{name:"existing"}); ui.dom.window.close();
});
test("switching from malformed POST details to GET does not retain an irrelevant error", async () => {
  const ui=await fixture({type:"object"},{});
  const raw=ui.d.getElementById("test-body");raw.value="{";ui.fire(raw,"change");
  const select=ui.d.getElementById("test-operation");select.selectedIndex=1;ui.fire(select,"change");ui.submit();
  assert.equal(ui.calls.length,1);assert.equal(ui.calls[0].method,"GET");ui.dom.window.close();
});
test("untouched required empty strings are valid when the schema allows them", async () => {
  const ui=await fixture({type:"object",required:["text"],properties:{text:{type:"string"}}},{text:""});ui.submit();
  assert.equal(ui.calls.length,1);assert.deepEqual(ui.calls[0].body,{text:""});ui.dom.window.close();
});
test("a schema-mismatched existing collection is not replaced with an empty object", async () => {
  const ui=await fixture({type:"object",properties:{value:{type:"object"},sibling:{type:"string"}}},{value:[1,2],sibling:"before"});
  const input=ui.field("Sibling").querySelector("input:not([type=checkbox])");input.value="after";ui.fire(input);ui.submit();
  assert.deepEqual(ui.calls[0]?.body,{value:[1,2],sibling:"after"});ui.dom.window.close();
});

test("a reviewed payload is not rewritten and its confirmation is not reset merely by submitting", async () => {
  const ui=await fixture({type:"object",properties:{enabled:{type:"boolean"}}},{enabled:false});
  const raw=ui.d.getElementById("test-body");raw.value='{ "enabled": false }';
  let confirmed=true;raw.addEventListener("input",()=>{confirmed=false;});
  ui.submit();assert.equal(confirmed,true);assert.equal(raw.value,'{ "enabled": false }');
  assert.deepEqual(ui.calls[0].body,{enabled:false});
  const select=ui.field("Enabled").querySelector("select");select.value="0";ui.fire(select,"change");
  assert.equal(confirmed,false);assert.deepEqual(JSON.parse(raw.value),{enabled:true});ui.dom.window.close();
});

test("a required boolean has no automatic approval and explicit No remains false", async () => {
  const ui=await fixture({type:"object",required:["approved"],properties:{approved:{type:"boolean"}}},{});
  ui.submit();assert.equal(ui.calls.length,0);
  const select=ui.field("Approved").querySelector("select");select.value="1";ui.fire(select,"change");ui.submit();
  assert.equal(ui.calls.length,1);assert.deepEqual(ui.calls[0].body,{approved:false});ui.dom.window.close();
});

test("discriminated object choices use the existing variant and preserve its values", async () => {
  const schema={type:"object",properties:{selection:{oneOf:[
    {type:"object",required:["kind","first"],properties:{kind:{const:"first",type:"string"},first:{type:"string",minLength:1}}},
    {type:"object",required:["kind","second"],properties:{kind:{const:"second",type:"string"},second:{type:"integer"}}},
  ]}}};
  const ui=await fixture(schema,{selection:{kind:"second",second:0}});ui.submit();
  assert.equal(ui.calls.length,1);assert.equal(ui.field("Selection").querySelector('select[aria-label="Choose an option"]').value,"1");
  assert.deepEqual(ui.calls[0].body,{selection:{kind:"second",second:0}});ui.dom.window.close();
});

test("explicit null can be selected in the guided form without substituting omission", async () => {
  const ui=await fixture({type:"object",properties:{note:{anyOf:[{type:"string"},{type:"null"}]}}},{note:"previous"});
  const format=ui.field("Note").querySelector('select[aria-label="Choose an option"]');format.value="1";ui.fire(format,"change");ui.submit();
  assert.deepEqual(ui.calls[0].body,{note:null});ui.dom.window.close();
});

test("readable results escape server text and disclose truncated collections while retaining exact raw output", async () => {
  const ui=await fixture({type:"object"},{});const response={message:'<img src=x onerror="alert(1)">',records:Array.from({length:201},(_,index)=>index)};
  ui.d.getElementById("test-output").textContent=JSON.stringify(response);await tick();
  const visible=ui.d.querySelector(".guided-result");assert.equal(visible.querySelector("img"),null);
  assert.match(visible.textContent,/Showing the first 200 entries/);
  assert.deepEqual(JSON.parse(ui.d.getElementById("test-output").textContent),response);ui.dom.window.close();
});

test("file-derived required fields remain owned by the original upload action", async () => {
  const ui=await fixture({type:"object",required:["asset","content_base64","media_type"],properties:{
    asset:{type:"string",minLength:1},content_base64:{type:"string",minLength:1},media_type:{type:"string",enum:["image/png","image/jpeg"]},
  }},{asset:"logo"},{provided:"content_base64 media_type"});
  assert.equal(ui.field("Content base64").querySelector("input:not([type=checkbox]),select,textarea"),null);
  ui.submit();assert.equal(ui.calls.length,1);assert.deepEqual(ui.calls[0].body,{asset:"logo"});ui.dom.window.close();
});

test("primitive controls use their actual field names as accessible labels", async () => {
  const ui=await fixture({type:"object",properties:{vendor_name:{type:"string"},expected_revision:{type:"integer"},approved:{type:"boolean"}}},{vendor_name:"Acme",expected_revision:2,approved:false});
  for (const [name,label] of [["Vendor name","Vendor name"],["Current version","Current version"],["Approved","Approved"]]) {
    const input=ui.field(name).querySelector("input:not([type=checkbox]),select");assert.equal(input.labels[0].textContent,label);
  }
  ui.dom.window.close();
});

test("a request reference is filled in and hidden, and a supplied one is kept exactly for retries", async () => {
  // Supplied with the request: kept byte-for-byte, even when other details change.
  let ui=await fixture({type:"object",properties:{idempotency_key:{type:"string",minLength:8,maxLength:128},operation_id:{type:"string"}}},{idempotency_key:"existing-reference",operation_id:"keep-operation"});
  assert.equal(ui.field("Request reference").hidden,true);
  assert.equal([...ui.d.querySelectorAll("button")].some(node=>node.textContent==="Generate reference"),false);
  const op=ui.field("Operation").querySelector("input:not([type=checkbox])");op.value="changed";ui.fire(op);
  ui.submit();ui.submit();
  assert.equal(ui.calls[0].body.idempotency_key,"existing-reference");assert.equal(ui.calls[1].body.idempotency_key,"existing-reference");
  ui.dom.window.close();
  // Not supplied: a secure reference is made, kept for retries, renewed when the request changes.
  ui=await fixture({type:"object",properties:{idempotency_key:{type:"string",minLength:8,maxLength:128},operation_id:{type:"string"}}},{operation_id:"first"});
  ui.submit();ui.submit();
  const generated=ui.calls[0].body.idempotency_key;
  assert.match(generated,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  assert.equal(ui.calls[1].body.idempotency_key,generated);
  const again=ui.field("Operation").querySelector("input:not([type=checkbox])");again.value="second";ui.fire(again);ui.submit();
  assert.notEqual(ui.calls[2].body.idempotency_key,generated);assert.equal(ui.calls[2].body.operation_id,"second");
  ui.dom.window.close();
});

test("reference generation is not offered for formats that cannot accept a UUID", async () => {
  for (const schema of [{type:"string",maxLength:16},{type:"string",pattern:"^fixed$"},{type:"integer"},{type:"string",format:"email"},{type:"string",enum:["existing-reference"]}]) {
    const ui=await fixture({type:"object",properties:{idempotency_key:schema}},{idempotency_key:"existing-reference"});
    assert.equal(ui.field("Request reference").hidden,false);ui.submit();
    assert.equal(ui.calls[0].body.idempotency_key,"existing-reference");ui.dom.window.close();
  }
});

test("an incompatible generated reference leaves the field for the person to fill", async () => {
  const ui=await fixture({type:"object",properties:{idempotency_key:{type:"string",pattern:"^ref-[0-9]+$"}}},{});
  assert.equal(ui.field("Request reference").hidden,false);ui.submit();
  assert.equal(ui.calls[0].body.idempotency_key,undefined);ui.dom.window.close();
});

test("closed-schema Add detail controls appear only after an optional field is removed", async () => {
  const ui=await fixture({type:"object",properties:{notes:{type:"string"}},additionalProperties:false},{notes:"Keep me"});
  const controls=ui.d.querySelector(".guided-known-add");assert.equal(controls.hidden,true);
  [...ui.field("Notes").querySelectorAll("button")].find(node=>node.textContent==="Remove notes").click();
  assert.equal(controls.hidden,false);const select=controls.querySelector("select");select.value="notes";
  controls.querySelector("button").click();assert.ok(ui.field("Notes"));assert.equal(controls.hidden,true);ui.dom.window.close();
});

async function standaloneFixture(schema, value, options={}) {
  const dom=new JSDOM('<form id="one"><label class="wide">Original JSON<textarea name="settings" data-guided-endpoint="/api/items" data-guided-property="settings" data-guided-title="Settings"></textarea></label><button>Save</button></form><form id="two"><textarea name="settings" data-guided-endpoint="/api/items" data-guided-property="settings" data-guided-title="Other settings">{"untouched":true}</textarea></form>',{url:"https://lightwork.test",runScripts:"outside-only"});
  const w=dom.window,d=w.document,form=d.getElementById("one"),raw=form.elements.settings,calls=[];
  raw.defaultValue=value;raw.required=!!options.required;
  w.fetch=async()=>({ok:true,json:async()=>({paths:{"/api/items":{post:{requestBody:{content:{"application/json":{schema:{$ref:"#/components/schemas/Request"}}}}}}},components:{schemas:{Request:{type:"object",properties:{settings:schema}}}}})});
  form.addEventListener("submit",event=>{event.preventDefault();calls.push(raw.value);});
  shell(w);
  w.eval(source);await tick();
  const fire=(node,type="input")=>node.dispatchEvent(new w.Event(type,{bubbles:true}));
  const field=key=>form.querySelector('[data-guided-field="'+key+'"]');
  const submit=()=>form.dispatchEvent(new w.Event("submit",{bubbles:true,cancelable:true}));
  return {dom,w,d,form,raw,calls,fire,field,submit};
}

test("standalone scan limits expose all eight numeric fields and preserve each form's original payload",async()=>{
  const limits={max_records:10000,max_files:1000,max_bytes:67108864,max_seconds:300,max_findings:10000,max_fields_per_record:256,max_record_bytes:262144,max_document_bytes:4194304};
  const properties=Object.fromEntries(Object.keys(limits).map(key=>[key,{type:key==="max_seconds"?"number":"integer",minimum:key==="max_seconds"?0.1:1,maximum:1000000000}]));
  const ui=await standaloneFixture({type:"object",properties,additionalProperties:false},JSON.stringify(limits),{required:true});
  assert.equal(ui.form.querySelectorAll('input[type="number"]').length,8);
  assert.equal(ui.raw.closest("details").open,false);assert.equal(ui.form.querySelector(".guided-standalone").classList.contains("wide"),true);
  const seconds=ui.field("max_seconds").querySelector('input[type="number"]');assert.equal(seconds.step,"any");assert.equal(seconds.min,"0.1");
  seconds.value="0.5";ui.fire(seconds);ui.submit();assert.deepEqual(JSON.parse(ui.calls[0]),{...limits,max_seconds:0.5});
  assert.equal(ui.d.getElementById("two").elements.settings.value,'{"untouched":true}');
  seconds.value="0.01";ui.fire(seconds);ui.submit();assert.equal(ui.calls.length,1);ui.dom.window.close();
});

test("standalone raw edits and form reset rehydrate fields without rewriting an exact submission",async()=>{
  const ui=await standaloneFixture({type:"object",properties:{count:{type:"integer",minimum:1}},additionalProperties:false},'{ "count": 2 }',{required:true});
  ui.submit();assert.equal(ui.calls[0],'{ "count": 2 }');
  ui.raw.value='{ "count": 7 }';ui.fire(ui.raw,"change");ui.submit();assert.equal(ui.calls[1],'{ "count": 7 }');
  assert.equal(ui.field("count").querySelector('input[type="number"]').value,"7");
  ui.raw.value="{";ui.fire(ui.raw,"change");ui.submit();assert.equal(ui.calls.length,2);assert.match(ui.form.querySelector('[role="alert"]').textContent,/valid JSON/);
  ui.form.reset();await new Promise(resolve=>ui.w.setTimeout(resolve,1));
  assert.equal(ui.field("count").querySelector('input[type="number"]').value,"2");assert.equal(ui.raw.value,'{ "count": 2 }');ui.dom.window.close();
});

test("optional blank audience stays blank until a guided audience is explicitly added",async()=>{
  const ui=await standaloneFixture({anyOf:[{type:"object",properties:{country_codes:{type:"array",items:{type:"string"}}},additionalProperties:false},{type:"null"}]},"");
  ui.submit();assert.equal(ui.calls[0],"");
  const group=ui.field("country_codes"),include=group.querySelector('input[type="checkbox"]');include.checked=true;ui.fire(include,"change");
  [...group.querySelectorAll("button")].find(node=>node.textContent==="Add item").click();
  const country=group.querySelector('input:not([type="checkbox"])');country.value="US";ui.fire(country);ui.submit();
  assert.deepEqual(JSON.parse(ui.calls[1]),{country_codes:["US"]});ui.dom.window.close();
});

test("standalone variant edits preserve review evidence and explicit false values",async()=>{
  const evidence="a".repeat(64),variant={variant_id:"control",allocation_bps:5000,content_ref:"bundle:control",content_sha256:evidence,accessibility_evidence_sha256:evidence,equal_choice_evidence_sha256:evidence,is_control:true,is_holdout:false};
  const properties=Object.fromEntries(Object.entries(variant).map(([key,value])=>[key,{type:typeof value==="number"?"integer":typeof value}]));
  const ui=await standaloneFixture({type:"array",items:{type:"object",properties,required:Object.keys(variant),additionalProperties:false}},JSON.stringify([variant]),{required:true});
  const allocation=ui.field("allocation_bps").querySelector('input[type="number"]');allocation.value="4000";ui.fire(allocation);ui.submit();
  assert.deepEqual(JSON.parse(ui.calls[0]),[{...variant,allocation_bps:4000}]);ui.dom.window.close();
});

async function publishingFixture(schemas,options={}) {
  const html=fs.readFileSync(path.join(__dirname,"fixtures/guided_publishing_form.html"),"utf8");
  const dom=new JSDOM(html,{url:"https://lightwork.test",runScripts:"outside-only"}),w=dom.window,d=w.document,calls=[];
  d.querySelector(".feature-gated-workbench").disabled=false;
  const form=d.getElementById("cpp-resource"),kind=form.elements.kind,raw=form.elements.payload;
  const paths=Object.fromEntries([...kind.options].map(option=>[option.dataset.guidedEndpoint,{post:{requestBody:{content:{"application/json":{schema:schemas[option.value]||{type:"object",properties:{version:{type:"integer"},expected_current_version:{type:"integer"},idempotency_key:{type:"string"},[option.value]:{type:"string"}},additionalProperties:false}}}}}}]));
  let release;
  const loaded=new Promise(resolve=>{release=resolve;});
  w.fetch=async(url,request)=>{if(url==="/openapi.json"){if(options.delayed)await loaded;return {ok:true,json:async()=>({paths,components:{schemas:{}}})};}calls.push({url,request});return {ok:!options.reject,json:async()=>options.reject?{detail:"The referenced notice version does not exist."}:{saved:true}};};
  shell(w);
  const script=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)[1];w.eval(script);w.eval(source);await tick();
  const fire=(node,type="input")=>node.dispatchEvent(new w.Event(type,{bubbles:true}));
  const choose=value=>{kind.value=value;fire(kind,"change");};
  const field=key=>form.querySelector('[data-guided-field="'+key+'"]');
  const set=(key,value)=>{const input=field(key).querySelector("input:not([type=checkbox]),select,textarea");input.value=value;fire(input,input.tagName==="SELECT"?"change":"input");};
  return {dom,w,d,form,kind,raw,calls,fire,choose,field,set,release,submit:()=>form.dispatchEvent(new w.Event("submit",{bubbles:true,cancelable:true}))};
}

const publishingVersionProperties={version:{type:"integer",minimum:1},expected_current_version:{type:"integer",minimum:0},idempotency_key:{type:"string",pattern:"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"}};

test("all eight publishing choices load their own guided contract without carrying another type's fields",async()=>{
  const ui=await publishingFixture({});
  for(const option of [...ui.kind.options]){ui.choose(option.value);assert.ok(ui.field(option.value));assert.equal(ui.form.querySelectorAll("[data-guided-field]").length,4);}
  assert.equal(ui.kind.options.length,8);assert.equal(ui.raw.closest("details").open,false);ui.dom.window.close();
});

test("guided purpose and translation drafts submit through the original controller and keep separate retry references",async()=>{
  const purpose={type:"object",required:[...Object.keys(publishingVersionProperties),"title_key","required","default_choice"],properties:{...publishingVersionProperties,title_key:{type:"string"},required:{type:"boolean"},default_choice:{type:"string",enum:["denied","granted","unset"]}},additionalProperties:false};
  const translation={type:"object",required:[...Object.keys(publishingVersionProperties),"messages"],properties:{...publishingVersionProperties,messages:{type:"object",additionalProperties:{type:"string"}}},additionalProperties:false};
  const ui=await publishingFixture({purposes:purpose,translations:translation});ui.form.elements.resource_id.value="consumer-main";
  ui.set("idempotency_key","purpose-retry");ui.set("title_key","purpose.title");ui.set("required","1");ui.set("default_choice","0");ui.submit();await tick();
  assert.equal(ui.calls[0].url,"/api/v1/consent/publishing/purposes/consumer-main/versions");
  const saved={version:1,expected_current_version:0,idempotency_key:"purpose-retry",title_key:"purpose.title",required:false,default_choice:"denied"};
  assert.deepEqual(JSON.parse(ui.calls[0].request.body),saved);
  ui.choose("translations");assert.equal(ui.form.elements.locale.required,true);assert.equal(ui.d.getElementById("cpp-resource-locale").hidden,false);
  assert.notEqual(JSON.parse(ui.raw.value).idempotency_key,"purpose-retry");ui.form.elements.locale.value="en-US";ui.set("idempotency_key","translation-retry");
  const messages=ui.field("messages"),add=messages.querySelector(".guided-add");add.querySelector('input[aria-label="New detail name"]').value="purpose.title";
  [...add.querySelectorAll("button")].find(node=>node.textContent==="Add named detail").click();
  ui.set("purpose.title","Your privacy choices");ui.submit();await tick();
  assert.equal(ui.calls[1].url,"/api/v1/consent/publishing/translations/consumer-main/en-US/versions");
  assert.deepEqual(JSON.parse(ui.calls[1].request.body),{version:1,expected_current_version:0,idempotency_key:"translation-retry",messages:{"purpose.title":"Your privacy choices"}});
  ui.choose("purposes");assert.deepEqual(JSON.parse(ui.raw.value),saved);assert.equal(ui.form.elements.locale.required,false);assert.equal(ui.form.elements.locale.disabled,true);
  ui.submit();await tick();assert.deepEqual(JSON.parse(ui.calls[2].request.body),saved);ui.dom.window.close();
});

test("schema arrival after a publishing kind change uses the current kind and reset clears saved drafts",async()=>{
  const ui=await publishingFixture({},{delayed:true});ui.choose("themes");ui.release();await tick();assert.ok(ui.field("themes"));assert.equal(ui.field("purposes"),null);
  ui.set("idempotency_key","theme-draft");ui.choose("translations");ui.form.reset();await new Promise(resolve=>ui.w.setTimeout(resolve,1));
  assert.equal(ui.kind.value,"purposes");assert.ok(ui.field("purposes"));assert.equal(ui.form.elements.locale.required,false);
  ui.choose("themes");assert.notEqual(JSON.parse(ui.raw.value).idempotency_key,"theme-draft");ui.dom.window.close();
});

test("template action maps offer only supported named actions and preserve the selected text reference",async()=>{
  const actions={type:"object",propertyNames:{enum:["accept_all","reject_all","manage_preferences"]},additionalProperties:{type:"string"}};
  const ui=await fixture({type:"object",required:["actions"],properties:{actions},additionalProperties:false},{actions:{}});
  const group=ui.field("Actions");assert.equal(group.querySelector(".guided-add"),null);
  const action=ui.field("Reject all"),include=action.querySelector('input[type="checkbox"]');include.checked=true;ui.fire(include,"change");
  const text=action.querySelector('input:not([type="checkbox"])');text.value="actions.reject";ui.fire(text);ui.submit();
  assert.deepEqual(ui.calls[0].body,{actions:{reject_all:"actions.reject"}});ui.dom.window.close();
});

test("rule groups expose nested typed resource references and preserve server validation failures",async()=>{
  const reference={type:"object",required:["id","version"],properties:{id:{type:"string"},version:{type:"integer",minimum:1}},additionalProperties:false};
  const rules={type:"array",items:{type:"object",required:["notice"],properties:{notice:reference},additionalProperties:false}};
  const schema={type:"object",required:[...Object.keys(publishingVersionProperties),"rules"],properties:{...publishingVersionProperties,rules},additionalProperties:false};
  const ui=await publishingFixture({"rule-groups":schema},{reject:true});ui.choose("rule-groups");ui.form.elements.resource_id.value="production";ui.set("idempotency_key","rule-retry");
  [...ui.field("rules").querySelectorAll("button")].find(node=>node.textContent==="Add item").click();ui.set("id","notice-main");
  const version=ui.field("notice").querySelector('[data-guided-field="version"] input[type="number"]');version.value="3";ui.fire(version);ui.submit();await tick();
  assert.deepEqual(JSON.parse(ui.calls[0].request.body),{version:1,expected_current_version:0,idempotency_key:"rule-retry",rules:[{notice:{id:"notice-main",version:3}}]});
  assert.match(ui.d.getElementById("cpp-status").textContent,/referenced notice version does not exist/);assert.equal(ui.d.getElementById("cpp-result").textContent,"No operation run.");ui.dom.window.close();
});

test('structured publishing errors identify and focus the invalid field without rebuilding the request',async()=>{
  const ui=await publishingFixture({themes:{type:'object',properties:{...publishingVersionProperties,primary_color:{type:'string',pattern:'^[0-9a-fA-F]{6}$'},text_color:{type:'string'}},required:['primary_color'],additionalProperties:false}});
  ui.choose('themes');ui.raw.value=JSON.stringify({version:1,expected_current_version:0,idempotency_key:'same-request',primary_color:'#oops',text_color:'ffffff'});ui.fire(ui.raw,'change');
  ui.w.fetch=async()=>({ok:false,status:422,json:async()=>({detail:[{loc:['body','primary_color'],msg:"String should match pattern '^[0-9a-fA-F]{6}$'",input:'#oops'}]})});
  const before=ui.raw.value;ui.submit();await tick();
  const color=ui.field('primary_color').querySelector('input');
  assert.equal(ui.d.activeElement,color);assert.equal(color.getAttribute('aria-invalid'),'true');assert.match(ui.form.textContent,/six hexadecimal characters/);assert.equal(ui.raw.value,before);
  color.value='112233';ui.fire(color);assert.equal(color.hasAttribute('aria-invalid'),false);assert.equal(JSON.parse(ui.raw.value).idempotency_key,'same-request');assert.equal(JSON.parse(ui.raw.value).text_color,'ffffff');ui.dom.window.close();
});

test('nested validation follows array indices after an item is removed',async()=>{
  const schema={type:'array',items:{type:'object',properties:{color:{type:'string'}},required:['color'],additionalProperties:false}};
  const ui=await standaloneFixture(schema,'[{"color":"first"},{"color":"second"}]',{required:true});
  [...ui.form.querySelectorAll('button')].find(button=>button.textContent==='Remove item').click();
  ui.w.mvValidation.show(ui.form,[{loc:['body',0,'color'],msg:'This color is unavailable.'}]);
  assert.equal(ui.d.activeElement.value,'second');assert.equal(ui.d.activeElement.getAttribute('aria-invalid'),'true');assert.deepEqual(JSON.parse(ui.raw.value),[{color:'second'}]);ui.dom.window.close();
});
