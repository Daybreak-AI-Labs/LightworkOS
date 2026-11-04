"use strict";
const {test} = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-personal-data.js"), "utf8");
function fixture(inventory) {
  class Node {
    constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.style = {}; this.textContent = ""; }
    appendChild(node) { this.children.push(node); return node; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = nodes; }
    addEventListener(name, fn) { this.events[name] = fn; }
  }
  const nodes = {}, el = id => nodes[id] || (nodes[id] = new Node("div"));
  el("pd-bootstrap").textContent = JSON.stringify({context:"c",identity:{channels:[],links:[],challenges:[]},scopes:[],sharing:{},policy:{},can_review_deletion:false});
  vm.runInNewContext(source, {document:{getElementById:el,createElement:tag=>new Node(tag),createTextNode:text=>Object.assign(new Node("text"),{textContent:text})}, Option: function(label,value){this.textContent=label;this.value=value;},
    // The shell's mvFetchJSON and mvStatus, reduced to the success path and the
    // text write for this DOM-less fixture.
    window:{confirm:()=>true, mvFetchJSON:async()=>inventory, mvStatus:(node,text)=>{node.textContent=text==null?"":String(text);}}, fetch:async()=>({ok:true,json:async()=>inventory}), Date, console});
  return {el, async click(id) { el(id).events.click(); await new Promise(resolve=>setImmediate(resolve)); }};
}
function content(node) { return node.textContent + node.children.map(content).join(" "); }
test("store inventory distinguishes draft counts from owned learning provenance", async()=>{
  const ui=fixture({holds:{blocked:false},limits:"Specific stores only",tasks:[],stores:[
    {name:"Recovery",state:"available",inventory:{saved:2,discarded:1}},
    {name:"Learning",state:"current-authorized-only",inventory:{tools:[{name:"owned_tool",goal_id:9}],learning_records:[{kind:"tool",goal_id:9,date:1}],learning_records_truncated:true}},
    {name:"Queued",state:"available",count:3,blocked:1}]});
  await ui.click("pd-inventory"); const rendered=content(ui.el("pd-stores"));
  assert.match(rendered,/2 saved private drafts/);assert.match(rendered,/owned_tool; source task 9/);
  assert.match(rendered,/Retained owned tool learning record/);assert.match(rendered,/Showing 500 current authorized/);
  assert.match(rendered,/1 records require reconciliation/);assert.doesNotMatch(rendered,/undefined/);
});
test("new stores have explicit independently reviewed deletion choices",()=>{
  const ui=fixture({}); const rendered=content(ui.el("pd-delete-stores"));
  assert.match(rendered,/model-test history/);assert.match(rendered,/current authorized generated tools/);assert.match(rendered,/queued messages, ended human exchanges and on-duty name/);
  assert.match(rendered,/saved dashboard views and task pins/);assert.match(rendered,/keeps tasks, annotations and gallery/);
});

test("owned navigation inventory names counts and retained shared records without reading filters",async()=>{
  const ui=fixture({holds:{blocked:false},limits:"Exact account store only",tasks:[],stores:[{
    name:"Saved views and task pins",state:"available",count:3,
    inventory:{view_count:2,pin_count:1,retained:"Annotations and gallery are retained separately."}}]});
  await ui.click("pd-inventory");const rendered=content(ui.el("pd-stores"));
  assert.match(rendered,/2 saved dashboard views; 1 pinned task references/);
  assert.match(rendered,/Annotations and gallery are retained/);assert.doesNotMatch(rendered,/undefined/);
});
test("owned local copies show expiry limits and safe native links without treating expiry as erasure",async()=>{
  const ui=fixture({holds:{blocked:false},limits:"Specific stores only",tasks:[],stores:[{
    name:"Owned bundles",state:"current-authorized-only",visible_count:1,partial:true,coverage:"Only readable owned records are counted.",
    items:[{name:"<img onerror=bad()>",state:"revoked",owner_label:"You",recipient:"Person",source:"Your original task",access_expires_at:100,
      expiry:"Access expiry is not deletion.",dependencies:"The original remains separate.",action:"Review saved copy",href:"/deliverable-bundles?open=DLB-one",source_href:"/chat/goal/4"}]}]});
  await ui.click("pd-inventory");const rendered=content(ui.el("pd-stores"));
  assert.match(rendered,/Access expiry is not deletion/);assert.match(rendered,/first 100/);assert.match(rendered,/1 owned records shown/);
  assert.match(rendered,/<img onerror=bad\(\)>/);
  const all=node=>[node,...node.children.flatMap(all)],nodes=all(ui.el("pd-stores"));
  assert.equal(nodes.some(node=>node.tagName==='img'),false);
  assert.ok(nodes.some(node=>node.href==='/deliverable-bundles?open=DLB-one'));
  assert.ok(nodes.some(node=>node.href==='/chat/goal/4'));
});

test("asking to review a deletion with no verified conversation says so in plain words", async () => {
  const ui = fixture({});
  ui.el("pd-delete").events.submit({preventDefault() {}});
  await new Promise(resolve => setImmediate(resolve));
  const shown = ui.el("pd-status").textContent;
  assert.match(shown, /no verified conversation/i);
  assert.doesNotMatch(shown, /Cannot read properties|undefined/);
});
