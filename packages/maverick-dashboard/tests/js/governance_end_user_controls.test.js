"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');
const editor = require("../../maverick_dashboard/static/lightwork-consent-policy-editor.js");

test("an unavailable consent editor visibly blocks policy publication while other consent tools remain usable", async () => {
  const html=fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/templates/consent_preferences.html"),"utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
  const helper=fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/static/lightwork-consent-workbench.js"),"utf8");
  const script=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)[1];
  const dom=new JSDOM(html,{url:"https://lightwork.test",runScripts:"outside-only"});
  const w=dom.window,d=w.document,calls=[];
  Object.defineProperty(w,"crypto",{value:require("node:crypto").webcrypto});
  w.TextEncoder=TextEncoder;
  w.fetch=async(url,options)=>{calls.push({url,options});return {ok:true,json:async()=>({profiles:[],policies:[],trackers:[]})};};
  shell(w);
  w.eval(helper);
  assert.doesNotThrow(()=>w.eval(script));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(d.getElementById("cp-policy-controls").disabled,true);
  assert.equal(d.getElementById("cp-policy-new").disabled,true);
  assert.match(d.getElementById("cp-purpose-error").textContent,/editor could not load/);
  d.getElementById("cp-policy-form").dispatchEvent(new w.Event("submit",{bubbles:true,cancelable:true}));
  assert.equal(calls.some(call=>call.url.endsWith("/policies")),false);
  const profile=d.getElementById("cp-profile-form");
  profile.elements.subject.value="Person@Example.com";
  profile.dispatchEvent(new w.Event("submit",{bubbles:true,cancelable:true}));
  for(let i=0;i<20;i++)await new Promise(resolve=>setTimeout(resolve,5));
  const created=calls.find(call=>call.url.endsWith("/profiles")&&call.options&&call.options.method==="POST");
  assert.ok(created);
  const body=JSON.parse(created.options.body);
  // Only a fingerprint of the normalized identifier leaves the browser.
  assert.equal(body.subject_sha256,require("node:crypto").createHash("sha256").update("person@example.com").digest("hex"));
  assert.equal(JSON.stringify(body).includes("example.com"),false);
  assert.equal(body.identity_kind,"known");
  dom.window.close();
});

class Node {
  constructor(tag = "div") {
    this.tag = tag; this.children = []; this.listeners = {}; this.dataset = {};
    this.value = ""; this.textContent = ""; this.disabled = false; this.style = {};
  }
  appendChild(node) { this.children.push(node); node.parent = this; return node; }
  replaceChildren(...nodes) { this.children = nodes; }
  remove() { this.parent.children = this.parent.children.filter(node => node !== this); }
  focus() { this.focused = true; }
  addEventListener(event, listener) { this.listeners[event] = listener; }
  fire(event) { return this.listeners[event](); }
}
function purposeUI() {
  const nodes = Object.fromEntries([
    "cp-purpose-rows", "cp-purpose-add", "cp-purpose-error", "cp-purpose-advanced", "cp-purpose-apply",
  ].map(id => [id, new Node()]));
  const raw = new Node("textarea"); raw.value = '{"analytics":"consent","essential":"contract"}';
  const form = { elements: { purposes: raw } };
  const mounted = editor.mount(form, { getElementById: id => nodes[id], createElement: tag => new Node(tag) });
  return { nodes, raw, read: mounted.read, rows: () => nodes["cp-purpose-rows"].children };
}

test("purpose rows preserve the policy object contract through edits, add and remove", () => {
  const ui = purposeUI();
  ui.rows()[0].children[0].children[0].value = "marketing";
  ui.rows()[0].children[1].children[0].value = "legitimate_interests";
  ui.rows()[0].children[0].children[0].fire("input");
  assert.deepEqual(JSON.parse(ui.raw.value), { marketing: "legitimate_interests", essential: "contract" });
  ui.nodes["cp-purpose-add"].fire("click");
  const added = ui.rows()[2].children[0].children[0]; added.value = "research"; added.fire("input");
  assert.equal(added.focused, true);
  assert.equal(ui.read().research, "consent");
  ui.rows()[1].children[2].fire("click");
  assert.deepEqual(JSON.parse(JSON.stringify(ui.read())), { marketing: "legitimate_interests", research: "consent" });
});

test("duplicate purposes fail before publishing without overwriting the last valid JSON", () => {
  const ui = purposeUI(); const original = ui.raw.value;
  const input = ui.rows()[1].children[0].children[0]; input.value = "analytics"; input.fire("input");
  assert.throws(ui.read, /appears more than once/);
  assert.match(ui.nodes["cp-purpose-error"].textContent, /unique/);
  assert.equal(ui.raw.value, original);
});

test("optional JSON edits replace guided fields and malformed drafts remain visible for correction", () => {
  const ui = purposeUI();
  ui.raw.value = '{"service":"legal_obligation"}'; ui.raw.fire("input");
  assert.equal(ui.read().service, "legal_obligation");
  assert.equal(ui.rows().length, 1);
  assert.equal(ui.rows()[0].children[0].children[0].value, "service");
  ui.raw.value = "{ incomplete"; ui.raw.fire("input");
  assert.throws(ui.read, /valid JSON/);
  assert.equal(ui.nodes["cp-purpose-advanced"].open, true);
  assert.equal(ui.raw.focused, true);
  assert.equal(ui.raw.value, "{ incomplete");
  ui.raw.value = '{"research":"public_task"}'; ui.raw.fire("input");
  ui.nodes["cp-purpose-apply"].fire("click");
  assert.equal(ui.read().research, "public_task");
});

test("purpose editor rejects invalid shapes, unsupported legal bases, empty and overlarge policies", () => {
  for (const value of ["[]", "null", "{}", '{"a":"not_a_basis"}', '{"__proto__":"consent"}', '{"a":{}}']) {
    assert.throws(() => editor.parsePurposes(value), Error, value);
  }
  assert.throws(() => editor.purposeMap(Array.from({length:129}, (_, i) => ({id:`p${i}`,basis:"consent"}))), /128/);
  assert.equal(editor.parsePurposes('{"toString":"consent"}').toString, "consent");
});

const tick = () => new Promise(resolve => setImmediate(resolve));
function playbookUI(responses) {
  const names = ["pw-playbook", "pw-playbook-save", "pw-playbook-retry", "pw-playbook-err", "pw-playbook-path", "pw-playbook-rows"];
  const nodes = Object.fromEntries(names.map(id => [id, new Node()]));
  nodes["pw-playbook"].open = true; nodes["pw-playbook-save"].disabled = true;
  const requests = [];
  const textareas = () => nodes["pw-playbook-rows"].children.flatMap(row => row.children.filter(node => node.tag === "textarea"));
  const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/privacy.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
  const script = source.split("  // The clause playbook editor:")[1].split("  // AI registry:")[0];
  vm.runInNewContext(script.slice(script.indexOf("  var playbook")), {
    document: { getElementById: id => nodes[id], createElement: tag => new Node(tag), querySelectorAll: textareas },
    fetch: async (url, options) => {
      requests.push({url, options});
      const response = responses.shift();
      if (response instanceof Error) throw response;
      if (typeof response === "function") return response();
      return response;
    },
  });
  return {nodes, requests, textareas};
}
const okPlaybook = () => ({ok:true, json:async () => ({positions:{data_use:"Approved clause"},customised:[],path:"/private/storage/playbook.toml"})});

for (const response of [
  {ok:false,status:503},
  {ok:true,json:async () => ({positions:{},customised:[]})},
  {ok:true,json:async () => ({positions:{a:42},customised:[]})},
]) {
  test("a failed or incomplete clause-playbook load cannot save an empty replacement and can retry", async () => {
    const ui = playbookUI([response, okPlaybook()]);
    ui.nodes["pw-playbook"].fire("toggle"); await tick();
    assert.equal(ui.nodes["pw-playbook-save"].disabled, true);
    assert.equal(ui.nodes["pw-playbook-retry"].hidden, false);
    ui.nodes["pw-playbook-save"].fire("click"); assert.equal(ui.requests.length, 1);
    ui.nodes["pw-playbook-retry"].fire("click"); await tick();
    assert.equal(ui.nodes["pw-playbook-save"].disabled, false);
    assert.equal(ui.textareas()[0].value, "Approved clause");
    assert.doesNotMatch(ui.nodes["pw-playbook-path"].textContent, /private|storage|toml/);
  });
}

test("clause save holds concurrent edits, prevents double-submit and retains edits after failure", async () => {
  let finish;
  const pending = new Promise(resolve => { finish = resolve; });
  const ui = playbookUI([okPlaybook(), () => pending]);
  ui.nodes["pw-playbook"].fire("toggle"); await tick();
  const field = ui.textareas()[0]; field.value = "Reviewed custom clause";
  ui.nodes["pw-playbook-save"].fire("click");
  ui.nodes["pw-playbook-save"].fire("click");
  assert.equal(ui.requests.length, 2); assert.equal(field.disabled, true);
  assert.deepEqual(JSON.parse(ui.requests[1].options.body), {positions:{data_use:"Reviewed custom clause"}});
  finish({ok:false,status:403,text:async () => "Administrator permission required"}); await tick();
  assert.equal(field.value, "Reviewed custom clause"); assert.equal(field.disabled, false);
  assert.equal(ui.nodes["pw-playbook-save"].disabled, false);
  assert.match(ui.nodes["pw-playbook-path"].textContent, /Your edits are still here/);
  assert.match(ui.nodes["pw-playbook-err"].textContent, /permission/);
  assert.doesNotMatch(ui.nodes["pw-playbook-err"].textContent, /403|HTTP/);
});

function governanceUI({get, post}) {
  const nodes = Object.fromEntries([
    "gov-refresh-attention", "gov-attention-status", "gov-attention-summary",
    "gov-grc-run", "gov-grc-status", "gov-grc-problems", "gov-grc-output",
  ].map(id => [id, new Node()]));
  const button = new Node("button");
  const form = nodes["gov-grc-run"];
  form.elements = {limit:{value:"5"},confirm_dispatch:{checked:true}};
  form.querySelector = () => button; form.reportValidity = () => true;
  const template = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/governance.html"), "utf8").replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
  const start = template.indexOf("  const refreshAttention =");
  const script = template.slice(start, template.indexOf("  const download =", start));
  vm.runInNewContext(script, {
    document:{getElementById:id => nodes[id],createElement:tag => new Node(tag)},
    get, post, prefix:"/api/v1/security/governance", status:(id,text) => {nodes[id].textContent = text;},
  });
  return {nodes,form,button,submit:() => form.listeners.submit({preventDefault(){}})};
}

test("GRC sync submits confirmed bounded input once and keeps failed/unconfirmed outcomes visible", async () => {
  let finish; const requests = [];
  const response = new Promise(resolve => {finish = resolve;});
  const ui = governanceUI({post:async (base,path,body) => {requests.push({base,path,body});return response;}});
  const first = ui.submit(); await ui.submit();
  assert.equal(requests.length, 1); assert.equal(ui.button.disabled, true);
  assert.deepEqual(JSON.parse(JSON.stringify(requests[0])), {
    base:"/api/v1/security/governance",path:"/grc-sync/run",body:{limit:5,confirm_dispatch:true},
  });
  finish({delivered_count:2,delivered:[{status:"delivered"},{status:"delivered_unconfirmed"}],
    unchanged_count:3,blocked_count:1,failure_count:1,
    blocked:[{source_id:"incident-a",reason:"Remote ID unconfirmed"}],
    failures:[{source_id:"finding-b",reason:"Provider unavailable"}]});
  await first;
  assert.match(ui.nodes["gov-grc-status"].textContent, /1 confirmed, 1 awaiting delivery confirmation/);
  assert.match(ui.nodes["gov-grc-status"].textContent, /1 held for review, 1 failed/);
  assert.equal(ui.nodes["gov-grc-problems"].children[1].textContent, "finding-b: Provider unavailable");
  assert.equal(ui.form.elements.confirm_dispatch.checked, false);
  assert.equal(ui.button.disabled, false);
});

test("failed GRC request restores controls and does not claim completion", async () => {
  const ui = governanceUI({post:async () => {throw new Error("Administrator permission required");}});
  await ui.submit();
  assert.equal(ui.button.disabled, false);
  assert.equal(ui.nodes["gov-grc-status"].textContent, "Administrator permission required");
  assert.equal(ui.nodes["gov-grc-output"].textContent, "");
});

test("alert refresh stays on the page and distinguishes unavailable sections from no findings", async () => {
  const requests = [];
  const ui = governanceUI({get:async (base,path) => {
    requests.push({base,path});
    return {attention_count:0,sections:{vendors:{enabled:false,error:"unavailable"}}};
  }});
  ui.form.elements.limit.value = "17";
  await ui.nodes["gov-refresh-attention"].fire("click");
  assert.equal(requests[0].path, "/alerts");
  assert.equal(ui.nodes["gov-attention-status"].textContent, "Alerts refreshed.");
  assert.equal(ui.form.elements.limit.value, "17");
  assert.match(ui.nodes["gov-attention-summary"].children[1].textContent, /Suppliers alerts could not be loaded/);
});
