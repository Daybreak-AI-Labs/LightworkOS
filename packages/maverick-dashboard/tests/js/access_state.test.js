"use strict";
const {test} = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const window = {};
vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-access-state.js"), "utf8"), {window});
const api = window.LightworkAccessState;
test("HTTP status classifies denial before body parsing and transient responses retain context", () => {
  const kinds = [401,403,409,503,200].map(status => api.classify({status,ok:status===200}).kind);
  assert.deepEqual(kinds, ["session","capability","conflict","transient","ok"]);
  assert.equal(api.classify({status:403,ok:false},null,{forbiddenScope:true}).kind,"scope");
  assert.equal(api.classify({status:409,ok:false},{detail:{code:"workspace_context_changed"}}).kind,"context");
});
test("context epochs reject late responses without relocking a deliberate new selection", () => {
  let context="a", invalidations=0;
  const state=api.create(()=>context,()=>invalidations++), old=state.capture();
  state.advance();context="b";
  assert.throws(()=>state.assertCurrent(old),/workspace changed/);
  assert.equal(state.blocked,false);
  state.assertCurrent(state.capture());
  const current=state.capture();context="c";
  assert.throws(()=>state.assertCurrent(current),/workspace changed/);
  assert.equal(state.blocked,true);assert.equal(invalidations,1);
  assert.throws(()=>state.capture(),/workspace changed/);
});
