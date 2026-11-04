"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const {shell} = require('./_shell');
const read = name => fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/templates",name),"utf8").replace(/\r\n/g,"\n");
const source=fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/templates/_assessment_review.html"),"utf8").replace(/\r\n/g,"\n").replace(/<script\b[^>]*><\/script>\s*$/,"")+"<script>"+fs.readFileSync(path.resolve(__dirname,"../../maverick_dashboard/static/lightwork-assessment-review.js"),"utf8")+"</script>",queue=read("_approvals_queue.html");
const flush=async()=>{for(let i=0;i<12;i++)await new Promise(setImmediate);};
const record=id=>({id,revision:1,subject:"Subject "+id,type:"pia",status:"pending_review",answers:{},question_text:{},result:{total:0,answered:0},followups:[]});
async function fixture(action) {
  const dom=new JSDOM(source+'<p id="approval-msg"></p><table><tbody><tr data-id="22" data-assessment="B"><td><button class="approval-btn" data-id="22" data-action="approve" disabled>Approve</button><button class="approval-btn" data-id="22" data-action="deny">Deny</button></td></tr></tbody></table>',{url:"https://fixture.invalid/approvals",runScripts:"outside-only"});
  const w=dom.window,doc=w.document,dlg=doc.getElementById("arv-dialog"),calls=[],events=[];
  dlg.showModal=()=>{dlg.open=true;};dlg.close=()=>{dlg.open=false;dlg.dispatchEvent(new w.Event("close"));};
  w.mvConfirm=async()=>true;w.mvForm=async(_title,fields)=>fields.some(field=>field.key==="expires_days")?{rationale:"Reviewed",expires_days:"90"}:{reason:"Contract renewal",note:"Reviewed"};
  doc.addEventListener("mv-assessment-decided",event=>events.push({...event.detail}));
  let resolve,reject;
  w.fetch=async(url,options)=>{
    calls.push({url,method:options?.method||"GET"});
    if(options?.method==="POST"&&url.endsWith("/"+action))return new Promise((yes,no)=>{resolve=yes;reject=no;});
    const match=url.match(/\/sessions\/([AB])$/);
    return {ok:true,json:async()=>match?record(match[1]):{timeline:[]}};
  };
  shell(w);
  w.eval(source.slice(source.indexOf("<script>")+8,source.indexOf("</script>")));
  const start=queue.indexOf("    document.addEventListener('mv-assessment-decided'");
  w.eval(queue.slice(start,queue.indexOf("\n  })();",start)));
  const mutate=queue.indexOf("  (function() {\n    const msg = document.getElementById('approval-msg')");
  w.eval(queue.slice(mutate,queue.indexOf("</script>",mutate)));
  await w.mvAssessmentReview.open("A");
  return {dom,w,doc,calls,events,resolve:body=>resolve(body),reject:error=>reject(error)};
}
for(const [action,button] of [["decide","arv-reject"],["decide","arv-approve"],["followups","arv-send"],["accept-risk","arv-accept"],["trigger-review","arv-trigger"]]) {
  for(const fails of [false,true])test(`late ${button} ${fails?"failure":"success"} cannot mutate the next assessment`,async()=>{
    const f=await fixture(action);
    try{
      f.doc.getElementById("arv-questions").value="More detail?";
      f.doc.getElementById(button).click();await flush();
      assert.equal(f.calls.find(call=>call.method==="POST").url,"/api/v1/assess/sessions/A/"+action);
      f.doc.getElementById("arv-close").click();await flush();await f.w.mvAssessmentReview.open("B");
      const body=f.doc.getElementById("arv-body").textContent;
      if(fails)f.reject(new Error("Late failure"));
      else f.resolve({ok:true,json:async()=>({...record("A"),revision:2,status:"rejected"})});
      await flush();
      assert.equal(f.doc.getElementById("arv-body").textContent,body);
      assert.equal(f.doc.getElementById("arv-status").textContent,"");
      assert.deepEqual(f.events,[]);
      assert.equal(f.calls.filter(call=>call.url.includes("/approvals/")).length,0);
      assert.equal(f.doc.getElementById(button).disabled,false);
    }finally{f.dom.window.close();}
  });
}
test("a current decision emits only the captured assessment identity",async()=>{
  const f=await fixture("decide");
  try{
    f.doc.getElementById("arv-reject").click();await flush();
    f.resolve({ok:true,json:async()=>({...record("A"),revision:2,status:"rejected"})});await flush();
    assert.deepEqual(f.events,[{id:"A",decision:"rejected"}]);
  }finally{f.dom.window.close();}
});
test("the review dialog uses in-page forms and plain wording, never browser prompts or status codes",()=>{
  assert.equal(source.includes("window.prompt"),false);
  assert.equal(/'HTTP '|\(HTTP /.test(source),false);
  assert.equal(source.includes("JSON.stringify(old.ai_metadata"),false);
  for(const label of ["Risk before safeguards","Risk after safeguards","Accept the remaining risk","Start a new review now","No scheduled review"])assert.ok(source.includes(label),label);
});
