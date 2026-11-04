// Local lifecycle regressions; no provider calls.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const script = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-answer-panel.js'), 'utf8');
const settle = async () => { for (let i=0;i<12;i++) await new Promise(resolve=>setImmediate(resolve)); };
function fragment(version, content='', status='done', operate='1') { return `<section id="answer-panel" data-goal="4" data-context="scope" data-updated-at="1" data-version="${version}" data-status="${status}" data-operate="${operate}">${content}</section>`; }
function page(content='', status='done') {
  const dom = new JSDOM(`<div id="cs-scroll">${fragment('one',content,status)}</div><p id="answer-refresh-status"></p><button id="answer-refresh"></button><textarea id="answer-input">Unsent follow-up</textarea>`,
    {url:'https://lightwork.invalid/chat/goal/4',runScripts:'outside-only',pretendToBeVisual:true});
  let answer = {ok:true,status:200,headers:{get:()=> 'scope'},text:async()=>fragment('one',content,status)};
  dom.window.fetch = async url => String(url).endsWith('/feedback') ? {ok:true,json:async()=>({})} : answer;
  dom.window.mvErrorText = ()=>'Refresh unavailable.';
  dom.window.mvRenderError = node=>{node.textContent='Refresh unavailable.';};
  dom.window.mvConfirm = async()=>true;
  shell(dom.window);
  dom.window.eval(script);
  return {dom, doc:dom.window.document, setAnswer(value){answer=value;}, update(html){answer={ok:true,status:200,headers:{get:()=> 'scope'},text:async()=>html};return dom.window.mvRefreshAnswerPanel();}};
}
test('completion mounts result controls and artifacts once without replacing focused composer', async()=>{
  const p=page('', 'running'); await settle(); const composer=p.doc.getElementById('answer-input');composer.focus();
  p.doc.getElementById('cs-scroll').scrollTop=70;
  const html=fragment('two','<div id="result-section"><div id="result">Finished</div></div><div id="feedback"><button id="copy-result">Copy</button><span id="feedback-msg"></span></div><div class="artifacts">New file</div><button id="signoff-approve">Approve current result</button>');
  p.setAnswer({ok:true,status:200,headers:{get:()=> 'scope'},text:async()=>html});
  p.doc.dispatchEvent(new p.dom.window.CustomEvent('lightwork:task-projection', {detail:{status:'done',terminal:true,result:'Finished',artifactsChanged:true}}));
  await settle(); await p.update(html);await settle();
  assert.equal(p.doc.querySelectorAll('#copy-result').length,1);
  assert.equal(p.doc.querySelector('.artifacts').textContent,'New file');
  assert.equal(p.doc.querySelectorAll('#signoff-approve').length,1);
  assert.equal(p.doc.activeElement,composer);assert.equal(composer.value,'Unsent follow-up');
  assert.equal(p.doc.getElementById('cs-scroll').scrollTop,70);p.dom.window.close();
});
test('accepted handoff updates the live closure notice and owner controls while preserving the draft',async()=>{
  const p=page('<button id="signoff-approve">Approve</button>');await settle();
  const composer=p.doc.getElementById('answer-input');composer.focus();
  await p.update(fragment('closed','<p id="handoff-closed-notice" role="status">Responsibility accepted. Original conversation closed.</p><div id="result">Saved result</div>','done','0'));await settle();
  assert.match(p.doc.querySelector('#answer-panel #handoff-closed-notice').textContent,/Original conversation closed/);
  assert.equal(p.doc.getElementById('signoff-approve'),null);
  assert.equal(p.doc.activeElement,composer);assert.equal(composer.value,'Unsent follow-up');p.dom.window.close();
});
test('private projection clears when account scope changes and preserves composer',async()=>{
  const p=page('Private saved result');await settle();
  p.setAnswer({ok:true,status:200,headers:{get:()=> 'other-scope'}});await p.dom.window.mvRefreshAnswerPanel();await settle();
  assert.equal(p.doc.getElementById('answer-panel').textContent,'');
  assert.equal(p.doc.getElementById('answer-input').value,'Unsent follow-up');p.dom.window.close();
});
test('dirty review note defers replacement until an explicit refresh decision',async()=>{
  const p=page('<textarea id="signoff-note">Unsaved review note</textarea>');await settle();
  await p.update(fragment('two','New result'));await settle();
  assert.equal(p.doc.getElementById('signoff-note').value,'Unsaved review note');
  assert.equal(p.doc.getElementById('answer-refresh').hidden,false);
  p.doc.getElementById('answer-refresh').click();await settle();
  assert.match(p.doc.getElementById('answer-panel').textContent,/New result/);
  assert.equal(p.doc.getElementById('answer-input').value,'Unsent follow-up');p.dom.window.close();
});

// As _chat_answer_panel.html renders the rating: one choice opens the note
// form (with the optional reasons for Needs improvement), and Save feedback
// sends it once, bound to the exact saved answer it was given for.
const FEEDBACK = '<div id="feedback"><button id="feedback-up" data-rating="up">up</button><button id="feedback-down" data-rating="down">down</button>' +
  '<button id="feedback-review">Review saved feedback</button><button id="feedback-copilot">Copilot</button><div id="feedback-saved"></div>' +
  '<form id="feedback-form" hidden><p id="feedback-choice"></p><div role="group" aria-labelledby="feedback-reason-q">' +
  '<p id="feedback-reason-q">What was wrong? This is optional.</p>' +
  '<button type="button" data-reason="wrong" aria-pressed="false">Wrong or inaccurate</button>' +
  '<button type="button" data-reason="incomplete" aria-pressed="false">Missing something</button></div>' +
  '<textarea id="feedback-note" maxlength="500"></textarea><button type="submit" id="feedback-save">Save feedback</button>' +
  '<button type="button" id="feedback-cancel">Cancel</button></form>' +
  '<button id="feedback-recover" hidden>Check my original feedback</button><span id="feedback-msg"></span>' +
  '<p id="feedback-hand-off" hidden><a href="/help#get-help">Get help</a></p></div>';
const REVISION = 'a'.repeat(64);
function feedbackPage(replies) {
  const p = page(FEEDBACK); const posts = [];
  p.dom.window.fetch = async (url, options = {}) => {
    if (String(url).includes('/answer-feedback') && options.method === 'POST') {
      const body = JSON.parse(options.body); posts.push(body);
      const reply = replies.shift() || {acknowledgement: 'Thanks. Saved with this task.'};
      return {ok: true, status: 200, json: async () => ({context: 'scope',
        feedback: {operation_id: body.operation_id, rating: body.rating, current_result: true, recorded_at: 1,
          acknowledgement: reply.acknowledgement}, ...reply})};
    }
    if (String(url).includes('/answer-feedback')) return {ok: true, status: 200,
      json: async () => ({context: 'scope', revision: REVISION, eligible: true, updated_at: 1, feedback: null})};
    return {ok: true, status: 200, headers: {get: () => 'scope'}, text: async () => fragment('two', FEEDBACK)};
  };
  return {p, posts};
}
async function open(p, rating) {
  // The refreshed answer binds its rating to the saved answer it shows.
  await p.dom.window.mvRefreshAnswerPanel(); await settle();
  // The rating buttons unlock once the current saved answer has been read.
  for (let i = 0; i < 50 && p.doc.getElementById('feedback-' + rating).disabled; i++) await settle();
  p.doc.getElementById('feedback-' + rating).click(); await settle();
  return p.doc.getElementById('feedback-form');
}
test('thumbs-down opens optional reasons that send once with a private note', async () => {
  const {p, posts} = feedbackPage([{acknowledgement: "Thanks. Saved with this task. The administrators' summary shows counts and the reasons picked for this agent, not what you wrote."}]);
  const form = await open(p, 'down');
  assert.equal(posts.length, 0, 'choosing does not save');
  assert.equal(form.hidden, false);
  assert.equal(p.doc.getElementById('feedback-reason-q').hidden, false);
  assert.equal(p.doc.activeElement, p.doc.getElementById('feedback-note'));
  form.querySelector('[data-reason="incomplete"]').click();
  assert.equal(form.querySelector('[data-reason="incomplete"]').getAttribute('aria-pressed'), 'true');
  p.doc.getElementById('feedback-note').value = 'It skipped the Fabrikam POs.';
  form.dispatchEvent(new p.dom.window.Event('submit', {cancelable: true})); await settle();
  assert.equal(posts.length, 1);
  const {operation_id: operation, ...sent} = posts[0];
  assert.match(operation, /^[a-f0-9]{32}$/);
  assert.deepEqual(sent, {rating: 'down', note: 'It skipped the Fabrikam POs.', reason: 'incomplete', revision: REVISION, expected_context: 'scope'});
  assert.equal(form.hidden, true);
  assert.match(p.doc.getElementById('feedback-msg').textContent, /Feedback saved\..*not what you wrote/);
  p.dom.window.close();
});
test('the reason step is one tap to cancel and sends nothing', async () => {
  const {p, posts} = feedbackPage([]);
  const form = await open(p, 'down');
  p.doc.getElementById('feedback-cancel').click(); await settle();
  assert.equal(form.hidden, true);
  assert.equal(posts.length, 0);
  p.dom.window.close();
});
test('after repeated rejections the reply asks one short open question', async () => {
  const {p} = feedbackPage([{acknowledgement: 'Thanks.', follow_up: {question: 'What would make this better?'}}]);
  const form = await open(p, 'down');
  form.dispatchEvent(new p.dom.window.Event('submit', {cancelable: true})); await settle();
  assert.match(p.doc.getElementById('feedback-msg').textContent, /What would make this better\?/);
  p.dom.window.close();
});
test('thumbs-up never shows the reasons', async () => {
  const {p, posts} = feedbackPage([]);
  const form = await open(p, 'up');
  assert.equal(form.hidden, false);
  assert.equal(p.doc.getElementById('feedback-reason-q').hidden, true);
  form.dispatchEvent(new p.dom.window.Event('submit', {cancelable: true})); await settle();
  assert.equal(posts[0].rating, 'up');
  assert.equal(posts[0].reason, '');
  p.dom.window.close();
});
