'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const root = path.resolve(__dirname, '../../maverick_dashboard');
const read = name => fs.readFileSync(path.join(root, name), 'utf8').replace(/\r\n?/g, '\n');
const template = read('templates/chat_goal.html');
// The answer panel's own feedback block, as the server renders it for a person who can operate.
const panelTemplate = read('templates/_chat_answer_panel.html');
const feedbackAt = panelTemplate.indexOf('<div id="feedback"');
const feedbackMarkup = panelTemplate.slice(feedbackAt, panelTemplate.indexOf('</div>{% endif %}', feedbackAt) + 6)
  .replace(/\{#[\s\S]*?#\}/g, '').replace(/\{%[\s\S]*?%\}/g, '').replace(/\{\{[\s\S]*?\}\}/g, 'x');
const projectionScript = read('static/lightwork-answer-panel.js');
const shareScript = read('static/lightwork-deliverable-sharing.js');
const historyScript = read('static/lightwork-thread-history.js');
const voiceScript = read('static/lightwork-read-aloud.js');
const settle = async () => { for (let i = 0; i < 15; i++) await new Promise(resolve => setImmediate(resolve)); };

function inlineScript(marker) {
  const start = template.indexOf(marker), end = template.indexOf('</script>', start);
  assert.ok(start > 0 && end > start, `missing script marker ${marker}`);
  return template.slice(start, end).replaceAll('{{ goal.id }}', '7');
}
function fragment(version, content, status = 'done', operate = '1', context = 'scope') {
  return `<section id="answer-panel" data-goal="7" data-context="${context}" data-version="${version}" data-status="${status}" data-operate="${operate}" data-updated-at="1">${content}</section>`;
}
function response(html, context = 'scope') {
  return {ok: true, status: 200, headers: {get: () => context}, text: async () => html};
}
function actionMarkup(answer = '## Saved answer\n\n- First step') {
  return `<div id="result-section"><div id="result">Rendered answer</div></div>
    ${feedbackMarkup}
    <textarea id="saved-answer-source" readonly hidden>${answer}</textarea><textarea id="edit-text">Unsaved changes</textarea>
    <button id="copy-result">Copy answer</button><button id="print-result">Print conversation</button>
    <button id="share-open" aria-expanded="false">Share</button><span id="answer-action-msg"></span>`;
}
async function projectionHarness(content = '<div id="result">Live answer</div>', status = 'done', operate = '1') {
  const initial = fragment('one', content, status, operate);
  const dom = new JSDOM(`<body><div id="cs-scroll">${initial}</div>
    <textarea id="answer-input">Keep my next message</textarea><div id="qa-thread">An existing clarification</div>
    <p id="answer-refresh-status"></p><button id="answer-refresh" hidden>Refresh</button>
    <details id="share-panel"><summary>Share</summary><button id="share-create">Review share link</button></details>
    <div class="answer-actions"><button class="turn-copy">Copy older answer</button><button class="turn-print">Print</button><span class="turn-copy-status"></span></div>
    <textarea class="turn-copy-source">An earlier answer</textarea></body>`,
  {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only', pretendToBeVisual: true});
  const {window} = dom, copied = [], calls = [];
  let prints = 0, projection = response(initial);
  Object.defineProperty(window.navigator, 'clipboard', {value: {writeText: async value => copied.push(value)}, configurable: true});
  window.print = () => {prints++;};
  window.document.getElementById('share-panel').scrollIntoView = () => {};
  window.mvErrorText = () => 'Could not refresh the saved result.';
  window.mvErrorResponse = async value => value;
  window.mvRenderError = node => {node.textContent = 'Could not refresh the saved result.';};
  window.mvConfirm = async () => true;
  window.mvWhen = () => '';
  window.lwMarkdown = {upgrade: () => {}};
  window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    if (url.endsWith('/feedback')) return {ok: true, json: async () => ({})};
    if (url.startsWith('/api/v1/goals/7/answer-feedback')) return {ok: true, status: 200, redirected: false,
      json: async () => ({context: 'scope', feedback: null, eligible: false})};
    assert.equal(url, '/chat/goal/7/answer-panel', 'refresh fetches the authorized result projection');
    return typeof projection === 'function' ? projection(url, options) : projection;
  };
  // A page script that throws must not leave this window (and its timers)
  // open: the test would fail, then the run would never finish.
  try {
    shell(window);
    window.eval(projectionScript);
    await settle();
  } catch (error) { window.close(); throw error; }
  return {dom, window, doc: window.document, copied, calls, get prints() {return prints;},
    setProjection(value) {projection = value;}, refresh() {return window.mvRefreshAnswerPanel();}};
}

test('answer actions copy only the saved answer once, print, and focus sharing', async t => {
  const p = await projectionHarness(actionMarkup()); t.after(() => p.window.close());
  p.window.LightworkThreadHistory = {printConversation: () => p.window.print()};
  p.window.eval(inlineScript('// Earlier answers retain'));
  p.doc.getElementById('copy-result').click(); await settle();
  assert.deepEqual(p.copied, ['## Saved answer\n\n- First step']);
  p.doc.querySelector('.turn-copy').click(); await settle();
  assert.deepEqual(p.copied, ['## Saved answer\n\n- First step', 'An earlier answer']);
  p.doc.getElementById('print-result').click(); assert.equal(p.prints, 1);
  p.doc.getElementById('share-open').click();
  assert.equal(p.doc.getElementById('share-panel').open, true);
  assert.equal(p.doc.getElementById('share-open').getAttribute('aria-expanded'), 'true');
  assert.equal(p.doc.activeElement.id, 'share-create');
});

test('earlier Copy and Print work while a newer message is still running', async t => {
  const p = await projectionHarness('', 'running'); t.after(() => p.window.close());
  p.window.LightworkThreadHistory = {printConversation: () => p.window.print()};
  p.window.eval(inlineScript('// Earlier answers retain'));
  p.doc.querySelector('.turn-copy').click(); await settle();
  assert.deepEqual(p.copied, ['An earlier answer']);
  p.doc.querySelector('.turn-print').click(); assert.equal(p.prints, 1);
});

test('Print refuses a partial conversation while history loading is unavailable', async t => {
  const p = await projectionHarness(actionMarkup()); t.after(() => p.window.close());
  p.window.eval(inlineScript('// Earlier answers retain'));
  p.doc.getElementById('print-result').click();
  p.doc.querySelector('.turn-print').click();
  assert.equal(p.prints, 0);
  assert.match(p.doc.getElementById('answer-action-msg').textContent, /Printing is still loading/);
  assert.match(p.doc.querySelector('.turn-copy-status').textContent, /Printing is still loading/);
});

test('newly finished answer actions initialize once after the authorized projection refresh', async t => {
  const p = await projectionHarness('', 'running'); t.after(() => p.window.close());
  const html = fragment('two', actionMarkup('Finished answer'));
  p.setProjection(response(html));
  p.doc.dispatchEvent(new p.window.CustomEvent('lightwork:task-projection', {detail: {status: 'done', terminal: true, result: 'Finished answer'}}));
  await settle(); await p.refresh(); await settle();
  p.doc.getElementById('copy-result').click(); await settle();
  assert.deepEqual(p.copied, ['Finished answer']);
  assert.equal(p.doc.querySelectorAll('#copy-result').length, 1);
});

test('terminal refresh preserves drafted input and clarification, and offers retry on failure', async t => {
  const p = await projectionHarness(); t.after(() => p.window.close());
  let attempts = 0, initialized = 0;
  p.doc.addEventListener('lightwork:answer-panel-updated', () => {initialized++;});
  p.setProjection((_url, options) => {
    assert.equal(options.credentials, 'same-origin'); assert.equal(options.cache, 'no-store');
    attempts++;
    return attempts === 1 ? {ok: false, status: 503} : response(fragment('two', actionMarkup('Saved answer'), 'done', '0'));
  });
  await p.refresh();
  assert.equal(p.doc.getElementById('answer-refresh').hidden, false);
  assert.equal(p.doc.getElementById('result').textContent, 'Live answer');
  await p.refresh();
  assert.equal(p.doc.getElementById('saved-answer-source').value, 'Saved answer');
  assert.equal(p.doc.getElementById('answer-input').value, 'Keep my next message');
  assert.equal(p.doc.getElementById('qa-thread').textContent, 'An existing clarification');
  assert.equal(initialized, 1);
  assert.equal(p.doc.getElementById('answer-panel').dataset.operate, '0');
  assert.equal(p.doc.getElementById('answer-refresh').hidden, true);
});

test('access denial, login redirects, and changed workspace context clear private answer content', async t => {
  for (const denied of [{ok: false, status: 401}, {ok: false, status: 403}, {ok: false, status: 404},
    {ok: true, status: 200, redirected: true}, response(fragment('two', 'Other account'), 'other-scope')]) {
    const p = await projectionHarness(); t.after(() => p.window.close());
    p.setProjection(denied); await p.refresh();
    assert.equal(p.doc.getElementById('answer-panel').textContent, '');
    assert.match(p.doc.getElementById('answer-refresh-status').textContent, /Access.*changed/);
    assert.equal(p.doc.getElementById('answer-input').value, 'Keep my next message');
    assert.equal(p.doc.getElementById('answer-refresh').hidden, true);
  }
});

test('a raced restart cannot mount an older terminal answer projection', async t => {
  const p = await projectionHarness(); t.after(() => p.window.close());
  let releaseOld, oldSignal, requests = 0;
  p.setProjection((_url, options) => {
    requests++;
    if (requests === 1) {
      oldSignal = options.signal;
      return new Promise(resolve => {releaseOld = resolve;});
    }
    return response(fragment('running', '<div id="result">Current running answer</div>', 'pending'));
  });
  const first = p.refresh();
  p.doc.dispatchEvent(new p.window.CustomEvent('lightwork:task-projection', {detail: {status: 'pending', terminal: false, result: ''}}));
  await settle();
  releaseOld(response(fragment('stale-done', actionMarkup('Stale completed answer'))));
  await first; await settle();
  assert.equal(oldSignal.aborted, true);
  assert.equal(p.doc.getElementById('answer-panel').dataset.status, 'pending');
  assert.equal(p.doc.getElementById('result').textContent, 'Current running answer');
  assert.equal(p.doc.getElementById('copy-result'), null);
});

test('unavailable clipboard exposes a readable selected answer for manual copying', async t => {
  const p = await projectionHarness(actionMarkup()); t.after(() => p.window.close());
  Object.defineProperty(p.window.navigator, 'clipboard', {value: undefined});
  p.doc.getElementById('copy-result').click();
  const source = p.doc.getElementById('saved-answer-source');
  assert.equal(source.hidden, false); assert.equal(source.readOnly, true);
  assert.equal(p.doc.activeElement, source);
  assert.equal(source.selectionStart, 0); assert.equal(source.selectionEnd, source.value.length);
  assert.match(p.doc.getElementById('answer-action-msg').textContent, /Ctrl\+C or Command\+C/);
});

test('earlier Copy exposes selectable text even when Download is unavailable', async t => {
  const p = await projectionHarness(actionMarkup()); t.after(() => p.window.close());
  p.window.eval(inlineScript('// Earlier answers retain'));
  Object.defineProperty(p.window.navigator, 'clipboard', {value: undefined});
  p.doc.querySelector('.turn-copy').click();
  const source = p.doc.querySelector('.turn-copy-source');
  assert.equal(source.hidden, false);
  assert.equal(source.classList.contains('turn-copy-source--visible'), true);
  assert.equal(p.doc.activeElement, source);
  assert.equal(source.selectionEnd, source.value.length);
  assert.match(p.doc.querySelector('.turn-copy-status').textContent, /Ctrl\+C or Command\+C/);
  assert.equal(p.doc.querySelector('.answer-actions a'), null);
});

test('Print loads every older page and answered clarification before opening the dialog', async t => {
  const dom = new JSDOM('<body><div id="earlier-history" data-goal="7" data-before="100"><button id="history-load"></button><p id="history-status"></p><div id="history-turns"></div></div><p id="print-status"></p></body>',
    {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const w = dom.window, seen = [], pages = [
    {turns: [{id:51, goal_id:3, role:'user', content:'Middle question', questions:[]},
      {id:52, goal_id:3, role:'assistant', content:'Middle answer'}], has_more:true, before_id:51},
    {turns: [{id:1, goal_id:1, role:'user', content:'Oldest question',
      questions:[{question:'Which year?', answer:'2026'}]},
      {id:2, goal_id:1, role:'assistant', content:'Oldest answer'}], has_more:false, before_id:1},
    {turns:[], has_more:false, before_id:1}
  ];
  w.fetch = async (url, options) => { seen.push({url, options}); return {ok:true, status:200, redirected:false, json:async()=>pages.shift()}; };
  let printed = ''; w.print = () => {printed = w.document.getElementById('history-turns').textContent;};
  shell(w);
  w.eval(historyScript);
  await w.LightworkThreadHistory.printConversation(w.document.getElementById('print-status'));
  assert.deepEqual(seen.map(call => call.url), [
    '/api/v1/goals/7/thread-history?before_id=100',
    '/api/v1/goals/7/thread-history?before_id=51',
    '/api/v1/goals/7/thread-history?before_id=1'
  ]);
  assert.ok(seen.every(call => call.options.credentials === 'same-origin' && call.options.cache === 'no-store'));
  assert.match(printed, /Oldest question[\s\S]*Which year\?[\s\S]*2026[\s\S]*Oldest answer[\s\S]*Middle question/);
  assert.equal(w.document.getElementById('history-load').hidden, true);
});

test('Print refuses a partial conversation and lets a later attempt continue', async t => {
  const dom = new JSDOM('<body><div id="earlier-history" data-goal="7" data-before="100"><button id="history-load"></button><p id="history-status"></p><div id="history-turns"></div></div><p id="print-status"></p></body>',
    {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const w = dom.window, calls = [];
  let fail = true, prints = 0;
  w.fetch = async url => {
    calls.push(url);
    if (url.endsWith('before_id=100')) return {ok:true, status:200, redirected:false,
      json:async()=>({turns:[{id:51,goal_id:3,role:'user',content:'Saved middle',questions:[]}],has_more:true,before_id:51})};
    if (url.endsWith('before_id=1')) return {ok:true, status:200, redirected:false,
      json:async()=>({turns:[],has_more:false,before_id:1})};
    if (fail) {fail = false; throw Error('offline');}
    return {ok:true, status:200, redirected:false,
      json:async()=>({turns:[{id:1,goal_id:1,role:'user',content:'Saved oldest',questions:[]}],has_more:false,before_id:1})};
  };
  w.print = () => {prints++;}; w.eval(historyScript);
  const status = w.document.getElementById('print-status');
  await w.LightworkThreadHistory.printConversation(status);
  assert.equal(prints, 0); assert.match(status.textContent, /Nothing was printed/);
  assert.match(w.document.getElementById('history-turns').textContent, /Saved middle/);
  await w.LightworkThreadHistory.printConversation(status);
  assert.equal(prints, 1); assert.deepEqual(calls.slice(-2), [
    '/api/v1/goals/7/thread-history?before_id=51',
    '/api/v1/goals/7/thread-history?before_id=1'
  ]);
});

test('Print stops at the history limit without opening an incomplete print view', async t => {
  const dom = new JSDOM('<body><div id="earlier-history" data-goal="7" data-before="1001"><button id="history-load"></button><p id="history-status"></p><div id="history-turns"></div></div><p id="print-status"></p></body>',
    {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only'});
  t.after(() => dom.window.close());
  const w = dom.window;
  let calls = 0, prints = 0;
  w.fetch = async () => {
    calls++;
    const id = 1001 - calls;
    return {ok:true, status:200, redirected:false, json:async()=>({
      turns:[{id, goal_id:7, role:'user', content:'Saved turn ' + id, questions:[]}],
      has_more:true, before_id:id
    })};
  };
  w.print = () => {prints++;}; w.eval(historyScript);
  await w.LightworkThreadHistory.printConversation(w.document.getElementById('print-status'));
  assert.equal(calls, 20);
  assert.equal(prints, 0);
  assert.match(w.document.getElementById('print-status').textContent, /too long to print at once/);
  assert.match(w.document.getElementById('history-turns').textContent, /Saved turn 1000/);
});

function shareHarness({localOnly = false, canCreate = true, existing = false} = {}) {
  const dom = new JSDOM(`<body><section id="answer-panel" data-status="done"><textarea id="saved-answer-source">Reviewed saved answer</textarea></section><div class="goal-share" data-goal="7" data-can-operate="1">
    <select id="share-scope"><option value="result" selected>Saved answer</option><option value="conversation">Full conversation</option></select>
    ${canCreate ? '<button id="share-create">Review share link</button>' : ''}
    <input id="share-url" readonly style="display:none"><button id="share-copy" hidden>Copy link</button>
    <span id="share-msg"></span><ul id="share-list"></ul></div></body>`,
  {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only', pretendToBeVisual: true});
  const {window} = dom, copied = [], calls = [];
  let minted = existing, revoked = false;
  Object.defineProperty(window.navigator, 'clipboard', {value: {writeText: async value => copied.push(value)}});
  window.mvConfirm = async () => true;
  window.mvErrorText = () => 'Could not manage this link.';
  window.mvRenderError = (node, error) => {node.textContent = error.message || 'Could not manage this link.';};
  window.fetch = async (url, options = {}) => {
    calls.push({url, options});
    let body;
    if (url.includes('/preview?scope=')) body = {audience: 'Anyone who has this link.', scope: 'Selected content only', allowed_lifetimes: [3600, 86400, 604800],
      source: url.endsWith('conversation')
        ? {title: 'Reviewed task', result: 'Reviewed saved answer', transcript: [{role: 'user', text: 'Earlier question'}, {role: 'clarification', question: 'Which year?', answer: '2026'}, {role: 'assistant', text: 'Reviewed saved answer'}], artifacts: [], sha256: 'b'.repeat(64)}
        : {title: 'Reviewed task', result: 'Reviewed saved answer', artifacts: [], sha256: 'a'.repeat(64)}};
    else if (url.endsWith('/3/revoke')) {revoked = true; body = {};}
    else if (options.method === 'POST') {
      minted = true; body = {id: 3, url: localOnly ? 'http://localhost/share/token' : 'https://lightwork.invalid/share/token',
        expires_at: Math.floor(Date.now() / 1000) + 86400, local_only: localOnly};
    } else body = {links: minted && !revoked ? [{id: 3, label: 'Reviewed result', state: 'active', revoked: false}] : []};
    return {ok: true, status: 200, json: async () => body};
  };
  shell(window);
  window.eval(shareScript);
  return {dom, window, doc: window.document, copied, calls};
}
async function createShare(p) {
  await settle(); p.doc.getElementById('share-create').click(); await settle();
  assert.equal(p.calls.filter(call => call.options.method === 'POST' && !call.url.includes('/preview?scope=')).length, 0, 'preview never creates a link');
  assert.match(p.doc.querySelector('.goal-share pre').textContent, /Reviewed saved answer/);
  p.doc.getElementById('share-confirm').click(); await settle();
}

test('a reviewed new share link has working Copy link and Revoke actions', async t => {
  const p = shareHarness(); t.after(() => p.window.close()); await createShare(p);
  const write = p.calls.find(call => call.options.method === 'POST' && call.url === '/api/v1/goals/7/share');
  assert.deepEqual(JSON.parse(write.options.body), {confirm: true, scope: 'result', source_sha256: 'a'.repeat(64), lifetime_seconds: 86400, label: 'Read-only deliverable'});
  const field = p.doc.getElementById('share-url');
  assert.equal(field.style.display, ''); assert.equal(p.doc.getElementById('share-copy').hidden, false);
  p.doc.getElementById('share-copy').click(); await settle();
  assert.deepEqual(p.copied, ['https://lightwork.invalid/share/token']);
  assert.match(p.doc.getElementById('share-msg').textContent, /Link copied/);
  p.doc.querySelector('.share-revoke').click(); await settle();
  assert.equal(p.calls.filter(call => call.url.endsWith('/3/revoke')).length, 1);
  assert.equal(field.value, ''); assert.equal(p.doc.getElementById('share-copy').hidden, true);
  assert.match(p.doc.getElementById('share-msg').textContent, /Link revoked/);
});

test('a local-only share link explains its reach before and after copying', async t => {
  const p = shareHarness({localOnly: true}); t.after(() => p.window.close()); await createShare(p);
  assert.match(p.doc.getElementById('share-msg').textContent, /limited to this computer or its private network/);
  p.doc.getElementById('share-copy').click(); await settle();
  assert.match(p.doc.getElementById('share-msg').textContent, /limited to this computer or its private network/);
});

test('existing share links can be revoked without a Create link control', async t => {
  const p = shareHarness({canCreate: false, existing: true}); t.after(() => p.window.close()); await settle();
  p.doc.querySelector('.share-revoke').click(); await settle();
  assert.equal(p.calls.filter(call => call.url.endsWith('/3/revoke')).length, 1);
  assert.equal(p.doc.querySelector('#share-list li'), null);
});

test('full conversation needs an explicit choice and shows the exact messages before minting', async t => {
  const p = shareHarness(); t.after(() => p.window.close()); await settle();
  assert.equal(p.doc.getElementById('share-scope').value, 'result');
  p.doc.getElementById('share-scope').value = 'conversation';
  p.doc.getElementById('share-create').click(); await settle();
  assert.ok(p.calls.some(call => call.url.endsWith('/preview?scope=conversation')));
  assert.equal(p.calls.filter(call => call.url === '/api/v1/goals/7/share' && call.options.method === 'POST').length, 0);
  assert.match(p.doc.querySelector('.share-review').textContent, /Earlier question[\s\S]*Which year\?[\s\S]*2026[\s\S]*Reviewed saved answer/);
  assert.equal(p.doc.getElementById('share-scope').disabled, true);
  p.doc.getElementById('share-confirm').click(); await settle();
  const write = p.calls.find(call => call.url === '/api/v1/goals/7/share' && call.options.method === 'POST');
  assert.deepEqual(JSON.parse(write.options.body), {confirm: true, scope: 'conversation', source_sha256: 'b'.repeat(64), lifetime_seconds: 86400, label: 'Read-only conversation'});
  assert.equal(p.doc.getElementById('share-scope').disabled, false);
});

function voiceHarness(text, allowed = true) {
  const dom = new JSDOM(`<body><section id="answer-panel" data-operate="${allowed ? '1' : '0'}"><div id="result" lang="und"></div>
    <div id="voice-actions"><button id="read-aloud" data-voice-only="0">Read aloud</button></div></section></body>`, {runScripts: 'outside-only'});
  const {window} = dom;
  window.document.getElementById('result').textContent = text;
  shell(window);
  window.eval(voiceScript); window.lwReadAloud(window.document.getElementById('read-aloud'));
  return {dom, window, doc: window.document, status: () => window.document.querySelector('#voice-actions [role="status"]')};
}
function deviceVoice(window) {
  const spoken = []; let stops = 0;
  window.SpeechSynthesisUtterance = function (text) {this.text = text;};
  window.speechSynthesis = {speak: utterance => spoken.push(utterance), cancel: () => {stops++;}, pause: () => {}, resume: () => {}};
  return {spoken, get stops() {return stops;}};
}

test('read aloud can stop a pending request without starting late audio', async t => {
  const p = voiceHarness('An answer'); t.after(() => p.window.close());
  let resolveResponse, signal, audioCreated = 0;
  p.window.fetch = async (_url, options) => {signal = options.signal; return new Promise(resolve => {resolveResponse = resolve;});};
  p.window.Audio = function () {audioCreated++;};
  const button = p.doc.getElementById('read-aloud'); button.click();
  assert.equal(button.textContent, 'Stop reading'); button.click(); assert.equal(signal.aborted, true);
  resolveResponse({ok: true, blob: async () => new p.window.Blob(['audio'])}); await settle();
  assert.equal(audioCreated, 0); assert.equal(button.getAttribute('aria-pressed'), 'false');
  assert.match(p.status().textContent, /Reading stopped/);
});

test('long-answer reading covers every part and releases audio after each part', async t => {
  const text = 'a'.repeat(4500), p = voiceHarness(text); t.after(() => p.window.close());
  const posted = [], revoked = [], players = [];
  p.window.fetch = async (_url, options) => {posted.push(JSON.parse(options.body).text); return {ok: true, blob: async () => new p.window.Blob(['audio'])};};
  p.window.URL.createObjectURL = () => `blob:voice-${players.length}`;
  p.window.URL.revokeObjectURL = url => revoked.push(url);
  p.window.Audio = function () {players.push(this); this.play = async () => {}; this.pause = () => {};};
  p.doc.getElementById('read-aloud').click(); await settle();
  assert.equal(posted[0].length, 3000); assert.match(p.status().textContent, /part 1 of 2/);
  players[0].onended(); await settle();
  assert.equal(posted.join(''), text); assert.match(p.status().textContent, /part 2 of 2/);
  players[1].onended();
  assert.deepEqual(revoked, ['blob:voice-0', 'blob:voice-1']);
  assert.match(p.status().textContent, /Reading finished/);
});

test('read aloud reports unavailable voices and never sends a paid voice request from a read-only account', async t => {
  const failed = voiceHarness('An answer'); t.after(() => failed.window.close());
  failed.window.fetch = async () => {throw new Error('offline');};
  failed.doc.getElementById('read-aloud').click(); await settle();
  assert.match(failed.status().textContent, /Audio is unavailable/);
  assert.equal(failed.doc.getElementById('read-aloud').getAttribute('aria-pressed'), 'false');
  const readonly = voiceHarness('An answer', false); t.after(() => readonly.window.close());
  let requests = 0; readonly.window.fetch = async () => {requests++;};
  const device = deviceVoice(readonly.window);
  readonly.doc.getElementById('read-aloud').click(); await settle();
  assert.equal(requests, 0); assert.equal(device.spoken.length, 1); assert.equal(device.spoken[0].text, 'An answer');
  readonly.doc.getElementById('read-aloud').click();
  assert.equal(readonly.doc.getElementById('read-aloud').getAttribute('aria-pressed'), 'false');
  assert.match(readonly.status().textContent, /Reading stopped/);
});

test('browser speech fallback has a working Stop reading action', async t => {
  const p = voiceHarness('An answer'); t.after(() => p.window.close());
  p.window.fetch = async () => ({ok: false}); const device = deviceVoice(p.window);
  const button = p.doc.getElementById('read-aloud'); button.click(); await settle();
  assert.equal(button.textContent, 'Stop reading'); assert.equal(device.spoken.length, 1);
  const before = device.stops; button.click(); assert.equal(device.stops, before + 1);
  assert.equal(button.getAttribute('aria-pressed'), 'false'); assert.match(p.status().textContent, /Reading stopped/);
});
