'use strict';
// Try again, Edit and resend and Branch from here offer the same per-task
// spending and time limits as the main composer; the review states them.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const {shell} = require('./_shell');
const root = path.resolve(__dirname, '../../maverick_dashboard');
const markup = fs.readFileSync(path.join(root, 'templates/_chat_message_actions.html'), 'utf8')
  .split('<style>')[0].replace(/\{\{[\s\S]*?\}\}/g, 'x');
const script = fs.readFileSync(path.join(root, 'static/lightwork-chat-message-actions.js'), 'utf8');
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };
const CONTEXT = 'a'.repeat(64);

function json(value, status = 200) {
  return {ok: status < 400, status, redirected: false, headers: {get: name => name.toLowerCase() === 'content-type' ? 'application/json' : null},
    text: async () => JSON.stringify(value)};
}

test('the alternative review sends and shows the limits the person chose', async t => {
  const dom = new JSDOM(`<body>${markup.replace('data-context="x"', `data-context="${CONTEXT}"`)}
    <button data-chat-message-action="retry" data-goal="7">Try again</button></body>`,
  {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only', pretendToBeVisual: true});
  const {window} = dom; t.after(() => window.close());
  const sent = [];
  const caps = {max_dollars: 2, max_wall_seconds: 1800, max_depth: 3};
  window.fetch = async (url, options = {}) => {
    sent.push({url, body: options.body ? JSON.parse(options.body) : null});
    if (url.includes('/source?')) return json({context: CONTEXT, goal: 7, action: 'retry', turn: null, source: 'b'.repeat(64),
      message: 'Write a short welcome note', history: [], files: [], accounts: [], caps, notice: 'A separate conversation.'});
    if (url.endsWith('/review')) return json({context: CONTEXT, operation: 'c'.repeat(32), token: 'sealed', action: 'Try again',
      message: 'Write a short welcome note', history: [], files: [], accounts: [], answer_only: true,
      caps: {...caps, max_dollars: 0.25, max_wall_seconds: 120}, notice: 'A separate conversation.'});
    throw new Error('unexpected ' + url);
  };
  window.HTMLElement.prototype.scrollIntoView = () => {};
  shell(window); window.eval(script);
  const doc = window.document;
  doc.querySelector('[data-chat-message-action]').click(); await settle();
  assert.equal(doc.getElementById('chat-alternative-max-dollars').placeholder, 'Up to $2.00');
  assert.equal(doc.getElementById('chat-alternative-max-minutes').placeholder, 'Up to 30 minutes');
  doc.getElementById('chat-alternative-max-dollars').value = '0.25';
  doc.getElementById('chat-alternative-max-minutes').value = '2';
  doc.getElementById('chat-alternative-form').dispatchEvent(new window.Event('submit', {cancelable: true}));
  await settle();
  const review = sent.find(call => call.url.endsWith('/review'));
  assert.equal(review.body.max_dollars, '0.25');
  assert.equal(review.body.max_minutes, '2');
  assert.match(doc.getElementById('chat-alternative-full-review').textContent, /stops at \$0\.25 or 2 minutes/);
});

test('a refused limit shows the plain reason', async t => {
  const dom = new JSDOM(`<body>${markup.replace('data-context="x"', `data-context="${CONTEXT}"`)}
    <button data-chat-message-action="retry" data-goal="7">Try again</button></body>`,
  {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only', pretendToBeVisual: true});
  const {window} = dom; t.after(() => window.close());
  window.fetch = async url => url.includes('/source?')
    ? json({context: CONTEXT, goal: 7, action: 'retry', turn: null, source: 'b'.repeat(64), message: 'Hello', history: [], files: [],
      accounts: [], caps: {max_dollars: 2, max_wall_seconds: 1800, max_depth: 3}, notice: 'n'})
    : json({detail: {code: 'task_limit', message: 'Check the limits for this task.',
      field_errors: {max_dollars: 'Choose no more than $2.00, this workspace’s limit for one task.'}}}, 400);
  window.HTMLElement.prototype.scrollIntoView = () => {};
  shell(window); window.eval(script);
  const doc = window.document;
  doc.querySelector('[data-chat-message-action]').click(); await settle();
  doc.getElementById('chat-alternative-max-dollars').value = '500';
  doc.getElementById('chat-alternative-form').dispatchEvent(new window.Event('submit', {cancelable: true}));
  await settle();
  assert.match(doc.getElementById('chat-alternative-status').textContent, /Check the limits for this task\. Choose no more than \$2\.00/);
});

function page(goal, saved = {}) {
  const dom = new JSDOM(`<body>${markup.replace('data-context="x"', `data-context="${CONTEXT}"`).replace('data-goal="x"', `data-goal="${goal}"`)}
    <button data-chat-message-action="retry" data-goal="${goal}">Try again</button></body>`,
  {url: `https://lightwork.invalid/chat/goal/${goal}`, runScripts: 'outside-only', pretendToBeVisual: true});
  const {window} = dom;
  Object.entries(saved).forEach(([name, value]) => window.sessionStorage.setItem(name, value));
  window.HTMLElement.prototype.scrollIntoView = () => {};
  return window;
}

test('the separate-conversation panel stays with the conversation it was started from', async t => {
  // Live: after one Try again on #50, the panel opened by itself on #51 and #54.
  const first = page(50); t.after(() => first.close());
  const caps = {max_dollars: 2, max_wall_seconds: 1800, max_depth: 3};
  first.fetch = async url => {
    if (url.includes('/source?')) return json({context: CONTEXT, goal: 50, action: 'retry', turn: null, source: 'b'.repeat(64),
      message: 'Hello', history: [], files: [], accounts: [], caps, notice: 'n'});
    if (url.endsWith('/review')) return json({context: CONTEXT, operation: 'c'.repeat(32), token: 'sealed-original', action: 'Try again',
      message: 'Hello', history: [], files: [], accounts: [], answer_only: true, caps, notice: 'n'});
    if (url.endsWith('/apply')) return json({context: CONTEXT, confirmed: true, state: 'ready', goal: 51, href: '/chat/goal/51',
      message: 'Started a separate conversation.'});
    throw new Error('unexpected ' + url);
  };
  shell(first); first.eval(script);
  const doc = first.document;
  doc.querySelector('[data-chat-message-action]').click(); await settle();
  doc.getElementById('chat-alternative-form').dispatchEvent(new first.Event('submit', {cancelable: true})); await settle();
  doc.getElementById('chat-alternative-start').click(); await settle();
  assert.equal(doc.getElementById('chat-alternative-open').getAttribute('href'), '/chat/goal/51');
  const saved = {};
  for (let i = 0; i < first.sessionStorage.length; i++) saved[first.sessionStorage.key(i)] = first.sessionStorage.getItem(first.sessionStorage.key(i));
  assert.ok(Object.values(saved).includes('sealed-original'));

  for (const goal of [51, 54]) {   // other task pages in the same tab
    const other = page(goal, saved); t.after(() => other.close());
    shell(other); other.eval(script);
    assert.equal(other.document.getElementById('chat-message-actions').hidden, true, `#${goal}`);
    assert.equal(other.document.getElementById('chat-alternative-original').hidden, true, `#${goal}`);
  }
  const back = page(50, saved); t.after(() => back.close());   // its own page keeps the protected original
  shell(back); back.eval(script);
  assert.equal(back.document.getElementById('chat-message-actions').hidden, false);
  assert.equal(back.document.getElementById('chat-alternative-original').hidden, false);
});

test('Try again redoes the work by default and starts from the review in one click', async t => {
  // Try again used to default to Answer only, which could not fetch anything
  // or take any action, so "try again" on a task that needed tools quietly
  // became a different, weaker task. It also needed a separate "I reviewed"
  // box before Start. The review itself is the confirmation now.
  const dom = new JSDOM(`<body>${markup.replace('data-context="x"', `data-context="${CONTEXT}"`)}
    <button data-chat-message-action="retry" data-goal="7">Try again</button></body>`,
  {url: 'https://lightwork.invalid/chat/goal/7', runScripts: 'outside-only', pretendToBeVisual: true});
  const {window} = dom; t.after(() => window.close());
  const sent = [];
  const caps = {max_dollars: 2, max_wall_seconds: 1800, max_depth: 3};
  window.fetch = async (url, options = {}) => {
    sent.push({url, body: options.body ? JSON.parse(options.body) : null});
    if (url.includes('/source?')) return json({context: CONTEXT, goal: 7, action: 'retry', turn: null, source: 'b'.repeat(64),
      message: 'Hello', history: [], files: [], accounts: [], caps, notice: 'n'});
    if (url.endsWith('/review')) return json({context: CONTEXT, operation: 'c'.repeat(32), token: 'sealed', action: 'Try again',
      message: 'Hello', history: [], files: [], accounts: [], answer_only: false, caps, notice: 'n'});
    if (url.endsWith('/apply')) return json({context: CONTEXT, confirmed: true, state: 'ready', goal: 8, href: '/chat/goal/8',
      message: 'Started a separate conversation.'});
    throw new Error('unexpected ' + url);
  };
  window.HTMLElement.prototype.scrollIntoView = () => {};
  shell(window); window.eval(script);
  const doc = window.document;
  doc.querySelector('[data-chat-message-action]').click(); await settle();
  assert.equal(doc.getElementById('chat-alternative-answer-only').checked, false);
  doc.getElementById('chat-alternative-form').dispatchEvent(new window.Event('submit', {cancelable: true})); await settle();
  assert.equal(sent.find(call => call.url.endsWith('/review')).body.answer_only, false);
  assert.equal(doc.getElementById('chat-alternative-confirm'), null);
  const start = doc.getElementById('chat-alternative-start');
  assert.equal(start.disabled, false);
  start.click(); await settle();
  assert.deepEqual(sent.find(call => call.url.endsWith('/apply')).body, {token: 'sealed', confirmed: true});
  assert.equal(doc.getElementById('chat-alternative-open').getAttribute('href'), '/chat/goal/8');
});
