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
