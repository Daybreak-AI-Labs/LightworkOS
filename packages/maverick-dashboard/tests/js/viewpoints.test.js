'use strict';
// Two viewpoints in Chat: the page reads current choices, the person reviews
// the complete AI request, ticks that they reviewed it, and only then starts
// it. Saved answers are read back from the original request.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const { shell } = require('./_shell');

const folder = path.resolve(__dirname, '../../maverick_dashboard');
const template = fs.readFileSync(path.join(folder, 'templates/chat.html'), 'utf8');
const panelStart = template.indexOf('<details class="panel cs-viewpoints"');
// The panel holds its own nested <details> (original history); it ends at the
// closing tag just before the template's {% endif %}.
const panelEnd = template.indexOf('</details>\n  {% endif %}', panelStart) + 10;
const panel = template.slice(panelStart, panelEnd);
const script = fs.readFileSync(path.join(folder, 'static/lightwork-viewpoints.js'), 'utf8');
const answer = {
  ran: true, rounds: 1, verdict: 'against', reason: 'The risks outweigh the gain.', key_point: 'Mondays are busy.', cost: 0.0123,
  turns: [{ side: 'for', text: 'It frees Fridays.' }, { side: 'against', text: '<img src=x onerror=alert(1)> Mondays are packed.' }]
};
const OPERATION = 'a'.repeat(32);
const CONTEXT = 'c'.repeat(64);
const current = { context: CONTEXT, revision: 'r'.repeat(64), ready: true, history: [] };
const review = { context: CONTEXT, operation: OPERATION, token: 'sealed:token',
  changes: [{ label: 'Question', after: 'Should we move the meeting?' }, { label: 'Spending limit', after: '$1.00' }] };
const saved = (result) => ({ operation: OPERATION, context: CONTEXT, confirmed: true, worker: 'done', question: 'Should we move the meeting?',
  result, message: result.ran ? 'These are the saved answers from your original request. Nothing was repeated.'
    : 'The original request ended without a complete answer. Nothing was repeated.' });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });

// `routes` answers by path after /api/v1/viewpoints ('' is the current choices).
async function fixture(routes = {}) {
  const dom = new JSDOM('<main>' + panel.replace(/\{\{[^}]*\}\}/g, 'x') + '</main>',
    { url: 'https://app.example/chat', runScripts: 'outside-only' });
  const w = shell(dom.window), calls = [];
  w.fetch = async (url, options = {}) => {
    calls.push({ url, options });
    const route = url.replace('/api/v1/viewpoints', '');
    const reply = Object.hasOwn(routes, route) ? routes[route] : { '': current, '/review': review, '/apply': saved(answer),
      ['/requests/' + OPERATION]: saved(answer) }[route];
    if (reply instanceof Response) return reply;
    if (reply === undefined) return json({ detail: 'Not found.' }, 404);
    return json(typeof reply === 'function' ? reply(options) : reply);
  };
  w.eval(script);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise(r => setTimeout(r, 0)); };
  await settle();
  const submit = () => w.document.getElementById('vp-form').dispatchEvent(new w.Event('submit', { cancelable: true }));
  const el = id => w.document.getElementById('vp-' + id);
  const posts = () => calls.filter(call => call.options.method === 'POST');
  const confirm = async () => {
    const tick = el('review').querySelector('input[type="checkbox"]');
    const start = Array.from(el('review').querySelectorAll('button')).find(b => /Start reviewed viewpoints/.test(b.textContent));
    assert.equal(start.disabled, true, 'nothing starts before the review is ticked');
    tick.checked = true; tick.dispatchEvent(new w.Event('change'));
    assert.equal(start.disabled, false);
    start.click();
    await settle();
  };
  return { w, calls, settle, submit, el, posts, confirm };
}

test('the panel is labelled and nothing runs until the person asks', async t => {
  assert.match(panel, /<label for="vp-question">/);
  assert.match(panel, /<label for="vp-rounds">/);
  assert.match(panel, /id="vp-status" role="status"/);
  const ui = await fixture();
  t.after(() => ui.w.close());
  assert.deepEqual(ui.calls.map(call => call.options.method), ['GET'], 'only the current choices are read');
  assert.match(ui.el('status').textContent, /Review your question and spending before starting/);
  ui.submit();
  await ui.settle();
  assert.equal(ui.posts().length, 0, 'an empty question is not sent');
});

test('sends the question and chosen depth for review, then shows both sides and the verdict as text', async t => {
  const ui = await fixture();
  t.after(() => ui.w.close());
  ui.el('question').value = 'Should we move the meeting?';
  ui.el('rounds').value = '3';
  ui.submit();
  await ui.settle();
  const [reviewCall] = ui.posts();
  assert.equal(reviewCall.url, '/api/v1/viewpoints/review');
  assert.deepEqual(JSON.parse(reviewCall.options.body), { question: 'Should we move the meeting?', rounds: 3, for_side: null, against_side: null,
    context: CONTEXT, revision: current.revision });
  assert.equal(reviewCall.options.headers['X-Lightwork-Viewpoints-Context'], CONTEXT);
  assert.match(ui.el('review').textContent, /Review this complete AI request.*Spending limit\$1\.00/s);
  assert.match(ui.el('status').textContent, /No AI work has started/);
  await ui.confirm();
  const apply = ui.posts()[1];
  assert.equal(apply.url, '/api/v1/viewpoints/apply');
  assert.deepEqual(JSON.parse(apply.options.body), { token: 'sealed:token', confirmed: true });
  const result = ui.el('result');
  assert.equal(result.hidden, false);
  assert.match(result.textContent, /case against stronger/);
  assert.match(result.textContent, /Why: The risks outweigh the gain\./);
  assert.match(result.textContent, /The case for.*It frees Fridays\./s);
  assert.equal(result.querySelector('img'), null, 'answers are shown as text only');
  assert.match(result.textContent, /This cost \$0\.01/);
  assert.match(ui.el('status').textContent, /Original answers are shown below\. No new AI work was started\./);
  assert.equal(ui.posts().length, 2, 'the original is read back, never started again');
});

test('a refusal shows its sentence; failures and odd answers stay plain', async t => {
  const limit = { ran: false, message: 'Your spending limit of $5.00 per day has been reached ($5.00 spent today).' };
  const refused = await fixture({ '/apply': saved(limit), ['/requests/' + OPERATION]: saved(limit) });
  t.after(() => refused.w.close());
  refused.el('question').value = 'Should we hire?';
  refused.submit();
  await refused.settle();
  await refused.confirm();
  assert.match(refused.el('result').textContent, /spending limit of \$5\.00/);
  assert.doesNotMatch(refused.el('result').textContent, /Verdict/);

  const failed = await fixture({ '/review': json({ detail: [{ loc: ['body'], msg: 'Traceback: boom' }] }, 503) });
  t.after(() => failed.w.close());
  failed.el('question').value = 'Should we hire?';
  failed.submit();
  await failed.settle();
  assert.equal(failed.el('status').textContent, 'The request could not be checked. Your entered question is kept.');
  assert.doesNotMatch(failed.el('status').textContent, /Traceback/);
  assert.equal(failed.el('question').value, 'Should we hire?');

  const odd = await fixture({ '/apply': saved({ ran: true, turns: 'nope' }), ['/requests/' + OPERATION]: saved({ ran: true, turns: 'nope' }) });
  t.after(() => odd.w.close());
  odd.el('question').value = 'Should we hire?';
  odd.submit();
  await odd.settle();
  await odd.confirm();
  assert.doesNotMatch(odd.el('result').textContent, /Verdict|nope/, 'an answer of the wrong shape is never shown');
});

test('chosen positions for each side are sent only when filled in', async t => {
  const ui = await fixture();
  t.after(() => ui.w.close());
  assert.match(panel, /<label for="vp-for">/);
  assert.match(panel, /<label for="vp-against">/);
  ui.el('question').value = 'Should we open on Sundays?';
  ui.el('for').value = 'Sunday trade is worth it';
  ui.submit();
  await ui.settle();
  const body = JSON.parse(ui.posts()[0].options.body);
  assert.equal(body.for_side, 'Sunday trade is worth it');
  assert.equal(body.against_side, null);
  assert.equal(body.rounds, 2);
});
