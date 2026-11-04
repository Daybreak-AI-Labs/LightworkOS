'use strict';
// Settings > Provider keys: after Save, Test connection or Remove key the row
// and the page header show the server's new state at once (no reload), the
// plain cause is announced, and the AI-stop link lands on the right row.
const {test} = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), {JSDOM} = require('jsdom');
const template = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/settings.html'), 'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const marker = "var forms = Array.prototype.slice.call(document.querySelectorAll('form[action^=\"/settings\"]'));";
const pageScript = (() => {
  const at = template.indexOf(marker);
  assert.ok(at > 0, 'settings page script found');
  const start = template.lastIndexOf('<script>', at) + '<script>'.length;
  return template.slice(start, template.indexOf('</script>', at));
})();

function header(text) {
  return `<section class="hero"><div class="hero-statebox" aria-live="polite"><div class="hero-statebox__row"><strong>${text}</strong></div></div></section>`;
}
function buttons(configured) {
  if (!configured) return '<div class="settings-row-form provider-row__buttons"></div>';
  return '<div class="settings-row-form provider-row__buttons">' +
    '<form method="post" action="/settings/providers/test"><input type="hidden" name="provider" value="openai"><button type="submit" class="btn">Test connection</button></form>' +
    '<form method="post" action="/settings/providers/clear" data-confirm="Remove the saved OpenAI key?" data-confirm-ok="Remove key"><input type="hidden" name="provider" value="openai"><button type="submit" class="btn btn--danger">Remove key</button></form>' +
    '</div>';
}
function row(label, reason, configured) {
  return '<div class="provider-row" data-settings-search-item id="provider-openai" role="group" aria-labelledby="provider-name-openai" data-ai-provider-focus>' +
    '<div class="provider-row__about"><div class="provider-row__name" id="provider-name-openai">OpenAI</div>' +
    `<div class="provider-row__readiness"><div class="integration-readiness"><div><span class="muted">Status:</span> <span class="badge">${label}</span></div>` +
    `<p class="muted integration-readiness__copy">${reason}</p></div></div></div>` +
    '<div class="provider-row__actions">' +
    '<form method="post" action="/settings/providers" class="settings-row-form"><input type="hidden" name="provider" value="openai">' +
    '<label class="settings-field"><span>OpenAI key</span><input class="input" id="provider-key-openai" type="password" name="api_key"></label>' +
    '<button type="submit" class="btn btn--primary">Save</button></form>' +
    buttons(configured) +
    '<p class="muted provider-row__status" data-provider-status role="status" aria-live="polite"></p>' +
    '</div></div>';
}
function page({head, label, reason, configured, saved = ''}) {
  return '<main>' + header(head) + (saved ? `<div class="panel settings-saved" role="status"><strong>Saved.</strong> ${saved}</div>` : '') +
    '<div id="settings-sections"><div class="section-head" data-settings-group="integrations" id="settings-integrations"><h2>Provider keys</h2></div>' +
    `<div class="panel" data-settings-group="integrations">${row(label, reason, configured)}</div></div></main>`;
}
const FAILED = 'Connection failed: Lightwork could not reach the service. Check the internet connection or the server address, then test again.';
const answers = {
  '/settings/providers': page({head: 'AI services: 1 set up · 0 connected', label: 'Key saved, not tested yet',
    reason: 'Key saved, not tested yet. Test it to make sure it works.', configured: true, saved: 'Provider keys updated.'}),
  '/settings/providers/test': page({head: 'AI services: 1 set up · 0 connected', label: FAILED,
    reason: 'Lightwork could not reach the service. Check the internet connection or the server address, then test again. Last tested just now.',
    configured: true, saved: 'Connection test finished. The result is shown next to the provider.'}),
  '/settings/providers/clear': page({head: 'AI services: 0 set up · 0 connected', label: 'Not set up',
    reason: 'Add the details to set up this service.', configured: false, saved: 'Provider keys updated.'}),
};

async function fixture({url = 'https://lightwork.example/settings', confirm = true} = {}) {
  const html = page({head: 'AI services: 0 set up · 0 connected', label: 'Not set up', reason: 'Add the details to set up this service.', configured: false});
  const dom = new JSDOM(html, {url, runScripts: 'outside-only', pretendToBeVisual: true});
  const {window} = dom, calls = [], confirms = [];
  window.fetch = async (target) => {
    const pathName = new URL(String(target)).pathname;
    calls.push(pathName);
    return new Response(answers[pathName], {status: 200, headers: {'Content-Type': 'text/html'}});
  };
  window.mvConfirm = async (message) => { confirms.push(message); return confirm; };
  window.mvErrorText = (failure, action) => 'Could not ' + action + '.';
  window.HTMLElement.prototype.scrollIntoView = function () {};
  window.eval(pageScript);
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((done) => setImmediate(done)); };
  await settle();
  const submit = (form) => form.dispatchEvent(new window.Event('submit', {bubbles: true, cancelable: true}));
  const $ = (selector) => window.document.querySelector(selector);
  return {window, document: window.document, calls, confirms, settle, submit, $};
}

test('saving a key updates the row and the header from the server answer', async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.$('#provider-key-openai').value = 'sk-test';
  ui.submit(ui.$('form[action="/settings/providers"]'));
  await ui.settle();
  assert.deepEqual(ui.calls, ['/settings/providers']);
  assert.match(ui.$('.hero-statebox').textContent, /1 set up · 0 connected/);
  assert.equal(ui.$('#provider-openai .badge').textContent, 'Key saved, not tested yet');
  const status = ui.$('#provider-openai [data-provider-status]').textContent;
  assert.match(status, /Provider keys updated/);
  assert.match(status, /Key saved, not tested yet/);
  assert.equal(ui.$('#provider-key-openai').value, '');
  assert.ok(ui.$('#provider-openai form[action="/settings/providers/test"]'), 'Test connection appears without a reload');
});

test('testing the connection shows the plain cause on the row and keeps focus', async (t) => {
  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.submit(ui.$('form[action="/settings/providers"]'));
  await ui.settle();
  const testButton = ui.$('form[action="/settings/providers/test"] button');
  testButton.focus();
  ui.submit(testButton.form);
  await ui.settle();
  assert.deepEqual(ui.calls, ['/settings/providers', '/settings/providers/test']);
  assert.equal(ui.$('#provider-openai .badge').textContent, FAILED);
  assert.match(ui.$('#provider-openai [data-provider-status]').textContent, /could not reach the service/);
  assert.equal(ui.document.activeElement, ui.$('form[action="/settings/providers/test"] button'),
    'focus moves to the re-rendered Test connection button');
  // The re-rendered buttons work again: a second test is a second request.
  ui.submit(ui.$('form[action="/settings/providers/test"]'));
  await ui.settle();
  assert.equal(ui.calls.filter((call) => call === '/settings/providers/test').length, 2);
});

test('removing a key asks first, then clears the row', async (t) => {
  const declined = await fixture({confirm: false});
  t.after(() => declined.window.close());
  declined.submit(declined.$('form[action="/settings/providers"]'));
  await declined.settle();
  declined.submit(declined.$('form[action="/settings/providers/clear"]'));
  await declined.settle();
  assert.equal(declined.confirms.length, 1);
  assert.deepEqual(declined.calls, ['/settings/providers'], 'nothing is removed without a yes');

  const ui = await fixture();
  t.after(() => ui.window.close());
  ui.submit(ui.$('form[action="/settings/providers"]'));
  await ui.settle();
  ui.submit(ui.$('form[action="/settings/providers/clear"]'));
  await ui.settle();
  assert.equal(ui.confirms.length, 1);
  assert.deepEqual(ui.calls, ['/settings/providers', '/settings/providers/clear']);
  assert.equal(ui.$('#provider-openai .badge').textContent, 'Not set up');
  assert.match(ui.$('.hero-statebox').textContent, /0 set up/);
  assert.equal(ui.$('form[action="/settings/providers/test"]'), null);
});

test('the AI-stop link lands on the provider row that needs attention', async (t) => {
  const ui = await fixture({url: 'https://lightwork.example/settings?focus=ai-provider'});
  t.after(() => ui.window.close());
  if (ui.document.readyState !== 'complete') ui.window.dispatchEvent(new ui.window.Event('load'));
  await ui.settle();
  assert.equal(ui.document.activeElement, ui.$('#provider-openai'));
});
