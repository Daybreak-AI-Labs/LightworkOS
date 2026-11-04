'use strict';
// The chat composer's recovery wiring fills in server-rendered markup and
// never moves the composer: moving a focused field drops focus, and wrapping
// the docked composer after load shifted it up on phones.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const source = fs.readFileSync(path.join(__dirname, '../../maverick_dashboard/static/lightwork-chat-drafts.js'), 'utf8');

const HOST = '<div class="cs-dock"><div data-draft-host>' +
  '<section class="draft-recovery" data-draft-panel inert><p>Checking for a recovery copy…</p></section>' +
  '<form action="/chat/send"><textarea name="title" autofocus></textarea><textarea name="description"></textarea>' +
  '<input name="connection_references" value="[]"></form>' +
  '<p class="muted draft-note" data-draft-note><span data-draft-note-for="kept">Recovery copies keep unsent text.</span>' +
  '<span data-draft-note-for="restored" aria-hidden="true">Text restored for review.</span></p></div></div>';

function page(html, create) {
  const dom = new JSDOM(html, {url: 'http://localhost/chat', runScripts: 'outside-only', pretendToBeVisual: true});
  const calls = [];
  dom.window.mvDraftRecovery = {create: options => {
    calls.push(options);
    if (!create) return null;
    const panel = dom.window.document.createElement('section');
    panel.className = 'draft-recovery'; panel.id = 'live-panel';
    options.host.prepend(panel);  // what the real library does
    return {panel: panel, clear: async () => true};
  }};
  return {dom, calls, doc: dom.window.document};
}

test('starting recovery keeps the focused composer in place and focused', () => {
  const {dom, calls, doc} = page(HOST, true);
  const form = doc.querySelector('form');
  const field = doc.querySelector('[name="title"]');
  const host = doc.querySelector('[data-draft-host]');
  field.focus();
  field.value = 'Half-typed request';
  assert.equal(doc.activeElement, field);
  dom.window.eval(source);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].host, host);
  assert.equal(form.parentElement, host, 'the composer is never moved into a new wrapper');
  assert.equal(doc.activeElement, field, 'focus stays in the message box');
  assert.equal(field.value, 'Half-typed request');
  // The live panel takes the placeholder's place, above the composer.
  assert.equal(doc.querySelector('[data-draft-panel]'), null);
  assert.equal(host.firstElementChild.id, 'live-panel');
  assert.equal(host.firstElementChild.nextElementSibling, form);
  assert.equal(host.querySelectorAll('.draft-recovery').length, 1);
  assert.equal(host.lastElementChild, doc.querySelector('[data-draft-note]'));
  assert.equal(host.querySelectorAll('p.muted').length, 1, 'no second note is appended');
  dom.window.close();
});

test('restoring a copy switches the note without replacing it', () => {
  const {dom, calls, doc} = page(HOST, true);
  dom.window.eval(source);
  const note = doc.querySelector('[data-draft-note]');
  const kept = note.querySelector('[data-draft-note-for="kept"]');
  const restored = note.querySelector('[data-draft-note-for="restored"]');
  calls[0].restore({title: 'Recovered request', description: 'Details', connection_references: '[]'});
  assert.equal(doc.querySelector('[name="title"]').value, 'Recovered request');
  assert.equal(doc.querySelector('[data-draft-note]'), note);
  assert.equal(kept.getAttribute('aria-hidden'), 'true');
  assert.equal(restored.hasAttribute('aria-hidden'), false);
  assert.equal(note.textContent.includes('Recovery copies keep unsent text.'), true, 'the longer note keeps its space');
  dom.window.close();
});

test('an unavailable recovery service leaves no placeholder behind', () => {
  const {dom, doc} = page(HOST, false);
  dom.window.eval(source);
  assert.equal(doc.querySelector('[data-draft-panel]'), null);
  assert.equal(doc.querySelector('form').parentElement, doc.querySelector('[data-draft-host]'));
  dom.window.close();
});

test('without the server-rendered wrapper nothing is inserted or wrapped', () => {
  const html = '<div class="ask"><form id="answer-form" action="/chat/goal/7/reply"><textarea name="message"></textarea></form></div>';
  const {dom, calls, doc} = page(html, true);
  const form = doc.querySelector('form');
  const before = doc.body.innerHTML;
  dom.window.eval(source);
  assert.equal(calls.length, 0);
  assert.equal(form.dataset.draftReady, 'true');
  assert.equal(doc.body.innerHTML.replace(' data-draft-ready="true"', ''), before);
  dom.window.close();
});
