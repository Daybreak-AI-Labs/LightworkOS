'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-file-selection.js'), 'utf8');

test('removing one pasted attachment preserves other files and the written draft', () => {
  const dom = new JSDOM('<form><textarea>Keep my answer</textarea><input id="reply-files" type="file" multiple></form>', {runScripts: 'outside-only'});
  const { window } = dom, input = window.document.getElementById('reply-files');
  let files = [{name: 'first.pdf', size: 500, type: 'application/pdf', lastModified: 1}, {name: 'second.txt', size: 100, type: 'text/plain', lastModified: 2}];
  Object.defineProperty(input, 'files', {get: () => files, set: value => { files = value; }});
  window.DataTransfer = class {
    constructor() { this.files = []; this.items = {add: file => this.files.push(file)}; }
  };
  window.eval(script);
  const remove = Array.from(window.document.querySelectorAll('button')).find(button => button.textContent === 'Remove first.pdf');
  remove.click();
  assert.deepEqual(files.map(file => file.name), ['second.txt']);
  assert.equal(window.document.querySelector('textarea').value, 'Keep my answer');
  assert.equal(window.document.querySelectorAll('li').length, 1);
  dom.window.close();
});

test('an unsupported DataTransfer preserves the batch and explains clear-all recovery', () => {
  const dom = new JSDOM('<form><input id="reply-files" type="file" multiple></form>', {runScripts: 'outside-only'});
  const { window } = dom, input = window.document.getElementById('reply-files');
  const files = [{name: 'keep.pdf', size: 50, type: 'application/pdf'}];
  Object.defineProperty(input, 'files', {get: () => files});
  window.eval(script);
  Array.from(window.document.querySelectorAll('button')).find(button => button.textContent === 'Remove keep.pdf').click();
  assert.equal(input.files.length, 1);
  assert.match(window.document.querySelector('[role="status"]').textContent, /Remove all selected files/);
  dom.window.close();
});

test('localized file controls isolate source names and format file sizes', () => {
  const dom = new JSDOM('<form><textarea>Keep مرحبا</textarea><input id="reply-files" type="file" multiple></form>', {runScripts: 'outside-only'});
  const {window} = dom, input = window.document.getElementById('reply-files');
  const sourceName = 'Save مرحبا <img>.pdf';
  const files = [{name: sourceName, size: 1234567, type: '', lastModified: 1}];
  Object.defineProperty(input, 'files', {get: () => files});
  const catalog = {
    'Files selected for this message': {text: 'Fichiers sélectionnés pour ce message', lang: 'fr'},
    'Remove all selected files': {text: 'Retirer tous les fichiers sélectionnés', lang: 'fr'},
    'Remove {file}': {text: 'Retirer {file}', lang: 'fr'},
    'Unknown type': {text: 'Type inconnu', lang: 'fr'},
  };
  const config = window.document.createElement('script'); config.id = 'lightwork-i18n-data'; config.type = 'application/json';
  config.textContent = JSON.stringify({language: 'fr', locale: 'fr-CA', catalog}); window.document.head.append(config);
  window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-i18n.js'), 'utf8'));
  window.eval(script);
  assert.equal(window.document.querySelector('ul').lang, 'fr');
  assert.equal(window.document.querySelector('li bdi').textContent, sourceName);
  assert.equal(window.document.querySelector('li bdi').lang, 'und');
  assert.equal(window.document.querySelector('li button').textContent, 'Retirer ' + sourceName);
  assert.equal(window.document.querySelector('li button').lang, 'fr');
  assert.ok(window.document.querySelector('li').textContent.includes(new Intl.NumberFormat('fr-CA', {style:'unit',unit:'kilobyte',unitDisplay:'short'}).format(Math.ceil(files[0].size / 1024))));
  assert.equal(window.document.querySelector('img'), null);
  assert.equal(window.document.querySelector('textarea').value, 'Keep مرحبا');
  dom.window.close();
});

test('first-task voice feedback uses the chosen locale and keeps dictated content verbatim', () => {
  const dom = new JSDOM('<form class="composer"><input lang="und" dir="auto" data-user-content name="title"><details><textarea name="description"></textarea></details><button id="mic-btn" type="button"></button><button id="send-btn" type="button"></button><p id="composer-hint"><span lang="fr">Votre brouillon reste ici.</span></p></form>', {runScripts: 'outside-only'});
  const {window} = dom, doc = window.document;
  const config = doc.createElement('script'); config.id = 'lightwork-i18n-data'; config.type = 'application/json';
  config.textContent = JSON.stringify({language:'fr',locale:'fr-CA',catalog:{'Listening… click the mic again to stop.':{text:'Écoute en cours… cliquez à nouveau sur le micro pour arrêter.',lang:'fr'}}}); doc.head.append(config);
  window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-i18n.js'), 'utf8'));
  let recognition;
  window.SpeechRecognition = class {constructor(){recognition=this;} start(){}};
  const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/chat.html'), 'utf8');
  window.eval(source.slice(source.indexOf('  function chatCopy('), source.indexOf('  // A prepared template')));
  const start = source.indexOf('  (function () {', source.indexOf('  // Voice commands:'));
  window.eval(source.slice(start, source.indexOf('  })();', start) + '  })();'.length));
  doc.getElementById('mic-btn').click();
  assert.equal(recognition.lang, 'fr-CA');
  assert.equal(doc.getElementById('composer-hint').lang, 'fr');
  assert.match(doc.getElementById('composer-hint').textContent, /^Écoute/);
  const content = 'Save مرحبا <img>';
  recognition.onresult({results:[[{transcript:content}]]}); recognition.onend();
  assert.equal(doc.querySelector('input[name="title"]').value, content);
  assert.equal(doc.querySelector('img'), null);
  assert.equal(doc.getElementById('composer-hint').textContent, 'Votre brouillon reste ici.');
  assert.equal(doc.querySelector('#composer-hint span').lang, 'fr');
  dom.window.close();
});

test('prepared template uses real input selectors and a translated review notice without submitting', async () => {
  const dom = new JSDOM('<form class="composer"><input type="hidden" name="connection_references" value="{}"><input lang="und" dir="auto" data-user-content name="title"><details><textarea name="description"></textarea></details><p id="template-draft-notice" hidden></p></form>', {runScripts:'outside-only',url:'https://local.invalid/chat'});
  const {window} = dom, doc = window.document;
  const source = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/chat.html'), 'utf8');
  const notice = 'Template ready. Review the task and details, then choose Start task when you are ready.';
  const config = doc.createElement('script'); config.id = 'lightwork-i18n-data'; config.type = 'application/json';
  config.textContent = JSON.stringify({language:'fr',locale:'fr-CA',catalog:{[notice]:{text:'Le modèle est prêt. Vérifiez la tâche et les détails.',lang:'fr'}}}); doc.head.append(config);
  window.eval(fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/static/lightwork-i18n.js'), 'utf8'));
  window.eval(source.slice(source.indexOf('  function chatCopy('),source.indexOf('  // A prepared template')));
  const draft = {title:'Save مرحبا <img>', description:'Exact original task body',context:'verified',created_at:Date.now(),connection_references:{account:{connector:'chat',revision:'exact-reviewed'}}};
  window.sessionStorage.setItem('lightwork:template-draft:v1',JSON.stringify(draft));
  window.fetch = async()=>({ok:true,json:async()=>({context:'verified'})});
  let submits=0;doc.querySelector('form').addEventListener('submit',e=>{e.preventDefault();submits++;});
  const start=source.indexOf('  (async function receiveTemplateDraft()');
  await window.eval(source.slice(start,source.indexOf('  })();',start)+'  })();'.length));
  assert.equal(doc.querySelector('input[name="title"]').value,draft.title);
  assert.equal(doc.querySelector('textarea').value,draft.description);
  assert.deepEqual(JSON.parse(doc.querySelector('input[name="connection_references"]').value),draft.connection_references);
  assert.equal(doc.querySelector('details').open,true);
  assert.equal(doc.getElementById('template-draft-notice').lang,'fr');
  assert.match(doc.getElementById('template-draft-notice').textContent,/^Le modèle/);
  assert.equal(doc.querySelector('img'),null);assert.equal(submits,0);
  dom.window.close();
});
