'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{JSDOM}=require('jsdom');
const folder=path.resolve(__dirname,'../../maverick_dashboard');
const installLocale=require('./helpers/recovery_review_i18n');
const settle=async()=>{for(let n=0;n<8;n++)await new Promise(done=>setImmediate(done));};
const voices=[{name:'System English',lang:'en-US',default:true},{name:'Français naturel',lang:'fr-FR'},{name:'日本語',lang:'ja-JP'},{name:'eSpeak',lang:'de-DE'}];
function fixture(language='und'){
  const dom=new JSDOM('<html lang="fr"><body><div id="result"></div><button id="read-aloud"></button></body></html>',{url:'https://app.example',runScripts:'outside-only'}),w=dom.window,spoken=[],requests=[];
  const result=w.document.getElementById('result');if(language!==null)result.lang=language;
  result.textContent='Stop reading Art. 28 GDPR https://example.test/texte 日本語';
  w.SpeechSynthesisUtterance=function(text){this.text=text;};w.speechSynthesis={getVoices:()=>voices,addEventListener(){},cancel(){},pause(){},resume(){},speak:value=>spoken.push(value)};
  w.fetch=async(url,options)=>{requests.push({url,options});return {ok:false};};
  installLocale(w,{catalog:{'Read aloud':{text:'Lire à voix haute',lang:'fr'},'Pause reading':{text:'Pause',lang:'fr'},'Resume reading':{text:'Reprendre',lang:'fr'},'Stop reading':{text:'Arrêter la lecture',lang:'fr'},'Read the result aloud':{text:'Lire le résultat à voix haute',lang:'fr'},'Skip code and tables when reading':{text:'Ignorer le code et les tableaux',lang:'fr'},'Reading stopped.':{text:'Lecture arrêtée.',lang:'fr'}}});
  w.eval(fs.readFileSync(path.join(folder,'static/lightwork-voice.js'),'utf8'));
  w.eval(fs.readFileSync(path.join(folder,'static/lightwork-read-aloud.js'),'utf8'));
  const button=w.document.getElementById('read-aloud');w.lwReadAloud(button);
  return {dom,w,spoken,requests,result,button};
}
test('unknown result language keeps exact text and browser default independently of French interface',async t=>{
  for(const language of ['und',null]){const ui=fixture(language);t.after(()=>ui.dom.window.close());
    assert.equal(ui.button.textContent,'Lire à voix haute');assert.equal(ui.button.lang,'fr');ui.button.click();await settle();
    assert.equal(JSON.parse(ui.requests[0].options.body).text,ui.result.textContent);assert.equal(ui.spoken[0].text,ui.result.textContent);assert.equal(ui.spoken[0].voice.name,'System English');
    assert.equal(ui.button.textContent,'Arrêter la lecture');ui.button.click();assert.equal(ui.w.document.querySelector('[role="status"]').textContent,'Lecture arrêtée.');assert.equal(ui.result.textContent,'Stop reading Art. 28 GDPR https://example.test/texte 日本語');
  }
});
test('declared content language selects a matching voice without translating or English rewriting',async t=>{
  const ui=fixture('fr-CA');t.after(()=>ui.dom.window.close());ui.button.click();await settle();
  assert.equal(ui.spoken[0].voice.name,'Français naturel');assert.equal(ui.spoken[0].lang,'fr-FR');assert.equal(ui.spoken[0].text,ui.result.textContent);
  assert.deepEqual(Array.from(ui.w.lwVoice.options(),voice=>voice.name).sort(),['Français naturel','System English','日本語'].sort());
});
test('explicit selected voice is honored across languages and an unavailable saved voice does not force English',async t=>{
  const ui=fixture('fr-CA');t.after(()=>ui.dom.window.close());ui.w.lwVoice.setVoice('日本語');ui.button.click();await settle();assert.equal(ui.spoken[0].voice.name,'日本語');assert.equal(ui.spoken[0].text,ui.result.textContent);
  ui.w.lwVoice.setVoice('Removed voice');assert.equal(ui.w.lwVoice.best('fr-CA').name,'Français naturel');
  voices[0].default=false;try{assert.equal(ui.w.lwVoice.best('und'),null);}finally{voices[0].default=true;}
});
