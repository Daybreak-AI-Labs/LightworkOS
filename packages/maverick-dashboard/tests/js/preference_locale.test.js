const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const assets=path.join(__dirname,'../../maverick_dashboard/static');
const wait=async()=>{for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));};

test('interface preference review is localized while custom guidance, revision and draft survive',async()=>{
  const initial={values:{interface_language:'en',output_style:'custom',custom_style:'Save مرحبا <img src=x>',chat_model:'',chat_effort:'',chat_specialist:'',favorites:[],today_cards:[]},sources:{interface_language:'personal',output_style:'personal',custom_style:'personal'},locked:[],context:'scope',revision:'before',destinations:{},effective_by_scope:{}};
  const catalog={
    'Save':{text:'Enregistrer',lang:'fr'},
    'Personal':{text:'Personnel',lang:'fr'},
    'Effective source: {source}':{text:'Source effective : {source}',lang:'fr'},
    'Interface language':{text:'Langue de l’interface',lang:'fr'},
    'Preferences saved for {scope}. Future work uses these defaults; running work is unchanged.':{text:'Préférences enregistrées pour {scope}. Le travail en cours ne change pas.',lang:'fr'},
    'Interface language saved. It applies on your next page load. Save any other drafts before reloading.':{text:'Langue enregistrée. Elle s’appliquera au prochain chargement. Enregistrez les autres brouillons avant de recharger.',lang:'fr'},
  };
  const dom=new JSDOM('<form id="preference-form"><select id="preference-scope"><option value="personal">Personal</option></select><select data-pref="interface_language"><option value="en">English</option><option value="fr">Français</option></select><span data-source-for="interface_language"></span><select id="preference-chat_model" data-pref="chat_model"><option value="" lang="fr">Utiliser les paramètres de l’espace</option></select><select id="preference-chat_effort" data-pref="chat_effort"><option value="" lang="fr">Profondeur habituelle du modèle</option></select><select id="preference-chat_specialist" data-pref="chat_specialist"><option value="" lang="fr">Laisser Lightwork choisir l’équipe</option></select><p id="preference-chat-status"></p><p id="preference-specialist-status"></p><select data-pref="output_style"><option value="custom">Custom</option></select><textarea data-pref="custom_style"></textarea><p id="preference-preview" lang="und" data-user-content></p><p id="preference-status"></p><button type="submit">Save</button></form><section id="preference-original" hidden><button type="button" id="preference-original-read">Check original save</button><button type="button" id="preference-original-new" hidden>Start a fresh review</button><p id="preference-original-status" role="status"></p></section><select data-ui-preference="interface_language" data-saved-value="en"><option value="en">English</option><option value="fr">Français</option></select>',{url:'https://lightwork.invalid/preferences',runScripts:'outside-only'});
  const w=dom.window,doc=w.document;
  for(const [id,value] of Object.entries({'preference-data':initial,'preference-thread':null,'preference-styles':{},'lightwork-i18n-data':{language:'fr',locale:'fr-CA',catalog}})){const script=doc.createElement('script');script.id=id;script.type='application/json';script.textContent=JSON.stringify(value);doc.head.append(script);}
  const requests=[],reviews=[];w.mvConfirm=async(message,options)=>{reviews.push({message,options});return true;};
  w.fetch=async(url,options)=>{requests.push({url,options});return {ok:true,json:async()=>({...initial,revision:'after',values:{...initial.values,interface_language:'fr'}})};};
  w.eval(fs.readFileSync(path.join(assets,'lightwork-i18n.js'),'utf8'));
  function retainedDefaults(){
    const defaults=['chat_model','chat_effort','chat_specialist'].map(key=>doc.getElementById('preference-'+key).firstElementChild);
    for(const option of defaults)assert.equal(option.lang,'fr');
    assert.deepEqual(defaults.map(option=>option.textContent),['Utiliser les paramètres de l’espace','Profondeur habituelle du modèle','Laisser Lightwork choisir l’équipe']);
  }
  w.eval(fs.readFileSync(path.join(assets,'lightwork-preferences.js'),'utf8'));
  retainedDefaults();
  assert.equal(doc.getElementById('preference-preview').textContent,initial.values.custom_style);
  assert.equal(doc.getElementById('preference-preview').lang,'und');
  assert.equal(doc.querySelector('[data-source-for]').textContent,'Source effective : Personnel');
  const field=doc.querySelector('[data-pref="interface_language"]');field.value='fr';field.dispatchEvent(new w.Event('change',{bubbles:true}));
  doc.getElementById('preference-form').dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await wait();
  assert.equal(reviews.length,1);assert.equal(reviews[0].options.productCopy,true);assert.equal(reviews[0].options.values.scope,'Personnel');
  const body=JSON.parse(requests[0].options.body);assert.deepEqual(body.changes,{interface_language:'fr'});assert.equal(body.expected_revision,'before');assert.equal(body.context,'scope');
  assert.equal(doc.querySelector('[data-ui-preference]').dataset.savedValue,'fr');
  retainedDefaults();
  assert.match(doc.getElementById('preference-status').textContent,/prochain chargement/);
  assert.equal(doc.getElementById('preference-status').lang,'fr');
  assert.equal(doc.querySelector('textarea').value,initial.values.custom_style);
  assert.equal(doc.querySelector('img'),null);assert.equal(w.location.pathname,'/preferences');
  w.close();
});
