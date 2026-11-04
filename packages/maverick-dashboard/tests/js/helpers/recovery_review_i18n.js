'use strict';
const fs=require('node:fs'),path=require('node:path');
const folder=path.resolve(__dirname,'../../../maverick_dashboard');
// Use the actual browser localization and confirmation controllers. This tiny
// test catalog deliberately contains user-content collisions as well as copy.
module.exports=function install(window,{language='fr',catalog={}}={}){
  const script=window.document.createElement('script');script.id='lightwork-i18n-data';
  script.type='application/json';script.textContent=JSON.stringify({language,locale:language==='fr'?'fr-CA':language,catalog});
  window.document.head.append(script);
  window.eval(fs.readFileSync(path.join(folder,'static/lightwork-i18n.js'),'utf8'));
  window.document.body.insertAdjacentHTML('beforeend','<dialog id="mv-confirm"><p id="mv-confirm-msg"></p><button id="mv-confirm-ok"></button><button id="mv-confirm-cancel"></button></dialog>');
  const dialog=window.document.getElementById('mv-confirm');
  dialog.showModal=()=>{dialog.open=true;};dialog.close=()=>{dialog.open=false;};
  window.matchMedia=()=>({matches:false,addEventListener(){},removeEventListener(){}});
  window.eval(fs.readFileSync(path.join(folder,'static/lightwork-ui.js'),'utf8'));
};
