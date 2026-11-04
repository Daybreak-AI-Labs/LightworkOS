'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const root = path.resolve(__dirname, '../../maverick_dashboard');
const code = name => fs.readFileSync(path.join(root, 'static', name), 'utf8');
// Use the literal shipped catalog, whose Python loader separately validates
// placeholders. Each row uses JSON-compatible string literals.
const rows = fs.readFileSync(path.join(root, 'i18n_journey_task_controls.py'), 'utf8').split('\n')
  .map(line => line.trim()).filter(line => line.startsWith('("'))
  .map(line => JSON.parse('[' + line.slice(1, -2) + ']'));
const {shell} = require('./_shell');
// The two-viewpoints panel as Chat renders it (its nested history <details> included).
const chat = fs.readFileSync(path.join(root, 'templates', 'chat.html'), 'utf8');
const panelAt = chat.indexOf('<details class="panel cs-viewpoints"');
const viewpointsPanel = chat.slice(panelAt, chat.indexOf('</details>\n  {% endif %}', panelAt) + 10).replace(/\{\{[^}]*\}\}/g, 'x');
const settle = async () => { for (let n=0;n<20;n++) await new Promise(resolve => setImmediate(resolve)); };
function page(markup, language) {
  const dom = new JSDOM(markup, {url:'https://lightwork.invalid/chat/goal/4', runScripts:'outside-only', pretendToBeVisual:true});
  const index = ['en','fr','de','ja','zh'].indexOf(language);
  const catalog = Object.fromEntries(rows.map(row => [row[0], {text:row[index],lang:language}]));
  const payload = dom.window.document.createElement('script'); payload.id='lightwork-i18n-data'; payload.type='application/json';
  payload.textContent=JSON.stringify({language,locale:language,catalog}); dom.window.document.head.append(payload);
  dom.window.eval(code('lightwork-i18n.js'));
  dom.window.mvErrorText=()=> 'Could not complete the request.';
  return {dom,w:dom.window,d:dom.window.document,catalog};
}
for (const language of ['fr','de','ja','zh']) {
  test(language + ': planning controls translate while authored output stays verbatim', async t => {
    const p=page('<div id="planning-steps" data-goal="4"><button id="ps-run"></button><select id="ps-passes"><option value="2">2</option></select><div id="ps-result" hidden></div><p id="ps-status"></p></div>',language);
    t.after(()=>p.w.close()); p.w.setTimeout=fn=>{fn();return 0;};
    p.w.fetch=async url=>new Response(JSON.stringify(String(url).endsWith('/planning-steps') ? {job:'a'.repeat(32)} : {state:'done',result:{ran:true,plan:['The plan'],steps:[{step:'Reviews',output:'<img src=x> Saving.'}],reviews:[{verdict:'done',notes:'The case for'}],status:'done',cost:1.25}}));
    p.w.eval(code('lightwork-planning-steps.js')); p.d.getElementById('ps-run').click(); await settle();
    assert.equal(p.d.querySelector('#ps-result h3').textContent,p.catalog['The plan'].text);
    assert.equal(p.d.querySelector('#ps-result h3').lang,language);
    const sources=[...p.d.querySelectorAll('#ps-result [data-user-content]')];
    assert.ok(sources.some(node=>node.textContent==='The plan' && node.lang==='und'));
    assert.ok(sources.some(node=>node.textContent==='<img src=x> Saving.'));
    assert.equal(p.d.querySelector('#ps-result img'),null);
    assert.equal(p.d.getElementById('ps-status').textContent,p.catalog['The planning attempt is ready below.'].text);
    assert.match(p.d.querySelector('#ps-result').textContent,new RegExp(p.catalog['The AI review considered the request met.'].text.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  });
  test(language + ': viewpoints retain source labels and text under translated controls', async t=>{
    const p=page('<main>'+viewpointsPanel+'</main>',language);
    t.after(()=>p.w.close()); shell(p.w);
    const context='c'.repeat(64), operation='b'.repeat(32);
    const saved={operation,context,confirmed:true,worker:'done',message:'Saved answers.',question:'Decision',
      result:{ran:true,turns:[{side:'for',text:'The case for'}],verdict:'for',reason:'Verdict',key_point:'<script>kept</script>',cost:0.005}};
    const replies={'':{context,revision:'r'.repeat(64),ready:true,history:[]},
      '/review':{context,operation,token:'sealed',changes:[{label:'Question',after:'Decision'}]},'/apply':saved,['/requests/'+operation]:saved};
    p.w.fetch=async url=>new Response(JSON.stringify(replies[String(url).replace('/api/v1/viewpoints','')]),{headers:{'Content-Type':'application/json'}});
    p.w.eval(code('lightwork-viewpoints.js')); await settle();
    assert.equal(p.d.getElementById('vp-status').textContent,p.catalog['Review your question and spending before starting. Original answers are available below.'].text);
    p.d.getElementById('vp-question').value='Decision';
    p.d.getElementById('vp-form').dispatchEvent(new p.w.Event('submit',{cancelable:true}));await settle();
    const review=p.d.getElementById('vp-review');
    assert.equal(review.querySelector('h3').textContent,p.catalog['Review this complete AI request'].text);
    assert.equal(review.querySelector('label span').textContent,p.catalog['I reviewed the full question, positions, connected model and spending.'].text);
    assert.equal(review.querySelector('dd').lang,'und','the reviewed question stays as written');
    const tick=review.querySelector('input[type="checkbox"]'); tick.checked=true; tick.dispatchEvent(new p.w.Event('change'));
    review.querySelector('button').click(); await settle();
    const verdict=p.d.querySelector('#vp-result .cs-viewpoints__verdict');
    assert.equal(verdict.querySelector('h3').textContent,p.catalog.Verdict.text);
    assert.equal(verdict.querySelector('p span').textContent,p.catalog['Why:'].text);
    assert.equal(p.d.querySelector('#vp-result li').textContent,'The case for');
    assert.equal(p.d.querySelector('#vp-result li').lang,'und');
    assert.equal(p.d.querySelector('#vp-result script'),null);
    assert.equal(p.d.getElementById('vp-status').lang,language);
    assert.equal(p.d.getElementById('vp-status').textContent,p.catalog['Original answers are shown below. No new AI work was started.'].text);
  });
  test(language + ': result access loss clears private content and localizes recovery', async t=>{
    const p=page('<section id="answer-panel" data-goal="4" data-context="mine" data-status="done">private</section><p id="answer-refresh-status"></p><button id="answer-refresh"></button>',language);
    t.after(()=>p.w.close());p.w.fetch=async()=>({ok:false,status:403});
    p.w.eval(code('lightwork-answer-panel.js'));await settle();
    assert.equal(p.d.getElementById('answer-panel').textContent,'');
    assert.equal(p.d.getElementById('answer-refresh-status').lang,language);
    assert.equal(p.d.getElementById('answer-refresh-status').textContent,p.catalog['Access to the saved result changed. Sign in or reopen the authorized task to continue.'].text);
  });
}
