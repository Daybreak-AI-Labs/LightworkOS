// Real template/CSP/JavaScript in Chromium, explicitly synthetic setup responses.
// No real workspace setup mutation, credential probe or provider write occurs.
const {test,expect}=require('@playwright/test');
test.skip(process.env.LIGHTWORK_BROWSER_SHOW_VENDOR_SETUP!=='1',
  'Synthetic setup recovery requires LIGHTWORK_BROWSER_SHOW_VENDOR_SETUP=1.');
const SETUP=/\/api\/v1\/vendor-setup(?:\?.*)?$/;

test.beforeEach(async({context,page,baseURL})=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin
    ?route.continue():route.abort('blockedbyclient'));
  page.__uncaught=[];page.__failedRequests=[];
  page.on('pageerror',error=>page.__uncaught.push(error.message));
  page.on('requestfailed',request=>page.__failedRequests.push({path:new URL(request.url()).pathname,
    method:request.method(),failure:request.failure()?.errorText}));
});
test.afterEach(async({page,context},info)=>{
  await info.attach('recovery-full-page',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  await info.attach('request-failures',{body:Buffer.from(JSON.stringify(page.__failedRequests,null,2)),contentType:'application/json'});
  expect(page.__uncaught).toEqual([]);
  await context.unrouteAll({behavior:'ignoreErrors'});
});

function initial(){return{
  context:'1'.repeat(64),configuration:'2'.repeat(64),revision:0,principal:'user:browser-reviewer',
  modules_enabled:true,connections_enabled:true,owner_locked:false,owner_source:'initial',
  eligible_owners:['user:browser-reviewer'],
  binding:{enable:true,resource_owner:'',ticket_connection:'',document_connection:'',reviewed_uploads:true},
  connections:[
    {name:'jira-first',connector:'jira',revision:'j1',has_token:true,base_url:'https://jira.example.test'},
    {name:'jira-corrected',connector:'jira',revision:'j2',has_token:true,base_url:'https://jira.example.test'},
    {name:'drive-review',connector:'gdrive',revision:'d1',has_token:true,base_url:'https://www.googleapis.com'},
  ],live_provider_verified:false,
  readiness:{state:'setup_required',configuration_complete:false,actions:[],live_provider_verified:false,
    deployment:{supported:true,message:'Configured for one persistent Lightwork installation.'}},
};}
async function routedServer(page,mode){
  let current=initial();const mutations=[];
  await page.route(SETUP,async route=>{
    const request=route.request();
    if(request.method()==='GET')return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(current)});
    if(request.method()!=='PUT')throw new Error('Unexpected synthetic setup operation');
    const payload=request.postDataJSON();mutations.push(payload);
    if(mode==='validation'&&mutations.length===1)return route.fulfill({status:422,contentType:'application/json',body:JSON.stringify({
      detail:[{loc:['body','ticket'],msg:'Invalid PRIVATE_VALIDATION_MESSAGE',input:'PRIVATE_REJECTED_VALUE',ctx:{secret:'PRIVATE_CONTEXT'}}], // pragma: allowlist secret -- synthetic rejected validation metadata
    })});
    current={...initial(),revision:1,owner_locked:true,owner_source:'saved',eligible_owners:[],
      binding:{enable:true,resource_owner:payload.resource_owner,ticket_connection:payload.ticket,
        document_connection:payload.document,reviewed_uploads:true},
      readiness:{...initial().readiness,state:'configured',configuration_complete:true,actions:[]}};
    if(mode==='lost-response')return route.abort('connectionreset');
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(current)});
  });
  return{mutations};
}
async function choose(page,document='drive-review'){
  await page.locator('#vs-resource-owner').selectOption('user:browser-reviewer');
  await page.locator('#vs-ticket').selectOption('jira-first');
  await page.locator('#vs-document').selectOption(document);
  await page.locator('#vs-confirm').focus();await page.locator('#vs-confirm').press('Space');
  await expect(page.locator('#vs-save')).toBeEnabled();
}
async function capture(page,info,name){
  expect(await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  await info.attach(name,{body:await page.locator('#vs-panel').screenshot(),contentType:'image/png'});
}

test('desktop validation preserves choices, names the field, and saves only after readback and correction',async({page},info)=>{
  const server=await routedServer(page,'validation');
  await page.setViewportSize({width:1280,height:1050});await page.goto('/third-party/vendor-onboarding');
  await expect(page.locator('#vs-readiness-summary')).toHaveText('Setup required');
  await choose(page);await page.locator('#vs-save').click();
  await expect(page.locator('#vs-status')).toContainText('Jira connection');
  await expect(page.locator('#vs-status')).not.toContainText('PRIVATE_');
  await expect(page.locator('#vs-resource-owner')).toHaveValue('user:browser-reviewer');
  await expect(page.locator('#vs-ticket')).toHaveValue('jira-first');
  await expect(page.locator('#vs-document')).toHaveValue('drive-review');
  for(const id of ['resource-owner','ticket','document','confirm','save'])await expect(page.locator('#vs-'+id)).toBeDisabled();
  await expect(page.locator('#vs-confirm')).not.toBeChecked();
  expect(server.mutations).toHaveLength(1);
  await capture(page,info,'validation-retained-disabled-controls-1280');
  await page.locator('#vs-refresh').click();
  await expect(page.locator('#vs-status')).toContainText('valid choices were kept');
  await expect(page.locator('#vs-document')).toHaveValue('drive-review');
  expect(server.mutations).toHaveLength(1);
  await page.locator('#vs-ticket').selectOption('jira-corrected');
  await expect(page.locator('#vs-confirm')).not.toBeChecked();
  await expect(page.locator('#vs-save')).toBeDisabled();
  await page.locator('#vs-confirm').focus();await page.locator('#vs-confirm').press('Space');
  await page.locator('#vs-save').click();
  await expect(page.locator('#vs-readiness-summary')).toHaveText('Setup saved; provider access still needs checking');
  expect(server.mutations).toHaveLength(2);
  expect(server.mutations[1]).toMatchObject({expected_revision:0,resource_owner:'user:browser-reviewer',
    ticket:'jira-corrected',ticket_revision:'j2',document:'drive-review',document_revision:'d1',confirm:true});
  expect(page.__failedRequests).toEqual([]);
  await capture(page,info,'validation-corrected-saved-controls-1280');
});

test('mobile lost committed save reconciles canonical state without resending the mutation',async({page},info)=>{
  const server=await routedServer(page,'lost-response');
  await page.setViewportSize({width:375,height:1050});await page.goto('/third-party/vendor-onboarding');
  await expect(page.locator('#vs-readiness-summary')).toHaveText('Setup required');
  await choose(page,'');await page.locator('#vs-save').click();
  await expect(page.locator('#vs-status')).toContainText('Refresh setup');
  await expect(page.locator('#vs-ticket')).toHaveValue('jira-first');
  await expect(page.locator('#vs-resource-owner')).toHaveValue('user:browser-reviewer');
  await expect(page.locator('#vs-save')).toBeDisabled();await expect(page.locator('#vs-confirm')).not.toBeChecked();
  await page.locator('#vs-form').evaluate(form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  expect(server.mutations).toHaveLength(1);
  await capture(page,info,'lost-save-retained-disabled-controls-375');
  await page.locator('#vs-refresh').click();
  await expect(page.locator('#vs-readiness-summary')).toHaveText('Setup saved; provider access still needs checking');
  await expect(page.locator('#vs-status')).toContainText('Current saved settings are shown because setup changed');
  await expect(page.locator('#vs-resource-owner')).toBeDisabled();
  await expect(page.locator('#vs-ticket')).toHaveValue('jira-first');await expect(page.locator('#vs-document')).toHaveValue('');
  await expect(page.locator('#vs-confirm')).not.toBeChecked();await expect(page.locator('#vs-save')).toBeDisabled();
  expect(server.mutations).toHaveLength(1);
  expect(page.__failedRequests).toHaveLength(1);
  expect(page.__failedRequests[0]).toMatchObject({path:'/api/v1/vendor-setup',method:'PUT'});
  await capture(page,info,'lost-save-reconciled-controls-375');
});
