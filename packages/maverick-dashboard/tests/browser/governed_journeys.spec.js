const {test,expect}=require('@playwright/test');

test.beforeEach(async({context,page,baseURL})=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  page.__uncaught=[];page.on('pageerror',error=>page.__uncaught.push(error.message));
});
test.afterEach(async({page,context},info)=>{
  await context.unrouteAll({behavior:'ignoreErrors'});
  await info.attach('rendered-state',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  expect(page.__uncaught).toEqual([]);
});
async function fits(page){
  const result=await page.evaluate(()=>({width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth}));
  expect(result.scroll).toBeLessThanOrEqual(result.width+1);
}
async function ok(response){expect(response.ok(),await response.text()).toBeTruthy();return response.json();}

test('saved consent content is listed and editing prepares the next version without saving',async({page,request})=>{
  const API='/api/v1/consent/publishing';
  for(const version of [1,2])await ok(await request.post(API+'/purposes/browser-analytics/versions',{data:{version,expected_current_version:version-1,
    idempotency_key:'browser-purpose-'+version,title_key:'purpose.title',description_key:'purpose.description',lawful_basis:'consent',required:false,default_choice:version===1?'denied':'granted'}}));
  await page.setViewportSize({width:375,height:812});await page.goto('/consent/publishing');
  const table=page.locator('#cpp-resource-table');
  const row=table.getByRole('row').filter({hasText:'Browser analytics'});
  await expect(row).toContainText('2');
  let saved=0;page.on('request',r=>{if(r.method()==='POST'&&r.url().includes(API))saved++;});
  await row.getByRole('button',{name:'Edit: Browser analytics'}).click();
  const form=page.locator('#cpp-resource');await expect(form).toBeVisible();
  await expect(form.locator('[name="resource_name"]')).toHaveValue('Browser analytics');
  await expect(form.locator('[name="resource_name"]')).toHaveAttribute('readonly','');
  await expect(form.locator('[name="version"]')).toHaveValue('3');
  await expect(form.locator('[name="expected_current_version"]')).toHaveValue('2');
  await expect(form.locator('[name="default_choice"]')).toHaveValue('granted');
  await expect(form.getByLabel('Legal reason')).toHaveValue('consent');
  expect(saved).toBe(0);await fits(page);
});

test('explicit consent publication resolves through an enrolled public client, rejects stale withdrawal and preserves history',async({page,request},info)=>{
  const API='/api/v1/consent/publishing',origin='https://browser-publish.example.test',notice='a'.repeat(64),property='browser-publish-web';
  await ok(await request.put(API+'/properties/'+property,{data:{kind:'web',consent_group_id:'browser-publish-group',expected_revision:0,
    idempotency_key:'browser-publish-property',web_domains:['browser-publish.example.test'],origin_allowlist:[origin]}}));
  async function version(resource,data){return ok(await request.post(API+'/'+resource+'/versions',{data:{version:1,expected_current_version:0,
    idempotency_key:'browser-publish-'+resource.replaceAll('/','-'),...data}}));}
  await version('purposes/browser-publish-analytics',{title_key:'purpose.title',description_key:'purpose.description',lawful_basis:'consent',required:false,default_choice:'denied'});
  await version('notices/browser-publish-notice',{title_key:'notice.title',body_key:'notice.body',document_sha256:notice});
  await version('translations/browser-publish-copy/en-US',{messages:{'purpose.title':'Synthetic analytics','purpose.description':'Measure synthetic service performance',
    'notice.title':'Synthetic privacy notice','notice.body':'Choose whether this fixture may use analytics.','template.title':'Synthetic privacy choices',
    'template.body':'Control this local test configuration.','action.accept':'Accept all','action.reject':'Reject all','action.manage':'Manage preferences',
    'action.save':'Save choices','brand.display_name':'Synthetic fixture','brand.heading':'Synthetic privacy','brand.description':'Local browser acceptance only.'}});
  await version('themes/browser-publish-brand',{display_name_key:'brand.display_name',heading_key:'brand.heading',description_key:'brand.description',
    primary_color:'174b3f',primary_text_color:'ffffff',surface_color:'ffffff',text_color:'16211d'});
  await version('templates/browser-publish-banner',{surface:'banner',title_key:'template.title',body_key:'template.body',theme_token_id:'browser-publish-brand',theme_token_version:1,
    actions:{accept_all:'action.accept',reject_all:'action.reject',manage_preferences:'action.manage',save_preferences:'action.save'}});
  await version('rule-groups/browser-publish-rules',{rules:[{rule_id:'global',priority:1,locales:['en-US'],default_locale:'en-US',consent_mode:'opt_in',
    purposes:[{id:'browser-publish-analytics',version:1}],notice:{id:'browser-publish-notice',version:1},template:{id:'browser-publish-banner',version:1},
    translation_catalog_id:'browser-publish-copy',translation_versions:{'en-US':1}}]});
  await ok(await request.post('/api/v1/consent/policies',{data:{policy_id:'browser-publish-policy',version:1,
    purposes:{'browser-publish-analytics':'consent'},notice_sha256:notice,effective_at:Date.now()/1000-60}}));
  await page.setViewportSize({width:375,height:900});await page.goto('/consent/publishing');
  const propertyRow=page.locator('#cpp-property-table').getByRole('row').filter({hasText:'Browser publish web'});
  await propertyRow.getByRole('button',{name:'Preview and publish: Browser publish web'}).click();
  const promotion=page.locator('#cpp-promotion');await expect(promotion).toBeVisible();
  await expect(promotion.getByLabel('Display rules to publish')).toHaveValue('browser-publish-rules|1');
  // The page carries the request reference and revisions; a person never types them.
  expect(await promotion.locator('[name="idempotency_key"]').inputValue()).toMatch(/^[A-Za-z0-9][A-Za-z0-9_.:/-]{7,}$/);
  await expect(promotion.locator('[name="expected_publication_revision"]')).toHaveValue('0');
  let publishes=0;page.on('request',req=>{if(req.url().endsWith('/publish'))publishes++;});
  await promotion.getByRole('button',{name:'Preview',exact:true}).click();
  await expect(page.locator('#cpp-status')).toHaveText('Preview ready. Nothing has been published.');
  await expect(page.locator('#cpp-preview-result')).toContainText('Synthetic privacy choices');
  await expect(page.locator('#cpp-preview-result')).toContainText('Synthetic analytics');
  expect(publishes).toBe(0);expect((await ok(await request.get(API+'/properties/'+property+'/history'))).items).toHaveLength(0);
  await promotion.getByRole('button',{name:'Publish version',exact:true}).click();
  await expect(page.locator('#mv-confirm-msg')).toContainText('Publish to Browser publish web?');await page.locator('#mv-confirm-ok').click();
  await expect(page.locator('#cpp-status')).toHaveText('Published to Browser publish web.');expect(publishes).toBe(1);
  const published=(await ok(await request.get(API+'/properties/'+property+'/history'))).items[0];expect(published.action).toBe('publish');
  const enrolled=await ok(await request.post('/api/v1/consent/public-clients',{data:{property_id:property,client_kind:'browser',browser_origin:origin,
    jurisdiction:'global',country_code:'US',region_code:'',default_locale:'en-US',rule_group_id:'browser-publish-rules',rule_group_version:1,
    policy_id:'browser-publish-policy',policy_version:1}}));
  const publicHeaders={Origin:origin,Authorization:'ConsentPublic '+enrolled.client_credential};
  expect((await request.get('/api/v1/public/consent/configuration')).status()).toBe(401);
  expect((await request.get('/api/v1/public/consent/configuration',{headers:{...publicHeaders,Origin:'https://other.example.test'}})).status()).toBe(401);
  const resolved=await ok(await request.get('/api/v1/public/consent/configuration',{headers:publicHeaders}));
  expect(resolved.allowed).toBe(true);expect(resolved.publication.publication_id).toBe(published.publication_id);
  expect(resolved.policy_id).toBe('browser-publish-policy');
  await propertyRow.getByRole('button',{name:'History: Browser publish web'}).click();
  await expect(page.locator('#cpp-history').getByRole('row')).toHaveCount(2);
  // Withdrawing opens a complete review of the exact banner first; nothing is withdrawn yet.
  await propertyRow.getByRole('button',{name:'Withdraw: Browser publish web'}).click();
  const review=page.locator('#cpp-withdrawal-review');await expect(review).toBeVisible();
  await expect(review).toContainText('Current banner');await expect(review).toContainText('Published version 1');
  // Someone else publishes after the review: the reviewed withdrawal is now stale and must be refused.
  await ok(await request.post(API+'/properties/'+property+'/publish',{data:{rule_group_id:'browser-publish-rules',rule_group_version:1,
    expected_property_revision:1,expected_publication_revision:1,idempotency_key:'browser-publish-elsewhere'}}));
  const rejected=page.waitForResponse(response=>response.url().endsWith('/withdrawal-requests/apply'));
  await review.getByRole('button',{name:'Withdraw reviewed banner',exact:true}).click();
  expect((await rejected).status()).toBe(409);
  await expect(page.locator('#cpp-withdrawal-status')).toContainText('This reviewed change was refused');
  await expect(page.locator('#cpp-withdrawal-status')).not.toContainText('revision');
  expect((await ok(await request.get(API+'/properties/'+property+'/history'))).items).toHaveLength(2);
  await page.reload();
  await page.locator('#cpp-property-table').getByRole('button',{name:'Withdraw: Browser publish web'}).click();
  const fresh=page.locator('#cpp-withdrawal-review');await expect(fresh).toContainText('Published version 2');
  const applied=page.waitForResponse(response=>response.url().endsWith('/withdrawal-requests/apply'));
  await fresh.getByRole('button',{name:'Withdraw reviewed banner',exact:true}).click();
  expect((await applied).status()).toBe(200);
  await expect(page.locator('#cpp-withdrawal-status')).toHaveText('Your exact original request withdrew the reviewed banner. Nothing was repeated.');
  expect((await request.get('/api/v1/public/consent/configuration',{headers:publicHeaders})).status()).toBe(409);
  const history=await ok(await request.get(API+'/properties/'+property+'/history'));expect(history.items.map(item=>item.action)).toEqual(['withdraw','publish','publish']);
  await page.locator('#cpp-withdrawal-status').scrollIntoViewIfNeeded();await info.attach('consent-published-and-withdrawn',{body:await page.screenshot(),contentType:'image/png'});await fits(page);
});

test('a failed recovery save retries the exact operation and survives a page reload',async({page})=>{
  await page.goto('/workflow-builder');const recovery=page.locator('.draft-recovery');
  await expect(recovery).toContainText('Draft recovery is ready');
  const attempts=[];
  const interrupted=async route=>{
    if(route.request().method()!=='PUT')return route.continue();
    attempts.push(route.request().postDataJSON());
    if(attempts.length===1)return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Synthetic connection interruption'})});
    return route.continue();
  };
  await page.route('**/api/v1/drafts/*',interrupted);
  await page.locator('#wf-brief').fill('Recover my incomplete workflow after a failed connection');
  // The person sees a plain sentence, never the server's raw error text.
  await expect(recovery).toContainText('Could not save the recovery copy');await expect(recovery).not.toContainText('Synthetic connection interruption');
  await expect(page.locator('#wf-brief')).toHaveValue('Recover my incomplete workflow after a failed connection');
  await recovery.getByRole('button',{name:'Retry recovery'}).click();
  await expect(recovery).toContainText('Recovery copy saved');expect(attempts).toHaveLength(2);expect(attempts[1]).toEqual(attempts[0]);
  await page.unroute('**/api/v1/drafts/*',interrupted);await page.reload();
  await expect(recovery).toContainText('A recovery copy is available');
  await recovery.getByRole('button',{name:'Restore recovery copy'}).click();await page.locator('#mv-confirm-ok').click();
  await expect(page.locator('#wf-brief')).toHaveValue('Recover my incomplete workflow after a failed connection');
  await expect(page.locator('#wf-status')).not.toContainText('Drafting');await fits(page);
});

test('a rejected website address is explained plainly and keeps the other fields',async({page})=>{
  await page.goto('/consent/publishing');
  await page.getByRole('button',{name:'Add a website or app'}).first().click();
  const form=page.locator('#cpp-property');await expect(form).toBeVisible();
  await form.getByLabel('Name').fill('Browser consumer web');await form.getByLabel('Consent group').fill('Browser consumers');
  await form.locator('[name="web_domains"]').fill('not a valid address!');
  const rejected=page.waitForResponse(r=>r.request().method()==='PUT'&&r.url().endsWith('/properties/browser-consumer-web'));
  await form.getByRole('button',{name:'Save property',exact:true}).click();const rejection=await rejected;expect(rejection.status()).toBe(422);
  // The page generated the request reference it sent; a person never types it.
  const enrollmentKey=rejection.request().postDataJSON().idempotency_key;expect(enrollmentKey).toMatch(/^[A-Za-z0-9][A-Za-z0-9_.:/-]{7,}$/);
  await expect(page.locator('#cpp-status')).toContainText('Check the website addresses');
  await expect(form.locator('[name="web_domains"]')).toHaveAttribute('aria-invalid','true');
  await expect(form.getByLabel('Consent group')).toHaveValue('Browser consumers');
  // A retry of the same operation keeps the same generated reference.
  await expect(form.locator('[name="idempotency_key"]')).toHaveValue(enrollmentKey);
  await form.locator('[name="web_domains"]').fill('browser-consumer.example.test');
  await expect(form.locator('[name="idempotency_key"]')).not.toHaveValue(enrollmentKey);
  await form.getByRole('button',{name:'Save property',exact:true}).click();
  await expect(page.locator('#cpp-status')).toHaveText('Saved Browser consumer web.');
  await expect(page.locator('#cpp-property-table')).toContainText('browser-consumer.example.test');
  await page.setViewportSize({width:320,height:800});await fits(page);
});

test('workspace recovery creates a real local snapshot and retains signed temporary restore evidence after reload',async({page},info)=>{
  test.setTimeout(150000); // Real archive verification and fresh-process restore, including Windows filesystem latency.
  await page.setViewportSize({width:375,height:812});await page.goto('/workspace/recovery');
  await expect(page.locator('#wrec-key-create')).toBeEnabled();
  const key=page.waitForEvent('download');await page.locator('#wrec-key-create').click();
  expect((await key).suggestedFilename()).toBe('Lightwork-recovery-key.txt');
  await expect(page.locator('#wrec-create')).toBeEnabled();
  const created=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/api/v1/recovery/snapshots'),{timeout:60000});
  await page.locator('#wrec-create').click();await ok(await created);
  await expect(page.locator('#wrec-status')).toContainText('Snapshot created and verified');
  await page.locator('#wrec-inspect').click();await expect(page.locator('#wrec-result')).toContainText('files verified');
  const archive=page.waitForEvent('download');await page.locator('#wrec-download').click();
  expect((await archive).suggestedFilename()).toMatch(/^Lightwork-snapshot-.+\.tgz$/);
  const restored=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/drill'),{timeout:60000});
  await page.locator('#wrec-drill').click();await ok(await restored);await expect(page.locator('#wrec-status')).toContainText('Local restore test passed');
  await expect(page.locator('#wrec-result')).toContainText('Your live workspace was not changed');
  const snapshot=await page.locator('#wrec-snapshot').inputValue();
  let reportLoads=0;page.on('request',r=>{if(r.url().endsWith('/drill/report'))reportLoads++;});
  await page.reload();await expect(page.locator('#wrec-snapshot')).toBeEnabled();
  await page.locator('#wrec-snapshot').selectOption(snapshot);
  expect(reportLoads).toBe(0);await expect(page.locator('#wrec-drill-report-download')).toBeDisabled();
  await page.locator('#wrec-drill-report-load').click();await expect(page.locator('#wrec-drill-report')).toBeVisible();
  await expect(page.locator('#wrec-drill-report-build')).toContainText('tested application build matches');
  await expect(page.locator('#wrec-drill-report-summary')).toContainText('old when tested');
  const saved=page.waitForEvent('download');await page.locator('#wrec-drill-report-download').click();
  const download=await saved;expect(download.suggestedFilename()).toMatch(/^Lightwork-restore-test-[a-f0-9]{32}\.json$/);
  const report=JSON.parse(require('node:fs').readFileSync(await download.path(),'utf8'));
  expect(report.authentication).toBeTruthy();expect(report.snapshot).toBe(snapshot);
  expect(report.restored).toBe(true);expect(report.post_restore_verified).toBe(true);expect(report.restore_authorized).toBe(false);
  expect(report.live_workspace_changed).toBe(false);expect(report.external_stores_tested).toBe(false);
  expect(report.file_count).toBeGreaterThan(0);expect(report.archive_sha256).toMatch(/^[a-f0-9]{64}$/);
  await page.setViewportSize({width:320,height:1000});await page.locator('#wrec-drill-report-load').scrollIntoViewIfNeeded();
  const widths=await page.locator('#wrec-drill-report').evaluate(el=>({client:el.clientWidth,scroll:el.scrollWidth}));
  expect(widths.scroll).toBeLessThanOrEqual(widths.client+1);
  await info.attach('recovery-retained-restore-test-320',{body:await page.screenshot(),contentType:'image/png'});
  const interrupted=route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Synthetic retained report interruption'})});
  await page.route('**/api/v1/recovery/snapshots/*/drill/report',interrupted);
  await page.locator('#wrec-drill-report-load').click();await expect(page.locator('#wrec-status')).toContainText('retained report interruption');
  await expect(page.locator('#wrec-drill-report')).toBeHidden();await expect(page.locator('#wrec-snapshot')).toHaveValue(snapshot);
  await page.unroute('**/api/v1/recovery/snapshots/*/drill/report',interrupted);
  await page.locator('#wrec-drill-report-load').click();await expect(page.locator('#wrec-drill-report')).toBeVisible();
  await page.route('**/api/v1/recovery/snapshots/*/drill/report/download',route=>route.fulfill({status:403,contentType:'text/html',body:'<p>Synthetic permission expiry</p>'}));
  await page.locator('#wrec-drill-report-download').click();await expect(page.locator('#wrec-status')).toContainText('reload this page');
  await expect(page.locator('#wrec-drill-report-summary')).toBeEmpty();await expect(page.locator('#wrec-identity')).toBeEmpty();
  await expect(page.locator('#wrec-drill-report-download')).toBeDisabled();await expect(page.locator('#wrec-drill-report-load')).toBeDisabled();
  await expect(page.locator('#wrec-prepare')).toBeDisabled();await fits(page);
});

test('separately retained keys rehearse recognized encrypted records in a fresh process without installing shared keys',async({page,request},info)=>{
  test.setTimeout(90000);
  await page.goto('/flows/designer');
  const draftContext=await page.locator('meta[name="lightwork-draft-context"]').getAttribute('content');
  const slot=require('node:crypto').createHash('sha256').update('custody-browser-rehearsal').digest('hex');
  const current=await ok(await request.get('/api/v1/drafts/'+slot,{headers:{'X-Lightwork-Draft-Context':draftContext}}));
  await ok(await request.put('/api/v1/drafts/'+slot,{headers:{'X-Lightwork-Draft-Context':draftContext},data:{
    expected_revision:current.revision,operation_id:'custody-browser-draft',payload:{brief:'Synthetic retained-key rehearsal task'}}}));
  await page.setViewportSize({width:320,height:1000});await page.goto('/workspace/recovery');
  await expect(page.locator('#wrec-refresh')).toBeEnabled();
  if(await page.locator('#wrec-key-create').isEnabled()){
    const key=page.waitForEvent('download');await page.locator('#wrec-key-create').click();await key;
  }
  await page.locator('#wrec-create').click();await expect(page.locator('#wrec-status')).toContainText('Snapshot created and verified');
  const snapshot=await page.locator('#wrec-snapshot').inputValue();
  await page.getByText("Keep a separate copy of this computer's encryption keys",{exact:true}).click();
  await page.locator('#wrec-encryption-confirm').check();
  const escrow=page.waitForEvent('download');await page.locator('#wrec-encryption-download').click();
  const custodyBytes=require('node:fs').readFileSync(await (await escrow).path());
  const upload={name:'separately-retained.zip',mimeType:'application/zip',buffer:custodyBytes};
  let starts=0,exportedAgain=0,startHeaders;
  page.on('request',r=>{
    if(r.url().endsWith('/custody-test')){starts++;startHeaders=r.headers();}
    if(r.url().includes('/encryption-keys/download'))exportedAgain++;
  });
  await page.locator('#wrec-custody-file').setInputFiles(upload);
  await expect(page.locator('#wrec-custody-test')).toBeDisabled();expect(starts).toBe(0);
  await page.locator('#wrec-custody-confirm').check();
  const completed=page.waitForResponse(r=>r.url().endsWith('/custody-test'));
  await page.locator('#wrec-custody-test').click();const report=await ok(await completed);
  await expect(page.locator('#wrec-custody-report')).toBeVisible();
  expect(starts).toBe(1);expect(exportedAgain).toBe(0);
  expect(startHeaders['x-lightwork-confirm-custody-test']).toBe('true');expect(startHeaders['x-lightwork-snapshot-sha256']).toBe(report.archive_sha256);
  expect(report.custody_sha256).toBe(require('node:crypto').createHash('sha256').update(custodyBytes).digest('hex'));
  expect(report.snapshot).toBe(snapshot);expect(report.fresh_process).toBe(true);expect(report.key_source).toBe('uploaded-custody-copy');
  expect(report.checks.reduce((sum,row)=>sum+row.verified,0)).toBeGreaterThan(0);
  expect(report.checks.reduce((sum,row)=>sum+row.failed,0)).toBe(0);
  expect(report.coverage_complete).toBe(false);expect(report.restore_authorized).toBe(false);expect(report.live_workspace_changed).toBe(false);expect(report.external_stores_tested).toBe(false);
  await expect(page.locator('#wrec-custody-file')).toHaveValue('');await expect(page.locator('#wrec-custody-confirm')).not.toBeChecked();
  await expect(page.locator('#wrec-prepare')).toBeDisabled();
  await page.reload();await expect(page.locator('#wrec-snapshot')).toBeEnabled();await page.locator('#wrec-snapshot').selectOption(snapshot);
  await expect(page.locator('#wrec-custody-report-download')).toBeDisabled();
  await page.locator('#wrec-custody-report-load').click();await expect(page.locator('#wrec-custody-report')).toBeVisible();expect(starts).toBe(1);
  const signed=page.waitForEvent('download');await page.locator('#wrec-custody-report-download').click();
  const saved=JSON.parse(require('node:fs').readFileSync(await (await signed).path(),'utf8'));
  expect(saved.report_id).toBe(report.report_id);expect(saved.authentication).toBeTruthy();expect(saved.custody_sha256).toBe(report.custody_sha256);
  await page.locator('details:has(#wrec-custody-checks) > summary').click();await expect(page.locator('details:has(#wrec-custody-checks) > summary')).toHaveText('Technical details');
  const width=await page.locator('#wrec-custody-report').evaluate(el=>({client:el.clientWidth,scroll:el.scrollWidth}));expect(width.scroll).toBeLessThanOrEqual(width.client+1);
  await page.locator('#wrec-custody-status').scrollIntoViewIfNeeded();await info.attach('retained-key-rehearsal-320',{body:await page.screenshot(),contentType:'image/png'});await fits(page);
  await page.setViewportSize({width:1280,height:1200});await page.locator('#wrec-custody-status').scrollIntoViewIfNeeded();
  expect(await page.locator('#wrec-custody-report').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBeTruthy();await fits(page);
  await info.attach('retained-key-rehearsal-1280',{body:await page.screenshot(),contentType:'image/png'});
  await page.setViewportSize({width:320,height:1000});
  await page.locator('#wrec-custody-file').setInputFiles({name:'damaged-custody.zip',mimeType:'application/zip',buffer:Buffer.from('Synthetic invalid retained-key copy')});
  await page.locator('#wrec-custody-confirm').check();
  const refused=page.waitForResponse(r=>r.url().endsWith('/custody-test'));
  await page.locator('#wrec-custody-test').click();expect((await refused).status()).toBe(409);
  await expect(page.locator('#wrec-custody-file')).toHaveValue('');await expect(page.locator('#wrec-custody-report-download')).toBeDisabled();
  await expect(page.locator('#wrec-snapshot')).toHaveValue(snapshot);
  await page.locator('#wrec-custody-report-load').click();await expect(page.locator('#wrec-custody-report')).toBeVisible();
  await expect(page.locator('#wrec-custody-identity')).toContainText(report.report_id);
  await page.route('**/api/v1/recovery/snapshots/*/custody-test/report/download',route=>route.fulfill({status:401,contentType:'text/html',body:'<p>Synthetic sign-in expiry</p>'}));
  await page.locator('#wrec-custody-report-download').click();await expect(page.locator('#wrec-status')).toContainText('reload this page');
  await expect(page.locator('#wrec-custody-identity')).toBeEmpty();await expect(page.locator('#wrec-custody-checks')).toBeEmpty();
  await expect(page.locator('#wrec-custody-test')).toBeDisabled();await expect(page.locator('#wrec-custody-report-load')).toBeDisabled();
});

test('recovery comparison pages real protected differences, downloads captured evidence and clears interrupted or expired access',async({page,request},info)=>{
  test.setTimeout(60000);
  await page.goto('/flows/designer');
  const draftContext=await page.locator('meta[name="lightwork-draft-context"]').getAttribute('content');
  expect(draftContext).toBeTruthy();
  await page.setViewportSize({width:320,height:900});await page.goto('/workspace/recovery');
  await expect(page.locator('#wrec-status')).toContainText('Review coverage');
  if(await page.locator('#wrec-key-create').isEnabled()){
    const key=page.waitForEvent('download');await page.locator('#wrec-key-create').click();await key;
  }
  await expect(page.locator('#wrec-create')).toBeEnabled();
  const created=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/api/v1/recovery/snapshots'),{timeout:60000});
  await page.locator('#wrec-create').click();await ok(await created);
  await expect(page.locator('#wrec-status')).toContainText('Snapshot created and verified');
  const snapshot=await page.locator('#wrec-snapshot').inputValue();
  for(let index=0;index<55;index++){
    const slot=require('node:crypto').createHash('sha256').update('recovery-comparison-fixture-'+index).digest('hex');
    const current=await ok(await request.get('/api/v1/drafts/'+slot,{headers:{'X-Lightwork-Draft-Context':draftContext}}));
    const response=await request.put('/api/v1/drafts/'+slot,{headers:{'X-Lightwork-Draft-Context':draftContext},data:{
      expected_revision:current.revision,operation_id:'browser-comparison-operation-'+index,payload:{brief:'Synthetic comparison draft body '+index}
    }});
    expect(response.status()).toBe(200);
  }
  expect((await request.post('/api/v1/facts',{data:{key:'browser_recovery_comparison',value:'Synthetic database content must not enter the report'}})).status()).toBe(204);
  let restoreRequests=0;page.on('request',req=>{if(/\/recovery\/(restore|.*\/prepare|installation\/authorize)$/.test(new URL(req.url()).pathname))restoreRequests++;});
  const compared=page.waitForResponse(r=>r.request().method()==='POST'&&/\/api\/v1\/recovery\/snapshots\/[^/]+\/compare$/.test(new URL(r.url()).pathname));
  await page.locator('#wrec-compare').press('Enter');
  const compareResponse=await compared;await compareResponse.finished();
  console.log(`recovery comparison initial request: ${Math.round(compareResponse.request().timing().responseEnd)} ms`);
  await expect(page.locator('#wrec-comparison-report')).toBeVisible();
  await expect(page.locator('#wrec-comparison-items > li')).toHaveCount(50);
  await expect(page.locator('#wrec-comparison-next')).toBeEnabled();
  await expect(page.locator('#wrec-prepare')).toBeDisabled();
  expect(await page.locator('#wrec-comparison-report').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBeTruthy();await fits(page);
  await page.locator('#wrec-comparison-summary').scrollIntoViewIfNeeded();
  await info.attach('recovery-captured-comparison-320',{body:await page.screenshot(),contentType:'image/png'});
  await page.locator('#wrec-comparison-next').click();
  await expect(page.locator('#wrec-comparison-previous')).toBeEnabled();
  const downloading=page.waitForEvent('download');await page.locator('#wrec-comparison-download').click();
  const download=await downloading;expect(download.suggestedFilename()).toMatch(/^Lightwork-recovery-comparison-.+\.json$/);
  const report=JSON.parse(await require('node:fs/promises').readFile(await download.path(),'utf8'));
  expect(report.total_changes).toBeGreaterThan(50);expect(report.protected_changes).toBeGreaterThan(0);
  expect(report.items.some(item=>item.protected&&item.path.endsWith('world.db'))).toBeTruthy();
  expect(report.authentication).toBeTruthy();expect(report.restore_authorized).toBe(false);expect(report.snapshot.id).toBe(snapshot);
  expect(JSON.stringify(report)).not.toContain('Synthetic database content must not enter the report');
  expect(JSON.stringify(report)).not.toContain('Synthetic comparison draft body');
  const interrupted=route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Synthetic comparison storage interruption'})});
  await page.getByText('Use a recovery key you already have',{exact:true}).click();
  await page.locator('#wrec-key-input').fill('Synthetic pending recovery key');
  await page.route('**/api/v1/recovery/snapshots/*/comparison',interrupted);
  await page.locator('#wrec-comparison-previous').click();
  await expect(page.locator('#wrec-status')).toContainText('Synthetic comparison storage interruption');
  await expect(page.locator('#wrec-key-input')).toHaveValue('Synthetic pending recovery key');
  await expect(page.locator('#wrec-snapshot')).toHaveValue(snapshot);
  await expect(page.locator('#wrec-comparison-report')).toBeHidden();await expect(page.locator('#wrec-comparison-download')).toBeDisabled();
  await page.unroute('**/api/v1/recovery/snapshots/*/comparison',interrupted);
  await page.locator('#wrec-compare').click();await expect(page.locator('#wrec-comparison-report')).toBeVisible();
  await page.route('**/api/v1/recovery/snapshots/*/comparison',route=>route.fulfill({status:401,contentType:'text/html',body:'<p>Synthetic expired sign-in</p>'}));
  await page.locator('#wrec-comparison-next').click();await expect(page.locator('#wrec-status')).toContainText('reload');
  await expect(page.locator('#wrec-key-input')).toHaveValue('');await expect(page.locator('#wrec-comparison-items')).toBeEmpty();
  await expect(page.locator('#wrec-identity')).toBeEmpty();await expect(page.locator('#wrec-compare')).toBeDisabled();
  expect(restoreRequests).toBe(0);await fits(page);
});

test('pilot preparation freezes four unrun tasks and preserves an observation after failed save',async({page},info)=>{
  // Every pilot change is saved through its complete review: read it, confirm, then save.
  const saveReviewed=async()=>{
    const review=page.locator('#op-guided-review');
    await expect(review.getByRole('heading',{name:'Review every detail before saving'})).toBeVisible();
    const save=review.getByRole('button',{name:'Save reviewed change'});await expect(save).toBeDisabled();
    await review.getByRole('checkbox',{name:'I reviewed the complete source, scope and proposed change.'}).check();
    await save.click();
  };
  await page.goto('/outcome-pilots');
  await page.locator('#op-plan-details > summary').click();
  await page.getByText('Prepare a task without starting it',{exact:true}).click();
  const preparation=page.locator('#op-prepare');
  await expect(page.locator('#op-specialist option')).not.toHaveCount(1);
  for(let i=1;i<=4;i++){
    await preparation.locator('[name="title"]').fill('Browser prepared case '+i);
    await page.locator('#op-specialist').selectOption({index:1});
    await preparation.locator('[name="description"]').fill('Synthetic held task; no provider execution.');
    await preparation.getByRole('button',{name:'Save prepared task'}).click();await saveReviewed();
    await expect(page.locator('#op-prepared')).toContainText('Prepared: Browser prepared case '+i);
    await expect(preparation.getByRole('button')).toBeEnabled();
  }
  const plan=page.locator('#op-plan');
  await plan.locator('[name="title"]').fill('Browser comparison pilot');await plan.locator('[name="customer"]').fill('Synthetic internal team');
  await plan.locator('[name="workflow"]').fill('Review identical prepared cases');await plan.locator('[name="criteria"]').fill('Human-reviewed evidence and all limitations recorded');
  for(let i=0;i<4;i++)await page.locator('#op-planned-cases select').nth(i).selectOption({label:'Task: Browser prepared case '+(i+1)});
  await plan.getByRole('button',{name:'Save and freeze plan'}).click();await saveReviewed();
  await expect(page.locator('#op-report')).toContainText('0 accepted / 4 planned');
  const details=page.locator('#op-report > details').first();await details.locator('summary').click();
  const form=details.locator('form');await form.locator('[name="baseline_minutes"]').fill('75');
  await form.locator('[name="evidence"]').fill('Synthetic timing sheet; no customer evidence');await form.locator('[name="note"]').fill('Partial observation; no claim of savings');
  const reject=route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Synthetic interruption before save'})});
  // The interruption hits the observation's review request; nothing is saved.
  await page.route('**/api/v1/outcome-pilot-controls/review',reject);
  await form.getByRole('button',{name:'Save observation'}).click();await expect(page.locator('#op-status')).toContainText('Could not save that.');await expect(page.locator('#op-status')).not.toContainText('Synthetic interruption');
  await expect(form.locator('[name="baseline_minutes"]')).toHaveValue('75');await expect(form.locator('[name="note"]')).toHaveValue('Partial observation; no claim of savings');
  await page.unroute('**/api/v1/outcome-pilot-controls/review',reject);
  await form.getByRole('button',{name:'Save observation'}).click();await saveReviewed();await expect(page.locator('#op-status')).toContainText('observation is recorded');
  await expect(page.locator('#op-report')).toContainText('0 current complete pairs');
  const costs=page.locator('#op-cost-form');await costs.getByRole('button',{name:'Find billing receipts'}).click();
  await expect(costs.getByRole('status')).toContainText('matching source lines');
  await costs.locator('select').selectOption({index:1});
  await expect(costs).toContainText('Net admitted amount: USD 10.000000001');
  await costs.locator('input[type="number"]').nth(0).fill('25');await costs.locator('input[type="number"]').nth(1).fill('75');
  await costs.locator('textarea').fill('Synthetic internal attribution only; not provider invoice acceptance.');await costs.locator('input[type="checkbox"]').check();
  const confirmLabel=costs.locator('label:has(input[type="checkbox"])');
  const checkboxBox=await confirmLabel.locator('input').boundingBox(),captionBox=await confirmLabel.locator('span:not(.mv-required)').boundingBox();
  expect(checkboxBox.x+checkboxBox.width).toBeLessThanOrEqual(captionBox.x);
  await costs.getByRole('button',{name:'Save reviewed allocation'}).click();
  await expect(page.locator('#op-provider-costs')).toContainText('Current allocated provider cost: USD 10.000000001');
  await page.getByText('Current allocated provider cost: USD 10.000000001',{exact:true}).scrollIntoViewIfNeeded();
  await info.attach('allocated-provider-cost',{body:await page.screenshot(),contentType:'image/png'});
  const download=page.waitForEvent('download');await page.locator('#op-export').click();
  expect((await download).suggestedFilename()).toBe('workflow-pilot-report.json');
  await page.setViewportSize({width:320,height:800});await fits(page);
});

test('held GRC delivery clears expired access and requires fresh human confirmation without resending',async({page,request},info)=>{
  const fixture=await (await request.get('/__browser_fixture')).json();
  await page.setViewportSize({width:375,height:812});await page.goto('/security/governance');
  const form=page.locator('#gov-grc-recovery');await form.locator('[name="delivery"]').selectOption(fixture.grc_delivery);
  await page.locator('#gov-grc-inspect').click();await expect(page.locator('#gov-grc-confirm')).toBeEnabled();
  await expect(page.locator('#gov-grc-comparison')).toContainText('matches');
  expect(await page.locator('#gov-grc-comparison').evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBeTruthy();
  await page.locator('#gov-grc-comparison').scrollIntoViewIfNeeded();
  await info.attach('held-grc-comparison',{body:await page.screenshot(),contentType:'image/png'});
  await form.locator('[name="note"]').fill('Retain this unsaved review during a temporary interruption.');
  const interrupted=route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'Synthetic review interruption'})});
  await page.route('**/grc-sync/outbound/*/resolve',interrupted);
  await page.locator('#gov-grc-confirm').click();await expect(page.locator('#gov-grc-recovery-status')).toContainText('The review could not be saved. Reload the delivery and try again; your note is kept here.');await expect(page.locator('#gov-grc-recovery-status')).not.toContainText('Synthetic review interruption');
  await expect(form.locator('[name="note"]')).toHaveValue('Retain this unsaved review during a temporary interruption.');
  await expect(page.locator('#gov-grc-comparison')).toBeEmpty();await expect(page.locator('#gov-grc-confirm')).toBeDisabled();
  await page.unroute('**/grc-sync/outbound/*/resolve',interrupted);
  await page.locator('#gov-grc-inspect').click();await expect(page.locator('#gov-grc-confirm')).toBeEnabled();
  const expired=route=>route.fulfill({status:401,contentType:'text/html',body:'<p>Synthetic expired session</p>'});
  await page.route('**/grc-sync/outbound/*/resolve',expired);
  await page.locator('#gov-grc-confirm').click();await expect(page.locator('#gov-grc-recovery-status')).toContainText('session or permissions changed');
  await expect(page.locator('#gov-grc-comparison')).toBeEmpty();await expect(form.locator('[name="note"]')).toHaveValue('');
  await expect(form.locator('[name="delivery"]')).toHaveValue('');await expect(page.locator('#gov-grc-inspect')).toBeDisabled();
  await page.unroute('**/grc-sync/outbound/*/resolve',expired);await page.reload();
  await form.locator('[name="delivery"]').selectOption(fixture.grc_delivery);
  await page.locator('#gov-grc-inspect').click();await expect(page.locator('#gov-grc-confirm')).toBeEnabled();
  await form.locator('[name="note"]').fill('Synthetic local reviewer compared the exact held attempt and recorded remote fields.');
  await page.locator('#gov-grc-confirm').click();await expect(page.locator('#gov-grc-recovery-status')).toContainText('No content was resent');
  const after=await (await request.get('/__browser_fixture')).json();expect(after.grc_writes).toBe(fixture.grc_writes);
  await fits(page);
});
