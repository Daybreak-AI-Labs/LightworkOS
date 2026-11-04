const {test,expect}=require('@playwright/test');
test.beforeEach(async({context,page,baseURL})=>{await context.route('**/*',r=>new URL(r.request().url()).origin===new URL(baseURL).origin?r.continue():r.abort());page.__errors=[];page.on('pageerror',e=>page.__errors.push(e.message));page.on('dialog',d=>d.accept());});
// Screenshot while the route above still releases requests: a test can end on a
// navigation whose fonts are still loading, and a request Chromium paused just as
// interception is switched off is never released, so the screenshot waited forever.
test.afterEach(async({page,context},info)=>{const path=info.outputPath('rendered-state.png');await page.screenshot({path,fullPage:true});await info.attach('rendered-state',{path,contentType:'image/png'});await context.unrouteAll({behavior:'ignoreErrors'});expect(page.__errors).toEqual([]);});
async function fits(page){expect(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1)).toBe(true);}

test('Goals keeps search failures distinct and its primary task link opens the normal work view',async({page})=>{
  await page.setViewportSize({width:320,height:820});await page.goto('/goals');
  // Search reads the retained task list part by part (search-page); a failed part keeps the words and results.
  await page.route('**/api/v1/goals/search-page?*',r=>r.fulfill({status:503,contentType:'text/html',body:'Synthetic unavailable service'}));
  await page.locator('#run-search-q').fill('Browser search task');await expect(page.locator('#run-search-status')).toContainText('This part could not be read');
  await expect(page.locator('#run-search-q')).toHaveValue('Browser search task');
  await expect(page.locator('#run-list')).toContainText('Browser search task');await expect(page.locator('#run-search-retry')).toBeVisible();await fits(page);
  await page.unroute('**/api/v1/goals/search-page?*');await page.locator('#run-search-retry').click();await expect(page.locator('#run-search-status')).toContainText('1 matching task found');
  const link=page.locator('.g-row__title a',{hasText:'Browser search task'});await link.focus();await page.keyboard.press('Enter');await expect(page).toHaveURL(/\/chat\/goal\/\d+$/);
});

test('Action Center keeps keyboard position and removes private synthetic state on an HTML denial',async({page})=>{
  await page.setViewportSize({width:320,height:900});await page.goto('/action-center');await expect(page.locator('#ac-status')).toHaveText('List refreshed.');
  const context=await page.locator('#action-center').getAttribute('data-context');let read=false;
  // Synthetic list/response injection exercises the actual DOM controller;
  // actual API authorization is covered separately, not bypassed in product.
  const model=()=>({context,revision:1,counts:{unread:read?0:1,overdue:0,snoozed:0},coverage:[],total:1,limit:50,has_more:false,items:[{id:'synthetic',title:'Synthetic private review',kind:'project_review',assignment:'mine',read,reason:'Synthetic review details',href:'/project-reviews',source_version:'a'.repeat(64)}]});
  await page.route('**/api/v1/action-center?*',r=>r.fulfill({json:model()}));await page.getByRole('button',{name:'Refresh list',exact:true}).click();
  await page.route('**/api/v1/action-center/*/preference',r=>{read=true;return r.fulfill({json:{revision:2}});});
  await page.getByRole('button',{name:'Mark read: Synthetic private review',exact:true}).focus();await page.keyboard.press('Enter');
  await expect(page.getByRole('button',{name:'Mark unread: Synthetic private review',exact:true})).toBeFocused();await fits(page);
  await page.unroute('**/api/v1/action-center/*/preference');await page.route('**/api/v1/action-center/*/preference',r=>r.fulfill({status:403,contentType:'text/html',body:'<h1>Synthetic access removed</h1>'}));await page.keyboard.press('Enter');
  await expect(page.locator('#ac-status')).toContainText('sign-in or access changed');await expect(page.locator('#ac-items')).toHaveText('');await expect(page.getByRole('button',{name:'Refresh list',exact:true})).toBeDisabled();
});

test('guided business intake saves typed answers, resumes after reload, preserves interruption input and submits only for review',async({page},info)=>{
  await page.setViewportSize({width:320,height:920});await page.goto('/security/assurance');await expect(page.locator('#abi-status')).toContainText('Start with what you know');
  const field=name=>page.locator('[data-field="'+name+'"]');
  await field('use_case_name').locator('input').fill('Browser guided support intake');await page.locator('#abi-save').click();await expect(page.locator('#abi-status')).toContainText('Draft answers saved');
  await expect(page.locator('#abi-submit')).toBeDisabled();await page.reload();await expect(page.locator('#abi-status')).toContainText('Start with what you know');
  await page.locator('#abi-drafts').selectOption({label:'Browser guided support intake · Draft'});await page.locator('#abi-open').click();await expect(field('use_case_name').locator('input')).toHaveValue('Browser guided support intake');
  await field('accountable_owner').locator('input').fill('Synthetic accountable owner');await field('business_unit').locator('input').fill('Support');await field('purpose').locator('textarea').fill('Help staff review public support documents.');
  await field('data_context.categories').locator('input[value="public"]').check();await field('data_context.personal_data').locator('select').selectOption('false');await field('data_context.sensitive_data').locator('select').selectOption('false');
  await field('deployment_context.stage').locator('select').selectOption('pilot');await field('deployment_context.audience').locator('select').selectOption('internal');await field('deployment_context.decision_role').locator('select').selectOption('assistive');
  for(const name of ['human_oversight','third_party','safety_critical'])await field('deployment_context.'+name).locator('select').selectOption(name==='human_oversight'?'true':'false');await field('deployment_context.transparency_notice').locator('select').selectOption('yes');
  for(const name of ['prohibited_signals','high_risk_domains','transparency_signals'])await field('regulatory_context.'+name).getByRole('checkbox',{name:'None of these signals',exact:true}).check();
  let firstBody;await page.route('**/ai-business-intake/drafts/ABI-*',r=>{if(r.request().method()!=='PATCH')return r.continue();firstBody=r.request().postData();return r.fulfill({status:503,contentType:'text/html',body:'Synthetic temporary interruption'});});
  await page.locator('#abi-save').click();await expect(page.locator('#abi-status')).toContainText('answers are kept');await expect(field('purpose').locator('textarea')).toHaveValue('Help staff review public support documents.');await expect(page.locator('#abi-submit')).toBeDisabled();
  await page.unroute('**/ai-business-intake/drafts/ABI-*');const saved=page.waitForRequest(r=>r.method()==='PATCH'&&r.url().includes('/ai-business-intake/drafts/'));await page.locator('#abi-save').click();expect((await saved).postData()).toBe(firstBody);await expect(page.locator('#abi-submit')).toBeEnabled();
  await fits(page);const bounds=await page.locator('#ai-business-intake-panel').evaluate(node=>({right:node.getBoundingClientRect().right,viewport:document.documentElement.clientWidth,scroll:node.scrollWidth,client:node.clientWidth}));expect(bounds.right).toBeLessThanOrEqual(bounds.viewport+1);expect(bounds.scroll).toBeLessThanOrEqual(bounds.client+1);await page.locator('#abi-progress').scrollIntoViewIfNeeded();const narrow=info.outputPath('guided-intake-320.png');await page.screenshot({path:narrow});await info.attach('guided-intake-320',{path:narrow,contentType:'image/png'});
  await page.locator('#abi-submit').click();await page.getByRole('dialog',{name:/Submit these saved answers for independent human review/}).getByRole('button',{name:'Submit for review',exact:true}).click();
  await expect(page.locator('#abi-status')).toContainText('Intake routed for independent review');await expect(page.locator('#abi-current')).toContainText('Awaiting independent review');await expect(page.locator('#abi-save')).toBeDisabled();
  await page.setViewportSize({width:1280,height:1000});await page.locator('#abi-current').scrollIntoViewIfNeeded();await fits(page);const wide=info.outputPath('guided-intake-1280.png');await page.screenshot({path:wide});await info.attach('guided-intake-1280',{path:wide,contentType:'image/png'});
});

test('a synthetic historical recovery report keeps failed coverage visible while technical detail remains accessible on a phone',async({page,request},info)=>{
  // This is UI-only rendering of a historical synthetic report. The existing
  // custody journey independently proves real worker, signature and key checks.
  const response=await request.get('/api/v1/recovery/status');expect(response.status()).toBe(200);const state=await response.json(),snapshot='synthetic-recovery-report';
  await page.route('**/api/v1/recovery/status',route=>route.fulfill({json:{...state,key_id:'synthetic-display-only',snapshots:[{id:snapshot,created_at:1700000000,bytes:1024}]}}));
  const report={schema:1,kind:'workspace-custody-test',state:'recorded',report_id:'e'.repeat(32),snapshot,archive_sha256:'a'.repeat(64),custody_sha256:'c'.repeat(64),target:state.target,tenant:state.tenant,
    application_version:state.application_version,application_identity:'source-sha256:'+'b'.repeat(64),completed_at:1700003600,snapshot_created_at:1700000000,elapsed_seconds:0.855624,
    outcome:'failed',checks:[{format:'Synthetic recognized format',detected:3,verified:2,failed:1,unsupported:0},{format:'Synthetic unsupported format',detected:2,verified:1,failed:0,unsupported:1}],files_scanned:5,sqlite_columns_scanned:0,unexamined_files:2,
    fresh_process:true,key_source:'uploaded-custody-copy',coverage_complete:false,restore_authorized:false,live_workspace_changed:false,external_stores_tested:false,limits:['Synthetic example: custom formats and external stores were not tested.'],current_build_matches:false};
  await page.route('**/api/v1/recovery/snapshots/*/custody-test/report',route=>route.fulfill({json:report}));
  let restores=0;page.on('request',request=>{if(/\/(restore|custody-test)$/.test(new URL(request.url()).pathname))restores++;});
  await page.setViewportSize({width:320,height:1000});await page.goto('/workspace/recovery');await expect(page.locator('#wrec-snapshot')).toBeEnabled();await page.locator('#wrec-snapshot').selectOption(snapshot);await page.locator('#wrec-custody-report-load').click();
  await expect(page.locator('#wrec-custody-totals')).toContainText('3 recognized encrypted records verified; 1 failed; 1 unsupported');await expect(page.locator('#wrec-custody-totals')).toContainText('2 files were not examined');await expect(page.locator('#wrec-custody-status')).toContainText('Verification failed');
  const details=page.locator('#wrec-custody-checks').locator('..');await expect(details).not.toHaveAttribute('open','');await expect(page.locator('#wrec-prepare')).toBeDisabled();
  await page.locator('#wrec-custody-status').scrollIntoViewIfNeeded();await fits(page);const narrow=info.outputPath('recovery-summary-320.png');await page.screenshot({path:narrow});await info.attach('recovery-summary-320',{path:narrow,contentType:'image/png'});
  await details.locator('summary').focus();await page.keyboard.press('Enter');await expect(page.locator('#wrec-custody-checks')).toBeVisible();expect(await page.locator('#wrec-custody-report').evaluate(node=>node.scrollWidth<=node.clientWidth+1)).toBeTruthy();await fits(page);
  await page.setViewportSize({width:1280,height:1000});await page.locator('#wrec-custody-status').scrollIntoViewIfNeeded();const wide=info.outputPath('recovery-details-1280.png');await page.screenshot({path:wide});await info.attach('recovery-details-1280',{path:wide,contentType:'image/png'});expect(restores).toBe(0);
});
