const {test,expect}=require('@playwright/test');
const path=require('node:path');

test.beforeEach(async({context,page,baseURL})=>{
  const origin=new URL(baseURL).origin;
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
  page.__uncaught=[];page.on('pageerror',error=>page.__uncaught.push(error.message));
});
test.afterEach(async({page,context},testInfo)=>{
  await context.unrouteAll({behavior:'ignoreErrors'});
  await testInfo.attach('rendered-state',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  expect(page.__uncaught,'Uncaught browser exceptions').toEqual([]);
});
async function fits(page){
  const sizes=await page.evaluate(()=>({width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,
    overflowing:[...document.querySelectorAll('body *')].filter(node=>node.getBoundingClientRect().right>document.documentElement.clientWidth+1&&getComputedStyle(node).visibility!=='hidden').slice(0,15).map(node=>({tag:node.tagName,id:node.id,cls:node.className,right:node.getBoundingClientRect().right})),
    dialogs:[...document.querySelectorAll('dialog[open]')].map(node=>({width:node.clientWidth,scroll:node.scrollWidth}))}));
  expect(sizes.scroll,'Page horizontal overflow '+JSON.stringify(sizes.overflowing)).toBeLessThanOrEqual(sizes.width+1);
  for(const dialog of sizes.dialogs)expect(dialog.scroll,'Open dialog horizontal overflow').toBeLessThanOrEqual(dialog.width+1);
}

test('a flow recovery copy survives browser-context restart without running or publishing',async({browser,page,baseURL})=>{
  await page.goto('/flows/designer');
  await expect(page.locator('.draft-recovery')).toContainText('Draft recovery is ready');
  await page.locator('#fd-name').fill('Browser recoverable flow');
  const initialSaved=page.waitForResponse(response=>response.request().method()==='PUT'&&response.url().includes('/api/v1/drafts/')&&response.request().postData().includes('Keep this unfinished human brief after restart'));
  await page.locator('#fd-nl').fill('Keep this unfinished human brief after restart');
  expect((await initialSaved).status()).toBe(200);
  await expect(page.locator('.draft-recovery')).toContainText('Recovery copy saved');
  const context=await browser.newContext({baseURL});
  try {
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  const restarted=await context.newPage();await restarted.goto('/flows/designer');
  await expect(restarted.locator('.draft-recovery')).toContainText('A recovery copy is available');
  await expect(restarted.locator('#fd-name')).not.toHaveValue('Browser recoverable flow');
  let mutations=[];restarted.on('request',request=>{if(request.method()!=='GET')mutations.push(request.url());});
  await restarted.getByRole('button',{name:'Restore recovery copy',exact:true}).click();
  // The app's confirmation is a real keyboard-operable dialog.
  await expect(restarted.locator('#mv-confirm')).toBeVisible();
  await restarted.locator('#mv-confirm-ok').press('Enter');
  await expect(restarted.locator('#fd-name')).toHaveValue('Browser recoverable flow');
  await expect(restarted.locator('#fd-nl')).toHaveValue('Keep this unfinished human brief after restart');
  const newerSaved=page.waitForResponse(response=>response.request().method()==='PUT'&&response.url().includes('/api/v1/drafts/')&&response.request().postData().includes('Newer draft from the first editor'));
  await page.locator('#fd-nl').fill('Newer draft from the first editor');
  expect((await newerSaved).status()).toBe(200);
  await expect(page.locator('.draft-recovery')).toContainText('Recovery copy saved');
  await restarted.locator('#fd-nl').fill('Keep my conflicting local changes');
  await expect(restarted.locator('.draft-recovery')).toContainText('newer recovery copy');
  await expect(restarted.locator('#fd-nl')).toHaveValue('Keep my conflicting local changes');
  expect(mutations.filter(url=>/\/flows|\/publish|\/run/.test(url))).toEqual([]);
  await fits(restarted);
  } finally { await context.close(); }
});

test('record search uses the actual API and keyboard opens the exact task at phone width',async({page})=>{
  await page.setViewportSize({width:320,height:740});await page.goto('/goals');
  await page.keyboard.press('Control+k');
  await expect(page.locator('#navfinder-dialog')).toBeVisible();
  await page.locator('#navfinder-input').fill('Browser search task');
  await expect(page.locator('#navfinder-record-status')).toContainText('matching business records');
  await expect(page.locator('#navfinder-record-0')).toContainText('Browser search task');
  await fits(page);
  await page.locator('#navfinder-input').press('Enter');
  await expect(page).toHaveURL(/\/chat\/goal\/\d+$/);
  await expect(page.locator('body')).toContainText('Browser search task');
});

test('display preferences and keyboard dismissal remain usable in a short high-contrast viewport',async({page},info)=>{
  await page.setViewportSize({width:375,height:480});await page.goto('/goals');
  await page.locator('#prefs-menu > summary').click();await fits(page);
  // Appearance saves in place: preserve the document and unfinished work.
  await page.evaluate(() => { window.__appearanceDocument = 'same-document'; });
  const locationBefore = page.url();
  await page.locator('#theme-select').selectOption('hicontrast');
  await expect(page.locator('#prefs-status')).toContainText('Saved. Your editor and unsaved work remain open.');
  await expect(page.locator('body')).toHaveClass(/theme-hicontrast/);
  await page.locator('#font-select').selectOption('dyslexic');
  await expect(page.locator('#prefs-status')).toContainText('Saved. Your editor and unsaved work remain open.');
  await expect(page.locator('body')).toHaveClass(/font-dyslexic/);
  expect(page.url()).toBe(locationBefore);
  expect(await page.evaluate(() => window.__appearanceDocument)).toBe('same-document');
  await page.reload();
  await expect(page.locator('body')).toHaveClass(/theme-hicontrast/);
  await expect(page.locator('body')).toHaveClass(/font-dyslexic/);
  await page.locator('#prefs-menu > summary').click();await page.keyboard.press('Escape');
  await expect(page.locator('#prefs-menu')).not.toHaveAttribute('open','');await expect(page.locator('#prefs-menu > summary')).toBeFocused();
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready','true');
  await page.keyboard.press('Control+k');await expect(page.locator('#navfinder-input')).toBeFocused();
  await page.locator('#navfinder-input').fill('Browser');await expect(page.locator('#navfinder-record-status')).toContainText('matching business records');
  const statusBox=await page.locator('#navfinder-record-status').boundingBox(),resultsBox=await page.locator('#navfinder-results').boundingBox();
  expect(statusBox.y+statusBox.height).toBeLessThanOrEqual(resultsBox.y);
  expect(await page.locator('#navfinder-record-status').evaluate(el=>el.scrollHeight<=el.clientHeight+1)).toBeTruthy();
  await fits(page);await info.attach('high-contrast-finder',{body:await page.screenshot(),contentType:'image/png'});
  await page.keyboard.press('Escape');await expect(page.locator('#navfinder-dialog')).not.toBeVisible();
});

test('vendor PDF intake exposes source status, explicit human review, and confirmed local effects',async({page,request})=>{
  const fixture=await (await request.get('/__browser_fixture')).json();
  await page.setViewportSize({width:375,height:812});
  await page.goto('/third-party/vendor-onboarding?case='+fixture.case_id);
  await expect(page.locator('#vo-message')).toContainText('Linked request loaded');
  await page.locator('#vo-upload').setInputFiles(path.resolve(__dirname,'../../../..','scripts/acceptance/fixtures/vendor-documents/northstar-policy.pdf'));
  await page.locator('#vo-document-date').fill(new Date(Date.now()-86400000).toISOString().slice(0,10));
  await page.locator('#vo-upload-submit').click();
  await expect(page.locator('#vo-message')).toContainText('Preview ready');
  await page.locator('#vo-upload-confirm').check();
  await page.locator('#vo-upload-accept').click();
  await expect(page.locator('#vo-message')).toContainText('Reviewed evidence added');
  await page.locator('#vo-collect').click();
  await expect(page.locator('#vo-message')).toContainText('Saved');
  await page.locator('#vo-assess').click();
  await expect(page.locator('#vo-rationale')).toBeEnabled();
  await page.locator('#vo-rationale').fill('Synthetic browser reviewer acknowledges unresolved evidence and approves a restricted local test.');
  await page.locator('#vo-review-approve').click();
  await expect(page.locator('#vo-prepare')).toBeEnabled();
  await page.locator('#vo-prepare').click();
  await expect(page.locator('#vo-approve')).toBeEnabled();
  await page.locator('#vo-approve').click();
  await expect(page.locator('#vo-execute')).toBeEnabled();
  await page.locator('#vo-execute').click();
  await expect(page.locator('#vo-accept')).toBeEnabled();
  await page.locator('#vo-acceptance-reason').fill('Synthetic browser acceptance only; no customer savings or provider acceptance measured.');
  await page.locator('#vo-accept').click();
  await expect(page.locator('#vo-status')).toContainText('accepted');
  const after=await (await request.get('/__browser_fixture')).json();
  expect(after.ticket_creates).toBe(fixture.ticket_creates+1);
  await fits(page);
});

test('new workspace surfaces fit narrow and desktop viewports with readable alternate preferences',async({page,context,baseURL},info)=>{
  test.setTimeout(120000);
  const pages=['/start','/action-center','/workflow-builder','/consent/publishing','/privacy/data-discovery','/connections','/workspace/recovery','/project-reviews','/outcome-pilots','/workflow-readiness'];
  await context.addCookies([{name:'mvk_theme',value:'light',url:baseURL},{name:'mvk_density',value:'compact',url:baseURL}]);
  for(const width of [320,1280]){
    await page.setViewportSize({width,height:800});
    for(const route of pages){
      const response=await page.goto(route);
      expect(response.status(),route).toBe(200);
      await expect(page.locator('#content')).toBeVisible();
      await page.waitForLoadState('networkidle');
      const name=route.replaceAll('/','-').slice(1)+'-'+width+'.png',shot=info.outputPath(name);
      await page.screenshot({path:shot});await info.attach(name,{path:shot,contentType:'image/png'});
      await fits(page);
    }
  }
});
