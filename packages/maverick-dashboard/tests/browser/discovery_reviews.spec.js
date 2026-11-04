const {test,expect}=require('@playwright/test');
test.beforeEach(async({context,page,baseURL})=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  page.__uncaught=[];page.on('pageerror',error=>page.__uncaught.push(error.message));page.on('dialog',dialog=>dialog.accept());
});
test.afterEach(async({page,context},info)=>{
  await context.unrouteAll({behavior:'ignoreErrors'});
  await info.attach('rendered-state',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  expect(page.__uncaught).toEqual([]);
});
async function fits(page){const s=await page.evaluate(()=>[document.documentElement.scrollWidth,document.documentElement.clientWidth]);expect(s[0]).toBeLessThanOrEqual(s[1]+1);}

test('discovery uses sealed connection references and explicitly rebinds a rotated evidence key',async({page,request},info)=>{
  await page.setViewportSize({width:375,height:812});await page.goto('/connections');
  let credentialDrafts=0;page.on('request',r=>{if(r.method()==='PUT'&&r.url().includes('/api/v1/drafts/'))credentialDrafts++;});
  await page.locator('#cx-preset').selectOption('servicenow_cmdb');await page.locator('#cx-name').fill('browser-managed');
  await page.locator('#cx-token').fill('synthetic-browser-only-credential');await page.locator('#cx-base').fill('https://data.example.com');
  await fits(page);await page.getByRole('button',{name:'Save connection',exact:true}).click();
  await expect(page.locator('#cx-list')).toContainText('browser-managed');await expect(page.locator('#cx-token')).toHaveValue('');
  expect(credentialDrafts).toBe(0);await page.goto('/privacy/data-discovery');
  const confirm=async()=>{await expect(page.locator('#mv-confirm')).toBeVisible();await page.locator('#mv-confirm-ok').click();};
  const saveSource=async()=>{
    await page.locator('#pdd-new-source').click();await expect(page.locator('#pdd-source-panel')).toBeVisible();
    await page.locator('#pdd-name').fill('browser-cmdb');await page.locator('#pdd-provider').selectOption('servicenow_cmdb');
    const reference=await page.locator('#pdd-connection option').filter({hasText:'browser-managed'}).getAttribute('value');
    await page.locator('#pdd-connection').selectOption(reference);await page.locator('#pdd-resource').fill('cmdb_ci');
    await page.getByRole('button',{name:'Save source',exact:true}).click();
    await expect(page.locator('#pdd-status')).toContainText('Data source saved');
  };
  await saveSource();
  const before=await (await request.get('/api/v1/privacy/data-discovery/sources/browser-cmdb')).json();
  expect(before.revision).toBe(1);expect(before.credential_env).not.toContain('synthetic-browser-only-credential');
  const row=page.locator('#pdd-sources tr').filter({hasText:/browser.cmdb/i});
  const response=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname==='/api/v1/privacy/data-discovery/sources/browser-cmdb/test-access');
  await row.getByRole('button',{name:'Test access'}).click();await confirm();expect((await response).status()).toBe(200);
  await expect(page.locator('#pdd-status')).toContainText('can read this source');
  await expect(page.locator('#pdd-root')).not.toContainText('never-return-this-value');
  await page.locator('#pdd-rotate-key').click();await confirm();
  await expect(page.locator('#pdd-status')).toContainText('Existing sources were not changed');
  const unchanged=await (await request.get('/api/v1/privacy/data-discovery/sources/browser-cmdb')).json();
  expect(unchanged.evidence_key_env).toBe(before.evidence_key_env);expect(unchanged.revision).toBe(1);
  await saveSource();
  const rebound=await (await request.get('/api/v1/privacy/data-discovery/sources/browser-cmdb')).json();
  expect(rebound.revision).toBe(2);expect(rebound.evidence_key_env).not.toBe(before.evidence_key_env);
  await page.locator('#pdd-sources').scrollIntoViewIfNeeded();await info.attach('connected-source',{body:await page.screenshot(),contentType:'image/png'});
  await fits(page);
});

test('owner shares an exact captured result and assigned colleague reviews it without live signoff',async({page,browser,baseURL,request},info)=>{
  const fixture=await (await request.get('/__browser_fixture')).json();
  await page.goto('/project-reviews#project='+fixture.project_id);
  await expect(page.locator('#pr-setup')).toBeVisible();
  await page.locator('#pr-member').selectOption('user:browser-colleague');await page.locator('#pr-grant').click();
  await expect(page.locator('#pr-members')).toContainText('browser-colleague');
  await page.locator('#pr-goal').selectOption(String(fixture.review_goal));await page.locator('#pr-preview').click();
  await expect(page.locator('#pr-preview-text')).toContainText('Evidence limitations remain explicit');
  await page.locator('#pr-reviewer').selectOption('user:browser-colleague');
  await page.locator('#pr-due').fill(new Date(Date.now()+86400000).toISOString().slice(0,16));
  await page.locator('#pr-note').fill('Review the captured evidence and limitations before responding.');
  const sent=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/packets'));
  await page.locator('#pr-send-button').click();
  // Sharing asks for an in-page confirmation that names the reviewer.
  const share=page.getByRole('dialog',{name:'Share exactly the captured result shown above with browser-colleague?'});
  await share.getByRole('button',{name:'Share for review',exact:true}).click();const packet=await (await sent).json();
  await expect(page.locator('#pr-status')).toContainText('Sent for review. No task was started or approved.');
  const reviewer=await browser.newContext({baseURL,viewport:{width:320,height:800},extraHTTPHeaders:{Origin:baseURL,'X-Browser-Principal':'browser-colleague'}});
  try {
    const review=await reviewer.newPage();review.on('dialog',dialog=>dialog.accept());
    await reviewer.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
    await review.goto('/action-center');await expect(review.locator('#content')).toContainText('Browser captured result');
    await review.goto('/project-reviews#packet='+packet.id);await expect(review.locator('#pr-result')).toContainText('Synthetic captured deliverable');
    await review.locator('#pr-action').selectOption('approve');await review.locator('#pr-response-note').fill('Synthetic colleague reviewed the captured result and limitations.');
    // Native leave-page protection must retain the actual unfinished note.
    review.removeAllListeners('dialog');const leaving=review.waitForEvent('dialog');const navigation=review.locator('a[href="/"]').first().click({noWaitAfter:true});
    const warning=await leaving;expect(warning.type()).toBe('beforeunload');await warning.dismiss();await navigation;await expect(review).toHaveURL(/\/project-reviews#packet=/);
    review.on('dialog',dialog=>dialog.accept());await expect(review.locator('#pr-response-note')).toHaveValue('Synthetic colleague reviewed the captured result and limitations.');
    // Another permitted actor changes the packet while this comment is dirty.
    await page.locator('#pr-response-note').fill('Owner added a clarification while the colleague was reviewing.');await page.locator('#pr-response-button').click();await expect(page.locator('#pr-status')).toContainText('Review response saved');
    await review.locator('#pr-refresh').click();await expect(review.locator('#pr-status')).toContainText('Your unfinished comment is kept');await expect(review.locator('#pr-response-note')).toHaveValue('Synthetic colleague reviewed the captured result and limitations.');await expect(review.locator('#pr-action')).toHaveValue('comment');
    await review.locator('#pr-action').selectOption('approve');
    await review.locator('#pr-response-button').click();
    await review.getByRole('dialog',{name:'Save this Approve decision for the captured result? The live task will remain unchanged.'}).getByRole('button',{name:'Save decision',exact:true}).click();
    await expect(review.locator('#pr-status')).toContainText('Review response saved');
    await expect(review.locator('#pr-packet-summary')).toContainText('Approved');await fits(review);
    const reviewImage=info.outputPath('assigned-colleague-review-320.png');await review.screenshot({path:reviewImage});await info.attach('assigned-colleague-review',{path:reviewImage,contentType:'image/png'});
    await review.route('**/api/v1/project-reviews**',route=>route.fulfill({status:401,contentType:'text/html',body:'<h1>Synthetic session expired</h1>'}));
    await review.locator('#pr-refresh').click();await expect(review.locator('#pr-status')).toContainText('sign-in or access changed');
    await expect(review.locator('#pr-packet')).not.toBeVisible();await expect(review.locator('#pr-result')).toHaveText('');await expect(review.locator('#pr-inbox')).toHaveText('');
  } finally {await reviewer.close();}
  const final=await (await request.get('/__browser_fixture')).json();expect(final.review_signoff).toBeNull();
});
