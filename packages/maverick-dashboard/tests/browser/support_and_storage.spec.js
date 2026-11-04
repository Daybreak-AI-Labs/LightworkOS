const {test,expect}=require('@playwright/test');
const crypto=require('node:crypto'),fs=require('node:fs/promises');

test.beforeEach(async({page,context,baseURL})=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  page.__errors=[];page.on('pageerror',error=>page.__errors.push(error.message));
});
test.afterEach(async({page},info)=>{
  await info.attach('rendered-state',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  expect(page.__errors).toEqual([]);
});
async function json(response){expect(response.ok(),await response.text()).toBeTruthy();return response.json();}

test('Help reviews the actual redacted support report before downloading its exact bytes',async({page},info)=>{
  await page.setViewportSize({width:320,height:800});await page.goto('/help');
  await expect(page.locator('.support-scope')).toContainText('the folder locations');
  await expect(page.locator('.support-scope')).toContainText('Task names, task types and raw error messages are left out');
  await expect(page.locator('.support-scope')).toContainText('The report preview is kept, encrypted, on this installation for up to ten minutes');
  await expect(page.locator('#support-status')).toHaveText('No report has been collected. Press Prepare support report when you need help from support.');
  const response=page.waitForResponse(r=>r.url().endsWith('/api/v1/support/preview'));
  await page.getByRole('button',{name:'Prepare support report',exact:true}).click();
  const report=await json(await response);
  await expect(page.locator('#support-result')).toBeVisible();
  await expect(page.getByRole('button',{name:'Download reviewed report',exact:true})).toBeDisabled();
  await page.getByText('Technical details: the exact file that will be downloaded',{exact:true}).click();
  expect(JSON.parse(await page.locator('#support-preview').textContent())).toEqual(report.bundle);
  const sizes=await page.locator('#support-center').evaluate(node=>({width:document.documentElement.clientWidth,right:node.getBoundingClientRect().right,scroll:node.scrollWidth,inner:node.clientWidth}));
  expect(sizes.right).toBeLessThanOrEqual(sizes.width+1);expect(sizes.scroll).toBeLessThanOrEqual(sizes.inner+1);
  // The report's follow-up links and the task bug-report form (added with the
  // same FAB-clearing layout class) must each stay clear of the Copilot button.
  const followups=page.locator('.support-followups');await expect(followups).toHaveCount(4);
  const fab=await page.locator('#mv-copilot-fab').boundingBox();
  for(const item of await followups.all()){
    const links=await item.boundingBox();
    expect(links&&fab&&!(links.x+links.width>fab.x&&links.x<fab.x+fab.width&&links.y+links.height>fab.y&&links.y<fab.y+fab.height)).toBeTruthy();
  }
  await page.screenshot({path:info.outputPath('help-320.png'),fullPage:true});
  await page.locator('#support-confirm').check();
  const pending=page.waitForEvent('download');await page.getByRole('button',{name:'Download reviewed report',exact:true}).click();
  const download=await pending,path=info.outputPath('reviewed-support.json');await download.saveAs(path);
  const bytes=await fs.readFile(path);expect(crypto.createHash('sha256').update(bytes).digest('hex')).toBe(report.sha256);
  expect(JSON.parse(bytes)).toEqual(report.bundle);
});

test('Help clears a reviewed private report on HTML access denial and blocks non-administrator collection',async({page,request})=>{
  await page.goto('/help');await page.locator('#support-prepare').click();await expect(page.locator('#support-result')).toBeVisible();
  const context=await page.locator('#support-center').getAttribute('data-context');
  expect((await request.post('/api/v1/support/preview',{headers:{'X-Browser-Principal':'browser-colleague','X-Lightwork-Support-Context':context},data:{}})).status()).toBe(403);
  await page.route('**/api/v1/support/download',route=>route.fulfill({status:403,contentType:'text/html',body:'Synthetic signed-out response'}));
  await page.locator('#support-confirm').check();await page.locator('#support-download').click();
  await expect(page.locator('#support-status')).toContainText('Your access changed');
  await expect(page.locator('#support-result')).toBeHidden();await expect(page.locator('#support-preview')).toHaveText('');
  await expect(page.locator('#support-download')).toBeDisabled();
});

test('Help keeps task reports local after review, copy, and download',async({page,baseURL},info)=>{
  const external=[];page.on('request',request=>{if(new URL(request.url()).origin!==new URL(baseURL).origin)external.push(request.url());});
  const reviews=[];
  await page.route('**/api/v1/support/issue-report**',async route=>{
    const pathname=new URL(route.request().url()).pathname;
    let value;
    if(pathname.endsWith('/tasks'))value={tasks:[{id:7,title:'Stopped task',when:1}],next_offset:null};
    else if(pathname.endsWith('/review')){
      reviews.push(route.request().postDataJSON());
      value={title:'Stopped task',body:'Customer [REDACTED]'};
    }else value={title:'Stopped task',body:'Customer secret',summary:'Review this local draft.'};
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  });
  await page.goto('/help');
  await expect(page.locator('#issue-report-task option')).toHaveCount(2);
  await page.locator('#issue-report-task').selectOption('7');
  await page.getByRole('button',{name:'Prepare the bug report'}).click();
  await expect(page.locator('#issue-report-preview')).toBeVisible();
  const copy=page.getByRole('button',{name:'Copy reviewed draft'});
  const download=page.getByRole('button',{name:'Download reviewed draft'});
  await expect(copy).toBeDisabled();await expect(download).toBeDisabled();
  await page.evaluate(()=>{window.__taskDraftCopies=[];Object.defineProperty(navigator,'clipboard',{
    configurable:true,value:{writeText:async text=>{window.__taskDraftCopies.push(text);}}
  });});
  // The first confirmation starts a fresh review and the page clears the box
  // itself, so click() rather than check(), which fails if it sees the reset.
  await page.locator('#issue-report-confirm').click();
  await expect(page.locator('#issue-report-body')).toHaveValue('Customer [REDACTED]');
  await expect(page.locator('#issue-report-confirm')).not.toBeChecked();
  await expect(copy).toBeDisabled();
  await page.locator('#issue-report-confirm').check();
  await expect(copy).toBeEnabled();await expect(download).toBeEnabled();
  await copy.click();
  await expect(page.locator('#issue-report-status')).toContainText('Reviewed draft copied');
  expect(await page.evaluate(()=>window.__taskDraftCopies)).toEqual(['Stopped task\n\nCustomer [REDACTED]']);
  const pending=page.waitForEvent('download');await download.click();
  const file=await pending,path=info.outputPath('reviewed-task-support.txt');await file.saveAs(path);
  expect(await fs.readFile(path,'utf8')).toBe('Stopped task\n\nCustomer [REDACTED]');
  await expect(page.locator('#issue-report-preview')).toBeVisible();
  expect(new URL(page.url()).pathname).toBe('/help');
  expect(reviews).toHaveLength(2);
  expect(external).toEqual([]);
});

test('recovery storage retires discarded copies while retaining saved work and rejecting old tabs',async({page,request})=>{
  await page.goto('/workflow-builder');await expect(page.locator('.draft-recovery')).toBeVisible();
  const context=await page.locator('meta[name="lightwork-draft-context"]').getAttribute('content');
  const headers={'X-Lightwork-Draft-Context':context},slots=[crypto.randomBytes(32).toString('hex'),crypto.randomBytes(32).toString('hex')];
  for(let i=0;i<slots.length;i++){
    const current=await json(await request.get('/api/v1/drafts/'+slots[i],{headers}));
    await json(await request.put('/api/v1/drafts/'+slots[i],{headers,data:{expected_revision:current.revision,operation_id:crypto.randomUUID(),payload:i?{brief:'Synthetic current saved work'}:null}}));
  }
  const old=await json(await request.get('/api/v1/drafts/'+slots[0],{headers}));
  const storage=page.locator('.draft-recovery details').filter({has:page.getByText('Manage recovery storage',{exact:true})});
  await storage.locator('summary').click();await expect(storage.getByRole('status')).toContainText('1 discarded copies');
  await storage.getByRole('button',{name:'Free discarded recovery space',exact:true}).click();
  await expect(page.locator('#mv-confirm')).toBeVisible();await page.locator('#mv-confirm-ok').click();
  await expect(storage.getByRole('status')).toContainText('Discarded recovery space freed.');
  expect((await request.put('/api/v1/drafts/'+slots[0],{headers,data:{expected_revision:old.revision,operation_id:crypto.randomUUID(),payload:{brief:'Stale tab must be refused'}}})).status()).toBe(409);
  expect((await json(await request.get('/api/v1/drafts/'+slots[1],{headers}))).payload).toEqual({brief:'Synthetic current saved work'});
});
