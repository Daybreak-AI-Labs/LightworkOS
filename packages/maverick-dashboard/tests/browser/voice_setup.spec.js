const {test,expect}=require('@playwright/test');

test('voice setup requires consent, survives reload, cancels and retries synthetic downloads without starting audio',async({page,context,request,baseURL},info)=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.setViewportSize({width:320,height:1000});await page.goto('/settings#settings-voice');
  const panel=page.locator('.voice-setup'),start=page.locator('#voice-setup-start'),confirm=page.locator('#voice-setup-confirm'),status=page.locator('#voice-setup-status');
  await expect(panel).toBeVisible();await expect(confirm).toBeEnabled();await expect(start).toBeDisabled();
  const fixture=async()=>{const r=await request.get('/__browser_fixture');expect(r.ok()).toBeTruthy();return r.json();};
  expect((await fixture()).voice_download_attempts).toBe(0);
  let starts=0,audio=0;page.on('request',r=>{if(r.method()==='POST'&&r.url().endsWith('/voice/setup/download'))starts++;if(r.url().includes('/voice/transcribe'))audio++;});
  await confirm.focus();await page.keyboard.press('Space');await start.focus();await page.keyboard.press('Enter');
  await expect(status).toContainText('Downloading');await expect(start).toBeDisabled();await expect(confirm).not.toBeChecked();
  await page.reload();await expect(page.locator('#voice-setup-cancel')).toBeEnabled();expect(starts).toBe(1);
  await page.locator('#voice-setup-cancel').click();await expect(status).toContainText('cancelled');
  await expect(start).toBeDisabled();expect((await fixture()).voice_download_attempts).toBe(1);
  await confirm.check();await start.click();await expect(status).toContainText('Setup failed');await expect(confirm).not.toBeChecked();
  await confirm.check();await start.click();await expect(status).toContainText('Model file verified');
  expect((await fixture()).voice_download_attempts).toBe(3);expect(starts).toBe(3);expect(audio).toBe(0);
  await panel.locator('summary').click();await panel.scrollIntoViewIfNeeded();
  async function fits(){const sizes=await page.evaluate(()=>({page:[document.documentElement.clientWidth,document.documentElement.scrollWidth],panel:[document.querySelector('.voice-setup').clientWidth,document.querySelector('.voice-setup').scrollWidth]}));for(const [client,scroll] of Object.values(sizes))expect(scroll).toBeLessThanOrEqual(client+1);}
  await fits();await info.attach('voice-setup-details-320',{body:await page.screenshot(),contentType:'image/png'});
  await panel.locator('summary').click();await panel.scrollIntoViewIfNeeded();await info.attach('voice-setup-320',{body:await page.screenshot(),contentType:'image/png'});
  await page.setViewportSize({width:1280,height:1000});await panel.scrollIntoViewIfNeeded();await fits();await info.attach('voice-setup-1280',{body:await page.screenshot(),contentType:'image/png'});
  await page.route('**/api/v1/voice/setup',route=>route.fulfill({status:503,contentType:'text/html',body:'Synthetic service interruption'}));
  await page.locator('#voice-setup-refresh').click();await expect(status).toContainText('Refresh');await expect(start).toBeDisabled();
  await page.unroute('**/api/v1/voice/setup');await page.locator('#voice-setup-refresh').click();await expect(status).toContainText('Model file verified');
  await page.route('**/api/v1/voice/setup',route=>route.fulfill({status:401,contentType:'text/html',body:'Synthetic sign-in expiry'}));
  await page.locator('#voice-setup-refresh').click();await expect(status).toContainText('reload');
  await expect(page.locator('#voice-setup-technical')).toBeEmpty();await expect(page.locator('#voice-setup-progress-text')).toBeEmpty();
  await expect(start).toBeDisabled();await expect(page.locator('#voice-setup-refresh')).toBeDisabled();
  expect(errors).toEqual([]);expect(audio).toBe(0);
});

test('voice recovery link opens the right settings section without overriding an active control',async({page})=>{
  await page.goto('/settings?focus=voice-model-setup');
  await expect(page.locator('[data-settings-tab="models"]')).toHaveAttribute('aria-selected','true');
  await expect(page.locator('#voice-model-setup')).toBeFocused();
  await expect(page.locator('.voice-setup')).toBeVisible();

  await page.addInitScript(()=>window.addEventListener('load',()=>document.getElementById('settings-search').focus()));
  await page.goto('/settings?focus=voice-model-setup');
  await expect(page.locator('#settings-search')).toBeFocused();
});
