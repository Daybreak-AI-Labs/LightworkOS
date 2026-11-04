const {test,expect}=require('@playwright/test');
test.beforeEach(async({page,context,baseURL})=>{page.__errors=[];page.on('pageerror',error=>page.__errors.push(error.message));await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort());});
test.afterEach(async({page,context},info)=>{await context.unrouteAll({behavior:'ignoreErrors'});const path=info.outputPath('rendered-state.png');await page.screenshot({path,fullPage:true});await info.attach('rendered-state',{path,contentType:'image/png'});expect(page.__errors).toEqual([]);});
async function fits(page){const bounds=await page.locator('#connection-setup').evaluate(node=>({right:node.getBoundingClientRect().right,viewport:document.documentElement.clientWidth,client:node.clientWidth,scroll:node.scrollWidth}));expect(bounds.right).toBeLessThanOrEqual(bounds.viewport+1);expect(bounds.scroll).toBeLessThanOrEqual(bounds.client+1);}

test('an administrator explicitly enables, registers and finishes a named account through a synthetic provider return',async({page,request,baseURL},info)=>{
  await page.setViewportSize({width:320,height:950});await page.goto('/connections');await expect(page.locator('#cs-enable')).toBeVisible();
  await expect(page.locator('#cs-enable-button')).toBeDisabled();await page.locator('#cs-enable-confirm').check();await page.locator('#cs-enable-button').click();await expect(page.locator('#cs-status')).toContainText('Reload Connections');
  await page.locator('#cs-refresh').click();await expect(page.locator('#cs-options')).toBeVisible();await expect(page.locator('#cs-callback')).toHaveValue(baseURL+'/connections');
  await page.locator('#cs-client-id').fill('synthetic-browser-client');await page.locator('#cs-client-secret').fill('synthetic-browser-client-secret');await page.locator('#cs-app-confirm').check();
  await page.locator('#cs-app-save').click();await expect(page.locator('#cs-status')).toContainText('Provider application saved securely');await expect(page.locator('#cs-client-secret')).toHaveValue('');
  await page.locator('#cs-profile').selectOption('google-drive');await page.locator('#cs-name').fill('browser-renewable-drive');await page.locator('#cs-authorize-confirm').check();await page.locator('#cs-authorize-button').click();
  await expect(page.locator('#cs-departure')).toBeVisible();await expect(page.locator('#cs-status')).toContainText('Sign-in prepared');
  const link=await page.locator('#cs-provider-link').getAttribute('href'),providerURL=new URL(link);expect(providerURL.origin+providerURL.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
  const stored=await page.evaluate(()=>JSON.parse(sessionStorage.getItem('lightwork:connection-consent:v1')));expect(Object.keys(stored).sort()).toEqual(['context','state']);expect(stored.state).toBe(providerURL.searchParams.get('state'));
  const before=await (await request.get('/__browser_fixture')).json();expect(before.connection_exchanges).toBe(0);await fits(page);
  // No request goes to Google. The fixture returns synthetic token bytes only
  // when the real state-bound exchange is explicitly submitted below.
  await page.goto('/connections?'+new URLSearchParams({code:'synthetic-browser-code',state:stored.state}));await expect(page).toHaveURL(baseURL+'/connections');await expect(page.locator('#cs-return')).toBeVisible();
  expect(await page.evaluate(()=>sessionStorage.getItem('lightwork:connection-consent:v1'))).toBeNull();expect((await (await request.get('/__browser_fixture')).json()).connection_exchanges).toBe(0);
  await expect(page.locator('#cs-finish')).toBeDisabled();await page.locator('#cs-finish-confirm').check();await page.locator('#cs-finish').focus();await page.keyboard.press('Enter');await expect(page.locator('#cs-status')).toContainText('Account connection saved');
  await expect(page.locator('#cs-connections')).toContainText('browser-renewable-drive');await expect(page.locator('#cx-list')).toContainText('browser-renewable-drive');
  expect((await (await request.get('/__browser_fixture')).json()).connection_exchanges).toBe(1);await page.locator('#cs-connections').scrollIntoViewIfNeeded();await fits(page);
  const narrow=info.outputPath('account-connected-320.png');await page.screenshot({path:narrow});await info.attach('account-connected-320',{path:narrow,contentType:'image/png'});
  await page.locator('#cs-existing').selectOption('browser-renewable-drive');await expect(page.locator('#cs-name')).toHaveValue('browser-renewable-drive');await expect(page.locator('#cs-name')).toHaveAttribute('readonly','');
  await page.setViewportSize({width:1280,height:950});await page.locator('#cs-title').scrollIntoViewIfNeeded();await fits(page);const wide=info.outputPath('account-setup-1280.png');await page.screenshot({path:wide});await info.attach('account-setup-1280',{path:wide,contentType:'image/png'});
  if(!await page.locator('#cs-app-details').evaluate(node=>node.open))await page.locator('#cs-app-details > summary').click();await page.locator('#cs-client-secret').fill('synthetic-unsaved-registration');await page.locator('#cx-token').fill('synthetic-unsaved-token');
  await page.route('**/api/v1/connection-setup',route=>route.fulfill({status:401,contentType:'text/html',body:'<h1>Synthetic expired sign-in</h1>'}));await page.locator('#cs-refresh').click();await expect(page.locator('#cs-status')).toContainText('administrator access changed');
  await expect(page.locator('#cs-client-secret')).toHaveValue('');await expect(page.locator('#cx-token')).toHaveValue('');await expect(page.locator('#cs-connections')).toBeEmpty();await expect(page.locator('#cx-list')).toBeEmpty();await expect(page.locator('#cs-refresh')).toBeDisabled();
});
