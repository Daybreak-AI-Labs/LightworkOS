// Actual local dashboard and case store; synthetic provider consent and renewal.
const {test,expect}=require('@playwright/test');
async function expectShellReady(page){
  // Copilot loads after window.load, during idle. Finish that real download
  // before navigating away so the journey's zero-failed-requests check does
  // not mistake navigation-cancelled scripts for a broken connection flow.
  await expect(page.locator('#mv-copilot-fab')).toHaveAttribute('data-copilot-ready','true');
}
function expectUnchangedCase(after,original){
  // The attention observation clock advances on every GET; persisted revision,
  // effective time, state, assessment and every other field must remain equal.
  expect(after.attention.as_of).toBeGreaterThanOrEqual(original.attention.as_of);
  expect({...after,attention:{...after.attention,as_of:original.attention.as_of}}).toEqual(original);
}
test.skip(process.env.LIGHTWORK_BROWSER_SHOW_VENDOR_SETUP!=='1','Requires the explicit synthetic setup fixture.');
test.beforeEach(async({page,context,baseURL})=>{
  page.__errors=[];page.__failures=[];page.on('pageerror',error=>page.__errors.push(error.message));
  page.on('requestfailed',request=>page.__failures.push({path:new URL(request.url()).pathname,error:request.failure()?.errorText}));
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort());
});
test.afterEach(async({page,context},info)=>{
  await expectShellReady(page);
  await info.attach('rendered-state',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  expect(page.__errors).toEqual([]);expect(page.__failures).toEqual([]);await context.unrouteAll({behavior:'ignoreErrors'});
});
async function beginTask({page,request},width){
  await page.setViewportSize({width,height:950});const fixture=await(await request.get('/__browser_fixture')).json();
  const original=await(await request.get('/api/v1/vendor-onboarding/cases/'+fixture.case_id)).json();
  await page.goto('/third-party/vendor-onboarding?case='+fixture.case_id);
  await expect(page.locator('#vo-case-reference a')).toHaveAttribute('href',new RegExp('[?&]case='+fixture.case_id+'(?:&|$)'));
  await expectShellReady(page);
  await page.locator('#vs-panel').getByRole('link',{name:'Connections',exact:true}).click();await expect(page.locator('#cs-task-return')).toBeVisible();
  if(await page.locator('#cs-enable').isVisible()){
    await page.locator('#cs-enable-confirm').check();await page.locator('#cs-enable-button').click();
    await expect(page.locator('#cs-refresh')).toHaveText('Reload Connections');await page.locator('#cs-refresh').click();
  }
  await expect(page.locator('#cs-options')).toBeVisible();
  const current=await(await request.get('/api/v1/connection-setup')).json();
  if(!current.applications.some(row=>row.provider==='google')){
    await page.locator('#cs-client-id').fill('synthetic-task-return-client');
    await page.locator('#cs-client-secret').fill('synthetic-task-return-secret');
    await page.locator('#cs-app-confirm').check();await page.locator('#cs-app-save').click();
    await expect(page.locator('#cs-status')).toContainText('Provider application saved securely');
  }
  await expectShellReady(page);return{fixture,original};
}
test('denied sign-in returns to the same saved request without a credential or workflow write',async({page,request},info)=>{
  const {fixture,original}=await beginTask({page,request},1280);
  await page.locator('#cs-name').fill('denied-task-drive');await page.locator('#cs-authorize-confirm').check();await page.locator('#cs-authorize-button').click();
  await expect(page.locator('#cs-departure')).toBeVisible();const state=await page.evaluate(()=>JSON.parse(sessionStorage.getItem('lightwork:connection-consent:v1')).state);
  await page.goto('/connections?'+new URLSearchParams({error:'access_denied',error_description:'synthetic-private-provider-detail',state}));
  await expect(page).toHaveURL(/\/connections$/);await expect(page.locator('#cs-status')).toContainText('denied');await expect(page.locator('#cs-name')).toHaveValue('denied-task-drive');
  await expect(page.locator('#cs-authorize-confirm')).not.toBeChecked();await expect(page.locator('#cs-task-return')).toBeVisible();
  await expectShellReady(page);
  await info.attach('denied-connection',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  await page.locator('#cs-task-link').click();await expect(page.locator('#vo-case-reference a')).toHaveAttribute('href',new RegExp('[?&]case='+fixture.case_id+'(?:&|$)'));
  const after=await(await request.get('/api/v1/vendor-onboarding/cases/'+fixture.case_id)).json();expectUnchangedCase(after,original);
  const stateAfter=await(await request.get('/__browser_fixture')).json();expect(stateAfter.connection_exchanges).toBe(fixture.connection_exchanges);expect(stateAfter.ticket_creates).toBe(fixture.ticket_creates);
});
test('unavailable renewal gives a usable reconnect choice and a failed refresh keeps it until readback',async({page,request},info)=>{
  const {fixture,original}=await beginTask({page,request},320);const canonical=await(await request.get('/api/v1/connection-setup')).json();
  // Only renewal availability is a response double; no live Google request runs.
  const data={...canonical,connections:[{name:'renewal-unavailable',revision:'c'.repeat(32),oauth:{profile:'google-drive',renewal_state:'reauth_required'}}]};let unavailable=false;
  await page.route('**/api/v1/connection-setup',route=>route.fulfill(unavailable?{status:503,contentType:'text/plain',body:'Unavailable'}:{json:data}));
  await page.locator('#cs-refresh').click();await expect(page.locator('#cs-connections')).toContainText('Unavailable: reconnect');
  await page.getByRole('button',{name:'Reconnect renewal-unavailable',exact:true}).click();await expect(page.locator('#cs-name')).toHaveValue('renewal-unavailable');
  unavailable=true;await page.locator('#cs-refresh').click();await expect(page.locator('#cs-status')).toContainText('unavailable');await expect(page.locator('#cs-authorize-button')).toBeDisabled();
  unavailable=false;await page.locator('#cs-refresh').click();await expect(page.locator('#cs-name')).toHaveValue('renewal-unavailable');await expect(page.locator('#cs-authorize-confirm')).not.toBeChecked();
  const bounds=await page.locator('#connection-setup').evaluate(node=>({scroll:node.scrollWidth,client:node.clientWidth}));expect(bounds.scroll).toBeLessThanOrEqual(bounds.client+1);
  await info.attach('renewal-recovery-mobile',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  await page.locator('#cs-task-link').click();await expect(page.locator('#vo-case-reference a')).toHaveAttribute('href',new RegExp('[?&]case='+fixture.case_id+'(?:&|$)'));
  expectUnchangedCase(await(await request.get('/api/v1/vendor-onboarding/cases/'+fixture.case_id)).json(),original);
});
