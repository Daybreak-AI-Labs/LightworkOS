// Real Chromium/template/CSP/API/sealed stores, with synthetic Tauri IPC and
// provider token responses. This does not qualify a native binary or live OAuth.
const {test,expect}=require('@playwright/test');
test.beforeEach(async({page,request,baseURL,context})=>{
  expect(baseURL).toBe('http://127.0.0.1:8765');
  page.__errors=[];page.on('pageerror',error=>page.__errors.push(error.message));page.on('console',message=>{if(message.type()==='error')page.__errors.push(message.text());});
  await context.route('**/*',route=>new URL(route.request().url()).origin===baseURL?route.continue():route.abort());
  const read=async()=>{const result=await request.get('/api/v1/connection-setup');expect(result.ok()).toBe(true);return result.json();};
  let current=await read();
  for(const [flag,path] of [['enabled','/enable'],['desktop_return_enabled','/desktop-return/enable']])if(!current[flag]){
    const result=await request.post('/api/v1/connection-setup'+path,{data:{context:current.context,confirm:true}});expect(result.ok()).toBe(true);current=await read();
  }
  const registered=current.applications.find(row=>row.provider==='google');
  const saved=await request.put('/api/v1/connection-setup/application',{data:{confirm:true,context:current.context,provider:'google',client_id:'synthetic-browser-native-client',client_secret:'synthetic-browser-native-secret',expected_revision:registered?.revision||'',desktop_return:true}});expect(saved.ok()).toBe(true);
  await page.addInitScript(()=>{
    window.__nativeFixture={calls:[],outcome:'returned',attempt:null};
    window.__TAURI__={core:{invoke:async(command,payload)=>{
      const fixture=window.__nativeFixture;fixture.calls.push(command);
      if(command==='prepare_oauth_return'){fixture.attempt={...payload,handle:'d'.repeat(64)};return{...fixture.attempt,return_profile:'desktop-loopback-v1',callback_uri:'http://127.0.0.1:8766/connections',expires_in:600};}
      if(command==='launch_oauth_return'){fixture.attempt.state=payload.state;return null;}
      if(command==='consume_oauth_return')return{outcome:fixture.outcome,context:fixture.attempt.context,state:fixture.attempt.state,code:'synthetic-browser-native-code'};
      if(command==='cancel_oauth_return'){fixture.attempt=null;return null;}
      throw new Error('Unknown synthetic native command');
    }}};
  });
});
test.afterEach(async({page,context},info)=>{await context.unrouteAll({behavior:'ignoreErrors'});const artifact=info.outputPath('rendered-state.png');await page.screenshot({path:artifact,fullPage:true});await info.attach('rendered-state',{path:artifact,contentType:'image/png'});await info.attach('browser-errors',{body:JSON.stringify(page.__errors),contentType:'application/json'});expect(page.__errors).toEqual([]);});
async function fits(page){const bounds=await page.locator('#connection-setup').evaluate(node=>({scroll:node.scrollWidth,client:node.clientWidth,page:document.documentElement.scrollWidth,width:document.documentElement.clientWidth}));expect(bounds.scroll).toBeLessThanOrEqual(bounds.client+1);expect(bounds.page).toBeLessThanOrEqual(bounds.width+1);}
async function prepare(page,name){await page.goto('/connections');await expect(page.locator('#cs-options')).toBeVisible();await page.locator('#cs-profile').selectOption('google-drive');await page.locator('#cs-name').fill(name);await page.locator('#cs-authorize-confirm').check();await page.locator('#cs-authorize-button').click();await expect(page.locator('#cs-provider-link')).toContainText('system browser');expect(await page.locator('#cs-provider-link').getAttribute('href')).toBe('#');}

test('native return preserves the page and requires explicit Finish with real API single use',async({page,request,baseURL},info)=>{
  await page.setViewportSize({width:1280,height:950});await prepare(page,'native-browser-drive');
  const policy=(await request.get('/connections')).headers()['content-security-policy'];expect(policy).toContain("connect-src 'self' ipc: http://ipc.localhost");
  const before=(await (await request.get('/__browser_fixture')).json()).connection_exchanges;
  await page.locator('#cs-provider-link').click();await expect(page.locator('#cs-return')).toBeVisible();await expect(page).toHaveURL(new URL('/connections',baseURL).href);await expect(page.locator('#cs-finish')).toBeDisabled();
  expect((await (await request.get('/__browser_fixture')).json()).connection_exchanges).toBe(before);expect(await page.evaluate(()=>sessionStorage.getItem('lightwork:connection-consent:v1'))).toBeNull();
  expect(await page.locator('body').textContent()).not.toContain('synthetic-browser-native-code');await fits(page);await page.locator('#cs-return').scrollIntoViewIfNeeded();await page.screenshot({path:info.outputPath('native-finish-1280.png')});
  await page.locator('#cs-finish-confirm').check();await page.locator('#cs-finish').click();await expect(page.locator('#cs-status')).toContainText('Account connection saved');
  expect((await (await request.get('/__browser_fixture')).json()).connection_exchanges).toBe(before+1);await expect(page.locator('#cs-connections')).toContainText('native-browser-drive');
});
test('native denial and explicit cancellation keep the reviewed choice at 320 pixels without saving credentials',async({page,request},info)=>{
  await page.setViewportSize({width:320,height:950});await prepare(page,'denied-native-drive');await page.evaluate(()=>{window.__nativeFixture.outcome='denied';});
  const before=(await (await request.get('/__browser_fixture')).json()).connection_exchanges;await page.locator('#cs-provider-link').click();await expect(page.locator('#cs-status')).toContainText('denied sign-in');await expect(page.locator('#cs-return')).toBeHidden();await expect(page.locator('#cs-name')).toHaveValue('denied-native-drive');
  await page.locator('#cs-refresh').click();await expect(page.locator('#cs-name')).toHaveValue('denied-native-drive');await page.locator('#cs-authorize-confirm').check();await page.locator('#cs-authorize-button').click();await expect(page.locator('#cs-departure')).toBeVisible();
  const cancellation=page.waitForResponse(response=>response.url().endsWith('/connection-setup/cancel'));await page.locator('#cs-cancel-departure').click();expect((await (await cancellation).json()).cancelled).toBe(true);await expect(page.locator('#cs-status')).toContainText('Sign-in closed.');
  expect((await (await request.get('/__browser_fixture')).json()).connection_exchanges).toBe(before);await fits(page);
  await page.locator('#cs-app-details').evaluate(node=>{node.open=true;});await page.locator('#cs-native-settings').scrollIntoViewIfNeeded();await fits(page);await page.screenshot({path:info.outputPath('native-operator-320.png')});
});
