const {test,expect}=require('@playwright/test');
const {spawn}=require('node:child_process'),net=require('node:net'),path=require('node:path');
const pythonExecutable=require('./python-runtime');

async function availablePort(){
  const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}

test('fresh owner setup and login submit real browser origin without header injection',async({browser},info)=>{
  // This journey owns a cold server (up to 30 seconds), two real password
  // operations, screenshots and process cleanup. Keep ordinary assertions at
  // ten seconds while bounding the complete lifecycle independently.
  test.setTimeout(90000);
  const port=await availablePort(),origin=`http://127.0.0.1:${port}`;
  const child=spawn(pythonExecutable,[path.join(__dirname,'owner_server.py'),'--port',String(port)],{cwd:__dirname,stdio:'ignore',windowsHide:true});
  const exited=new Promise(resolve=>child.once('exit',resolve));
  let context;
  try{
    await expect.poll(async()=>{try{return (await fetch(origin+'/livez')).status;}catch{return 0;}},{timeout:30000}).toBe(200);
    // Creating the context directly deliberately avoids playwright.config's
    // synthetic Origin header; otherwise a broken form policy is invisible.
    context=await browser.newContext({extraHTTPHeaders:{}});
    await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
    const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
    // A fresh install sends Get started to owner creation itself.
    await page.goto(origin+'/start');await expect(page).toHaveURL(origin+'/auth/local-owner');
    const password='Synthetic browser owner passphrase only'; // pragma: allowlist secret - disposable synthetic account fixture
    await page.locator('input[name="email"]').fill('native-owner@example.test');
    await page.locator('input[name="password"]').fill(password);
    // Mismatched passphrases are refused before anything is saved.
    await page.locator('input[name="password2"]').fill(password+' typo');await page.locator('input[name="confirm"]').check();
    await page.locator('button[type="submit"]').click();
    await expect(page.locator('#owner-match')).toContainText('do not match');
    expect((await context.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(false);
    await page.locator('input[name="password2"]').fill(password);
    const enrollment=page.waitForResponse(response=>response.request().method()==='POST'&&response.url()===origin+'/auth/local-owner');
    await page.locator('button[type="submit"]').press('Enter');
    const saved=await enrollment;expect(saved.status()).toBe(303);
    expect(await saved.request().headerValue('origin')).toBe(origin);
    await expect(page).toHaveURL(origin+'/start');
    expect((await context.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(true);
    await page.screenshot({path:info.outputPath('first-owner.png'),fullPage:true});
    await page.getByRole('link',{name:'Sign out',exact:true}).click();
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    expect((await context.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(false);
    await page.goto(origin+'/goals');
    await expect(page).toHaveURL(/\/auth\/local-login/);
    await page.locator('input[name="email"]').fill('native-owner@example.test');
    await page.locator('input[name="password"]').fill(password);
    // Signing in returns to the page that asked for it (here Tasks).
    const login=page.waitForResponse(response=>response.request().method()==='POST'&&new URL(response.url()).pathname==='/auth/local-login');
    await page.locator('button[type="submit"]').press('Enter');
    const signedIn=await login;expect(signedIn.status()).toBe(303);
    expect(new URL(signedIn.url()).searchParams.get('return_to')).toBe('/goals');
    expect(await signedIn.request().headerValue('origin')).toBe(origin);
    await expect(page).toHaveURL(origin+'/goals');expect(errors).toEqual([]);
  }finally{
    try{
      await test.step('Close isolated browser context',async()=>{if(context)await context.close();});
    }finally{
      child.kill();
      await test.step('Wait for owned fixture process to exit',async()=>{await exited;});
    }
  }
});
