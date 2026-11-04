// An invited colleague accepts, signs out and signs back in; the signed-out
// pages they see are styled and fit a phone. Real owner form, real invite and
// real cookies on a fresh server; no injected identity or headers.
const {test,expect}=require('@playwright/test');
const {spawn}=require('node:child_process'),net=require('node:net'),path=require('node:path');
const pythonExecutable=require('./python-runtime');

async function availablePort(){
  const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}

async function looksRight(page){
  // The shell stylesheet loaded (brand font, small logo) and nothing scrolls sideways.
  const facts=await page.evaluate(()=>({
    font:getComputedStyle(document.body).fontFamily,
    logo:Math.round((document.querySelector('.brand__logo')||{getBoundingClientRect:()=>({width:999})}).getBoundingClientRect().width),
    overflow:document.documentElement.scrollWidth-window.innerWidth,
  }));
  expect(facts.font).toContain('Manrope');
  expect(facts.logo).toBeLessThan(80);
  expect(facts.overflow).toBeLessThanOrEqual(0);
}

test('invited colleague sets a passphrase, signs out and signs back in on a phone',async({browser},info)=>{
  test.setTimeout(120000);
  const port=await availablePort(),origin=`http://127.0.0.1:${port}`;
  const child=spawn(pythonExecutable,[path.join(__dirname,'owner_server.py'),'--port',String(port)],{cwd:__dirname,stdio:'ignore',windowsHide:true});
  const exited=new Promise(resolve=>child.once('exit',resolve));
  const contexts=[];
  try{
    await expect.poll(async()=>{try{return (await fetch(origin+'/livez')).status;}catch{return 0;}},{timeout:30000}).toBe(200);
    const owner=await browser.newContext({extraHTTPHeaders:{}});contexts.push(owner);
    await owner.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
    const ownerPage=await owner.newPage();
    const ownerPassphrase='Synthetic invite owner passphrase'; // pragma: allowlist secret - disposable synthetic account fixture
    await ownerPage.goto(origin+'/auth/local-owner');
    await ownerPage.locator('input[name="email"]').fill('invite-owner@example.test');
    await ownerPage.locator('input[name="password"]').fill(ownerPassphrase);
    await ownerPage.locator('input[name="password2"]').fill(ownerPassphrase);
    await ownerPage.locator('input[name="confirm"]').check();
    await ownerPage.locator('button[type="submit"]').click();
    await expect(ownerPage).toHaveURL(origin+'/start');
    const made=await owner.request.post(origin+'/users/invite',{form:{email:'colleague@example.test',role:'operator'},headers:{Origin:origin}});
    expect(made.status(),await made.text()).toBe(200);
    const link=(await made.text()).match(/\/auth\/invite\/inv_[A-Za-z0-9_-]+/)[0];

    const phone=await browser.newContext({extraHTTPHeaders:{},viewport:{width:390,height:844},isMobile:true,hasTouch:true});contexts.push(phone);
    await phone.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
    const page=await phone.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
    await page.goto(origin+link);
    await expect(page.getByRole('heading',{name:"You're invited"})).toBeVisible();
    await expect(page.locator('main')).toContainText('Operator');
    await expect(page.locator('main')).not.toContainText('as operator');
    await looksRight(page);
    await page.screenshot({path:info.outputPath('invite-phone.png'),fullPage:true});
    const passphrase='Synthetic invited colleague passphrase'; // pragma: allowlist secret - disposable synthetic account fixture
    await page.locator('input[name="password"]').fill(passphrase);
    await page.locator('input[name="password2"]').fill(passphrase+' typo');
    await page.getByRole('button',{name:'Accept invitation',exact:true}).click();
    await expect(page.locator('#owner-match')).toContainText('do not match');
    expect((await phone.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(false);
    await page.locator('input[name="password2"]').fill(passphrase);
    await page.getByRole('button',{name:'Accept invitation',exact:true}).click();
    // Acceptance ends on the saved result for this account (the link cannot grant again).
    await expect(page.getByRole('heading',{name:'Invitation accepted'})).toBeVisible();
    await expect(page.locator('main')).toContainText('it does not give access again');
    expect((await phone.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(true);

    // Sign out, then come back: the sign-in page is styled and accepts the passphrase.
    await page.goto(origin+'/auth/logout');
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    expect((await phone.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(false);
    await page.goto(origin+'/goals');
    await expect(page).toHaveURL(/\/auth\/local-login/);
    await looksRight(page);
    await expect(page.locator('main')).toContainText('Ask your administrator for an invitation');
    await page.screenshot({path:info.outputPath('sign-in-phone.png'),fullPage:true});
    await page.locator('input[name="email"]').fill('colleague@example.test');
    await page.locator('input[name="password"]').fill(passphrase);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();
    await expect(page).not.toHaveURL(/\/auth\/local-login/);
    expect((await phone.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(true);
    // The used link explains itself instead of locking anyone out: its own account
    // reads the saved result, and anyone else is told it is no longer available.
    const reread=await page.goto(origin+link);
    expect(reread.status()).toBe(200);
    await expect(page.getByRole('heading',{name:'Invitation accepted'})).toBeVisible();
    const stranger=await browser.newContext({extraHTTPHeaders:{}});contexts.push(stranger);
    const other=await stranger.newPage();
    const reused=await other.goto(origin+link);
    expect(reused.status()).toBe(410);
    await expect(other.getByRole('heading',{name:'Invitation not available'})).toBeVisible();
    expect(errors).toEqual([]);
  }finally{
    try{
      await test.step('Close isolated browser contexts',async()=>{for(const context of contexts)await context.close();});
    }finally{
      child.kill();
      await test.step('Wait for owned fixture process to exit',async()=>{await exited;});
    }
  }
});
