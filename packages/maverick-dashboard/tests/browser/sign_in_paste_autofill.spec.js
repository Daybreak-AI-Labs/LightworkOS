// Sign-in never fights paste or a password manager (WCAG 2.2 SC 3.3.8).
// Real owner setup, invitation, sign-in and supplier access-code pages on a
// fresh server: every field takes a real Ctrl/Cmd+V from the clipboard, and
// sign-in succeeds when a password manager fills the fields without keystrokes
// (simulated by setting each value and firing input/change, as managers do).
// No injected identity or headers. This does not exercise a real password
// manager extension or the operating system's clipboard.
const {test,expect}=require('@playwright/test');
const {spawn}=require('node:child_process'),net=require('node:net'),path=require('node:path');
const pythonExecutable=require('./python-runtime');

async function availablePort(){
  const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}

async function paste(page,field,text,log,writer=page){
  // The text is put on the clipboard by script in `writer`, then pasted with
  // the keyboard in `page`, as a person copying it from elsewhere would.
  await writer.evaluate(value=>navigator.clipboard.writeText(value),text);
  await field.click();await field.press('ControlOrMeta+V');
  await expect(field).toHaveValue(text);
  log.push({page:new URL(page.url()).pathname.replace(/inv_[A-Za-z0-9_-]+/,'inv_…'),
    field:await field.getAttribute('name')||await field.getAttribute('id'),pasted:true});
}

async function autofill(field,value){
  await field.evaluate((input,text)=>{
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,text);
    input.dispatchEvent(new Event('input',{bubbles:true}));
    input.dispatchEvent(new Event('change',{bubbles:true}));
  },value);
}

async function newContext(browser,origin){
  // Creating contexts directly avoids playwright.config's synthetic Origin header.
  const context=await browser.newContext({extraHTTPHeaders:{},permissions:['clipboard-read','clipboard-write']});
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
  return context;
}

test('every sign-in field takes a paste and a password manager fill',async({browser},info)=>{
  test.setTimeout(120000);
  // A fixed port may be given when the machine assigns ports to test runs.
  const port=Number(process.env.LIGHTWORK_SIGN_IN_FIXTURE_PORT)||await availablePort(),origin=`http://127.0.0.1:${port}`;
  const child=spawn(pythonExecutable,[path.join(__dirname,'owner_server.py'),'--port',String(port)],{cwd:__dirname,stdio:'ignore',windowsHide:true});
  const exited=new Promise(resolve=>child.once('exit',resolve));
  const contexts=[],log=[];
  try{
    await expect.poll(async()=>{try{return (await fetch(origin+'/livez')).status;}catch{return 0;}},{timeout:30000}).toBe(200);
    const owner=await newContext(browser,origin);contexts.push(owner);
    const ownerPage=await owner.newPage(),errors=[];ownerPage.on('pageerror',error=>errors.push(error.message));
    const ownerPassphrase='Synthetic pasted owner passphrase'; // pragma: allowlist secret - disposable synthetic account fixture
    await ownerPage.goto(origin+'/auth/local-owner');
    await expect(ownerPage.locator('input[name="email"]')).toHaveAttribute('autocomplete','username');
    await expect(ownerPage.locator('input[name="password"]')).toHaveAttribute('autocomplete','new-password');
    await expect(ownerPage.locator('input[name="password2"]')).toHaveAttribute('autocomplete','new-password');
    await paste(ownerPage,ownerPage.locator('input[name="email"]'),'paste-owner@example.test',log);
    await paste(ownerPage,ownerPage.locator('input[name="password"]'),ownerPassphrase,log);
    await paste(ownerPage,ownerPage.locator('input[name="password2"]'),ownerPassphrase,log);
    await ownerPage.locator('input[name="confirm"]').check();
    await ownerPage.locator('button[type="submit"]').click();
    await expect(ownerPage).toHaveURL(origin+'/start');
    const made=await owner.request.post(origin+'/users/invite',{form:{email:'paste-colleague@example.test',role:'operator'},headers:{Origin:origin}});
    expect(made.status(),await made.text()).toBe(200);
    const link=(await made.text()).match(/\/auth\/invite\/inv_[A-Za-z0-9_-]+/)[0];

    const colleague=await newContext(browser,origin);contexts.push(colleague);
    const page=await colleague.newPage();page.on('pageerror',error=>errors.push(error.message));
    await page.goto(origin+link);
    await expect(page.locator('input[autocomplete="username"]')).toHaveValue('paste-colleague@example.test');
    const passphrase='Synthetic pasted colleague passphrase'; // pragma: allowlist secret - disposable synthetic account fixture
    await paste(page,page.locator('input[name="password"]'),passphrase,log);
    await paste(page,page.locator('input[name="password2"]'),passphrase,log);
    await page.getByRole('button',{name:'Accept invitation',exact:true}).click();
    // Acceptance ends on the saved result for this account (the link cannot grant again).
    await expect(page.getByRole('heading',{name:'Invitation accepted',exact:true})).toBeVisible();
    await expect(page.locator('main')).toContainText('it does not give access again');
    expect((await colleague.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(true);

    // Signed out: paste works on the sign-in page, and a manager's fill signs in.
    await page.goto(origin+'/auth/logout');
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.goto(origin+'/auth/local-login');
    await expect(page.locator('input[name="password"]')).toHaveAttribute('autocomplete','current-password');
    await paste(page,page.locator('input[name="email"]'),'paste-colleague@example.test',log);
    await paste(page,page.locator('input[name="password"]'),passphrase,log);
    await page.locator('input[name="email"]').fill('');await page.locator('input[name="password"]').fill('');
    await autofill(page.locator('input[name="email"]'),'paste-colleague@example.test');
    await autofill(page.locator('input[name="password"]'),passphrase);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();
    await expect(page).not.toHaveURL(/\/auth\/local-login/);
    expect((await colleague.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(true);
    log.push({page:'/auth/local-login',field:'email+password',autofilled:true,signedIn:true});

    // A supplier pastes the access code from their invitation.
    const supplier=await newContext(browser,origin);contexts.push(supplier);
    const portal=await supplier.newPage();portal.on('pageerror',error=>errors.push(error.message));
    await portal.goto(origin+'/api/v1/external/third-party-collaboration/browser-supplier-portal-0001/portal');
    // The portal's Permissions-Policy turns off the clipboard for its own
    // scripts (a keyboard paste is unaffected), so the code is copied from
    // another page, like copying it from the invitation email.
    const copiedFrom=await supplier.newPage();await copiedFrom.goto(origin+'/auth/local-login');
    await paste(portal,portal.locator('#invitation-credential'),'synthetic-access-code-for-paste-check',log,copiedFrom);
    await info.attach('paste-and-autofill',{body:JSON.stringify(log,null,2),contentType:'application/json'});
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
