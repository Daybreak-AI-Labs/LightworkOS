// A fresh owner walks every page tour and asks "Show me" on each step: every
// step must point at a visible control. Connections has a tour once it is on.
const {test,expect}=require('@playwright/test');
const {spawn}=require('node:child_process'),net=require('node:net'),path=require('node:path');
const pythonExecutable=require('./python-runtime');

async function availablePort(){
  const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}

test('every page tour step shows a control that is on the page',async({browser},info)=>{
  test.setTimeout(240000);
  const port=await availablePort(),origin=`http://127.0.0.1:${port}`;
  const child=spawn(pythonExecutable,[path.join(__dirname,'owner_server.py'),'--port',String(port)],
    {cwd:__dirname,stdio:'ignore',windowsHide:true});
  const exited=new Promise(resolve=>child.once('exit',resolve));
  let context;const walked=[],errors=[];
  try{
    await expect.poll(async()=>{try{return (await fetch(origin+'/livez')).status;}catch{return 0;}},{timeout:30000}).toBe(200);
    context=await browser.newContext({extraHTTPHeaders:{},viewport:{width:1280,height:900}});
    await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
    const page=await context.newPage();
    page.on('pageerror',error=>errors.push(error.message));
    await page.goto(origin+'/');await expect(page).toHaveURL(origin+'/auth/local-owner');
    const passphrase='Synthetic first owner product tour phrase'; // pragma: allowlist secret - disposable synthetic account fixture
    await page.locator('input[name="email"]').fill('tour-owner@example.test');
    await page.locator('input[name="password"]').fill(passphrase);
    await page.locator('input[name="password2"]').fill(passphrase);
    await page.locator('input[name="confirm"]').check();
    await page.locator('button[type="submit"]').click();
    await expect(page).toHaveURL(origin+'/start');
    await page.goto(origin+'/connections');
    await page.getByRole('button',{name:'Turn on Connections'}).click();
    await expect(page.locator('#cx-list')).toBeAttached();
    for(const destination of ['/start','/chat','/goals','/connections','/automations','/learned']){
      await page.goto(origin+destination);
      const open=page.locator('.lw-tour-offer button').filter({hasText:/^(Take a quick tour|Continue tour)$/});
      await expect(open,`${destination}: tour offer`).toBeVisible();await open.click();
      const dialog=page.locator('dialog.lw-tour[open]'),eyebrow=dialog.locator('.lw-tour__eyebrow');
      await expect(eyebrow).toContainText(/Step 1 of \d+/);
      const total=Number((await eyebrow.innerText()).match(/of (\d+)/)[1]);
      for(let step=1;step<=total;step++){
        await expect(eyebrow).toContainText(`Step ${step} of ${total}`);
        const title=await dialog.locator('h2').innerText();
        await dialog.getByRole('button',{name:'Show me'}).click();
        // Show me closes the step and marks its control; a missing control
        // keeps the step open and says so instead.
        await expect(dialog,`${destination}: ${title}`).toHaveCount(0);
        await expect(page.locator('.lw-tour-target'),`${destination}: ${title}`).toBeVisible();
        walked.push(`${destination}: ${title}`);
        await page.locator('.lw-tour-offer button').filter({hasText:'Continue tour'}).click();
        await expect(eyebrow).toContainText(`Step ${step} of ${total}`);
        await dialog.getByRole('button',{name:step<total?'Next':'Finish tour'}).click();
      }
      await expect(page.locator('dialog.lw-tour[open]')).toHaveCount(0);
    }
    expect(walked.length).toBeGreaterThanOrEqual(11);
    expect(errors).toEqual([]);
  }finally{
    await info.attach('product-tour',{body:JSON.stringify({walked,errors},null,2),contentType:'application/json'});
    try{if(context)await context.close();}finally{child.kill();await exited;}
  }
});
