// An actual first owner and default product configuration. No injected account,
// domain store, successful provider reply, or configured-workflow fixture.
const {test,expect}=require('@playwright/test');
const {spawn}=require('node:child_process'),net=require('node:net'),path=require('node:path');
const pythonExecutable=require('./python-runtime');

async function availablePort(){
  const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}

test('fresh owner can browse every sidebar destination and sign out at phone width',async({browser},info)=>{
  test.setTimeout(240000);
  const port=await availablePort(),origin=`http://127.0.0.1:${port}`;
  const child=spawn(pythonExecutable,[path.join(__dirname,'owner_server.py'),'--port',String(port)],
    {cwd:__dirname,stdio:'ignore',windowsHide:true});
  const exited=new Promise(resolve=>child.once('exit',resolve));
  let context;
  const visited=[],errors=[],failures=[];
  try{
    await expect.poll(async()=>{try{return (await fetch(origin+'/livez')).status;}catch{return 0;}},{timeout:30000}).toBe(200);
    context=await browser.newContext({extraHTTPHeaders:{},viewport:{width:1280,height:900}});
    await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
    const page=await context.newPage();
    page.on('pageerror',error=>errors.push({page:page.url(),error:error.message}));
    page.on('response',response=>{if(response.status()===500)failures.push(response.url());});
    // A fresh install opens on owner creation before anything else; "Skip for
    // now" reaches Get started and is remembered for the next visit.
    await page.goto(origin+'/');
    await expect(page).toHaveURL(origin+'/auth/local-owner');
    await page.getByRole('link',{name:'Skip for now'}).click();
    await expect(page).toHaveURL(origin+'/start?owner=later');
    await page.goto(origin+'/');
    await expect(page).toHaveURL(origin+'/start');
    await page.goto(origin+'/auth/local-owner');
    const passphrase='Synthetic first owner navigation phrase'; // pragma: allowlist secret - disposable synthetic account fixture
    await page.locator('input[name="email"]').fill('navigation-owner@example.test');
    await page.locator('input[name="password"]').fill(passphrase);
    await page.locator('input[name="password2"]').fill(passphrase);
    await page.locator('input[name="confirm"]').check();
    await page.locator('button[type="submit"]').click();
    await expect(page).toHaveURL(origin+'/start');
    // The redirect URL can be committed while Chrome is still parsing the
    // streamed head. Read destinations only once the actual shell is ready.
    await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready','true');
    await expect(page.locator('#sidebar')).toBeVisible();
    const destinations=await page.locator('#sidebar a[href^="/"]').evaluateAll(links=>[...new Set(links.map(link=>link.getAttribute('href')))]);
    // Get started remains reachable from the home/finder; it is intentionally
    // folded out of the sidebar. The five main customer destinations stay in it.
    expect(destinations).toEqual(expect.arrayContaining(['/goals','/connections','/knowledge-access','/deliverables','/settings']));
    for(const destination of destinations){
      const response=await page.goto(origin+destination,{waitUntil:'domcontentloaded',timeout:30000});
      expect(response.status(),destination).toBe(200);
      await expect(page.locator('main')).toBeVisible();
      // The page shell has an explicit initialization signal. Network idle is
      // not a product readiness signal for pages with continuing activity.
      await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready','true');
      await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
      visited.push(destination);
    }
    await page.setViewportSize({width:320,height:740});
    await page.goto(origin+'/start');await page.waitForLoadState('networkidle');
    await expect(page.getByRole('link',{name:'Sign out',exact:true})).toBeVisible();
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1)).toBe(true);
    await info.attach('fresh-owner-phone',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
    await page.getByRole('link',{name:'Sign out',exact:true}).click();
    // Sign-out is a POST behind a confirmation page so a cross-site GET cannot
    // end an existing session. Exercise the complete customer journey.
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    expect((await context.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(false);
    await page.goto(origin+'/goals');await expect(page).toHaveURL(/\/auth\/local-login/);
    expect(errors).toEqual([]);expect(failures).toEqual([]);
  }finally{
    await info.attach('fresh-customer-navigation',{body:JSON.stringify({visited,errors,failures},null,2),contentType:'application/json'});
    try{if(context)await context.close();}finally{child.kill();await exited;}
  }
});
