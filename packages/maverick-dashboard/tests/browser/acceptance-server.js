// A new loopback process/home for each acceptance case, with bounded teardown.
const {expect}=require('@playwright/test');
const {spawn}=require('node:child_process'),net=require('node:net'),path=require('node:path');
const python=require('./python-runtime');

module.exports=async function start(browser,info,{fixed=false}={}){
  const listener=net.createServer();await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
  const port=listener.address().port;await new Promise(resolve=>listener.close(resolve));
  const origin=`http://127.0.0.1:${port}`;
  const child=spawn(python,[path.join(__dirname,'workspace_switch_server.py'),'--port',String(port),...(fixed?['--fixed']:[])],
    {cwd:__dirname,stdio:['ignore','pipe','pipe'],windowsHide:true});
  let log='',context;
  const exited=new Promise(resolve=>child.once('exit',resolve));
  child.stdout.on('data',data=>log+=data);child.stderr.on('data',data=>log+=data);
  child.on('error',error=>log+='\n'+error.message);
  async function close(){
    if(context)await context.close();
    if(child.exitCode===null){
      child.kill();let timer;
      try{await Promise.race([exited,new Promise(resolve=>{timer=setTimeout(resolve,10000);})]);}
      finally{clearTimeout(timer);}
    }
    await info.attach('workspace-fixture-log',{body:Buffer.from(log),contentType:'text/plain'});
    if(child.exitCode===null&&child.signalCode===null)throw Error('Owned workspace fixture did not stop');
  }
  try{
    await expect.poll(async()=>{if(child.exitCode!==null)throw Error(log);try{return(await fetch(origin+'/livez')).status;}catch(_){return 0;}},{timeout:120000}).toBe(200);
    context=await browser.newContext({baseURL:origin,extraHTTPHeaders:{Origin:origin}});
    await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
    context.setDefaultTimeout(15000);context.setDefaultNavigationTimeout(30000);
    const page=await context.newPage(),passphrase=log.match(/FIXTURE_ADMIN_PASSPHRASE=(\S+)/);
    expect(passphrase,log).toBeTruthy();
    // The administrator already has an account, so they sign in; an invitation could never replace it.
    await page.goto('/auth/local-login');
    await page.locator('input[name="email"]').fill('acceptance-admin@example.test');
    await page.locator('input[name="password"]').fill(passphrase[1]);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();
    await expect(page).not.toHaveURL(/\/auth\/local-login/);
    expect((await context.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(true);
    const state=async()=>{const response=await context.request.get('/__workspace_acceptance');expect(response.status(),await response.text()).toBe(200);return response.json();};
    return {origin,context,page,state,close};
  }catch(error){await close();throw error;}
};
