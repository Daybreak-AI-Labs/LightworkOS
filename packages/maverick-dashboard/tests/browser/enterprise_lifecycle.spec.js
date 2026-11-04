// Real local invites/cookies and native authorization; synthetic content/provider only.
const {test,expect}=require('@playwright/test');
const {spawn}=require('node:child_process'),net=require('node:net'),path=require('node:path');
const pythonExecutable=require('./python-runtime');

async function availablePort(){
  const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}

test('invited employee connects only an approved own account, shares a captured artifact, exports and loses departed access',async({browser},info)=>{
  test.setTimeout(300000);
  const port=await availablePort(),origin=`http://127.0.0.1:${port}`;
  const child=spawn(pythonExecutable,[path.join(__dirname,'enterprise_server.py'),'--port',String(port)],{cwd:__dirname,stdio:['ignore','pipe','pipe'],windowsHide:true});
  let serverLog='';child.stdout.on('data',data=>serverLog+=data);child.stderr.on('data',data=>serverLog+=data);
  const exited=new Promise(resolve=>child.once('exit',resolve));
  const contexts=[],errors=[];
  child.on('error',error=>{serverLog+='\nSpawn error: '+error.message;});
  async function context(headers={}){
    const value=await browser.newContext({baseURL:origin,extraHTTPHeaders:headers,viewport:{width:1280,height:900}});
    await value.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
    value.setDefaultTimeout(15000);value.setDefaultNavigationTimeout(30000);
    contexts.push(value);return value;
  }
  async function accept(value,link){
    const page=await value.newPage();page.on('pageerror',error=>errors.push(error.message));
    await page.goto(link);await expect(page.getByRole('heading',{name:"You're invited"})).toBeVisible();
    // Accepting sets the colleague's passphrase so they can sign back in later.
    const passphrase='Synthetic invited colleague passphrase'; // pragma: allowlist secret - disposable synthetic account fixture
    await page.locator('input[name="password"]').fill(passphrase);await page.locator('input[name="password2"]').fill(passphrase);
    await page.getByRole('button',{name:'Accept invitation',exact:true}).click({timeout:45000});
    // The saved grant is confirmed first; opening the workspace is a separate step.
    await expect(page.getByRole('heading',{name:'Invitation accepted'})).toBeVisible();
    await page.getByRole('button',{name:/^Open /}).click();
    await expect(page).not.toHaveURL(/\/auth\/invite\//);
    expect((await value.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(true);
    return page;
  }
  async function signIn(value,email,passphrase){
    const page=await value.newPage();page.on('pageerror',error=>errors.push(error.message));
    await page.goto('/auth/local-login');
    await page.locator('input[name="email"]').fill(email);await page.locator('input[name="password"]').fill(passphrase);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();
    await expect(page).not.toHaveURL(/\/auth\/local-login/);
    expect((await value.cookies()).some(cookie=>cookie.name==='mvk_session')).toBe(true);
    return page;
  }
  try{
    await expect.poll(async()=>{if(child.exitCode!==null)throw Error('Fixture failed: '+serverLog);try{return(await fetch(origin+'/livez')).status;}catch(_){return 0;}},{timeout:120000,message:'Isolated enterprise fixture starts: '+serverLog}).toBe(200);
    const admin=await context({Origin:origin});
    // The administrator already has an account, so they sign in; an invitation could never replace it.
    const administratorPassphrase=serverLog.match(/FIXTURE_ADMIN_PASSPHRASE=(\S+)/);
    expect(administratorPassphrase).toBeTruthy();
    await signIn(admin,'admin@browser.example.test',administratorPassphrase[1]);
    const fixtureResponse=await admin.request.get('/__enterprise_fixture');
    expect(fixtureResponse.status(),await fixtureResponse.text()).toBe(200);
    const fixture=await fixtureResponse.json();
    expect(fixture.outbound_calls).toBe('blocked');
    const employee=await context(),manager=await context();
    const page=await accept(employee,fixture.invites.employee),review=await accept(manager,fixture.invites.manager);
    // Reopening a used link shows its own account the saved result, never a second grant;
    // anyone else gets "no longer valid".
    const reopened=await employee.request.get(fixture.invites.employee);expect(reopened.status()).toBe(200);
    const receipt=await reopened.text();expect(receipt).toContain('Invitation accepted');expect(receipt).not.toContain('Accept invitation');
    expect((await (await context()).request.get(fixture.invites.employee)).status()).toBe(410);
    expect((await employee.request.get(fixture.invites.expired)).status()).toBe(410);
    console.info('Enterprise journey: invitation and least privilege');
    for(const forbidden of ['/settings','/users','/users/departures']){
      const denied=await employee.request.get(forbidden);expect(denied.status(),forbidden).toBe(403);
    }
    const auditor=await context(),tenantAdmin=await context();
    await accept(auditor,fixture.invites.auditor);await accept(tenantAdmin,fixture.invites['workspace-admin']);
    for(const actor of [auditor,tenantAdmin]){
      expect((await actor.request.get('/account')).status()).toBe(200);
      expect((await actor.request.get('/settings')).status()).toBe(403);
      expect((await actor.request.get('/api/v1/employee-departures')).status()).toBe(403);
    }
    expect((await auditor.request.get('/connections')).status()).toBe(403);
    for(const actor of [manager,admin,auditor,tenantAdmin]){
      const denied=await actor.request.get('/chat/goal/'+fixture.goal);
      expect([403,404]).toContain(denied.status());expect(await denied.text()).not.toContain('Synthetic private brief');
    }
    console.info('Enterprise journey: approved own connection');
    await page.goto('/connections');await expect(page.locator('#cs-options')).toBeVisible();
    await expect(page.locator('#cs-app-save')).not.toBeVisible();
    await page.locator('#cs-profile').selectOption('google-drive');await page.locator('#cs-name').fill('employee-own-drive');
    await page.locator('#cs-authorize-confirm').check();await page.locator('#cs-authorize-button').click();
    await expect(page.locator('#cs-departure')).toBeVisible();
    const provider=new URL(await page.locator('#cs-provider-link').getAttribute('href'));
    expect(provider.hostname).toBe('accounts.google.com'); // Link is inspected, never followed.
    await page.goto('/connections?'+new URLSearchParams({code:'synthetic-employee-code',state:provider.searchParams.get('state')}));
    await expect(page.locator('#cs-return')).toBeVisible();
    await expect(page.locator('#cs-finish')).toBeDisabled();
    await page.locator('#cs-finish-confirm').check();await page.locator('#cs-finish').click();
    await expect(page.locator('#cs-connections')).toContainText('employee-own-drive');
    const own=await(await employee.request.get('/api/v1/connection-setup')).json();
    expect(own.can_manage_applications).toBe(false);expect(own.profiles.map(row=>row.id)).toEqual(['google-drive']);
    expect((await employee.request.put('/api/v1/connection-setup/application',{headers:{Origin:origin},data:{context:own.context,confirm:true,provider:'google',client_id:'forbidden',client_secret:'synthetic-forbidden'}})).status()).toBe(403);
    const colleague=await(await manager.request.get('/api/v1/connection-setup')).json();
    expect(colleague.connections.some(row=>row.name==='employee-own-drive')).toBe(false);

    console.info('Enterprise journey: exact own-account template input');
    const savedTemplate=await employee.request.post('/api/v1/workflows',{headers:{Origin:origin},data:{
      name:'employee-connected-review',title:'Connected review',body:'Review {{account}}',params:['account'],overwrite:false,
      parameter_schema:{version:1,fields:{account:{type:'connection',label:'Evidence account',required:true}}}
    }});
    expect(savedTemplate.status(),await savedTemplate.text()).toBe(201);
    await page.goto('/templates');
    const card=page.locator('[data-template-name="employee-connected-review"]');
    await card.locator('[data-prepare-template]').click();
    const accountPicker=card.locator('[data-connected-account]');
    await expect(accountPicker.locator('option')).toHaveCount(2);
    await accountPicker.selectOption({label:'employee-own-drive (gdrive)'});
    await card.getByRole('button',{name:'Check in Chat',exact:true}).click();
    await expect(page).toHaveURL(/\/chat$/);
    await expect(page.locator('textarea[name="description"]')).toHaveValue('Review employee-own-drive (gdrive)');
    const binding=JSON.parse(await page.locator('input[name="connection_references"]').inputValue());
    expect(binding).toHaveLength(1);expect(binding[0].name).toBe('employee-own-drive');expect(binding[0].owner).toBe(fixture.employee);
    // Preparing a template never starts paid work; discard this synthetic draft before the next journey.
    // This socket-blocked fixture has no configured model, so the composer is
    // intentionally disabled. Clear fixture state without pretending to run it.
    await page.locator('form[action="/chat/send"]').evaluate(form=>{
      for(const name of ['title','description'])form.querySelector('[name="'+name+'"]').value='';
      form.querySelector('[name="connection_references"]').value='[]';
    });

    console.info('Enterprise journey: governed source and correction');
    await page.goto('/knowledge-access');await page.locator('#ka-query').fill('synthetic governed browser policy');
    await page.locator('#ka-search').click();await expect(page.locator('#ka-results')).toContainText('Synthetic governed browser policy');
    await page.getByRole('button',{name:'View details for Synthetic governed browser policy'}).click();
    await expect(page.locator('#ka-detail')).toContainText('revalidated cache hit');
    const exported=page.waitForEvent('download');await page.locator('#ka-export').click();await exported;
    await expect(page.locator('#ka-status')).toContainText('Exported 1 currently eligible source');
    const requestForm=page.locator('#ka-request-form');await requestForm.locator('[name="request_type"]').selectOption('correction');
    await requestForm.locator('[name="reason"]').fill('Synthetic employee identifies a dated policy statement.');
    await requestForm.locator('[name="proposed_correction"]').fill('Synthetic corrected statement for independent review.');
    await requestForm.locator('[name="confirm"]').check();await page.locator('#ka-submit-request').click();
    await expect(page.locator('#ka-requests')).toContainText('Synthetic employee identifies');

    console.info('Enterprise journey: captured artifact and independent review');
    await page.goto('/project-reviews#project='+fixture.project);await page.locator('#pr-member').selectOption(fixture.manager);
    await page.locator('#pr-grant').click();await expect(page.locator('#pr-members')).toContainText('manager@browser.example.test');
    await page.locator('#pr-goal').selectOption(String(fixture.goal));await page.locator('#pr-preview').click();
    await expect(page.locator('#pr-preview-text')).toContainText('AI quality and live retrieval are unqualified');
    await page.locator('#pr-reviewer').selectOption(fixture.manager);await page.locator('#pr-due').fill(new Date(Date.now()+86400000).toISOString().slice(0,16));
    await page.locator('#pr-note').fill('Review only this selected captured artifact and its stated limits.');
    const sent=page.waitForResponse(response=>response.request().method()==='POST'&&response.url().endsWith('/packets'));
    await page.locator('#pr-send-button').click();
    await page.getByRole('dialog',{name:/Share exactly the captured result shown above/}).getByRole('button',{name:'Share for review',exact:true}).click();
    const packet=await(await sent).json();
    await review.goto('/project-reviews#packet='+packet.id);await expect(review.locator('#pr-result')).toContainText('Synthetic captured artifact');
    await review.locator('#pr-action').selectOption('approve');await review.locator('#pr-response-note').fill('The synthetic captured artifact and limitations were reviewed.');
    await review.locator('#pr-response-button').click();await review.getByRole('dialog',{name:'Save this Approve decision for the captured result? The live task will remain unchanged.'}).getByRole('button',{name:'Save decision',exact:true}).click();
    await expect(review.locator('#pr-packet-summary')).toContainText('Approved');
    expect([403,404]).toContain((await manager.request.get('/chat/goal/'+fixture.goal)).status());

    console.info('Enterprise journey: personal export and departure');
    await page.goto('/my-data');await page.locator('#pd-inventory').click();await expect(page.locator('#pd-stores')).toContainText('external');
    const personalExport=page.waitForEvent('download');await page.getByRole('button',{name:'Export this verified conversation scope',exact:true}).first().click();await personalExport;
    const departing=await admin.newPage();await departing.goto('/users/departures');
    await departing.locator('#ed-person').selectOption(fixture.employee);await departing.getByRole('button',{name:'Preview access and work',exact:true}).click();
    await expect(departing.locator('#ed-inventory')).toContainText('employee-own-drive');
    await departing.locator('#ed-custodian').selectOption(fixture.admin);await departing.locator('#ed-preserve').check();
    await departing.getByRole('button',{name:'Deactivate and begin handoff',exact:true}).click();
    await expect(departing.locator('#ed-cases')).toContainText('handoff required');
    await expect(departing.locator('#ed-cases')).toContainText('unconfirmed');
    const denied=await employee.request.get('/api/v1/my-data');expect([401,403]).toContain(denied.status());
    await page.locator('#pd-refresh').click();await expect(page.locator('#pd-memory')).toBeEmpty();
    const revoked=await admin.request.post('/__enterprise_fixture/revoke-session');expect(revoked.status()).toBe(200);
    expect([401,403]).toContain((await auditor.request.get('/api/v1/my-data')).status());
    const after=await(await admin.request.get('/__enterprise_fixture')).json();expect(after.connection_exchanges).toBe(1);
    expect(errors).toEqual([]);
    await info.attach('employee-departure-review',{body:await departing.screenshot({fullPage:true}),contentType:'image/png'});
  }finally{
    await info.attach('synthetic-enterprise-server',{body:serverLog.replace(/FIXTURE_ADMIN_INVITE=\S+/g,'FIXTURE_ADMIN_INVITE=[synthetic one-time link]'),contentType:'text/plain'});
    for(const value of contexts)await value.close();child.kill();await exited;
  }
});
