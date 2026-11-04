const {test,expect}=require('@playwright/test');
const start=require('./acceptance-server');

test('keyboard submission cannot default a fresh role grant to admin and an explicit custom role is recorded',async({browser},info)=>{
  test.setTimeout(180000);
  const app=await start(browser,info);
  let releaseShell;
  try{
    const person=(await app.state()).unassigned,page=app.page;
    await page.goto('/users');
    let form=page.locator('form[action="/users/set"]').filter({has:page.getByRole('button',{name:'Give role',exact:true})});
    await form.locator('select[name=principal]').selectOption(person);
    await expect(form.locator('select[name=role]')).toHaveValue('');
    let roleWrites=0;page.on('request',request=>{if(request.method()==='POST'&&new URL(request.url()).pathname==='/users/set')roleWrites++;});
    await form.getByRole('button',{name:'Give role',exact:true}).focus();
    await page.keyboard.press('Enter');
    // The shared error pattern: focus moves to the summary, whose link puts
    // focus in the role field; nothing is sent.
    const summary=form.locator('[data-mv-error-summary]');
    await expect(summary).toBeFocused();
    await expect(summary.getByRole('link',{name:'Choose the role to give them.',exact:true})).toBeVisible();
    await expect(form.locator('select[name=role]')).toHaveAttribute('aria-invalid','true');
    await page.keyboard.press('Tab');await page.keyboard.press('Enter');
    await expect(form.locator('select[name=role]')).toBeFocused();
    expect(roleWrites).toBe(0);expect((await app.state()).unassigned_role).toBeNull();
    // Native malformed/stale submissions must still fail before any grant.
    for(const binding of [null,'workspace-b']){
      const fields={principal:person,role:'admin'};
      if(binding)fields._expected_tenant=binding;
      const response=await app.context.request.post('/users/set',{form:fields});
      expect(response.status(),await response.text()).toBe(409);
      expect((await app.state()).unassigned_role).toBeNull();
    }
    const custom=page.locator('form[action="/users/roles/save"]');
    await custom.locator('input[name=name]').fill('evidence-reviewer');
    await custom.locator('input[value=audit]').check();
    await custom.locator('input[name=description]').fill('Synthetic acceptance role: inspect history only.');
    const shellGate=new Promise(resolve=>{releaseShell=resolve;});
    let shellWaiting=false;
    await page.route('**/static/lightwork-ui.js*',async route=>{
      shellWaiting=true;await shellGate;
      try{await route.continue();}catch(error){if(!page.isClosed()&&!/closed|disposed|intercept|invalid/i.test(String(error)))throw error;}
    });
    await custom.getByRole('button',{name:'Save role',exact:true}).click();
    await expect.poll(()=>shellWaiting).toBe(true);
    expect(await page.evaluate(()=>typeof window.mvWorkspaceTenant)).toBe('undefined');
    form=page.locator('form[action="/users/set"]').filter({has:page.getByRole('button',{name:'Give role',exact:true})});
    const nativeBindings=await page.locator('form[method="post"]').evaluateAll(forms=>forms.map(form=>({
      action:form.getAttribute('action'),binding:form.querySelector('input[name="_expected_tenant"]')?.value})));
    expect(nativeBindings.length).toBeGreaterThan(4);
    expect(nativeBindings.every(item=>item.binding==='workspace-a')).toBe(true);
    await form.locator('select[name=principal]').selectOption(person);
    await expect(form.locator('select[name=role]')).toHaveValue('');
    await form.getByRole('button',{name:'Give role',exact:true}).focus();
    await page.keyboard.press('Enter');
    await expect(form.locator('select[name=role]')).toBeFocused();
    expect(roleWrites).toBe(0);
    await expect(form.locator('select[name=principal]')).toHaveValue(person);
    await form.locator('select[name=role]').selectOption('evidence-reviewer');
    await form.getByRole('button',{name:'Give role',exact:true}).focus();
    const granted=page.waitForResponse(response=>response.request().method()==='POST'&&new URL(response.url()).pathname==='/users/set');
    await page.keyboard.press('Enter');
    const response=await granted;
    expect(response.status()).toBe(303);
    expect(new URLSearchParams(response.request().postData()).get('_expected_tenant')).toBe('workspace-a');
    await expect.poll(async()=>(await app.state()).unassigned_role).toBe('evidence-reviewer');
    expect(roleWrites).toBe(1);
    await expect(page.locator('body')).toContainText('Evidence reviewer');
  }finally{if(releaseShell)releaseShell();await app.close();}
});
