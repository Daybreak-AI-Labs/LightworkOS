const {test,expect}=require('@playwright/test');
const start=require('./acceptance-server');

test('a real switch in one tab pauses another tab draft and approval without cross-workspace writes',async({browser},info)=>{
  test.setTimeout(180000);
  const app=await start(browser,info);
  try{
    const original=await app.state();expect(original.selected).toBe('workspace-a');
    const created=await app.context.request.post('/api/v1/workflows',{headers:{'X-Lightwork-Expected-Tenant':'workspace-a'},data:{name:'workspace-draft',title:'Original A workflow',body:'Original A steps',params:[],overwrite:false}});
    expect(created.status(),await created.text()).toBe(201);
    const draft=app.page,approval=await app.context.newPage(),picker=await app.context.newPage();
    await draft.goto('/workflow-builder?edit=workspace-draft');
    await expect(draft.locator('.draft-recovery > [role=status]')).toContainText('Draft recovery is ready');
    await draft.locator('#wf-steps').fill('Unsaved workspace A draft');
    // Finish the legitimate debounced save in A before observing writes across
    // the switch. Navigation in the other tab does not synchronize autosave.
    await expect(draft.locator('.draft-recovery > [role=status]')).toContainText('Recovery copy saved');
    await approval.goto('/approvals');
    const reject=approval.locator(`button[data-id="${original.approvals['workspace-a']}"][data-action=deny]`);
    await expect(reject).toBeEnabled();
    const writes=[],approvalPosts=[];
    for(const page of [draft,approval])page.on('request',request=>{
      if(!['GET','HEAD','OPTIONS'].includes(request.method()))writes.push(request.url());
      if(page===approval&&request.method()==='POST'&&new URL(request.url()).pathname.includes('/api/v1/approvals/'))approvalPosts.push(request.url());
    });
    expect((await picker.goto('/workspace/tenant')).status()).toBe(200);
    await picker.locator('.tsel-pick[data-tenant="workspace-b"]').click();
    await expect.poll(async()=>(await app.state()).selected).toBe('workspace-b');
    for(const page of [draft,approval])await expect(page.locator('section[role=alert]').filter({hasText:'Your workspace changed in another tab.'})).toBeVisible();
    await expect(draft.locator('#wf-steps')).toBeFocused();
    await draft.setViewportSize({width:320,height:740});
    const narrowNotice=draft.locator('main section[role=alert]').filter({hasText:'Your workspace changed in another tab.'});
    await expect(narrowNotice).toBeVisible();
    const noticeBounds=await narrowNotice.boundingBox();
    expect(noticeBounds.x).toBeGreaterThanOrEqual(0);
    expect(noticeBounds.x+noticeBounds.width).toBeLessThanOrEqual(320);
    await expect(draft.locator('#wf-steps')).toHaveValue('Unsaved workspace A draft');
    // Exercise autosave after the switch as well as the explicit save action.
    await draft.locator('#wf-steps').fill('Edited after workspace switch');
    await expect(draft.locator('.draft-recovery > [role=status]')).toContainText('Your editor contents have been kept. Check your connection and try again.');
    await draft.locator('#wf-save-btn').click();
    await reject.click();
    await expect(approval.locator('#mv-form')).toBeVisible();
    await approval.locator('#mv-form-ok').click();
    await expect(draft.locator('#wf-status')).toContainText('Could not save the workflow');
    await expect(draft.locator('#wf-steps')).toHaveValue('Edited after workspace switch');
    await expect(approval.locator('#approval-msg')).toContainText('Could not');
    expect(approvalPosts).toEqual([]);
    expect(writes).toEqual([]);
    const stale=await app.context.request.post(`/api/v1/approvals/${original.approvals['workspace-a']}/deny`,{headers:{'X-Lightwork-Expected-Tenant':'workspace-a'}});
    expect(stale.status(),await stale.text()).toBe(409);
    expect((await app.state()).approval_states).toEqual({'workspace-a':'pending','workspace-b':'pending'});
    await approval.getByRole('link',{name:'Reopen in current workspace',exact:true}).click();
    await expect(approval.locator('meta[name="lightwork-workspace-tenant"]')).toHaveAttribute('content','workspace-b');
    await expect(approval.locator('body')).toContainText('Acceptance workspace B');
    await expect(approval.locator('section[role=alert]').filter({hasText:'Your workspace changed in another tab.'})).toHaveCount(0);
  }finally{await app.close();}
});

test('a fixed-workspace installation exposes no ineffective selector and refuses an API switch',async({browser},info)=>{
  test.setTimeout(150000);
  const app=await start(browser,info,{fixed:true});
  try{
    expect((await app.page.goto('/workspace/tenant')).status()).toBe(200);
    await expect(app.page.getByText('Your installation always uses one workspace.',{exact:true})).toBeVisible();
    await expect(app.page.locator('.tsel-pick,.tsel-clear,#tsel-create,#tsel-quick')).toHaveCount(0);
    const changed=await app.context.request.put('/api/v1/workspace/active-tenant',{headers:{'X-Lightwork-Expected-Tenant':'workspace-a'},data:{tenant_id:'workspace-b'}});
    expect(changed.status(),await changed.text()).toBe(409);
    expect(await changed.text()).toContain('uses a fixed workspace');
    expect((await app.state()).selected).toBe('workspace-a');
    const missing=await app.page.goto('/missing-acceptance-page');
    expect(missing.status()).toBe(404);
    await expect(app.page.getByRole('heading',{name:'Page not found',exact:true})).toBeVisible();
  }finally{await app.close();}
});
