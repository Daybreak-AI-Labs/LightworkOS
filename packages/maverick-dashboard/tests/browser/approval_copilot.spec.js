const {test,expect}=require('@playwright/test');
const base='/api/v1/copilot/product-operations',fixture='/__browser_fixture/approval-copilot';
test('selected native approvals support ordinary Copilot decisions and exact receipt recovery',async({page,request,context,baseURL},testInfo)=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  const setup=async(data={})=>{const response=await request.post(fixture+'/setup',{data});expect(response.ok(),await response.text()).toBeTruthy();return await response.json();};
  const state=async(id)=>await (await request.get(fixture+'/state/'+id)).json();
  const selected=id=>({page:'/approvals',selection:{kind:'approval',id}});
  const catalog=async(id,headers={})=>await (await request.post(base+'/catalog',{headers,data:selected(id)})).json();
  const prepare=async(id,operation,input={},headers={})=>{
    const current=await catalog(id,headers),item=current.operations.find(row=>row.id===operation);
    return await request.post(base+'/prepare',{headers,data:{...selected(id),context:current.context,operation,revision:item.revision,arguments:input}});
  };
  const open=async(id,label)=>{
    await page.goto('/approvals');await page.locator('#approval-'+id).getByRole('button',{name:'Review with Copilot',exact:true}).click();
    await page.locator('#mv-product-operation-buttons').getByRole('button',{name:label,exact:true}).click();
    return page.locator('#mv-product-operation-form');
  };
  let row=await setup({risk:'critical'}),id=row.approval_id;
  let current=await catalog(id);expect(JSON.stringify(current)).not.toContain('synthetic-hidden-private-value');expect(JSON.stringify(current)).not.toContain('b'.repeat(64));
  const hidden=await catalog(id,{'X-Browser-Principal':'browser-colleague'});expect(hidden.operations.filter(row=>row.id.startsWith('reviews.approval_'))).toEqual([]);
  expect((await prepare(id,'reviews.approval_approve',{acknowledged:true,confirmation:''})).status()).toBe(422);
  let form=await open(id,'Approve the selected request');await form.getByRole('checkbox',{name:'I have read the full request and what this action will do',exact:true}).check();
  await form.getByRole('textbox',{name:'This is a critical action. Type APPROVE to confirm',exact:true}).fill('APPROVE');
  const reviewed=page.waitForResponse(response=>response.url().endsWith(base+'/prepare')&&response.request().method()==='POST');
  await form.getByRole('button',{name:'Review change',exact:true}).click();const material=await (await reviewed).json();
  await expect(form).toContainText('Assign these three records to Priya');await expect(form).toContainText('audit delivery');
  await form.locator('input[type="checkbox"]').check();
  await context.route('**'+base+'/execute',async route=>{await route.fetch();await route.abort('connectionfailed');});
  await form.getByRole('button',{name:'Apply reviewed change',exact:true}).click();await expect(form).toContainText('result could not be confirmed');
  await context.unroute('**'+base+'/execute');
  let checked=await state(id);expect(checked.state.status).toBe('approved');expect(checked.external_calls).toBe(0);
  expect(checked.events.filter(row=>row.kind==='approval_decision')).toHaveLength(1);expect(checked.events.every(row=>row.sig)).toBe(true);
  const before=JSON.stringify(checked.events),attempts=checked.delivery_attempts;
  const replay=await request.post(base+'/execute',{data:{token:material.token,confirmed:true}});expect(replay.ok(),await replay.text()).toBeTruthy();
  expect((await replay.json()).status).toBe('replayed');checked=await state(id);expect(JSON.stringify(checked.events)).toBe(before);expect(checked.delivery_attempts).toBe(attempts);
  expect((await request.post(base+'/execute',{headers:{'X-Browser-Principal':'browser-colleague'},data:{token:material.token,confirmed:true}})).status()).toBe(403);
  await page.reload();await page.locator('#mv-copilot-fab').click();
  await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Read the selected approval',exact:true}).click();
  await form.getByRole('button',{name:'Check current status',exact:true}).click();await expect(form).toContainText('Your original decisions');await expect(form).toContainText('Delivered');
  await page.screenshot({path:testInfo.outputPath('selected-decision-receipt.png'),fullPage:true});
  // Change native risk after card admission but before the actual vote. The
  // exact reviewed row is checked again at the native effect boundary.
  row=await setup();id=row.approval_id;const review=await prepare(id,'reviews.approval_approve',{acknowledged:true});expect(review.ok(),await review.text()).toBeTruthy();
  const fresh=await review.json();await request.post(fixture+'/mode',{data:{change:true}});
  const changed=await request.post(base+'/execute',{data:{token:fresh.token,confirmed:true}});expect(changed.status()).toBe(409);expect((await state(id)).state.status).toBe('pending');
  // A native competing claim arrives AFTER every dashboard precheck but
  // before the audited vote takes its SQLite reservation. Both interfaces
  // must refuse inside the transaction without an outbox/signoff write.
  for(const direct of [false,true]){
    row=await setup();id=row.approval_id;
    const review=direct?null:await prepare(id,'reviews.approval_approve',{acknowledged:true});
    const token=review?(await review.json()).token:null;
    await request.post(fixture+'/mode',{data:{late_claim:true}});
    const result=direct?await request.post('/api/v1/approvals/'+id+'/approve',{data:{acknowledged:true},headers:{'X-Lightwork-Approval-Binding':row.binding}}):
      await request.post(base+'/execute',{data:{token,confirmed:true}});
    expect(result.status()).toBe(409);const refused=await state(id);expect(refused.state.status).toBe('pending');expect(refused.state.approved_count).toBe(0);expect(refused.state.audit_pending_count).toBe(0);
    expect(refused.events.filter(row=>row.kind==='approval_decision')).toEqual([]);
  }
  // Native independence remains effective; owner access does not permit a
  // requester to approve their own two-person request.
  row=await setup({required:2});id=row.approval_id;const own=await prepare(id,'reviews.approval_approve',{acknowledged:true});expect(own.status()).toBe(409);
  expect((await request.post('/api/v1/approvals/'+id+'/approve',{data:{acknowledged:true},headers:{'X-Lightwork-Approval-Binding':row.binding}})).status()).toBe(403);expect((await state(id)).state.approved_count).toBe(0);
  // Older cards retain their truthful reject path and native redacted reason.
  row=await setup({legacy:true});id=row.approval_id;form=await open(id,'Reject the selected request');await form.getByLabel('Why are you rejecting it? (optional)',{exact:true}).fill('Please prepare a current review.');
  await form.getByRole('button',{name:'Review change',exact:true}).click();await form.locator('input[type="checkbox"]').check();await form.getByRole('button',{name:'Apply reviewed change',exact:true}).click();
  await expect(form).toContainText('Your decision was recorded');checked=await state(id);expect(checked.state.status).toBe('denied');expect(checked.events.filter(row=>row.action==='approval_rejection_reason')).toHaveLength(1);
  // A durable vote whose signed delivery is held remains non-effective. Its
  // readback never retries delivery or fabricates an effective authorization.
  row=await setup();id=row.approval_id;const pending=await prepare(id,'reviews.approval_approve',{acknowledged:true});const token=(await pending.json()).token;
  await request.post(fixture+'/mode',{data:{hold_audit:true}});const accepted=await request.post(base+'/execute',{data:{token,confirmed:true}});expect(accepted.ok(),await accepted.text()).toBeTruthy();expect((await accepted.json()).status).toBe('unconfirmed');
  const held=await state(id);expect(held.state.status).toBe('pending');expect(held.state.audit_pending_count).toBe(1);
  const readback=await request.post(base+'/execute',{data:{token,confirmed:true}});expect((await readback.json()).status).toBe('unconfirmed');expect((await state(id)).delivery_attempts).toBe(held.delivery_attempts);
  await request.post(fixture+'/mode',{data:{}});
  // The existing direct route's explicit recovery retains its native status
  // and headers. It finalizes the same original vote, not a second vote.
  const direct=await request.post('/api/v1/approvals/'+id+'/approve',{data:{acknowledged:true},headers:{'X-Lightwork-Approval-Binding':row.binding}});
  expect(direct.status()).toBe(204);expect(direct.headers()['x-lightwork-approval-audit']).toBe('delivered');expect((await state(id)).state.status).toBe('approved');
  const keysResponse=await request.post(fixture+'/keys');expect(keysResponse.ok(),await keysResponse.text()).toBeTruthy();const keys=await keysResponse.json();
  row=await setup();id=row.approval_id;const permitted=await catalog(id,{Authorization:'Bearer '+keys.approval});expect(permitted.operations.find(row=>row.id==='reviews.approval_read').available).toBe(true);
  const prohibited=await catalog(id,{Authorization:'Bearer '+keys.task});expect(prohibited.operations.filter(row=>row.id.startsWith('reviews.approval_'))).toEqual([]);
  const keyReview=await prepare(id,'reviews.approval_reject',{reason:'Synthetic approval-only key decision.'},{Authorization:'Bearer '+keys.approval});expect(keyReview.ok(),await keyReview.text()).toBeTruthy();
  const keyDecision=await request.post(base+'/execute',{headers:{Authorization:'Bearer '+keys.approval},data:{token:(await keyReview.json()).token,confirmed:true}});expect(keyDecision.ok(),await keyDecision.text()).toBeTruthy();expect((await state(id)).state.status).toBe('denied');
  expect(errors).toEqual([]);
});
