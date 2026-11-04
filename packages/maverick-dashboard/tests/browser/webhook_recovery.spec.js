const {test,expect}=require('@playwright/test'),crypto=require('node:crypto');
const base='/settings/webhooks/recovery',copilot='/api/v1/copilot/product-operations';

test('an interrupted signing-secret publication is recovered without republishing credentials',async({page,request,context,baseURL},testInfo)=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  const arm=mode=>request.post('/__browser_fixture/webhook-recovery/arm',{data:{mode}});
  const state=async()=>await (await request.get('/__browser_fixture/webhook-recovery/state')).json();
  await page.goto('/settings#settings-integrations');
  const panel=page.locator('#webhook-change-recovery');await expect(panel).toBeVisible();
  await expect(page.locator('#wh-secret')).toBeEnabled();
  await arm('interrupt');const secret='synthetic-browser-original-rotation';  // pragma: allowlist secret -- synthetic test value
  await page.locator('#wh-secret').fill(secret);await page.locator('#wh-confirm').check();await page.locator('#wh-save').click();
  await expect(page.locator('#wh-state')).toContainText('not confirmed');
  await expect.poll(async()=> (await (await request.get(base)).json()).records.filter(row=>row.can_reconcile).length).toBe(1);
  let choices=await (await request.get(base)).json(),row=choices.records.find(item=>item.can_reconcile);
  expect(row.summary).toContain('exact reviewed local change is active');
  expect((await (await request.get(base,{headers:{'X-Browser-Principal':'browser-learning-reviewer'}})).json()).records).toEqual([]);
  const other=(await (await request.get(base,{headers:{'X-Browser-Principal':'browser-learning-reviewer'}})).json()).context;
  expect((await request.post(base+'/'+row.id+'/check',{headers:{'X-Browser-Principal':'browser-learning-reviewer'},data:{context:other,review:row.review,confirm:true}})).status()).toBe(409);
  expect((await request.post(base+'/'+row.id+'/check',{data:{context:'0'.repeat(64),review:row.review,confirm:true}})).status()).toBe(409);
  const body=JSON.stringify({description:'No title: do not create work'}),timestamp=String(Math.floor(Date.now()/1000));
  const sign=value=>'sha256='+crypto.createHmac('sha256',value).update(timestamp+'.'+body).digest('hex');
  expect((await request.post('/webhook/start',{data:body,headers:{'Content-Type':'application/json','X-Maverick-Timestamp':timestamp,'X-Maverick-Signature':sign(secret)}})).status()).toBe(403);
  expect((await request.post('/webhook/start',{data:body,headers:{'Content-Type':'application/json','X-Maverick-Timestamp':timestamp,'X-Maverick-Signature':sign('synthetic-fixture-control-key')}})).status()).toBe(400);
  expect((await request.post('/webhook/start',{data:body,headers:{'Content-Type':'application/json','X-Maverick-Timestamp':timestamp,'X-Maverick-Signature':sign('synthetic-wrong-key')}})).status()).toBe(403);
  await panel.getByRole('button',{name:'Refresh saved changes',exact:true}).click();await panel.getByRole('combobox').selectOption(row.id);
  await arm('refuse');await panel.getByRole('button',{name:'Record verified check',exact:true}).click();
  await page.locator('#mv-confirm-ok').click();
  await expect(panel.getByRole('status')).toContainText('not accepted');expect((await state()).writes).toBe(1);
  // Lose the response after the actual recovery succeeds, then read its receipt.
  await context.route('**/settings/webhooks/recovery/*/check',async route=>{await route.fetch();await route.abort('connectionfailed');});
  await panel.getByRole('button',{name:'Record verified check',exact:true}).click();await page.locator('#mv-confirm-ok').click();
  await expect(panel.getByRole('status')).toContainText('No change was repeated');
  await context.unroute('**/settings/webhooks/recovery/*/check');
  let checked=await state();expect(checked.writes).toBe(1);expect(checked.pending).toBe(0);
  expect(checked.events.map(item=>item.phase)).toEqual(['reviewed','reconciled_active']);
  expect(new Set(checked.events.map(item=>item.operation_id)).size).toBe(1);
  expect(checked.signed&&checked.all_journals_encrypted&&checked.completed_material_removed).toBe(true);
  expect(checked.events.every(item=>item.sig)).toBe(true);
  expect(JSON.stringify(checked.events)).not.toContain(secret);expect(JSON.stringify(checked.events)).not.toContain(crypto.createHash('sha256').update(secret).digest('hex'));
  const replay=await request.post(base+'/'+row.id+'/check',{data:{context:choices.context,review:row.review,confirm:true}});
  expect(replay.ok(),await replay.text()).toBeTruthy();expect((await state()).events).toHaveLength(2);
  await page.screenshot({path:testInfo.outputPath('saved-change-recovery.png'),fullPage:true});
  // A native confirmation outage rolls back exact old bytes. Copilot records
  // the old state truthfully, rather than claiming the attempted key was active.
  await arm('rollback');const reviewed=await (await request.get('/settings/webhooks')).json();
  const failed=await request.post('/settings/webhooks',{form:{action:'set',secret:'synthetic-browser-rolled-back',expected_generation:reviewed.expected_generation}});  // pragma: allowlist secret -- synthetic test value
  expect(failed.status()).toBe(503);
  choices=await (await request.get(base)).json();row=choices.records.find(item=>item.can_reconcile);expect(row.summary).toContain('exact previous settings');
  await page.reload();await page.locator('#mv-copilot-fab').click();
  await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Verify a signing-secret change',exact:true}).click();
  const form=page.locator('#mv-product-operation-form');await form.getByRole('combobox').selectOption({label:row.label});
  await form.getByRole('button',{name:'Review change',exact:true}).click();await expect(form).toContainText('exact previous settings');
  await form.locator('input[type="checkbox"]').check();await form.getByRole('button',{name:'Apply reviewed change',exact:true}).click();
  await expect(form).toContainText('records this attempt as not confirmed');
  checked=await state();expect(checked.writes).toBe(2);expect(checked.events.map(item=>item.phase)).toEqual(['reviewed','reconciled_active','reviewed','reconciled_previous']);
  expect(checked.pending).toBe(0);expect(checked.completed_material_removed).toBe(true);
  // Accepted native completion plus a lost private receipt is not claimed to
  // be a missing audit row. The page explicitly records a NEW state check.
  await page.locator('#mv-copilot-close').click();await arm('receipt');
  const receiptBefore=await (await request.get('/settings/webhooks')).json();
  const accepted=await request.post('/settings/webhooks',{form:{action:'set',secret:'synthetic-browser-receipt-loss',expected_generation:receiptBefore.expected_generation}});  // pragma: allowlist secret -- synthetic test value
  expect(accepted.ok(),await accepted.text()).toBeTruthy();expect((await accepted.json()).history_pending).toBe(true);
  choices=await (await request.get(base)).json();row=choices.records.find(item=>item.can_reconcile);expect(row.summary).toContain('earlier completion entry may already exist');
  await panel.getByRole('button',{name:'Refresh saved changes',exact:true}).click();await panel.getByRole('combobox').selectOption(row.id);
  await panel.getByRole('button',{name:'Record verified check',exact:true}).click();await expect(page.locator('#mv-confirm-msg')).toContainText('earlier completion entry may already exist');await page.locator('#mv-confirm-ok').click();
  await expect(panel.getByRole('status')).toContainText('A new verified state check');
  checked=await state();expect(checked.writes).toBe(3);expect(checked.events.slice(-3).map(item=>item.phase)).toEqual(['reviewed','confirmed','reconciled_active']);
  expect(new Set(checked.events.slice(-3).map(item=>item.operation_id)).size).toBe(1);expect(checked.pending).toBe(0);
  // A newly active external owner cannot be overridden or treated as evidence
  // that the original publication remains effective.
  await arm('interrupt');const before=await (await request.get('/settings/webhooks')).json();
  await request.post('/settings/webhooks',{form:{action:'set',secret:'synthetic-browser-stale-owner',expected_generation:before.expected_generation}});  // pragma: allowlist secret -- synthetic test value
  choices=await (await request.get(base)).json();row=choices.records.find(item=>item.can_reconcile);await arm('external');
  const stale=await request.post(base+'/'+row.id+'/check',{data:{context:choices.context,review:row.review,confirm:true}});expect(stale.status()).toBe(409);
  const after=await (await request.get(base)).json();expect(after.records.find(item=>item.id===row.id).can_reconcile).toBe(false);
  expect((await (await request.get('/settings/webhooks')).json()).source).toBe('external_secret');expect((await state()).writes).toBe(4);
  expect((await state()).events).toHaveLength(8);expect(errors).toEqual([]);
});
