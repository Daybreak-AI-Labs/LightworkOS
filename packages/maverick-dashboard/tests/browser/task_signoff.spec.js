const {test,expect}=require('@playwright/test');
const base='/api/v1/copilot/product-operations',fixture='/__browser_fixture/task-signoff';
test('exact native result review supports direct lost-response recovery and ordinary Copilot',async({page,request,context,baseURL},testInfo)=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  const setup=async(data={})=>{const r=await request.post(fixture+'/setup',{data});expect(r.ok(),await r.text()).toBeTruthy();return r.json();};
  const state=async(id)=>await (await request.get(fixture+'/state/'+id)).json();
  const selected=id=>({page:'/chat/goal/'+id,selection:{kind:'goal',id}});
  const catalog=async(id,headers={})=>await (await request.post(base+'/catalog',{headers,data:selected(id)})).json();
  const prepare=async(id,operation,input)=>{const current=await catalog(id),item=current.operations.find(row=>row.id===operation);expect(item).toBeTruthy();return request.post(base+'/prepare',{data:{...selected(id),context:current.context,operation,revision:item.revision,arguments:input}});};
  let row=await setup(),id=row.goal_id;
  await page.goto('/chat/goal/'+id);await page.locator('#signoff-note').fill('Forecast reconciled.');
  await context.route('**/api/v1/goals/'+id+'/signoff',async route=>{if(route.request().method()==='POST'){await route.fetch();await route.abort('connectionfailed');}else await route.continue();});
  await page.locator('#signoff-approve').click();await expect(page.locator('#signoff-msg')).toContainText('response was interrupted');
  await expect(page.locator('#signoff-approve')).toBeDisabled();await expect(page.locator('#signoff-recover')).toBeVisible();
  let before=await state(id);expect(before.review.decided_by).toBe('user:browser-reviewer');expect(before.review.note).toBe('Forecast reconciled.');expect(before.learning).toHaveLength(1);expect(before.handoff).toHaveLength(1);
  await context.unroute('**/api/v1/goals/'+id+'/signoff');
  await page.reload();
  // Delay the exact accepted receipt while the real live projection replaces
  // the panel with another reviewer's newer decision. Publish into the new
  // authorized panel, never its detached predecessor or another task.
  let releaseReceipt, receiptSeen;const release=new Promise(resolve=>releaseReceipt=resolve),seen=new Promise(resolve=>receiptSeen=resolve);
  await context.route('**/api/v1/goals/'+id+'/signoff?operation_id=*',async route=>{const response=await route.fetch();receiptSeen();await release;await route.fulfill({response});});
  await page.locator('#signoff-recover').click();await seen;
  await request.post(fixture+'/later-review/'+id);await page.evaluate(()=>window.mvRefreshAnswerPanel());
  await expect(page.locator('#signoff')).toContainText('A later native review');await expect(page.locator('#signoff-recover')).toBeDisabled();
  releaseReceipt();await expect(page.locator('#signoff-msg')).toContainText('Your original approval was recorded');
  await context.unroute('**/api/v1/goals/'+id+'/signoff?operation_id=*');
  const recovered=await state(id);expect(recovered.learning).toEqual(before.learning);expect(recovered.handoff).toEqual(before.handoff);expect(recovered.receipts).toEqual(before.receipts);expect(recovered.review.decided_by).toBe('user:browser-colleague');
  await expect(page.locator('#signoff-recover')).toBeHidden();
  const reference=before.receipts[0].operation_id;
  const receipt=await request.get('/api/v1/goals/'+id+'/signoff?operation_id='+reference);expect((await receipt.json()).receipt.current_result).toBe(true);
  expect((await request.get('/api/v1/goals/'+id+'/signoff?operation_id='+reference,{headers:{'X-Browser-Principal':'browser-colleague'}})).status()).toBe(404);
  await page.screenshot({path:testInfo.outputPath('native-result-review-receipt.png'),fullPage:true});
  // An identical decision by another reviewer is read-only, never claimed as this actor's decision.
  row=await setup({prior_reviewer:true});id=row.goal_id;
  const noop=await request.post('/api/v1/goals/'+id+'/signoff',{data:{decision:'approved',expected_updated_at:row.updated_at,operation_id:'a'.repeat(32)}});
  expect(noop.ok(),await noop.text()).toBeTruthy();const no=await noop.json();expect(no.receipt.changed).toBe(false);expect(no.receipt.own_decision).toBe(false);expect(no.receipt.message).toContain('already approved');
  const noState=await state(id);expect(noState.learning).toEqual([]);expect(noState.handoff).toEqual([]);expect(noState.review.decided_by).toBe('user:browser-colleague');
  // Copilot previews only the actual parsed deliverable, then records/replays one native rejection.
  row=await setup();id=row.goal_id;let current=await catalog(id);expect(JSON.stringify(current.operations.filter(item=>item.id.startsWith('reviews.result_')))).not.toContain('UNREVIEWED_SYNTHETIC_PREFACE');
  expect((await prepare(id,'reviews.result_reject',{acknowledged:false,note:'Needs correction'})).status()).toBe(422);
  await page.goto('/chat/goal/'+id);await page.locator('#signoff-copilot').click();
  await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Reject this finished result',exact:true}).click();
  let form=page.locator('#mv-product-operation-form');await form.getByRole('checkbox',{name:'I have reviewed the complete saved result',exact:true}).check();await form.getByRole('textbox',{name:'Review note (optional)',exact:true}).fill('Reconcile W2 before release.');
  const prepared=page.waitForResponse(r=>r.url().endsWith(base+'/prepare')&&r.request().method()==='POST');await form.getByRole('button',{name:'Review change',exact:true}).click();const material=await (await prepared).json();
  await expect(form).toContainText('300');await form.locator('input[type="checkbox"]').check();
  await context.route('**'+base+'/execute',async route=>{await route.fetch();await route.abort('connectionfailed');});
  await form.getByRole('button',{name:'Apply reviewed change',exact:true}).click();await expect(form).toContainText('result could not be confirmed');await context.unroute('**'+base+'/execute');
  const recorded=await state(id);expect(recorded.review.decision).toBe('rejected');expect(recorded.learning).toHaveLength(1);expect(recorded.handoff).toEqual([]);
  await form.getByRole('button',{name:'Check original outcome',exact:true}).click();
  await expect(form).toContainText('Your original rejection was recorded');expect(await state(id)).toEqual(recorded);
  const replay=await request.post(base+'/execute',{data:{token:material.token,confirmed:true}});expect(replay.ok(),await replay.text()).toBeTruthy();expect((await replay.json()).status).toBe('replayed');expect(await state(id)).toEqual(recorded);
  // Saved-result replacement refuses the prior review and leaves no decision or receipt.
  row=await setup();id=row.goal_id;const stale=await prepare(id,'reviews.result_approve',{acknowledged:true,note:''});expect(stale.ok(),await stale.text()).toBeTruthy();const token=(await stale.json()).token;
  await request.post(fixture+'/change/'+id);expect((await request.post(base+'/execute',{data:{token,confirmed:true}})).status()).toBe(409);expect((await state(id)).review).toBeNull();expect((await state(id)).receipts).toEqual([]);
  // Historical original receipts remain truthful after a result changes and never repeat follow-through.
  const historicalId=recorded.review.goal_id;await request.post(fixture+'/change/'+historicalId);
  const history=await request.post(base+'/recover',{data:{token:material.token}});expect(history.ok(),await history.text()).toBeTruthy();expect((await history.json()).message).toContain('historical receipt');expect((await state(historicalId)).learning).toHaveLength(1);
  expect(errors).toEqual([]);
});
