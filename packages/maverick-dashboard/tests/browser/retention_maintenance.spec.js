const {test,expect}=require('@playwright/test');
const base='/api/v1/copilot/product-operations',root='/api/v1/compliance/retention',fixture='/__browser_fixture/retention';
test('native retention reviews delete only eligible records and recover without destructive replay',async({page,request,context,baseURL},info)=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  const setup=async(data={})=>{const r=await request.post(fixture+'/setup',{data});expect(r.ok(),await r.text()).toBeTruthy();return r.json();};
  const state=async(id)=>await(await request.get(fixture+'/state/'+id)).json();
  async function confirmDialog(){await page.getByRole('dialog').getByRole('button',{name:'Delete reviewed records',exact:true}).click();}
  let row=await setup({race_writer:true});await page.goto('/compliance');await expect(page.locator('#cmp-retention-apply')).toBeEnabled();
  await page.locator('#cmp-retention-apply').click();await expect(page.locator('#cmp-retention-summary')).toContainText('2 eligible');
  await page.locator('#cmp-retention-holds').check();
  await context.route('**'+root+'/apply',async route=>{await route.fetch();await route.abort('connectionfailed');});
  await page.locator('#cmp-retention-confirm').click();await confirmDialog();await expect(page.locator('#cmp-retention-result')).toContainText('reply was interrupted');
  expect((await state(row.goal_id)).remaining).toBe(1);expect((await state(row.goal_id)).writer_blocked).toBe(true);await expect(page.locator('#cmp-retention-confirm')).toBeDisabled();
  await context.unroute('**'+root+'/apply');await page.reload();await expect(page.locator('#cmp-retention-result')).toContainText('2 removals were confirmed');
  const before=await state(row.goal_id);await page.locator('#cmp-retention-recover').click();await expect(page.locator('#cmp-retention-result')).toContainText('2 removals were confirmed');expect(await state(row.goal_id)).toEqual(before);
  // An actual native effect with a lost native result stays unknown and cannot
  // be redispatched by either result readback or a repeated confirmation.
  row=await setup({unknown:true});await page.locator('#cmp-retention-apply').click();await page.locator('#cmp-retention-holds').check();await page.locator('#cmp-retention-confirm').click();await confirmDialog();
  await expect(page.locator('#cmp-retention-result')).toContainText('outcomes or activity records remain unconfirmed');await expect(page.locator('#cmp-retention-confirm')).toBeHidden();
  const unknown=await state(row.goal_id);expect(unknown.remaining).toBe(1);await page.locator('#cmp-retention-recover').click();expect(await state(row.goal_id)).toEqual(unknown);
  const histories=await(await request.get(root+'/reviews')).json(),unknownId=histories.records[0].id;
  const repeated=await request.post(root+'/apply',{data:{review_id:unknownId,confirm_no_holds:true,context:histories.context,operation_id:'a'.repeat(32)}});expect(repeated.ok(),await repeated.text()).toBeTruthy();expect((await repeated.json()).unresolved).toBe(true);expect(await state(row.goal_id)).toEqual(unknown);
  expect((await request.get(root+'/runs/'+unknownId,{headers:{'X-Browser-Principal':'browser-learning-reviewer'}})).status()).toBe(404);
  // An unacknowledged review audit blocks every native store before deletion.
  row=await setup({audit_refused:true});const noAudit=await state(row.goal_id);
  await page.locator('#cmp-retention-apply').click();await page.locator('#cmp-retention-holds').check();await page.locator('#cmp-retention-confirm').click();await confirmDialog();
  await expect(page.locator('#cmp-retention-result')).toContainText('review could not be recorded');expect(await state(row.goal_id)).toEqual(noAudit);
  await page.locator('#cmp-retention-recover').click();expect(await state(row.goal_id)).toEqual(noAudit);
  // Same-count changes are refused by the native transaction before DELETE;
  // candidate seals never enter an API result or Copilot guide.
  row=await setup();const exact=await(await request.post(root+'/preview')).json();
  expect(JSON.stringify(exact)).not.toContain('review_binding');expect(JSON.stringify(exact)).not.toContain('digest');
  const beforeChange=await state(row.goal_id);await request.post(fixture+'/change/'+row.goal_id);
  const changed=await request.post(root+'/apply',{data:{review_id:exact.id,context:exact.context,expected_revision:exact.revision,confirm_no_holds:true,operation_id:'c'.repeat(32)}});
  expect(changed.status()).toBe(409);expect(await changed.text()).toContain('eligible records changed');expect(await state(row.goal_id)).toEqual(beforeChange);
  const blocked=await(await request.get(root+'/runs/'+exact.id)).json();expect(blocked.steps[0].status).toBe('blocked');expect(blocked.message).toContain('Blocked stores were not deleted');expect(blocked.can_apply).toBe(false);
  // Ordinary Copilot creates its own native preview, then uses the exact same
  // reviewed native deletion contract and original receipt recovery.
  row=await setup();await page.locator('#cmp-retention-copilot').click();
  await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Preview old records',exact:true}).click();
  let form=page.locator('#mv-product-operation-form');await form.getByRole('button',{name:'Review change',exact:true}).click();await form.locator('input[type=checkbox]').check();await form.getByRole('button',{name:'Apply reviewed change',exact:true}).click();await expect(form).toContainText('Retention preview saved');
  await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Confirm a saved retention review',exact:true}).click();
  await expect(form.getByRole('combobox',{name:'Saved retention review',exact:true}).locator('option').first()).toContainText('6 eligible at preview');
  await form.getByRole('combobox',{name:'Saved retention review',exact:true}).selectOption({index:0});await form.getByRole('checkbox',{name:'I confirmed with the records owner that no preservation hold applies',exact:true}).check();
  const prepared=page.waitForResponse(r=>r.url().endsWith(base+'/prepare'));await form.getByRole('button',{name:'Review change',exact:true}).click();const sealed=await(await prepared).json();
  await form.locator('input[type=checkbox]').check();await form.getByRole('button',{name:'Apply reviewed change',exact:true}).click();await expect(form).toContainText('Deletion completed');
  const after=await state(row.goal_id);expect(after.remaining).toBe(1);const replay=await request.post(base+'/execute',{data:{token:sealed.token,confirmed:true}});expect(replay.ok(),await replay.text()).toBeTruthy();expect((await replay.json()).status).toBe('replayed');expect(await state(row.goal_id)).toEqual(after);
  // Current policy changes refuse an older review before any native dispatch.
  const old=await(await request.post(root+'/preview')).json();await request.post(root,{data:{messages_days:90}});
  expect((await request.post(root+'/apply',{data:{review_id:old.id,expected_revision:old.revision,context:old.context,confirm_no_holds:true,operation_id:'b'.repeat(32)}})).status()).toBe(409);
  await page.setViewportSize({width:390,height:844});await page.goto('/compliance#cmp-retention');await page.reload();await expect(page.locator('#cmp-retention-history')).toBeVisible();
  await expect(page.locator('#cmp-ret-messages_days')).toHaveValue('90');
  await page.locator('#cmp-retention-form').locator('..').screenshot({path:info.outputPath('native-retention-phone.png')});expect(errors).toEqual([]);
});
