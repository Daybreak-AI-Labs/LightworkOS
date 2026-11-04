const {test,expect}=require('@playwright/test');
test('native reviewed team preserves choices and recovers the original direct and Copilot save',async({page,request,context,baseURL},info)=>{
 await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const state=async()=>await(await request.get('/__browser_fixture/department-team')).json();
 const before=await state();
 expect((await request.post('/api/v1/departments/sales_gtm/deploy')).status()).toBe(409);
 expect(await state()).toEqual(before);
 await page.setViewportSize({width:320,height:844});await page.goto('/workforce');
 const button=page.locator('[data-key="sales_gtm"][data-act="deploy"]');await expect(button).toHaveText('Update team');await button.click();
 const dialog=page.getByRole('dialog',{name:'Review team changes',exact:true});await expect(dialog.getByRole('button',{name:'Save reviewed team',exact:true})).toBeVisible();
 await expect(dialog).toContainText('Before');await expect(dialog).toContainText('After');await expect(dialog).toContainText('Preserve my customer review role');await expect(dialog).toContainText('Manual meeting follow-up');await expect(dialog).toContainText('New customer follow-up specialist');await expect(dialog).toContainText('latest 32 save receipts');
 await dialog.screenshot({path:info.outputPath('native-team-before-after-320px.png')});
 expect(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth)).toBeTruthy();
 await context.route('**/api/v1/department-team-updates/save',async route=>{const native=await route.fetch();expect(native.ok(),await native.text()).toBeTruthy();await route.abort('connectionfailed');});
 await dialog.getByRole('button',{name:'Save reviewed team',exact:true}).click();await expect(dialog).toContainText('Check the original result');await expect(dialog.getByRole('button',{name:'Check original result',exact:true})).toBeVisible();await context.unroute('**/api/v1/department-team-updates/save');
 const accepted=await state();expect(accepted.receipts).toHaveLength(1);expect(accepted.agents).toHaveLength(3);expect(accepted.agents.map(row=>row.name)).not.toContain(before.removed);expect(accepted.agents.find(row=>row.name===before.agents[0].name)).toEqual(before.agents[0]);
 await dialog.getByRole('button',{name:'Close',exact:true}).click();await button.click();await expect(dialog).toContainText('earlier save reply was not confirmed');await dialog.getByRole('button',{name:'Check original result',exact:true}).click();await expect(dialog).toContainText('Added 1 new specialist');expect(await state()).toEqual(accepted);
 await dialog.getByRole('button',{name:'Close',exact:true}).click();await expect(button).toBeFocused();
 // Real manual edits survive; their history does not claim the current team still matches.
 const current=await(await request.get('/api/v1/department-team-updates/context')).json();
 const prepare=async()=>await request.post('/api/v1/department-team-updates/review',{data:{department:'sales_gtm',expected_context:current.context}});
 let reviewed=await prepare();expect(reviewed.ok(),await reviewed.text()).toBeTruthy();const stale=(await reviewed.json()).token;
 await request.post('/__browser_fixture/department-team/change-roster');
 expect((await request.post('/api/v1/department-team-updates/save',{data:{token:stale,confirmed:true}})).status()).toBe(409);expect((await state()).receipts).toHaveLength(1);
 // A hidden instruction change must invalidate the same apparent roster review.
 reviewed=await prepare();expect(reviewed.ok(),await reviewed.text()).toBeTruthy();const oldSource=(await reviewed.json()).token;await request.post('/__browser_fixture/department-team/change-source');
 expect((await request.post('/api/v1/department-team-updates/save',{data:{token:oldSource,confirmed:true}})).status()).toBe(409);expect((await state()).receipts).toHaveLength(1);
 expect((await request.post('/api/v1/department-team-updates/review',{headers:{'X-Browser-Principal':'browser-colleague'},data:{department:'sales_gtm',expected_context:current.context}})).status()).toBe(409);
 const outsider=await(await request.get('/api/v1/department-team-updates/context',{headers:{'X-Browser-Principal':'browser-colleague'}})).json();expect((await request.post('/api/v1/department-team-updates/review',{headers:{'X-Browser-Principal':'browser-colleague'},data:{department:'sales_gtm',expected_context:outsider.context}})).status()).toBe(403);
 // Both Agent Factory entries host the exact same native review.
 await page.goto('/agents');await page.locator('.dep-deploy[data-key="sales_gtm"]').click();await expect(dialog).toContainText('Customer revised this job');await dialog.getByRole('button',{name:'Close',exact:true}).click();
 await page.locator('.dep-details[data-key="sales_gtm"]').click();await page.locator('#dept-dlg-deploy').click();await expect(dialog).toContainText('Before');await dialog.getByRole('button',{name:'Close',exact:true}).click();await expect(page.locator('.dep-details[data-key="sales_gtm"]')).toBeFocused();
 // Copilot gets readable choices and the same reviewed before/after; lost replies do not save twice.
 await page.goto('/workforce');await page.locator('#mv-copilot-fab').click();await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Review and update my department team',exact:true}).click();
 const form=page.locator('#mv-product-operation-form');await form.getByRole('combobox',{name:'Department',exact:true}).selectOption({label:'Sales & GTM'});
 const prepared=page.waitForResponse(response=>response.url().endsWith('/product-operations/prepare')&&response.request().method()==='POST');await form.getByRole('button',{name:'Review change',exact:true}).click();const original=(await(await prepared).json()).token;
 await expect(form).toContainText('Customer revised this job');await expect(form).toContainText('Saved roster');
 await context.route('**/api/v1/copilot/product-operations/execute',async route=>{const native=await route.fetch();expect(native.ok(),await native.text()).toBeTruthy();await route.abort('connectionfailed');});
 await form.locator('input[type="checkbox"]').check();await form.getByRole('button',{name:'Apply reviewed change',exact:true}).click();await expect(form).toContainText('result could not be confirmed');await context.unroute('**/api/v1/copilot/product-operations/execute');const copilotSaved=await state();expect(copilotSaved.receipts).toHaveLength(2);
 await form.getByRole('button',{name:'Check original outcome',exact:true}).click();await expect(form).toContainText('Team unchanged');expect(await state()).toEqual(copilotSaved);
 const replay=await request.post('/api/v1/copilot/product-operations/execute',{data:{token:original,confirmed:true}});expect(replay.ok(),await replay.text()).toBeTruthy();expect((await replay.json()).status).toBe('replayed');expect(await state()).toEqual(copilotSaved);
 await request.post('/__browser_fixture/department-team/change-roster');const recovery=await request.post('/api/v1/copilot/product-operations/recover',{data:{token:original}});expect(recovery.ok(),await recovery.text()).toBeTruthy();expect((await recovery.json()).message).toContain('saved roster has changed');expect((await state()).receipts).toHaveLength(2);
 // A concurrent native pack write is held until this reviewed team save completes.
 await request.post('/__browser_fixture/department-team/arm-source-race');reviewed=await prepare();expect(reviewed.ok(),await reviewed.text()).toBeTruthy();const raced=(await reviewed.json()).token;
 const raceSave=await request.post('/api/v1/department-team-updates/save',{data:{token:raced,confirmed:true}});expect(raceSave.ok(),await raceSave.text()).toBeTruthy();await expect.poll(async()=>(await state()).source_race.finished).toBe(true);const racedState=await state();expect(racedState.source_race.blocked).toBe(true);expect(racedState.source_race.error).toBe('');expect(racedState.receipts).toHaveLength(3);
 await page.getByRole('button',{name:'Close Copilot',exact:true}).click();await button.click();await expect(dialog).toContainText('Before');await page.evaluate(()=>document.dispatchEvent(new CustomEvent('lightwork:copilot-context-changed')));await expect(dialog.locator('#team-update-preview')).toBeEmpty();await dialog.getByRole('button',{name:'Close',exact:true}).click();await button.click();await expect(dialog).toContainText('Before');
 await context.setExtraHTTPHeaders({Origin:baseURL,'X-Browser-Principal':'browser-colleague'});await page.evaluate(()=>document.dispatchEvent(new CustomEvent('lightwork:account-context-changed')));await expect(dialog.locator('#team-update-preview')).toBeEmpty();await expect(dialog.getByRole('button',{name:'Save reviewed team',exact:true})).toBeHidden();expect((await page.request.post('/api/v1/copilot/product-operations/recover',{data:{token:original}})).status()).toBe(409);
 expect(errors).toEqual([]);
});
