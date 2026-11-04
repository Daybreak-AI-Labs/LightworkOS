const {test,expect}=require('@playwright/test');
const root='/api/v1/consent/bulk-jobs',ops='/api/v1/copilot/product-operations',fixture='/__browser_fixture/consent-creation';
test('ordinary and Copilot consent requests retain exact selections and original allowance receipts',async({page,request,context,baseURL},info)=>{
 await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const state=async()=>{const reply=await request.get(fixture);expect(reply.ok(),await reply.text()).toBeTruthy();return reply.json();};
 const confirm=async name=>page.getByRole('dialog').getByRole('button',{name,exact:true}).click();
 await page.goto('/consent/bulk-jobs');await expect(page.locator('#cbj-new')).toBeEnabled();
 await page.getByRole('button',{name:'Prepare with Copilot',exact:true}).click();
 await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Prepare a consent request',exact:true}).click();
 await page.getByRole('button',{name:'Choose and review the request',exact:true}).click();
 let form=page.locator('#mv-product-operation-form #cbj-create');await expect(form).toBeVisible();
 await form.locator('#cbj-people').getByRole('checkbox',{name:'Customer-A',exact:true}).check();
 await form.getByRole('button',{name:'Next people',exact:true}).click();await form.locator('#cbj-people').getByRole('checkbox',{name:'Customer-C',exact:true}).check();
 await expect(form.locator('#cbj-people-count')).toContainText('2 people selected');
 await form.getByRole('button',{name:'Review bulk change',exact:true}).click();await expect(form.locator('#cbj-review-rows')).toContainText('Customer-A');await expect(form.locator('#cbj-review-rows')).toContainText('Customer-C');
 await context.route('**'+root+'/exports',async route=>{await route.fetch();await route.abort('connectionfailed');});
 await context.route('**'+root+'/requests/check',route=>route.abort('connectionfailed'));
 await form.getByRole('button',{name:'Start reviewed job',exact:true}).click();await confirm('Start job');
 await expect(page.locator('#mv-product-operation-form #cbj-operation-status')).toContainText('submission result could not be confirmed');
 expect((await state()).jobs).toHaveLength(1);
 await page.getByRole('button',{name:'Close Copilot',exact:true}).click();await expect(page.locator('#consent-bulk-jobs-shell #cbj-create')).toBeVisible();
 await expect(page.locator('#cbj-submission-recovery')).toBeVisible();
 await context.unroute('**'+root+'/exports');await context.unroute('**'+root+'/requests/check');
 await page.getByRole('button',{name:'Check submitted job',exact:true}).click();await expect(page.locator('#cbj-operation-status')).toContainText('No job was repeated');
 let saved=await state();expect(saved.jobs).toHaveLength(1);expect(saved.jobs[0].total_items).toBe(2);
 await page.goto('/consent/bulk-jobs?job='+saved.jobs[0].job_id);await expect(page.locator('#cbj-detail')).toBeVisible();await expect(page.locator('#cbj-detail-body')).toContainText('2');
 // Direct ordinary receipt pagination retains an earlier selected choice.
 await page.locator('#cbj-new').click();form=page.locator('#cbj-create');
 await form.getByRole('radio',{name:'Remove an end date from a choice',exact:true}).check();await form.locator('#cbj-people').getByRole('checkbox',{name:'Customer-A',exact:true}).check();
 await form.getByRole('button',{name:'Show the chosen people’s choices',exact:true}).click();await expect(form.locator('#cbj-receipts input')).toHaveCount(2);await form.locator('#cbj-receipts input').first().check();
 await form.getByRole('button',{name:'Older choices',exact:true}).click();await expect(form.locator('#cbj-receipts input')).toHaveCount(2);await form.locator('#cbj-receipts input').first().check();await expect(form.locator('#cbj-selected-receipts input')).toHaveCount(2);
 await form.getByRole('button',{name:'Review bulk change',exact:true}).click();await expect(form.locator('#cbj-review-rows tr')).toHaveCount(2);
 await form.getByRole('button',{name:'Start reviewed job',exact:true}).click();await confirm('Start job');await expect(form).toBeHidden();
 saved=await state();expect(saved.jobs).toHaveLength(2);const change=saved.jobs.find(row=>row.operation==='clear_expiration');expect(change.total_items).toBe(2);
 const run=await request.post(root+'/'+change.job_id+'/run',{data:{expected_revision:change.revision}});expect(run.ok(),await run.text()).toBeTruthy();expect((await run.json()).failed_items).toBe(0);expect((await state()).profiles.find(row=>row.profile_id==='Customer-A').revision).toBe(7);
 // The native submission boundary refuses a profile changed after review.
 await page.locator('#cbj-new').click();form=page.locator('#cbj-create');await form.getByRole('radio',{name:'Erase their stored identifier',exact:true}).check();await form.locator('#cbj-people').getByRole('checkbox',{name:'Customer-A',exact:true}).check();await form.getByRole('button',{name:'Review bulk change',exact:true}).click();await expect(form.locator('#cbj-review')).toBeVisible();await expect(form.locator('#cbj-review-rows tr')).toHaveCount(1);await request.post(fixture+'/change-profile');
 await form.getByRole('button',{name:'Start reviewed job',exact:true}).click();await confirm('Start job');await expect(page.locator('#cbj-operation-status')).toContainText('record changed');expect((await state()).jobs).toHaveLength(2);await expect(form.locator('#cbj-people input').first()).toBeChecked();
 // A direct lost allowance reply survives reload and reads only its original row.
 await context.route('**'+root+'/credits/grant',async route=>{await route.fetch();await route.abort('connectionfailed');});
 const allowanceBefore=(await state()).allowance.available;await page.getByRole('button',{name:'Add to the allowance',exact:true}).click();await confirm('Review the larger allowance');await confirm('Add');await expect(page.locator('#cbj-operation-status')).toContainText('allowance reply was interrupted');expect((await state()).allowance.available).toBe(allowanceBefore+10);
 await context.unroute('**'+root+'/credits/grant');await page.reload();await expect(page.locator('#cbj-allowance-recovery')).toBeVisible();await page.getByRole('button',{name:'Check allowance change',exact:true}).click();await expect(page.locator('#cbj-operation-status')).toContainText('No allowance was added again');expect((await state()).allowance.available).toBe(allowanceBefore+10);
 // Copilot uses the very same native grant and actual actor-bound receipt.
 await page.getByRole('button',{name:'Prepare with Copilot',exact:true}).click();await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Increase the consent record allowance',exact:true}).click();let operationForm=page.locator('#mv-product-operation-form');await operationForm.getByRole('combobox',{name:'Additional records allowed',exact:true}).selectOption({index:1});
 const prepared=page.waitForResponse(r=>r.url().endsWith(ops+'/prepare'));await operationForm.getByRole('button',{name:'Review change',exact:true}).click();const sealed=await(await prepared).json();await operationForm.locator('input[type=checkbox]').check();await operationForm.getByRole('button',{name:'Apply reviewed change',exact:true}).click();await expect(operationForm).toContainText('increased by 50');const accepted=await state();expect(accepted.allowance.available).toBe(allowanceBefore+60);
 const replay=await request.post(ops+'/execute',{data:{token:sealed.token,confirmed:true}});expect(replay.ok(),await replay.text()).toBeTruthy();expect((await replay.json()).status).toBe('replayed');expect((await state()).allowance).toEqual(accepted.allowance);
 // Changed account stops the hosted native selectors and removes private data.
 await page.locator('#mv-product-operation-buttons').getByRole('button',{name:'Prepare a consent request',exact:true}).click();await page.getByRole('button',{name:'Choose and review the request',exact:true}).click();await expect(page.locator('#mv-product-operation-form #cbj-create')).toBeVisible();
 await context.setExtraHTTPHeaders({Origin:baseURL,'X-Browser-Principal':'browser-colleague'});await page.locator('#cbj-find-people').click();await expect(page.locator('#cbj-people')).toBeEmpty();await expect(page.locator('#consent-bulk-jobs-shell #cbj-operation-status')).toContainText('account');expect((await state()).jobs).toHaveLength(2);
 await context.setExtraHTTPHeaders({Origin:baseURL});await page.setViewportSize({width:390,height:844});await page.goto('/consent/bulk-jobs');await expect(page.locator('#cbj-new')).toBeEnabled();await page.locator('#cbj-new').click();await page.locator('#cbj-create').screenshot({path:info.outputPath('native-consent-request-phone.png')});expect(errors).toEqual([]);
});
