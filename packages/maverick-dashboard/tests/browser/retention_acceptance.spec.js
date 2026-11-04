const {test,expect}=require('@playwright/test');
const start=require('./acceptance-server');

test('Keep until I choose clears mixed and all saved periods through the actual form and survives reload',async({browser},info)=>{
  test.setTimeout(180000);
  const app=await start(browser,info);
  try{
    const keys=['audit_days','episodes_days','events_days','messages_days','usage_days'];
    const seeded=await app.context.request.post('/api/v1/compliance/retention',{headers:{'X-Lightwork-Expected-Tenant':'workspace-a'},data:Object.fromEntries(keys.map(key=>[key,30]))});
    expect(seeded.status(),await seeded.text()).toBe(200);
    const page=app.page;await page.goto('/compliance');
    for(const key of keys)await expect(page.locator('#cmp-ret-'+key)).toHaveValue('30');
    await page.locator('#cmp-ret-audit_days').selectOption('');
    await page.locator('#cmp-ret-messages_days').selectOption('90');
    let saved=page.waitForResponse(response=>response.url().endsWith('/api/v1/compliance/retention')&&response.request().method()==='POST');
    await page.locator('#cmp-retention-save').click();
    const mixed=await saved;expect(mixed.status(),await mixed.text()).toBe(200);
    expect(mixed.request().postDataJSON()).toEqual({audit_days:null,episodes_days:30,events_days:30,messages_days:90,usage_days:30});
    await expect(page.locator('#cmp-retention-result')).toContainText('Retention periods saved.');
    await page.reload();
    await expect(page.locator('#cmp-ret-audit_days')).toHaveValue('');
    await expect(page.locator('#cmp-ret-messages_days')).toHaveValue('90');
    for(const key of keys)await page.locator('#cmp-ret-'+key).selectOption('');
    saved=page.waitForResponse(response=>response.url().endsWith('/api/v1/compliance/retention')&&response.request().method()==='POST');
    await page.locator('#cmp-retention-save').click();
    const all=await saved;expect(all.status(),await all.text()).toBe(200);
    expect(all.request().postDataJSON()).toEqual(Object.fromEntries(keys.map(key=>[key,null])));
    await expect(page.locator('#cmp-retention-result')).toContainText('Retention periods saved.');
    await page.reload();
    for(const key of keys)await expect(page.locator('#cmp-ret-'+key)).toHaveValue('');
    const readback=await app.context.request.get('/api/v1/compliance/retention');
    expect((await readback.json()).fields.every(field=>field.days===null)).toBe(true);
  }finally{await app.close();}
});
