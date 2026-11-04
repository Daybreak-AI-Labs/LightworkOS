// Real palette rendering and focus transfer through installed Chromium.
const {test,expect}=require('@playwright/test');

test.beforeEach(async({context,baseURL})=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin
    ?route.continue():route.abort('blockedbyclient'));
});

test('a four-colour white theme derives readable runtime and editor preview colours',async({page},info)=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/chat');await page.locator('#prefs-menu > summary').click();
  await page.locator('#prefs-device-only').check();
  const saved=page.waitForResponse(response=>response.request().method()==='POST'
    &&new URL(response.url()).pathname==='/api/v1/preferences/display');
  await page.locator('#theme-select').selectOption('browser-white');expect((await saved).status()).toBe(200);
  await expect(page.locator('#theme-select')).toHaveValue('browser-white');
  await expect(page.locator('#theme-select')).toBeEnabled();await page.reload();
  await expect(page.locator('body')).toHaveClass(/theme-browser-white/);
  const runtime=await page.evaluate(()=>{
    const body=getComputedStyle(document.body),hint=document.querySelector('.composer__hint');
    return {palette:Object.fromEntries(['bg','panel','text','accent','border','muted','warn','danger']
      .map(key=>[key,body.getPropertyValue('--'+key).trim()])),
      background:body.backgroundColor,quiet:hint&&getComputedStyle(hint).color};
  });
  expect(runtime.palette).toEqual({bg:'#ffffff',panel:'#ffffff',text:'#111111',accent:'#111111',
    border:'#111111',muted:'#111111',warn:'#111111',danger:'#111111'});
  expect(runtime.background).toBe('rgb(255, 255, 255)');
  expect(runtime.quiet).toBe('rgb(17, 17, 17)');

  await page.goto('/settings/all?id=dashboard.themes&theme=browser-white');
  const setting=page.locator('[data-setting-id="dashboard.themes"]');
  const row=setting.locator('[data-grid-row][data-name="browser-white"]');
  await expect(row).toBeVisible();
  for(const key of ['border','muted','warn','danger']){
    await expect(row.locator(`[data-cell="${key}"] [data-cell-use]`)).not.toBeChecked();
  }
  await row.locator('[data-cell="text"] [data-cell-input]').focus();
  const preview=setting.locator('[data-theme-preview]');
  await expect(preview.locator('[role="status"]')).toContainText('meet the checked contrast thresholds');
  const computed=await preview.evaluate(panel=>{
    const sample=panel.querySelector('div'),input=panel.querySelector('input');
    return {background:getComputedStyle(sample).backgroundColor,
      border:getComputedStyle(input).borderTopColor,
      status:[...sample.querySelectorAll('p')].map(node=>({text:node.textContent,color:getComputedStyle(node).color})),
      editor:getComputedStyle(document.body).getPropertyValue('--bg').trim()};
  });
  expect(computed.background).toBe('rgb(255, 255, 255)');
  expect(computed.border).toBe('rgb(17, 17, 17)');
  expect(computed.status).toEqual([{text:'Warning: review needed',color:'rgb(17, 17, 17)'},
    {text:'Error: task could not finish',color:'rgb(17, 17, 17)'}]);
  expect(computed.editor).toBe('#ffffff');expect(errors).toEqual([]);
  await info.attach('computed-four-colour-palette',{body:JSON.stringify({runtime,computed}),contentType:'application/json'});
  await info.attach('theme-preview',{body:await page.screenshot(),contentType:'image/png'});
});

async function mobileDrawer(page){
  await page.setViewportSize({width:390,height:844});await page.goto('/chat');
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready','true');
  await page.locator('#cs-menu').click();
  await expect(page.locator('.cs-brand')).toBeFocused();
  await page.keyboard.press('Tab');await expect(page.locator('#cs-menu-close')).toBeFocused();
}

test('resizing an open chat drawer moves focus from hidden Close to visible navigation',async({page},info)=>{
  await mobileDrawer(page);
  await page.evaluate(()=>{
    window.drawerFocusEvents=[];
    for(const type of ['focusin','focusout'])document.addEventListener(type,event=>{
      window.drawerFocusEvents.push({type,target:event.target.id||event.target.className,
        active:document.activeElement.id||document.activeElement.tagName,
        related:event.relatedTarget&&(event.relatedTarget.id||event.relatedTarget.tagName)});
    });
    matchMedia('(max-width: 860px)').addEventListener('change',()=>{
      window.drawerFocusEvents.push({type:'media',active:document.activeElement.id||document.activeElement.tagName});
    });
  });
  await page.setViewportSize({width:1280,height:900});
  await expect(page.locator('#cs-menu-close')).toBeHidden();
  await expect.poll(()=>page.evaluate(()=>window.drawerFocusEvents.some(event=>event.type==='media'))).toBe(true);
  await info.attach('focus-events',{body:JSON.stringify(await page.evaluate(()=>window.drawerFocusEvents)),contentType:'application/json'});
  await expect(page.locator('.cs-brand')).toBeVisible();await expect(page.locator('.cs-brand')).toBeFocused();
  await expect(page.locator('body')).not.toHaveClass(/cs-drawer-open/);
  expect(await page.locator('main').evaluate(node=>node.inert)).toBe(false);
  await page.keyboard.press('Tab');await expect(page.locator('#cs-side a.cs-item[href="/chat"]')).toBeFocused();
});

test('desktop resize preserves focus on a visible drawer navigation link',async({page})=>{
  await mobileDrawer(page);await page.keyboard.press('Tab');
  const link=page.locator('#cs-side a.cs-item[href="/chat"]');await expect(link).toBeFocused();
  await page.setViewportSize({width:1280,height:900});await expect(link).toBeFocused();await expect(link).toBeVisible();
  expect(await page.locator('main').evaluate(node=>node.inert)).toBe(false);
});

test('desktop resize preserves focus handed from the drawer to its search dialog',async({page})=>{
  await mobileDrawer(page);await page.locator('#navfinder-open').click();
  const input=page.locator('#navfinder-input');await expect(input).toBeFocused();
  await page.setViewportSize({width:1280,height:900});await expect(input).toBeFocused();
  await expect(page.locator('#navfinder-dialog')).toBeVisible();
  await expect(page.locator('body')).not.toHaveClass(/cs-drawer-open/);
  expect(await page.locator('main').evaluate(node=>node.inert)).toBe(false);
});
