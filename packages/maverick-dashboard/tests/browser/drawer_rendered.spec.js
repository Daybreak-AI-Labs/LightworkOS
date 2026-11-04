const {test,expect}=require('@playwright/test');

for(const width of [320,390,768])for(const mode of [
  {direction:'ltr',size:'standard'},
  {direction:'rtl',size:'larger'},
])test(`chat drawer Close remains visible and returns keyboard focus at ${width}px ${mode.direction} ${mode.size}`,async({page,context,baseURL},info)=>{
  await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin
    ?route.continue():route.abort('blockedbyclient'));
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  // Set the actual shipped maximum text preset through its acknowledged native
  // preference route. It is 125% root text, not an OS scaling qualification.
  await page.setViewportSize({width:1280,height:900});await page.goto('/chat');
  await expect(page.locator('#navfinder-dialog')).toHaveAttribute('data-navfinder-ready','true');
  await page.locator('#prefs-menu > summary').click();await page.locator('#prefs-device-only').check();
  const saved=page.waitForResponse(response=>response.request().method()==='POST'
    &&new URL(response.url()).pathname==='/api/v1/preferences/display');
  await page.locator('[data-ui-preference="text_size"]').selectOption(mode.size);
  expect((await saved).status()).toBe(200);
  await expect(page.locator('[data-ui-preference="text_size"]')).toBeEnabled();
  await expect(page.locator('html')).toHaveAttribute('data-text-size',mode.size);
  await page.keyboard.press('Escape');
  // Direction is browser CSS emulation only. English product text stays English;
  // this does not present an incomplete Arabic catalog as translated content.
  await page.evaluate(direction=>{document.documentElement.dir=direction;},mode.direction);
  await page.setViewportSize({width,height:844});
  const menu=page.locator('#cs-menu'),close=page.locator('#cs-menu-close');
  await menu.focus();await menu.press('Enter');await expect(page.locator('.cs-brand')).toBeFocused();
  await page.keyboard.press('Tab');await expect(close).toBeFocused();
  await expect(close).toHaveAccessibleName('Close menu');await expect(close).toBeVisible();
  // Visibility and focus are available before the 0.18s drawer entrance finishes.
  await expect.poll(async()=>page.locator('#cs-side').evaluate(node=>{
    const side=node.getBoundingClientRect();return side.left>=-1&&side.right<=innerWidth+1;
  })).toBe(true);
  const geometry=await close.evaluate(node=>{
    const rect=node.getBoundingClientRect(),side=document.getElementById('cs-side').getBoundingClientRect();
    return {left:rect.left,right:rect.right,top:rect.top,bottom:rect.bottom,width:innerWidth,height:innerHeight,
      sideLeft:side.left,sideRight:side.right,fontSize:getComputedStyle(document.documentElement).fontSize,
      mainInert:document.querySelector('main').inert,direction:getComputedStyle(node).direction};
  });
  expect(geometry.left).toBeGreaterThanOrEqual(0);expect(geometry.right).toBeLessThanOrEqual(width);
  expect(geometry.top).toBeGreaterThanOrEqual(0);expect(geometry.bottom).toBeLessThanOrEqual(844);
  expect(geometry.sideLeft).toBeGreaterThanOrEqual(-1);expect(geometry.sideRight).toBeLessThanOrEqual(width+1);
  expect(geometry.mainInert).toBe(true);expect(geometry.direction).toBe(mode.direction);
  expect(geometry.fontSize).toBe(mode.size==='larger'?'20px':'16px');
  await info.attach('drawer-geometry',{body:JSON.stringify(geometry),contentType:'application/json'});
  await info.attach('drawer-rendered',{body:await page.screenshot(),contentType:'image/png'});
  await close.press('Enter');await expect(menu).toBeFocused();await expect(menu).toHaveAttribute('aria-expanded','false');
  await expect(page.locator('body')).not.toHaveClass(/cs-drawer-open/);
  expect(await page.locator('main').evaluate(node=>node.inert)).toBe(false);
  await page.setViewportSize({width:1280,height:900});await expect(close).toBeHidden();
  expect(errors).toEqual([]);
});
