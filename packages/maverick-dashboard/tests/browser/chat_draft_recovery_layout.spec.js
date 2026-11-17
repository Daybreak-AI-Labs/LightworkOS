const {test,expect}=require('@playwright/test');

// Live: "Draft recovery ready" opened by itself as a floating panel over the
// "Check budget before starting" note and the suggestion cards, and it could
// not be closed until a choice was made. Now a recovery copy only changes
// the row's words; opened by the person, the panel sits in the page flow.
test.beforeEach(async({context,baseURL})=>{
  const origin=new URL(baseURL).origin;
  await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort('blockedbyclient'));
});

async function overlaps(page,selector,others){
  return page.evaluate(([selector,others])=>{
    const box=document.querySelector(selector).getBoundingClientRect();
    return others.flatMap(other=>[...document.querySelectorAll(other)]).filter(node=>{
      const rect=node.getBoundingClientRect();
      return rect.width&&rect.height&&rect.left<box.right&&box.left<rect.right&&rect.top<box.bottom&&box.top<rect.bottom;
    }).map(node=>node.tagName+'.'+node.className);
  },[selector,others]);
}

test('a chat recovery copy waits for review without covering or blocking the page',async({browser,page,baseURL})=>{
  await page.goto('/chat');
  await page.locator('fieldset.composer__controls').evaluate(node=>{node.disabled=false;});
  const saved=page.waitForResponse(response=>response.request().method()==='PUT'&&response.url().includes('/api/v1/drafts/'));
  await page.locator('#composer-title').fill('Unsent request kept for recovery');
  expect((await saved).status()).toBe(200);
  const context=await browser.newContext({baseURL});
  try {
    await context.route('**/*',route=>new URL(route.request().url()).origin===new URL(baseURL).origin?route.continue():route.abort('blockedbyclient'));
    const restarted=await context.newPage();await restarted.goto('/chat');
    // The composer's own row (Chat's viewpoints form has another).
    const COMPOSER_ROW='[data-draft-host] > .draft-recovery > .draft-recovery__compact';
    const row=restarted.locator(COMPOSER_ROW);
    await expect(row.locator(':scope > summary')).toHaveText('Recovery copy needs review');
    await expect(row).not.toHaveAttribute('open','');
    // Nothing covers the budget note or the suggestions, and typing works.
    expect(await overlaps(restarted,'[data-draft-host] > .draft-recovery',['[data-budget-launch]','.cs-viewpoints'])).toEqual([]);
    await restarted.locator('fieldset.composer__controls').evaluate(node=>{node.disabled=false;});
    await restarted.locator('#composer-title').fill('Typing goes on while the copy waits');
    await expect(restarted.locator('#composer-title')).toHaveValue('Typing goes on while the copy waits');
    // Opened by the person, the panel is in the page flow and closes again.
    await row.locator(':scope > summary').click();
    await expect(row).toHaveAttribute('open','');
    expect(await restarted.locator(COMPOSER_ROW+' > div').evaluate(node=>getComputedStyle(node).position)).not.toBe('absolute');
    expect(await overlaps(restarted,COMPOSER_ROW+' > div',['#composer-title','[data-budget-launch]'])).toEqual([]);
    await row.locator(':scope > summary').click();
    await expect(row).not.toHaveAttribute('open','');
  } finally { await context.close(); }
});
