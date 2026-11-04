const {test, expect} = require('@playwright/test');

function localTime(minutesFromNow) {
  const d = new Date(Date.now() + minutesFromNow * 60000);
  const two = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${two(d.getMonth()+1)}-${two(d.getDate())}T${two(d.getHours())}:${two(d.getMinutes())}`;
}

async function enableFeature(page, name) {
  await expect(page).toHaveURL(new RegExp(`/settings/all\\?id=features\\.${name}$`));
  const feature = page.locator(`[data-setting-id="features.${name}"]`);
  const toggle = feature.getByRole('switch');
  await expect(toggle).toBeVisible();
  // The browser server is shared: an earlier journey may already have turned
  // Copilot changes on, and then there is nothing to save.
  if (!(await toggle.isChecked())) {
    await toggle.check();
    await feature.locator('[data-save]').click();
    const review = page.getByRole('dialog', {name: 'Review setting changes'});
    await expect(review).toContainText('Include');
    await review.getByRole('button', {name: 'Use reviewed changes'}).click();
    await expect(feature.locator('[data-row-status]')).toHaveText('Saved.');
  }
  await page.reload();
  await expect(toggle).toBeChecked();
}

test('Settings enables an owner review; native and Copilot decisions survive response loss and reload', async ({page, context, baseURL}, testInfo) => {
  test.setTimeout(120000);
  await context.setExtraHTTPHeaders({Origin:baseURL, 'X-Browser-Principal':'browser-reviewer'});
  await page.goto('/commitment-reviews');
  await expect(page.getByText('Promise reviews are off')).toBeVisible();
  // The page also offers the separate financial-comparison switch; open this review's own setting.
  await page.locator('#content a[href="/settings?focus=feature-commitment_viability"]').click();
  // Settings lists the feature; its switch is changed through the reviewed save in All settings.
  await page.locator('#feature-commitment_viability').getByRole('link', {name: 'Review choice'}).click();
  await enableFeature(page, 'commitment_viability');
  await page.goto('/settings#settings-features');
  await page.locator('#feature-copilot_operations').getByRole('link', {name: 'Review choice'}).click();
  await enableFeature(page, 'copilot_operations');
  await page.addInitScript(() => Object.defineProperty(Crypto.prototype, 'randomUUID',
    {value:undefined, configurable:true}));
  await page.goto('/commitment-reviews');
  expect(await page.evaluate(() => typeof crypto.randomUUID)).toBe('undefined');
  await expect(page.locator('#cmv-new-details > summary')).toBeVisible();
  await page.locator('#cmv-new-details > summary').click();
  const form = page.locator('#cmv-new');
  await form.locator('[name=title]').fill('October accepted orders');
  await form.locator('[name=order_a_name]').fill('Alpha');
  await form.locator('[name=order_a_due_at]').fill(localTime(4*1440));
  await form.locator('[name=order_a_material_units]').fill('1');
  await form.locator('[name=order_b_name]').fill('Beta');
  await form.locator('[name=order_b_due_at]').fill(localTime(5*1440));
  await form.locator('[name=order_b_material_units]').fill('1');
  await form.locator('[name=capacity_name]').fill('Finishing line');
  await form.locator('[name=capacity_units]').fill('1');
  await form.locator('[name=material_name]').fill('Component');
  await form.locator('[name=stock_units]').fill('2');
  await form.locator('[name=stock_certainty]').selectOption('confirmed');
  await form.locator('[name=option_name]').fill('Extra line shift');
  await form.locator('[name=option_kind]').selectOption('capacity');
  await form.locator('[name=option_units]').fill('1');
  await form.locator('[name=option_ready_at]').fill(localTime(60));
  await form.locator('[name=option_expires_at]').fill(localTime(1440));
  await form.locator('[name=option_lead_hours]').fill('0');
  await form.locator('[name=option_cost_note]').fill('Owner must approve overtime.');
  await form.locator('[name=basis]').fill('Synthetic browser team board for an internal test; no provider data.');
  await form.locator('[name=review_by]').fill(localTime(2880));
  await form.locator('[name=order_b_uses_capacity]').uncheck();

  // Simulate a lost response *after* the local governed store committed.
  let lostCreate = false;
  const createLoss = async route => {
    if (route.request().method() !== 'POST' || lostCreate) return route.continue();
    lostCreate = true;
    await route.fetch();
    return route.fulfill({status:503, contentType:'application/json',
      body:JSON.stringify({detail:'The saved result is uncertain. Refresh this review before trying again.'})});
  };
  await page.route('**/api/v1/commitment-reviews', createLoss);
  await form.getByRole('button', {name:'Create review'}).click();
  await expect(page.locator('#cmv-message')).toContainText('saved result is uncertain');
  await expect(form.locator('[name=title]')).toHaveValue('October accepted orders');
  await page.unroute('**/api/v1/commitment-reviews', createLoss);
  await page.locator('#cmv-refresh').click();
  await expect(page.locator('#cmv-select option')).toHaveCount(2);
  const id = await page.locator('#cmv-select option').last().getAttribute('value');
  await page.locator('#cmv-select').selectOption(id);
  await page.locator('#cmv-open').click();
  await expect(page.locator('#cmv-report-title')).toHaveText('October accepted orders');
  await expect(page.locator('#cmv-report-state')).toContainText('Feasible within the reported model');

  // Selecting another record must not leave the prior report or its Copilot
  // action target available, including during delayed reads and list refreshes.
  await form.locator('[name=title]').fill('Second accepted orders');
  await form.getByRole('button', {name:'Create review'}).click();
  await expect(page.locator('#cmv-report-title')).toHaveText('Second accepted orders');
  const secondId = await page.locator('#cmv-select').inputValue();
  const secondBefore = await (await page.request.get('/api/v1/commitment-reviews/'+secondId)).json();
  await page.evaluate(() => {
    window.__reviewSelections = [];
    document.addEventListener('lightwork:copilot-selection', event => window.__reviewSelections.push(event.detail.selection));
  });
  await page.getByText('Record observed contention', {exact:true}).click();
  const secondTrace = page.locator('#cmv-trace');
  await secondTrace.locator('[name=running_order]').selectOption('order-a');
  await secondTrace.locator('[name=blocked_order]').selectOption('order-b');
  await secondTrace.locator('[name=started_at]').fill(localTime(-180));
  await secondTrace.locator('[name=ended_at]').fill(localTime(-120));
  await secondTrace.locator('[name=observed_at]').fill(localTime(-60));
  await secondTrace.locator('[name=review_by]').fill(localTime(1440));
  await secondTrace.locator('[name=basis]').fill('Synthetic shift log reports one order waited while another ran.');
  await page.getByText('Record observed contention', {exact:true}).click();
  await page.locator('#cmv-select').selectOption(id);
  await expect(page.locator('#cmv-report')).toBeHidden();
  expect(await page.evaluate(() => window.__reviewSelections.at(-1))).toEqual({});
  await expect(secondTrace.locator('[name=basis]')).toHaveValue('');
  await expect(secondTrace.locator('[name=started_at]')).toHaveValue('');
  await expect(secondTrace.locator('[name=running_order]')).toHaveValue('');
  await secondTrace.evaluate(node => node.dispatchEvent(new Event('submit', {bubbles:true, cancelable:true})));
  const secondAfter = await (await page.request.get('/api/v1/commitment-reviews/'+secondId)).json();
  expect(secondAfter.revision).toBe(secondBefore.revision);

  let releaseRead, staleReadStarted = false, staleReadFinished = false;
  const readGate = new Promise(resolve => { releaseRead = resolve; });
  const delayedRead = async route => {
    staleReadStarted = true;
    const response = await route.fetch();
    await readGate;
    await route.fulfill({response});
    staleReadFinished = true;
  };
  await page.route('**/api/v1/commitment-reviews/'+id, delayedRead);
  await page.locator('#cmv-open').click();
  await expect.poll(() => staleReadStarted).toBe(true);
  await page.locator('#cmv-select').selectOption(secondId);
  releaseRead();
  await expect.poll(() => staleReadFinished).toBe(true);
  await page.waitForTimeout(100);
  await expect(page.locator('#cmv-report')).toBeHidden();
  await expect(page.locator('#cmv-select')).toHaveValue(secondId);
  await page.unroute('**/api/v1/commitment-reviews/'+id, delayedRead);

  await page.locator('#cmv-open').click();
  await expect(page.locator('#cmv-report-title')).toHaveText('Second accepted orders');
  let releaseList, listStarted = false;
  const listGate = new Promise(resolve => { releaseList = resolve; });
  const delayedList = async route => {
    listStarted = true;
    const response = await route.fetch();
    await listGate;
    await route.fulfill({response});
  };
  await page.route('**/api/v1/commitment-reviews?*', delayedList);
  await page.locator('#cmv-refresh').click();
  await expect.poll(() => listStarted).toBe(true);
  await expect(page.locator('#cmv-report')).toBeHidden();
  expect(await page.evaluate(() => window.__reviewSelections.at(-1))).toEqual({});
  releaseList();
  await expect(page.locator('#cmv-select option')).toHaveCount(3);
  await expect(page.locator('#cmv-select')).toHaveValue(secondId);
  await page.unroute('**/api/v1/commitment-reviews?*', delayedList);
  await page.locator('#cmv-select').selectOption(id);
  await page.locator('#cmv-open').click();
  await expect(page.locator('#cmv-report-title')).toHaveText('October accepted orders');
  await page.getByText('Record observed contention', {exact:true}).click();

  const trace = page.locator('#cmv-trace');
  await trace.locator('[name=running_order]').selectOption('order-a');
  await trace.locator('[name=blocked_order]').selectOption('order-b');
  await trace.locator('[name=started_at]').fill(localTime(-180));
  await trace.locator('[name=ended_at]').fill(localTime(-120));
  await trace.locator('[name=observed_at]').fill(localTime(-60));
  await trace.locator('[name=review_by]').fill(localTime(1440));
  await trace.locator('[name=basis]').fill('Synthetic shift log reports Beta waited while Alpha used the finishing line.');
  await page.locator('#cmv-refresh').click();
  await expect(page.locator('#cmv-report')).toBeHidden();
  await expect(page.locator('#cmv-select')).toHaveValue(id);
  await page.locator('#cmv-open').click();
  await expect(trace.locator('[name=basis]')).toHaveValue('Synthetic shift log reports Beta waited while Alpha used the finishing line.');
  await trace.getByRole('button', {name:'Record observation'}).click();
  await expect(page.locator('#cmv-proposals')).toContainText('Possible shared work center');
  await page.locator('#cmv-proposals button').click();
  await expect(page.locator('#cmv-proposals')).not.toContainText('Possible shared work center');
  await expect(page.locator('#cmv-report-state')).toContainText('Not feasible within the reported model');
  await expect(page.locator('#cmv-options button')).toHaveText('Confirm this choice for review');

  // Copilot uses the same selected record, owner check and revision fence.
  const selection = {kind:'commitment_review', id};
  const catalogResponse = await page.request.post('/api/v1/copilot/product-operations/catalog',
    {data:{page:'/commitment-reviews',selection}});
  expect(catalogResponse.status()).toBe(200);
  const catalog = await catalogResponse.json();
  const choice = catalog.operations.find(item => item.id === 'commitments.confirm_choice');
  expect(choice.available).toBe(true);
  const preparedResponse = await page.request.post('/api/v1/copilot/product-operations/prepare',
    {data:{page:'/commitment-reviews',selection,context:catalog.context,
      revision:choice.revision,operation:'commitments.confirm_choice',arguments:{}}});
  expect(preparedResponse.status()).toBe(200);
  const prepared = await preparedResponse.json();
  expect(prepared.summary).toContain('does not order or reserve');
  const executeResponse = await page.request.post('/api/v1/copilot/product-operations/execute',
    {data:{token:prepared.token,confirmed:true}});
  expect(executeResponse.status()).toBe(200);
  expect((await executeResponse.json()).message).toContain('Nothing was ordered or reserved');
  await page.reload();
  await page.locator('#cmv-select').selectOption(id);
  await page.locator('#cmv-open').click();
  await expect(page.locator('#cmv-options')).toContainText('owner recorded intent');
  await expect(page.locator('#cmv-options button')).toHaveCount(0);
  const report = await (await page.request.get('/api/v1/commitment-reviews/'+id)).json();
  expect(report.external_reservation_verified).toBe(false);
  expect(report.proposals).toEqual([]);
  await page.locator('#cmv-reassess').focus();
  await expect(page.locator('#cmv-reassess')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#cmv-message')).toContainText('Current assessment refreshed');
  await expect(page.locator('#cmv-reassess')).toBeFocused();
  await page.locator('#cmv-report-title').scrollIntoViewIfNeeded();
  await page.screenshot({path:testInfo.outputPath('promise-reviews-desktop.png')});
  await page.setViewportSize({width:390,height:844});
  await page.locator('#cmv-report-title').scrollIntoViewIfNeeded();
  await expect(page.locator('#cmv-report-title')).toBeVisible();
  await page.screenshot({path:testInfo.outputPath('promise-reviews-mobile.png')});
  await page.setViewportSize({width:1280,height:720});
  await page.locator('#mv-copilot-fab').click();
  await page.locator('#mv-product-operation-buttons').getByRole('button', {name:'Start a promise review'}).click();
  await expect(page.locator('#mv-product-operation-form input[type="datetime-local"]')).toHaveCount(5);
  await expect(page.locator('#mv-product-operation-form')).toContainText('Lead time in hours');
  await page.locator('#mv-copilot-close').click();

  // An old successful read must not overwrite a newer one.
  let releaseStale, staleStarted = false;
  const staleGate = new Promise(resolve => { releaseStale = resolve; });
  const staleRead = async route => {
    if (staleStarted) return route.continue();
    staleStarted = true;
    const response = await route.fetch();
    const old = await response.json();
    await staleGate;
    return route.fulfill({response, body:JSON.stringify({...old,title:'Outdated review title'})});
  };
  await page.route('**/api/v1/commitment-reviews/'+id, staleRead);
  await page.locator('#cmv-reassess').click();
  await expect.poll(() => staleStarted).toBe(true);
  await page.locator('#cmv-open').click();
  await expect(page.locator('#cmv-report-title')).toHaveText('October accepted orders');
  releaseStale();
  await page.waitForTimeout(100);
  await expect(page.locator('#cmv-report-title')).toHaveText('October accepted orders');
  await page.unroute('**/api/v1/commitment-reviews/'+id, staleRead);

  // The owner closes a completed review in the product. Its full source
  // history stays readable after reload while the active slot is released.
  await page.locator('#cmv-archive-details > summary').click();
  await page.locator('#cmv-archive [name=confirm_finished]').check();
  await page.locator('#cmv-archive').getByRole('button', {name:'Finish and archive'}).click();
  await expect(page.locator('#cmv-lifecycle-note')).toContainText('Archived on');
  await expect(page.locator('#cmv-trace-details')).toBeHidden();
  await expect(page.locator('#cmv-archive-details')).toBeHidden();
  expect((await (await page.request.get('/api/v1/commitment-reviews')).json()).items
    .some(item => item.id === id)).toBe(false);
  expect((await (await page.request.get('/api/v1/commitment-reviews?archived=true')).json()).items
    .some(item => item.id === id)).toBe(true);
  await page.reload();
  await page.locator('#cmv-select').selectOption(id);
  await page.locator('#cmv-open').click();
  await expect(page.locator('#cmv-lifecycle-note')).toContainText('Archived on');
  await expect(page.locator('#cmv-sources')).toContainText('Synthetic browser team board');

  // A delayed success must also remain invisible after the next read loses access.
  let releasePrivate, privateStarted = false;
  const privateGate = new Promise(resolve => { releasePrivate = resolve; });
  const lostAccess = async route => {
    if (privateStarted) return route.fulfill({status:403, contentType:'application/json',
      body:JSON.stringify({detail:'Access changed.'})});
    privateStarted = true;
    const response = await route.fetch();
    await privateGate;
    return route.fulfill({response});
  };
  await page.route('**/api/v1/commitment-reviews/'+id, lostAccess);
  await page.locator('#cmv-reassess').click();
  await expect.poll(() => privateStarted).toBe(true);
  await page.locator('#cmv-open').click();
  await expect(page.locator('#cmv-report')).toBeHidden();
  releasePrivate();
  await page.waitForTimeout(100);
  await expect(page.locator('#cmv-report')).toBeHidden();
  await expect(page.locator('#cmv-select option')).toHaveCount(1);
});
