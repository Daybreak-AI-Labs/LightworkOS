const {test, expect} = require('@playwright/test');

test('Learning accepts ordinary score entries and distinguishes comparison from proof', async ({page, context, baseURL}, info) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin ? route.continue() : route.abort());
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.setViewportSize({width: 320, height: 850});
  await page.goto('/learning');
  await expect(page.getByRole('heading', {name: 'Overnight improvement review'})).toBeVisible();
  await page.getByRole('tab', {name: 'Review & restore', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Compare recorded results'})).toBeVisible();
  for (let row = 0; row < 3; row++) await page.locator('#lrn-score-add').click();
  for (let row = 1; row <= 6; row++) {
    await page.getByLabel('Before score for task ' + row, {exact: true}).fill('0');
    await page.getByLabel('After score for task ' + row, {exact: true}).fill('100');
  }
  const response = page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname === '/api/v1/learning/prove');
  await page.locator('#lrn-prove').click();
  const result = await response;
  expect(result.status()).toBe(200);
  expect(await result.json()).toMatchObject({tasks: 6, before: 0, after: 1, causal_claim_supported: false});
  await expect(page.locator('#lrn-prove-result')).toContainText('The recorded scores are higher');
  await expect(page.locator('#lrn-prove-result')).toContainText('does not establish that learning caused');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
  await info.attach('ordinary-score-comparison-phone', {body: await page.screenshot({path: info.outputPath('learning-phone.png'), fullPage: true}), contentType: 'image/png'});
  expect(errors).toEqual([]);
});
