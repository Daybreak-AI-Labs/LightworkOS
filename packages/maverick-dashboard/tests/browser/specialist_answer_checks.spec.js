const {test, expect} = require('@playwright/test');

test('an owner writes and revisits a specialist answer check in Workforce', async ({page, context, baseURL}) => {
  await context.route('**/*', route =>
    new URL(route.request().url()).origin === new URL(baseURL).origin
      ? route.continue() : route.abort('blockedbyclient'));
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/workforce');
  await expect(page.getByRole('heading', {name: 'Check answers from your agents and specialists'})).toBeVisible();
  const specialist = page.locator('#wo-test-specialist');
  await expect.poll(() => specialist.locator('option').count()).toBeGreaterThan(1);
  await specialist.selectOption({index: 1});
  await expect(page.locator('#wo-test-form')).toBeVisible();
  const question = 'What should we do with two invoices for the same purchase order?';
  await page.locator('#wo-test-task').fill(question);
  await page.locator('#wo-test-includes').fill('duplicate');
  await page.locator('#wo-test-excludes').fill('payment sent');
  await page.locator('#wo-test-save').click();
  await expect(page.locator('#wo-tests-list')).toContainText(question);
  await page.reload();
  await specialist.selectOption({index: 1});
  await expect(page.locator('#wo-tests-list')).toContainText(question);
  await expect(page.locator('#wo-tests-list')).toContainText('duplicate');
  expect(errors).toEqual([]);
});
