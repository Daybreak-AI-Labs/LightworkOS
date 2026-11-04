const {test, expect} = require('@playwright/test');

test('Safety settings plainly show rehearsal watch mode and the review path', async ({page, context, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));

  await page.goto('/settings/all?id=rehearsal.enable');
  const enabled = page.locator('[data-setting-id="rehearsal.enable"]');
  await expect(enabled).toBeVisible();
  await expect(enabled.getByRole('switch')).toBeChecked();
  await expect(enabled).toContainText('The mode below controls whether predictions can stop an action.');

  await page.goto('/settings/all?id=rehearsal.mode');
  const mode = page.locator('[data-setting-id="rehearsal.mode"]');
  await expect(mode).toBeVisible();
  await expect(mode.locator('select[data-input]')).toHaveValue('observe');
  await expect(mode).toContainText('until a person reviews the exact step in Approvals');
  await expect(mode.locator('select[data-input]')).toContainText('Hold high-impact actions for review');
  expect(errors).toEqual([]);
});

test('a signed-in reviewer can release a paused step from Approvals', async ({page, context, request, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  const seeded = await request.post('/__browser_fixture/approvals/setup?kind=rehearsal');
  expect(seeded.status()).toBe(200);
  const {approval_id: id} = await seeded.json();

  await page.goto('/approvals');
  const item = page.locator(`article.approval-item[data-id="${id}"]`);
  await expect(item).toBeVisible();
  await expect(item).toContainText('Review paused action');
  await expect(item).toContainText('Lightwork paused this step');
  await expect(item).toContainText('Task 42: save a file');
  await expect(item).toContainText('Other safety checks still apply.');

  await item.locator('button[data-action="approve"]').click();
  const confirmation = page.locator('#approval-confirm');
  await expect(confirmation).toBeVisible();
  await expect(confirmation).toContainText('Allow Lightwork to save a file once in this task.');
  await page.locator('#approval-confirm-ack').check();
  await page.locator('#approval-confirm-ok').click();
  await expect(confirmation).toBeHidden();
  await expect(page.locator('#approval-decided')).toContainText('Approved just now');
  await expect(page.locator('#approval-msg')).toContainText('Execution is a separate step');
});
