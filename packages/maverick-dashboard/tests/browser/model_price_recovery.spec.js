const {test, expect} = require('@playwright/test');

test('an owner can price a private model, see the effective route, and withdraw it', async ({page}) => {
  await page.goto('/settings');
  await page.getByRole('tab', {name: 'Models'}).click();
  const prices = page.locator('#settings-model-prices');
  await expect(prices).toBeVisible();
  await prices.locator('[name="rate_model"]').selectOption('__custom__');
  await prices.locator('[name="rate_model_custom"]').fill('openai_compatible:customer-model');
  await prices.locator('[name="input_per_mtok"]').fill('4');
  await prices.locator('[name="output_per_mtok"]').fill('12');
  await prices.locator('[name="source"]').fill('Synthetic customer contract R1');
  await prices.locator('[name="confirm"]').check();
  await prices.getByRole('button', {name: 'Save spending ceiling'}).click();
  await expect(page.locator('.settings-saved')).toContainText('Model spending ceiling updated');
  await expect(prices).toContainText('Synthetic customer contract R1');

  await page.locator('#settings-model-default').selectOption('__custom__');
  await page.locator('[name="model_custom"]').fill('openai_compatible:customer-model');
  await page.getByRole('button', {name: 'Save default'}).click();
  await expect(page.locator('form[action="/settings/models"] [data-save-status]'))
    .toContainText('Default model updated');
  await expect(prices).toContainText('Administrator ceiling');
  await expect(page.locator('#settings-current-default')).toContainText('Customer Model');
  await page.reload();
  await expect(prices).toContainText('Administrator ceiling');
  await prices.getByRole('button', {name: 'Remove rate'}).click();
  await expect(page.locator('.settings-saved')).toContainText('Model spending ceiling removed');
  await expect(prices).toContainText('Will stop before a paid request');
});
