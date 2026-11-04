const {test, expect} = require('@playwright/test');

test('Copilot keeps a short account-scoped conversation in this tab and lets the customer clear it', async ({page}) => {
  await page.goto('/goals');
  await page.getByRole('button', {name: 'Open Lightwork Copilot'}).click();
  await expect(page.getByRole('dialog', {name: 'Copilot'})).toBeVisible();

  const question = 'What can I do on this page?';
  await page.getByRole('textbox', {name: 'Ask Copilot about this page'}).fill(question);
  await page.getByRole('button', {name: 'Send question', exact: true}).click();
  const log = page.locator('#mv-copilot-log');
  await expect(log).toContainText(question);
  await expect.poll(async () => log.locator('.mv-copilot__msg--bot').count()).toBeGreaterThan(0);
  const response = await log.textContent();
  expect(response.length).toBeGreaterThan(question.length + 12);

  await page.reload();
  await page.getByRole('button', {name: 'Open Lightwork Copilot'}).click();
  await expect(page.locator('#mv-copilot-log')).toContainText(question);
  await page.setExtraHTTPHeaders({'X-Browser-Principal': 'browser-colleague'});
  await page.reload();
  await page.getByRole('button', {name: 'Open Lightwork Copilot'}).click();
  await expect(page.locator('#mv-copilot-log')).toBeEmpty();

  await page.getByRole('textbox', {name: 'Ask Copilot about this page'}).fill('What can I inspect?');
  await page.getByRole('button', {name: 'Send question', exact: true}).click();
  await expect(page.locator('#mv-copilot-log .mv-copilot__msg--bot')).toHaveCount(1);
  await page.getByRole('button', {name: 'Clear recent chat'}).click();
  await expect(page.locator('#mv-copilot-log')).toBeEmpty();
  await page.reload();
  await page.getByRole('button', {name: 'Open Lightwork Copilot'}).click();
  await expect(page.locator('#mv-copilot-log')).toBeEmpty();
});
