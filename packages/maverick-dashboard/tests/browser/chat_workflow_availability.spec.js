const {test, expect} = require('@playwright/test');

test('Chat offers workflow drafting only while workflows can be used', async ({page}) => {
  await page.goto('/chat');
  await expect(page.locator('#authoring-kind option[value="flow"]')).toHaveCount(1);
  const switchUrl = '/api/v1/features/switches';
  try {
    const off = await page.request.post(switchUrl, {data: {section: 'flows', enabled: false}});
    expect(off.ok()).toBe(true);
    await page.reload();
    await expect(page.locator('#authoring-kind option[value="flow"]')).toHaveCount(0);
    await page.getByRole('link', {name: 'Turn them on in Learning'}).click();
    await expect(page).toHaveURL(/\/learning#lrn-flows-on$/);
    await expect(page.locator('#lrn-flows-on')).toBeVisible();
  } finally {
    await page.request.post(switchUrl, {data: {section: 'flows', enabled: true}});
  }
});
