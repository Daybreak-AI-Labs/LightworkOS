const {test, expect} = require('@playwright/test');

test('Copilot stays available in Chat and knows the current task on desktop and mobile', async ({page, request}) => {
  const {review_goal: goalId} = await (await request.get('/__browser_fixture')).json();

  await page.goto('/chat');
  await page.locator('#cs-side [data-copilot-toggle]').click();
  await expect(page.getByRole('dialog', {name: 'Copilot'})).toBeVisible();
  await expect(page.locator('#mv-copilot-current')).toContainText('Describe the work you want Lightwork to do');
  await expect(page.locator('#mv-copilot-input')).toBeFocused();
  await page.getByRole('button', {name: 'Close Copilot'}).click();

  await page.goto(`/chat/goal/${goalId}`);
  const taskButton = page.getByRole('button', {name: 'Ask Copilot about this task'});
  await taskButton.click();
  await expect(page.locator('#mv-copilot-current')).toContainText('Browser captured result');
  await expect(page.locator('#mv-copilot-current')).toContainText('complete');
  await expect(taskButton).toHaveAttribute('aria-expanded', 'true');
  expect(await page.evaluate(() => document.getElementById('cs-side').contains(document.getElementById('mv-copilot')))).toBe(false);
  await page.keyboard.press('Escape');
  await expect(taskButton).toBeFocused();

  await page.setViewportSize({width: 390, height: 844});
  const mobileButton = page.locator('.cs-topbar [data-copilot-toggle]');
  await mobileButton.click();
  await expect(page.getByRole('dialog', {name: 'Copilot'})).toBeVisible();
  const bounds = await page.locator('#mv-copilot').boundingBox();
  expect(bounds.x).toBeGreaterThanOrEqual(0);
  expect(bounds.x + bounds.width).toBeLessThanOrEqual(390);
  await page.getByRole('button', {name: 'Close Copilot'}).click();

  await page.getByRole('button', {name: 'Menu', exact: true}).click();
  await page.locator('#cs-side [data-copilot-toggle]').click();
  await expect(page.getByRole('dialog', {name: 'Copilot'})).toBeVisible();
  await expect(page.locator('#cs-side')).toHaveAttribute('inert', '');
  await expect(page.locator('main')).not.toHaveAttribute('inert', '');
  await expect(page.locator('#mv-copilot-input')).toBeFocused();
});

test('everyday pages show specific Copilot guidance in the real interface', async ({page}) => {
  // One short line on what Copilot can do on this page, then tasks people
  // come to this page to do (copilot_context.intro_for / suggestions_for).
  for (const [path, intro, question] of [
    ['/settings', 'I can explain Settings,', 'Choose the AI model'],
    ['/goals', 'I can explain Tasks,', 'Show tasks that failed'],
    ['/help', 'I can explain Help and diagnostics,', 'How do I report a failed task?'],
  ]) {
    await page.goto(path);
    await page.getByRole('button', {name: 'Open Lightwork Copilot'}).click();
    await expect(page.locator('#mv-copilot-hello')).toContainText(intro);
    await expect(page.locator('#mv-copilot-prompts')).toContainText(question);
  }
});
