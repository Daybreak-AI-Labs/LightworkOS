const {test, expect} = require('@playwright/test');

test('the Chat composer submits a long, multiline message without flattening or losing the draft', async ({page}) => {
  await page.goto('/chat');
  // This isolated fixture intentionally has no AI provider. Enable only the
  // form and intercept transport; the real server save is covered separately.
  await page.locator('fieldset.composer__controls').evaluate(node => {node.disabled = false;});
  let submitted = '';
  await page.route('**/chat/send', route => {
    submitted = route.request().postData() || '';
    return route.fulfill({status:422, contentType:'application/json', body:'{"detail":"Synthetic transport hold."}'});
  });
  const message = page.getByRole('textbox', {name: 'Describe a task for Lightwork to do'});
  const firstLine = 'Prepare a customer response that reconciles these details before making a recommendation. '.repeat(3);
  await message.fill(firstLine);
  await message.press('Shift+Enter');
  await message.type('Keep this second line and its meaning.');
  // The composer also has specialist and AI choices; open the one that holds the details.
  await page.locator('form.composer details:has(textarea[name="description"]) > summary').click();
  await page.locator('textarea[name="description"]').fill('Use the attached evidence.');
  await expect(message).toHaveValue(firstLine + '\nKeep this second line and its meaning.');
  await message.press('Enter');
  await expect.poll(() => submitted).toContain('Keep this second line and its meaning.');
  expect(submitted).toContain(firstLine);
  expect(submitted).toContain('Use the attached evidence.');
  expect(submitted).toContain('composer_mode');
  expect(submitted).toContain('message');
  await expect(message).toHaveValue(firstLine + '\nKeep this second line and its meaning.');
});
