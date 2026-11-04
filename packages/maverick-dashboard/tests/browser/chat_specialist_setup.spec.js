const {test, expect} = require('@playwright/test');

test('missing specialist action explains setup and does not offer a blind retry', async ({page, request}) => {
  const created = await request.post('/__browser_fixture/chat');
  expect(created.status(), await created.text()).toBe(200);
  const {goal_id, root_id} = await created.json();
  const failed = await request.post(`/__browser_fixture/chat/${goal_id}/specialist-setup-fail`);
  expect(failed.status(), await failed.text()).toBe(200);

  await page.goto(`/chat/goal/${goal_id}`);
  await expect(page.locator('#halt-card')).toBeVisible();
  await expect(page.locator('#halt-title')).toHaveText("Can't start");
  await expect(page.locator(`#chat-status-${root_id}`)).toHaveText("Can't start");
  await expect(page.locator('#halt-reason')).toContainText('Web search is unavailable');
  await expect(page.locator('#halt-specialist-alternative a[href="/agents"]')).toBeVisible();
  await expect(page.locator('#halt-specialist-alternative a[href="/chat"]')).toBeVisible();
  await expect(page.locator('#halt-resume-form')).toBeHidden();
  await expect(page.locator('#cancel-btn')).toBeHidden();
  await expect(page.locator('[data-budget-launch]')).toBeHidden();
  await page.locator('#halt-check-setup').click();
  await expect(page.locator('#halt-setup-message')).toContainText('needs setup');
  await expect(page.locator('#halt-resume-form')).toBeHidden();
  await expect(page.locator('#halt-technical')).not.toHaveAttribute('open', '');
  await expect(page.locator('#halt-technical-text')).toBeHidden();
  await expect(page.locator('#halt-reason')).not.toContainText('legal_research');
});
