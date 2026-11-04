const {test, expect} = require('@playwright/test');

test('Show work presents readable activity and useful findings after live updates and replay', async ({page, request}) => {
  const created = await request.post('/__browser_fixture/chat');
  const {goal_id} = await created.json();
  await page.goto(`/chat/goal/${goal_id}`);
  expect((await request.post(`/__browser_fixture/chat/${goal_id}/activity`)).status()).toBe(200);
  await expect(page.locator('#events')).toContainText('Asked you a question');
  await page.locator('#work-activity > summary').click();
  // Steps are narrated in plain words; what a step recorded (the finding
  // itself) is folded under "What each step recorded".
  await expect(page.locator('#events')).toContainText('Shared what it found');
  await page.locator('#raw-trace > summary').click();
  await expect(page.locator('#raw-trace-list')).toContainText('The invoice matches the purchase order.');
  for (const shown of [page.locator('#events'), page.locator('#raw-trace-list')])
    await expect(shown).not.toContainText(/INTERNAL PROMPT|private model scratch|tool_output|QUEUED|Prior failures/);
  await page.reload();
  await expect(page.locator('#events')).toContainText('Asked you a question');
  await expect(page.locator('#events')).not.toContainText(/INTERNAL PROMPT|private model scratch|tool_output|QUEUED|Prior failures/);
});
