const {test, expect} = require('@playwright/test');

test('chat follow-up serializes text and files and retains both for a readable retry', async ({page, request, context, baseURL}) => {
  const origin = new URL(baseURL).origin;
  await context.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const fixture = await (await request.get('/__browser_fixture')).json();
  const goal = fixture.goal_id;
  // Deterministic terminal status and reply failures exercise native browser
  // serialization/retry. HTTP/storage admission is covered by pytest separately.
  // The page shows a server reason only when it is a plain sentence
  // (mvPlainDetail), so the synthetic reasons end with a full stop.
  await page.route(`**/api/goal/${goal}/events/stream?*`, route => route.fulfill({
    contentType: 'text/event-stream',
    body: 'event: terminal\ndata: {"status":"done","terminal":true,"events":[]}\n\n',
  }));
  const bodies = [];
  await page.route(`**/chat/goal/${goal}/reply`, route => {
    bodies.push(route.request().postData());
    return route.fulfill({status: 422, json: {detail: [{loc: ['body', 'message'], msg: bodies.length === 1 ? 'Please review this message.' : 'Retry received.'}]}});
  });
  try {
    await page.goto(`/chat/goal/${goal}`);
    await expect(page.locator('#answer-send')).toBeEnabled();
    await page.locator('#answer-input').fill('Preserve the full follow-up and original attachment.');
    await page.locator('#reply-files').setInputFiles({name: 'source.txt', mimeType: 'text/plain', buffer: Buffer.from('Original source')});
    await page.locator('#answer-send').click();
    await expect(page.locator('#composer-hint')).toHaveText('Please review this message.');
    await expect(page.locator('#answer-input')).toHaveValue('Preserve the full follow-up and original attachment.');
    expect(await page.locator('#reply-files').evaluate(node => Array.from(node.files).map(file => file.name))).toEqual(['source.txt']);
    await page.locator('#answer-input').press('Enter');
    await expect(page.locator('#composer-hint')).toHaveText('Retry received.');
    expect(bodies).toHaveLength(2);
    for (const body of bodies) {
      expect(body).toContain('name="message"');
      expect(body).toContain('Preserve the full follow-up and original attachment.');
      expect(body).toContain('filename="source.txt"');
      expect(body).toContain('Original source');
      expect(body).toContain('name="submission_key"');
    }
    expect(errors).toEqual([]);
  } finally {
    await context.unrouteAll({behavior: 'ignoreErrors'});
  }
});
