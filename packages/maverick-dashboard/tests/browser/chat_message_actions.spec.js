const {test, expect} = require('@playwright/test');

test('a saved answer exposes the product and its print, copy, download and share actions', async ({page, context, request}, info) => {
  const fixture = await (await request.get('/__browser_fixture')).json();
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.addInitScript(() => { window.print = () => { window.__printed = true; }; });
  await page.goto(`/chat/goal/${fixture.review_goal}`);

  const product = page.getByRole('navigation', {name: 'Primary'});
  // Workflows is a sidebar group entry; Recent pages may repeat it by design.
  await expect(product.locator('.navgrp__items').getByRole('link', {name: 'Workflows', exact: true})).toBeVisible();
  // Tasks is a one-click Most used shortcut as well as a Work entry.
  await expect(product.getByRole('list', {name: 'Most used'}).getByRole('link', {name: 'Tasks', exact: true})).toBeVisible();
  const answer = page.locator('#result');
  await expect(answer).toContainText('Synthetic captured deliverable');

  await page.getByRole('button', {name: 'Copy answer'}).click();
  await expect(page.locator('#answer-action-msg')).toHaveText('Copied.');
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    'Synthetic captured deliverable. Evidence limitations remain explicit.'
  );

  await page.getByRole('button', {name: 'Print conversation'}).click();
  await expect.poll(() => page.evaluate(() => window.__printed)).toBe(true);
  await page.emulateMedia({media: 'print'});
  await expect(page.locator('#cs-side')).toHaveCSS('display', 'none');
  await expect(page.getByRole('link', {name: 'Conversation response style'})).toBeHidden();
  await expect(page.getByRole('navigation', {name: 'Task pages'})).toBeHidden();
  await expect(page.getByRole('link', {name: 'View my background work'})).toBeHidden();
  await expect(page.getByText('Organize this conversation')).toBeHidden();
  await expect(page.getByRole('link', {name: 'Prepare selected deliverable bundle'})).toBeHidden();
  await expect(page.locator('#conversation-inbox')).toBeHidden();
  await expect(page.locator('#answer-refresh-status')).toBeHidden();
  await expect(page.getByText('Question answers can include documents, PDFs, images and text.')).toBeHidden();
  await expect(page.locator('.print-heading')).toBeVisible();
  await expect(answer).toBeVisible();
  await info.attach('print-view', {body: await page.screenshot({fullPage: true}), contentType: 'image/png'});
  await page.emulateMedia({media: 'screen'});

  const answerActions = page.getByRole('group', {name: 'Answer actions', exact: true});
  await expect(answerActions.getByRole('link', {name: 'Download Word document'})).toHaveAttribute('href', `/chat/goal/${fixture.review_goal}/download.docx`);
  const downloaded = page.waitForEvent('download');
  await answerActions.getByRole('link', {name: 'Download Markdown'}).click();
  expect((await downloaded).suggestedFilename()).toBe(`lightwork-answer-${fixture.review_goal}.md`);

  await page.getByRole('button', {name: 'Share', exact: true}).click();
  await expect(page.locator('#share-panel')).toHaveAttribute('open', '');
  await page.getByRole('button', {name: 'Review share link'}).click();
  await expect(page.getByRole('region', {name: 'Review public link'})).toContainText('Review before creating a public link');
  await expect(page.locator('#share-msg')).toContainText('No link has been created');
  await page.getByRole('button', {name: 'Create this public link'}).click();
  const link = page.locator('#share-url');
  await expect(link).toBeVisible();
  await page.getByRole('button', {name: 'Copy link'}).click();
  await expect(page.locator('#share-msg')).toContainText('Link copied');
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(await link.inputValue());
  await info.attach('answer-actions', {body: await page.screenshot(), contentType: 'image/png'});

  await page.setViewportSize({width: 390, height: 844});
  await expect(page.getByRole('button', {name: 'Menu', exact: true})).toBeVisible();
  await page.getByRole('button', {name: 'Menu', exact: true}).click();
  // Workflows is a sidebar group entry; Recent pages may repeat it by design.
  await expect(product.locator('.navgrp__items').getByRole('link', {name: 'Workflows', exact: true})).toBeVisible();
  await expect(page.getByRole('button', {name: 'Close menu'})).toBeVisible();
  await expect(page.locator('main')).toHaveAttribute('inert', '');
  const firstNavigation = page.locator('#cs-side .cs-brand');
  await expect(firstNavigation).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  expect(await page.evaluate(() => document.getElementById('cs-side').contains(document.activeElement))).toBe(true);
  await page.keyboard.press('Tab');
  await expect(firstNavigation).toBeFocused();
  await page.getByRole('button', {name: 'Close menu'}).click();
  await expect(page.getByRole('button', {name: 'Menu', exact: true})).toBeFocused();
  await expect(page.locator('#cs-side')).toHaveCSS('visibility', 'hidden');
  await expect(page.getByRole('button', {name: 'Print conversation'})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(391);
  await info.attach('answer-actions-mobile', {body: await page.screenshot(), contentType: 'image/png'});
});

test('Print waits for both earlier pages and includes answered clarifications', async ({page, request}) => {
  const {review_goal: goalId} = await (await request.get('/__browser_fixture')).json();
  await page.addInitScript(() => { window.print = () => { window.__printed = true; }; });
  const releases = [];
  await page.route(`**/api/v1/goals/${goalId}/thread-history*`, route => new Promise(resolve => {
    releases.push(async body => { await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(body)}); resolve(); });
  }));
  await page.goto(`/chat/goal/${goalId}`);
  await page.locator('#earlier-history').evaluate(node => { node.dataset.before = '100'; });
  await page.getByRole('button', {name: 'Print conversation'}).click();
  await expect.poll(() => releases.length).toBe(1);
  expect(await page.evaluate(() => window.__printed === true)).toBe(false);
  await releases[0]({turns: [
    {id: 98, goal_id: goalId, role: 'user', content: 'Earlier request A',
      questions: [{question: 'Which location?', answer: 'Chattanooga'}]},
    {id: 99, goal_id: goalId, role: 'assistant', content: 'Earlier answer A'},
  ], has_more: true, before_id: 98});
  await expect(page.locator('#history-turns')).toContainText('Which location?');
  await expect(page.locator('#history-turns')).toContainText('Chattanooga');
  await expect.poll(() => releases.length).toBe(2);
  expect(await page.evaluate(() => window.__printed === true)).toBe(false);
  await releases[1]({turns: [
    {id: 96, goal_id: goalId, role: 'user', content: 'Earlier request B', questions: []},
    {id: 97, goal_id: goalId, role: 'assistant', content: 'Earlier answer B'},
  ], has_more: false, before_id: 96});
  await expect.poll(() => releases.length).toBe(3);
  expect(await page.evaluate(() => window.__printed === true)).toBe(false);
  await releases[2]({turns: [], has_more: false, before_id: 96});
  await expect.poll(() => page.evaluate(() => window.__printed === true)).toBe(true);
  await expect(page.locator('#history-turns')).toContainText('Earlier answer B');
  await expect(page.locator('#history-status')).toContainText('Beginning of this conversation');
});

test('Print refuses a partial long conversation when history cannot load', async ({page, request}) => {
  const setup = await request.post('/__browser_fixture/long-chat');
  expect(setup.status(), await setup.text()).toBe(200);
  const {goal_id: goalId} = await setup.json();
  await page.addInitScript(() => { window.print = () => { window.__printed = true; }; });
  await page.route('**/static/lightwork-thread-history.js*', route => route.fulfill({status: 404, body: ''}));
  await page.goto(`/chat/goal/${goalId}`);
  await expect(page.locator('#history-load')).toBeVisible();
  expect(Number(await page.locator('#earlier-history').getAttribute('data-before'))).toBeGreaterThan(1);
  await page.locator('#print-result').click();
  await expect(page.locator('#answer-action-msg')).toContainText('Printing is still loading');
  expect(await page.evaluate(() => window.__printed === true)).toBe(false);
});

test('message actions arrive after live completion without losing a reply or prior answers', async ({page, context, request}) => {
  const fixture = await (await request.post('/__browser_fixture/chat')).json();
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto(`/chat/goal/${fixture.goal_id}`);
  const earlier = page.getByRole('group', {name: 'Earlier answer actions'});
  await earlier.getByRole('button', {name: 'Copy answer'}).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe('Earlier answer as originally delivered.');
  const priorDownload = page.waitForEvent('download');
  await earlier.getByRole('link', {name: 'Download Markdown'}).click();
  const savedPrior = await priorDownload;
  const stream = await savedPrior.createReadStream();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  expect(Buffer.concat(chunks).toString('utf8')).toBe('Earlier answer as originally delivered.');
  await page.locator('#answer-input').fill('Keep this unsent reply.');
  await request.post(`/__browser_fixture/chat/${fixture.goal_id}/finish`);
  const actions = page.getByRole('group', {name: 'Answer actions', exact: true});
  await expect(actions.getByRole('button', {name: 'Copy answer'})).toBeVisible();
  await expect(page.locator('#answer-input')).toHaveValue('Keep this unsent reply.');
  await actions.getByRole('button', {name: 'Copy answer'}).click();
  await expect.poll(() => page.evaluate(async () => (await navigator.clipboard.readText()).replace(/\r\n/g, '\n'))).toBe('## Finished answer\n\nDelivery is planned for Friday.');
  await actions.getByRole('button', {name: 'Edit & save'}).click();
  await page.locator('#edit-text').fill('Unsaved draft that must not replace the delivered answer.');
  await actions.getByRole('button', {name: 'Copy answer'}).click();
  await expect.poll(() => page.evaluate(async () => (await navigator.clipboard.readText()).replace(/\r\n/g, '\n'))).toBe('## Finished answer\n\nDelivery is planned for Friday.');
  const downloaded = page.waitForEvent('download');
  await actions.getByRole('link', {name: 'Download Markdown'}).click();
  expect((await downloaded).suggestedFilename()).toBe(`lightwork-answer-${fixture.goal_id}.md`);
  await actions.getByRole('button', {name: 'Share', exact: true}).click();
  await page.getByRole('button', {name: 'Review share link'}).click();
  await expect(page.getByRole('region', {name: 'Review public link'})).toContainText('Review before creating a public link');
  await page.getByRole('button', {name: 'Create this public link'}).click();
  await expect(page.locator('#share-url')).toBeVisible();
  await expect(page.locator('#qa-thread')).toContainText('Use Friday.');
  await page.emulateMedia({media: 'print'});
  await expect(page.locator('#qa-thread')).toBeVisible();
  await expect(page.locator('#qa-thread')).toContainText('Which delivery date should I use?');
  await expect(page.locator('#qa-thread .bubble')).toContainText('Use Friday.');
  await expect(page.getByRole('paragraph').filter({hasText: 'Earlier answer as originally delivered.'})).toBeVisible();
  await expect(page.locator('#conversation-inbox')).toBeHidden();
});

test('a failed action refresh gives a working retry and preserves the next reply', async ({page, request}) => {
  const fixture = await (await request.post('/__browser_fixture/chat')).json();
  await page.goto(`/chat/goal/${fixture.goal_id}`);
  await page.locator('#answer-input').fill('Preserve my next message through a connection failure.');
  await page.route(`**/chat/goal/${fixture.goal_id}/answer-panel`, route => route.fulfill({status: 503, body: 'Synthetic temporary failure'}));
  await request.post(`/__browser_fixture/chat/${fixture.goal_id}/finish`);
  await expect(page.locator('#answer-refresh')).toBeVisible();
  await expect(page.locator('#answer-input')).toHaveValue('Preserve my next message through a connection failure.');
  await page.unroute(`**/chat/goal/${fixture.goal_id}/answer-panel`);
  await page.locator('#answer-refresh').click();
  await expect(page.getByRole('group', {name: 'Answer actions', exact: true})).toBeVisible();
  await expect(page.locator('#answer-input')).toHaveValue('Preserve my next message through a connection failure.');
});

test('printing wraps wide tables and long code instead of clipping the answer', async ({page, request}, info) => {
  const fixture = await (await request.post('/__browser_fixture/print')).json();
  await page.goto(`/chat/goal/${fixture.goal_id}`);
  await expect(page.locator('#result table')).toBeVisible();
  await expect(page.locator('#result pre')).toBeVisible();
  await page.emulateMedia({media: 'print'});
  for (const selector of ['#result table', '#result pre']) {
    const size = await page.locator(selector).evaluate(node => ({width: node.clientWidth, content: node.scrollWidth}));
    expect(size.content, selector).toBeLessThanOrEqual(size.width + 1);
  }
  const pdf = await page.pdf({format: 'A4', printBackground: true});
  expect(pdf.length).toBeGreaterThan(10000);
  await info.attach('long-conversation-print', {body: pdf, contentType: 'application/pdf'});
});

test('a customer can revoke an existing share while the answer is being replaced', async ({page, request}) => {
  const fixture = await (await request.post('/__browser_fixture/chat')).json();
  const previewResponse = await request.post(`/api/v1/goals/${fixture.root_id}/share/preview`, {data: {}});
  expect(previewResponse.status()).toBe(200);
  const preview = await previewResponse.json();
  const shareResponse = await request.post(`/api/v1/goals/${fixture.root_id}/share`, {data: {
    confirm: true, source_sha256: preview.source.sha256, lifetime_seconds: 86400, label: 'Browser acceptance link'
  }});
  expect(shareResponse.status()).toBe(201);
  const share = await shareResponse.json();
  await request.post(`/__browser_fixture/chat/${fixture.root_id}/restart`);
  await page.goto(`/chat/goal/${fixture.root_id}`);
  await page.locator('#share-panel summary').click();
  await expect(page.getByRole('button', {name: 'Create share link'})).toHaveCount(0);
  await page.getByRole('button', {name: 'Revoke', exact: true}).click();
  await page.getByRole('button', {name: 'Revoke link', exact: true}).click();
  await expect(page.locator('#share-list li')).toHaveCount(1);
  await expect(page.locator('#share-list li')).toContainText('revoked');
  await expect(page.locator('#share-list .share-revoke')).toHaveCount(0);
  await request.post(`/__browser_fixture/chat/${fixture.root_id}/finish`);
  expect((await request.get(share.url)).status()).toBe(404);
});
