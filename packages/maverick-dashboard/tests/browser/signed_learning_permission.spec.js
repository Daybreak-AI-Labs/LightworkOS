const {test, expect} = require('@playwright/test');

test('accepted examples need separate permission, and withdrawal stops a learned flow before another action',
  async ({page, request, context, baseURL}) => {
    test.setTimeout(180000);
    page.setDefaultTimeout(15000);
    const origin = new URL(baseURL).origin;
    await context.route('**/*', route => new URL(route.request().url()).origin === origin
      ? route.continue() : route.abort('blockedbyclient'));
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));

    const setup = await request.post('/__browser_fixture/signed-learning/setup');
    expect(setup.status(), await setup.text()).toBe(200);
    const {flow_id: flowId, run_ids: runs, tools, calls: sourceCalls} = await setup.json();
    expect(runs).toHaveLength(2);
    expect(sourceCalls).toBe(4);

    // Settings lists each feature; its switch is changed through the reviewed
    // save in All settings.
    await page.goto('/settings#settings-features');
    await page.locator('#feature-copilot_operations').getByRole('link', {name: 'Review choice'}).click();
    await expect(page).toHaveURL(/\/settings\/all\?id=features\.copilot_operations$/);
    const feature = page.locator('[data-setting-id="features.copilot_operations"]');
    const toggle = feature.getByRole('switch');
    await expect(toggle).toBeVisible();
    // The browser server is shared: an earlier journey may already have
    // turned this on, and then there is nothing to save.
    if (!(await toggle.isChecked())) {
      await toggle.check();
      await feature.locator('[data-save]').click();
      const review = page.getByRole('dialog', {name: 'Review setting changes'});
      await expect(review).toContainText('Include');
      await review.getByRole('button', {name: 'Use reviewed changes'}).click();
      await expect(feature.locator('[data-row-status]')).toHaveText('Saved.');
    }
    await page.reload();
    await expect(toggle).toBeChecked();

    await page.goto('/workflows');
    await page.getByRole('link', {name: 'Learning examples'}).click();
    await expect(page).toHaveURL(/\/learning\/examples$/);
    await expect(page.locator('#lex-list .lex__row')).toHaveCount(2);
    await page.locator('#lex-filter').selectOption('permission');
    await expect(page.locator('#lex-list .lex__row')).toHaveCount(2);
    await page.locator('#lex-list a').first().click();
    await expect(page.locator('#lx-grant')).toBeVisible();

    await page.goto(`/flows/${flowId}/teach`);
    const choices = page.locator('#rc-runs input[name="rc-run"]');
    await expect(choices).toHaveCount(2);
    for (const choice of await choices.all()) await expect(choice).toBeDisabled();
    await expect(page.locator('#sg-runs')).toContainText('No runs are allowed for learning right now');
    const denied = await request.post(`/api/v1/flows/${flowId}/teach/recipe/learn`, {
      data: {run_ids: runs, tools, style: 'plain', max_operations: 2},
    });
    expect(denied.status(), await denied.text()).toBe(409);
    const accepted = await (await request.get(`/api/v1/flows/${flowId}/runs/${runs[0]}/episode-capture`)).json();
    expect(accepted.status).toBe('accepted');
    expect(accepted.grant_sha256).toBeFalsy();
    const unsigned = await request.post(`/api/v1/flows/${flowId}/runs/${runs[0]}/episode-capture/signed-export`, {
      data: {expected_revision: accepted.revision, expected_episode_sha256: accepted.episode_sha256,
        expected_grant_sha256: '0'.repeat(64)},
    });
    expect(unsigned.status(), await unsigned.text()).toBe(409);

    for (const run of runs) {
      await page.goto(`/flows/${flowId}/runs/${run}`);
      await expect(page.locator('#lx-grant')).toBeVisible();
      await page.locator('#lx-grant-reason').fill('Allow this reviewed local example to teach a bounded flow.');
      await page.locator('#lx-grant-copies').check();
      // Permission is a reviewed decision: every retained detail is shown and must be confirmed.
      await page.locator('#lx-grant-go').click();
      const decision = page.locator('#lx-decision-review');
      const confirm = decision.getByRole('button', {name: 'Confirm learning permission', exact: true});
      await expect(confirm).toBeDisabled();
      await decision.getByLabel('I reviewed every retained detail and this decision.').check();
      await confirm.click();
      await expect(page.locator('#lx-status')).toContainText('new flows may learn from it');
    }

    await page.goto('/learning/examples');
    await page.locator('#lex-filter').selectOption('ready');
    await expect(page.locator('#lex-list .lex__row')).toHaveCount(2);

    await page.goto(`/flows/${flowId}/teach`);
    await expect(choices).toHaveCount(2);
    for (const choice of await choices.all()) {
      await expect(choice).toBeEnabled();
      await choice.check();
    }
    await expect(page.locator('#sg-runs button')).toHaveCount(2);
    await page.locator('#mv-copilot-fab').click();
    await page.locator('#mv-product-operation-buttons').getByRole('button', {name: 'Learn from reviewed runs', exact: true}).click();
    await page.locator('#mv-operation-run_ids').selectOption(['0', '1']);
    await page.locator('#mv-product-operation-form').getByRole('button', {name: 'Review change', exact: true}).click();
    await page.locator('#mv-product-operation-form input[type="checkbox"]').check();
    await page.locator('#mv-product-operation-form').getByRole('button', {name: 'Apply reviewed change', exact: true}).click();
    await expect(page.locator('#mv-product-operation-form')).toContainText('Review the learned procedure');
    await page.locator('#mv-copilot-close').click();
    await expect(page.locator('#rc-result')).toBeVisible();
    await expect(page.locator('#rc-summary')).toContainText('Learned from 2 runs');
    await page.locator('#rc-name').fill('Local learned procedure');
    const drafted = page.waitForResponse(response => response.url().endsWith('/teach/recipe/draft'), {timeout: 60000});
    await page.locator('#rc-draft').click();
    await expect(page.locator('#mv-confirm')).toBeVisible();
    await page.locator('#mv-confirm-ok').click();
    const draftResponse = await drafted;
    expect(draftResponse.status(), await draftResponse.text()).toBe(200);
    await expect(page.locator('#ft-save')).toBeVisible();
    await expect(page.locator('#ft-save-note')).toContainText('evidence is bound');
    await page.locator('#ft-save-go').click();
    await expect(page.locator('#mv-confirm')).toBeVisible();
    await page.locator('#mv-confirm-ok').click();
    await expect(page.locator('#ft-status')).toContainText('Saved');
    const designer = await page.locator('#ft-status a').getAttribute('href');
    const learnedId = decodeURIComponent(designer.split('/').pop());
    const probe = await request.post(`/__browser_fixture/signed-learning/prepare-probe?flow_id=${encodeURIComponent(learnedId)}`);
    expect(probe.status(), await probe.text()).toBe(200);
    expect(await probe.json()).toMatchObject({status: 'paused_approval', calls: sourceCalls, lineage_bound: true});

    await page.goto(`/flows/${flowId}/runs/${runs[0]}`);
    await expect(page.locator('#le-withdraw')).toBeVisible();
    await page.locator('#le-withdraw').click();
    await page.locator('#le-reason').fill('Stop future learning and execution from this source.');
    await page.locator('#le-confirm').click();
    await expect(page.locator('#le-status')).toHaveText('Use stopped');

    const continued = await request.post('/__browser_fixture/signed-learning/continue-probe');
    expect(continued.status(), await continued.text()).toBe(200);
    const outcome = await continued.json();
    expect(['failed', 'indeterminate']).toContain(outcome.status);
    expect(outcome.calls_after).toBe(outcome.calls_before);
    expect(errors).toEqual([]);
  });
