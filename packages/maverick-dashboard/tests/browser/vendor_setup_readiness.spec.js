// Rendered UI regression with explicitly synthetic vendor-setup responses.
// The real local template, CSP and JavaScript execute in Chromium. Separate
// service/API tests establish deployment enforcement; this spec does not.
const {test, expect} = require('@playwright/test');
const SETUP = /\/api\/v1\/vendor-setup(?:\/enable)?(?:\?.*)?$/;
test.skip(process.env.LIGHTWORK_BROWSER_SHOW_VENDOR_SETUP !== '1',
  'This explicitly synthetic setup fixture requires LIGHTWORK_BROWSER_SHOW_VENDOR_SETUP=1.');

test.beforeEach(async ({context, page, baseURL}) => {
  await context.route('**/*', route => new URL(route.request().url()).origin === new URL(baseURL).origin
    ? route.continue() : route.abort('blockedbyclient'));
  page.__uncaught = [];
  page.on('pageerror', error => page.__uncaught.push(error.message));
});

test.afterEach(async ({page, context}, info) => {
  await info.attach('setup-readiness-rendered-state', {
    body: await page.screenshot({fullPage: true}), contentType: 'image/png',
  });
  expect(page.__uncaught).toEqual([]);
  await context.unrouteAll({behavior: 'ignoreErrors'});
});

function setupFixture(overrides = {}) {
  return {
    context: '1'.repeat(64), configuration: '2'.repeat(64), revision: 0,
    principal: 'user:browser-reviewer', modules_enabled: false, connections_enabled: false,
    owner_locked: false, owner_source: 'unassigned', eligible_owners: ['user:browser-reviewer'],
    binding: {enable: false, resource_owner: '', ticket_connection: '', document_connection: '',
      reviewed_uploads: true},
    connections: [], live_provider_verified: false,
    readiness: {
      state: 'setup_required', configuration_complete: false, live_provider_verified: false,
      deployment: {supported: true, message: 'One persistent application replica is supported.'},
      actions: [
        {id: 'connect_jira', label: 'Connect a Jira account', href: '/connections'},
        {id: 'choose_owner', label: 'Choose a vendor review owner', href: '#vs-resource-owner'},
        {id: 'enable_workflow', label: 'Enable vendor workflow', href: '#vs-enable'},
        {id: 'save_setup', label: 'Save workspace setup', href: '#vs-confirm'},
      ],
    },
    ...overrides,
  };
}

function configuredFixture() {
  return setupFixture({
    revision: 4, modules_enabled: true, connections_enabled: true, owner_locked: true,
    owner_source: 'workspace_binding', eligible_owners: [],
    binding: {enable: true, resource_owner: 'user:browser-reviewer',
      ticket_connection: 'browser-jira', document_connection: '', reviewed_uploads: true},
    connections: [{name: 'browser-jira', connector: 'jira', base_url: 'https://jira.example.test',
      revision: 'jira-1', has_token: true}],
    readiness: {
      state: 'configured', configuration_complete: true, live_provider_verified: false,
      deployment: {supported: true, message: 'One persistent application replica is supported.'},
      actions: [],
    },
  });
}

async function routeFixture(page, initial) {
  let current = initial;
  const mutations = [];
  await page.route(SETUP, async route => {
    if (route.request().method() !== 'GET') {
      mutations.push({method: route.request().method(), url: route.request().url()});
      // UI verification never enables or saves the actual fixture server.
      return route.fulfill({status: 409, contentType: 'application/json',
        body: JSON.stringify({detail: 'Synthetic readiness fixture forbids setup mutation.'})});
    }
    return route.fulfill({status: 200, contentType: 'application/json',
      body: JSON.stringify(current)});
  });
  return {mutations, replace: value => { current = value; }};
}

async function openSetup(page, width) {
  await page.setViewportSize({width, height: 950});
  await page.goto('/third-party/vendor-onboarding');
  await expect(page.locator('#vs-panel')).toBeVisible();
}

async function fitsAndCapture(page, info, name) {
  const bounds = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth,
  }));
  expect(bounds.scroll).toBeLessThanOrEqual(bounds.viewport + 1);
  const presentation = await page.locator('#vs-confirm').evaluate(input => {
    const checkbox = input.getBoundingClientRect();
    const text = input.closest('label').querySelector('span').getBoundingClientRect();
    return {width: checkbox.width, gap: text.left - checkbox.right};
  });
  expect(presentation.width).toBeGreaterThan(0);
  expect(presentation.width).toBeLessThan(30);
  expect(presentation.gap).toBeGreaterThanOrEqual(0);
  expect(presentation.gap).toBeLessThan(17);
  await info.attach(name, {body: await page.locator('#vs-panel').screenshot(), contentType: 'image/png'});
}

test('fresh mobile setup names the required actions without claiming readiness', async ({page}, info) => {
  const fixture = await routeFixture(page, setupFixture());
  await openSetup(page, 320);
  await expect(page.locator('#vs-readiness-summary')).toContainText('Setup required');
  await expect(page.locator('#vs-next-actions li')).toHaveCount(4);
  for (const action of setupFixture().readiness.actions) {
    await expect(page.locator('#vs-next-actions').getByRole('link', {name: action.label, exact: true}))
      .toHaveAttribute('href', action.href);
  }
  await expect(page.locator('#vs-save')).toBeDisabled();
  await expect(page.locator('#vs-enable')).toBeDisabled();
  await expect(page.locator('#vs-next-actions')).not.toContainText('Google Drive');
  expect(fixture.mutations).toEqual([]);
  await fitsAndCapture(page, info, 'fresh-setup-controls-320');
  await page.locator('#vs-next-actions').getByRole('link', {name: 'Choose a vendor review owner', exact: true}).click();
  await expect.poll(() => page.locator('#vs-resource-owner').evaluate(select => {
    const bounds = select.getBoundingClientRect();
    return document.elementFromPoint(bounds.left + bounds.width / 2, bounds.top + bounds.height / 2) === select;
  })).toBe(true);
});

test('saved uploads-only configuration stays distinct from verified provider access on desktop', async ({page}, info) => {
  const fixture = await routeFixture(page, configuredFixture());
  await openSetup(page, 1280);
  await expect(page.locator('#vs-readiness-summary'))
    .toContainText('Setup saved; provider access still needs checking');
  await expect(page.locator('#vs-next-actions li')).toHaveCount(0);
  await expect(page.locator('#vs-ticket')).toHaveValue('browser-jira');
  await expect(page.locator('#vs-document')).toHaveValue('');
  await expect(page.locator('#vs-resource-owner')).toBeDisabled();
  await expect(page.locator('#vs-save')).toBeDisabled();
  await page.locator('#vs-confirm').focus();
  await page.locator('#vs-confirm').press('Space');
  await expect(page.locator('#vs-confirm')).toBeChecked();
  await expect(page.locator('#vs-save')).toBeEnabled();
  await expect(page.locator('#vs-enable')).toBeDisabled();
  // Confirmation alone grants no provider call and sends no setup mutation.
  expect(fixture.mutations).toEqual([]);
  await fitsAndCapture(page, info, 'configured-setup-controls-1280');
});

test('unsupported deployment blocks activation and saving even with otherwise configured inputs', async ({page}, info) => {
  const blocked = {
    state: 'blocked', configuration_complete: false, live_provider_verified: false,
    deployment: {supported: false, message: 'This workflow requires one persistent application replica.'},
    actions: [{id: 'deployment_support', label: 'Review deployment support', href: '#vs-deployment'}],
  };
  const fixture = await routeFixture(page, setupFixture({readiness: blocked}));
  await openSetup(page, 320);
  await expect(page.locator('#vs-readiness-summary')).toContainText('Deployment needs attention');
  await expect(page.locator('#vs-next-actions').getByRole('link', {name: 'Review deployment support'}))
    .toHaveAttribute('href', '#vs-deployment');
  // A checked property must not override deployment gating, including when a
  // previous form interaction or an extension restores checkbox state.
  await page.locator('#vs-confirm').evaluate(input => {
    input.checked = true; input.dispatchEvent(new Event('change', {bubbles: true}));
  });
  await expect(page.locator('#vs-enable')).toBeDisabled();
  await expect(page.locator('#vs-save')).toBeDisabled();
  fixture.replace({...configuredFixture(), readiness: blocked});
  await page.locator('#vs-refresh').click();
  await expect(page.locator('#vs-ticket')).toHaveValue('browser-jira');
  await page.locator('#vs-confirm').evaluate(input => {
    input.checked = true; input.dispatchEvent(new Event('change', {bubbles: true}));
  });
  await expect(page.locator('#vs-readiness-summary')).toContainText('Deployment needs attention');
  await expect(page.locator('#vs-enable')).toBeDisabled();
  await expect(page.locator('#vs-save')).toBeDisabled();
  expect(fixture.mutations).toEqual([]);
  await fitsAndCapture(page, info, 'blocked-setup-controls-320');
});
