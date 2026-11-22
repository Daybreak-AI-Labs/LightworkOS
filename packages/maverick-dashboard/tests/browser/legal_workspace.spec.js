const {test, expect} = require('@playwright/test');
const {execFile} = require('node:child_process');
const {promisify} = require('node:util');
const path = require('node:path');

test('legal department completes reviewed work and recovers interrupted replies', async ({baseURL}, testInfo) => {
  const result = await promisify(execFile)(process.execPath, [path.join(__dirname, 'legal_workspace_smoke.cjs')], {
    env: {...process.env, LIGHTWORK_BROWSER_URL: baseURL, LIGHTWORK_SCREENSHOT_DIR: testInfo.outputPath('screenshots')},
    timeout: 160000
  });
  expect(result.stdout).toContain('PASS: legal intake');
});
