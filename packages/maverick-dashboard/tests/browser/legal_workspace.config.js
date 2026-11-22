const {defineConfig} = require('@playwright/test');
const path = require('node:path');
const python = require('./python-runtime');
const port = Number(process.env.LIGHTWORK_LEGAL_BROWSER_PORT || 8911);
module.exports = defineConfig({
  testDir: '.', testMatch: 'legal_workspace.spec.js', workers: 1, retries: 0,
  timeout: 180000, reporter: 'list',
  outputDir: path.resolve(__dirname, '../../../..', '.browser-legal-workspace-results'),
  use: {baseURL: `http://127.0.0.1:${port}`},
  webServer: {
    command: `${JSON.stringify(python)} legal_workspace_server.py --port ${port}`,
    url: `http://127.0.0.1:${port}/livez`, reuseExistingServer: false, timeout: 120000,
    gracefulShutdown: {signal: 'SIGTERM', timeout: 10000}
  }
});
