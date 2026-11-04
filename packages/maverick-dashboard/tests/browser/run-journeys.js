'use strict';
// `npm test`: the journeys that share the default fixture server
// (playwright.config.js), then each journey whose fixture needs its own server
// (<journey>.config.js). Every run reports; the command fails if any fails.
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const cli = require.resolve('@playwright/test/cli');
const own = fs.readdirSync(__dirname).filter(name => name.endsWith('.config.js') && name !== 'playwright.config.js').sort();
const failed = [];
for (const config of ['playwright.config.js', ...own]) {
  const run = spawnSync(process.execPath, [cli, 'test', '--config', config], {cwd: __dirname, stdio: 'inherit'});
  if (run.status !== 0) failed.push(config);
}
if (failed.length) {
  console.error('Browser journeys failed under: ' + failed.join(', '));
  process.exit(1);
}
