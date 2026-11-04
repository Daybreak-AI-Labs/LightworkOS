const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// build-native.cjs refuses to run without a platform ("Choose android or ios."),
// so every npm script that calls it must name one. `npm run prebuild` once
// passed only --generate-only and could never succeed.
const root = path.resolve(__dirname, '..');
const scripts = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts;

test('every script that runs build-native.cjs names android or ios', () => {
  const native = Object.entries(scripts).filter(([, command]) => command.includes('build-native.cjs'));
  assert.ok(native.length >= 4);
  for (const [name, command] of native) {
    const args = command.split(/\s+/).slice(command.split(/\s+/).indexOf('build-native.cjs') + 1);
    assert.equal(args.filter(arg => arg === 'android' || arg === 'ios').length, 1, `${name}: ${command}`);
  }
});

test('project generation is available for each platform on its own', () => {
  assert.equal(scripts['prebuild:android'], 'node build-native.cjs android --generate-only');
  assert.equal(scripts['prebuild:ios'], 'node build-native.cjs ios --generate-only');
  assert.equal(scripts.prebuild, undefined, 'no platform-less prebuild script remains');
});

test('generating the iOS project does not need a Mac; building it does', () => {
  const code = fs.readFileSync(path.join(root, 'build-native.cjs'), 'utf8');
  assert.match(code, /if \(platform === 'ios' && process\.platform !== 'darwin' && !generateOnly\) throw/);
  assert.match(code, /if \(generateOnly\) process\.exit\(0\);/);
});
