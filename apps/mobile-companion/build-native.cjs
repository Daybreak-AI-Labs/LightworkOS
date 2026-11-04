/* Local-only Expo project generation and unsigned/simulator builds. No upload. */
const {spawnSync} = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const platform = process.argv.slice(2).find(arg => ['android', 'ios'].includes(arg));
if (!['android', 'ios'].includes(platform)) throw Error('Choose android or ios.');
const root = __dirname;
process.env.EXPO_NO_TELEMETRY = '1';
function run(command, args, cwd = root) {
  const temporary = path.join(root, '.native-template', 'tmp');
  fs.mkdirSync(temporary, {recursive: true});
  const result = spawnSync(command, args, {cwd, stdio: 'inherit', shell: false,
    env: {...process.env, TEMP: temporary, TMP: temporary, TMPDIR: temporary}});
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status || 1);
}
const generateOnly = process.argv.includes('--generate-only');
// Generating either project works on any OS; building the iOS one needs a Mac.
if (platform === 'ios' && process.platform !== 'darwin' && !generateOnly) throw Error('iOS builds require macOS and Xcode. No build was started.');
const template = require('./native-template.json');
const templateDir = path.join(root, '.native-template');
fs.mkdirSync(templateDir, {recursive: true});
const archive = path.join(templateDir, template.package + '-' + template.version + '.tgz');
if (!fs.existsSync(archive)) {
  if (!process.env.npm_execpath) throw Error('Use npm run build:android:local or build:ios:local so the installed npm CLI is explicit.');
  run(process.execPath, [process.env.npm_execpath, 'pack', template.package + '@' + template.version,
    '--ignore-scripts', '--pack-destination', templateDir]);
}
const integrity = 'sha512-' + crypto.createHash('sha512').update(fs.readFileSync(archive)).digest('base64');
if (integrity !== template.integrity) throw Error('Native template integrity does not match the reviewed pin.');
run(process.execPath, [require.resolve('expo/bin/cli'), 'prebuild', '--platform', platform, '--no-install',
  '--template', archive, '--skip-dependency-update', 'react,react-native,expo']);
if (generateOnly) process.exit(0);
if (platform === 'android') {
  if (!process.env.JAVA_HOME || !(process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT)) {
    throw Error('Install JDK 17 and Android SDK, then set JAVA_HOME and ANDROID_HOME. No signed build or upload is attempted.');
  }
  // Gradle's wrapper jar starts Java directly, avoiding a cmd/batch shell.
  run(path.join(process.env.JAVA_HOME, 'bin', process.platform === 'win32' ? 'java.exe' : 'java'),
    ['-classpath', path.join(root, 'android/gradle/wrapper/gradle-wrapper.jar'),
     'org.gradle.wrapper.GradleWrapperMain', '--no-daemon', 'assembleDebug'], path.join(root, 'android'));
} else {
  run('pod', ['install'], path.join(root, 'ios'));
  const workspace = fs.readdirSync(path.join(root, 'ios')).find(name => name.endsWith('.xcworkspace'));
  if (!workspace) throw Error('Generated iOS workspace is missing.');
  run('xcodebuild', ['-workspace', workspace, '-scheme', 'LightworkCompanion', '-configuration', 'Debug',
    '-sdk', 'iphonesimulator', '-destination', 'generic/platform=iOS Simulator',
    '-derivedDataPath', path.join(root, 'dist/ios-simulator'), 'CODE_SIGNING_ALLOWED=NO', 'build'], path.join(root, 'ios'));
}
