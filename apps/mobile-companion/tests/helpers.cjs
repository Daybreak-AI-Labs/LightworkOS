const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
const React = require('react');
const renderer = require('react-test-renderer');
const ts = require('typescript');

const root = path.resolve(__dirname, '..');
const native = Object.fromEntries(
  ['Pressable', 'SafeAreaView', 'Text', 'TextInput', 'View', 'ScrollView', 'FlatList', 'Switch']
    .map(name => [name, name]),
);
native.useColorScheme = () => 'light';
native.Platform = {OS: 'web'};
const lifecycleListeners = new Set();
native.AppState = {
  currentState: 'active',
  addEventListener(_name, fn) { lifecycleListeners.add(fn); return {remove() { lifecycleListeners.delete(fn); }}; },
  emit(state) { this.currentState = state; lifecycleListeners.forEach(fn => fn(state)); },
};
native.BackHandler = {addEventListener() { return {remove() {}}; }};
native.Alert = {alert() {}};
native.Linking = {openURL: async () => {}};
native.StyleSheet = { create: value => value, hairlineWidth: 1 };
native.FlatList = function FlatList({ data, renderItem, ListEmptyComponent, ListHeaderComponent, ListFooterComponent }) {
  return React.createElement('FlatList', null, ListHeaderComponent, data.length
    ? data.map((item, index) => React.createElement(React.Fragment, { key: item.id ?? index }, renderItem({ item, index })))
    : ListEmptyComponent, ListFooterComponent);
};

// Execute real TS/TSX with React's renderer. Device APIs and timers are explicit
// mocks; this does not pretend to exercise native layout or the OS keychain.
function source(relative, mocks = {}) {
  const filename = path.join(root, relative);
  const compiled = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.React,
      esModuleInterop: true, target: ts.ScriptTarget.ES2022,
    },
    fileName: filename,
  });
  const module = { exports: {} };
  function requireMock(name) {
    if (Object.hasOwn(mocks, name)) {
      if (name.endsWith('/settings')) return {listProfiles: async () => ({active: '', profiles: []}), InvalidSavedConnection: class extends Error {}, ...mocks[name]};
      return mocks[name];
    }
    if (name === 'react') return React;
    if (name === 'react-native') return native;
    if (name === 'expo-modules-core') return {requireOptionalNativeModule: () => null};
    if (name === '@react-native-async-storage/async-storage') return {getItem: async () => null, setItem: async () => {}};
    if (name === 'expo-status-bar') return { StatusBar: 'StatusBar' };
    if (name.endsWith('/connectionValidation')) return source('src/connectionValidation.ts', mocks);
    if (name.endsWith('/nativeTransport')) return source('src/nativeTransport.ts', mocks);
    if (name.endsWith('/language')) return source('src/language.ts', mocks);
    if (name.endsWith('/api')) return source('src/api.ts', mocks);
    if (name.endsWith('/runReplay')) return source('src/runReplay.ts', mocks);
    if (name.endsWith('/poll')) return source('src/poll.ts', mocks);
    if (name.endsWith('/format')) return source('src/format.ts', mocks);
    if (name.endsWith('/theme')) return source('src/theme.ts', mocks);
    if (name.endsWith('/offlineCache') && Object.hasOwn(mocks, '@react-native-async-storage/async-storage')) return source('src/offlineCache.ts', mocks);
    if (name.endsWith('/offlineCache')) return {
      purgeBundle: async () => {}, purgeAppBundles: async () => {}, useCachedBundle: () => null,
      useConnectionCache: () => ({data: null, savedAt: null}),
    };
    if (name.endsWith('/components/ConnectionNotice')) return source('src/components/ConnectionNotice.tsx', mocks);
    if (name.endsWith('/components/ui')) return source('src/components/ui.tsx', mocks);
    if (name === './ui') return source('src/components/ui.tsx', mocks);
    if (name.endsWith('/components/PairingPanel')) return source('src/components/PairingPanel.tsx', mocks);
    if (name.endsWith('/components/TaskActions')) return source('src/components/TaskActions.tsx', mocks);
    if (name.includes('/screens/')) {
      const screen = name.split('/').at(-1);
      if (screen === 'SettingsScreen') return source('src/screens/SettingsScreen.tsx', mocks);
      return { [screen]: props => React.createElement(screen, props) };
    }
    throw new Error(`Unexpected import: ${name}`);
  }
  vm.runInNewContext(compiled.outputText, {
    module, exports: module.exports, require: requireMock, console, Error, URL,
    fetch: mocks.fetch, AbortController, TextDecoder,
    Response: Object.hasOwn(mocks, 'Response') ? mocks.Response : Response,
    ReadableStream: Object.hasOwn(mocks, 'ReadableStream') ? mocks.ReadableStream : ReadableStream,
    expo: Object.hasOwn(mocks, 'expo') ? mocks.expo : { uuidv4: randomUUID },
    crypto: mocks.crypto,
    setInterval: mocks.setInterval || (() => 1),
    clearInterval: mocks.clearInterval || (() => {}),
    setTimeout: mocks.setTimeout || setTimeout,
    clearTimeout: mocks.clearTimeout || clearTimeout,
  }, { filename });
  return module.exports;
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

const connection = { baseUrl: 'https://old.example.test', token: 'synthetic-old-token' };
const newer = { baseUrl: 'https://new.example.test', token: 'synthetic-new-token' };
const text = app => JSON.stringify(app.toJSON());
function tab(app, name) {
  return app.root.findAllByType('Pressable').find(node =>
    node.props.accessibilityRole === 'tab'
    && node.findAllByType('Text').some(label => label.props.children === name));
}
function button(app, label) {
  return app.root.findAllByType('Pressable').find(node =>
    node.findAllByType('Text').some(child => child.props.children === label));
}
module.exports = { native, React, ...renderer, source, deferred, connection, newer, text, tab, button };
