const test = require('node:test');
const assert = require('node:assert/strict');
const merge = require('../js/deepmerge/index.cjs');

function assertClean(value) {
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
  assert.equal(value.poisoned, undefined);
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    assert.equal(Object.hasOwn(value, key), false);
  }
}

test('unsafe own keys cannot poison a result from either operand', () => {
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const hostile = JSON.parse(`{"${key}":{"poisoned":true},"safe":1}`);
    for (const input of [hostile, Object.assign(Object.create(null), hostile)]) {
      for (const result of [merge(input, {}), merge({}, input), merge(input, input)]) {
        assertClean(result);
        assert.equal(result.safe, 1);
      }
    }
  }
  assert.equal({}.poisoned, undefined);
});

test('nested objects and arrays retain the same prototype protection', () => {
  const hostile = JSON.parse('{"nested":{"__proto__":{"poisoned":true}},"items":[{"__proto__":{"poisoned":true}}]}');
  for (const result of [merge(hostile, {}), merge({}, hostile)]) {
    assertClean(result.nested);
    assertClean(result.items[0]);
  }
});

test('Svelte config arrays replace and ordinary settings merge without mutation', () => {
  const before = {compilerOptions: {dev: false}, extensions: ['.svelte']};
  const after = {compilerOptions: {runes: true}, extensions: ['.custom']};
  const result = merge(before, after, {arrayMerge: (_, source) => source});
  assert.deepEqual(result, {compilerOptions: {dev: false, runes: true}, extensions: ['.custom']});
  assert.deepEqual(before, {compilerOptions: {dev: false}, extensions: ['.svelte']});
});

test('symbols, dates, regular expressions, functions and default array merging survive', () => {
  const key = Symbol('setting'), date = new Date(), regex = /example/, callback = () => 1;
  const result = merge({items: [1], [key]: {a: 1}}, {items: [2], [key]: {b: 2}, date, regex, callback});
  assert.deepEqual(result.items, [1, 2]);
  assert.deepEqual(result[key], {a: 1, b: 2});
  assert.equal(result.date, date);
  assert.equal(result.regex, regex);
  assert.equal(result.callback, callback);
});
