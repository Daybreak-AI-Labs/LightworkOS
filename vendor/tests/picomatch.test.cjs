'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

for (const version of [2, 3, 4]) {
  const picomatch = require('../js/picomatch-v' + version);
  const implementation = require('../js/picomatch-v' + version + '/lib/picomatch');

  test('picomatch v' + version + ' keeps ordinary patterns and non-repeated choices', () => {
    assert.equal(picomatch.isMatch('src/ui/Card.ts', 'src/**/*.{js,ts}'), true);
    assert.equal(picomatch.isMatch('src/ui/Card.css', 'src/**/*.{js,ts}'), false);
    assert.equal(picomatch.isMatch('src/ui/Card.ts', 'src/@(ui|data)/*.ts'), true);
    assert.equal(picomatch.isMatch('src/other/Card.ts', 'src/@(ui|data)/*.ts'), false);
    assert.equal(picomatch.isMatch('index.js', '**/!(*.test).js'), true);
    assert.equal(picomatch.isMatch('index.test.js', '**/!(*.test).js'), false);
  });

  test('picomatch v' + version + ' refuses repeated groups before compiling', () => {
    const refusal = {name: 'SyntaxError', message: 'Repeated extglob quantifiers are not supported'};
    assert.throws(() => picomatch.makeRe('src/+(archive).ts'), refusal);
    assert.throws(() => implementation.parse('reports/*(draft).csv', {maxExtglobRecursion: false}), refusal);
    assert.throws(() => picomatch('+(example)', {fastpaths: false}), refusal);
  });
}
