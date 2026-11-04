// Authored regression tests; run later with node --test.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../maverick_dashboard/static/lightwork-ui.js'), 'utf8');
function helpers() {
  const start = source.indexOf('      // Only the business-error envelope');
  const end = source.indexOf('      // A server message', start);
  const context = {window: {}}; vm.createContext(context); vm.runInContext(source.slice(start, end), context);
  return context.window;
}
test('business meanings survive status codes without generic wrong remedies', () => {
  const ui = helpers();
  const cases = [['budget_ceiling', 400, 'Choose a lower spending limit.'],
    ['task_unfinished', 409, 'Wait for the task to finish.'],
    ['signoff_required', 409, 'Review and sign off the saved result.'],
    ['stale_version', 409, 'Review the changed result.'],
    ['admission_hold', 409, 'Recover the outcome pilot.']];
  for (const [code, status, message] of cases) assert.equal(ui.mvErrorText({status,
    detail: {schema:'lightwork.error.v1', code, message, field_errors:{}}}), message);
  assert.match(ui.mvErrorText({status:401}), /sign-in has expired/);
});
test('raw provider details and malformed envelopes stay opaque', () => {
  const ui = helpers();
  assert(!ui.mvErrorText({status:500, detail:'private provider credential'}).includes('credential'));
  assert.equal(ui.mvBusinessError({schema:'unknown', code:'failure', message:'private'}), null);
});
