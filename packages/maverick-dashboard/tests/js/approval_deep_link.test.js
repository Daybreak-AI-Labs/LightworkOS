// Run with: node --test packages/maverick-dashboard/tests/js/approval_deep_link.test.js
'use strict';
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');

const template = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/approvals.html'), 'utf8').replace(/<script nonce="\{\{ csp_script_nonce \}\}">/g, "<script>");
const start = template.lastIndexOf('<script>');
const script = template.slice(start + 8, template.indexOf('</script>', start));

function page(hash) {
  const dom = new JSDOM(`<p id="approval-missing" role="status" hidden>This approval was already decided or no longer exists.
    <a href="#request-decision-history" id="approval-missing-history">See decisions on your requests</a></p>
    <article id="approval-5" data-id="5"></article><details id="request-decision-history"><summary>Decisions</summary></details>`,
    {url: 'https://local.test/approvals' + hash, runScripts: 'outside-only'});
  dom.window.eval(script);
  return dom;
}

test('a link to an approval that is no longer waiting says so', () => {
  const dom = page('#approval-999'), d = dom.window.document;
  assert.equal(d.getElementById('approval-missing').hidden, false);
  d.getElementById('approval-missing-history').click();
  assert.equal(d.getElementById('request-decision-history').open, true);
  dom.window.close();
});

test('a link to a waiting approval, or no approval link, shows no note', () => {
  for (const hash of ['#approval-5', '', '#request-decision-history']) {
    const dom = page(hash);
    assert.equal(dom.window.document.getElementById('approval-missing').hidden, true, hash);
    dom.window.close();
  }
});
