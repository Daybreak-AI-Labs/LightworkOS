"use strict";
// Rejecting (or approving) on the approval queue shows feedback on the card at
// once, the way data-mv-save forms say "Saving…": the button is busy and the
// card says "Rejecting…" before the server answers. Stream U measured just over
// 100 ms to the first feedback, which appeared only in the page's status line.
// Run with: node --test tests/js/approvals_decision_feedback.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const queue = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/_approvals_queue.html"), "utf8").replace(/\r\n/g, "\n");
const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(setImmediate); };

const CARD = `<article class="approval-item" data-id="7" data-label="Delete records" data-risk="low" data-irreversible="no" id="approval-7" aria-labelledby="approval-title-7">
    <div class="approval-item__head"><h2 id="approval-title-7">Delete records</h2><span class="badge approval-outcome" hidden></span></div>
    <p class="approval-item__decided muted" hidden></p>
    <div class="approval-actions">
      <button type="button" class="btn approval-btn" data-id="7" data-action="approve">Approve</button>
      <button type="button" class="btn btn--ghost approval-btn" data-id="7" data-action="deny">Reject</button>
    </div>
    <div class="approval-actions approval-actions--decided" hidden>
      <button type="button" class="btn approval-undo" data-id="7">Undo</button>
      <button type="button" class="btn btn--ghost approval-dismiss" data-id="7">Dismiss</button>
    </div>
  </article>`;

function fixture() {
  const dialog = queue.slice(queue.indexOf('<dialog id="approval-confirm"'), queue.indexOf("</dialog>") + "</dialog>".length);
  const dom = new JSDOM(`<main id="content" tabindex="-1"><div id="approval-queue">${CARD}</div>
    <p id="approval-msg" role="status" aria-live="polite"></p>
    <section id="approval-decided" hidden><div id="approval-decided-list"></div></section>${dialog}</main>`,
  {url: "https://fixture.invalid/approvals", runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window, pending = [];
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () { this.open = false; };
  w.mvToast = () => {};
  w.mvErrorText = (_failure, action) => "Could not " + action + ". Try again.";
  w.setInterval = () => 1; w.clearInterval = () => {};
  let answer; const forms = [];
  w.mvForm = (title, fields) => { forms.push(fields); return new Promise(resolve => { answer = resolve; }); };
  w.fetch = () => new Promise((resolve, reject) => pending.push({resolve, reject}));
  const start = queue.indexOf("  (function() {\n    const msg = document.getElementById('approval-msg')");
  w.eval(queue.slice(start, queue.indexOf("</script>", start)));
  const button = w.document.querySelector('[data-action="deny"]');
  return {dom, w, doc: w.document, pending, button, forms, answer: value => answer(value)};
}
const busyText = doc => (doc.querySelector("#approval-7 [data-approval-busy]") || {textContent: ""}).textContent;

test("the card says Rejecting… and the button is busy as soon as the reason is given", async () => {
  const f = fixture();
  try {
    f.button.click();
    await flush();
    f.answer({reason: "Wrong records"});
    await Promise.resolve(); await Promise.resolve();   // the same task as the dialog's answer, no waiting on the server
    assert.equal(f.pending.length, 1, "the decision is on its way");
    assert.equal(busyText(f.doc), "Rejecting…");
    assert.equal(f.doc.querySelector("#approval-7 [data-approval-busy]").getAttribute("role"), "status");
    assert.equal(f.button.getAttribute("aria-busy"), "true");
    assert.equal(f.button.disabled, true);
    f.pending[0].resolve({ok: true, status: 204, headers: new f.w.Headers({"X-Lightwork-Undo-Seconds": "0"})});
    await flush();
    assert.equal(busyText(f.doc), "", "the outcome replaces the busy line");
    assert.equal(f.button.hasAttribute("aria-busy"), false);
  } finally { f.dom.window.close(); }
});

test("a failed decision replaces the busy line with the error and gives the buttons back", async () => {
  const f = fixture();
  try {
    f.button.click();
    await flush();
    f.answer({});
    await flush();
    assert.equal(busyText(f.doc), "Rejecting…");
    f.pending[0].reject(new f.w.TypeError("Failed to fetch"));
    await flush();
    // "Rejecting…" gives way to the error, on the card itself.
    assert.equal(busyText(f.doc), "Could not record your decision. Try again.");
    assert.equal(f.button.disabled, false);
    assert.equal(f.button.hasAttribute("aria-busy"), false);
    assert.match(f.doc.getElementById("approval-msg").textContent, /Could not record your decision/);
  } finally { f.dom.window.close(); }
});

test("cancelling the reason changes nothing and shows no busy line", async () => {
  const f = fixture();
  try {
    f.button.click();
    await flush();
    f.answer(null);
    await flush();
    assert.equal(f.pending.length, 0);
    assert.equal(busyText(f.doc), "");
    assert.equal(f.button.hasAttribute("aria-busy"), false);
  } finally { f.dom.window.close(); }
});

test("a blocked rejection says so on the card and keeps the typed reason for the retry", async () => {
  const f = fixture();
  try {
    f.button.click(); await flush();
    assert.equal(f.forms[0][0].default || "", "");
    f.answer({reason: "Wrong records"}); await flush();
    f.pending[0].reject(new f.w.TypeError("Failed to fetch")); await flush();
    const line = f.doc.querySelector("#approval-7 [data-approval-busy]");
    assert.equal(line.textContent, "Could not record your decision. Try again.");
    assert.equal(line.classList.contains("mv-status--error"), true);
    assert.equal(f.doc.querySelectorAll('#approval-queue article.approval-item[data-id="7"]').length, 1, "still waiting in the queue");
    f.button.click(); await flush();
    assert.equal(f.forms[1][0].default, "Wrong records", "what was typed is offered again");
    assert.equal(line.textContent, "", "a new attempt clears the old error");
  } finally { f.dom.window.close(); }
});
