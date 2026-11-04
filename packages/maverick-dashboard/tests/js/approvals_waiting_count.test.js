"use strict";
// The Approvals header ("N requests waiting") follows the queue after a
// decision, an undo or a send-back, and the confirmation names the action.
// Run with: node --test tests/js/approvals_waiting_count.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const queue = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/_approvals_queue.html"), "utf8").replace(/\r\n/g, "\n");
const counter = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-approvals-count.js"), "utf8");
const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(setImmediate); };

function card(id, risk, label) {
  return `<article class="approval-item" data-id="${id}" data-label="${label}" data-risk="${risk}" data-irreversible="no" id="approval-${id}">
    <div class="approval-item__head"><h2>${label}</h2><span class="badge approval-outcome" hidden></span></div>
    <div class="muted approval-detail"><p>Detail ${id}</p></div>
    <p class="approval-item__decided muted" hidden></p>
    <div class="approval-actions">
      <button type="button" class="btn approval-btn" data-id="${id}" data-action="approve">Approve "${label}"</button>
      <button type="button" class="btn btn--ghost approval-btn" data-id="${id}" data-action="deny">Reject "${label}"</button>
    </div>
    <div class="approval-actions approval-actions--decided" hidden>
      <button type="button" class="btn approval-undo" data-id="${id}">Undo</button>
      <button type="button" class="btn btn--ghost approval-dismiss" data-id="${id}">Dismiss</button>
    </div>
  </article>`;
}

function fixture({flow = 0, privateCount = 0} = {}) {
  const dialog = queue.slice(queue.indexOf('<dialog id="approval-confirm"'), queue.indexOf("</dialog>") + "</dialog>".length);
  const html = `<main id="content"><div id="approvals-current-state" data-flow-count="${flow}" data-private-count="${privateCount}" data-in-chat="0" data-coverage="current">
      <div class="hero-statebox"><div class="hero-statebox__row"><strong>2 requests waiting</strong><span class="badge warn">Action needed</span></div></div></div>
    <div id="approval-queue">${card(1, "low", "Write file")}${card(2, "high", "Delete records")}</div>
    <p id="approval-msg" role="status"></p>
    <section id="approval-decided" hidden><div id="approval-decided-list"></div></section>${dialog}</main>`;
  const dom = new JSDOM(html, {url: "https://fixture.invalid/approvals", runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window, doc = w.document, forms = [];
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () { this.open = false; };
  w.mvToast = () => {};
  w.mvForm = async (title, fields, options) => { forms.push({title, options}); return {reason: ""}; };
  w.setInterval = () => 1; w.clearInterval = () => {};
  w.fetch = async (url) => {
    if (url.endsWith("/undo")) return {ok: true, status: 200, headers: new w.Headers()};
    return {ok: true, status: 204, headers: new w.Headers({"X-Lightwork-Decided-By": "user:reviewer", "X-Lightwork-Undo-Seconds": "30"})};
  };
  const start = queue.indexOf("  (function() {\n    const msg = document.getElementById('approval-msg')");
  w.eval(queue.slice(start, queue.indexOf("</script>", start)));
  w.eval(counter);
  const count = () => doc.querySelector("#approvals-current-state strong").textContent;
  const badge = () => doc.querySelector("#approvals-current-state .badge");
  const press = (button) => button.dispatchEvent(new w.MouseEvent("click", {bubbles: true, detail: 0}));
  return {dom, w, doc, forms, count, badge, press, item: (id) => doc.getElementById("approval-" + id)};
}

test("approving one of two requests updates the header count, and undo restores it", async () => {
  const f = fixture();
  try {
    f.press(f.item(1).querySelector('[data-action="approve"]'));
    await flush();
    assert.equal(f.count(), "1 request waiting");
    f.press(f.item(1).querySelector(".approval-undo"));
    await flush();
    assert.equal(f.count(), "2 requests waiting");
  } finally { f.dom.window.close(); }
});

test("deciding the last request says nothing is waiting, and flow approvals still count", async () => {
  const f = fixture();
  try {
    f.press(f.item(1).querySelector('[data-action="deny"]'));
    await flush();
    assert.equal(f.forms[0].options.okText, 'Reject "Write file"');
    const high = f.item(2).querySelector('[data-action="approve"]');
    f.press(high);
    await flush();
    const ok = f.doc.getElementById("approval-confirm-ok");
    assert.equal(ok.textContent, 'Approve "Delete records"');
    f.doc.getElementById("approval-confirm-ack").checked = true;
    f.doc.getElementById("approval-confirm-form").dispatchEvent(new f.w.Event("submit", {cancelable: true}));
    await flush();
    assert.equal(f.count(), "0 requests waiting");
    assert.equal(f.badge().textContent, "All clear");
  } finally { f.dom.window.close(); }
  const g = fixture({flow: 1});
  try {
    g.press(g.item(1).querySelector('[data-action="approve"]'));
    await flush();
    assert.equal(g.count(), "2 requests waiting");
  } finally { g.dom.window.close(); }
});
