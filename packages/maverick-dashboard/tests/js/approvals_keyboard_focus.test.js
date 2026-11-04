"use strict";
// Keyboard and screen reader behaviour of the approval queue, measured on the
// dashboard: after a decision focus fell to <body>, Undo (a 30-second window)
// was 58 Tab presses away, and the decision was announced twice (status line
// and toast). Run with: node --test tests/js/approvals_keyboard_focus.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const queue = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/_approvals_queue.html"), "utf8").replace(/\r\n/g, "\n");
const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(setImmediate); };
// The confirmation opens one frame after the click (requestAnimationFrame,
// then setTimeout 0). A callback queued the same way after the click runs
// after it, so the dialog is open by then however loaded the machine is; a
// fixed wait let a busy run submit the form before the dialog opened.
const nextFrame = (w) => new Promise(resolve => w.requestAnimationFrame(() => w.setTimeout(resolve, 0)));

function card(id, risk, label) {
  return `<article class="approval-item" data-id="${id}" data-label="${label}" data-risk="${risk}" data-irreversible="no" id="approval-${id}" aria-labelledby="approval-title-${id}">
    <div class="approval-item__head"><h2 id="approval-title-${id}">${label}</h2><span class="badge approval-outcome" hidden></span></div>
    <div class="muted approval-detail"><p>Detail ${id}</p></div>
    <p class="approval-item__decided muted" hidden></p>
    <div class="approval-actions">
      <button type="button" class="btn approval-btn" data-id="${id}" data-action="approve">Approve</button>
      <button type="button" class="btn btn--ghost approval-btn" data-id="${id}" data-action="deny">Reject</button>
    </div>
    <div class="approval-actions approval-actions--decided" hidden>
      <button type="button" class="btn approval-undo" data-id="${id}">Undo</button>
      <button type="button" class="btn btn--ghost approval-dismiss" data-id="${id}">Dismiss</button>
    </div>
  </article>`;
}

function fixture({undoSeconds = 30, undoOk = true} = {}) {
  const dialog = queue.slice(queue.indexOf('<dialog id="approval-confirm"'), queue.indexOf("</dialog>") + "</dialog>".length);
  const html = `<main id="content" tabindex="-1"><div id="approval-queue">${card(1, "low", "Write file")}${card(2, "low", "Send email")}${card(3, "high", "Delete records")}</div>
    <p id="approval-msg" role="status" aria-live="polite"></p>
    <section id="approval-decided" hidden><h2>Decided just now</h2><div id="approval-decided-list"></div></section>${dialog}</main>`;
  const dom = new JSDOM(html, {url: "https://fixture.invalid/approvals", runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window, doc = w.document, toasts = [], timers = [], calls = [];
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () { this.open = false; };
  w.mvToast = (message, options) => toasts.push({message, options: options || {}});
  w.mvForm = async () => ({reason: ""});
  w.setInterval = (fn) => { timers.push(fn); return timers.length; };
  w.clearInterval = () => {};
  w.fetch = async (url, options) => {
    calls.push({url, options});
    if (url.endsWith("/undo")) return {ok: undoOk, status: undoOk ? 200 : 409, headers: new w.Headers()};
    return {ok: true, status: 204, headers: new w.Headers({"X-Lightwork-Decided-By": "user:reviewer", "X-Lightwork-Undo-Seconds": String(undoSeconds)})};
  };
  const start = queue.indexOf("  (function() {\n    const msg = document.getElementById('approval-msg')");
  w.eval(queue.slice(start, queue.indexOf("</script>", start)));
  const press = (button) => { button.focus(); button.dispatchEvent(new w.MouseEvent("click", {bubbles: true, detail: 0})); };
  return {dom, w, doc, toasts, timers, calls, press, item: (id) => doc.getElementById("approval-" + id)};
}

test("after approving by keyboard, focus is on that card's Undo and the decision is spoken once", async () => {
  const f = fixture();
  try {
    f.press(f.item(1).querySelector('[data-action="approve"]'));
    await flush();
    const undo = f.item(1).querySelector(".approval-undo");
    assert.equal(f.doc.getElementById("approval-decided-list").contains(f.item(1)), true);
    assert.equal(f.doc.activeElement, undo, "focus moves to Undo, 0 Tab presses away");
    // The status line speaks the decision, with the undo window, once; the
    // toast shows the same words without being read again.
    const said = f.doc.getElementById("approval-msg").textContent;
    assert.match(said, /Write file authorized\. Execution is a separate step/);
    assert.match(said, /You can undo for 30 seconds\./);
    assert.equal(f.toasts.length, 1);
    assert.equal(f.toasts[0].options.quiet, true);
    // The countdown is shown but stays out of the button's name, so a focused
    // Undo is not re-announced every second.
    assert.equal(undo.firstChild.nodeValue, "Undo");
    const countdown = undo.querySelector('[aria-hidden="true"]');
    assert.equal(countdown.textContent, "(30s)");
    f.timers[0]();
    assert.equal(countdown.textContent, "(29s)");
    assert.equal(undo.firstChild.nodeValue, "Undo");
  } finally { f.dom.window.close(); }
});

test("when the undo window ends while Undo has focus, focus moves to the decided line", async () => {
  const f = fixture({undoSeconds: 2});
  try {
    f.press(f.item(1).querySelector('[data-action="approve"]'));
    await flush();
    f.timers[0](); f.timers[0]();
    const line = f.item(1).querySelector(".approval-item__decided");
    assert.equal(f.item(1).querySelector(".approval-undo").hidden, true);
    assert.equal(f.doc.activeElement, line);
    assert.match(line.textContent, /The undo window has ended\./);
  } finally { f.dom.window.close(); }
});

test("without an undo window, focus moves to the next waiting card, never to an action", async () => {
  const f = fixture({undoSeconds: 0});
  try {
    f.press(f.item(1).querySelector('[data-action="approve"]'));
    await flush();
    assert.equal(f.doc.activeElement, f.item(2));
    assert.equal(f.item(2).getAttribute("tabindex"), "-1");
    assert.doesNotMatch(f.doc.getElementById("approval-msg").textContent, /undo for/);
  } finally { f.dom.window.close(); }
});

test("undo returns focus to the restored card, and dismiss to the next card", async () => {
  const f = fixture();
  try {
    f.press(f.item(1).querySelector('[data-action="approve"]'));
    await flush();
    f.press(f.item(1).querySelector(".approval-undo"));
    await flush();
    assert.equal(f.doc.getElementById("approval-queue").contains(f.item(1)), true);
    assert.equal(f.doc.activeElement, f.item(1));
    assert.equal(f.toasts.at(-1).options.quiet, true);

    f.press(f.item(2).querySelector('[data-action="approve"]'));
    await flush();
    f.press(f.item(2).querySelector(".approval-dismiss"));
    assert.equal(f.item(2), null);
    assert.equal(f.doc.activeElement, f.doc.querySelector("#approval-queue article.approval-item"));
  } finally { f.dom.window.close(); }
});

test("an undo refused because the window passed moves focus to the decided line", async () => {
  const f = fixture({undoOk: false});
  try {
    f.press(f.item(1).querySelector('[data-action="approve"]'));
    await flush();
    const undo = f.item(1).querySelector(".approval-undo");
    f.press(undo);
    await flush();
    // 409: the button goes, and focus does not fall to <body> with it.
    assert.equal(undo.hidden, true);
    assert.equal(f.doc.activeElement, f.item(1).querySelector(".approval-item__decided"));
  } finally { f.dom.window.close(); }
});

test("the acknowledgement error is tied to the box it is about", async () => {
  const f = fixture();
  try {
    f.press(f.item(3).querySelector('[data-action="approve"]'));
    await nextFrame(f.w); await flush();
    assert.equal(f.doc.getElementById("approval-confirm").open, true);
    const ack = f.doc.getElementById("approval-confirm-ack");
    const form = f.doc.getElementById("approval-confirm-form");
    assert.equal(ack.hasAttribute("aria-invalid"), false);
    form.dispatchEvent(new f.w.Event("submit", {bubbles: true, cancelable: true}));
    assert.equal(f.doc.getElementById("approval-confirm-err").textContent, "Tick the box to confirm you have read what this action will do.");
    assert.equal(ack.getAttribute("aria-invalid"), "true");
    assert.equal(ack.getAttribute("aria-describedby"), "approval-confirm-err");
    assert.equal(f.doc.activeElement, ack);
    // Ticking the box clears the error state.
    ack.checked = true;
    ack.dispatchEvent(new f.w.Event("change", {bubbles: true}));
    assert.equal(ack.hasAttribute("aria-invalid"), false);
    assert.equal(ack.hasAttribute("aria-describedby"), false);
    form.dispatchEvent(new f.w.Event("submit", {bubbles: true, cancelable: true}));
    await flush();
    assert.equal(f.doc.activeElement, f.item(3).querySelector(".approval-undo"));
  } finally { f.dom.window.close(); }
});

// Opening the modal restyles the whole page; the click's frame paints first
// and the confirmation opens in the next one (phone INP was 208-232 ms).
test("the high-risk confirmation opens just after the click's frame, once", async () => {
  const f = fixture();
  try {
    const approve = f.item(3).querySelector('[data-action="approve"]');
    f.press(approve);
    const dialog = f.doc.getElementById("approval-confirm");
    assert.equal(dialog.open, false, "not inside the click's own task");
    f.press(approve);   // a second click while it opens does not open it twice
    await nextFrame(f.w); await flush();
    assert.equal(dialog.open, true);
    assert.equal(f.doc.activeElement, f.doc.getElementById("approval-confirm-ack"));
  } finally { f.dom.window.close(); }
});
