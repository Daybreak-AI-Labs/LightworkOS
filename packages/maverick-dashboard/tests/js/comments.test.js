"use strict";
// Comment threads with @mentions (static/lightwork-comments.js, NOT-4): load
// the thread, offer only the people the server lists, post with the people
// whose names are still in the text, and delete with a way back.
// Run with: node --test tests/js/comments.test.js
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const {JSDOM} = require("jsdom");
const pkg = path.resolve(__dirname, "../../maverick_dashboard");
const ui = fs.readFileSync(path.join(pkg, "static/lightwork-ui.js"), "utf8");
const script = fs.readFileSync(path.join(pkg, "static/lightwork-comments.js"), "utf8");
const flush = async () => { for (let i = 0; i < 20; i++) await new Promise(setImmediate); };

const MARKUP = `<section class="panel mv-comments" id="comments-policy-tools" data-comments-kind="policy" data-comments-id="tools">
  <h2>Comments</h2><ol class="mv-comments__list"></ol>
  <form class="mv-comments__form" hidden>
    <label for="b">Add a comment</label><textarea class="input mv-comments__body" id="b" required></textarea>
    <div class="mv-comments__mention"><label for="w">Mention someone</label>
      <select class="select mv-comments__who" id="w"><option value="">Choose a person</option></select>
      <button type="button" class="btn btn--ghost mv-comments__add">Add mention</button></div>
    <p class="muted mv-comments__mentioned"></p><button type="submit" class="btn">Post comment</button>
  </form><p class="mv-comments__status muted" data-mv-status></p></section>`;

function boot(thread) {
  const dom = new JSDOM(`<div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content">${MARKUP}</main>`,
    {url: "https://fixture.invalid/permissions", runScripts: "outside-only", pretendToBeVisual: true});
  const w = dom.window, calls = [];
  w.matchMedia = () => ({matches: false, addEventListener() {}, removeEventListener() {}});
  w.eval(ui);
  let current = thread;
  w.mvFetchJSON = async (url, opts) => {
    calls.push({url, opts: opts || {}});
    if (opts && opts.method === "POST") {
      current = Object.assign({}, current, {comments: current.comments.concat([{id: 9, author: "dana", mine: true,
        body: opts.body.body, created_at: 1, mentions: ["Lee"]}])});
    }
    return current;
  };
  w.fetch = async (url, options) => { calls.push({url, opts: options}); return {ok: true, status: 200}; };
  w.eval(script);
  return {w, calls, doc: w.document};
}

test("the thread loads, and only the people the server lists can be mentioned", async () => {
  const {doc, calls} = boot({comments: [], people: [{principal: "user:lee", label: "Lee"}], can_comment: true});
  await flush();
  assert.equal(calls[0].url, "/api/v1/comments?kind=policy&id=tools");
  assert.equal(doc.querySelector(".mv-comments__form").hidden, false);
  assert.match(doc.querySelector(".mv-comments__list").textContent, /No comments yet/);
  const options = [...doc.querySelectorAll(".mv-comments__who option")].map(o => o.textContent);
  assert.deepEqual(options, ["Choose a person", "Lee"]);
});

test("a mention is sent only while its name stays in the text, and posting says who was notified", async () => {
  const {doc, calls} = boot({comments: [], people: [{principal: "user:lee", label: "Lee"}], can_comment: true});
  await flush();
  doc.querySelector(".mv-comments__who").value = "user:lee";
  doc.querySelector(".mv-comments__add").click();
  const body = doc.querySelector(".mv-comments__body");
  assert.equal(body.value, "@Lee ");
  assert.match(doc.querySelector(".mv-comments__mentioned").textContent, /Will notify: Lee/);
  body.value += "can we keep this blocked?";
  doc.querySelector(".mv-comments__form").dispatchEvent(new doc.defaultView.Event("submit", {cancelable: true}));
  await flush();
  const post = calls.find(c => c.opts.method === "POST");
  assert.deepEqual(JSON.parse(JSON.stringify(post.opts.body)), {kind: "policy", id: "tools", body: "@Lee can we keep this blocked?", mentions: ["user:lee"]});
  assert.match(doc.querySelector(".mv-comments__status").textContent, /Comment posted\. 1 person was notified\./);
  assert.equal(doc.querySelectorAll(".mv-comments__item").length, 1);
  // A name removed from the text is not mentioned.
  doc.querySelector(".mv-comments__who").value = "user:lee";
  doc.querySelector(".mv-comments__add").click();
  body.value = "never mind";
  doc.querySelector(".mv-comments__form").dispatchEvent(new doc.defaultView.Event("submit", {cancelable: true}));
  await flush();
  const second = calls.filter(c => c.opts.method === "POST")[1];
  assert.deepEqual([...second.opts.body.mentions], []);
});

test("the author deletes a comment with a 10-second undo", async () => {
  const {doc, calls} = boot({comments: [{id: 4, author: "dana", mine: true, body: "Old note", created_at: 1, mentions: []},
    {id: 5, author: "lee", mine: false, body: "Reply", created_at: 2, mentions: []}], people: [], can_comment: true});
  await flush();
  const items = doc.querySelectorAll(".mv-comments__item");
  assert.equal(items[1].querySelector("button"), null, "only your own comments can be deleted");
  items[0].querySelector("button").click();
  assert.equal(items[0].hidden, true);
  const undo = doc.querySelector(".mv-toast--undo button");
  assert.ok(undo, "an undo is offered");
  undo.click();
  await flush();
  assert.equal(items[0].hidden, false);
  assert.equal(calls.some(c => String(c.url).startsWith("/api/v1/comments/4")), false, "nothing was deleted");
  assert.equal(doc.querySelector(".mv-comments__who").disabled, true, "nobody else to mention");
});
