// Run with: node --test packages/maverick-dashboard/tests/js/lightwork_ui_shared_helpers.test.js
"use strict";
// Shared helpers in lightwork-ui.js that pages use instead of their own
// copies: the browser chrome colour follows the theme.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-ui.js"), "utf8");

function load(head = "", body = "") {
  const dom = new JSDOM(`<!doctype html><html><head>${head}</head><body class="theme-dark">
    <div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content">${body}</main></body></html>`,
  { url: "https://lightwork.test/overview", runScripts: "outside-only" });
  dom.window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  dom.window.eval(source);
  return dom.window;
}

test("switching the theme moves the browser chrome colour to the new canvas", () => {
  const w = load(`<meta name="theme-color" content="#04050A">
    <style>body.theme-dark { background-color: rgb(4, 5, 10); } body.theme-light { background-color: rgb(244, 246, 250); }</style>`);
  w.mvApplyDisplayPreference("theme", "light");
  assert.equal(w.document.querySelector('meta[name="theme-color"]').getAttribute("content"), "rgb(244, 246, 250)");
  w.mvApplyDisplayPreference("density", "compact");   // other preferences leave it alone
  assert.equal(w.document.querySelector('meta[name="theme-color"]').getAttribute("content"), "rgb(244, 246, 250)");
  w.close();
});

test("without a canvas colour the server's theme colour stays", () => {
  const w = load('<meta name="theme-color" content="#04050A">');
  w.mvApplyDisplayPreference("theme", "light");
  assert.equal(w.document.querySelector('meta[name="theme-color"]').getAttribute("content"), "#04050A");
  w.close();
});

// ---- mvFetchJSON: one JSON request helper ---------------------------------
function respond(status, body, headers = {}) {
  const text = body === undefined ? "" : (typeof body === "string" ? body : JSON.stringify(body));
  return { ok: status >= 200 && status < 300, status, headers: new Map(Object.entries(headers)),
    text: async () => text, json: async () => JSON.parse(text) };
}

test("mvFetchJSON sends JSON with the page's cookies and returns the parsed body", async () => {
  const w = load();
  const calls = [];
  w.fetch = async (url, options) => { calls.push({ url, options }); return respond(200, { saved: true }); };
  const result = await w.mvFetchJSON("/api/v1/things", { method: "POST", body: { name: "Q3" } }, "save the thing");
  assert.deepEqual(JSON.parse(JSON.stringify(result)), { saved: true });
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.credentials, "same-origin");
  assert.equal(calls[0].options.body, JSON.stringify({ name: "Q3" }));
  assert.equal(calls[0].options.headers["Content-Type"], "application/json");
  assert.equal(calls[0].options.headers.Accept, "application/json");
  w.close();
});

test("mvFetchJSON passes strings and form data through and reads an empty body as null", async () => {
  const w = load();
  const seen = [];
  w.fetch = async (url, options) => { seen.push(options); return respond(204); };
  assert.equal(await w.mvFetchJSON("/a", { method: "POST", body: "raw=1", headers: { "Content-Type": "text/plain" } }), null);
  const form = new w.FormData(); form.append("file", "x");
  await w.mvFetchJSON("/b", { method: "POST", body: form });
  assert.equal(seen[0].body, "raw=1");
  assert.equal(seen[0].headers["Content-Type"], "text/plain");
  assert.equal(seen[1].body, form);
  assert.equal(seen[1].headers["Content-Type"], undefined);
  w.close();
});

test("a body sent with its own non-JSON type goes as is", async () => {
  const w = load();
  const seen = [];
  w.fetch = async (url, options) => { seen.push(options); return respond(200, { fingerprint: "ab" }); };
  const file = { name: "tool", size: 5 };  // a file as a page holds it
  await w.mvFetchJSON("/fp", { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file });
  assert.equal(seen[0].body, file);
  w.close();
});

test("a failed request rejects with plain words from mvErrorText, never the server's internals", async () => {
  const w = load();
  w.fetch = async () => respond(500, { detail: "Traceback (most recent call last): KeyError 'tenant'" });
  await assert.rejects(w.mvFetchJSON("/api/v1/x", {}, "load the report"), (error) => {
    assert.equal(error.message, "Could not load the report. Something went wrong on our side. Try again in a minute.");
    assert.equal(error.status, 500);
    assert.doesNotMatch(error.message, /Traceback|500|tenant/);
    return true;
  });
  w.fetch = async () => respond(403, { detail: "off" }, { "X-Lightwork-Reason": "feature-off", "X-Lightwork-Feature-Label": "Ekko" });
  await assert.rejects(w.mvFetchJSON("/api/v1/x", {}, "open Ekko"), (error) => {
    assert.match(error.message, /^Could not open Ekko\. Ekko is turned off\./);
    assert.ok(w.mvFeatureOff(error), "the error still tells a page the feature is off");
    return true;
  });
  w.fetch = async () => { throw new TypeError("Failed to fetch"); };
  await assert.rejects(w.mvFetchJSON("/api/v1/x", {}, "save"), (error) => {
    assert.equal(error.message, "Could not save. Lightwork could not be reached. Check your connection and try again.");
    assert.equal(error.status, 0);
    return true;
  });
  w.close();
});

test("a business error keeps its authored message and its payload for mvRenderError", async () => {
  const w = load();
  const detail = { schema: "lightwork.error.v1", code: "limit.too_low", message: "Pick a limit above today's spend." };
  w.fetch = async () => respond(422, { detail });
  await assert.rejects(w.mvFetchJSON("/api/v1/limits", { method: "PUT", body: {} }, "save the limit"), (error) => {
    assert.equal(error.message, "Pick a limit above today's spend.");
    assert.equal(error.payload.detail.code, "limit.too_low");
    return true;
  });
  w.close();
});

// ---- mvStatus: one inline status line --------------------------------------
test("mvStatus writes the text at once and styles errors", () => {
  const w = load("", '<p id="s"></p><p id="own" aria-live="assertive"></p>');
  const line = w.document.getElementById("s");
  w.mvStatus(line, "Saving…");
  assert.equal(line.textContent, "Saving…");
  assert.equal(line.classList.contains("mv-status--error"), false);
  w.mvStatus(line, "Could not save. Try again.", { error: true });
  assert.equal(line.textContent, "Could not save. Try again.");
  assert.equal(line.classList.contains("mv-status--error"), true);
  w.mvStatus(line, "");
  assert.equal(line.textContent, "");
  assert.equal(line.classList.contains("mv-status--error"), false);
  const own = w.document.getElementById("own");   // a page's own live region is left as it is
  w.mvStatus(own, "Done", { error: true });
  assert.equal(own.getAttribute("role"), null);
  assert.equal(own.textContent, "Done");
  assert.equal(w.mvStatus(null, "x"), null);
  w.close();
});

// A live region that appears, or gets its role, in the same moment as its
// first words is often not read out at all. mvStatus never makes the line
// itself a fresh region: it speaks through two regions that exist before
// any message (base.html, or made once here), and writes into them a moment
// after clearing them, so even the first message, and a repeat of the same
// words, is a change to a region the screen reader already knows.
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("the first message into a brand-new status line is announced through a region that already existed", async () => {
  const w = load("", '<p id="s"></p>');
  const line = w.document.getElementById("s");
  w.mvStatus(line, "Saved.");
  const polite = w.document.getElementById("mv-announce"), alert = w.document.getElementById("mv-announce-alert");
  assert.ok(polite && alert, "both announcers exist before the first words are written into them");
  assert.equal(polite.getAttribute("aria-live"), "polite");
  assert.equal(alert.getAttribute("aria-live"), "assertive");
  assert.equal(line.textContent, "Saved.", "the words show at once");
  assert.equal(line.hasAttribute("role") || line.hasAttribute("aria-live"), false, "the line is not made a fresh live region");
  assert.equal(polite.textContent, "", "the announcer is cleared first");
  await wait(150);
  assert.equal(polite.textContent, "Saved.");
  w.mvStatus(line, "Saved.");   // the same words again are spoken again
  assert.equal(polite.textContent, "");
  await wait(150);
  assert.equal(polite.textContent, "Saved.");
  w.mvStatus(line, "Could not save. Try again.", { error: true });
  await wait(150);
  assert.equal(alert.textContent, "Could not save. Try again.", "an error is spoken at once");
  assert.equal(polite.textContent, "", "and the polite region does not repeat it");
  w.close();
});

test("only the latest of quick messages is spoken, and clearing the line speaks nothing", async () => {
  const w = load("", '<p id="s"></p>');
  const line = w.document.getElementById("s");
  w.mvStatus(line, "Saving…");
  w.mvStatus(line, "Saved.");
  const polite = w.document.getElementById("mv-announce");
  await wait(150);
  assert.equal(polite.textContent, "Saved.");
  w.mvStatus(line, "");
  await wait(150);
  assert.equal(polite.textContent, "Saved.", "an empty line is not announced");
  w.close();
});

test("announcers already in the page (base.html) are reused, not duplicated", async () => {
  const w = load("", '<div id="mv-announce" class="sr-only" role="status" aria-live="polite" aria-atomic="true"></div><p id="s"></p>');
  assert.equal(w.document.querySelectorAll("#mv-announce").length, 1);
  w.mvStatus(w.document.getElementById("s"), "Done.");
  await wait(150);
  assert.equal(w.document.querySelector("#mv-announce").textContent, "Done.");
  w.close();
});

// ---- mvFetchJSON options for pages that guard access and waiting --------
test("timeout aborts a request that takes too long, with mvErrorText's words", async () => {
  const w = load();
  let seen;
  w.fetch = (url, options) => new Promise((resolve, reject) => {
    seen = options.signal;
    options.signal.addEventListener("abort", () => reject(new w.DOMException("The operation was aborted.", "AbortError")));
  });
  await assert.rejects(w.mvFetchJSON("/slow", { timeout: 20 }, "load the report"), (error) => {
    assert.equal(error.name, "AbortError");
    assert.equal(error.timedOut, true);
    assert.equal(error.message, "Could not load the report. It took too long. Try again.");
    return true;
  });
  assert.equal(seen.aborted, true);
  w.close();
});

test("the deadline holds even when a request ignores its abort, with the page's own words if it has them", async () => {
  const w = load();
  w.fetch = () => new Promise(() => {});
  await assert.rejects(w.mvFetchJSON("/stuck", { timeout: 20, messages: { timeout: "The request timed out. Refresh to check." } }, "save"),
    (error) => { assert.equal(error.message, "The request timed out. Refresh to check."); assert.equal(error.timedOut, true); assert.equal(error.name, "AbortError"); return true; });
  w.close();
});

test("a page's own signal still cancels the request, and a finished request clears its timer", async () => {
  const w = load();
  const owner = new w.AbortController();
  w.fetch = (url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener("abort", () => reject(new w.DOMException("aborted", "AbortError")));
  });
  const pending = w.mvFetchJSON("/x", { signal: owner.signal, timeout: 60000 }, "load");
  owner.abort();
  await assert.rejects(pending, (error) => { assert.equal(error.name, "AbortError"); assert.equal(error.timedOut, undefined); return true; });
  w.fetch = async (url, options) => { assert.equal(options.timeout, undefined, "options of ours are not sent to fetch"); return respond(200, { ok: 1 }); };
  assert.deepEqual(JSON.parse(JSON.stringify(await w.mvFetchJSON("/y", { timeout: 50 }, "load"))), { ok: 1 });
  w.close();
});

test("onAccess runs before the rejection when access is gone (401, 403, a redirect, or the page's own statuses)", async () => {
  const w = load();
  const lost = [];
  const onAccess = (error) => lost.push(error.status);
  let parsed = false;
  w.fetch = async () => ({ ok: false, status: 403, headers: new Map(), redirected: false,
    text: async () => { parsed = true; return "<html>sign in</html>"; }, json: async () => { parsed = true; throw new SyntaxError("html"); } });
  await assert.rejects(w.mvFetchJSON("/a", { onAccess: (error) => { assert.equal(parsed, false, "cleared before anything is read"); onAccess(error); } }, "open the list"), /You do not have permission/);
  assert.equal(parsed, false, "the refusal's body is never read");
  w.fetch = async () => respond(401, {});
  await assert.rejects(w.mvFetchJSON("/a", { onAccess }, "open the list"), /Sign in again/);
  w.fetch = async () => Object.assign(respond(200, {}), { redirected: true });
  await assert.rejects(w.mvFetchJSON("/a", { onAccess }, "open the list"), (error) => { assert.equal(error.accessChanged, true); return true; });
  w.fetch = async () => respond(404, {});
  await assert.rejects(w.mvFetchJSON("/a", { onAccess }, "open the list"));
  await assert.rejects(w.mvFetchJSON("/a", { onAccess, accessStatuses: [401, 403, 404] }, "open the list"));
  w.fetch = async () => respond(500, {});
  await assert.rejects(w.mvFetchJSON("/a", { onAccess }, "open the list"));
  assert.deepEqual(lost, [403, 401, 200, 404]);
  w.close();
});

test("a refusal body that is not read is released, so the page can go quiet", async () => {
  const w = load();
  const released = [];
  w.fetch = async (url) => ({ ok: false, status: 403, headers: new Map(), body: { cancel: async () => { released.push(url); } } });
  await assert.rejects(w.mvFetchJSON("/gone", { onAccess() {} }, "load"));
  await assert.rejects(w.mvFetchJSON("/unreadable", {}, "load"));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(released, ["/gone", "/unreadable"]);
  w.close();
});

test("plainDetail shows a server sentence written for people, and never its internals", async () => {
  const w = load();
  w.fetch = async () => respond(422, { detail: "Pick a date after today." });
  await assert.rejects(w.mvFetchJSON("/a", { plainDetail: true }, "save"), { message: "Pick a date after today." });
  await assert.rejects(w.mvFetchJSON("/a", {}, "save"), { message: "Could not save. Some of the details need fixing. Check what you entered and try again." });
  w.fetch = async () => respond(422, { detail: "expected_revision mismatch in tenant_id" });
  await assert.rejects(w.mvFetchJSON("/a", { plainDetail: true }, "save"), { message: "Could not save. Some of the details need fixing. Check what you entered and try again." });
  w.close();
});

test("messages keep a page's own sentence for a status it knows more about", async () => {
  const w = load();
  const messages = { 409: "This changed since the list loaded. Refresh the list and try again." };
  w.fetch = async () => respond(409, { detail: "revision 4 != 5" });
  await assert.rejects(w.mvFetchJSON("/a", { messages }, "save"), { message: messages[409], status: 409 });
  w.fetch = async () => respond(409, { detail: "Pick a later date." });
  await assert.rejects(w.mvFetchJSON("/a", { messages, plainDetail: true }, "save"), { message: "Pick a later date." }, "a plain server sentence still comes first");
  w.fetch = async () => respond(500, {});
  await assert.rejects(w.mvFetchJSON("/a", { messages }, "save"), { message: "Could not save. Something went wrong on our side. Try again in a minute." });
  w.close();
});

test("messages.offline keeps a page's own sentence when the server cannot be reached", async () => {
  const w = load();
  const messages = { offline: "Could not reach the server — check your connection and try again." };
  w.fetch = async () => { throw new TypeError("Failed to fetch"); };
  await assert.rejects(w.mvFetchJSON("/a", { messages }, "save"), { message: messages.offline, status: 0, name: "TypeError" });
  const plain = await w.mvFetchJSON("/a", {}, "save").catch((error) => error);
  assert.notEqual(plain.message, messages.offline, "without the option the shared sentence is used");
  assert.equal(plain.message, w.mvErrorText(new TypeError("Failed to fetch"), "save"));
  w.close();
});

test("raw returns the response itself for a download, and still rejects plainly", async () => {
  const w = load();
  const file = respond(200, "csv,data");
  w.fetch = async () => file;
  assert.equal(await w.mvFetchJSON("/export", { raw: true }, "download"), file);
  w.fetch = async () => respond(500, { detail: "boom" });
  await assert.rejects(w.mvFetchJSON("/export", { raw: true }, "download the file"), { message: "Could not download the file. Something went wrong on our side. Try again in a minute." });
  w.close();
});

test("a success whose body cannot be read fails closed, without echoing it", async () => {
  const w = load();
  w.fetch = async () => respond(200, "<html>secret sign-in page</html>");
  await assert.rejects(w.mvFetchJSON("/a", {}, "load the list"), (error) => {
    assert.equal(error.message, "Could not load the list. Something went wrong. Try again.");
    assert.equal(error.status, 0);
    assert.equal(error.unreadable, true);
    assert.doesNotMatch(error.message, /secret/);
    return true;
  });
  // A page's own fake with only json() works the same way.
  w.fetch = async () => ({ ok: true, status: 200, headers: new Map(), json: async () => { throw new SyntaxError("bad"); } });
  await assert.rejects(w.mvFetchJSON("/a", {}, "load the list"), { status: 0 });
  w.fetch = async () => ({ ok: true, status: 204, headers: new Map(), json: async () => { throw new SyntaxError("empty"); } });
  assert.equal(await w.mvFetchJSON("/a", {}, "load the list"), null, "No Content is an empty success");
  w.close();
});

test("an unreachable server gives the same words whether the error or its cause is passed on", async () => {
  const w = load();
  w.fetch = async () => { throw new TypeError("Failed to fetch"); };
  const error = await w.mvFetchJSON("/x", {}, "save").catch((e) => e);
  assert.equal(w.mvErrorText(error, "save"), error.message);
  assert.equal(error.name, "TypeError");
  w.close();
});

test("serverDetail shows the server's own sentence as written, else the page's sentence", async () => {
  const w = load();
  const fallback = "The reply could not be checked. Read the original request before another attempt.";
  w.fetch = async () => respond(422, { detail: "Choose at most three reviewers." });
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: fallback }, "save"), { message: "Choose at most three reviewers.", status: 422 });
  w.fetch = async () => respond(422, { detail: [{ loc: ["body", "x"], msg: "field required" }] });
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: fallback }, "save"), { message: fallback }, "a structured detail is never shown");
  w.fetch = async () => respond(500, "<html>boom</html>");
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: fallback }, "save"), { message: fallback, status: 500 });
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: fallback, messages: { 500: "Try again in a minute." } }, "save"), { message: "Try again in a minute." }, "a page's sentence for the status comes before its fallback");
  w.close();
});

test("serverDetail reads a lost access's own sentence only after the page cleared, never a redirect's page", async () => {
  const w = load();
  const order = [];
  w.fetch = async () => ({ ok: false, status: 403, headers: new Map(), redirected: false,
    text: async () => { order.push("read"); return JSON.stringify({ detail: "Learning permission was removed." }); } });
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: "Unavailable.", onAccess: () => order.push("cleared") }, "load"),
    { message: "Learning permission was removed.", status: 403, accessChanged: true });
  assert.deepEqual(order, ["cleared", "read"]);
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: "Unavailable.", messages: { 403: "Sign in with current permission." }, onAccess() {} }, "load"),
    { message: "Sign in with current permission." }, "the page's own sentence for a lost access comes first");
  let read = false;
  w.fetch = async () => ({ ok: true, status: 200, headers: new Map(), redirected: true, text: async () => { read = true; return "<html>sign in</html>"; } });
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: "Unavailable.", onAccess() {} }, "load"), { message: "Unavailable." });
  assert.equal(read, false);
  w.close();
});

test("onContextChange clears private data when a 409 says the account or workspace changed", async () => {
  const w = load();
  const cleared = [];
  const onContextChange = (error) => cleared.push(error.message);
  w.fetch = async () => respond(409, { detail: "Your account or workspace changed. Reopen the page." });
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: "x", onContextChange }, "save"),
    { message: "Your account or workspace changed. Reopen the page.", status: 409, contextChanged: true });
  assert.deepEqual(cleared, ["Your account or workspace changed. Reopen the page."], "cleared before the rejection");
  w.fetch = async () => respond(409, { detail: "This record changed since you opened it." });
  await assert.rejects(w.mvFetchJSON("/a", { serverDetail: "x", onContextChange }, "save"), (error) => error.contextChanged === undefined);
  w.fetch = async () => respond(422, { detail: "Your account or workspace changed." });
  await assert.rejects(w.mvFetchJSON("/a", { onContextChange }, "save"));
  w.fetch = async () => respond(409, { detail: "The account, workspace or access changed." });
  await assert.rejects(w.mvFetchJSON("/a", { onContextChange, contextChange: /account, workspace or access changed/ }, "save"));
  assert.equal(cleared.length, 2, "only a 409 whose sentence matches clears");
  w.close();
});

test("messages.unreadable names a reply whose body cannot be read", async () => {
  const w = load();
  const unreadable = "The reply could not be confirmed. Entered work is kept.";
  w.fetch = async () => respond(200, "<html>x</html>");
  await assert.rejects(w.mvFetchJSON("/a", { messages: { unreadable } }, "save"), { message: unreadable, status: 0, unreadable: true });
  w.fetch = async () => respond(502, "<html>gateway</html>");
  await assert.rejects(w.mvFetchJSON("/a", { messages: { unreadable }, serverDetail: "x" }, "save"), { message: unreadable, status: 502 });
  w.close();
});

test("mvFetchJSON keeps headers given as a Headers object or name/value pairs", async () => {
  // Copied as a plain object, a Headers instance or a pair list lost every
  // header it carried (a page's context or idempotency key never arrived).
  const w = load();
  const seen = [];
  w.fetch = async (url, options) => { seen.push(options); return respond(200, {}); };
  await w.mvFetchJSON("/a", { method: "POST", body: { a: 1 }, headers: new w.Headers({ "X-Context": "abc" }) });
  await w.mvFetchJSON("/b", { method: "POST", body: { a: 1 }, headers: [["X-Context", "def"]] });
  assert.equal(seen[0].headers["x-context"], "abc");
  assert.equal(seen[1].headers["X-Context"], "def");
  for (const options of seen) {
    assert.equal(options.headers["Content-Type"], "application/json");
    assert.equal(options.headers.Accept, "application/json");
  }
  w.close();
});

test("mvFetchJSON adds no second content type beside a lower-case one", async () => {
  const w = load();
  const seen = [];
  w.fetch = async (url, options) => { seen.push(options); return respond(200, {}); };
  await w.mvFetchJSON("/a", { method: "POST", body: { a: 1 }, headers: { "content-type": "application/json", accept: "text/plain" } });
  assert.deepEqual(Object.keys(seen[0].headers).sort(), ["accept", "content-type"]);
  assert.equal(seen[0].body, JSON.stringify({ a: 1 }));
  w.close();
});

test("a workspace change in another tab reaches every page's clear-private-data listener", () => {
  // About 80 pages clear what they showed on workspace, account, authority,
  // draft or copilot context events, listening on document or window. Only
  // lightwork:context-changed was ever sent, so none of them cleared anything.
  const dom = new JSDOM(`<!doctype html><html><head><meta name="lightwork-workspace-tenant" content="owned"></head>
    <body><div id="mv-toasts"></div><div id="mv-toasts-alert"></div><main id="content"></main></body></html>`,
  { url: "https://lightwork.test/overview", runScripts: "outside-only" });
  const w = dom.window;
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  w.fetch = async () => ({ ok: true, status: 200 });
  w.eval(source);
  const names = ["lightwork:workspace-changed", "lightwork:account-context-changed", "lightwork:authority-changed",
    "lightwork:draft-context-changed", "lightwork:copilot-context-changed"];
  const heard = [];
  for (const name of names) {
    w.document.addEventListener(name, () => heard.push("document " + name));
    w.addEventListener(name, () => heard.push("window " + name));
  }
  w.dispatchEvent(new w.StorageEvent("storage", { key: "lightwork-workspace-changed", newValue: "other" }));
  assert.deepEqual(heard.sort(), names.flatMap(name => ["document " + name, "window " + name]).sort());
  w.close();
});
