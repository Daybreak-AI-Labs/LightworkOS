// Run with: node --test packages/maverick-dashboard/tests/js/public_chat_admin.test.js
// The Channels page's public chat section: the confirmation gates for rotating and
// stopping a website, the one-time key, text-only recent messages, and the plain
// sentence a failed request shows (never the word "true").
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM, VirtualConsole } = require("jsdom");

const staticDir = path.resolve(__dirname, "../../maverick_dashboard/static");
const uiSource = fs.readFileSync(path.join(staticDir, "lightwork-ui.js"), "utf8");
const adminSource = fs.readFileSync(path.join(staticDir, "lightwork-public-chat-admin.js"), "utf8");
// The markup is the real partial with its template tags removed, so a renamed id fails here.
const partial = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/templates/_public_chat_admin.html"), "utf8")
  .replace(/{%[^%]*%}/g, "")
  .replace(/{{\s*name\s*\|\s*humanize\s*}}/g, "Finance AP")
  .replace(/{{\s*name\s*}}/g, "finance_ap")
  .replace(/<script[^>]*><\/script>/g, "");
const fixture = '<div id="mv-toasts"></div><div id="mv-toasts-alert"></div>' + partial +
  '<dialog id="mv-confirm"><p id="mv-confirm-msg"></p>' +
  '<button type="button" id="mv-confirm-ok">OK</button>' +
  '<button type="button" id="mv-confirm-cancel">Cancel</button></dialog>';

const API = "/api/v1/public-chat/sites";
const SITE = {
  id: "site-1", display_name: "Acme shop", origins: ["https://shop.example"], specialist: "finance_ap",
  state: "active", daily_cap_dollars: 5, spent_today_dollars: 0, messages_per_session: 20,
  messages_per_minute: 6, messages_per_client_per_day: 200, retention_days: 30, greeting: "",
};
const tick = () => new Promise((resolve) => setTimeout(resolve, 5));
const pause = async () => { for (let i = 0; i < 10; i += 1) await tick(); };
async function settle(predicate) {
  for (let i = 0; i < 200 && !predicate(); i += 1) await tick();
}

function json(status, body) {
  const text = JSON.stringify(body);
  return { ok: status < 400, status, redirected: false, headers: { get: () => null },
    text: async () => text, json: async () => body };
}
function html(status, text) {
  return { ok: status < 400, status, redirected: false, headers: { get: () => null },
    text: async () => text, json: async () => { throw new SyntaxError("Unexpected token <"); } };
}

// Routes by "METHOD /path". Any other request is a 404, so a stray call shows up in the calls list.
function serve(extra) {
  const table = Object.assign({ [`GET ${API}`]: () => json(200, { sites: [SITE] }) }, extra);
  return (method, url) => {
    const handler = table[`${method} ${url.split("?")[0]}`];
    return handler ? handler(url) : json(404, { detail: "not found" });
  };
}

function load(route) {
  const console_ = new VirtualConsole();
  const dom = new JSDOM(`<!doctype html><body>${fixture}</body>`, {
    url: "https://lightwork.test/channels", runScripts: "outside-only", virtualConsole: console_ });
  const w = dom.window;
  w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  // jsdom has no modal dialog: a stand-in that keeps the same open state.
  const dialog = w.document.getElementById("mv-confirm");
  let isOpen = false;
  Object.defineProperty(dialog, "open", { configurable: true, get: () => isOpen });
  dialog.showModal = () => { isOpen = true; };
  dialog.close = () => { isOpen = false; };
  const calls = [];
  w.fetch = async (url, options) => {
    const method = String((options && options.method) || "GET").toUpperCase();
    calls.push({ method, url: String(url), body: options && options.body });
    return route(method, String(url));
  };
  const copied = [];
  w.eval(uiSource);
  w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
  w.mvCopy = (text) => copied.push(text);
  w.eval(adminSource);
  return { w, doc: w.document, dialog, calls, copied };
}

function button(doc, label) {
  const found = [...doc.querySelectorAll("button")].find((node) => node.getAttribute("aria-label") === label);
  assert.ok(found, `button: ${label}`);
  return found;
}
const posts = (calls) => calls.filter((call) => call.method === "POST");

test("a failed load with a non-JSON body shows the page's own sentence, never the word true", async () => {
  const { doc, calls } = load(serve({ [`GET ${API}`]: () => html(502, "<html>Bad gateway</html>") }));
  await settle(() => calls.length > 0 && doc.getElementById("pc-status").textContent !== "");
  const status = doc.getElementById("pc-status").textContent;
  assert.equal(status, "Websites could not be loaded. Reload this page to try again.");
  assert.doesNotMatch(doc.getElementById("pc-sites").textContent, /\btrue\b/);
});

test("a failed key rotation with a non-JSON body shows a plain sentence and shows no key", async () => {
  const { doc, dialog, calls } = load(serve({
    [`POST ${API}/site-1/rotate`]: () => html(502, "<html>Bad gateway</html>"),
  }));
  await settle(() => doc.querySelector("#pc-sites table"));
  button(doc, "Rotate key for Acme shop").click();
  await settle(() => dialog.open);
  doc.getElementById("mv-confirm-ok").click();
  await settle(() => posts(calls).length > 0 && doc.getElementById("pc-status").textContent !== "");
  await pause();
  assert.equal(doc.getElementById("pc-status").textContent, "That did not work. Try again.");
  assert.equal(doc.getElementById("pc-secret").hidden, true);
});

test("rotating a key waits for confirmation, cancelling sends nothing, and confirming shows the key once", async () => {
  const { doc, dialog, calls, copied } = load(serve({
    [`POST ${API}/site-1/rotate`]: () => json(200, { site_id: "site-1", publishable_key: "lwpk_rotated", shown_once: true }),
  }));
  await settle(() => doc.querySelector("#pc-sites table"));
  button(doc, "Rotate key for Acme shop").click();
  await settle(() => dialog.open);
  assert.match(doc.getElementById("mv-confirm-msg").textContent, /current key stops working/);
  doc.getElementById("mv-confirm-cancel").click();
  await pause();
  assert.equal(posts(calls).length, 0, "cancel sends nothing");
  assert.equal(doc.getElementById("pc-secret").hidden, true);

  button(doc, "Rotate key for Acme shop").click();
  await settle(() => dialog.open);
  doc.getElementById("mv-confirm-ok").click();
  await settle(() => doc.getElementById("pc-key").textContent === "lwpk_rotated");
  assert.equal(posts(calls).length, 1, "confirm sends one rotation");
  assert.equal(doc.getElementById("pc-secret").hidden, false);
  assert.match(doc.getElementById("pc-snippet").textContent, /data-key="lwpk_rotated"/);

  doc.getElementById("pc-copy-key").click();
  assert.deepEqual(copied, ["lwpk_rotated"]);
  doc.getElementById("pc-secret-done").click();
  assert.equal(doc.getElementById("pc-secret").hidden, true);
  assert.equal(doc.getElementById("pc-key").textContent, "", "the key is cleared from the page");
  assert.equal(doc.getElementById("pc-snippet").textContent, "", "the website code is cleared too");
  doc.getElementById("pc-copy-key").click();
  assert.deepEqual(copied, ["lwpk_rotated"], "a cleared key cannot be copied");
});

test("stopping a website waits for confirmation, cancelling sends nothing, and confirming stops it once", async () => {
  const { doc, dialog, calls } = load(serve({
    [`POST ${API}/site-1/revoke`]: () => json(200, { site_id: "site-1", state: "revoked" }),
  }));
  await settle(() => doc.querySelector("#pc-sites table"));
  button(doc, "Stop website for Acme shop").click();
  await settle(() => dialog.open);
  assert.match(doc.getElementById("mv-confirm-msg").textContent, /stored message for it is deleted/);
  doc.getElementById("mv-confirm-cancel").click();
  await pause();
  assert.equal(posts(calls).length, 0, "cancel sends nothing");

  button(doc, "Stop website for Acme shop").click();
  await settle(() => dialog.open);
  doc.getElementById("mv-confirm-ok").click();
  await settle(() => posts(calls).length === 1);
  await pause();
  assert.equal(posts(calls).length, 1, "confirm stops the website once");
  assert.match(posts(calls)[0].url, /\/site-1\/revoke$/);
});

test("recent messages are text only, newest first, and ask for at most 50", async () => {
  const messages = [
    { role: "visitor", text: "first question", created_at: 1_700_000_000 },
    { role: "assistant", text: '<img src="x" onerror="alert(1)"> an answer', created_at: 1_700_000_060 },
    { role: "visitor", text: "third question", created_at: 1_700_000_120 },
  ];
  const { doc, calls } = load(serve({
    [`GET ${API}/site-1/transcripts`]: () => json(200, { site_id: "site-1", messages }),
  }));
  await settle(() => doc.querySelector("#pc-sites table"));
  button(doc, "Recent messages for Acme shop").click();
  await settle(() => doc.querySelectorAll("#pc-messages-body li").length === 3);
  const items = [...doc.querySelectorAll("#pc-messages-body li")];
  assert.equal(items.length, 3);
  assert.match(items[0].textContent, /third question/);
  assert.match(items[2].textContent, /first question/);
  assert.equal(doc.querySelectorAll("#pc-messages-body img").length, 0, "markup is never rendered");
  assert.match(items[1].textContent, /<img src="x" onerror="alert\(1\)"> an answer/);
  assert.ok(calls.some((call) => call.url === `${API}/site-1/transcripts?limit=50`));
});

test("a new website shows its key once with the website code, and the form closes", async () => {
  const { doc, calls } = load(serve({
    [`POST ${API}`]: () => json(201, { site: SITE, publishable_key: "lwpk_created", shown_once: true }),
  }));
  await settle(() => doc.querySelector("#pc-sites table"));
  doc.getElementById("pc-new").click();
  const form = doc.getElementById("pc-create");
  assert.equal(form.hidden, false);
  form.elements.display_name.value = "Acme shop";
  form.elements.origins.value = "https://shop.example";
  form.elements.daily_cap_dollars.value = "5";
  form.dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));
  await settle(() => doc.getElementById("pc-key").textContent === "lwpk_created");
  assert.equal(doc.getElementById("pc-key").textContent, "lwpk_created");
  assert.match(doc.getElementById("pc-snippet").textContent, /data-key="lwpk_created"/);
  assert.equal(form.hidden, true);
  const sent = posts(calls)[0];
  assert.equal(JSON.parse(sent.body).origins[0], "https://shop.example");
});
