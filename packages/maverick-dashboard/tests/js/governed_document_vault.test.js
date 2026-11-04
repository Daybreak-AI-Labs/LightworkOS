// Run with: node --test packages/maverick-dashboard/tests/js/governed_document_vault.test.js
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell: loadShell} = require("./_shell");

const base = path.join(__dirname, "../../maverick_dashboard");
const template = fs.readFileSync(path.join(base, "templates/governed_document_vault.html"), "utf8");
const source = fs.readFileSync(path.join(base, "static/lightwork-governed-document-vault.js"), "utf8");
const body = template.slice(template.indexOf('<div class="document-vault-shell"'), template.lastIndexOf("{% endblock %}"))
  .replace("{{ vault_api_base }}", "/api/v1/administration/document-vault")
  .replace("{{ access_api_base }}", "/api/v1/administration/document-access")
  .replace(/\{%[^%]*%\}/g, "").replace(/\{\{\s*hero\([^}]*\}\}/, "").replace(/\{\{[^}]*\}\}/g, "true");

const DOC = { document_ref: "doc1", product_area: "privacy_automation", record_type: "incident_attachment",
  safe_display_name: "Breach notice.pdf", media_type: "application/pdf", byte_size: 2048, authority_revision: 3,
  state: "active", created_at: 1800000000, retained_until: null };

function fixture(t, { confirm = true } = {}) {
  const dom = new JSDOM(`<main>${body}</main>`, { url: "https://lightwork.test/administration/document-vault", runScripts: "outside-only" });
  t.after(() => dom.window.close());
  const w = dom.window;
  const calls = [];
  w.mvConfirm = async () => confirm;
  w.URL.createObjectURL = () => "blob:x";
  w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () { calls.push({ key: "SAVE " + this.download }); };
  w.fetch = async (url, options = {}) => {
    const key = (options.method || "GET") + " " + url;
    calls.push({ key, body: typeof options.body === "string" ? JSON.parse(options.body) : undefined });
    const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
    if (key.endsWith("/document-vault/status")) return json({ enabled: true, configured: true, ready: true, limits: { max_document_bytes: 10485760, allowed_media_types: ["application/pdf"] } });
    if (key.includes("/documents?limit=")) return json({ items: [DOC], count: 1 });
    if (key.endsWith("/revoke")) return json({ ...DOC, state: "revoked", authority_revision: 4 });
    if (key.endsWith("/document-access/tokens")) return json({ download_token: "lwddt_v1_" + "a".repeat(43) }, 201);
    if (key.endsWith("/tokens/redeem")) return json({ delivery_grant: "lwdvg_v1_" + "b".repeat(43) });
    if (key.endsWith("/delivery")) return new Response("abc", { status: 200, headers: { "content-length": "3" } });
    return json({ detail: "document_vault_conflict" }, 409);
  };
  loadShell(w);
  w.eval(source);
  const settle = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => setImmediate(r)); };
  return { w, calls, settle, $: (id) => w.document.getElementById(id) };
}

test("documents load as rows with plain labels and action buttons", async (t) => {
  const h = fixture(t);
  await h.settle();
  const text = h.$("document-vault-documents").textContent;
  assert.match(text, /Breach notice\.pdf/);
  assert.match(text, /Privacy/);
  assert.match(text, /Incident attachment/);
  assert.match(text, /Shared/);
  const labels = [...h.$("document-vault-documents").querySelectorAll("button")].map((b) => b.textContent);
  assert.deepEqual(labels, ["Download", "Share one-time code", "Stop sharing"]);
  assert.doesNotMatch(text, /doc1|incident_attachment|privacy_automation/);
});

test("stop sharing confirms first and sends the row's version", async (t) => {
  const h = fixture(t, { confirm: false });
  await h.settle();
  const stop = () => [...h.$("document-vault-documents").querySelectorAll("button")].find((b) => b.textContent === "Stop sharing");
  stop().click();
  await h.settle();
  assert.equal(h.calls.some((c) => c.key.endsWith("/revoke")), false);
  h.w.mvConfirm = async () => true;
  stop().click();
  await h.settle();
  const revoke = h.calls.find((c) => c.key.endsWith("/documents/doc1/revoke"));
  assert.deepEqual(revoke.body, { expected_revision: 3 });
  assert.match(h.$("document-vault-operation-status").textContent, /Sharing stopped for Breach notice\.pdf/);
});

test("download creates a one-time code, uses it and saves the file without anything typed", async (t) => {
  const h = fixture(t);
  await h.settle();
  [...h.$("document-vault-documents").querySelectorAll("button")].find((b) => b.textContent === "Download").click();
  await h.settle();
  const keys = h.calls.map((c) => c.key);
  assert.ok(keys.some((k) => k.endsWith("/document-access/tokens")));
  assert.ok(keys.some((k) => k.endsWith("/tokens/redeem")));
  assert.ok(keys.includes("SAVE Breach notice.pdf"));
  const mint = h.calls.find((c) => c.key.endsWith("/document-access/tokens"));
  assert.equal(mint.body.document_ref, "doc1");
  assert.equal(mint.body.max_uses, 1);
  assert.match(h.$("document-vault-operation-status").textContent, /Downloaded Breach notice\.pdf/);
});
