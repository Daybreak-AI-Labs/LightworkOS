"use strict";
const {test} = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), {JSDOM} = require("jsdom");
const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/static/lightwork-provider-spending.js"), "utf8");
const template = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/provider_spending.html"), "utf8").replace(/{%[\s\S]*?%}/g, "")
  .replace("{{ provider_options | tojson }}", JSON.stringify([{name: "openai", label: "OpenAI"}, {name: "anthropic", label: "Anthropic (Claude)"}]));
const current = () => ({period: "2026-09-06", context: "account-a", expected_tenant: "tenant-a", available: true, isolated: false, shared: false, offset: 0, limit: 100,
  providers: [{provider: "openai", cap: 20, spent: 5, reserved: 3, remaining: 12, holds_total: 1, holds_next_offset: null, holds: [{id: "receipt-a", projected: 3, state: "unknown"}]}]});
const review = () => ({id: "PAR-review-a", kind: "hold", provider: "openai", period: "2026-09-06", receipt: "receipt-a", actual: 2, evidence: "Final receipt INV-7 verified", state: "prepared"});
async function fixture(reply) {
  const dom = new JSDOM(template, {url: "https://lightwork.example/provider-spending", runScripts: "outside-only"}), {window} = dom, calls = [];
  window.fetch = async (url, options = {}) => { calls.push({url, ...options}); return reply(url, options, calls); };
  const el = id => window.document.getElementById("spend-" + id);
  const settle = async () => { for (let i = 0; i < 15; i++) await new Promise(done => setImmediate(done)); };
  const submit = id => el(id).dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  window.eval(source); await settle();
  return {window, el, calls, settle, submit};
}
const response = value => new Response(JSON.stringify(value), {headers: {"Content-Type": "application/json"}});
test("real spending controller binds review and requires separate confirmation before exact apply", async t => {
  const ui = await fixture((url, options) => response(url.endsWith("/hold-review") ? review() : url.endsWith("/apply") ? {...review(), state: "completed"} : current()));
  t.after(() => ui.window.close());
  ui.el("actual").value = "2"; ui.el("evidence").value = review().evidence; ui.submit("hold-form"); await ui.settle();
  assert.equal(ui.calls.filter(call => call.url.endsWith("/apply")).length, 0);
  assert.match(ui.el("review-detail").textContent, /OpenAI .* settle this request at/); assert.doesNotMatch(ui.el("review-detail").textContent, /PAR-|receipt-a/);
  assert.equal(ui.el("apply").disabled, true);
  ui.el("confirm").checked = true; ui.el("confirm").dispatchEvent(new ui.window.Event("change")); ui.el("apply").click(); await ui.settle();
  const apply = ui.calls.find(call => call.url.endsWith("/apply"));
  assert.deepEqual(JSON.parse(apply.body), {review: "PAR-review-a", confirm: true});
  assert.equal(apply.headers["X-Lightwork-Spending-Context"], "account-a"); assert.equal(apply.headers["X-Lightwork-Expected-Tenant"], "tenant-a");
  assert.match(ui.el("status").textContent, /Correction completed/); assert.equal(ui.window.sessionStorage.length, 0);
});
for (const status of [401, 403, 409]) test(`HTML ${status} clears private balances, evidence and mutation controls`, async t => {
  const ui = await fixture((url, options) => options.method ? new Response("<html>session changed</html>", {status}) : response(current()));
  t.after(() => ui.window.close());
  ui.el("actual").value = "2"; ui.el("evidence").value = "Private synthetic receipt reference"; ui.submit("hold-form"); await ui.settle();
  assert.equal(ui.el("balances").textContent, ""); assert.equal(ui.el("evidence").value, ""); assert.equal(ui.el("hold").options.length, 0);
  assert.equal(ui.el("apply").disabled, true); assert.equal(ui.el("diagnostics").disabled, true); assert.equal(ui.el("refresh").disabled, false);
});
test("failed application retains exact review for refresh and never retries automatically", async t => {
  const ui = await fixture((url) => url.endsWith("/apply") ? new Response("storage unavailable", {status: 503}) : response(url.includes("/review/") ? {...review(), state: "applying"} : url.endsWith("/hold-review") ? review() : current()));
  t.after(() => ui.window.close());
  ui.el("actual").value = "2"; ui.el("evidence").value = review().evidence; ui.submit("hold-form"); await ui.settle();
  ui.el("confirm").checked = true; ui.el("confirm").dispatchEvent(new ui.window.Event("change")); ui.el("apply").click(); await ui.settle();
  assert.equal(ui.calls.filter(call => call.url.endsWith("/apply")).length, 1);
  ui.el("refresh").click(); await ui.settle();
  assert.ok(ui.calls.some(call => call.url.endsWith("/review/PAR-review-a")));
  assert.match(ui.el("status").textContent, /interrupted/); assert.equal(ui.el("confirm").checked, false);
  assert.equal(ui.calls.filter(call => call.url.endsWith("/apply")).length, 1);
});
test("old periods and paginated reservations use real filters and preserve explicit selection", async t => {
  const ui = await fixture(url => { const value = current(); value.offset = new URL(url, "https://lightwork.example").searchParams.get("offset") === "100" ? 100 : 0;
    value.providers[0].holds_total = 201; value.providers[0].holds_next_offset = value.offset + 100; return response(value); });
  t.after(() => ui.window.close()); ui.el("period").value = "2025-01"; ui.el("provider").value = "openai"; ui.el("load-period").click(); await ui.settle();
  ui.el("next").click(); await ui.settle();
  const reads = ui.calls.filter(call => call.url.includes("?offset="));
  assert.match(reads.at(-1).url, /offset=100/); assert.match(reads.at(-1).url, /period=2025-01/); assert.match(reads.at(-1).url, /provider=openai/);
  assert.match(ui.el("page").textContent, /of 201 unresolved/); assert.equal(ui.el("prev").disabled, false);
  assert.equal(ui.el("provider").value, "openai");
  ui.el("period-kind").value = "day"; ui.el("period-kind").dispatchEvent(new ui.window.Event("change")); ui.el("period-day").value = "2025-01-05";
  ui.el("load-period").click(); await ui.settle();
  assert.match(ui.calls.filter(call => call.url.includes("?offset=")).at(-1).url, /period=2025-01-05/);
});
test("a retained review reference reopens only through the authenticated context without applying", async t => {
  const ui = await fixture(url => response(url.endsWith("/reviews") ? {reviews: [{...review(), state: "applying"}]} : url.includes("/review/") ? {...review(), state: "applying"} : current()));
  t.after(() => ui.window.close());
  assert.match(ui.el("review-pick").textContent, /Settle OpenAI .* \(interrupted\)/); assert.doesNotMatch(ui.el("review-pick").textContent, /PAR-/);
  ui.el("review-pick").value = "PAR-review-a"; ui.el("review-pick").dispatchEvent(new ui.window.Event("change")); ui.el("open-review").click(); await ui.settle();
  const read = ui.calls.find(call => call.url.endsWith("/review/PAR-review-a"));
  assert.equal(read.headers["X-Lightwork-Spending-Context"], "account-a");
  assert.match(ui.el("status").textContent, /interrupted/); assert.equal(ui.el("confirm").checked, false);
  assert.equal(ui.calls.some(call => call.method === "POST"), false);
});
test("isolated repair leaves amounts blank and requires complete final receipt coverage plus review", async t => {
  const ui = await fixture(url => response(url.endsWith("/import") ? {id: "PAR-import-a", kind: "import", exported_at: 1700000000, totals: [{provider: "openai", period: "2025-01", confirmed: 5, reserved: 3}]} :
    url.endsWith("/repair-review") ? {id: "PAR-repair-a", kind: "repair", state: "prepared", exported_at: 1700000000, evidence: "All final invoices verified", totals: [{provider: "openai", period: "2025-01", confirmed: 8}]} : {...current(), isolated: true, available: false, message: "Accounting unavailable"}));
  t.after(() => ui.window.close());
  Object.defineProperty(ui.el("import"), "files", {value: [new ui.window.File(["synthetic export"], "accounting.json") ]});
  ui.el("inspect").click(); await ui.settle(); assert.equal(ui.el("total-0").value, "");
  ui.el("total-0").value = "8"; ui.el("repair-evidence").value = "All final invoices verified";
  ui.submit("repair-form"); await ui.settle(); assert.equal(ui.calls.some(call => call.url.endsWith("/repair-review")), false);
  ui.el("add-total").click(); ui.el("provider-1").value = "anthropic";
  ui.el("kind-1").value = "day"; ui.el("kind-1").dispatchEvent(new ui.window.Event("change")); ui.el("day-1").value = "2026-09-06"; ui.el("total-1").value = "4";
  ui.el("receipts-complete").checked = true; ui.submit("repair-form"); await ui.settle();
  const prepared = ui.calls.find(call => call.url.endsWith("/repair-review")); assert.ok(prepared);
  const body = JSON.parse(prepared.body); assert.equal(body.receipts_complete, true); assert.deepEqual(body.totals[1], {provider: "anthropic", period: "2026-09-06", confirmed: 4});
  assert.equal(ui.calls.some(call => call.url.endsWith("/apply")), false); assert.equal(ui.el("confirm").checked, false);
});
