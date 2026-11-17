// Today renders at once; each work source loads from /today/sections/<source>
// into its own cards with its own loading and error state (live: /today
// timed out at the load balancer while it read every source first).
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");

const source = fs.readFileSync(path.join(__dirname, "../../maverick_dashboard/static/lightwork-today.js"), "utf8");
const PAGE = `<!doctype html><body><main>
<p class="panel" id="today-decisions-reminder" data-today-source="decisions"><span role="status" data-today-status>Checking…</span></p>
<div class="today-grid">
<section class="panel" id="today-card-tasks" data-today-source="tasks" aria-busy="true"><h2>In-flight work</h2><p role="status" data-today-status>Loading…</p></section>
<section class="panel" id="today-card-recent" data-today-source="tasks" aria-busy="true"><h2>Recent</h2><p role="status" data-today-status>Loading…</p></section>
<section class="panel" id="today-card-schedules" data-today-source="schedules" aria-busy="true"><h2>Upcoming</h2><p role="status" data-today-status>Loading…</p></section>
<section class="panel" id="today-card-templates" data-today-source="templates" aria-busy="true"><h2>Pinned templates</h2><p role="status" data-today-status>Loading…</p></section>
</div>
<script id="today-preferences" type="application/json">{"context":"c","revision":"r","pins":["weekly"]}</script>
</main></body>`;
const FRAGMENTS = {
  tasks: '<section class="panel" id="today-card-tasks"><h2>In-flight work</h2><ul><li><a href="/chat/goal/7">Vendor review</a></li></ul></section>'
    + '<section class="panel" id="today-card-recent"><h2>Recent</h2><p>Nothing yet.</p></section>',
  decisions: '<p class="panel" id="today-decisions-reminder">2 waiting on you.</p>',
  templates: '<section class="panel" id="today-card-templates"><h2>Pinned templates</h2><button type="button" data-unpin-template="weekly">Unpin</button><p id="today-pin-status"></p></section>',
};

async function fixture(t, respond) {
  const dom = new JSDOM(PAGE, {url: "https://lightwork.test/today", runScripts: "outside-only"});
  t.after(() => dom.window.close());
  const w = dom.window, calls = [];
  w.fetch = async (url, options = {}) => {
    calls.push({url: String(url), options});
    const name = String(url).split("/").pop();
    return respond(name, url, options, w);
  };
  w.mvFetchJSON = async (url, options) => { calls.push({url, options}); return {context: "c"}; };
  w.eval(source);
  for (let i = 0; i < 20; i += 1) await new Promise(resolve => setImmediate(resolve));
  return {w, calls, $: id => w.document.getElementById(id)};
}
const html = (body, status = 200) => new Response(body, {status, headers: {"Content-Type": "text/html"}});

test("each source is read once, in parallel, and its cards replace the placeholders", async t => {
  const h = await fixture(t, name => FRAGMENTS[name] ? html(FRAGMENTS[name]) : html("", 500));
  assert.deepEqual(h.calls.map(call => call.url).sort(),
    ["/today/sections/decisions", "/today/sections/schedules", "/today/sections/tasks", "/today/sections/templates"]);
  assert.match(h.$("today-card-tasks").textContent, /Vendor review/);
  assert.equal(h.$("today-card-tasks").hasAttribute("data-today-source"), false);
  assert.match(h.$("today-card-recent").textContent, /Nothing yet/);
  assert.match(h.$("today-decisions-reminder").textContent, /2 waiting on you/);
});

test("a failed source says so in its own cards with a working retry; the others still load", async t => {
  let schedulesUp = false;
  const h = await fixture(t, name => name === "schedules" && !schedulesUp ? html("", 503)
    : html(name === "schedules" ? '<section class="panel" id="today-card-schedules"><p>Next run Monday.</p></section>' : (FRAGMENTS[name] || "")));
  const card = h.$("today-card-schedules");
  assert.match(card.textContent, /could not be loaded just now/);
  assert.equal(card.getAttribute("aria-busy"), null);
  assert.match(h.$("today-card-tasks").textContent, /Vendor review/);
  schedulesUp = true;
  card.querySelector("button").click();
  for (let i = 0; i < 20; i += 1) await new Promise(resolve => setImmediate(resolve));
  assert.match(h.$("today-card-schedules").textContent, /Next run Monday/);
});

test("an expired sign-in asks for a refresh instead of showing a sign-in page in a card", async t => {
  const h = await fixture(t, name => html("<h1>Sign in</h1>", name === "tasks" ? 401 : 200));
  assert.match(h.$("today-card-tasks").textContent, /sign-in has expired/);
  assert.doesNotMatch(h.$("today-card-tasks").textContent, /<h1>|Sign in$/);
});

test("pin controls work after their card arrives", async t => {
  const h = await fixture(t, name => html(FRAGMENTS[name] || ""));
  h.w.document.querySelector("[data-unpin-template]").click();
  await new Promise(resolve => setImmediate(resolve));
  const saved = h.calls.find(call => call.url === "/api/v1/preferences");
  assert.ok(saved, "the unpin was saved");
  assert.deepEqual(JSON.parse(JSON.stringify(saved.options.body.changes)), {template_favorites: []});
});
