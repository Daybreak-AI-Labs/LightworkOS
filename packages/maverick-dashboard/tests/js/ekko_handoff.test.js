"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../maverick_dashboard/templates/ekko.html"), "utf8"
).replace(/\r\n/g, "\n");
const start = source.indexOf("  async function handoff(id, kind) {");
const end = source.indexOf("  async function eraseData()", start);
assert.ok(start >= 0 && end > start);

function reviewState() {
  const fields = new Map();
  for (const field of ['goal', 'inputs', 'output', 'approval']) {
    fields.set('ekko-review-' + field, {value: 'Owner supplied ' + field});
  }
  fields.set('ekko-review-flow', {}); fields.set('ekko-review-agent', {});
  fields.set('ekko-review-type', {value: 'reporting'});
  return {
    handoffPending: false, deviceRevision: 0,
    reviewCandidate: {opportunity_id: 'opportunity', evidence_revision: 'current-evidence'},
    reviewForm: {reportValidity: () => true}, setText: () => {},
    document: {getElementById: id => fields.get(id)},
  };
}

for (const kind of ["flow", "agent"]) {
  test(`Ekko ${kind} handoff carries the current workspace binding into authoring`, async () => {
    const storage = new Map();
    const window = { location: { href: "" } };
    const context = {
      ...reviewState(),
      Date, JSON, encodeURIComponent, window, current: { workflows_enabled: true },
      device: () => "desk",
      request: async (_path, options) => {
        const input = JSON.parse(options.body);
        assert.equal(input.review.goal, 'Owner supplied goal');
        assert.equal(input.evidence_revision, 'current-evidence');
        return ({
        kind, brief: "Review this work", context: "current-workspace",
        flow: kind === "flow" ? { start: "human-review", nodes: [{ id: "human-review", kind: "approval", next: "observed-1" }, { id: "observed-1", kind: "agent" }] } : undefined,
        redirect: kind === "flow" ? "/flows/designer" : "/workflow-builder"
      }); },
      sessionStorage: { setItem: (key, value) => storage.set(key, value) },
      mvToast: message => assert.fail(message),
    };
    vm.runInNewContext(source.slice(start, end), context);
    await context.handoff("opportunity", kind);
    const handoff = JSON.parse(storage.get("lightwork.authoring-handoff"));
    assert.equal(handoff.context, "current-workspace");
    assert.equal(handoff.brief, "Review this work");
    assert.equal(handoff.kind, kind);
    if (kind === "flow") assert.equal(handoff.flow.start, "human-review");
    assert.equal(window.location.href, kind === "flow" ? "/flows/designer" : "/workflow-builder");
  });
}

test("Ekko does not open an unusable workflow draft while Workflows are off", async () => {
  const storage = new Map();
  const notices = [];
  const context = {
    Date, JSON, encodeURIComponent,
    current: { workflows_enabled: false },
    window: { location: { href: "" } },
    device: () => "desk",
    request: () => assert.fail("the handoff API must not be called"),
    sessionStorage: { setItem: (key, value) => storage.set(key, value) },
    mvToast: (message, options) => notices.push({ message, options }),
  };
  vm.runInNewContext(source.slice(start, end), context);
  await context.handoff("opportunity", "flow");
  assert.equal(storage.size, 0);
  assert.equal(context.window.location.href, "");
  assert.match(notices[0].message, /Workflows are off/);
  assert.equal(notices[0].options.error, true);
});

test('Ekko ignores a draft response after device or workspace changes and prevents duplicate submission', async () => {
  let finish, calls = 0;
  const context = {
    ...reviewState(), Date, JSON, encodeURIComponent, current: {workflows_enabled: true},
    window: {location: {href: ''}}, device: () => 'desk',
    request: () => { calls++; return new Promise(resolve => { finish = resolve; }); },
    sessionStorage: {setItem: () => assert.fail('stale draft must not be retained')},
    mvToast: message => assert.fail(message),
  };
  vm.runInNewContext(source.slice(start, end), context);
  const pending = context.handoff('opportunity', 'agent');
  await context.handoff('opportunity', 'agent');
  assert.equal(calls, 1);
  context.deviceRevision++;
  finish({kind: 'agent', brief: 'Old workspace', context: 'old', redirect: '/workflow-builder'});
  await pending;
  assert.equal(context.window.location.href, '');
  assert.equal(context.handoffPending, false);
});

test('Ekko requires the reviewed candidate and valid task fields before requesting a draft', async () => {
  const context = {
    ...reviewState(), current: {workflows_enabled: true},
    request: () => assert.fail('no valid task review'), mvToast: message => assert.fail(message),
  };
  vm.runInNewContext(source.slice(start, end), context);
  await context.handoff('different-opportunity', 'agent');
  context.reviewForm.reportValidity = () => false;
  await context.handoff('opportunity', 'agent');
});

test('a late discovery refresh cannot replace evidence from the current device', async () => {
  const refreshStart = source.indexOf('  async function refresh() {');
  const refreshEnd = source.indexOf("  document.addEventListener('lightwork:ekko-recording-status'", refreshStart);
  const reads = [];
  let chosen = 'first';
  const statuses = [], suggestions = [];
  const context = {
    refreshVersion: 0, encodeURIComponent, device: () => chosen,
    request: () => new Promise(resolve => reads.push(resolve)),
    renderStatus: state => statuses.push(state), renderCandidates: items => suggestions.push(items),
    setText: () => {}, mvToast: message => assert.fail(message),
  };
  vm.runInNewContext(source.slice(refreshStart, refreshEnd), context);
  const first = context.refresh();
  chosen = 'second';
  const second = context.refresh();
  reads[1]({device_id: 'second'});
  await new Promise(resolve => setImmediate(resolve));
  reads[2]({candidates: ['current']});
  await second;
  reads[0]({device_id: 'first'});
  await first;
  assert.deepEqual(statuses, [{device_id: 'second'}]);
  assert.deepEqual(suggestions, [['current']]);
});
