"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const inputs = require("../../maverick_dashboard/templates/flow_designer_inputs.js");
const core = require("../../maverick_dashboard/templates/flow_designer_core.js");
const clone = value => JSON.parse(JSON.stringify(value));
const obj = properties => ({type: "object", properties, required: Object.keys(properties), additionalProperties: false});
const integer = {type: "integer", minimum: -10, maximum: 10};
const text = {type: "string", minLength: 0, maxLength: 10};
const number = {type: "number", minimum: -10, maximum: 10};
const families = ["lightwork.action-recipe.v2", "lightwork.action-choice.v1",
  "lightwork.workflow-transducer.v1", "lightwork.workflow-memory.v1"];
const artifact = (schema = families[0], properties = {quantity: integer}) => ({schema, domain: {inputs: obj(properties)}});
function values(plan, data) {
  return Object.fromEntries(plan.fields.filter(field => field.type !== "null").map(field => [field.id,
    Object.is(field.path.reduce((value, key) => value[key], data), -0) ? '-0.0' :
      String(field.path.reduce((value, key) => value[key], data))]));
}
for (const family of families) test(`${family}: nested form preserves input shape and strict float wire type`, () => {
  const original = artifact(family, {customer: obj({name: text, consent: {type: "boolean"}}),
    lines: {type: "array", minItems: 2, maxItems: 2, items: obj({amount: number, count: integer})},
    empty: obj({}), absent: {type: "null"}});
  const before = clone(original), plan = inputs.plan(original);
  const expected = {customer: {name: "  Ada  ", consent: false}, lines: [{amount: 1, count: 2}, {amount: -0, count: 0}], empty: {}, absent: null};
  const data = inputs.read(plan, values(plan, expected)), wire = inputs.wireData(plan, data);
  assert.deepEqual(clone(data), {input: clone(expected)});
  assert.match(wire, /"amount":1\.0/);
  assert.match(wire, /"amount":-0\.0/);
  assert.deepEqual(original, before, "never rewrite the artifact or infer defaults from its examples");
});
test("v1 exact input_shape supports mixed fixed lists, empty structures, and collision-safe paths", () => {
  const original = {schema: "lightwork.action-recipe.v1", input_shape: [
    {path: [], kind: "object", keys: ["a.b", "a", "items", "empty"]},
    {path: ["a.b"], kind: "string"}, {path: ["a"], kind: "object", keys: ["b"]},
    {path: ["a", "b"], kind: "boolean"}, {path: ["items"], kind: "array", length: 2},
    {path: ["items", 0], kind: "integer"}, {path: ["items", 1], kind: "null"},
    {path: ["empty"], kind: "array", length: 0}]};
  const plan = inputs.plan(original), expected = {"a.b": "literal", a: {b: true}, items: [3, null], empty: []};
  assert.equal(new Set(plan.fields.map(field => field.id)).size, plan.fields.length);
  assert.deepEqual(clone(inputs.read(plan, values(plan, expected))), {input: expected});
});
test("a retained 65-item list uses ordinary fields without changing its fixed shape", () => {
  const shape = [{path: [], kind: "object", keys: ["lines"]},
    {path: ["lines"], kind: "array", length: 65}];
  for (let index = 0; index < 65; index++) shape.push({path: ["lines", index], kind: "integer"});
  const plan = inputs.plan({schema: "lightwork.action-recipe.v1", input_shape: shape});
  assert.equal(plan.fields.length, 65);
  const data = inputs.read(plan, values(plan, {lines: Array.from({length: 65}, (_, index) => index)}));
  assert.deepEqual(clone(data), {input: {lines: Array.from({length: 65}, (_, index) => index)}});
  assert.deepEqual(JSON.parse(inputs.wireData(plan, data)), clone(data));
  const ui = dom(), pending = ui.api.prompt(ui.api.plan({schema: "lightwork.action-recipe.v1", input_shape: shape}));
  for (const field of plan.fields) ui.elements.find(element => element.id === field.id).value = String(field.path[1]);
  ui.elements.find(element => element.tagName === "form").dispatch("submit");
  return pending.then(result => {
    assert.deepEqual(clone(result), clone(data));
    assert.ok(ui.elements.some(element => /Enter 65 values/.test(element.textContent || "")));
    assert.equal(ui.opener.focused, true);
  });
});
test("bounded nested declared records may have more than 64 actual values", () => {
  const first = Object.fromEntries(Array.from({length: 64}, (_, index) => [`field_${index}`, integer]));
  const plan = inputs.plan(artifact(families[0], {first: obj(first), last: integer}));
  assert.equal(plan.fields.length, 65);
  const submitted = Object.fromEntries(plan.fields.map(field => [field.id, "2"]));
  assert.equal(Object.keys(inputs.read(plan, submitted).input.first).length, 64);
});
test("legacy form covers the native 512-leaf limit and refuses a larger list", () => {
  function shape(size) {
    return [{path: [], kind: "object", keys: ["lines"]}, {path: ["lines"], kind: "array", length: size},
      ...Array.from({length: size}, (_, index) => ({path: ["lines", index], kind: "integer"}))];
  }
  const model = inputs.plan({schema: "lightwork.action-recipe.v1", input_shape: shape(512)});
  assert.equal(model.fields.length, 512);
  assert.equal(inputs.read(model, Object.fromEntries(model.fields.map(field => [field.id, "1"]))).input.lines.length, 512);
  assert.throws(() => inputs.plan({schema: "lightwork.action-recipe.v1", input_shape: shape(513)}), /cannot display safely/);
});
test("prototype-like keys stay data, and markup labels are not interpreted", () => {
  const props = JSON.parse('{"__proto__":{"type":"string","maxLength":10},"<img src=x>":{"type":"boolean"}}');
  const plan = inputs.plan(artifact(families[0], props));
  const data = inputs.read(plan, Object.fromEntries(plan.fields.map(field => [field.id, field.type === "boolean" ? "false" : "safe"])));
  assert.equal(Object.getPrototypeOf(data.input), null);
  assert.equal(data.input.__proto__, "safe");
  assert.equal(JSON.parse(inputs.wireData(plan, data)).input.__proto__, "safe");
  assert.equal({}.polluted, undefined);
});
test("an empty input object still produces the required input envelope", () => {
  const plan = inputs.plan(artifact(families[0], {}));
  assert.equal(inputs.wireData(plan, inputs.read(plan, {})), '{"input":{}}');
});
for (const bad of ["", "1.2", "1e1", "0x10", "NaN", "Infinity", "9007199254740993", "11"]) {
  test(`integer field refuses ${JSON.stringify(bad)} rather than coercing a value`, () => {
    const plan = inputs.plan(artifact());
    assert.throws(() => inputs.read(plan, {[plan.fields[0].id]: bad}), /Workflow inputs/);
  });
}
test("strict Boolean and nullable values cannot be silently defaulted or forged", () => {
  const plan = inputs.plan(artifact(families[0], {flag: {type: "boolean"}, nothing: {type: "null"}}));
  const id = plan.fields.find(field => field.type === "boolean").id;
  assert.throws(() => inputs.read(plan, {}), /missing/);
  assert.throws(() => inputs.read(plan, {[id]: ""}), /choose Yes or No/);
  assert.throws(() => inputs.read(plan, {[id]: false}), /enter a value/);
  assert.throws(() => inputs.wireData(plan, {input: {flag: 0, nothing: null}}), /no longer matches/);
});
test("Unicode limits count code points, preserve whitespace, and reject unpaired surrogates", () => {
  const plan = inputs.plan(artifact(families[0], {text: {type: "string", minLength: 2, maxLength: 2}}));
  const id = plan.fields[0].id;
  assert.equal(inputs.read(plan, {[id]: "😀 "}).input.text, "😀 ");
  assert.throws(() => inputs.read(plan, {[id]: "😀"}), /characters/);
  assert.throws(() => inputs.read(plan, {[id]: "\ud800a"}), /character/);
});
const invalidSchemas = [
  {type: "string", pattern: ".*", maxLength: 4}, {type: "integer", minimum: 0, maximum: 1e24},
  {type: "array", minItems: 0, maxItems: 1, items: integer}, {type: "array", minItems: 65, maxItems: 65, items: integer},
  {type: "object", properties: {a: integer}, required: [], additionalProperties: false},
  {type: "array", minItems: 0, maxItems: 0, items: {type: "unsupported"}},
  {type: "number", minimum: 2, maximum: 1}, {type: "string", maxLength: 1025},
];
for (const schema of invalidSchemas) test(`unsupported declared schema fails visibly: ${JSON.stringify(schema)}`, () => {
  assert.throws(() => inputs.plan(artifact(families[0], {value: schema})), /Workflow inputs/);
});
test("expanded array size is bounded even when the compact schema is small", () => {
  assert.throws(() => inputs.plan(artifact(families[0], {grid: {type: "array", minItems: 64, maxItems: 64,
    items: {type: "array", minItems: 64, maxItems: 64, items: integer}}})), /more than 512 values/);
});
for (const shape of [
  [{path: [], kind: "object", keys: ["missing"]}],
  [{path: [], kind: "object", keys: []}, {path: [], kind: "object", keys: []}],
  [{path: [], kind: "object", keys: []}, {path: ["extra"], kind: "integer"}],
]) test(`malformed v1 shape does not produce a partial form: ${JSON.stringify(shape)}`, () => {
  assert.throws(() => inputs.plan({schema: "lightwork.action-recipe.v1", input_shape: shape}), /Workflow inputs/);
});
test("unknown artifact cannot fall back to manual sample input", () => {
  assert.throws(() => inputs.plan({schema: "new-unknown"}), /supported input form/);
});

// Execute the actual designer run function, including its request and receipt checks.
function runner(prompt) {
  const calls = [], messages = [], watched = [];
  const rootFlow = inputs.parseText(JSON.stringify({id: "case", name: "Case", published: true, nodes: [{id: "start", kind: "approval", prompt: "Review"}], start: "start", learned_recipe: artifact()}));
  const button = {setAttribute() {}, removeAttribute() {}, focus() {this.focused = true;}};
  const context = {rootFlow, publishedFlow: clone(rootFlow), flowInputs: [], runInFlight: false, FDCore: core,
    FDActionFields: {async ready() {}, check() { return []; }},
    FDRecipeInputs: {...inputs, prompt}, draftSnapshot: () => JSON.stringify(context.rootFlow),
    document: {getElementById(id) { if (id === "fd-sample") throw new Error("learned flow read hidden JSON");
      if (id === "fd-legend") return {classList: {add() {}}}; return button; }},
    apiFetch: async (url, options) => {calls.push({url, options});
      const result = url.endsWith('/published') ? {flow: context.publishedFlow, release_id: 'a'.repeat(64)} :
        {run_id: "run", status: "paused_approval", dry_run: url.endsWith("dry-run")};
      return {ok: true, text: async () => JSON.stringify(result, (key, value) => key === '_fdEvidence' ? undefined : value)};
    },
    readMutationResult: inputs.responseJson,
    say: (message, error) => messages.push({message, error}), watchRun: id => watched.push(id),
    toApiFlow: () => clone(context.rootFlow), commitRawFields: () => [], slugify: value => value,
  };
  context.window = context;
  const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/flow_designer.js"), "utf8");
  const start = source.indexOf("  function inputFields("), end = source.indexOf("  function runUrl(", start);
  vm.runInNewContext(source.slice(start, end), context);
  return {context, calls, messages, watched, button};
}
async function turn() { await new Promise(resolve => setImmediate(resolve)); }
for (const dry of [false, true]) test(`actual ${dry ? "test" : "published"} run submits form values and preserves graph`, async () => {
  const ui = runner(async plan => inputs.read(plan, values(plan, {quantity: 3})));
  const before = JSON.parse(inputs.flowText(ui.context.rootFlow));
  ui.context.run(dry); await turn();
  assert.equal(ui.calls.length, dry ? 1 : 2);
  const body = JSON.parse(ui.calls.at(-1).options.body);
  assert.deepEqual(body.data, {input: {quantity: 3}});
  assert.deepEqual(JSON.parse(inputs.flowText(ui.context.rootFlow)), before);
  if (dry) assert.deepEqual(body.flow, before);
  else assert.equal(body.expected_release_id, 'a'.repeat(64));
  assert.deepEqual(ui.watched, ["run"]);
});
test("Copilot opens the same learned form and binds it to the reviewed release", async () => {
  const ui = runner(async plan => inputs.read(plan, values(plan, {quantity: 3})));
  const accepted = await ui.context.LightworkFlowRun.open('case', 'a'.repeat(64));
  assert.equal(accepted.status, 'started'); assert.equal(accepted.run_id, 'run');
  assert.equal(JSON.parse(ui.calls.at(-1).options.body).expected_release_id, 'a'.repeat(64));
  const changed = runner(async () => { throw new Error('stale release must not open inputs'); });
  const stale = await changed.context.LightworkFlowRun.open('case', 'b'.repeat(64));
  assert.equal(stale.status, 'stale'); assert.equal(changed.calls.length, 1);
  assert.deepEqual(changed.watched, []);
  const wrongFlow = await changed.context.LightworkFlowRun.open('other-case', 'a'.repeat(64));
  assert.equal(wrongFlow.status, 'stale'); assert.equal(changed.calls.length, 1);
});
test("cancel and duplicate clicks dispatch nothing, then allow a fresh input attempt", async () => {
  let finish, count = 0;
  const ui = runner(() => {count++; return new Promise(resolve => {finish = resolve;});});
  ui.context.run(false); ui.context.run(false);
  await turn();
  assert.equal(count, 1); assert.equal(ui.calls.length, 1);
  finish(null); await turn();
  assert.match(ui.messages.at(-1).message, /cancelled/);
  ui.context.run(false); await turn(); assert.equal(count, 2); finish(null); await turn();
});
test("changed artifact or graph while inputs are open blocks the run", async () => {
  let finish;
  const ui = runner(() => new Promise(resolve => {finish = resolve;}));
  ui.context.run(false); await turn();
  ui.context.rootFlow.nodes[0].prompt = "Changed approval";
  finish({input: {quantity: 2}}); await turn();
  assert.equal(ui.calls.length, 1); assert.match(ui.messages.at(-1).message, /changed/);
});
test("unknown draft schema produces a useful error before form or network", async () => {
  const ui = runner(() => {throw new Error("should not open");});
  ui.context.rootFlow.learned_recipe.schema = "unsupported";
  ui.context.run(true); await turn();
  assert.equal(ui.calls.length, 0); assert.match(ui.messages.at(-1).message, /supported input form/);
});
test("published learned inputs come from the reviewed release, never the newer canvas draft", async () => {
  let shown;
  const ui = runner(async plan => {shown = plan.fields.map(field => field.path); return inputs.read(plan, values(plan, {customer_name: 'Ada'}));});
  ui.context.publishedFlow.learned_recipe = artifact(families[1], {customer_name: text});
  ui.context.run(false); await turn();
  assert.deepEqual(shown, [['customer_name']]);
  assert.deepEqual(JSON.parse(ui.calls.at(-1).options.body), {data: {input: {customer_name: 'Ada'}}, dry_run: false, expected_release_id: 'a'.repeat(64)});
  assert.ok(ui.context.rootFlow.learned_recipe.domain.inputs.properties.quantity);
});
test("ordinary published forms also use the exact release inputs and token", async () => {
  const ui = runner(() => {throw new Error('not learned');});
  delete ui.context.rootFlow.learned_recipe; delete ui.context.publishedFlow.learned_recipe;
  ui.context.flowInputs = [{key: 'draft_only', type: 'text'}];
  ui.context.publishedFlow.inputs = [{key: 'published_value', type: 'text'}];
  ui.context.document.getElementById = () => ({value: '', setAttribute() {}, removeAttribute() {}, classList: {add() {}}});
  let shown;
  ui.context.mvForm = async (_title, fields) => {shown = fields; return {published_value: 'entered'};};
  ui.context.run(false); await turn();
  assert.equal(shown[0].key, 'published_value');
  assert.deepEqual(JSON.parse(ui.calls.at(-1).options.body), {data: {published_value: 'entered'}, dry_run: false, expected_release_id: 'a'.repeat(64)});
});
test("changed release refusal is surfaced without retry or a success claim", async () => {
  const ui = runner(async plan => inputs.read(plan, values(plan, {quantity: 2})));
  const normal = ui.context.apiFetch;
  ui.context.apiFetch = async (url, options) => {
    if (url.endsWith('/published')) return normal(url, options);
    ui.calls.push({url, options}); throw new Error('The published workflow changed. Reopen it.');
  };
  ui.context.run(false); await turn();
  assert.equal(ui.calls.length, 2); assert.deepEqual(ui.watched, []);
  assert.match(ui.messages.at(-1).message, /published workflow changed/);
});
for (const moved of [false, true]) test(`completed request restores invoker focus without stealing focus: moved=${moved}`, async () => {
  const ui = runner(async plan => inputs.read(plan, values(plan, {quantity: 2})));
  ui.context.document.body = {};
  ui.context.document.activeElement = moved ? {id: 'another-control'} : ui.context.document.body;
  ui.context.run(true); await turn();
  assert.equal(ui.button.focused === true, !moved);
});

// Small DOM adapter drives actual form submit/cancel, rather than replacing prompt().
function dom() {
  const elements = [];
  class Element {
    constructor(tag) {this.tagName = tag; this.children = []; this.listeners = {}; this.value = ""; this.attributes = {}; elements.push(this);}
    appendChild(child) {this.children.push(child); return child;}
    setAttribute(key, value) {this.attributes[key] = value;}
    removeAttribute(key) {delete this.attributes[key];}
    addEventListener(event, handler) {this.listeners[event] = handler;}
    dispatch(event) {this.listeners[event]({preventDefault() {}});}
    showModal() {this.open = true;}
    close() {this.open = false;}
    focus() {this.focused = true;}
    remove() {this.removed = true;}
  }
  const opener = new Element("button"); opener.isConnected = true;
  const document = {activeElement: opener, createElement: tag => new Element(tag), body: new Element("body")};
  const context = {document, module: {exports: {}}};
  vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/flow_designer_inputs.js"), "utf8"), context);
  return {api: context.module.exports, elements, opener};
}
test("actual dialog keeps invalid values open, labels fields, submits typed input and restores focus", async () => {
  const ui = dom(), plan = ui.api.plan(artifact());
  const pending = ui.api.prompt(plan, {title: "New case"});
  const field = ui.elements.find(element => element.id === plan.fields[0].id);
  const form = ui.elements.find(element => element.tagName === "form");
  field.value = "22"; form.dispatch("submit");
  assert.match(ui.elements.find(element => element.id === field.id + '-error').textContent, /from -10 to 10/);
  assert.equal(field.attributes['aria-invalid'], 'true');
  assert.equal(field.focused, true);
  assert.match(field.attributes['aria-describedby'], /-error/);
  assert.equal(ui.elements.find(element => element.tagName === "dialog").removed, undefined);
  field.value = "4"; form.dispatch("submit");
  assert.deepEqual(clone(await pending), {input: {quantity: 4}});
  assert.equal(ui.opener.focused, true);
  assert.equal(ui.elements.find(element => element.tagName === "label").attributes.for, field.id);
});
test("actual dialog Escape cancels without collecting values", async () => {
  const ui = dom(), pending = ui.api.prompt(ui.api.plan(artifact()));
  ui.elements.find(element => element.tagName === "dialog").dispatch("cancel");
  assert.equal(await pending, null); assert.equal(ui.opener.focused, true);
});

test("raw evidence bytes survive load, clone, save and dry-run without guessing integral float or large integer types", () => {
  const raw = '{"id":"typed", "learned_recipe":{"schema":"lightwork.action-recipe.v2","artifact_sha256":"exact",' +
    '"domain":{"inputs":{"type":"object","properties":{},"required":[],"additionalProperties":false}},' +
    '"episodes":[{"value":1.0,"large":9007199254740993,"negative":-0.0,"text":"} \\\" ,"}]},"nodes":[]}';
  const flow = inputs.parseText(raw), copied = clone(flow);
  const wire = inputs.flowText(copied);
  assert.match(wire, /"value":1\.0/); assert.match(wire, /9007199254740993/); assert.match(wire, /"negative":-0\.0/);
  const payload = inputs.payloadText(inputs.plan(flow.learned_recipe), {flow: copied, data: {input: {}}, dry_run: true});
  assert.match(payload, /"value":1\.0/); assert.match(payload, /9007199254740993/);
  copied.learned_recipe.episodes[0].value = 2;
  assert.throws(() => inputs.flowText(copied), /original learning evidence/);
});
test("raw flow envelope, duplicate members and absent evidence are handled explicitly", () => {
  const value = inputs.parseText('{"flow":{"learned_recipe":{"schema":"test","n":7.0}}}');
  assert.equal(inputs.flowText(value.flow), '{"learned_recipe":{"schema":"test","n":7.0}}');
  assert.throws(() => inputs.parseText('{"learned_recipe":{"x":1},"learned_recipe":{"x":2}}'), /repeats a field/);
  assert.throws(() => inputs.flowText({learned_recipe: {schema: "never loaded"}}), /Reopen/);
});
test("actual undo snapshot and restoration retain learning evidence, lineage and teaching marker", () => {
  const raw = '{"id":"teaching","name":"Teaching","start":"a","nodes":[{"id":"a","kind":"approval","prompt":"Review"}],' +
    '"learned_recipe":{"schema":"lightwork.action-choice.v1","exact":1.0},"recipe_lineage":{"id":"admitted"},' +
    '"recipe_teaching":{"schema":"lightwork.action-choice-teaching.v1"},"version":2,"revision":"v2","published":true}';
  const source = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/flow_designer.js"), "utf8");
  const context = {rootFlow: inputs.parseText(raw), FDCore: core, FDRecipeInputs: inputs,
    FDHistory: require("../../maverick_dashboard/templates/flow_designer_history.js"),
    idInput: {value: "teaching"}, nameInput: {value: "Teaching"}, normalizeNode: core.normalizeNode,
    flowInputs: [], document: {getElementById() { return null; }}, syncScheduleControls() {},
    renderCrumbs() {}, autoLayout() {}, render() {}, renderProps() {}};
  vm.runInNewContext(source.slice(source.indexOf("  function snapState("), source.indexOf("  function undo(")), context);
  const snapshot = context.snapState(); assert.match(snapshot, /"exact":1\.0/);
  delete context.rootFlow.learned_recipe; delete context.rootFlow.recipe_lineage;
  context.restoreState(snapshot);
  assert.equal(context.rootFlow.recipe_lineage.id, "admitted");
  assert.equal(context.rootFlow.recipe_teaching.schema, "lightwork.action-choice-teaching.v1");
  assert.equal(context.rootFlow.version, 2);
  assert.match(inputs.flowText(context.rootFlow), /"exact":1\.0/);
});
test("simple learned step summaries hide internal plumbing and preserve ordinary approval instructions", () => {
  const template = fs.readFileSync(path.resolve(__dirname, '../../maverick_dashboard/templates/flow_designer.html'), 'utf8');
  const start = template.indexOf('    function summarize('), end = template.indexOf('    function render()', start);
  const context = {};
  vm.runInNewContext(template.slice(start, end), context);
  const approval = {id: 'approval_0', kind: 'approval', prompt: 'Internal _recipe_next_arguments'};
  assert.equal(context.summarize(approval, true), 'Review the proposed action before it starts.');
  assert.equal(context.summarize(approval, false), approval.prompt);
  assert.match(context.summarize({...approval, id: 'teaching_review'}, true), /review the action separately/);
  assert.doesNotMatch(context.summarize({kind: 'switch', condition: '_recipe_choice.route'}, true), /_recipe/);
});
