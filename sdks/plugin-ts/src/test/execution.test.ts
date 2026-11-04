import assert from "node:assert/strict";
import { test } from "node:test";
import { PassThrough, Writable } from "node:stream";
import { defineTool, defineValidatedTool, servePlugin, PROTOCOL, MAX_FRAME_BYTES, type ToolDef } from "../index.js";

function request(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    protocol: PROTOCOL, id: "logical-1", attempt: 1, replay: "never",
    deadline_unix_ms: Date.now() + 5000, tool: "fixture", args: {}, ...extra,
  }) + "\n";
}

async function run(tool: ToolDef, raw: string): Promise<Record<string, unknown>[]> {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: Buffer[] = [];
  output.on("data", chunk => chunks.push(chunk));
  const done = servePlugin([tool], { input, output, argv: [] });
  input.end(raw);
  await done;
  return Buffer.concat(chunks).toString("utf8").split("\n").filter(Boolean).map(line => JSON.parse(line));
}

test("versioned context and effect receipt are explicit; ids do not imply deduplication", async () => {
  let calls = 0;
  const tool = defineTool({ name: "fixture", description: "fixture", inputSchema: {}, handler: (_, context) => {
    calls++;
    assert.equal(context.requestId, "logical-1");
    assert.equal(context.attempt, 1);
    assert.equal(context.replay, "never");
    assert.ok(context.deadlineUnixMs! > Date.now());
    return "ok";
  } });
  const output = await run(tool, request() + request());
  assert.equal(calls, 2); // SDK makes no unsupported durable idempotency claim.
  assert.deepEqual(output[0], { id: "logical-1", attempt: 1, effect: "completed", result: "ok" });
});

test("expired and invalid metadata are rejected before invoking handler", async () => {
  let calls = 0;
  const tool = defineTool({ name: "fixture", description: "fixture", inputSchema: {}, handler: () => { calls++; return "wrong"; } });
  const output = await run(tool, request({ deadline_unix_ms: Date.now() - 1 }) + request({ replay: "idempotent" }) + request({ attempt: 2 }));
  assert.equal(calls, 0);
  assert.ok(output.every(result => result.effect === "not_started" && typeof result.error === "string"));
});

test("typed parser rejects malformed or missing args before handler and keeps validation errors private", async () => {
  let calls = 0;
  const tool = defineValidatedTool({name: "fixture", description: "typed fixture", inputSchema: {type: "object"},
    parseArgs(value: unknown): {who: string} {
      if (!value || typeof value !== "object" || typeof (value as {who?: unknown}).who !== "string") throw new Error("secret-value-must-not-be-returned");
      return {who: (value as {who: string}).who};
    }, handler: ({who}) => { calls++; return who.toUpperCase(); }});
  const output = await run(tool, request({args: null}) + request({args: []}) + request({args: {}}) + request({args: {who: "Ada"}}));
  assert.equal(calls, 1);
  assert.ok(output.slice(0, 3).every(value => value.effect === "not_started"));
  assert.equal(output[3].result, "ADA");
  assert.ok(!JSON.stringify(output).includes("secret-value"));
});

test("an asynchronous parser is refused, not handed to the handler as its arguments", async () => {
  const unhandled: unknown[] = [];
  const watch = (reason: unknown): void => { unhandled.push(reason); };
  process.on("unhandledRejection", watch);
  try {
    let calls = 0;
    // parseArgs is documented as synchronous; a Promise is an object, so it must not pass as args.
    const asyncParser = (async (value: unknown) => {
      if (!value || typeof value !== "object" || typeof (value as {who?: unknown}).who !== "string") throw new Error("secret-value-must-not-be-returned");
      return {who: (value as {who: string}).who};
    }) as unknown as ToolDef["parseArgs"];
    const tool = defineTool({name: "fixture", description: "async parser", inputSchema: {type: "object"},
      parseArgs: asyncParser, handler: () => { calls++; return "ran"; }});
    const output = await run(tool, request({args: {}}) + request({args: {who: "Ada"}}));
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls, 0);
    assert.ok(output.every(value => value.effect === "not_started" && typeof value.error === "string"));
    assert.match(String(output[0].error), /synchronous/);
    assert.ok(!JSON.stringify(output).includes("secret-value"));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off("unhandledRejection", watch);
  }
});

test("deadline requests cancellation but retains handler ownership until cleanup", async () => {
  let cleanup = false;
  let calls = 0;
  const tool = defineTool({ name: "fixture", description: "fixture", inputSchema: {}, handler: async (_, context) => {
    if (++calls === 1) {
      await new Promise<void>(resolve => context.signal.addEventListener("abort", () => resolve(), { once: true }));
      await new Promise(resolve => setTimeout(resolve, 20));
      cleanup = true;
      return "late";
    }
    assert.ok(cleanup);
    return "next";
  } });
  const output = await run(tool, request({ deadline_unix_ms: Date.now() + 40 }) + request({ id: "logical-2" }));
  assert.equal(calls, 2);
  assert.equal(output[0].effect, "unknown");
  assert.equal(output[0].result, undefined);
  assert.equal(output[1].result, "next");
});

test("failure after a possible effect reports unknown without a handler replay", async () => {
  let effects = 0;
  const tool = defineTool({ name: "fixture", description: "fixture", inputSchema: {}, handler: () => { effects++; throw new Error("after effect"); } });
  const output = await run(tool, request());
  assert.equal(effects, 1);
  assert.equal(output[0].effect, "unknown");
  assert.match(String(output[0].result), /^ERROR:/);
});

test("oversized unterminated input and partial EOF fail without dispatch", async () => {
  let calls = 0;
  const tool = defineTool({ name: "fixture", description: "fixture", inputSchema: {}, handler: () => { calls++; return "wrong"; } });
  await assert.rejects(run(tool, "x".repeat(MAX_FRAME_BYTES + 1)), /frame too large/);
  await assert.rejects(run(tool, '{"id":1'), /inside a frame/);
  assert.equal(calls, 0);
});

test("oversized handler output fails after one invocation", async () => {
  let calls = 0;
  const tool = defineTool({ name: "fixture", description: "fixture", inputSchema: {}, handler: () => { calls++; return "x".repeat(MAX_FRAME_BYTES); } });
  await assert.rejects(run(tool, request()), /frame too large/);
  assert.equal(calls, 1);
});

test("output backpressure prevents another handler from starting", async () => {
  let calls = 0;
  let release: (() => void) | undefined;
  const tool = defineTool({ name: "fixture", description: "fixture", inputSchema: {}, handler: () => { calls++; return "ok"; } });
  const input = new PassThrough();
  const output = new Writable({ write(_chunk, _encoding, callback) {
    if (!release) release = () => callback(); else callback();
  } });
  const done = servePlugin([tool], { input, output, argv: [] });
  input.end(request() + request());
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(calls, 1);
  assert.ok(release);
  release();
  await done;
  assert.equal(calls, 2);
});

test("a broken output rejects and does not replay or leak an unhandled error", async () => {
  const tool = defineTool({ name: "fixture", description: "fixture", inputSchema: {}, handler: () => "ok" });
  const input = new PassThrough();
  const output = new Writable({ write(_chunk, _encoding, callback) { callback(new Error("closed output")); } });
  const done = servePlugin([tool], { input, output, argv: [] });
  input.end(request());
  await assert.rejects(done, /closed output/);
});

test("a validated tool without a parser is refused, even from plain JavaScript", () => {
  // TypeScript requires parseArgs, but a JavaScript caller (or a typo) got a
  // "validated" tool whose handler ran on unchecked input.
  const untyped = defineValidatedTool as unknown as (def: Record<string, unknown>) => ToolDef;
  assert.throws(() => untyped({name: "pay", description: "pays", inputSchema: {type: "object"},
    parseArg: (input: unknown) => input, handler: () => "paid"}), /parseArgs must be a function/);
});
