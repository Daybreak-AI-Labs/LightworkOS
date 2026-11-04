import assert from "node:assert/strict";
import { test } from "node:test";
import { PassThrough } from "node:stream";
import { defineTool, servePlugin, PROTOCOL, type ToolDef } from "../index.js";

const echo = defineTool({
  name: "echo",
  description: "Echo back the text argument.",
  inputSchema: { type: "object", properties: { text: { type: "string" } } },
  handler: (args) => `echo:${args.text}`,
});

const boom = defineTool({
  name: "boom",
  description: "Always throws.",
  inputSchema: { type: "object" },
  handler: async () => {
    throw new Error("kaboom");
  },
});

/** Run servePlugin against in-memory streams; returns parsed response lines. */
async function run(
  tools: ToolDef[],
  requests: string[],
  argv: string[] = [],
): Promise<Array<Record<string, unknown>>> {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: Buffer[] = [];
  output.on("data", (c: Buffer) => chunks.push(c));
  const done = servePlugin(tools, { input, output, argv });
  for (const r of requests) input.write(r + "\n");
  input.end();
  await done;
  return Buffer.concat(chunks)
    .toString("utf8")
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

test("defineTool rejects invalid definitions", () => {
  const ok = { name: "t1", description: "d", inputSchema: {}, handler: () => "x" };
  assert.equal(defineTool(ok), ok);
  assert.throws(() => defineTool({ ...ok, name: "has space" }), TypeError);
  assert.throws(() => defineTool({ ...ok, name: "" }), TypeError);
  assert.throws(() => defineTool({ ...ok, description: "" }), TypeError);
  assert.throws(() => defineTool({ ...ok, inputSchema: null as never }), TypeError);
  assert.throws(() => defineTool({ ...ok, handler: "nope" as never }), TypeError);
});

test("--describe prints the manifest and returns", async () => {
  const lines = await run([echo, boom], [], ["--describe"]);
  assert.equal(lines.length, 1);
  const m = lines[0] as { protocol: string; tools: Array<Record<string, unknown>> };
  assert.equal(m.protocol, PROTOCOL);
  assert.deepEqual(m.tools[0], {
    name: "echo",
    description: "Echo back the text argument.",
    inputSchema: { type: "object", properties: { text: { type: "string" } } },
  });
  assert.equal(m.tools.length, 2);
  assert.ok(!("handler" in m.tools[0]));
});

test("request -> response round trip over a stream pair", async () => {
  const lines = await run(
    [echo],
    [JSON.stringify({ id: 1, tool: "echo", args: { text: "hi" } }), JSON.stringify({ id: 2, tool: "nope", args: {} })],
  );
  assert.deepEqual(lines[0], { id: 1, result: "echo:hi" });
  assert.deepEqual(lines[1], { id: 2, error: "unknown tool: nope" });
});

test("handler exceptions map to ERROR result strings", async () => {
  const lines = await run([boom], [JSON.stringify({ id: 7, tool: "boom", args: {} })]);
  assert.deepEqual(lines[0], { id: 7, result: "ERROR: boom failed: kaboom" });
});

test("non-serializable handler result becomes an ERROR, not a dropped key", async () => {
  // A handler that falls through with no explicit return yields undefined;
  // JSON.stringify(undefined) is undefined, which would drop the result key off
  // the wire (neither result nor error). It must surface as a readable error.
  const dropper = defineTool({
    name: "dropper",
    description: "Returns undefined.",
    inputSchema: { type: "object" },
    handler: () => undefined as never,
  });
  const lines = await run([dropper], [JSON.stringify({ id: 9, tool: "dropper", args: {} })]);
  assert.equal(lines[0].id, 9);
  assert.equal(lines[0].error, undefined);
  assert.match(String(lines[0].result), /^ERROR: dropper returned a non-serializable value/);
});

test("malformed lines get an error response, not a crash", async () => {
  const lines = await run([echo], ["{not json", JSON.stringify({ id: 3, args: {} })]);
  assert.equal(lines[0].id, null);
  assert.match(String(lines[0].error), /invalid request/);
  assert.deepEqual(lines[1], { id: 3, error: "invalid request: missing tool" });
});

test("servePlugin rejects duplicate tool names", async () => {
  await assert.rejects(() => servePlugin([echo, echo], { argv: ["--describe"] }), TypeError);
});
