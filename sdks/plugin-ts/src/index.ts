/**
 * @maverick/plugin-sdk — author Lightwork agent tools in TypeScript.
 *
 * A plugin is a Node script that ends with `servePlugin([...tools])`. The
 * Lightwork host (packages/maverick-core/maverick/ts_plugin_host.py) speaks
 * NDJSON to it, one JSON object per line:
 *
 *   plugin --describe              -> one-line manifest JSON, then exit
 *   {"id", "tool", "args"} on stdin -> {"id", "result"} | {"id", "error"} on stdout
 *
 * Handler exceptions become "ERROR: ..." result strings, matching the
 * convention of Lightwork's built-in Python tools. Anything you log must go to
 * stderr (console.error) — stdout belongs to the protocol.
 */
import type { Readable } from "node:stream";

export const PROTOCOL = "maverick-plugin/2";
export const MAX_FRAME_BYTES = 1024 * 1024;
const NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;

export interface InvocationContext {
  /** Stable logical invocation id, not an idempotency guarantee. */
  requestId: string | number | null;
  attempt: number;
  deadlineUnixMs: number | null;
  /** Aborted at the deadline; handlers must pass it into owned async work. */
  signal: AbortSignal;
  /** Neither the host nor SDK automatically repeats a handler. */
  replay: "never";
}

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  /** Optional synchronous validation before handler entry. Throws on invalid input. */
  parseArgs?: (input: unknown) => Record<string, unknown>;
  handler: (args: Record<string, unknown>, context: InvocationContext) => string | Promise<string>;
}

export function defineTool(def: ToolDef): ToolDef {
  if (typeof def?.name !== "string" || !NAME_RE.test(def.name)) {
    throw new TypeError("defineTool: invalid tool name");
  }
  if (typeof def.description !== "string" || def.description.length === 0) {
    throw new TypeError(`defineTool(${def.name}): description must be a non-empty string`);
  }
  if (typeof def.inputSchema !== "object" || def.inputSchema === null || Array.isArray(def.inputSchema)) {
    throw new TypeError(`defineTool(${def.name}): inputSchema must be a JSON Schema object`);
  }
  if (typeof def.handler !== "function") {
    throw new TypeError(`defineTool(${def.name}): handler must be a function`);
  }
  if (def.parseArgs !== undefined && typeof def.parseArgs !== "function") {
    throw new TypeError(`defineTool(${def.name}): parseArgs must be a function`);
  }
  return def;
}

/** Adapt a typed parser (including a schema library's parse) without a dependency.
 * inputSchema advertises the contract; parseArgs enforces it before any effect.
 */
export function defineValidatedTool<T extends Record<string, unknown>>(def: {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  parseArgs: (input: unknown) => T;
  handler: (args: T, context: InvocationContext) => string | Promise<string>;
}): ToolDef {
  // The type requires a parser; a JavaScript caller (or a typo) must not get a
  // "validated" tool whose handler runs on unchecked input.
  if (typeof (def as { parseArgs?: unknown } | undefined)?.parseArgs !== "function") {
    throw new TypeError(`defineValidatedTool(${String(def?.name)}): parseArgs must be a function`);
  }
  return defineTool({ ...def, handler: (args, context) => def.handler(args as T, context) });
}

type Effect = "not_started" | "completed" | "unknown";
interface WireResponse {
  id: unknown;
  attempt?: number;
  effect?: Effect;
  result?: string;
  error?: string;
}

function manifest(tools: ToolDef[]): string {
  return JSON.stringify({
    protocol: PROTOCOL,
    execution: { replay: "never", deadline: "cooperative", framingBytes: MAX_FRAME_BYTES },
    tools: tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
  });
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (typeof value === "object" || typeof value === "function") && value !== null
    && typeof (value as { then?: unknown }).then === "function";
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

async function answer(byName: Map<string, ToolDef>, line: string): Promise<WireResponse> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return { id: null, error: "invalid request: malformed JSON" };
  }
  const req = (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed : {}) as Record<string, unknown>;
  const id = "id" in req ? req.id : null;
  const versioned = req.protocol === PROTOCOL;
  const reply = (effect: Effect, content: { result: string } | { error: string }): WireResponse => ({
    id, ...(versioned ? { attempt: 1, effect } : {}), ...content,
  });
  if (req.protocol !== undefined && !versioned && req.protocol !== "maverick-plugin/1") {
    return reply("not_started", { error: "unsupported protocol" });
  }
  if (versioned && (
    typeof id !== "string" || id.length === 0 || id.length > 128
    || req.attempt !== 1 || req.replay !== "never"
    || typeof req.deadline_unix_ms !== "number" || !Number.isSafeInteger(req.deadline_unix_ms)
  )) {
    return reply("not_started", { error: "invalid execution metadata" });
  }
  if (typeof req.tool !== "string") return reply("not_started", { error: "invalid request: missing tool" });
  const tool = byName.get(req.tool);
  if (tool === undefined) return reply("not_started", { error: `unknown tool: ${req.tool}` });
  const deadline = versioned ? req.deadline_unix_ms as number : null;
  if (deadline !== null && deadline <= Date.now()) {
    return reply("not_started", { error: "invocation deadline expired before dispatch" });
  }
  let args: Record<string, unknown>;
  try {
    const parsedArgs: unknown = tool.parseArgs ? tool.parseArgs(req.args) :
      (typeof req.args === "object" && req.args !== null && !Array.isArray(req.args) ? req.args : {});
    if (isThenable(parsedArgs)) {
      // A Promise is an object, so it would pass as the arguments and its rejection would
      // go unhandled (Node exits). parseArgs is synchronous: consume the promise and refuse.
      Promise.resolve(parsedArgs).catch(() => undefined);
      return reply("not_started", { error: "invalid tool definition: parseArgs must be synchronous; handler was not started" });
    }
    if (typeof parsedArgs !== "object" || parsedArgs === null || Array.isArray(parsedArgs)) throw new TypeError("invalid arguments");
    args = parsedArgs as Record<string, unknown>;
  } catch {
    // Validation messages may contain credentials or private argument values.
    return reply("not_started", { error: "invalid tool arguments; handler was not started" });
  }
  if (deadline !== null && deadline <= Date.now()) {
    return reply("not_started", { error: "invocation deadline expired during argument validation" });
  }
  const controller = new AbortController();
  const context: InvocationContext = {
    requestId: typeof id === "string" || typeof id === "number" ? id : null,
    attempt: 1, deadlineUnixMs: deadline, signal: controller.signal, replay: "never",
  };
  const timer = deadline === null ? undefined : setTimeout(
    () => controller.abort(new Error("invocation deadline exceeded")),
    Math.min(deadline - Date.now(), 2147483647),
  );
  try {
    // Do not race the handler against a timeout and then start another effect:
    // retain serial ownership until it settles. The host owns hard termination.
    const result = await tool.handler(args, context);
    if (controller.signal.aborted || (deadline !== null && Date.now() >= deadline)) {
      return reply("unknown", { error: "deadline exceeded; effect outcome unknown" });
    }
    if (typeof result === "string") return reply("completed", { result });
    const serialized = JSON.stringify(result);
    if (serialized === undefined) {
      return reply("unknown", { result: `ERROR: ${tool.name} returned a non-serializable value (${typeof result})` });
    }
    return reply("completed", { result: serialized });
  } catch (e) {
    return reply("unknown", { result: `ERROR: ${tool.name} failed: ${errorMessage(e)}` });
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export interface ServeOptions {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  argv?: string[];
}

async function writeFrame(output: NodeJS.WritableStream, frame: string): Promise<void> {
  if (Buffer.byteLength(frame) > MAX_FRAME_BYTES) throw new Error("plugin response frame too large");
  // The callback waits for this write, including backpressure. Only one response
  // is outstanding; a slow host cannot cause an unbounded output queue.
  await new Promise<void>((resolve, reject) => {
    const failure = (error: Error): void => { output.off("error", failure); reject(error); };
    output.once("error", failure);
    try {
      output.write(frame + "\n", (error?: Error | null) => {
        if (error) reject(error);
        else { output.off("error", failure); resolve(); }
      });
    } catch (error) {
      output.off("error", failure);
      reject(error);
    }
  });
}

/** Bounded UTF-8 frames; serialized handlers; deadline context for version 2. */
export async function servePlugin(tools: ToolDef[], opts: ServeOptions = {}): Promise<void> {
  const checked = tools.map(defineTool);
  const byName = new Map(checked.map((tool) => [tool.name, tool]));
  if (byName.size !== checked.length) throw new TypeError("servePlugin: duplicate tool names");
  const output = opts.output ?? process.stdout;
  if ((opts.argv ?? process.argv.slice(2)).includes("--describe")) {
    await writeFrame(output, manifest(checked));
    return;
  }
  let pending = Buffer.alloc(0);
  for await (const raw of (opts.input ?? process.stdin) as Readable) {
    const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as string);
    let start = 0;
    for (let index = 0; index < chunk.length; index++) {
      if (chunk[index] !== 10) continue;
      if (pending.length + index - start > MAX_FRAME_BYTES) throw new Error("plugin request frame too large");
      const line = Buffer.concat([pending, chunk.subarray(start, index)]).toString("utf8");
      pending = Buffer.alloc(0);
      start = index + 1;
      if (line.trim()) await writeFrame(output, JSON.stringify(await answer(byName, line)));
    }
    if (pending.length + chunk.length - start > MAX_FRAME_BYTES) throw new Error("plugin request frame too large");
    pending = Buffer.concat([pending, chunk.subarray(start)]);
  }
  if (pending.length) throw new Error("plugin input ended inside a frame");
}

// --------------------------------------------------------------------------
// Structured page context supplied by an integration.
//
// The browser extension currently flattens its observe-only snapshot into a
// goal's description; it does not populate a structured plugin argument.
// These types + parser accept explicitly supplied snapshots safely: parse
// validates/normalizes untrusted JSON and re-applies the same bounds the
// extension enforces, so a plugin never trusts oversized or malformed input.
// --------------------------------------------------------------------------

/** One interactive control (button/link/input/…) from the page snapshot. */
export interface PageElement {
  /** ARIA role or tag name, e.g. "button", "link", "textbox". */
  role: string;
  /** Lowercase tag name, e.g. "a", "button", "input". */
  tag: string;
  /** Accessible name/label (may be empty). */
  name: string;
  /** Advisory selector hint (#id / tag[name=…] / :nth-of-type); not guaranteed. */
  selector: string;
  /** Input type, when the element is a form field. */
  type?: string;
  /** Visible value or placeholder (never a password value). */
  value?: string;
  /** True when the control is disabled. */
  disabled?: boolean;
}

/** A landmark or heading giving the page outline. */
export interface PageLandmark {
  role: string;
  tag: string;
  name: string;
}

/** The structured snapshot the extension attaches to a goal. */
export interface StructuredPageContext {
  /** Document language (BCP-47-ish), may be empty. */
  lang: string;
  counts: { elements: number; landmarks: number };
  /** True when caps were hit and the snapshot is partial. */
  truncated: boolean;
  landmarks: PageLandmark[];
  elements: PageElement[];
}

// Bounds mirror content.js so a plugin re-clamps untrusted input.
const PCTX_MAX_ELEMENTS = 60;
const PCTX_MAX_LANDMARKS = 25;
const PCTX_MAX_NAME = 120;
const PCTX_MAX_SELECTOR = 120;
const PCTX_MAX_VALUE = 80;

function pctxStr(v: unknown, max: number): string {
  // slice() counts UTF-16 code units, so the cap can land mid-surrogate-pair
  // (and crafted JSON can smuggle lone surrogates outright). toWellFormed()
  // (Node >= 20) swaps any unpaired surrogate for U+FFFD so the output never
  // breaks downstream UTF-8 encoders (the host's JSON wire, sqlite, the LLM
  // request body).
  return typeof v === "string" ? v.slice(0, max).toWellFormed() : "";
}

function pctxElement(raw: unknown): PageElement {
  const o = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const el: PageElement = {
    role: pctxStr(o.role, 32),
    tag: pctxStr(o.tag, 32),
    name: pctxStr(o.name, PCTX_MAX_NAME),
    selector: pctxStr(o.selector, PCTX_MAX_SELECTOR),
  };
  if (typeof o.type === "string") el.type = pctxStr(o.type, 24);
  if (typeof o.value === "string") el.value = pctxStr(o.value, PCTX_MAX_VALUE);
  if (o.disabled === true) el.disabled = true;
  return el;
}

function pctxLandmark(raw: unknown): PageLandmark {
  const o = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  return {
    role: pctxStr(o.role, 32),
    tag: pctxStr(o.tag, 32),
    name: pctxStr(o.name, PCTX_MAX_NAME),
  };
}

/**
 * Parse + validate an untrusted structured-page-context value (object or JSON
 * string) into a normalized {@link StructuredPageContext}, re-applying the
 * extension's caps. Returns null when the input is not a usable snapshot.
 */
export function parseStructuredPageContext(input: unknown): StructuredPageContext | null {
  let raw: unknown = input;
  if (typeof input === "string") {
    try {
      raw = JSON.parse(input);
    } catch {
      return null;
    }
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  const elementsIn = Array.isArray(o.elements) ? o.elements : [];
  const landmarksIn = Array.isArray(o.landmarks) ? o.landmarks : [];
  const elements = elementsIn.slice(0, PCTX_MAX_ELEMENTS).map(pctxElement);
  const landmarks = landmarksIn.slice(0, PCTX_MAX_LANDMARKS).map(pctxLandmark);
  const counts = (typeof o.counts === "object" && o.counts !== null ? o.counts : {}) as Record<string, unknown>;
  return {
    lang: pctxStr(o.lang, 16),
    counts: {
      elements: typeof counts.elements === "number" ? counts.elements : elements.length,
      landmarks: typeof counts.landmarks === "number" ? counts.landmarks : landmarks.length,
    },
    truncated: o.truncated === true,
    landmarks,
    elements,
  };
}

/** Render a parsed snapshot to a compact, human/agent-readable summary. */
export function summarizePageContext(ctx: StructuredPageContext): string {
  const lines: string[] = [];
  lines.push(
    `page: ${ctx.counts.elements} interactive, ${ctx.counts.landmarks} landmarks` +
      (ctx.truncated ? " (truncated)" : "") +
      (ctx.lang ? `, lang=${ctx.lang}` : ""),
  );
  for (const l of ctx.landmarks) {
    lines.push(`  [${l.tag}${l.role && l.role !== l.tag ? "/" + l.role : ""}] ${l.name}`.trimEnd());
  }
  for (const e of ctx.elements) {
    let line = `  <${e.role || e.tag}> ${e.name}`.trimEnd();
    if (e.type) line += ` type=${e.type}`;
    if (e.disabled) line += " (disabled)";
    if (e.selector) line += ` @ ${e.selector}`;
    lines.push(line);
  }
  return lines.join("\n");
}
