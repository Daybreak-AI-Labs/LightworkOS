import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseStructuredPageContext,
  summarizePageContext,
  type StructuredPageContext,
} from "../index.js";

const SAMPLE = {
  lang: "en",
  counts: { elements: 2, landmarks: 1 },
  truncated: false,
  landmarks: [{ role: "navigation", tag: "nav", name: "Primary" }],
  elements: [
    { role: "button", tag: "button", name: "Save", selector: "#save" },
    {
      role: "textbox",
      tag: "input",
      name: "Email",
      selector: 'input[name="email"]',
      type: "email",
      value: "a@b.co",
    },
  ],
};

test("parses an object snapshot and normalizes it", () => {
  const ctx = parseStructuredPageContext(SAMPLE);
  assert.ok(ctx);
  assert.equal(ctx.lang, "en");
  assert.equal(ctx.elements.length, 2);
  assert.equal(ctx.landmarks.length, 1);
  assert.equal(ctx.elements[1].type, "email");
  assert.equal(ctx.elements[1].value, "a@b.co");
});

test("parses a JSON string form", () => {
  const ctx = parseStructuredPageContext(JSON.stringify(SAMPLE));
  assert.ok(ctx);
  assert.equal(ctx.elements[0].name, "Save");
});

test("rejects junk and malformed JSON", () => {
  assert.equal(parseStructuredPageContext("{not json"), null);
  assert.equal(parseStructuredPageContext(null), null);
  assert.equal(parseStructuredPageContext(42), null);
  assert.equal(parseStructuredPageContext([1, 2, 3]), null);
});

test("re-applies caps on oversized / malformed untrusted input", () => {
  const many = Array.from({ length: 500 }, (_unused, i) => ({
    role: "link",
    tag: "a",
    name: "x".repeat(1000),
    selector: "y".repeat(1000),
    value: "z".repeat(1000),
  }));
  const ctx = parseStructuredPageContext({ elements: many, landmarks: many });
  assert.ok(ctx);
  assert.equal(ctx.elements.length, 60); // capped
  assert.equal(ctx.landmarks.length, 25); // capped
  assert.ok(ctx.elements[0].name.length <= 120);
  assert.ok(ctx.elements[0].selector.length <= 120);
  assert.ok((ctx.elements[0].value ?? "").length <= 80);
  // counts fall back to actual array lengths when absent.
  assert.equal(ctx.counts.elements, 60);
});

test("never emits lone surrogates (caps split pairs, crafted input smuggles them)", () => {
  // Every cap boundary lands mid-surrogate-pair (emoji = 2 UTF-16 code units).
  const ctx = parseStructuredPageContext({
    lang: "\uD800", // lone high surrogate passed through outright
    elements: [
      {
        role: "button",
        tag: "button",
        name: "x".repeat(119) + "\u{1F600}more",
        selector: "s".repeat(119) + "\u{1F600}",
        type: "t".repeat(23) + "\u{1F600}",
        value: "v".repeat(79) + "\u{1F600}",
      },
    ],
    landmarks: [{ role: "navigation", tag: "nav", name: "orphan low \uDC00" }],
  });
  assert.ok(ctx);
  const el = ctx.elements[0];
  assert.equal(el.name.length, 120); // still capped, U+FFFD in place of the split pair
  for (const s of [ctx.lang, el.name, el.selector, el.type ?? "", el.value ?? "", ctx.landmarks[0].name]) {
    assert.ok(s.isWellFormed(), `ill-formed output: ${JSON.stringify(s)}`);
  }
  // The rendered tool-result text must survive UTF-8 encoding end-to-end.
  assert.ok(summarizePageContext(ctx).isWellFormed());
});

test("sanitizes lone-surrogate escapes in crafted JSON string input", () => {
  const ctx = parseStructuredPageContext('{"lang": "\\ud800en", "elements": [], "landmarks": []}');
  assert.ok(ctx);
  assert.equal(ctx.lang, "�en");
});

test("drops non-string/garbage fields safely", () => {
  const ctx = parseStructuredPageContext({
    lang: 123,
    elements: [{ role: 5, tag: null, name: {}, selector: undefined, disabled: "yes" }],
  });
  assert.ok(ctx);
  assert.equal(ctx.lang, "");
  assert.equal(ctx.elements[0].role, "");
  assert.equal(ctx.elements[0].name, "");
  assert.equal(ctx.elements[0].disabled, undefined); // only literal true sets it
});

test("summarize produces a compact, stable string", () => {
  const ctx = parseStructuredPageContext(SAMPLE) as StructuredPageContext;
  const text = summarizePageContext(ctx);
  assert.match(text, /2 interactive, 1 landmarks/);
  assert.match(text, /lang=en/);
  assert.match(text, /\[nav\/navigation\] Primary/);
  assert.match(text, /<button> Save @ #save/);
  assert.match(text, /<textbox> Email type=email @ input\[name="email"\]/);
});
