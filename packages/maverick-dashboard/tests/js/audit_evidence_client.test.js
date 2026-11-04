"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function scriptFor(file, marker) {
  const template = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates", file), "utf8");
  const script = [...template.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1]).find(source => source.includes(marker));
  assert.ok(script, `${file} must contain its client script`);
  return script;
}

test("binder download preserves the exact signed JSON values without numeric reserialization", async () => {
  // Python distinguishes these integral floats and the integer outside JS's
  // exact range when computing its advertised sorted-JSON artifact digest.
  const original = '{"generated_at":1780000000.0,"amount":1.0,"id":9007199254740993,"artifact":{"binder_id":"sample"}}';
  let click;
  let exported;
  const source = { textContent: original };
  const button = { addEventListener: (_name, callback) => { click = callback; } };
  const link = { click() {}, remove() {} };
  const document = {
    getElementById: id => id === "binder-json" ? button :
      ["binder-print", "binder-days"].includes(id) ? { addEventListener() {} } : source,
    createElement: () => link,
    body: { appendChild() {} },
  };
  vm.runInNewContext(scriptFor("audit_binder.html", "binder-json"), {
    document, Blob,
    URL: { createObjectURL: blob => { exported = blob; return "blob:synthetic"; }, revokeObjectURL() {} },
  });
  click();
  assert.equal(await exported.text(), original + "\n");
  assert.equal(link.download, "lightwork-audit-binder-sample.json");
});

test("server-rendered audit search warns on partial reads even when no match can be returned", () => {
  const template = fs.readFileSync(path.resolve(__dirname, "../../maverick_dashboard/templates/audit.html"), "utf8");
  assert.match(template, /<form method="get" action="\/audit"[^>]*id="aud-filter"/);
  assert.match(template, /audit_read_report and audit_read_report\.failures/);
  assert.match(template, /role="alert">Some entries could not be read\. This view is incomplete/);
  assert.match(template, /No readable events are available in this tail/);
  assert.match(template, /this does not establish that no activity was recorded/);
});
