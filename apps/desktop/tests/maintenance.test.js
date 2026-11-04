const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function node() {
  return { textContent: "", value: "", hidden: false, disabled: false, className: "", handlers: {}, children: [],
    addEventListener(name, handler) { this.handlers[name] = handler; },
    appendChild(child) { this.children.push(child); } };
}
function render(invoke, extra = {}) {
  const elements = Object.fromEntries([
    "installed-version", "maintenance-status", "maintenance-details", "check-update",
    "repair-install", "install-update", "update-review", "update-version", "update-notes", "back",
    "maintenance-authorization", "maintenance-incomplete", "maintenance-recovery-result", "rollback-install", "resume-maintenance",
    "maintenance-logs", "maintenance-log-point",
    "identity-transition-notice", "save-identity-transition",
    "maintenance-authorization-hint", "paste-authorization", "clear-authorization", "update-steps", "repair-steps",
    "maintenance-details-copy", "maintenance-details-save", "maintenance-details-copied",
    "load-handoff", "offline-folder", "offline-review", "offline-details", "offline-install",
    "planner-point", "planner-load", "planner-next", "planner-save", "planner-repair", "planner-workspace", "planner-details",
  ].map(id => [id, node()]));
  const context = { document: { getElementById: id => elements[id], createElement: () => ({}) },
    window: { __TAURI__: { core: { invoke } }, location: { replace() {} } },
    setInterval() {}, setTimeout() {}, ...extra };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../ui/maintenance.js"), "utf8"), context);
  return elements;
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test("maintenance checks never install without an explicit review action", async () => {
  const calls = [];
  const elements = render(async (command, payload) => {
    calls.push([command, payload]);
    if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true };
    if (command === "check_desktop_update") return {
      review: "7", version: "1.0.1", current_version: "1.0.0", notes: "<img src=x onerror=bad()>", repair: false,
    };
  });
  await settle();
  await elements["check-update"].handlers.click();
  assert.equal(calls.length, 2);
  assert.equal(elements["update-notes"].textContent, "<img src=x onerror=bad()>");
  assert.equal(elements["install-update"].disabled, true);
  elements["maintenance-authorization"].value = "a".repeat(32) + ":" + "b".repeat(64);
  elements["maintenance-authorization"].handlers.input();
  await elements["install-update"].handlers.click();
  assert.equal(calls[2][0], "install_desktop_update");
  assert.deepEqual(JSON.parse(JSON.stringify(calls[2][1])), { review: "7", confirm: true, authorization: "a".repeat(32) + ":" + "b".repeat(64) });
});

test("unconfigured customer channel cannot offer a pretend update or repair", async () => {
  const elements = render(async () => ({ version: "1.0.0", updates_configured: false }));
  await settle();
  assert.equal(elements["check-update"].disabled, true);
  assert.equal(elements["repair-install"].disabled, true);
  assert.match(elements["maintenance-status"].textContent, /administrator/);
});

test("failed install discards the stale review and permits a fresh check", async () => {
  const elements = render(async command => {
    if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true };
    if (command === "check_desktop_update") return { review: "1", version: "1.0.0", repair: true, notes: "" };
    throw new Error("signature mismatch");
  });
  await settle();
  await elements["repair-install"].handlers.click();
  await elements["install-update"].handlers.click();
  assert.equal(elements["update-review"].hidden, true);
  assert.equal(elements["check-update"].disabled, false);
  assert.match(elements["maintenance-status"].textContent, /could not/);
  assert.match(elements["maintenance-details"].textContent, /signature mismatch/);
});

test("double clicks cannot queue another maintenance operation", async () => {
  let finish;
  let checks = 0;
  const elements = render(async command => {
    if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true };
    checks += 1;
    return new Promise(resolve => { finish = resolve; });
  });
  await settle();
  const pending = elements["check-update"].handlers.click();
  await elements["repair-install"].handlers.click();
  assert.equal(checks, 1);
  finish(null);
  await pending;
});

test("identity transition is disclosed but cannot install without the separately reviewed authorization", async () => {
  const calls = [];
  const elements = render(async command => {
    calls.push(command);
    if (command === "maintenance_status") return { version:"1.0.0",updates_configured:true };
    return { review:"bridge-1",version:"1.0.1",repair:false,identity_transition:{policy:{id:"synthetic-pending-review"}} };
  });
  await settle();await elements["check-update"].handlers.click();
  assert.equal(elements["identity-transition-notice"].hidden,false);
  assert.equal(elements["save-identity-transition"].hidden,false);
  assert.equal(elements["install-update"].disabled,true);
  await elements["install-update"].handlers.click();
  assert.deepEqual(calls,["maintenance_status","check_desktop_update"]);
});

test("repair cannot turn transition metadata into a trust-adopting installation", async () => {
  const elements = render(async command => command === "maintenance_status" ? {version:"1.0.0",updates_configured:true} :
    {review:"bad-repair",version:"1.0.0",repair:true,identity_transition:{policy:{}}});
  await settle();await elements["repair-install"].handlers.click();
  assert.equal(elements["install-update"].disabled,true);
  assert.equal(elements["update-review"].hidden,true);
  assert.match(elements["maintenance-status"].textContent, /could not complete that step/);
  assert.match(elements["maintenance-details"].textContent, /signing transition/);
  assert.equal(elements["repair-install"].disabled,false);
});

test("completed and pending repair receipts use end-user repair language", async () => {
  const elements = render(async () => ({
    version: "1.0.0",
    updates_configured: true,
    recovery: {
      recovery_points: [
        { id: "done", old_version: "1.0.0", new_version: "1.0.0", status: "repaired", pending_finalization: false },
        { id: "resume", old_version: "1.0.0", new_version: "1.0.0", status: "repair_recovered", pending_finalization: true },
        { id: "upgrade-recovered", old_version: "1.0.0", new_version: "1.1.0", status: "upgrade_recovered", pending_finalization: false },
      ],
    },
  }));
  await settle();
  assert.match(elements["maintenance-recovery-result"].textContent, /repaired 1\.0\.0/);
  assert.match(elements["maintenance-recovery-result"].textContent, /returned to 1\.0\.0/);
  assert.equal(elements["maintenance-incomplete"].children.length, 1);
  assert.match(elements["maintenance-incomplete"].children[0].textContent, /needs finishing/);
});

test("unfinished maintenance offers recovery language instead of candidate replay", async () => {
  const elements = render(async () => ({
    version: "1.1.0",
    updates_configured: true,
    recovery: {
      incomplete: true,
      recovery_points: [
        { id: "failed", old_version: "1.0.0", new_version: "1.1.0", status: "incomplete", pending_finalization: true },
      ],
    },
  }));
  await settle();
  assert.equal(elements["resume-maintenance"].textContent, "Recover and restart");
  assert.match(elements["maintenance-recovery-result"].textContent, /Recover and restart to put back the last working version/);
  assert.match(elements["maintenance-status"].textContent, /Finish it under Go back to the previous version/);
});

const CODE = "a".repeat(32) + ":" + "b".repeat(64);
const updateStatus = async command => {
  if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true };
  if (command === "check_desktop_update") return { review: "7", version: "1.0.1", repair: false, notes: "" };
};

test("approval code forgives stray spaces and line breaks but still checks the full format", async () => {
  const calls = [];
  const elements = render(async (command, payload) => { calls.push([command, payload]); return updateStatus(command); });
  await settle();
  assert.match(elements["maintenance-authorization-hint"].textContent, /No code yet/);
  await elements["check-update"].handlers.click();
  assert.equal(elements["update-steps"].hidden, false);
  assert.equal(elements["repair-steps"].hidden, true);
  elements["maintenance-authorization"].value = CODE.slice(0, 60);
  elements["maintenance-authorization"].handlers.input();
  assert.equal(elements["install-update"].disabled, true);
  assert.equal(elements["rollback-install"].disabled, true);
  assert.match(elements["maintenance-authorization-hint"].textContent, /isn't a complete approval code/);
  assert.match(elements["maintenance-authorization-hint"].className, /bad/);
  elements["maintenance-authorization"].value = "  " + CODE.slice(0, 50) + "\n" + CODE.slice(50) + " \r\n";
  elements["maintenance-authorization"].handlers.input();
  assert.equal(elements["install-update"].disabled, false);
  assert.match(elements["maintenance-authorization-hint"].textContent, /Code ready/);
  await elements["install-update"].handlers.click();
  assert.deepEqual(JSON.parse(JSON.stringify(calls.at(-1))), ["install_desktop_update", { review: "7", confirm: true, authorization: CODE }]);
  assert.equal(elements["maintenance-authorization"].value, "");
});

test("paste button fills the code from the clipboard and clear removes it", async () => {
  const elements = render(updateStatus, { navigator: { clipboard: { readText: async () => "\n" + CODE + "\n" } } });
  await settle();
  await elements["paste-authorization"].handlers.click();
  assert.equal(elements["maintenance-authorization"].value, CODE);
  assert.equal(elements["rollback-install"].disabled, false);
  elements["clear-authorization"].handlers.click();
  assert.equal(elements["maintenance-authorization"].value, "");
  assert.equal(elements["rollback-install"].disabled, true);
});

test("paste explains the keyboard fallback when the clipboard cannot be read", async () => {
  const elements = render(updateStatus, { navigator: { clipboard: { readText: async () => { throw new Error("denied"); } } } });
  await settle();
  await elements["paste-authorization"].handlers.click();
  assert.match(elements["maintenance-authorization-hint"].textContent, /Ctrl\+V/);
  assert.equal(elements["maintenance-authorization"].value, "");
});

test("an expired approval code gets a plain next step and the raw reason stays in support details", async () => {
  const elements = render(async command => {
    if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true };
    throw "This maintenance authorization expired or was already used. Review it again in Workspace recovery.";
  });
  await settle();
  elements["maintenance-authorization"].value = CODE;
  elements["maintenance-authorization"].handlers.input();
  await elements["rollback-install"].handlers.click();
  assert.match(elements["maintenance-status"].textContent, /^Lightwork could not complete that step\. The approval code has expired/);
  assert.doesNotMatch(elements["maintenance-status"].textContent, /authorization/);
  assert.match(elements["maintenance-authorization-hint"].textContent, /get a new one|Get a new one/);
  assert.match(elements["maintenance-details"].textContent, /maintenance authorization expired/);
});

test("repair review hides the approval steps and saved history uses plain labels", async () => {
  const elements = render(async command => {
    if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true, recovery: { recovery_points: [
      { id: "a", old_version: "1.0.0", new_version: "1.1.0", status: "upgrade_recovered", pending_finalization: false },
    ] } };
    return { review: "r", version: "1.0.0", repair: true, notes: "" };
  });
  await settle();
  assert.equal(elements["maintenance-log-point"].children[0].textContent, "1.0.0 → 1.1.0 · returned to the previous version");
  await elements["repair-install"].handlers.click();
  assert.equal(elements["update-steps"].hidden, true);
  assert.equal(elements["repair-steps"].hidden, false);
  assert.equal(elements["install-update"].disabled, false);
  const page = fs.readFileSync(path.join(__dirname, "../ui/maintenance.html"), "utf8");
  for (const phrase of ["dual-signed", "signing trust", "pre-upgrade", "exact-release", "Troubleshooting details"]) {
    assert.equal(page.includes(phrase), false, phrase);
  }
});

const approval = operation => ({ actor_label: "An administrator", operation, expires_at: Math.floor(Date.now() / 1000) + 600,
  scope: "This installation only.", old_version: "1.0.0", new_version: "1.0.1" });

test("a rollback that used the protected approval no longer shows it as loaded", async () => {
  const calls = [];
  const elements = render(async command => {
    calls.push(command);
    if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true };
    if (command === "review_maintenance_handoff") return approval("rollback");
    throw new Error("the installer could not be started");
  });
  await settle();
  await elements["load-handoff"].handlers.click();
  assert.equal(elements["rollback-install"].disabled, false);
  await elements["rollback-install"].handlers.click();
  assert.ok(calls.includes("rollback_desktop_update"));
  assert.equal(elements["rollback-install"].disabled, true);
  assert.match(elements["maintenance-authorization-hint"].textContent, /No code yet/);
  await elements["rollback-install"].handlers.click();
  assert.equal(calls.filter(command => command === "rollback_desktop_update").length, 1);
});

test("an upgrade that used the protected approval needs it loaded again before a retry", async () => {
  const elements = render(async command => {
    if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true, reviewed_update: { review: "7", version: "1.0.1", notes: "" } };
    if (command === "review_maintenance_handoff") return approval("upgrade");
    if (command === "check_desktop_update") return { review: "7", version: "1.0.1", repair: false, notes: "" };
    throw new Error("the download failed");
  });
  await settle();
  await elements["check-update"].handlers.click();
  await elements["load-handoff"].handlers.click();
  assert.equal(elements["install-update"].disabled, false);
  await elements["install-update"].handlers.click();
  assert.match(elements["maintenance-details"].textContent, /download failed/);
  assert.equal(elements["install-update"].disabled, true);
  assert.match(elements["maintenance-authorization-hint"].textContent, /No code yet/);
});

test("a repair keeps the protected approval, which it never uses", async () => {
  const elements = render(async command => {
    if (command === "maintenance_status") return { version: "1.0.0", updates_configured: true };
    if (command === "review_maintenance_handoff") return approval("rollback");
    if (command === "check_desktop_update") return { review: "1", version: "1.0.0", repair: true, notes: "" };
    throw new Error("signature mismatch");
  });
  await settle();
  await elements["load-handoff"].handlers.click();
  await elements["repair-install"].handlers.click();
  await elements["install-update"].handlers.click();
  assert.equal(elements["rollback-install"].disabled, false);
});

