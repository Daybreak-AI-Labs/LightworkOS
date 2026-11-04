"use strict";

const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {JSDOM} = require("jsdom");

const template = fs.readFileSync(path.resolve(__dirname,
  "../../maverick_dashboard/templates/agents.html"), "utf8");
const marker = "    // ---- departments roster (real: /api/v1/departments + deploy) ----";
const start = template.indexOf("    (function () {", template.indexOf(marker));
const end = template.indexOf("    })();", start) + "    })();".length;
const source = template.slice(start, end);

async function flush() {
  for (let i = 0; i < 5; i += 1) await new Promise(resolve => setTimeout(resolve, 0));
}

test("both Agent Factory deploy paths open the exact team's reviewed setup", async () => {
  const dom = new JSDOM(`<div id="dept-roster"></div>
    <dialog id="dept-dialog">
      <span id="dept-dlg-avatar"></span><span id="dept-dlg-title"></span>
      <span id="dept-dlg-sub"></span><span id="dept-dlg-charter"></span>
      <ul id="dept-dlg-members"></ul><button id="dept-dlg-close"></button>
      <button id="dept-dlg-deploy"></button>
      <p id="dept-dlg-msg" role="status"></p>
    </dialog>`, {url: "https://lightwork.test/agents", runScripts: "outside-only"});
  const w = dom.window;
  let dialogOpen = false;
  w.document.getElementById("dept-dialog").showModal = () => { dialogOpen = true; };
  w.document.getElementById("dept-dialog").close = () => { dialogOpen = false; };
  w.mvConfirm = async () => true;
  const fetched = [];
  w.fetch = async url => {
    fetched.push(String(url));
    return {ok: true, json: async () => [{key: "sales", title: "Sales", entitled: true, members: ["sales_ops"]}]};
  };
  w.eval(source);
  await flush();
  const roster = w.document.getElementById("dept-roster");

  // Without the team review loaded, neither path saves a team behind the person's back.
  roster.querySelector(".dep-deploy").click();
  await flush();
  assert.match(roster.querySelector(".dep-msg").textContent, /team review could not load/);
  assert.deepEqual(fetched, ["/api/v1/departments"]);

  // Team setup now goes through the complete before-and-after review.
  const opened = [];
  w.LWDepartmentTeamUpdates = {open: async (key, origin) => { opened.push([key, origin]); }};
  roster.querySelector(".dep-deploy").click();
  await flush();
  assert.deepEqual(opened.map(([key]) => key), ["sales"]);
  assert.equal(opened[0][1], roster.querySelector(".dep-deploy"));

  roster.querySelector(".dep-details").click();
  assert.equal(dialogOpen, true);
  w.document.getElementById("dept-dlg-deploy").click();
  await flush();
  assert.equal(dialogOpen, false, "the details dialog hands over to the team review");
  assert.deepEqual(opened.map(([key]) => key), ["sales", "sales"]);
  assert.equal(opened[1][1], roster.querySelector(".dep-details"), "focus returns to the team that was reviewed");
  assert.deepEqual(fetched, ["/api/v1/departments"], "no team is deployed without its review");
  w.close();
});
