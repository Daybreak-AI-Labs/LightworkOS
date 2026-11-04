"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const {shell} = require('./_shell');
const base = path.resolve(__dirname, "../../maverick_dashboard");
const html = fs.readFileSync(path.join(base, "templates/flow_run.html"), "utf8");
const scriptPath = path.join(base, "static/lightwork-learning-example.js");
const source = fs.existsSync(scriptPath) ? fs.readFileSync(scriptPath, "utf8") : "";
const tick = () => new Promise(resolve => setImmediate(resolve));
const accepted = (extra = {}) => ({ id: "LAE-" + "a".repeat(32), revision: 3, status: "accepted",
  audit_status: "delivered", episode_sha256: "b".repeat(64), review_sha256: "c".repeat(64),
  withdrawal_available: true, ...extra });
const reply = (status, body) => ({ ok: status >= 200 && status < 300, status,
  json: async () => body });
async function harness(first = reply(200, accepted())) {
  const rendered = html.replace(/{{ flow_id }}/g, "orders").replace(/{{ run_id }}/g, "run-42");
  const dom = new JSDOM(rendered, { url: "http://localhost/flows/orders/runs/run-42", runScripts: "outside-only" });
  const calls = [], pending = [];
  dom.window.fetch = (url, options) => {
    calls.push({ url, options });
    return new Promise((resolve, reject) => pending.push({ resolve, reject }));
  };
  shell(dom.window);
  dom.window.eval(source);
  const get = id => dom.window.document.getElementById("le-" + id);
  assert.ok(get("card"), "The actual run template must contain the learning example card.");
  assert.equal(calls.length, 1, "Maintenance reads must start independently of ordinary run polling.");
  if (first !== null) { pending[0].resolve(first); await tick(); await tick(); }
  return { dom, calls, pending, get, text: () => get("card").textContent,
    open(reason = "This example no longer applies.") {
      get("withdraw").click(); get("reason").value = reason;
      get("reason").dispatchEvent(new dom.window.Event("input"));
    },
    submit() { get("form").dispatchEvent(new dom.window.Event("submit", { cancelable: true })); },
    async settle(index, response) { pending[index].resolve(response); await tick(); await tick(); }
  };
}
test("actual run template mounts a separate shared-glass learning card and external script", () => {
  assert.match(html, /id="le-card"/);
  assert.match(html, /class="panel[^"]*"[^>]*id="le-card"|id="le-card"[^>]*class="panel/);
  assert.match(html, /lightwork-learning-example\.js/);
  assert.match(html, /data-draft-recovery="off"/);
});
test("loading and exact maintenance path are independent of workflow execution reads", async () => {
  const h = await harness(null);
  assert.match(h.text(), /Checking/);
  assert.equal(h.get("card").hidden, false);
  assert.equal(h.calls[0].url, "/api/v1/flows/orders/runs/run-42/episode-capture/withdrawal");
  assert.equal(h.calls[0].options.credentials, "same-origin");
  assert.equal(h.get("withdraw").hidden, true);
  await h.settle(0, reply(200, accepted())); h.dom.window.close();
});
test("only an initially missing record hides the card", async () => {
  const h = await harness(reply(404, {detail:"internal missing source"}));
  assert.equal(h.get("card").hidden, true); assert.doesNotMatch(h.text(), /internal/);
  h.dom.window.close();
});
for (const status of [401, 403, 409, 500, 503]) test("initial HTTP " + status + " stays visible without echoing server details", async () => {
  const h = await harness(reply(status, {detail:"private stack or customer value"}));
  assert.equal(h.get("card").hidden, false); assert.equal(h.get("withdraw").hidden, true);
  assert.doesNotMatch(h.text(), /private stack|customer value|withdrawn|Use stopped/);
  assert.equal(h.get("refresh").disabled, false); h.dom.window.close();
});
for (const response of [reply(503, {status:"audit_pending",committed_status:"withdrawn"}),
    reply(503, {detail:{status:"audit_pending"}}),
    reply(200, accepted({status:"audit_pending",committed_status:"withdrawn",audit_status:"pending"}))]) {
  test("pending delivery does not become withdrawal success", async () => {
    const h = await harness(response); assert.match(h.text(), /Waiting|confirm/);
    assert.doesNotMatch(h.text(), /Use stopped/); assert.equal(h.get("withdraw").hidden, true);
    assert.equal(h.get("refresh").disabled, false); h.dom.window.close();
  });
}
for (const [status, label] of [["withdrawn","Use stopped"],["expired","Expired"],["rejected","Not accepted"],
    ["awaiting_review","Needs review"],["unusable","Not usable"],["paused","Being collected"]]) {
  test("readable nonaccepted state " + status + " has no withdrawal action", async () => {
    const h = await harness(reply(200, accepted({status,withdrawal_available:false})));
    assert.match(h.text(), new RegExp(label)); assert.equal(h.get("withdraw").hidden, true); h.dom.window.close();
  });
}
for (const extra of [{withdrawal_available:1}, {withdrawal_available:"true"}, {revision:1.5},
  {episode_sha256:"bad"}, {review_sha256:"bad"}, {audit_status:"unknown"}, {status:"invented"},
  {status:"__proto__"}, {id:null}]) {
  test("invalid or nonliteral readiness never authorizes submission " + JSON.stringify(extra), async () => {
    const h = await harness(reply(200, accepted(extra)));
    assert.equal(h.get("withdraw").hidden, true); h.submit(); assert.equal(h.calls.length, 1); h.dom.window.close();
  });
}
test("explicit reason and confirmation send current hidden bindings once, then actual withdrawn readback", async () => {
  const h = await harness();
  h.open("The business requirement changed.");
  assert.equal(h.dom.window.document.activeElement, h.get("reason"));
  assert.match(h.text(), /future/); assert.match(h.text(), /downloads/);
  assert.doesNotMatch(h.text(), /bbbbbbbb|cccccccc|LAE-/);
  h.submit(); h.submit(); h.get("refresh").click();
  assert.equal(h.calls.length, 2);
  const request = h.calls[1];
  assert.equal(request.url, "/api/v1/flows/orders/runs/run-42/episode-capture/withdraw");
  assert.deepEqual(JSON.parse(request.options.body), {expected_revision:3,expected_episode_sha256:"b".repeat(64),
    expected_review_sha256:"c".repeat(64),withdraw:true,rationale:"The business requirement changed."});
  assert.equal(h.get("confirm").disabled, true);
  await h.settle(1, reply(200, accepted({status:"withdrawn",revision:4,withdrawal_available:false})));
  assert.match(h.text(), /Use stopped/); assert.equal(h.get("form").hidden,true);
  assert.equal(h.get("reason").value,"");
  assert.equal(h.dom.window.document.activeElement,h.get("refresh")); h.dom.window.close();
});
test("blank or oversized reason stays local with field error and focus", async () => {
  const h = await harness(); h.open("   "); h.submit();
  assert.equal(h.calls.length,1); assert.equal(h.get("reason").getAttribute("aria-invalid"),"true");
  assert.equal(h.dom.window.document.activeElement,h.get("reason"));
  assert.match(h.get("error").textContent,/reason/);
  h.get("reason").value="x".repeat(2001); h.submit(); assert.equal(h.calls.length,1); h.dom.window.close();
});
test("cancel and Escape preserve an unsent reason and restore invoker focus", async () => {
  const h = await harness(); h.open("Keep my reason."); h.get("cancel").click();
  assert.equal(h.get("form").hidden,true); assert.equal(h.get("reason").value,"Keep my reason.");
  assert.equal(h.dom.window.document.activeElement,h.get("withdraw"));
  h.get("withdraw").click(); h.get("form").dispatchEvent(new h.dom.window.KeyboardEvent("keydown",{key:"Escape",bubbles:true}));
  assert.equal(h.get("form").hidden,true); assert.equal(h.calls.length,1); h.dom.window.close();
});
test("409 refresh preserves rationale and requires a new deliberate submit using refreshed revision", async () => {
  const h=await harness(); h.open("Review this changed example."); h.submit();
  await h.settle(1,reply(409,{detail:"raw sensitive conflict"}));
  assert.equal(h.calls.length,3); assert.equal(h.calls[2].options.method,"GET");
  await h.settle(2,reply(200,accepted({revision:8})));
  assert.equal(h.get("reason").value,"Review this changed example.");
  assert.equal(h.get("form").hidden,false); assert.match(h.get("message").textContent,/Review|confirm/);
  assert.doesNotMatch(h.text(),/raw sensitive/); assert.equal(h.calls.length,3);
  h.submit(); assert.equal(JSON.parse(h.calls[3].options.body).expected_revision,8);
  await h.settle(3,reply(503,{status:"audit_pending",committed_status:"withdrawn"}));
  assert.doesNotMatch(h.text(),/Use stopped/); assert.equal(h.get("confirm").disabled,true); h.dom.window.close();
});
test("lost POST response reads current state without replaying the mutation", async () => {
  const h=await harness(); h.open(); h.submit(); h.pending[1].reject(new Error("secret request failure"));
  await tick(); await tick(); assert.equal(h.calls.length,3); assert.equal(h.calls[2].options.method,"GET");
  await h.settle(2,reply(200,accepted({status:"withdrawn",revision:4,withdrawal_available:false})));
  assert.match(h.text(),/Use stopped/); assert.equal(h.calls.filter(c=>c.options.method==="POST").length,1);
  assert.doesNotMatch(h.text(),/secret request/); h.dom.window.close();
});
test("failed uncertain readback cannot hide a known example or authorize another mutation", async () => {
  const h=await harness(); h.open("Keep this after uncertainty."); h.submit();
  h.pending[1].reject(new Error("network")); await tick(); await tick();
  await h.settle(2,reply(404,{}));
  assert.equal(h.get("card").hidden,false); assert.equal(h.get("reason").value,"Keep this after uncertainty.");
  assert.equal(h.get("confirm").disabled,true); assert.doesNotMatch(h.text(),/Use stopped/); h.dom.window.close();
});
test("unexpected successful POST data requires readback instead of inventing success", async () => {
  const h=await harness(); h.open(); h.submit();
  await h.settle(1,reply(200,accepted()));
  assert.equal(h.calls.length,3); assert.doesNotMatch(h.text(),/Use stopped/);
  await h.settle(2,reply(403,{})); assert.equal(h.get("confirm").disabled,true); h.dom.window.close();
});
test("initial network failure offers a safe refresh and never renders error details", async () => {
  const h=await harness(null); h.pending[0].reject(new Error("sensitive endpoint"));
  await tick(); await tick(); assert.equal(h.get("card").hidden,false);
  assert.equal(h.get("refresh").disabled,false); assert.doesNotMatch(h.text(),/sensitive/);
  h.get("refresh").click(); await h.settle(1,reply(200,accepted()));
  assert.equal(h.get("withdraw").hidden,false); h.dom.window.close();
});
for (const body of [{status:"withdrawn",audit_status:"delivered"},
  accepted({status:"withdrawn",revision:0}), accepted({status:"withdrawn",id:"invalid"})]) {
  test("malformed withdrawn metadata does not confirm success " + JSON.stringify(body), async () => {
    const h=await harness(reply(200,body));
    assert.match(h.text(),/Status unavailable/); assert.doesNotMatch(h.text(),/Use stopped/);
    assert.equal(h.get("withdraw").hidden,true); h.dom.window.close();
  });
}
test("a later readback for a different record cannot confirm withdrawal", async () => {
  const h=await harness(); h.open("Keep this reason."); h.submit();
  h.pending[1].reject(new Error("lost response")); await tick(); await tick();
  await h.settle(2,reply(200,accepted({id:"LAE-"+"d".repeat(32),status:"withdrawn",revision:4})));
  assert.match(h.text(),/Status unavailable/); assert.doesNotMatch(h.text(),/Use stopped/);
  assert.equal(h.get("reason").value,"Keep this reason."); assert.equal(h.get("confirm").disabled,true);
  h.dom.window.close();
});

function loseDisabledFocus(h, control) {
  assert.equal(control.disabled, true);
  // JSDOM does not reproduce Chromium's loss of focus on disabled controls.
  const body=h.dom.window.document.body; body.tabIndex=-1; body.focus();
  assert.equal(h.dom.window.document.activeElement,body);
}
test("pending submit moves focus to Refresh after controls re-enable", async () => {
  const h=await harness(); h.open("Keep the pending reason.");
  h.get("confirm").focus(); h.submit();
  // Browsers can move focus to the body when the active control becomes disabled.
  loseDisabledFocus(h,h.get("confirm"));
  await h.settle(1,reply(503,{status:"audit_pending",committed_status:"withdrawn"}));
  assert.equal(h.get("refresh").disabled,false);
  assert.equal(h.get("confirm").disabled,true);
  assert.equal(h.get("form").hidden,false);
  assert.equal(h.get("reason").value,"Keep the pending reason.");
  assert.equal(h.dom.window.document.activeElement,h.get("refresh"));
  h.dom.window.close();
});
test("unavailable submit readback restores Refresh focus after controls re-enable", async () => {
  const h=await harness(); h.open(); h.get("confirm").focus(); h.submit(); loseDisabledFocus(h,h.get("confirm"));
  await h.settle(1,reply(503,{detail:{status:"audit_unavailable"}}));
  await h.settle(2,reply(503,{detail:{status:"audit_unavailable"}}));
  assert.equal(h.get("refresh").disabled,false);
  assert.equal(h.dom.window.document.activeElement,h.get("refresh"));
  h.dom.window.close();
});
for (const outcome of ["ready","pending","denied","network"]) {
  test("user Refresh restores its focus after " + outcome + " response", async () => {
    const h=await harness(); h.get("refresh").focus(); h.get("refresh").click();
    loseDisabledFocus(h,h.get("refresh"));
    if (outcome === "network") {
      h.pending[1].reject(new Error("network")); await tick(); await tick();
    } else {
      const response = outcome === "ready" ? reply(200,accepted())
        : outcome === "pending" ? reply(503,{status:"audit_pending"})
        : reply(403,{detail:"denied"});
      await h.settle(1,response);
    }
    assert.equal(h.get("refresh").disabled,false);
    assert.equal(h.dom.window.document.activeElement,h.get("refresh"));
    h.dom.window.close();
  });
}
test("initial automatic status read does not move focus from another control", async () => {
  const h=await harness(null);
  const elsewhere=h.dom.window.document.getElementById("fr-designer-link");
  elsewhere.focus();
  await h.settle(0,reply(200,accepted()));
  assert.equal(h.dom.window.document.activeElement,elsewhere);
  h.dom.window.close();
});
