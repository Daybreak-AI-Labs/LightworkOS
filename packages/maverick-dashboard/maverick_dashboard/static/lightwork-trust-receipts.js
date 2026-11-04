// Trust receipts page: create a receipt for a recorded decision, check a
// receipt file, share this installation's key, and download or check a
// signed proof of how Lightwork behaved. Every answer is shown as a plain
// sentence; the raw report stays inside "Technical details".
(function () {
  "use strict";

  var root = document.getElementById("rcp-root");
  if (!root) { return; }
  var apiBase = root.dataset.apiBase || "/api/v1/audit/receipts";
  var maxBytes = 8 * 1024 * 1024;
  var hexPattern = /^[0-9a-f]{64}$/;
  var rows = document.getElementById("rcp-rows");
  var daySelect = document.getElementById("rcp-day");
  var kindSelect = document.getElementById("rcp-kind");
  var status = null;
  var loadedRows = null;

  var CLAIMS = {
    row_integrity: "The decision itself is unchanged",
    claim_consistency: "The receipt's summary matches the decision",
    disclosure: "Nothing private was left in",
    execution_pair: "The action and its result belong together",
    chain_linkage: "Nothing was removed after it",
    commitment: "It matches a published checkpoint",
    policy_envelope: "Agents stayed within your rules",
    bounded_self_improvement: "Learning never gave itself more power",
    authentic_history: "The activity record is complete and unchanged"
  };
  var STATUS = { HOLDS: "Passed", FAILS: "Failed", INDETERMINATE: "Couldn't check", NOT_APPLICABLE: "Not needed" };
  var STATUS_BADGE = { HOLDS: "ok", FAILS: "danger", INDETERMINATE: "warn", NOT_APPLICABLE: "idle" };
  var DEPTH = {
    signed: "The recorded row verifies against the issuer's key.",
    chained: "The recorded row is linked to a signed commitment.",
    anchored: "The commitment matches a separately supplied checkpoint.",
    corroborated: "The receipt matches this installation's current records.",
    unverified: "It could not be confirmed."
  };

  function human(value) {
    if (window.mvHuman) { return window.mvHuman(value); }
    var s = String(value || "").replace(/[_-]+/g, " ").trim();
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
  function errorText(failure, action) {
    return window.mvErrorText ? window.mvErrorText(failure, action) : "Could not " + action + ". Try again.";
  }
  function problem(message) { var e = new Error(message); e.plain = true; return e; }
  function say(id, text) { window.mvStatus(document.getElementById(id), text); }
  function explain(id, action) {
    return function (failure) { say(id, failure && failure.plain ? failure.message : errorText(failure, action)); };
  }

  // The page's requests carry a JSON string body; mvFetchJSON sends it as is.
  function settingsFor(options) {
    var settings = Object.assign({}, options || {});
    if (settings.body) { settings.headers = Object.assign({ "Content-Type": "application/json" }, settings.headers); }
    return settings;
  }
  async function json(path, options) {
    return window.mvFetchJSON(apiBase + path, settingsFor(options));
  }
  async function text(path, options) {
    var response = await window.mvFetchJSON(apiBase + path, Object.assign(settingsFor(options), { raw: true }));
    return { text: await response.text(), response: response };
  }

  function saveBlob(name, body, type) {
    var url = URL.createObjectURL(new Blob([body], { type: type }));
    var link = document.createElement("a");
    link.href = url; link.download = name;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  function when(ts) {
    var n = Number(ts);
    if (!isFinite(n) || n <= 0) { return "—"; }
    return window.mvTimeAbsolute(n);
  }

  function readFile(input, what) {
    var file = input.files && input.files[0];
    if (!file) { return Promise.reject(problem("Choose the " + what + " first.")); }
    if (file.size > maxBytes) { return Promise.reject(problem("That file is too large to be a Lightwork " + what + ". Choose the " + what + " file you were sent.")); }
    return file.text();
  }

  function mark(badge, word, title, detail) {
    var state = document.getElementById("rcp-state");
    state.className = "badge " + badge;
    state.textContent = word;
    say("rcp-health-title", title);
    say("rcp-health-detail", detail);
  }

  async function loadStatus() {
    status = await json("/status");
    say("rcp-key-id", status.key_id ? "Ready" : "Missing");
    say("rcp-custody", status.key_custody === "offhost" ? "Supplied from elsewhere; used here" : "On this computer");
    say("rcp-days", String(status.days.length));
    say("rcp-pubkey", status.pubkey || "There is no key yet.");
    say("rcp-verifier-sha", status.verifier_sha256 || "—");
    document.getElementById("rcp-signing-action").hidden = !!status.signing_enabled;
    if (!status.signing_enabled) {
      mark("danger", "Off", "Signing is off",
        "Activity is recorded without signatures, so receipts can't be created. An administrator can turn on the signed activity record.");
    } else if (!status.key_id) {
      mark("danger", "No key", "The signing key can't be found",
        "Receipts can't be created until the signing key is available. Ask your IT team to check it.");
    } else if (status.key_custody === "colocated") {
      mark("warn", "On", "Receipts are signed",
        "A process with access to this key can re-sign history. Retain checkpoints independently to detect later changes to committed records.");
    } else {
      mark("warn", "On", "Receipts are signed with an externally supplied key",
        "The signing process can still use this key to re-sign history. Retain checkpoints independently to detect later changes to committed records.");
    }
    daySelect.textContent = "";
    if (!status.days.length) {
      var none = document.createElement("option");
      none.value = ""; none.textContent = "No activity recorded yet";
      daySelect.appendChild(none);
    }
    status.days.forEach(function (day, index) {
      var option = document.createElement("option");
      option.value = day;
      var label = window.mvDateAbsolute(day) || day;
      option.textContent = label + (index === 0 ? " (latest)" : "");
      daySelect.appendChild(option);
    });
    return status;
  }

  function cell(value) {
    var td = document.createElement("td");
    if (value && value.nodeType) { td.appendChild(value); } else { td.textContent = value; }
    return td;
  }

  function renderRows() {
    rows.textContent = "";
    if (!loadedRows) { return; }
    var kind = kindSelect.value;
    var items = loadedRows.items.filter(function (row) { return !kind || row.kind === kind; });
    say("rcp-rows-note", items.length + " decision" + (items.length === 1 ? "" : "s") + " shown" +
      (loadedRows.truncated ? " (the latest " + loadedRows.items.length + " of " + loadedRows.total + ")" : "") + ".");
    if (!items.length) {
      var empty = document.createElement("tr");
      var td = cell("No decisions match. Choose another day or decision type.");
      td.colSpan = 5; empty.appendChild(td); rows.appendChild(empty);
      return;
    }
    items.slice().reverse().forEach(function (row) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(when(row.ts)));
      tr.appendChild(cell(human(row.kind) || "—"));
      tr.appendChild(cell(human(row.agent) || "—"));
      tr.appendChild(cell([row.decision ? human(row.decision) : "Recorded", row.tool ? human(row.tool) : ""].filter(Boolean).join(" · ")));
      if (row.signed) {
        var button = document.createElement("button");
        button.type = "button"; button.className = "btn";
        button.textContent = "Create receipt";
        button.setAttribute("aria-label", "Create a receipt for " + human(row.kind) + " at " + when(row.ts));
        button.addEventListener("click", function () {
          button.disabled = true;
          mint(loadedRows.day, row).catch(explain("rcp-mint-msg", "create the receipt"))
            .then(function () { button.disabled = false; });
        });
        tr.appendChild(cell(button));
      } else {
        tr.appendChild(cell("Can't create (recorded before signing was on)"));
      }
      rows.appendChild(tr);
    });
  }

  async function loadRows(day) {
    if (!day) { loadedRows = null; rows.textContent = ""; return; }
    say("rcp-rows-note", "Loading decisions…");
    loadedRows = await json("/rows?day=" + encodeURIComponent(day) + "&limit=500");
    var chosen = kindSelect.value;
    var kinds = {};
    loadedRows.items.forEach(function (row) { if (row.kind) { kinds[row.kind] = true; } });
    kindSelect.textContent = "";
    var all = document.createElement("option"); all.value = ""; all.textContent = "All decisions";
    kindSelect.appendChild(all);
    Object.keys(kinds).sort().forEach(function (kind) {
      var option = document.createElement("option");
      option.value = kind; option.textContent = human(kind);
      kindSelect.appendChild(option);
    });
    kindSelect.value = kinds[chosen] ? chosen : "";
    renderRows();
  }

  async function mint(day, row) {
    var anchor = document.getElementById("rcp-anchor").checked;
    if (anchor && !(await window.mvConfirm("Publish a checkpoint of the activity record? It is saved next to the record so others can confirm this receipt.", { okText: "Publish and create" }))) {
      return;
    }
    say("rcp-mint-msg", "Creating the receipt…");
    var body = { day: day, row_hash: row.hash, include_suffix: document.getElementById("rcp-suffix").checked, anchor: anchor };
    var result = await text("/mint", { method: "POST", body: JSON.stringify(body) });
    var name = "trust-receipt-" + day + "-" + row.position + ".json";
    saveBlob(name, result.text, "application/json");
    say("rcp-mint-msg", "Receipt saved as " + name + ". Send it together with our key.");
  }

  function renderVerdict(prefix, result, okWord, badWord) {
    var box = document.getElementById(prefix === "proof" ? "rcp-proof-box" : "rcp-verdict-box");
    var verdict = document.getElementById(prefix === "proof" ? "rcp-proof-verdict" : "rcp-verdict");
    var detail = document.getElementById(prefix === "proof" ? "rcp-proof-detail" : "rcp-verdict-detail");
    var claims = document.getElementById(prefix === "proof" ? "rcp-proof-claims" : "rcp-claims");
    var report = document.getElementById(prefix === "proof" ? "rcp-proof-report" : "rcp-report");
    box.hidden = false;
    verdict.textContent = result.ok ? okWord : badWord;
    verdict.dataset.ok = result.ok ? "true" : "false";
    detail.textContent = result.ok ? (DEPTH[result.depth] || "") :
      "It may have been changed, or it was signed with a key you haven't chosen to trust.";
    claims.textContent = "";
    (result.claims || []).forEach(function (claim) {
      var li = document.createElement("li");
      var badge = document.createElement("span");
      badge.className = "badge " + (STATUS_BADGE[claim.status] || "idle");
      badge.textContent = STATUS[claim.status] || human(claim.status);
      li.appendChild(badge);
      li.appendChild(document.createTextNode(" " + (CLAIMS[claim.name] || human(claim.name))));
      claims.appendChild(li);
    });
    report.textContent = result.report || "";
  }

  function keyFrom(inputId) {
    var key = String(document.getElementById(inputId).value || "").trim().toLowerCase();
    if (key && !hexPattern.test(key)) { throw problem("That key doesn't look right. Copy it again from the sender."); }
    return key;
  }

  async function checkReceipt() {
    var raw = String(await readFile(document.getElementById("rcp-file"), "receipt file")).trim();
    var parsed;
    try { parsed = JSON.parse(raw); } catch (_e) { throw problem("That file isn't a Lightwork receipt. Choose the receipt file you were sent."); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) { throw problem("That file isn't a Lightwork receipt. Choose the receipt file you were sent."); }
    // Sent verbatim: re-encoding would change number formatting and break the signature.
    var body = { receipt: raw, keys: [], use_local_keys: document.getElementById("rcp-local-keys").checked };
    var key = keyFrom("rcp-extra-key");
    if (key) { body.keys.push(key); }
    var code = String(document.getElementById("rcp-anchor-digest").value || "").trim().toLowerCase();
    if (code) {
      if (!hexPattern.test(code)) { throw problem("That checkpoint code doesn't look right. Copy it again."); }
      body.anchor_digest = code;
    }
    renderVerdict("receipt", await json("/verify", { method: "POST", body: JSON.stringify(body) }),
      "Receipt is genuine", "Receipt could not be verified");
  }

  async function downloadProof() {
    var since = document.getElementById("rcp-proof-since").value;
    say("rcp-proof-msg", "Preparing the signed proof…");
    var result = await text("/attestation", { method: "POST", body: JSON.stringify(since ? { since_day: since } : {}) });
    saveBlob("lightwork-proof.json", result.text, "application/json");
    say("rcp-proof-msg", "Proof saved as lightwork-proof.json. Send it together with our key.");
  }

  async function checkProof() {
    var raw = String(await readFile(document.getElementById("rcp-proof-file"), "proof file")).trim();
    try { JSON.parse(raw); } catch (_e) { throw problem("That file isn't a Lightwork proof file. Choose the proof file you were sent."); }
    var key = keyFrom("rcp-proof-key");
    var body = { bundle: raw, use_own_key: !key };
    if (key) { body.key = key; }
    say("rcp-proof-msg", "");
    renderVerdict("proof", await json("/attestation/verify", { method: "POST", body: JSON.stringify(body) }),
      "Proof is genuine", "Proof could not be verified");
  }

  async function withKey(use) {
    if (!status) { await loadStatus(); }
    if (!status.pubkey) { throw problem("There is no key to share yet. Turn on the signed activity record first."); }
    use(status.pubkey);
  }

  async function downloadChecker(path, name) {
    var result = await text(path);
    saveBlob(name, result.text, "text/x-python");
    var digest = result.response.headers.get("x-verifier-sha256");
    if (digest) { say("rcp-verifier-sha", digest); }
  }

  async function turnOnSigning() {
    if (!(await window.mvConfirm("Sign every entry in the activity record so any later change can be detected? New entries are signed after Lightwork restarts.", { okText: "Turn on" }))) { return; }
    var data = await window.mvFetchJSON("/api/v1/compliance/switches/signed_audit", { method: "POST" });
    say("rcp-signing-msg", data.active ? "Signing is on." : "Saved. Signing starts after Lightwork restarts.");
    await loadStatus();
  }

  function on(id, event, handler) {
    var el = document.getElementById(id);
    if (el) { el.addEventListener(event, handler); }
  }

  on("rcp-refresh", "click", function () { loadStatus().then(function () { return loadRows(daySelect.value); }).catch(explain("rcp-signing-msg", "refresh")); });
  on("rcp-turn-on-signing", "click", function () { turnOnSigning().catch(explain("rcp-signing-msg", "turn on signing")); });
  on("rcp-day", "change", function () { loadRows(daySelect.value).catch(explain("rcp-rows-note", "load that day's decisions")); });
  on("rcp-kind", "change", renderRows);
  on("rcp-rows-form", "submit", function (event) { event.preventDefault(); });
  on("rcp-copy-key", "click", function () { withKey(function (k) { window.mvCopy(k); }).catch(explain("rcp-signing-msg", "copy the key")); });
  on("rcp-download-key", "click", function () { withKey(function (k) { saveBlob("lightwork-key.txt", k + "\n", "text/plain"); }).catch(explain("rcp-signing-msg", "download the key")); });
  on("rcp-key-file", "click", function () {
    var input = document.createElement("input");
    input.type = "file"; input.accept = ".txt,.pub,.key,text/plain";
    input.addEventListener("change", function () {
      var f = input.files && input.files[0];
      if (!f) { return; }
      f.text().then(function (t) {
        var m = String(t).match(/[0-9a-fA-F]{64}/);
        if (m) { document.getElementById("rcp-extra-key").value = m[0].toLowerCase(); }
        else { say("rcp-verdict-detail", "That file doesn't contain a key."); document.getElementById("rcp-verdict-box").hidden = false; }
      });
    });
    input.click();
  });
  on("rcp-verify-form", "submit", function (event) {
    event.preventDefault();
    checkReceipt().catch(function (failure) {
      document.getElementById("rcp-verdict-box").hidden = false;
      say("rcp-verdict", "Not checked");
      document.getElementById("rcp-claims").textContent = "";
      say("rcp-verdict-detail", failure && failure.plain ? failure.message : errorText(failure, "check the receipt"));
    });
  });
  on("rcp-proof-form", "submit", function (event) { event.preventDefault(); downloadProof().catch(explain("rcp-proof-msg", "create the proof")); });
  on("rcp-proof-verify-form", "submit", function (event) { event.preventDefault(); checkProof().catch(explain("rcp-proof-msg", "check the proof")); });
  on("rcp-download-verifier", "click", function () { downloadChecker("/verifier", "trust_receipt_verify.py").catch(explain("rcp-signing-msg", "download the checker")); });
  on("rcp-download-proof-verifier", "click", function () { downloadChecker("/attestation/verifier", "attestation_verify.py").catch(explain("rcp-signing-msg", "download the checker")); });

  loadStatus().then(function (st) {
    if (st.days.length) { return loadRows(st.days[0]); }
    say("rcp-rows-note", "No activity has been recorded yet. Receipts appear here as agents act.");
    return null;
  }).catch(function (failure) {
    mark("danger", "Unavailable", "Trust receipts are not available", errorText(failure, "load trust receipts"));
  });
})();
