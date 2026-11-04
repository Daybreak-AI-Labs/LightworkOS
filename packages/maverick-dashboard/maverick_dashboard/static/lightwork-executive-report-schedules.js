"use strict";
(function (global) {
  var root = document.getElementById("tper-schedules");
  if (!root) return;
  var form = document.getElementById("tprs-form"), fields = document.getElementById("tprs-fields");
  var reviewNode = document.getElementById("tprs-review"), status = document.getElementById("tprs-status");
  var originalStatus = document.getElementById("tprs-original-status"), originalButton = document.getElementById("tprs-check-original");
  var list = document.getElementById("tprs-list"), base = "/api/v1/third-party/executive-reports/schedules";
  var context = "", catalog = null, pending = null, generation = 0, busy = false, controllers = new Set();
  var key = function () { return "lightwork.report-schedule-original:" + context; };
  var labels = {organization_name:"Organization", report_title:"Report title", footer_text:"Footer",
    primary_color:"Main color", accent_color:"Highlight color", text_color:"Text color",
    brand_asset_metadata_ref:"Recorded brand file", brand_asset_metadata_sha256:"Recorded brand file version"};
  function element(tag, text) { var e = document.createElement(tag); if (text !== undefined) e.textContent = text; return e; }
  function tell(text) { status.textContent = text; }
  function stamp() { return JSON.stringify(Array.from(new FormData(form).entries())); }
  function store() { try { if (pending) localStorage.setItem(key(), JSON.stringify(pending)); } catch (_) {} }
  function clear() {
    generation++; controllers.forEach(function (c) { c.abort(); }); controllers.clear();
    fields.disabled = true; reviewNode.textContent = ""; reviewNode.hidden = true; list.textContent = "";
    form.reset(); form.elements.report.textContent = ""; pending = null; catalog = null; context = "";
    originalButton.disabled = true; originalStatus.textContent = "Your account or access changed. Open the current report page again.";
    tell("Private report choices were cleared because your account, workspace or access changed.");
  }
  async function request(path, body) {
    var captured = generation, c = new AbortController(); controllers.add(c);
    try {
      var response = await fetch(base + path, {method:body === undefined ? "GET" : "POST", credentials:"same-origin",
        cache:"no-store", redirect:"error", signal:c.signal, headers:{"Accept":"application/json", "Content-Type":"application/json"},
        body:body === undefined ? undefined : JSON.stringify(body)});
      if (captured !== generation) throw Error("Your account changed. Open the current page again.");
      var type = response.headers.get("Content-Type") || "";
      if (!type.toLowerCase().startsWith("application/json")) throw Error("The current report controls could not be read. Your choices are kept.");
      if (Number(response.headers.get("Content-Length") || 0) > 800000) throw Error("This complete response is too large to display.");
      var reader = response.body.getReader(), chunks = [], size = 0;
      while (true) { var part = await reader.read(); if (part.done) break; size += part.value.length;
        if (size > 800000) { await reader.cancel(); throw Error("This complete response is too large to display."); } chunks.push(part.value); }
      var bytes = new Uint8Array(size), offset = 0; chunks.forEach(function (chunk) { bytes.set(chunk, offset); offset += chunk.length; });
      var result = JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(bytes));
      if (captured !== generation) throw Error("Your account changed. Open the current page again.");
      if (response.status === 401 || response.status === 403) { clear(); throw Error(result.detail || "Your current access does not allow report scheduling."); }
      if (!response.ok) throw Error(typeof result.detail === "string" ? result.detail : "This request could not be confirmed. Check Original before creating again.");
      if (result.context && context && result.context !== context) { clear(); throw Error("Your account or workspace changed. Open the current page again."); }
      return result;
    } finally { controllers.delete(c); }
  }
  function populate(select, rows, initial) {
    var chosen = select.value; select.textContent = "";
    if (initial) { var empty = element("option", initial); empty.value = ""; select.appendChild(empty); }
    rows.forEach(function (row) { var e = element("option", row.label); e.value = row.value; select.appendChild(e); });
    if (chosen && !rows.some(function (row) { return row.value === chosen; })) {
      var old = element("option", "Previously selected layout is unavailable; choose a current report"); old.value = chosen; select.appendChild(old);
    }
    if (chosen) select.value = chosen;
  }
  function visibility() {
    root.querySelectorAll("[data-tprs-week]").forEach(function (e) { e.hidden = form.elements.repeat.value !== "weekly"; });
    root.querySelectorAll("[data-tprs-month]").forEach(function (e) { e.hidden = form.elements.repeat.value !== "monthly"; });
  }
  async function load() {
    var current = generation, result = await request("/options");
    if (current !== generation) return false;
    if (context && result.context !== context) { clear(); return false; }
    context = result.context; catalog = result;
    populate(form.elements.report, result.choices, "Choose a saved report");
    populate(form.elements.zone, result.zones.map(function (z) { return {value:z, label:z}; }));
    fields.disabled = !result.enabled; tell(result.message);
    if (!pending) { try { var held = JSON.parse(localStorage.getItem(key()) || "null");
      if (held && typeof held.reference === "string" && held.context === context) pending = held;
    } catch (_) {} }
    originalButton.disabled = !pending; visibility(); await refreshList(); return true;
  }
  function choices() {
    var row = catalog.choices.find(function (r) { return r.value === form.elements.report.value; });
    if (!row) throw Error("Choose a current saved report layout.");
    return {context:context, report:row.value, revision:row.revision, timetable:{repeat:form.elements.repeat.value,
      at:form.elements.at.value, zone:form.elements.zone.value, days:form.elements.repeat.value === "weekly" ? [Number(form.elements.weekday.value)] : [],
      day_of_month:Number(form.elements.monthday.value), every_hours:1, advanced:null}};
  }
  function when(value, zone) { return new Date(value*1000).toLocaleString(undefined, {timeZone:zone || "UTC", timeZoneName:"short"}); }
  function review(result, body, capturedStamp) {
    reviewNode.textContent = ""; reviewNode.hidden = false; reviewNode.classList.add("tper-starting-review");
    reviewNode.appendChild(element("h3", "Review recurring report creation"));
    var dl = element("dl");
    Object.keys(labels).forEach(function (name) { if (result.layout[name] !== null && result.layout[name] !== undefined) {
      dl.appendChild(element("dt", labels[name])); dl.appendChild(element("dd", String(result.layout[name]))); } }); reviewNode.appendChild(dl);
    reviewNode.appendChild(element("h4", "Selected records today")); var sources = element("ul");
    result.sources.forEach(function (source) { sources.appendChild(element("li", source.kind + ": " + source.name + " — current recorded version " + source.reviewed_version)); });
    reviewNode.appendChild(sources); reviewNode.appendChild(element("h4", "Next three scheduled starts"));
    var times = element("ul"); result.next_runs.forEach(function (time) { times.appendChild(element("li", when(time, body.timetable.zone))); }); reviewNode.appendChild(times);
    if (body.timetable.repeat === "monthly") reviewNode.appendChild(element("p", "Every month on day " + body.timetable.day_of_month + ". Months without that date are skipped."));
    reviewNode.appendChild(element("p", result.notice));
    var actions = element("div"); actions.className = "tper-actions";
    var confirm = element("button", "Create reviewed schedule"); confirm.className = "btn btn--primary"; confirm.type = "button";
    var cancel = element("button", "Cancel"); cancel.className = "btn"; cancel.type = "button";
    cancel.addEventListener("click", function () { reviewNode.hidden = true; tell("Review cancelled. Your entered choices are kept; no schedule was created."); });
    confirm.addEventListener("click", async function () {
      if (busy) return;
      if (stamp() !== capturedStamp) { tell("Your choices changed. Review the current draft again; nothing was created."); return; }
      busy = true; confirm.disabled = true; cancel.disabled = true;
      pending = {context:context, reference:result.reference, attempted:true, confirmed:false}; store(); originalButton.disabled = false;
      try { var original = await request("/create", {reference:result.reference, choices:body, confirmed:true});
        pending.confirmed = original.found; store(); originalStatus.textContent = original.message;
        reviewNode.hidden = true; tell(original.message); await refreshList();
      } catch (error) { tell(error.message + " Check Original before creating again."); }
      finally { busy = false; cancel.disabled = false; } // uncertain requests never reactivate Confirm
    });
    actions.append(confirm, cancel); reviewNode.appendChild(actions); confirm.focus();
  }
  async function refreshList() {
    var result = await request("/list"); list.textContent = "";
    result.items.forEach(function (row) {
      var card = element("section"); card.className = "panel"; card.appendChild(element("h3", row.title));
      card.appendChild(element("p", row.state === "active" ? "Scheduled — next start " + when(row.next_run) : "Future creation stopped. Existing reports remain separate."));
      var names = {scheduled:"Scheduled", prepared:"Current records prepared", creating:"Creation started; outcome may still be unconfirmed",
        created:"PDF created", stopped:"Stopped or unavailable", unconfirmed:"Creation unconfirmed — not repeated"};
      row.history.forEach(function (item) {
        var p = element("p", when(item.when) + " — " + (names[item.state] || "Outcome unavailable"));
        if (item.report) { var a = element("a", "Open created report"); a.href = "/third-party/executive-reports?report=" + encodeURIComponent(item.report); p.append(" ", a); }
        card.appendChild(p);
        var check = element("button", "Check this run's original"); check.className = "btn";
        check.addEventListener("click", async function () {
          if (busy) return; busy = true;
          try { var read = await request("/occurrences/"+item.id+"/original"); tell(read.message);
            if (read.report) { var link = element("a", "Open original PDF report"); link.href = "/third-party/executive-reports?report="+encodeURIComponent(read.report); p.append(" ", link); }
          } catch (error) { tell(error.message); } finally { busy = false; }
        }); card.appendChild(check);
      });
      if (row.state === "active") {
        var stop = element("button", "Stop future report creation"); stop.className = "btn";
        stop.addEventListener("click", async function () {
          if (busy) return; busy = true; var captured = generation;
          try {
            var accepted = global.mvConfirm ? await global.mvConfirm("Stop future creation of “" + row.title + "”? PDFs already created are not withdrawn.", {title:"Stop recurring reports", okText:"Stop future creation"}) : false;
            if (!accepted || captured !== generation) return;
            await request("/"+encodeURIComponent(row.definition)+"/stop", {context:context, revision:row.revision, confirmed:true});
            tell("Future report creation stopped. Existing PDFs remain separate."); await refreshList();
          } catch (error) { tell(error.message); } finally { busy = false; }
        }); card.appendChild(stop);
      }
      list.appendChild(card);
    });
    if (!result.items.length) list.appendChild(element("p", "No report schedules are listed for your account in this workspace."));
    if (result.more) list.appendChild(element("p", "Showing the 100 most recent schedules. Older schedule history is retained."));
  }
  form.addEventListener("change", visibility);
  form.addEventListener("submit", async function (event) {
    event.preventDefault(); if (busy) return;
    if (pending && pending.attempted && !pending.confirmed) { tell("The earlier creation is unconfirmed. Check Original and current schedules before separately reviewing new work."); return; }
    busy = true; var capturedStamp = stamp(), captured = generation;
    try { var body = choices(), result = await request("/review", body);
      if (captured !== generation || stamp() !== capturedStamp) { tell("Your choices changed while the review loaded. Your draft is kept; review it again."); return; }
      review(result, body, capturedStamp);
    } catch (error) { tell(error.message); } finally { busy = false; }
  });
  originalButton.addEventListener("click", async function () {
    if (!pending || busy) return; busy = true;
    try { var result = await request("/original", {reference:pending.reference}); pending.confirmed = result.found; store();
      originalStatus.textContent = result.message; tell(result.message); await refreshList();
    } catch (error) { originalStatus.textContent = error.message; } finally { busy = false; }
  });
  document.getElementById("tprs-refresh").addEventListener("click", function () { if (!busy) load().catch(function (e) { tell(e.message); }); });
  ["workspace-changed", "account-context-changed"].forEach(function (event) { document.addEventListener(event, clear); });
  ["lightwork:workspace-changed", "lightwork:account-context-changed"].forEach(function (event) { global.addEventListener(event, clear); });
  global.LightworkExecutiveReportSchedules = {open:async function (expected, isCurrent) {
    if (!/^[a-f0-9]{64}$/.test(expected) || busy || (isCurrent && !isCurrent())) return false;
    var saved = stamp(), captured = generation;
    try { if (!await load() || context !== expected || captured !== generation || (isCurrent && !isCurrent())) return false;
      if (stamp() !== saved) { tell("Current availability was refreshed. Your chosen values are kept; review the current choices before creating."); }
      root.open = true; root.scrollIntoView({block:"start", behavior:"auto"});
      (fields.disabled ? originalButton : form.elements.report).focus(); return true;
    } catch (error) { tell(error.message); return false; }
  }};
  load().catch(function (error) { tell(error.message); });
})(window);
