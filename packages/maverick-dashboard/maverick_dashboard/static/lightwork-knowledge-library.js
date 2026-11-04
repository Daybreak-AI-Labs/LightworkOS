/* Knowledge library panel: collections, starter content and rebuilding the
   search index -- previously command-line only. */
(function () {
  "use strict";
  var panel = document.getElementById("ka-library");
  if (!panel) return;
  var API = "/api/v1/knowledge/library";
  var canAdmin = panel.dataset.canAdmin === "true";
  var statusEl = document.getElementById("ka-library-status");
  var tbody = document.getElementById("ka-library-collections");
  var starters = document.getElementById("ka-library-starters");

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function human(value) {
    if (typeof window.mvHuman === "function") return window.mvHuman(value);
    var text = String(value || "").replace(/[_.-]+/g, " ").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "";
  }
  function money(value) { return window.mvMoney ? window.mvMoney(Number(value || 0)) : "$" + Number(value || 0).toFixed(2); }
  async function call(method, path, body, action) {
    var payload = await window.mvFetchJSON(API + path, { method: method, body: body, plainDetail: true }, action);
    if (!payload || typeof payload !== "object") {
      throw new Error(window.mvErrorText({ name: "SyntaxError" }, action));
    }
    return payload;
  }
  function confirmed(message, okText) {
    if (typeof window.mvConfirm === "function") return window.mvConfirm(message, { okText: okText });
    return Promise.resolve(false);
  }
  function button(label, handler, cls) {
    var b = el("button", cls || "btn", label);
    b.type = "button";
    b.addEventListener("click", function () {
      if (b.disabled) return;
      b.disabled = true;
      Promise.resolve().then(handler).catch(function (error) {
        statusEl.textContent = error && error.message ? error.message : "Something went wrong. Try again.";
      }).then(function () { b.disabled = false; });
    });
    return b;
  }
  var jobsPanel = el("section"), jobsContext = "", pendingRebuild = null;
  jobsPanel.setAttribute("aria-label", "Search index rebuilds"); panel.appendChild(jobsPanel);
  async function refreshJobs() {
    if (!canAdmin) return;
    var payload = await call("GET", "/reindex-jobs", undefined, "refresh the rebuilds");
    if (jobsContext && jobsContext !== payload.context) { jobsPanel.replaceChildren(); pendingRebuild = null; throw new Error("Your workspace changed. Reload to review rebuilds."); }
    jobsContext = payload.context; jobsPanel.replaceChildren(el("h3", null, "Search index rebuilds"));
    if (!payload.jobs.length) {
      var title = "No rebuilds to show", body = "Rebuilds you start appear here with their progress and cost. Use Rebuild search index on a collection to start one. Archived operation receipts remain recorded.";
      jobsPanel.appendChild(window.mvEmpty ? window.mvEmpty(title, body, null, { compact: true }) : el("p", null, title + ". " + body));
    }
    payload.jobs.forEach(function(job) {
      var section = el("section"), progress = el("progress"); progress.max = Math.max(1,job.count); progress.value = job.done; progress.setAttribute("aria-label", "Rebuild progress");
      section.append(el("h4", null,human(job.collection)), el("p", null, human(job.state) + ": " + job.done + " of " + job.count + " passages. " + job.message),progress);
      section.appendChild(el("p", null, "Observed provider usage at reviewed rates: " + money(job.observed_dollars) + ". Unresolved reservation: " + money(job.unresolved_dollars) + "."));
      if (["queued","running","publishing"].indexOf(job.state) >= 0) {
        ["cancel","resume"].forEach(function(action) {
          section.appendChild(button(action === "cancel" ? "Cancel at next safe boundary" : "Continue after an interruption", async function() {
            if (!(await confirmed(action === "cancel" ? "Stop after the current batch? The live index stays unchanged unless its complete replacement already published." : "Continue this rebuild? Saved progress and current permissions will be checked. A rebuild that is already running is not started twice.", "Confirm"))) return;
            await call("POST","/reindex-jobs/"+job.job_id+"/"+action,{context:jobsContext,confirmed:true},action + " rebuild"); await refreshJobs();
          },"btn btn--ghost"));
        });
      }
      if (["completed","cancelled","failed","changed","unconfirmed"].indexOf(job.state) >= 0) {
        section.appendChild(button("Archive finished rebuild", async function(){
          if (!(await confirmed("Archive this finished rebuild? Its operation receipt remains recorded; saved temporary vectors are removed.", "Archive"))) return;
          await call("POST","/reindex-jobs/"+job.job_id+"/archive",{context:jobsContext,confirmed:true},"archive rebuild"); await refreshJobs();
        },"btn btn--ghost"));
      }
      jobsPanel.appendChild(section);
    });
    jobsPanel.appendChild(button("Refresh rebuild progress",refreshJobs,"btn btn--ghost"));
  }
  async function reindex(name) {
    var result = await call("GET", "/collections/" + encodeURIComponent(name) + "/reindex-review", undefined, "review rebuild limits"), review = result.review;
    jobsContext = result.context;
    var ok = await confirmed("Rebuild " + human(name) + "? " + review.count + " passages, using " + review.model + ". Provider admission ceiling: " + money(review.cost_ceiling) + ". " + review.price_basis + " Time limit: " + review.limits.max_wall_seconds + " seconds, checked between batches. A complete replacement is published only after validation. AI indexing can cost money with a paid provider; paid requests are blocked without verified cost admission.", "Start rebuild");
    if (!ok) return;
    pendingRebuild = {name:name,body:{context:result.context,job_id:crypto.randomUUID().replace(/-/g,""),review:review.review,confirmed:true}};
    statusEl.textContent = "Starting the rebuild. You may leave this page and return to its recorded status.";
    try {
      await call("POST", "/collections/" + encodeURIComponent(name) + "/reindex", pendingRebuild.body, "start rebuild");
      pendingRebuild = null; await refreshJobs();
    } catch(error) {
      statusEl.textContent = "The start could not be confirmed. Refresh rebuild progress to find the recorded rebuild before starting again. " + error.message;
      await refreshJobs();
    }
  }
  async function seed(collection, title) {
    var ok = await confirmed("Load the starter content “" + title + "”? Loading again replaces the earlier copy.", "Load");
    if (!ok) return;
    statusEl.textContent = "Loading starter content…";
    var result = await call("POST", "/seed", { collection: collection }, "load the starter content");
    statusEl.textContent = "Loaded " + result.chunks + " pieces of text.";
    await load();
  }
  async function load() {
    var body;
    try {
      body = await call("GET", "", undefined, "load the knowledge library");
    } catch (error) {
      statusEl.textContent = error.message;
      return;
    }
    tbody.textContent = "";
    starters.textContent = "";
    if (!body.enabled) {
      if (canAdmin) {
        var settings = el("a", null, "Turn it on in Settings");
        settings.href = "/settings/all?id=knowledge_access.enable";
        statusEl.replaceChildren(document.createTextNode("The knowledge library is turned off. "), settings);
      } else {
        statusEl.textContent = "The knowledge library is turned off. Ask an administrator to turn it on in Settings.";
      }
      return;
    }
    var collections = Array.isArray(body.collections) ? body.collections : [];
    statusEl.textContent = collections.length ? "" : "No collections yet." + (canAdmin ? " Load some starter content below to begin." : "");
    collections.forEach(function (item) {
      var tr = el("tr");
      var th = el("th", null, human(item.name)); th.scope = "row"; tr.appendChild(th);
      tr.appendChild(el("td", null, item.chunks === null || item.chunks === undefined ? "—" : String(item.chunks)));
      var actions = el("td");
      if (canAdmin) {
        var rebuild = button("Rebuild search index", function () { return reindex(item.name); }, "btn btn--ghost");
        rebuild.setAttribute("aria-label", "Rebuild the search index for " + human(item.name));
        actions.appendChild(rebuild);
      }
      tr.appendChild(actions);
      tbody.appendChild(tr);
    });
    (Array.isArray(body.starter_content) ? body.starter_content : []).forEach(function (item) {
      var li = el("li", null, item.title + " (" + item.documents + " documents)" + (item.loaded ? " — loaded" : "") + " ");
      if (canAdmin) {
        var load = button(item.loaded ? "Load again" : "Load", function () { return seed(item.collection, item.title); }, "btn btn--ghost");
        load.setAttribute("aria-label", (item.loaded ? "Load again: " : "Load: ") + item.title);
        li.appendChild(load);
      }
      starters.appendChild(li);
    });
  }
  document.getElementById("ka-library-refresh").addEventListener("click", function(){ load(); refreshJobs().catch(function(error){ statusEl.textContent=error.message; }); });
  refreshJobs().catch(function(error){statusEl.textContent=error.message;});
  load();
})();
