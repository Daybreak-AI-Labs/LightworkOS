/* Banner and preference center: websites and apps, content, display rules,
   preview, publish, restore and withdraw. Every record is picked from a list;
   versions, references and document fingerprints are carried or computed
   here, never typed. Wording is stored in the language pack so people type
   words, not text references. */
(function () {
  "use strict";
  var API = "/api/v1/consent/publishing";

  // The shared consent JSON client (mvFetchJSON): a non-2xx or malformed response is never success.
  async function call(path, options) {
    return window.LightworkConsentWorkbench.client(API)(path, options);
  }

  var CW = window.LightworkConsentWorkbench;
  // The shell's helpers (lightwork-ui.js) load after the page content.
  function begin() {
    if (CW && document.getElementById("cpp-withdrawal-original")) startWithdrawal();
    if (CW && document.getElementById("cpp-root")) start();
    if (CW && document.getElementById("cpp-signing")) startSigning();
  }
  if (window.mvFetchJSON) begin(); else document.addEventListener("DOMContentLoaded", begin);

  // Withdrawal has its own complete review and native original-request reader.
  // The ordinary Publish/Restore controls retain their separate contracts.
  function startWithdrawal() {
    var $ = function (id) { return document.getElementById(id); };
    var status = $("cpp-withdrawal-status"), select = $("cpp-withdrawal-requests");
    var panel = $("cpp-withdrawal-review"), result = $("cpp-withdrawal-result");
    var client = CW.client("/api/v1/consent/withdrawal-requests");
    function request(path, options) { return client(path, Object.assign({timeout: 20000, onAccess: clear}, options || {})); }
    var context = "", generation = 0, prepared = null, after = null, busy = false, ended = false;
    var requested = new URLSearchParams(window.location.search).get("withdrawal") || "";
    function say(text, bad) { CW.say(status, text, bad); }
    function clear() {
      generation++; ended = true; prepared = null; after = null; panel.hidden = true;
      $("cpp-withdrawal-changes").replaceChildren(); result.replaceChildren(); select.replaceChildren();
      $("cpp-withdrawal-confirm").disabled = true; $("cpp-withdrawal-read").disabled = true;
      say("Your account, workspace or access changed. Reload before using private banner records.", true);
    }
    function check(value, started) {
      if (ended || generation !== started) return false;
      if (!value || !/^[a-f0-9]{64}$/.test(value.context) || context && value.context !== context) { clear(); return false; }
      if (!context) context = value.context;
      return true;
    }
    function failed(error, action) {
      if (error && (error.status === 401 || error.status === 403 || error.redirected)) { clear(); return; }
      say(CW.errorText(error, action), true);
      if (error && (error.status === 404 || error.status === 409)) {
        var started = generation;
        request("", {method: "GET"}).then(function (value) { check(value, started); }).catch(function (failure) {
          if (failure.status === 401 || failure.status === 403 || failure.accessChanged) clear();
        });
      }
    }
    function show(value) {
      CW.facts(result, [["Original result", value.message], ["Current banner", value.current],
        ["Original decision time", value.accepted_at ? CW.when(value.accepted_at) : "Not confirmed"], ["Scope", value.notice]]);
      say(value.message, !value.confirmed);
    }
    async function load() {
      var started = generation, value = await request("", {method: "GET"});
      if (!check(value, started)) return false;
      if (!requested) {
        try { requested = window.sessionStorage.getItem("lightwork-banner-withdrawal:" + context) || ""; } catch (_error) { requested = ""; }
      }
      CW.fill(select, value.requests, value.requests.length ? "Choose your original request" : "No original withdrawal requests yet");
      if (requested && value.requests.some(function (row) { return row.value === requested; })) select.value = requested;
      $("cpp-withdrawal-read").disabled = !select.value;
      return true;
    }
    async function read() {
      if (!context || !select.value || ended) return;
      var selected = select.value, started = generation;
      var value = await request("/" + encodeURIComponent(selected) + "?context=" + encodeURIComponent(context), {method: "GET"});
      if (check(value, started) && select.value === selected) show(value);
    }
    async function review(website, callback) {
      if (busy || ended) return false;
      if (!context && !(await load())) return false;
      var started = ++generation;
      var value = await request("/review", {method: "POST", json: {website: website, context: context}});
      if (!check(value, started)) return false;
      if (!Array.isArray(value.changes) || value.changes.length !== 8 || !value.changes.every(function (row) {
        return typeof row.label === "string" && (typeof row.after === "string" || Array.isArray(row.after) && row.after.length <= 64 && row.after.every(function (item) { return typeof item === "string"; }));
      })) { say("The complete review could not be displayed. Nothing was withdrawn.", true); return false; }
      var list = CW.el("dl");
      value.changes.forEach(function (row) {
        list.appendChild(CW.el("dt", "", row.label));
        var entry = CW.el("dd");
        if (Array.isArray(row.after)) { var items = CW.el("ul"); row.after.forEach(function (item) { items.appendChild(CW.el("li", "", item)); }); entry.appendChild(items); }
        else entry.textContent = row.after;
        list.appendChild(entry);
      });
      $("cpp-withdrawal-changes").replaceChildren(list); prepared = value; after = callback;
      $("cpp-withdrawal-confirm").disabled = false;
      panel.hidden = false;
      var heading = $("cpp-withdrawal-review-title"); heading.focus({preventScroll: true}); heading.scrollIntoView({block: "center"});
      say("Review every current address and the exact banner. Keep the banner to cancel.");
      return true;
    }
    $("cpp-withdrawal-confirm").addEventListener("click", function () {
      if (!prepared || busy || ended) return;
      var original = prepared, started = generation, callback = after;
      CW.busy(this, async function () {
        busy = true; requested = original.operation;
        try { window.sessionStorage.setItem("lightwork-banner-withdrawal:" + context, requested); } catch (_error) { /* Native history remains available. */ }
        var option = Array.from(select.options).find(function (item) { return item.value === requested; });
        if (!option) { option = CW.el("option", "", "The withdrawal you just confirmed"); option.value = requested; select.appendChild(option); }
        select.value = requested; $("cpp-withdrawal-read").disabled = false;
        panel.hidden = true; prepared = null; after = null;
        say("Waiting for the original withdrawal result. A missing reply will not run it again.");
        try {
          var value = await request("/apply", {method: "POST", json: {operation: original.operation, token: original.token, confirmed: true}});
          if (!check(value, started)) return;
          show(value); await load();
          if (generation === started && !ended && value.confirmed && callback) await callback();
        } catch (error) {
          failed(error, "confirm the banner withdrawal");
          if (!ended && generation === started) say(error.status === 409 || error.status === 422 ?
            "This reviewed change was refused. Read its original result, then review current banner settings before a new decision." :
            "The original response is uncertain. Use Read original result before reviewing a new withdrawal. Nothing will repeat automatically.", true);
        } finally { busy = false; }
      });
    });
    $("cpp-withdrawal-cancel").addEventListener("click", function () {
      generation++; prepared = null; after = null; panel.hidden = true;
      say("Cancelled. The banner was kept.");
    });
    select.addEventListener("change", function () { requested = select.value; result.replaceChildren(); $("cpp-withdrawal-read").disabled = !select.value; });
    $("cpp-withdrawal-read").addEventListener("click", function () { CW.busy(this, function () { return read().catch(function (error) { failed(error, "read the original withdrawal"); }); }); });
    $("cpp-withdrawal-refresh").addEventListener("click", function () { CW.busy(this, function () { return load().catch(function (error) { failed(error, "load original withdrawals"); }); }); });
    document.addEventListener("lightwork:copilot-context-changed", function () {
      // Selection alone is not a new account; verify instead of discarding work.
      var started = generation;
      request("", {method: "GET"}).then(function (value) { check(value, started); }).catch(function (error) { failed(error, "verify current banner access"); });
    });
    window.addEventListener("lightwork:context-changed", clear);
    window.addEventListener("lightwork:draft-context-changed", clear);
    window.LightworkConsentWithdrawal = {review: review};
    load().then(function (ok) { if (ok && select.value) return read(); }).catch(function (error) { failed(error, "load original withdrawals"); });
    // Only an opaque operation reference survives a missing reply or reload.
    window.addEventListener("pagehide", function () {
      if (requested && context && !ended) {
        try { window.sessionStorage.setItem("lightwork-banner-withdrawal:" + context, requested); } catch (_error) { /* Native history remains available. */ }
      }
    });
  }

  // ---- Signing key: shown by fingerprint only; the private key never leaves the server.
  function startSigning() {
    var $ = function (id) { return document.getElementById(id); };
    var status = $("cpp-signing-status");
    var rotate = $("cpp-signing-rotate");
    var download = $("cpp-signing-download");
    var canAdmin = $("cpp-signing").dataset.canAdmin === "true";
    var configured = false;

    function grouped(fingerprint) {
      return String(fingerprint || "").toUpperCase().match(/.{1,4}/g).join(" ");
    }
    function render(state) {
      configured = !!state.key;
      var pairs = [
        ["Signed publishing", state.required ? "On" : "Off (turn it on in All settings)"],
        ["Key", state.key ? state.key.key_id : "Not created yet"],
        ["Public key fingerprint", state.key ? grouped(state.key.fingerprint) : ""],
        ["Earlier keys kept to check older publications", state.retired_keys ? String(state.retired_keys) : ""],
        ["Last changed", state.rotated_at ? CW.when(state.rotated_at) : ""],
        ["Kept on the server", state.managed_by_server ? "Yes, set by your server team; it can't be changed here." : ""],
      ];
      CW.facts($("cpp-signing-state"), pairs);
      download.hidden = !state.key;
      rotate.textContent = state.key ? "Replace signing key" : "Create signing key";
      rotate.disabled = !canAdmin || !!state.managed_by_server;
      if (!canAdmin) rotate.title = "Only an administrator can change the signing key.";
    }
    async function load() {
      var state = await call("/signing-key");
      render(state);
      return state;
    }
    rotate.addEventListener("click", function () {
      CW.busy(rotate, async function () {
        var replacing = configured;
        var question = replacing
          ? "Replace the signing key? Websites that check signatures stop showing your banner until they are given the new public key. Settings you published keep working."
          : "Create the signing key? You can then turn on signed publishing and give the public key to your websites.";
        if (!(await CW.confirm(question, replacing ? "Replace key" : "Create key"))) return;
        try {
          render(await call("/signing-key/rotate", { method: "POST", json: { confirm: true } }));
          CW.say(status, replacing ? "The signing key was replaced. Download the new public key for your websites." : "The signing key was created. Download the public key for your websites.");
        } catch (error) { CW.fail(status, error, "change the signing key"); }
      });
    });
    load().catch(function (error) { $("cpp-signing-state").replaceChildren(); CW.fail(status, error, "load the signing key"); });
  }

  function start() {
    var $ = function (id) { return document.getElementById(id); };
    var status = $("cpp-status");
    var canAdmin = $("cpp-root").dataset.canAdmin === "true";
    var state = { properties: [], items: {}, messages: {}, kind: "purposes", locale: "en-US", pack: "consent-text" };
    var BASES = [["consent", "Consent"], ["contract", "Needed for a contract"], ["legal_obligation", "Required by law"],
      ["legitimate_interests", "Legitimate business interest"], ["public_task", "Public task"], ["vital_interests", "Protects someone’s life"]]
      .map(function (p) { return { value: p[0], label: p[1] }; });
    var DEFAULTS = [{ value: "denied", label: "Off until they agree" }, { value: "granted", label: "On unless they say no" }, { value: "unset", label: "No default; they must choose" }];
    var MODES = [{ value: "opt_in", label: "Ask before collecting (opt-in)" }, { value: "opt_out", label: "Collect unless people say no (opt-out)" }, { value: "notice_only", label: "Show a notice only" }];
    var SURFACES = [{ value: "banner", label: "Banner" }, { value: "modal", label: "Pop-up window" }, { value: "mobile_sheet", label: "Mobile sheet" }, { value: "preferences_center", label: "Preference center" }];
    var ACTIONS = [["accept_all", "Accept all button"], ["reject_all", "Reject all button"], ["manage_preferences", "Manage preferences button"], ["save_preferences", "Save preferences button"], ["close", "Close button"]];
    var KINDS = {
      "purposes": { noun: "use of data", prefix: "purpose", endpoint: "purposes", help: "The reasons you use personal data, such as analytics or marketing. People choose which ones they agree to." },
      "topics": { noun: "topic", prefix: "topic", endpoint: "topics", help: "Finer choices within a use of data, such as newsletter subjects." },
      "custom-preferences": { noun: "extra question", prefix: "question", endpoint: "custom-preferences", help: "Extra questions to ask people, such as how often they want to hear from you." },
      "notices": { noun: "privacy notice", prefix: "notice", endpoint: "notices", help: "Your privacy notice. Attach the document so Lightwork can prove which version people saw." },
      "templates": { noun: "banner design", prefix: "design", endpoint: "templates", help: "The wording and buttons of the banner or preference center." },
      "themes": { noun: "brand theme", prefix: "theme", endpoint: "themes", help: "Your brand name and colors. Colors must be easy to read against each other." },
      "translations": { noun: "language", prefix: "language", endpoint: "translations", help: "Each language your text is available in. Translate your text to add a language." },
      "rule-groups": { noun: "set of display rules", prefix: "rules", endpoint: "rule-groups", help: "Which content shows in which regions and languages. You publish display rules to a website or app." },
    };

    function close(id) { $(id).hidden = true; }
    document.querySelectorAll("[data-cpp-close]").forEach(function (b) { b.addEventListener("click", function () { close(b.dataset.cppClose); }); });
    function field(label, control, wide, help) {
      var wrap = CW.el("label", wide ? "cw-wide" : "");
      wrap.append(label, control);
      if (help) wrap.appendChild(CW.el("span", "muted", help));
      return wrap;
    }
    function input(name, type, value, attrs) {
      var node = CW.el(type === "textarea" ? "textarea" : "input", type === "textarea" ? "textarea" : "input");
      if (type !== "textarea") node.type = type || "text";
      node.name = name;
      if (value !== undefined && value !== null) { if (type === "checkbox") node.checked = !!value; else node.value = value; }
      Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
      return node;
    }
    function select(name, options, value, multiple) {
      var node = CW.el("select", "select"); node.name = name;
      if (multiple) { node.multiple = true; node.size = 5; }
      CW.fill(node, options);
      if (multiple) Array.prototype.forEach.call(node.options, function (o) { o.selected = (value || []).indexOf(o.value) >= 0; });
      else if (value !== undefined && value !== null) node.value = value;
      return node;
    }
    function checks(name, options, chosen) {
      var box = CW.el("div", "cw-checks");
      if (!options.length) box.appendChild(CW.el("span", "muted", "Nothing saved yet. Save a choice above to use it here."));
      options.forEach(function (o) {
        var l = CW.el("label"), c = input(name, "checkbox", (chosen || []).indexOf(o.value) >= 0);
        c.value = o.value; l.append(c, " " + o.label); box.appendChild(l);
      });
      return box;
    }
    function picked(scope, name) {
      return Array.prototype.filter.call(scope.querySelectorAll('[name="' + name + '"]'), function (c) { return c.checked; }).map(function (c) { return c.value; });
    }
    function multi(scope, name) {
      var node = scope.querySelector('[name="' + name + '"]');
      return node ? Array.prototype.filter.call(node.options, function (o) { return o.selected; }).map(function (o) { return o.value; }) : [];
    }

    // ---- Language pack (text is stored by reference; people only see words)
    function packLocales() {
      return (state.items.translations || []).filter(function (t) { return t.resource_id === state.pack; })
        .map(function (t) { return { locale: t.locale, version: t.current_version }; });
    }
    async function loadMessages(locale, fresh) {
      var key = state.pack + "|" + locale;
      if (!fresh && state.messages[key]) return state.messages[key];
      var data = await call("/catalog/translations?resource_id=" + encodeURIComponent(state.pack) + "&limit=50");
      var mine = (data.items || []).filter(function (t) { return t.locale === locale; })[0];
      var result = { version: 0, messages: {} };
      if (mine) {
        var current = await call("/catalog/translations/" + encodeURIComponent(state.pack) + "/versions/" + mine.current_version + "?locale=" + encodeURIComponent(locale));
        result = { version: mine.current_version, messages: (current.payload && current.payload.messages) || {} };
      }
      state.messages[key] = result;
      return result;
    }
    async function saveMessages(locale, add) {
      var current = await loadMessages(locale, true);
      var merged = Object.assign({}, current.messages), changed = false;
      Object.keys(add).forEach(function (k) { if (merged[k] !== add[k]) { merged[k] = add[k]; changed = true; } });
      if (!changed) return current;
      if (Object.keys(merged).length > 256) { var full = new Error("full"); full.status = 413; throw full; }
      await call("/translations/" + encodeURIComponent(state.pack) + "/" + encodeURIComponent(locale) + "/versions",
        { method: "POST", json: { version: current.version + 1, expected_current_version: current.version, idempotency_key: CW.reference(), messages: merged } });
      delete state.messages[state.pack + "|" + locale];
      return loadMessages(locale, true);
    }
    function words(messages, key, fallback) { return (messages && messages[key]) || fallback || ""; }

    // ---- Websites and apps
    async function loadProperties() {
      var all = [], offset = 0;
      for (var i = 0; i < 20 && offset !== null; i++) {
        var data = await call("/catalog/properties?limit=50&offset=" + offset);
        all = all.concat(data.items || []); offset = data.next_offset;
      }
      state.properties = all;
      var groups = {}; all.forEach(function (p) { groups[p.consent_group_id] = true; });
      var list = $("cpp-group-suggestions"); list.replaceChildren();
      Object.keys(groups).forEach(function (g) { var o = document.createElement("option"); o.value = CW.human(g); list.appendChild(o); });
      CW.table($("cpp-property-table"), all, {
        label: "Websites and apps", name: function (p) { return CW.human(p.property_id); },
        columns: [
          { label: "Name", value: function (p) { return CW.human(p.property_id); } },
          { label: "Type", value: function (p) { return p.kind === "mobile" ? "Mobile app" : "Website"; } },
          { label: "Addresses", value: function (p) { return (p.kind === "mobile" ? p.mobile_bundle_ids : p.web_domains).join(", "); } },
          { label: "Consent group", value: function (p) { return CW.human(p.consent_group_id); } },
          { label: "Published", value: function (p) { return p.publication_action === "withdraw" ? CW.badge("Withdrawn", "idle") : p.publication_revision ? CW.badge("Yes", "ok") : CW.badge("Not yet", "idle"); } },
        ],
        actions: [
          { label: "Preview and publish", run: function (p) { openPromotion(p); } },
          { label: "History", when: function (p) { return p.publication_revision > 0; }, run: function (p) { openHistory(p); } },
          { label: "Edit", when: function () { return canAdmin; }, run: function (p) { editProperty(p); } },
          { label: "Withdraw", kind: "danger", when: function (p) { return canAdmin && p.publication_revision > 0 && p.publication_action !== "withdraw"; }, run: function (p, b) { withdraw(p, b); } },
        ],
        empty: { title: "No websites or apps yet.", body: "Add the website or app where your consent banner should appear.", action: canAdmin ? { label: "Add a website or app", run: function () { editProperty(null); } } : null },
      });
    }
    var propertyForm = $("cpp-property");
    function syncKind() {
      var kind = propertyForm.querySelector("[name=kind]:checked").value;
      propertyForm.querySelectorAll("[data-kind]").forEach(function (n) { n.hidden = n.dataset.kind !== kind; });
    }
    propertyForm.querySelectorAll("[name=kind]").forEach(function (r) { r.addEventListener("change", syncKind); });
    function editProperty(p) {
      propertyForm.reset(); var f = propertyForm.elements;
      f.property_name.value = p ? CW.human(p.property_id) : ""; f.property_name.readOnly = !!p;
      f.property_id.value = p ? p.property_id : ""; f.expected_revision.value = String(p ? p.revision : 0);
      if (p) {
        propertyForm.querySelector('[name=kind][value="' + p.kind + '"]').checked = true;
        f.group_name.value = CW.human(p.consent_group_id);
        f.web_domains.value = (p.web_domains || []).join("\n"); f.mobile_bundle_ids.value = (p.mobile_bundle_ids || []).join("\n");
        if (p.platform) f.platform.value = p.platform;
      }
      $("cpp-property-title").textContent = p ? "Edit " + CW.human(p.property_id) : "Add a website or app";
      syncKind(); CW.open(propertyForm, p ? "[name=group_name]" : "[name=property_name]");
    }
    $("cpp-property-new").addEventListener("click", function () { editProperty(null); });
    ["web_domains", "mobile_bundle_ids"].forEach(function (name) {
      propertyForm.elements[name].addEventListener("input", function () { this.removeAttribute("aria-invalid"); });
    });
    function lines(text) { return String(text || "").split(/[\n,]+/).map(function (v) { return v.trim(); }).filter(Boolean); }
    function host(value) { return value.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase(); }
    propertyForm.addEventListener("submit", async function (event) {
      event.preventDefault(); var f = propertyForm.elements, kind = propertyForm.querySelector("[name=kind]:checked").value;
      if (!f.property_name.value.trim() || !f.group_name.value.trim()) { CW.say(status, "Enter a name and a consent group.", true); return; }
      var id = f.property_id.value || CW.slug(f.property_name.value, "site");
      if (!f.property_id.value && state.properties.some(function (p) { return p.property_id === id; })) { CW.say(status, "A website or app with that name already exists. Use Edit on its row.", true); return; }
      var domains = kind === "web" ? lines(f.web_domains.value).map(host) : [];
      var bundles = kind === "mobile" ? lines(f.mobile_bundle_ids.value) : [];
      if (kind === "web" && !domains.length) { CW.say(status, "Enter at least one website address.", true); f.web_domains.focus(); return; }
      if (kind === "mobile" && !bundles.length) { CW.say(status, "Enter the app store ID.", true); f.mobile_bundle_ids.focus(); return; }
      var body = { kind: kind, consent_group_id: CW.slug(f.group_name.value, "group"), expected_revision: Number(f.expected_revision.value) || 0,
        idempotency_key: f.idempotency_key.value || CW.reference(), web_domains: domains,
        origin_allowlist: domains.map(function (d) { return "https://" + d; }), mobile_bundle_ids: bundles };
      if (kind === "mobile") body.platform = f.platform.value;
      try {
        await call("/properties/" + encodeURIComponent(id), { method: "PUT", json: body });
        propertyForm.hidden = true; await loadProperties(); CW.say(status, "Saved " + CW.human(id) + ".");
      } catch (error) {
        if (error && error.status === 422) {
          var bad = kind === "web" ? f.web_domains : f.mobile_bundle_ids;
          bad.setAttribute("aria-invalid", "true"); bad.focus();
          CW.say(status, "Could not save the website or app. Check the " + (kind === "web" ? "website addresses" : "app store IDs") + " and try again.", true);
        } else CW.fail(status, error, "save the website or app");
      }
    });

    // ---- Preview and publish
    var promotion = $("cpp-promotion"), promoted = null;
    async function openPromotion(p) {
      promoted = p; promotion.reset(); var f = promotion.elements;
      f.property_id.value = p.property_id; f.expected_property_revision.value = String(p.revision);
      f.expected_publication_revision.value = String(p.publication_revision || 0);
      $("cpp-promotion-title").textContent = "Preview and publish to " + CW.human(p.property_id);
      $("cpp-preview-result").replaceChildren();
      await ensureKind("rule-groups");
      var groups = (state.items["rule-groups"] || []).map(function (g) { return { value: g.resource_id + "|" + g.version, label: CW.human(g.resource_id) + " · version " + g.version }; });
      CW.fill(f.rule_group, groups, groups.length ? "" : "No display rules yet. Create them under Content first.");
      if (groups.length) f.rule_group.value = groups[0].value;
      CW.open(promotion, "[name=rule_group]");
    }
    function chosenGroup() {
      var value = promotion.elements.rule_group.value.split("|");
      return value[0] ? { rule_group_id: value[0], rule_group_version: Number(value[1]) } : null;
    }
    $("cpp-preview").addEventListener("click", function () {
      var button = this; CW.busy(button, async function () {
        var group = chosenGroup(); if (!group) { CW.say(status, "Choose display rules first.", true); return; }
        try { renderPreview(await call("/properties/" + encodeURIComponent(promotion.elements.property_id.value) + "/preview", { method: "POST", json: group })); CW.say(status, "Preview ready. Nothing has been published."); }
        catch (error) { $("cpp-preview-result").replaceChildren(); CW.fail(status, error, "build the preview"); }
      });
    });
    function renderPreview(result) {
      var out = $("cpp-preview-result"); out.replaceChildren();
      var bundle = result.bundle || {}, resources = bundle.resources || [];
      function find(kind, ref, locale) { return resources.filter(function (r) { return r.resource_kind === kind && r.resource_id === ref.id && r.version === ref.version && (locale === undefined || r.locale === locale); })[0]; }
      var rules = (bundle.rule_group && bundle.rule_group.payload && bundle.rule_group.payload.rules) || [];
      rules.forEach(function (rule) {
        var locale = rule.default_locale, translation = find("translation", { id: rule.translation_catalog_id, version: rule.translation_versions[locale] }, locale);
        var text = (translation && translation.payload && translation.payload.messages) || {};
        var template = find("template", rule.template) || { payload: { actions: {} } };
        var theme = template.payload.theme_token_version ? find("theme", { id: template.payload.theme_token_id, version: template.payload.theme_token_version }) : null;
        var card = CW.el("div", "panel");
        card.appendChild(CW.el("p", "muted", "Shown " + (rule.jurisdictions.length || rule.country_codes.length ? "in " + rule.jurisdictions.map(function (j) { return CW.labelFor(CW.JURISDICTIONS, j); }).concat(rule.country_codes.map(function (c) { return CW.labelFor(CW.COUNTRIES, c); })).join(", ") : "everywhere") +
          " · " + CW.labelFor(MODES, rule.consent_mode) + " · " + rule.locales.map(function (l) { return CW.labelFor(CW.LOCALES, l); }).join(", ")));
        var mock = CW.el("div", "cw-secret");
        if (theme) { mock.style.background = "#" + theme.payload.surface_color; mock.style.color = "#" + theme.payload.text_color; }
        mock.appendChild(CW.el("strong", "", words(text, template.payload.title_key, "Your privacy choices")));
        mock.appendChild(CW.el("p", "", words(text, template.payload.body_key)));
        var uses = CW.el("ul");
        rule.purposes.forEach(function (ref) { var p = find("purpose", ref); if (p) uses.appendChild(CW.el("li", "", words(text, p.payload.title_key, CW.human(ref.id)) + (p.payload.required ? " (always on)" : ""))); });
        mock.appendChild(uses);
        var buttons = CW.el("div", "cw-actions");
        Object.keys(template.payload.actions || {}).forEach(function (a) {
          var b = CW.el("span", "btn", words(text, template.payload.actions[a], CW.human(a)));
          if (theme && a === "accept_all") { b.style.background = "#" + theme.payload.primary_color; b.style.color = "#" + theme.payload.primary_text_color; }
          buttons.appendChild(b);
        });
        mock.appendChild(buttons);
        var notice = find("notice", rule.notice);
        if (notice) mock.appendChild(CW.el("p", "muted", words(text, notice.payload.title_key, "Privacy notice")));
        card.appendChild(mock); out.appendChild(card);
      });
      if (!rules.length) out.appendChild(CW.el("p", "muted", "These display rules have no content yet."));
    }
    $("cpp-publish").addEventListener("click", function () {
      var button = this; CW.busy(button, async function () {
        var group = chosenGroup(), f = promotion.elements; if (!group) { CW.say(status, "Choose display rules first.", true); return; }
        var name = CW.human(f.property_id.value);
        if (!(await CW.confirm("Publish to " + name + "? People visiting it will see this banner and preference center right away.", "Publish"))) return;
        try {
          await call("/properties/" + encodeURIComponent(f.property_id.value) + "/publish", { method: "POST", json: Object.assign({}, group, {
            expected_property_revision: Number(f.expected_property_revision.value), expected_publication_revision: Number(f.expected_publication_revision.value),
            idempotency_key: f.idempotency_key.value || CW.reference() }) });
          promotion.hidden = true; await loadProperties(); CW.say(status, "Published to " + name + ".");
        } catch (error) { CW.fail(status, error, "publish"); }
      });
    });

    // ---- History, restore, withdraw
    var WHAT = { publish: "Published", rollback: "Restored an earlier version", withdraw: "Withdrawn" };
    async function openHistory(p) {
      $("cpp-history-title").textContent = "Publishing history for " + CW.human(p.property_id);
      var host = $("cpp-history"); host.replaceChildren(); CW.open($("cpp-history-panel"));
      try {
        var data = await call("/properties/" + encodeURIComponent(p.property_id) + "/history?limit=100");
        var items = data.items || [], head = items[0];
        CW.table(host, items, {
          label: "Publishing history", name: function (h) { return "version " + h.publication_revision; },
          columns: [
            { label: "Version", value: function (h) { return h.publication_revision; } },
            { label: "What happened", value: function (h) { return WHAT[h.action] || CW.human(h.action); } },
            { label: "When", value: function (h) { return CW.when(h.created_at); } },
            { label: "Live now", value: function (h) { return h === head && h.action !== "withdraw" ? CW.badge("Live", "ok") : ""; } },
          ],
          actions: [{ label: "Restore this version", when: function (h) { return canAdmin && h !== head && h.action !== "withdraw"; }, run: function (h, b) { restore(p, h, b); } }],
          empty: { title: "Nothing has been published here yet.", body: "Publish a reviewed version above to put it live." },
        });
      } catch (error) { CW.fail(status, error, "load the publishing history"); }
    }
    function restore(p, h, button) {
      CW.busy(button, async function () {
        if (!(await CW.confirm("Restore version " + h.publication_revision + " on " + CW.human(p.property_id) + "? It will replace what people see now. The history is kept.", "Restore"))) return;
        try {
          await call("/properties/" + encodeURIComponent(p.property_id) + "/rollback", { method: "POST", json: {
            target_publication_id: h.publication_id, expected_property_revision: p.revision,
            expected_publication_revision: p.publication_revision, idempotency_key: CW.reference() } });
          await loadProperties(); var fresh = state.properties.filter(function (x) { return x.property_id === p.property_id; })[0];
          CW.say(status, "Version " + h.publication_revision + " restored on " + CW.human(p.property_id) + ".");
          if (fresh) openHistory(fresh);
        } catch (error) { CW.fail(status, error, "restore that version"); }
      });
    }
    function withdraw(p, button) {
      CW.busy(button, async function () {
        try {
          if (!window.LightworkConsentWithdrawal) throw new Error("The protected banner review is unavailable. Reload this page.");
          await window.LightworkConsentWithdrawal.review(p.property_id, loadProperties);
        } catch (error) {
          CW.fail(status, error, "review the banner withdrawal");
        }
      });
    }

    // ---- Content
    async function ensureKind(kind) {
      var all = [], offset = 0;
      for (var i = 0; i < 20 && offset !== null; i++) {
        var data = await call("/catalog/" + kind + "?limit=50&offset=" + offset);
        all = all.concat(data.items || []); offset = data.next_offset;
      }
      state.items[kind] = all;
      if (kind === "translations") {
        var packs = {}; all.forEach(function (t) { packs[t.resource_id] = true; });
        var names = Object.keys(packs);
        if (names.length && names.indexOf(state.pack) < 0) state.pack = names[0];
      }
      return all;
    }
    function latest(kind) { return (state.items[kind] || []).map(function (r) { return { value: r.resource_id + "|" + r.version, label: CW.human(r.resource_id) + " · version " + r.version, id: r.resource_id, version: r.version }; }); }
    function ref(value) { var parts = String(value || "").split("|"); return parts[0] ? { id: parts[0], version: Number(parts[1]) } : null; }
    async function renderKind() {
      var kind = state.kind, spec = KINDS[kind];
      $("cpp-kind-help").textContent = spec.help;
      $("cpp-resource-new").textContent = kind === "translations" ? "Add a language" : "New " + spec.noun;
      var host = $("cpp-resource-table"); host.replaceChildren(CW.el("p", "muted", "Loading…"));
      try {
        await ensureKind("translations");
        var items = kind === "translations" ? state.items.translations.filter(function (t) { return t.resource_id === state.pack; }) : await ensureKind(kind);
        var text = (await loadMessages(state.locale)).messages;
        var columns = kind === "translations"
          ? [{ label: "Language", value: function (t) { return CW.labelFor(CW.LOCALES, t.locale); } }, { label: "Version", value: function (t) { return t.version; } }, { label: "Last saved", value: function (t) { return CW.when(t.created_at); } }]
          : [{ label: "Name", value: function (r) { return CW.human(r.resource_id); } }, { label: "Shows as", value: function (r) { return summary(kind, r, text); } }, { label: "Version", value: function (r) { return r.version; } }, { label: "Last saved", value: function (r) { return CW.when(r.created_at); } }];
        CW.table(host, items, {
          label: spec.noun, name: function (r) { return kind === "translations" ? CW.labelFor(CW.LOCALES, r.locale) : CW.human(r.resource_id); },
          columns: columns,
          actions: [{ label: kind === "translations" ? "Translate" : "Edit", when: function () { return canAdmin; }, run: function (r) { editResource(r); } }],
          empty: { title: "Nothing saved yet.", body: spec.help, action: canAdmin ? { label: kind === "translations" ? "Add a language" : "New " + spec.noun, run: function () { editResource(null); } } : null },
        });
      } catch (error) { host.replaceChildren(); CW.fail(status, error, "load content"); }
    }
    var titles = {};
    function summary(kind, r, text) {
      // Catalog rows omit the saved details; the list shows the name and the
      // editor loads the wording. A remembered title is shown when known.
      return titles[kind + "|" + r.resource_id] || (text && text[KINDS[kind].prefix + "." + r.resource_id + ".title"]) || "";
    }
    $("cpp-kind").addEventListener("change", function () { state.kind = this.value; $("cpp-resource").hidden = true; renderKind(); });
    CW.fill($("cpp-locale"), CW.LOCALES); $("cpp-locale").value = state.locale;
    $("cpp-locale").addEventListener("change", function () { state.locale = this.value; renderKind(); });
    $("cpp-resource-new").addEventListener("click", function () { editResource(null); });

    var resourceForm = $("cpp-resource"), fields = $("cpp-resource-fields"), editing = null;
    function textKey(id, name) { return KINDS[state.kind].prefix + "." + id + "." + name; }
    async function editResource(record) {
      var kind = state.kind, spec = KINDS[kind]; resourceForm.reset(); fields.replaceChildren();
      var f = resourceForm.elements, payload = {};
      try {
        if (record && kind !== "translations") payload = (await call("/catalog/" + kind + "/" + encodeURIComponent(record.resource_id) + "/versions/" + record.version)).payload || {};
        var text = (await loadMessages(state.locale, true)).messages;
        for (var k of ["purposes", "topics", "custom-preferences", "notices", "templates", "themes"]) if (!state.items[k]) await ensureKind(k);
      } catch (error) { CW.fail(status, error, "open that item"); return; }
      editing = { kind: kind, record: record, payload: payload, text: text };
      f.resource_name.value = record ? CW.human(record.resource_id) : ""; f.resource_name.readOnly = !!record;
      f.resource_name.closest("label").hidden = kind === "translations";
      f.resource_id.value = record ? record.resource_id : ""; f.version.value = String(record ? record.current_version + 1 : 1);
      f.expected_current_version.value = String(record ? record.current_version : 0);
      $("cpp-resource-title").textContent = (kind === "translations" ? (record ? "Translate into " + CW.labelFor(CW.LOCALES, record.locale) : "Add a language") : (record ? "Edit " + CW.human(record.resource_id) : "New " + spec.noun));
      BUILD[kind](payload, text, record);
      CW.open(resourceForm, record ? "#cpp-resource-fields input, #cpp-resource-fields select, #cpp-resource-fields textarea" : "[name=resource_name]");
    }
    function t(payload, text, key) { return payload[key] ? words(text, payload[key]) : ""; }
    var BUILD = {
      "purposes": function (p, text) {
        fields.append(field("Title people see", input("title", "text", t(p, text, "title_key"), { required: "", maxlength: "200" }), true),
          field("Description", input("description", "textarea", t(p, text, "description_key"), { rows: "3", required: "" }), true),
          field("Legal reason", select("lawful_basis", BASES, p.lawful_basis || "consent")),
          field("Default", select("default_choice", DEFAULTS, p.default_choice || "denied")),
          field("Always on ", input("required", "checkbox", !!p.required), true, "People cannot turn this off (for example, what the site needs to work)."));
      },
      "topics": function (p, text) {
        var current = p.purpose ? p.purpose.id + "|" + p.purpose.version : "";
        fields.append(field("Part of which use of data", select("purpose_ref", latest("purposes"), current), true),
          field("Title people see", input("title", "text", t(p, text, "title_key"), { required: "", maxlength: "200" }), true),
          field("Description", input("description", "textarea", t(p, text, "description_key"), { rows: "3", required: "" }), true),
          field("Default", select("default_choice", DEFAULTS, p.default_choice || "denied")));
      },
      "custom-preferences": function (p, text) {
        fields.append(field("Question people see", input("title", "text", t(p, text, "title_key"), { required: "", maxlength: "200" }), true),
          field("Help text", input("description", "textarea", t(p, text, "description_key"), { rows: "2", required: "" }), true),
          field("Answer type", select("value_type", [{ value: "boolean", label: "Yes or no" }, { value: "single_select", label: "Pick one" }, { value: "multi_select", label: "Pick several" }], p.value_type || "boolean")),
          field("Answers to choose from (one per line)", input("options", "textarea", (p.option_ids || []).map(CW.human).join("\n"), { rows: "3" }), true, "Not needed for yes or no questions."),
          field("Answer required ", input("required", "checkbox", !!p.required), true, "People must answer this question."));
      },
      "notices": function (p, text) {
        fields.append(field("Title", input("title", "text", t(p, text, "title_key"), { required: "", maxlength: "200" }), true),
          field("Short summary people see", input("description", "textarea", t(p, text, "body_key"), { rows: "4", required: "" }), true),
          field("Notice document", input("document", "file", null, { accept: ".pdf,.html,.htm,.txt,.md,.doc,.docx" }), true,
            p.document_sha256 ? "A document is already attached. Choose a file only to replace it." : "Attach the full notice so Lightwork can prove which version people saw."));
      },
      "templates": function (p, text) {
        var themes = [{ value: "", label: "No brand theme" }].concat(latest("themes"));
        var chosenTheme = p.theme_token_version ? p.theme_token_id + "|" + p.theme_token_version : "";
        fields.append(field("Where it appears", select("surface", SURFACES, p.surface || "banner")),
          field("Brand theme", select("theme_ref", themes, chosenTheme)),
          field("Heading", input("title", "text", t(p, text, "title_key"), { required: "", maxlength: "200" }), true),
          field("Message", input("description", "textarea", t(p, text, "body_key"), { rows: "3", required: "" }), true));
        ACTIONS.forEach(function (a) {
          var key = (p.actions || {})[a[0]];
          fields.appendChild(field(a[1] + " text", input("action_" + a[0], "text", key ? words(text, key) : "", { maxlength: "80" }), false, "Leave empty to leave the button out."));
        });
      },
      "themes": function (p, text) {
        function color(name, label, fallback) { return field(label, input(name, "color", "#" + (p[name] || fallback))); }
        fields.append(field("Brand name", input("display_name", "text", t(p, text, "display_name_key"), { required: "", maxlength: "80" })),
          field("Heading", input("heading", "text", t(p, text, "heading_key"), { required: "", maxlength: "120" })),
          field("Description", input("description", "textarea", t(p, text, "description_key"), { rows: "2", required: "" }), true),
          color("primary_color", "Main button color", "1f5fbf"), color("primary_text_color", "Main button text color", "ffffff"),
          color("surface_color", "Background color", "ffffff"), color("text_color", "Text color", "1a1a1a"));
      },
      "translations": function (_p, _text, record) {
        var have = packLocales().map(function (l) { return l.locale; });
        var from = have.indexOf(state.locale) >= 0 ? state.locale : have[0];
        if (!from) { fields.appendChild(CW.el("p", "muted cw-wide", "Write some content first. Its text becomes your first language.")); return; }
        var target = record ? record.locale : "";
        var choices = CW.LOCALES.filter(function (l) { return record ? l.value === target : have.indexOf(l.value) < 0; });
        fields.append(field("Translate from", select("from_locale", CW.LOCALES.filter(function (l) { return have.indexOf(l.value) >= 0; }), from)),
          field("Into", select("to_locale", choices, target || (choices[0] && choices[0].value))));
        var rows = CW.el("div", "cw-wide"); rows.id = "cpp-translation-rows"; fields.appendChild(rows);
        async function paint() {
          rows.replaceChildren(CW.el("p", "muted", "Loading text…"));
          try {
            var source = (await loadMessages(resourceForm.elements.from_locale.value)).messages;
            var existing = (await loadMessages(resourceForm.elements.to_locale.value)).messages;
            rows.replaceChildren();
            Object.keys(source).forEach(function (key) {
              var box = input("message", "textarea", existing[key] || "", { rows: "2", "data-key": key });
              rows.appendChild(field(source[key], box, true));
            });
          } catch (error) { rows.replaceChildren(); CW.fail(status, error, "load the text to translate"); }
        }
        resourceForm.elements.from_locale.addEventListener("change", paint);
        resourceForm.elements.to_locale.addEventListener("change", paint);
        paint();
      },
      "rule-groups": function (p) {
        var list = CW.el("div", "cw-wide"); list.id = "cpp-rules";
        var add = CW.el("button", "btn", "Add a rule"); add.type = "button";
        add.addEventListener("click", function () { list.appendChild(ruleEditor({})); });
        fields.append(CW.el("p", "muted cw-wide", "Rules are checked from top to bottom; the first rule that matches a visitor's region and language is used."), list, add);
        ((p.rules && p.rules.length) ? p.rules : [{}]).forEach(function (r) { list.appendChild(ruleEditor(r)); });
      },
    };
    function refs(list) { return (list || []).map(function (r) { return r.id + "|" + r.version; }); }
    function ruleEditor(rule) {
      var box = CW.el("fieldset", "cw-form panel");
      var legend = CW.el("legend", "", "Rule"); box.appendChild(legend);
      var locales = packLocales().map(function (l) { return { value: l.locale, label: CW.labelFor(CW.LOCALES, l.locale) }; });
      box.append(
        field("Regions (leave empty for everywhere)", select("jurisdictions", CW.JURISDICTIONS, rule.jurisdictions || [], true)),
        field("Countries (optional)", select("country_codes", CW.COUNTRIES, rule.country_codes || [], true)),
        field("How to ask", select("consent_mode", MODES, rule.consent_mode || "opt_in")),
        field("Default language", select("default_locale", locales, rule.default_locale || (locales[0] && locales[0].value))));
      var langs = CW.el("fieldset", "cw-wide"); langs.append(CW.el("legend", "", "Languages"), checks("locales", locales, rule.locales || locales.map(function (l) { return l.value; }).slice(0, 1)));
      var uses = CW.el("fieldset", "cw-wide"); uses.append(CW.el("legend", "", "Uses of data"), checks("purposes", latest("purposes"), refs(rule.purposes)));
      var topics = CW.el("fieldset", "cw-wide"); topics.append(CW.el("legend", "", "Topics"), checks("topics", latest("topics"), refs(rule.topics)));
      var questions = CW.el("fieldset", "cw-wide"); questions.append(CW.el("legend", "", "Extra questions"), checks("custom_preferences", latest("custom-preferences"), refs(rule.custom_preferences)));
      box.append(langs, uses, topics, questions,
        field("Privacy notice", select("notice", [{ value: "", label: "Choose a notice" }].concat(latest("notices")), rule.notice ? rule.notice.id + "|" + rule.notice.version : "")),
        field("Banner design", select("template", [{ value: "", label: "Choose a design" }].concat(latest("templates")), rule.template ? rule.template.id + "|" + rule.template.version : "")));
      var remove = CW.el("button", "btn btn--ghost", "Remove this rule"); remove.type = "button";
      remove.addEventListener("click", function () { box.remove(); });
      var actions = CW.el("div", "cw-actions"); actions.appendChild(remove); box.appendChild(actions);
      return box;
    }
    function readRules() {
      var boxes = Array.prototype.slice.call(document.querySelectorAll("#cpp-rules > fieldset"));
      var versions = {}; packLocales().forEach(function (l) { versions[l.locale] = l.version; });
      return boxes.map(function (box, index) {
        var locales = picked(box, "locales");
        var def = box.querySelector("[name=default_locale]").value;
        if (!locales.length) throw new Error("Choose at least one language for each rule.");
        if (locales.indexOf(def) < 0) locales.unshift(def);
        var tv = {}; locales.forEach(function (l) { tv[l] = versions[l]; });
        var notice = ref(box.querySelector("[name=notice]").value), template = ref(box.querySelector("[name=template]").value);
        if (!notice || !template) throw new Error("Choose a privacy notice and a banner design for each rule.");
        return { rule_id: "rule-" + (index + 1), priority: Math.max(0, 1000 - index * 10), jurisdictions: multi(box, "jurisdictions"), country_codes: multi(box, "country_codes"),
          region_codes: [], locales: locales, default_locale: def, consent_mode: box.querySelector("[name=consent_mode]").value,
          purposes: picked(box, "purposes").map(ref), topics: picked(box, "topics").map(ref), custom_preferences: picked(box, "custom_preferences").map(ref),
          notice: notice, template: template, translation_catalog_id: state.pack, translation_versions: tv };
      });
    }
    function val(name) { var n = resourceForm.elements[name]; return n ? String(n.value || "").trim() : ""; }
    resourceForm.addEventListener("submit", async function (event) {
      event.preventDefault(); if (!editing) return;
      var kind = editing.kind, f = resourceForm.elements, p = editing.payload;
      try {
        if (kind === "translations") {
          var to = val("to_locale"), add = {};
          if (!to) { CW.say(status, "Choose the language to translate into.", true); return; }
          Array.prototype.forEach.call(resourceForm.querySelectorAll("[name=message]"), function (box) { if (box.value.trim()) add[box.dataset.key] = box.value.trim(); });
          if (!Object.keys(add).length) { CW.say(status, "Translate at least one text.", true); return; }
          await saveMessages(to, add); resourceForm.hidden = true; await renderKind();
          CW.say(status, "Saved the " + CW.labelFor(CW.LOCALES, to) + " text."); return;
        }
        var name = f.resource_name.value.trim(); if (!name) { CW.say(status, "Give it a name.", true); return; }
        var id = f.resource_id.value || CW.slug(name, KINDS[kind].prefix);
        if (!f.resource_id.value && (state.items[kind] || []).some(function (r) { return r.resource_id === id; })) { CW.say(status, "Something with that name already exists. Use Edit on its row.", true); return; }
        var body = { version: Number(f.version.value), expected_current_version: Number(f.expected_current_version.value), idempotency_key: CW.reference() }, messages = {};
        function textField(field, keyField, label) {
          var value = val(field); if (!value) throw new Error("Fill in " + label + ".");
          var key = p[keyField] || textKey(id, field); messages[key] = value; body[keyField] = key;
        }
        if (kind === "purposes" || kind === "topics" || kind === "custom-preferences") {
          textField("title", "title_key", "the title"); textField("description", "description_key", "the description");
        }
        if (kind === "purposes") { body.lawful_basis = val("lawful_basis"); body.required = f.required.checked; body.default_choice = val("default_choice"); }
        if (kind === "topics") {
          var purpose = ref(val("purpose_ref")); if (!purpose) throw new Error("Choose the use of data this topic belongs to.");
          body.purpose_id = purpose.id; body.purpose_version = purpose.version; body.default_choice = val("default_choice");
        }
        if (kind === "custom-preferences") {
          body.value_type = val("value_type"); body.required = f.required.checked;
          body.option_ids = body.value_type === "boolean" ? [] : lines(f.options.value).map(function (o) { return CW.slug(o, "answer"); });
          if (body.value_type !== "boolean" && !body.option_ids.length) throw new Error("Add the answers people can choose from.");
        }
        if (kind === "notices") {
          textField("title", "title_key", "the title"); textField("description", "body_key", "the summary");
          var file = f.document.files && f.document.files[0];
          body.document_sha256 = file ? await CW.sha256File(file) : p.document_sha256;
          if (!body.document_sha256) throw new Error("Attach the notice document.");
        }
        if (kind === "templates") {
          textField("title", "title_key", "the heading"); textField("description", "body_key", "the message");
          body.surface = val("surface"); body.actions = {};
          ACTIONS.forEach(function (a) { var v = val("action_" + a[0]); if (v) { var key = (p.actions || {})[a[0]] || textKey(id, "action." + a[0]); messages[key] = v; body.actions[a[0]] = key; } });
          if (!Object.keys(body.actions).length) throw new Error("Add the text for at least one button.");
          var theme = ref(val("theme_ref")); body.theme_token_id = theme ? theme.id : (p.theme_token_id || "default"); body.theme_token_version = theme ? theme.version : null;
        }
        if (kind === "themes") {
          textField("display_name", "display_name_key", "the brand name"); textField("heading", "heading_key", "the heading"); textField("description", "description_key", "the description");
          ["primary_color", "primary_text_color", "surface_color", "text_color"].forEach(function (c) { body[c] = val(c).replace(/^#/, ""); });
        }
        if (kind === "rule-groups") {
          var rules = readRules();
          if (!rules.length) throw new Error("Add at least one rule.");
          var purposeOfTopic = {};
          await Promise.all((state.items.topics || []).map(async function (tp) {
            var detail = await call("/catalog/topics/" + encodeURIComponent(tp.resource_id) + "/versions/" + tp.version);
            purposeOfTopic[tp.resource_id + "|" + tp.version] = detail.payload && detail.payload.purpose;
          }));
          rules.forEach(function (r) {
            r.topics.forEach(function (tp) {
              var owner = purposeOfTopic[tp.id + "|" + tp.version];
              if (owner && !r.purposes.some(function (x) { return x.id === owner.id && x.version === owner.version; })) throw new Error("Tick the use of data that each chosen topic belongs to.");
            });
          });
          body.rules = rules;
        }
        if (Object.keys(messages).length) await saveMessages(state.locale, messages);
        await call("/" + KINDS[kind].endpoint + "/" + encodeURIComponent(id) + "/versions", { method: "POST", json: body });
        titles[kind + "|" + id] = messages[body.title_key] || messages[body.display_name_key] || "";
        resourceForm.hidden = true; await renderKind(); CW.say(status, "Saved " + CW.human(id) + ".");
      } catch (error) {
        if (error && error.status === undefined && error.message && !/fetch|network/i.test(error.message)) CW.say(status, error.message, true);
        else CW.fail(status, error, "save");
      }
    });

    if ($("cpp-root").dataset.featureEnabled === "false") { ["cpp-property-table", "cpp-resource-table"].forEach(function (id) { $(id).replaceChildren(CW.el("p", "muted", "Turn this feature on to use it.")); }); return; }
    loadProperties().catch(function (error) { $("cpp-property-table").replaceChildren(); CW.fail(status, error, "load your websites and apps"); });
    renderKind();
  }
})();
