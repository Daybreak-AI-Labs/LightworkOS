/* Accessible, registry-backed command menu for the Lightwork shell: "Search or
   run a command". The server renders every allowed destination and every
   command the person may use into the dialog. This module only filters, ranks
   and activates those options; it never constructs a route, and a command only
   opens the page's own form or confirmation -- it never decides, stops work or
   saves anything by itself. */
(function (global) {
  "use strict";

  // Typing one of these first narrows the search. The shortcuts dialog lists
  // the ones that apply to this person (prefixes()).
  var PREFIXES = {">": "actions", "/": "pages", "#": "records", "@": "people", ":": "settings"};
  var SETTING_SCOPES = {all: true, actions: true, settings: true};

  function init(documentRef) {
    var doc = documentRef || global.document;
    if (!doc) return null;

    var trigger = doc.getElementById("navfinder-open");
    var dialog = doc.getElementById("navfinder-dialog");
    var input = doc.getElementById("navfinder-input");
    var results = doc.getElementById("navfinder-results");
    var closeButton = doc.getElementById("navfinder-close");
    var count = doc.getElementById("navfinder-count");
    var empty = doc.getElementById("navfinder-empty");
    if (!trigger || !dialog || !input || !results || !closeButton || !count || !empty) {
      return null;
    }
    if (dialog.getAttribute("data-navfinder-ready") === "true") return null;
    dialog.setAttribute("data-navfinder-ready", "true");

    var options = Array.prototype.slice.call(
      results.querySelectorAll("[data-navfinder-target]")
    );
    var pageOptions = options.slice();
    // Commands are rendered with the dialog, only for people who may use them.
    var actionOptions = Array.prototype.slice.call(results.querySelectorAll("[data-navfinder-action]"));
    var recordOptions = [];
    var settingOptions = [];
    var peopleOptions = [];
    // People, agents and specialists, waiting approvals and help from the
    // server's own permission-checked search (/nav/finder/find).
    var foundOptions = [], weakFound = [];
    var choiceOptions = [];
    var activeIndex = -1;
    var returnFocus = null;
    var isOpen = false;
    var placedOrder = "";
    var afterClose = [];
    // A command's list of choices (Approve or reject…) while it is open.
    var mode = null, modeQuery = "", listGeneration = 0, listLoading = false;
    var modeChip = doc.getElementById("navfinder-mode");
    var emptyCopy = doc.getElementById("navfinder-empty-copy");
    var emptyDefault = null, emptyScope = "all";
    var peopleSource = results.getAttribute("data-navfinder-people");
    var recordsOn = results.getAttribute("data-navfinder-records") !== null;
    var peopleTimer = null, peopleGeneration = 0;
    var findSource = results.getAttribute("data-navfinder-find");
    var findTimer = null, findGeneration = 0, foundFor = "";
    // The destinations are server-rendered by GET /nav/finder (the same
    // role-filtered registry as the sidebar) and inserted on first open, so
    // every page does not carry the whole list. The list is never built here.
    var source = results.getAttribute("data-navfinder-src");
    var loaded = !source || pageOptions.length > 0;
    var loading = null;

    function copy(node, text, values) {
      if (global.LightworkI18n) global.LightworkI18n.set(node, text, values);
      else node.textContent = String(text).replace(/\{(\w+)\}/g, function (whole, name) {
        return values && Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : whole;
      });
    }

    function phrase(text, values) {
      if (global.LightworkI18n) return global.LightworkI18n.text(text, values);
      return String(text).replace(/\{(\w+)\}/g, function (whole, name) {
        return values && Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : whole;
      });
    }

    function adoptPages() {
      pageOptions = Array.prototype.slice.call(results.querySelectorAll("[data-navfinder-target]"));
      pageOptions.forEach(bindOption);
      loaded = true;
    }

    function ensureLoaded() {
      if (loaded) return Promise.resolve();
      if (loading) return loading;
      count.textContent = "Loading pages…";
      loading = global.fetch(source, {headers: {"Accept": "text/html"}, credentials: "same-origin"})
        .then(function (response) {
          if (!response.ok) throw new Error("finder unavailable");
          return response.text();
        })
        .then(function (html) {
          results.insertAdjacentHTML("afterbegin", html);
          adoptPages();
          filterResults();
        })
        .catch(function () {
          count.textContent = "Pages could not be loaded. Use the sidebar, or try again.";
        })
        .finally(function () { loading = null; });
      return loading;
    }

    function normalise(value) {
      return String(value || "").replace(/[‘’]/g, "'").replace(/\s+/g, " ").trim().toLowerCase();
    }

    // What was typed: the narrowed scope (a leading prefix, or the open
    // command's list) and the words to match.
    function parsed() {
      var raw = String(input.value || "");
      if (mode) return {scope: mode, text: raw.trim()};
      var start = raw.replace(/^\s+/, "");
      var scope = PREFIXES[start.charAt(0)];
      return scope ? {scope: scope, text: start.slice(1).trim()} : {scope: "all", text: raw.trim()};
    }

    // How well a page's own names match what was typed, strongest first: the
    // whole name, its start, the start of each word, then words inside it.
    // Labels outrank the page heading, which outranks a synonym; a match only
    // in the group, address or aliases ranks below every named match.
    var NAME_FIELDS = [["data-label", 3], ["data-heading", 2], ["data-synonyms", 1]];

    function nameTier(name, query, terms) {
      if (name === query) return 4;
      if (name.indexOf(query) === 0) return 3;
      var words = name.split(/[^\p{L}\p{N}']+/u);
      var starts = terms.every(function (term) {
        return words.some(function (word) { return word.indexOf(term) === 0; });
      });
      if (starts) return 2;
      return terms.every(function (term) { return name.indexOf(term) !== -1; }) ? 1 : 0;
    }

    function score(option, query, terms) {
      var best = 0;
      NAME_FIELDS.forEach(function (field) {
        String(option.getAttribute(field[0]) || "").split("|").forEach(function (name) {
          var tier = name ? nameTier(normalise(name), query, terms) : 0;
          if (tier) best = Math.max(best, tier * 4 + field[1]);
        });
      });
      if (best) return best;
      var haystack = normalise(option.getAttribute("data-search"));
      return terms.every(function (term) { return haystack.indexOf(term) !== -1; }) ? 1 : 0;
    }

    // The person's pinned and recent pages, from the sidebar's own lists:
    // {href: [list, position]} with pins (0) before recent pages (1).
    var personal = {};
    function readPersonal() {
      personal = {};
      if (typeof doc.querySelectorAll !== "function") return;
      ["pins", "recent"].forEach(function (list, rankOfList) {
        Array.prototype.forEach.call(doc.querySelectorAll('[data-nav-list="' + list + '"] a[href]'), function (link, position) {
          var href = link.getAttribute("href");
          if (!personal[href]) personal[href] = [rankOfList, position];
        });
      });
    }

    // Best matches first. A command and a page that match equally well put
    // the command first (typing "pause" offers the emergency stop itself),
    // then the person's pinned and recent pages; other equal pages keep the
    // sidebar's registry order. An empty box starts with pinned and recent
    // pages, then the commands, then every other page.
    function rank(scope, query) {
      var terms = query.split(" ").filter(Boolean);
      var entries = [];
      if (scope === "all" || scope === "actions") {
        actionOptions.forEach(function (option, index) { entries.push({option: option, kind: 0, index: index}); });
      }
      if (scope === "all" || scope === "pages") {
        pageOptions.forEach(function (option, index) {
          var mine = personal[option.getAttribute("href")];
          entries.push({option: option, kind: mine ? 1 + mine[0] : 3, index: mine ? mine[1] : index});
        });
      }
      // A person, agent, approval or help topic named exactly what was typed
      // outranks a page that only partly matches; equal matches list pages first.
      if (scope === "all" && terms.length) {
        foundOptions.forEach(function (option, index) { entries.push({option: option, kind: 4, index: index}); });
      }
      entries.forEach(function (entry) {
        entry.score = terms.length ? score(entry.option, query, terms) : 1;
        // Before the commands while nothing is typed.
        if (!terms.length && (entry.kind === 1 || entry.kind === 2)) entry.kind -= 3;
        // The server matched it (question words aside), so it always shows;
        // a page named as well wins, so a person, agent or topic needs a
        // clearly better name match to come first.
        if (entry.kind === 4) entry.score = Math.max(1, entry.score - 4);
      });
      // A person, agent or topic that matched only in its description waits
      // below the records (filterResults), so it never pushes a named task down.
      weakFound = entries.filter(function (entry) { return entry.kind === 4 && entry.score <= 1; })
        .map(function (entry) { return entry.option; });
      entries = entries.filter(function (entry) { return !(entry.kind === 4 && entry.score <= 1); });
      return entries.sort(function (a, b) { return b.score - a.score || a.kind - b.kind || a.index - b.index; });
    }

    function rankable(item) {
      return !!(item.querySelector && (item.querySelector("[data-navfinder-target]") || item.querySelector("[data-navfinder-action]") ||
        item.querySelector("[data-navfinder-found]")));
    }

    // Keep the listbox in the order people hear and arrow through: ranked
    // commands and pages first, then records, settings and people as they arrive.
    function placeRanked(ranked) {
      if (typeof results.insertBefore !== "function") return;
      var after = null;
      for (var child = results.firstElementChild; child; child = child.nextElementSibling) {
        if (!rankable(child)) { after = child; break; }
      }
      ranked.forEach(function (entry) {
        var item = entry.option.parentElement;
        if (item && item.parentElement === results) results.insertBefore(item, after);
      });
    }

    function hide(option, hidden) {
      option.hidden = hidden;
      if (option.parentElement) option.parentElement.hidden = hidden;
    }

    function visibleOptions() {
      return options.filter(function (option) { return !option.hidden; });
    }

    function setActive(index, shouldScroll) {
      var visible = visibleOptions();
      options.forEach(function (option) {
        option.classList.remove("is-active");
        option.setAttribute("aria-selected", "false");
      });

      if (!visible.length) {
        activeIndex = -1;
        input.removeAttribute("aria-activedescendant");
        return null;
      }

      activeIndex = ((index % visible.length) + visible.length) % visible.length;
      var selected = visible[activeIndex];
      selected.classList.add("is-active");
      selected.setAttribute("aria-selected", "true");
      input.setAttribute("aria-activedescendant", selected.id);
      if (shouldScroll && typeof selected.scrollIntoView === "function") {
        selected.scrollIntoView({ block: "nearest" });
      }
      return selected;
    }

    function shown(list) {
      return list.filter(function (option) { return !option.hidden; }).length;
    }

    // "3 pages, 2 commands, 4 records shown": each part only where it applies.
    function describe(scope) {
      var parts = [];
      var pages = shown(pageOptions), actions = shown(actionOptions);
      if (scope === "approvals") {
        if (listLoading) return [["Loading requests waiting for you…"]];
        var waiting = choiceOptions.filter(function (option) { return option.getAttribute("data-navfinder-request") !== null; });
        return waiting.length ? [["{count} request waiting", "{count} requests waiting", shown(waiting)]]
          : [["Nothing is waiting for your decision."]];
      }
      if (scope === "all" || scope === "pages") parts.push(["{count} page", "{count} pages", pages]);
      if ((scope === "all" && actions) || scope === "actions") parts.push(["{count} command", "{count} commands", actions]);
      if (scope === "all" || scope === "records") {
        if (recordOptions.length || scope === "records") parts.push(["{count} record shown", "{count} records shown", shown(recordOptions)]);
      }
      if (SETTING_SCOPES[scope] && (settingOptions.length || scope === "settings")) {
        parts.push(["{count} setting shown", "{count} settings shown", shown(settingOptions)]);
      }
      if (scope === "people") parts.push(["{count} person shown", "{count} people shown", shown(peopleOptions)]);
      if (scope === "all" && shown(foundOptions)) {
        parts.push(["{count} person, agent, approval or help topic", "{count} people, agents, approvals or help topics", shown(foundOptions)]);
      }
      return parts;
    }

    function english(part) {
      if (part.length === 1) return part[0];
      return (part[2] === 1 ? part[0] : part[1]).replace("{count}", String(part[2]));
    }

    function writeCount(scope) {
      var parts = describe(scope);
      if (global.LightworkI18n) {
        var locale = global.LightworkI18n;
        parts.forEach(function (part, index) {
          var text = part.length === 1 ? locale.text(part[0]) : locale.plural(part[0], part[1], part[2]);
          if (!index) { locale.set(count, text); return; }
          count.appendChild(doc.createTextNode(", "));
          var partCount = doc.createElement("span");
          locale.set(partCount, text);
          count.appendChild(partCount);
        });
        if (!parts.length) count.textContent = "";
      } else count.textContent = parts.map(english).join(", ");
    }

    // The empty state says what this narrowed search covers.
    function writeEmpty(scope) {
      if (!emptyCopy || !emptyCopy.content || scope === emptyScope) return;
      if (!emptyDefault) emptyDefault = Array.prototype.map.call(empty.childNodes, function (node) { return node.cloneNode(true); });
      var copySource = scope === "all" ? null : emptyCopy.content.querySelector('[data-scope="' + scope + '"]');
      var nodes = copySource ? Array.prototype.map.call(copySource.childNodes, function (node) { return node.cloneNode(true); })
        : emptyDefault.map(function (node) { return node.cloneNode(true); });
      empty.replaceChildren.apply(empty, nodes);
      emptyScope = scope;
    }

    // In a list of commands a setting reads as one: "Open setting: Theme".
    function setVerb(option, on) {
      var label = option.querySelector && option.querySelector(".navfinder__label");
      if (!label) return;
      var verb = label.querySelector("[data-navfinder-verb]");
      if (on && !verb) {
        verb = doc.createElement("span"); verb.setAttribute("data-navfinder-verb", "");
        copy(verb, "Open setting:");
        label.insertBefore(doc.createTextNode(" "), label.firstChild);
        label.insertBefore(verb, label.firstChild);
      } else if (!on && verb) {
        if (verb.nextSibling && verb.nextSibling.nodeType === 3) verb.nextSibling.remove();
        verb.remove();
      }
    }

    function matchesChoice(option, text) {
      var terms = normalise(text).split(" ").filter(Boolean);
      var haystack = normalise(option.textContent);
      return terms.every(function (term) { return haystack.indexOf(term) !== -1; });
    }

    function filterResults() {
      var query = parsed(), scope = query.scope;
      var ranked = rank(scope, normalise(query.text));
      actionOptions.forEach(function (option) { hide(option, true); });
      pageOptions.forEach(function (option) { hide(option, true); });
      foundOptions.forEach(function (option) { hide(option, true); });
      ranked.forEach(function (entry) { hide(entry.option, !entry.score); });
      var order = ranked.map(function (entry) { return entry.option.id; }).join(",");
      if (order !== placedOrder) {
        placeRanked(ranked);
        placedOrder = order;
      }
      recordOptions.forEach(function (option) { hide(option, !(scope === "all" || scope === "records")); });
      settingOptions.forEach(function (option) {
        hide(option, !SETTING_SCOPES[scope]);
        setVerb(option, scope === "actions" || scope === "settings");
      });
      peopleOptions.forEach(function (option) { hide(option, scope !== "people"); });
      choiceOptions.forEach(function (option) { hide(option, scope !== mode || !matchesChoice(option, query.text)); });
      weakFound.forEach(function (option) {
        hide(option, false);
        if (option.parentElement && typeof results.appendChild === "function") results.appendChild(option.parentElement);
      });
      options = ranked.map(function (entry) { return entry.option; })
        .concat(recordOptions, weakFound, settingOptions, peopleOptions, choiceOptions);

      var visible = visibleOptions();
      writeCount(scope);
      writeEmpty(scope);
      empty.hidden = visible.length !== 0 || (scope === "approvals" && listLoading);
      results.hidden = visible.length === 0;
      setActive(visible.length ? 0 : -1, false);
      return visible;
    }

    function canRestoreFocus(node) {
      if (!node || typeof node.focus !== "function" || node.isConnected === false) return false;
      try {
        return !(typeof node.closest === "function" && node.closest("[inert]"));
      } catch (error) {
        return false;
      }
    }

    function restoreFocus() {
      var target = canRestoreFocus(returnFocus) ? returnFocus : doc.getElementById("nav-toggle");
      returnFocus = null;
      if (canRestoreFocus(target)) target.focus();
    }

    // Run what a command asked for once the menu has closed and handed focus
    // back, so a confirmation it opens keeps the focus.
    function flushAfterClose() {
      var queued = afterClose.splice(0, afterClose.length);
      queued.forEach(function (callback) { callback(); });
    }

    function onClosed() {
      if (!isOpen) return;
      isOpen = false;
      trigger.setAttribute("aria-expanded", "false");
      input.setAttribute("aria-expanded", "false");
      input.removeAttribute("aria-activedescendant");
      if (mode) leaveList(true);
      queryChanged("closed");
      restoreFocus();
      flushAfterClose();
    }

    function closeFinder(then) {
      if (typeof then === "function") afterClose.push(then);
      if (!isOpen) {
        flushAfterClose();
        return;
      }
      if (dialog.open && typeof dialog.close === "function") {
        dialog.close();
        // The close event arrives later; settle now so a quick Ctrl+K reopens.
        onClosed();
      } else {
        dialog.removeAttribute("open");
        onClosed();
      }
    }

    function refreshPinLabel() {
      var pins = global.LightworkPins;
      actionOptions.forEach(function (option) {
        if (option.getAttribute("data-navfinder-action") !== "pin" || !pins) return;
        var text = option.getAttribute(pins.isPinned() ? "data-label-unpin" : "data-label-pin");
        var label = option.querySelector && option.querySelector(".navfinder__label");
        if (!text || !label) return;
        copy(label, text);
        option.setAttribute("data-label", text + "|" + phrase(text));
      });
    }

    function openFinder(opener) {
      if (isOpen) {
        input.focus({ preventScroll: true });
        return;
      }
      returnFocus = opener || doc.activeElement || trigger;
      isOpen = true;
      trigger.setAttribute("aria-expanded", "true");
      input.setAttribute("aria-expanded", "true");
      input.value = "";
      refreshPinLabel();
      readPersonal();
      if (loaded) filterResults(); else ensureLoaded();
      if (typeof dialog.showModal === "function") {
        dialog.showModal();
      } else {
        dialog.setAttribute("open", "");
      }
      input.focus({ preventScroll: true });
      queryChanged("opened");
    }

    trigger.addEventListener("click", function () { openFinder(trigger); });
    closeButton.addEventListener("click", function () { closeFinder(); });
    input.addEventListener("input", function () {
      var query = parsed();
      if (query.scope === "people") searchPeople(query.text);
      else if (peopleOptions.length) setPeople([]);
      if (query.scope === "all") searchFound(query.text);
      else if (foundOptions.length) setFound([]);
      filterResults();
      queryChanged("input");
    });

    // A search has an address (?find=…) that reproduces it, without
    // adding a Back step; closing the finder removes it again.
    function rememberQuery(reason) {
      var history = global.history, loc = global.location;
      if (!history || !history.replaceState || !loc || typeof global.URL !== "function") return;
      var url = new global.URL(loc.href);
      if (reason === "closed" || !input.value) url.searchParams.delete("find");
      else url.searchParams.set("find", input.value);
      if (url.href !== loc.href) history.replaceState(history.state, "", url.pathname + url.search + url.hash);
    }

    // Other searches (settings, records) listen for this. Each only searches
    // within the scope that includes it, with the prefix removed.
    function queryChanged(reason) {
      if (reason !== "opened") rememberQuery(reason);
      if (typeof global.CustomEvent === "function") {
        var query = parsed();
        dialog.dispatchEvent(new global.CustomEvent("lightwork:finder-query", {detail: {
          reason: reason, scope: query.scope, text: query.text,
          query: SETTING_SCOPES[query.scope] ? query.text : "",
        }}));
      }
    }

    function hover(option) {
      // Late results can appear under a stationary pointer. A boundary-enter
      // event then belongs to layout, not a new choice by the person typing.
      option.addEventListener("mousemove", function () {
        var index = visibleOptions().indexOf(option);
        if (index >= 0) setActive(index, false);
      });
    }

    function bindOption(option) {
      hover(option);
      option.addEventListener("click", function () { closeFinder(); });
    }

    function stop(event) {
      if (event && typeof event.preventDefault === "function") event.preventDefault();
    }

    // The emergency stop's own control asks for confirmation before anything
    // stops; the menu only presses it, and never while work is stopped (that
    // press would resume work).
    function pressEmergencyStop() {
      var pill = doc.getElementById("halt-pill");
      if (!pill || pill.getAttribute("data-can-halt") !== "true") return;
      if (doc.body && doc.body.classList && doc.body.classList.contains("halt-armed")) {
        var message = "Work is already stopped. Use the emergency stop control to resume it.";
        if (typeof global.mvToast === "function") global.mvToast(phrase(message));
        return;
      }
      pill.click();
    }

    function composerField() {
      if (typeof doc.querySelector !== "function") return null;
      return doc.querySelector('form[action="/chat/send"] textarea[name="title"]');
    }

    function runAction(option, event) {
      var name = option.getAttribute("data-navfinder-action");
      if (name === "approvals") { stop(event); enterList(option); return; }
      if (name === "setting") {
        stop(event);
        input.value = ": ";
        filterResults();
        queryChanged("input");
        input.focus({ preventScroll: true });
        return;
      }
      if (name === "halt") { stop(event); closeFinder(pressEmergencyStop); return; }
      if (name === "pin") {
        stop(event);
        closeFinder(function () { if (global.LightworkPins) global.LightworkPins.toggle(); });
        return;
      }
      if (name === "shortcuts") {
        stop(event);
        closeFinder(function () { if (global.LightworkShortcuts) global.LightworkShortcuts.open(); });
        return;
      }
      var field = name === "new-task" ? composerField() : null;
      if (field) { stop(event); closeFinder(function () { field.focus(); }); return; }
      closeFinder();  // a link: the browser follows it
    }

    actionOptions.forEach(function (option) {
      hover(option);
      option.addEventListener("click", function (event) { runAction(option, event); });
    });

    // One result row: a name and where it lives. Names that come from records
    // or people are isolated as user content; the rest is product copy.
    function resultRow(prefix, index, row, userTitle) {
      var entry = doc.createElement("li"); entry.setAttribute("role", "none");
      var option = doc.createElement("a"); option.id = prefix + index;
      option.href = row.href; option.setAttribute("role", "option"); option.setAttribute("tabindex", "-1");
      option.setAttribute("aria-selected", "false");
      var label = doc.createElement("span"); label.className = "navfinder__label";
      if (userTitle) {
        label.textContent = row.title; label.lang = "und"; label.dir = "auto"; label.setAttribute("data-user-content", "");
      } else copy(label, row.title);
      var description = doc.createElement("span"); description.className = "navfinder__group";
      option.appendChild(label); option.appendChild(description); entry.appendChild(option);
      return {entry: entry, option: option, description: description};
    }

    function setRecords(rows) {
      recordOptions.forEach(function (option) { option.parentElement.remove(); });
      recordOptions = [];
      rows.forEach(function (row, index) {
        var built = resultRow("navfinder-record-", index, row, true), description = built.description;
        var reference = doc.createElement("bdi"); reference.lang = "und"; reference.dir = "auto"; reference.setAttribute("data-user-content", "");
        reference.textContent = row.kind + " · " + row.id; description.appendChild(reference);
        if (row.revision) {
          description.appendChild(doc.createTextNode(" · "));
          var version = doc.createElement("span");
          if (global.LightworkI18n) global.LightworkI18n.set(version, "Version"); else version.textContent = "version";
          var revision = doc.createElement("bdi"); revision.lang = "und"; revision.dir = "auto"; revision.setAttribute("data-user-content", "");
          revision.textContent = row.revision; description.append(version, doc.createTextNode(" "), revision);
        }
        if (row.state) {
          var state = doc.createElement("bdi"); state.lang = "und"; state.dir = "auto"; state.setAttribute("data-user-content", "");
          state.textContent = row.state.replaceAll("_", " "); description.append(doc.createTextNode(" · "), state);
        }
        results.appendChild(built.entry);
        recordOptions.push(built.option); bindOption(built.option);
      });
      filterResults();
      if (!isOpen) input.removeAttribute("aria-activedescendant");
    }

    function setSettings(rows) {
      settingOptions.forEach(function (option) { option.parentElement.remove(); }); settingOptions = [];
      rows.forEach(function (row, index) {
        var entry = doc.createElement("li"); entry.setAttribute("role", "none");
        var option = doc.createElement("a"); option.id = "navfinder-setting-" + index; option.href = row.href;
        option.setAttribute("role", "option"); option.setAttribute("tabindex", "-1"); option.setAttribute("aria-selected", "false");
        var label = doc.createElement("span"); label.className = "navfinder__label";
        var title = doc.createElement("bdi"); title.lang = "und"; title.dir = "auto"; title.setAttribute("data-user-content", "");
        title.textContent = row.title; label.appendChild(title);
        var group = doc.createElement("span"); group.className = "navfinder__group";
        var prefix = doc.createElement("span"); copy(prefix, "Setting");
        var metadata = doc.createElement("bdi"); metadata.lang = "und"; metadata.dir = "auto"; metadata.setAttribute("data-user-content", "");
        metadata.textContent = row.group + (row.effective ? " - " + row.effective : "") + (row.required_role ? " - " + row.required_role : "");
        group.append(prefix, doc.createTextNode(" › "), metadata);
        option.appendChild(label); option.appendChild(group); entry.appendChild(option); results.appendChild(entry);
        settingOptions.push(option); bindOption(option);
      });
      filterResults();
    }

    // People for "@": only from the server's own people search, which admits
    // exactly the people who may open the Users page.
    function setPeople(rows) {
      peopleOptions.forEach(function (option) { option.parentElement.remove(); }); peopleOptions = [];
      rows.forEach(function (row, index) {
        if (!row || typeof row.label !== "string" || row.href !== "/users") return;
        var built = resultRow("navfinder-person-", index, {href: row.href, title: row.label}, true);
        var people = doc.createElement("span"); copy(people, "People");
        built.description.appendChild(people);
        if (row.role) {
          var role = doc.createElement("bdi"); role.lang = "und"; role.dir = "auto"; role.setAttribute("data-user-content", "");
          role.textContent = row.role; built.description.append(doc.createTextNode(" › "), role);
        }
        results.appendChild(built.entry);
        peopleOptions.push(built.option); bindOption(built.option);
      });
      filterResults();
    }

    function searchPeople(text) {
      var generation = ++peopleGeneration;
      if (peopleTimer) global.clearTimeout(peopleTimer);
      if (!peopleSource || !text) { setPeople([]); return; }
      peopleTimer = global.setTimeout(function () {
        peopleTimer = null;
        global.mvFetchJSON(peopleSource + "?q=" + encodeURIComponent(text.slice(0, 100)), {cache: "no-store"})
          .then(function (data) {
            if (generation !== peopleGeneration || parsed().scope !== "people") return;
            setPeople(data && Array.isArray(data.people) ? data.people : []);
          })
          .catch(function () { if (generation === peopleGeneration) setPeople([]); });
      }, 200);
    }

    // People, agents and specialists, approvals and help topics for an
    // ordinary search. Each row is checked on the server for this person;
    // only these destinations are accepted.
    var FOUND_KINDS = {person: "People", specialist: "Specialist", agent: "Agent", approval: "Approval waiting", help: "Help"};
    var FOUND_HREF = /^\/(?:users\?q=[^#\s]*#people|agents\?name=[A-Za-z0-9%_.-]+|approvals#approval-[A-Za-z0-9_-]{1,64}|help#how-[a-z0-9-]+)$/;
    function setFound(rows, forText) {
      foundOptions.forEach(function (option) { option.parentElement.remove(); }); foundOptions = []; weakFound = [];
      foundFor = rows.length ? String(forText || "") : "";
      rows.forEach(function (row, index) {
        if (!row || !FOUND_KINDS[row.kind] || typeof row.title !== "string" || typeof row.href !== "string" || !FOUND_HREF.test(row.href)) return;
        var built = resultRow("navfinder-found-", index, row, row.kind !== "help");
        var labels = Array.isArray(row.labels) ? row.labels.filter(function (label) { return typeof label === "string"; }) : [];
        built.option.setAttribute("data-navfinder-found", row.kind);
        built.option.setAttribute("data-label", (labels.length ? labels : [row.title]).join("|"));
        built.option.setAttribute("data-search", row.title + " " + (row.context || ""));
        var kind = doc.createElement("span"); copy(kind, FOUND_KINDS[row.kind]);
        built.description.appendChild(kind);
        if (row.context) {
          var context = doc.createElement("bdi"); context.lang = "und"; context.dir = "auto"; context.setAttribute("data-user-content", "");
          context.textContent = String(row.context).slice(0, 160); built.description.append(doc.createTextNode(" › "), context);
        }
        results.appendChild(built.entry);
        foundOptions.push(built.option); bindOption(built.option);
      });
      placedOrder = "";
      filterResults();
    }

    function searchFound(text) {
      var generation = ++findGeneration;
      if (findTimer) global.clearTimeout(findTimer);
      // Rows found for earlier words never stand in for the new ones.
      if (foundOptions.length && text !== foundFor) setFound([]);
      if (!findSource || Array.from(String(text || "").replace(/\s+/g, "")).length < 2) { if (foundOptions.length) setFound([]); return; }
      findTimer = global.setTimeout(function () {
        findTimer = null;
        global.mvFetchJSON(findSource + "?q=" + encodeURIComponent(text.slice(0, 100)), {cache: "no-store"})
          .then(function (data) {
            if (generation !== findGeneration || parsed().scope !== "all") return;
            setFound(data && Array.isArray(data.results) ? data.results : [], text);
          })
          .catch(function () { if (generation === findGeneration) setFound([]); });
      }, 60);
    }

    // "Approve or reject…": the requests this person may decide, from the
    // Approvals page's own permission-checked list. Choosing one opens its
    // card on the Approvals page, where the page's buttons and confirmation
    // decide; nothing is decided here.
    var RISKS = {low: "Low risk", medium: "Medium risk", high: "High risk", critical: "Critical risk"};

    function actionTitle(action) {
      var text = String(action || "").trim();
      if (!text) return phrase("Reviewed action");
      if (text.indexOf(" ") === -1) text = text.replace(/[._]+/g, " ");
      return text.charAt(0).toUpperCase() + text.slice(1);
    }

    function approvalRows(data) {
      var rows = [];
      (data && Array.isArray(data.approvals) ? data.approvals : []).forEach(function (item) {
        var id = String(item && item.id);
        if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) return;
        rows.push({href: "/approvals#approval-" + id, title: actionTitle(item.action),
          context: RISKS[item.risk] || "Waiting for a decision", request: true});
      });
      (data && Array.isArray(data.flow_approvals) ? data.flow_approvals : []).forEach(function (item) {
        var href = item && item.href;
        if (typeof href !== "string" || !/^\/[A-Za-z0-9/_.~%?=&#-]*$/.test(href) || href.indexOf("//") === 0) return;
        rows.push({href: href, title: String(item.title || phrase("Flow approval")), context: "Flow approval", request: true});
      });
      rows.push({href: "/approvals", title: "Open Approvals", context: "Every request waiting for you", product: true});
      return rows;
    }

    function setChoices(rows) {
      choiceOptions.forEach(function (option) { option.parentElement.remove(); }); choiceOptions = [];
      rows.forEach(function (row, index) {
        var built = resultRow("navfinder-choice-", index, row, !row.product);
        var area = doc.createElement("span"); copy(area, "Approvals");
        var context = doc.createElement("span"); copy(context, row.context);
        built.description.append(area, doc.createTextNode(" › "), context);
        if (row.request) built.option.setAttribute("data-navfinder-request", "");
        results.appendChild(built.entry);
        choiceOptions.push(built.option); bindOption(built.option);
      });
      filterResults();
    }

    function enterList(option) {
      var listSource = option.getAttribute("data-navfinder-list");
      if (!listSource) return;
      modeQuery = input.value;
      mode = "approvals";
      input.value = "";
      if (modeChip) {
        modeChip.hidden = false;
        copy(modeChip, "Approve or reject");
      }
      var generation = ++listGeneration;
      listLoading = true;
      setChoices([]);
      queryChanged("input");
      input.focus({ preventScroll: true });
      global.mvFetchJSON(listSource, {cache: "no-store"})
        .then(function (data) {
          if (generation !== listGeneration || mode !== "approvals") return;
          listLoading = false;
          setChoices(approvalRows(data));
        })
        .catch(function () {
          if (generation !== listGeneration || mode !== "approvals") return;
          listLoading = false;
          setChoices([{href: "/approvals", title: "Open Approvals", context: "Waiting requests could not be loaded here", product: true}]);
        });
    }

    function leaveList(quietly) {
      listGeneration += 1;
      listLoading = false;
      mode = null;
      if (modeChip) modeChip.hidden = true;
      input.value = quietly ? "" : modeQuery;
      setChoices([]);
      if (!quietly) {
        queryChanged("input");
        input.focus({ preventScroll: true });
      }
    }

    dialog.addEventListener("cancel", function (event) {
      event.preventDefault();
      if (mode) leaveList(false); else closeFinder();
    });
    // A late close event must not undo a reopen that already happened.
    dialog.addEventListener("close", function () { if (!dialog.open) onClosed(); });
    dialog.addEventListener("keydown", function (event) {
      if (event.isComposing) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        // Escape first goes back from a command's list of choices.
        if (mode) leaveList(false); else closeFinder();
        return;
      }
      // Arrow/Enter listbox control belongs to the combobox. Do not consume
      // those keys when a user tabs to the dialog's Close button.
      if (event.target !== input) return;
      if (event.key === "Backspace" && mode && !input.value) {
        event.preventDefault();
        leaveList(false);
        return;
      }
      var visible = visibleOptions();
      if (event.key === "ArrowDown" && visible.length) {
        event.preventDefault();
        setActive(activeIndex + 1, true);
      } else if (event.key === "ArrowUp" && visible.length) {
        event.preventDefault();
        setActive(activeIndex - 1, true);
      } else if (event.key === "Enter" && visible.length && activeIndex >= 0) {
        event.preventDefault();
        visible[activeIndex].click();
      }
    });

    pageOptions.forEach(bindOption);
    if (!loaded) trigger.addEventListener("mouseenter", function () { ensureLoaded(); }, {once: true});

    doc.addEventListener("keydown", function (event) {
      var shortcut = (event.ctrlKey || event.metaKey) && !event.altKey &&
        normalise(event.key) === "k";
      if (!shortcut) return;
      event.preventDefault();
      if (isOpen) input.focus({ preventScroll: true });
      else openFinder(doc.activeElement || trigger);
    });

    var controller = {
      open: openFinder,
      close: closeFinder,
      filter: filterResults,
      visibleOptions: visibleOptions,
      setRecords: setRecords,
      setSettings: setSettings,
      setPeople: setPeople,
      setFound: setFound,
      // What record search should look for, without a prefix, and where.
      query: function () { return parsed().text; },
      scope: function () { return parsed().scope; },
      // The prefixes that narrow a search for this person.
      prefixes: function () {
        return Object.keys(PREFIXES).filter(function (prefix) {
          return (prefix !== "#" || recordsOn) && (prefix !== "@" || !!peopleSource);
        });
      },
    };
    dialog.lightworkFinder = controller;
    // An address with ?find=… opens the finder on that search.
    try {
      var shared = global.location && typeof global.URL === "function"
        ? new global.URL(global.location.href).searchParams.get("find") : null;
      if (shared) {
        openFinder(trigger);
        input.value = shared.slice(0, 200);
        input.dispatchEvent(new global.Event("input"));
      }
    } catch (_) { /* an unreadable address opens nothing */ }
    return controller;
  }

  global.LightworkNavFinder = { init: init };
  if (global.document) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", function () { init(global.document); });
    } else {
      init(global.document);
    }
  }
})(typeof window !== "undefined" ? window : this);
