/* Pinned and recent pages in the sidebar (navigation_api). Pins change only
   through POST /api/v1/navigation/pins, which accepts a page only when the
   person may open it: the page's "Pin to sidebar" button, the sidebar's Edit
   buttons and the command menu's "Pin this page" all use it. Opening a page
   the person may open is remembered for their Recent pages. */
(function (global) {
  "use strict";

  var PATHS = {up: "M8 12.5v-9M4.5 7 8 3.5 11.5 7", down: "M8 3.5v9M4.5 9 8 12.5 11.5 9", remove: "m4.5 4.5 7 7m0-7-7 7"};
  var TOOLS = [["up", "Move {page} up"], ["down", "Move {page} down"], ["remove", "Unpin {page}"]];
  var SVG = "http://www.w3.org/2000/svg";

  function init(documentRef) {
    var doc = documentRef || global.document;
    var root = doc && doc.getElementById("navpins");
    if (!root || root.getAttribute("data-pins-ready") === "true") return null;
    root.setAttribute("data-pins-ready", "true");
    var list = doc.getElementById("navpins-list");
    var edit = doc.getElementById("navpins-edit");
    var empty = doc.getElementById("navpins-empty");
    var status = doc.getElementById("navpins-status");
    var toggle = doc.getElementById("page-pin-toggle");
    var current = root.getAttribute("data-nav-current") || "";
    var currentLabel = root.getAttribute("data-nav-current-label") || current;
    var editing = false, busy = false;
    if (!list) return null;

    function text(source, values) {
      if (global.LightworkI18n) return global.LightworkI18n.text(source, values);
      return String(source).replace(/\{(\w+)\}/g, function (whole, name) {
        return values && Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : whole;
      });
    }

    function copy(node, source, values) {
      if (global.LightworkI18n) global.LightworkI18n.set(node, source, values);
      else node.textContent = text(source, values);
    }

    function say(source, values, toast) {
      if (status) copy(status, source, values);
      if (toast && typeof global.mvToast === "function") global.mvToast(text(source, values));
    }

    function meta(name) {
      var node = doc.querySelector('meta[name="' + name + '"]');
      return node ? node.getAttribute("content") || "" : "";
    }

    function items() { return Array.prototype.slice.call(list.querySelectorAll("li[data-pin]")); }
    function hrefs() { return items().map(function (item) { return item.getAttribute("data-pin"); }); }
    function isPinned(href) { return hrefs().indexOf(href) !== -1; }
    function find(href) { return items().filter(function (item) { return item.getAttribute("data-pin") === href; })[0] || null; }
    function nameOf(href) {
      var item = find(href), label = item && item.querySelector(".nav-label");
      return label ? label.textContent.trim() : href === current ? currentLabel : href;
    }

    function icon(path, className) {
      var svg = doc.createElementNS(SVG, "svg");
      svg.setAttribute("width", "14"); svg.setAttribute("height", "14"); svg.setAttribute("viewBox", "0 0 16 16");
      svg.setAttribute("fill", "none"); svg.setAttribute("stroke", "currentColor"); svg.setAttribute("stroke-width", "1.6");
      svg.setAttribute("stroke-linecap", "round"); svg.setAttribute("stroke-linejoin", "round"); svg.setAttribute("aria-hidden", "true");
      if (className) svg.setAttribute("class", className);
      var shape = doc.createElementNS(SVG, "path"); shape.setAttribute("d", path); svg.appendChild(shape);
      return svg;
    }

    // The same markup the sidebar renders for a pin (_sidebar_nav.html).
    function build(pin) {
      var item = doc.createElement("li"); item.setAttribute("data-pin", pin.href);
      var link = doc.createElement("a"); link.href = pin.href;
      if (pin.href === current) link.className = "active";
      var symbol = doc.createElementNS(SVG, "svg"); symbol.setAttribute("class", "nav-ic"); symbol.setAttribute("aria-hidden", "true");
      var use = doc.createElementNS(SVG, "use"); use.setAttribute("href", "#i-" + (pin.icon || "dot")); symbol.appendChild(use);
      var label = doc.createElement("span"); label.className = "nav-label"; copy(label, pin.label);
      link.append(symbol, label);
      var tools = doc.createElement("span"); tools.className = "navpins__tools"; tools.hidden = !editing;
      var page = text(pin.label);
      TOOLS.forEach(function (tool) {
        var button = doc.createElement("button"); button.type = "button"; button.className = "navpins__tool";
        button.setAttribute("data-pin-op", tool[0]); button.setAttribute("aria-label", text(tool[1], {page: page}));
        button.appendChild(icon(PATHS[tool[0]])); tools.appendChild(button);
      });
      item.append(link, tools);
      return item;
    }

    function render(pins) {
      var existing = {};
      items().forEach(function (item) { existing[item.getAttribute("data-pin")] = item; });
      pins.forEach(function (pin) {
        var item = existing[pin.href] || build(pin);
        delete existing[pin.href];
        list.appendChild(item);
      });
      Object.keys(existing).forEach(function (href) { existing[href].remove(); });
      if (empty) empty.hidden = pins.length > 0;
      if (edit) {
        edit.hidden = !pins.length;
        if (!pins.length && editing) setEditing(false);
      }
      if (toggle) toggle.setAttribute("aria-pressed", isPinned(current) ? "true" : "false");
    }

    function setBusy(on) {
      busy = on;
      list.querySelectorAll("[data-pin-op]").forEach(function (button) { button.disabled = on; });
      if (toggle) toggle.disabled = on;
    }

    // Nothing changed: the list and the button stay as they were.
    function refused(failure, toast) {
      if (status) status.textContent = failure;
      if (toast && typeof global.mvToast === "function") global.mvToast(failure, {error: true});
      return null;
    }

    // One change at a time; the server answers with the whole new list.
    async function change(op, href, toast) {
      if (busy || !href) return null;
      var page = nameOf(href);
      setBusy(true);
      try {
        var response = await global.fetch("/api/v1/navigation/pins", {
          method: "POST", credentials: "same-origin", cache: "no-store",
          headers: {"Content-Type": "application/json", "Accept": "application/json"},
          body: JSON.stringify({op: op, href: href, context: meta("lightwork-preference-context")}),
        });
        if (!response.ok) return refused(global.mvErrorText ? global.mvErrorText(response, "change your pinned pages")
          : text("Your pinned pages could not be changed. Try again."), toast);
        var data = await response.json();
        render(Array.isArray(data.pins) ? data.pins : []);
        var revision = doc.querySelector('meta[name="lightwork-preference-revision"]');
        if (revision && typeof data.revision === "string") revision.setAttribute("content", data.revision);
        say({add: "Pinned {page} to the sidebar.", remove: "Unpinned {page}.", up: "Moved {page} up.",
             down: "Moved {page} down."}[op], {page: page}, toast);
        return data;
      } catch (error) {
        // Blocked or offline: an error like a refusal, never a quiet note.
        return refused(text("Your pinned pages could not be changed. Check your connection and try again."), toast);
      } finally {
        setBusy(false);
      }
    }

    function setEditing(on) {
      editing = on;
      items().forEach(function (item) {
        var tools = item.querySelector(".navpins__tools");
        if (tools) tools.hidden = !on;
      });
      if (!edit) return;
      edit.setAttribute("aria-expanded", on ? "true" : "false");
      copy(edit, on ? "Done" : "Edit");
      edit.setAttribute("aria-label", text(on ? "Done editing pinned pages" : "Edit pinned pages"));
    }

    function focusAfter(op, href, index) {
      var moved = find(href);
      if (moved && op !== "remove") {
        var same = moved.querySelector('[data-pin-op="' + op + '"]');
        if (same) same.focus();
        return;
      }
      var rest = items(), next = rest[Math.min(index, rest.length - 1)];
      var target = next && next.querySelector('[data-pin-op="remove"]');
      if (target) target.focus();
      else if (empty) { empty.setAttribute("tabindex", "-1"); empty.focus(); }
    }

    if (edit) edit.addEventListener("click", function () { setEditing(!editing); });
    list.addEventListener("click", function (event) {
      var button = event.target.closest && event.target.closest("[data-pin-op]");
      if (!button || !list.contains(button)) return;
      var item = button.closest("li[data-pin]"), href = item.getAttribute("data-pin");
      var op = button.getAttribute("data-pin-op"), index = items().indexOf(item);
      change(op, href, false).then(function (data) { if (data) focusAfter(op, href, index); });
    });

    function togglePin() {
      if (!current) return Promise.resolve(null);
      return change(isPinned(current) ? "remove" : "add", current, true);
    }
    if (toggle) toggle.addEventListener("click", togglePin);

    // Remember this page for Recent pages. Nothing the person sees waits for
    // it, and a page that cannot be remembered says so quietly (recorded: false).
    // The answer is read even though nothing uses it: a response left unread
    // never finishes, so the page would never settle and leaving it would
    // cancel the request.
    if (root.getAttribute("data-nav-record") !== null && current && typeof global.fetch === "function") {
      global.fetch("/api/v1/navigation/recent", {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: {"Content-Type": "application/json", "Accept": "application/json"},
        body: JSON.stringify({path: current, context: meta("lightwork-preference-context")}),
      }).then(function (response) { return response.text(); }).catch(function () {});
    }

    var controller = {
      toggle: togglePin,
      isPinned: function () { return !!current && isPinned(current); },
      current: current,
      change: change,
    };
    global.LightworkPins = controller;
    return controller;
  }

  global.LightworkPinsInit = init;
  if (global.document) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", function () { init(global.document); });
    } else {
      init(global.document);
    }
  }
})(typeof window !== "undefined" ? window : this);
