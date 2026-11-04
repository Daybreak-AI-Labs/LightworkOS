/* Keyboard shortcuts and the "Help and shortcuts" dialog (_shortcuts.html).
   The dialog's list is the single source: every [data-shortcut] entry it
   shows is bound here, and nothing else is, so the list and the keys cannot
   drift apart. Go-to entries are rendered only for pages the person may open.
   Single keys never fire while someone is typing in a field. */
(function (global) {
  "use strict";

  var SEQUENCE_MS = 1500;

  // A field, an editable region or a text-entry widget: keys belong to it.
  function typing(target) {
    if (!target || target.nodeType !== 1) return false;
    if (target.isContentEditable) return true;
    var tag = String(target.tagName || "").toUpperCase();
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
    var role = target.getAttribute && target.getAttribute("role");
    if (role === "textbox" || role === "searchbox" || role === "combobox") return true;
    return !!(target.closest && target.closest('[contenteditable]:not([contenteditable="false"])'));
  }

  function init(documentRef) {
    var doc = documentRef || global.document;
    var dialog = doc && doc.getElementById("shortcuts-dialog");
    if (!dialog || dialog.getAttribute("data-shortcuts-ready") === "true") return null;
    dialog.setAttribute("data-shortcuts-ready", "true");
    var opener = doc.getElementById("shortcuts-open");
    var closeButton = doc.getElementById("shortcuts-close");
    var finderButton = doc.getElementById("shortcuts-finder");
    var returnFocus = null, pending = null, pendingTimer = null;

    var entries = Array.prototype.map.call(dialog.querySelectorAll("[data-shortcut]"), function (node) {
      return {keys: node.getAttribute("data-shortcut").split(" "), href: node.getAttribute("data-shortcut-href"),
              run: node.getAttribute("data-shortcut-run")};
    });

    // Show the Mac modifier where it applies.
    if (/Mac|iPhone|iPad/.test((global.navigator && (global.navigator.platform || global.navigator.userAgent)) || "")) {
      Array.prototype.forEach.call(dialog.querySelectorAll("[data-shortcut-mod]"), function (key) { key.textContent = "⌘"; });
    }

    function finder() {
      var node = doc.getElementById("navfinder-dialog");
      return node && node.lightworkFinder;
    }

    function isOpen() { return !!dialog.open || dialog.getAttribute("open") !== null; }

    function open() {
      if (isOpen()) return;
      returnFocus = doc.activeElement;
      if (typeof dialog.showModal === "function") dialog.showModal(); else dialog.setAttribute("open", "");
      if (opener) opener.setAttribute("aria-expanded", "true");
      if (closeButton) closeButton.focus();
    }

    function close() {
      if (!isOpen()) return;
      if (typeof dialog.close === "function") dialog.close(); else { dialog.removeAttribute("open"); onClosed(); }
    }

    function onClosed() {
      if (opener) opener.setAttribute("aria-expanded", "false");
      var target = returnFocus;
      returnFocus = null;
      if (target && typeof target.focus === "function" && target.isConnected !== false) target.focus();
    }

    function go(href) {
      if (global.location && typeof global.location.assign === "function") global.location.assign(href);
    }

    function run(entry) {
      if (entry.href) { go(entry.href); return; }
      if (entry.run === "shortcuts") { if (isOpen()) close(); else open(); return; }
      if (entry.run === "finder") {
        var menu = finder();
        if (!menu) return;
        if (isOpen()) close();
        menu.open(doc.activeElement);
      }
    }

    // Another modal (a confirmation, the command menu) owns the keyboard.
    function otherModal() {
      var open;
      try { open = doc.querySelectorAll("dialog:modal"); } catch (error) { open = doc.querySelectorAll("dialog[open]"); }
      return Array.prototype.some.call(open, function (node) { return node !== dialog; });
    }

    function pressed(event) {
      var key = String(event.key || "");
      if (event.ctrlKey || event.metaKey) return event.altKey ? "" : "mod+" + key.toLowerCase();
      if (event.altKey) return "";
      return key.length === 1 && /[a-z]/i.test(key) ? key.toLowerCase() : key;
    }

    function clearPending() {
      pending = null;
      if (pendingTimer) { global.clearTimeout(pendingTimer); pendingTimer = null; }
    }

    doc.addEventListener("keydown", function (event) {
      if (event.defaultPrevented || event.isComposing || event.repeat) return;
      // Holding Shift for "?" (or a capital letter) is not a key of its own.
      if (/^(Shift|Control|Alt|Meta|CapsLock|AltGraph)$/.test(event.key)) return;
      var key = pressed(event);
      if (!key) return;
      var modified = key.indexOf("mod+") === 0;
      if (!modified && typing(event.target)) { clearPending(); return; }
      if (otherModal()) { clearPending(); return; }
      // Inside this dialog only its own key (?) and Escape apply.
      if (isOpen() && key !== "?") return;
      var match = null;
      if (pending) {
        var first = pending;
        clearPending();
        match = entries.filter(function (entry) { return entry.keys.length === 2 && entry.keys[0] === first && entry.keys[1] === key; })[0];
      } else {
        match = entries.filter(function (entry) { return entry.keys.length === 1 && entry.keys[0] === key; })[0];
        if (!match && entries.some(function (entry) { return entry.keys.length === 2 && entry.keys[0] === key; })) {
          pending = key;
          pendingTimer = global.setTimeout(clearPending, SEQUENCE_MS);
          return;
        }
      }
      if (!match) return;
      event.preventDefault();
      run(match);
    });

    if (opener) opener.addEventListener("click", open);
    if (closeButton) closeButton.addEventListener("click", close);
    if (finderButton) finderButton.addEventListener("click", function () {
      // The command menu takes over, and later returns focus to where this
      // dialog was opened from.
      var menu = finder(), origin = returnFocus;
      returnFocus = null;
      close();
      if (menu) menu.open(origin || opener);
    });
    dialog.addEventListener("close", onClosed);

    var controller = {
      open: open,
      close: close,
      // What the dialog lists, and so exactly what is bound.
      shortcuts: function () { return entries.map(function (entry) { return entry.keys.join(" "); }); },
    };
    global.LightworkShortcuts = controller;
    return controller;
  }

  global.LightworkShortcutsInit = init;
  if (global.document) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener("DOMContentLoaded", function () { init(global.document); });
    } else {
      init(global.document);
    }
  }
})(typeof window !== "undefined" ? window : this);
