/* The one tab bar (templates/_tabs.html), in two kinds.
   Link tabs (data-mv-tabs): each tab is a link to its view (?tab=…), so the
   address is the state and the bar works without scripts. Left and Right
   (Up and Down too) move between tabs, Home and End go to the first and
   last, and Enter or Space opens the focused tab; moving focus opens
   nothing, because each view is a page load.
   Panel tabs (data-mv-tabs="panels"): each tab is a button that shows its
   panel in the page (aria-controls) or, when every tab controls the same
   list, filters it. A click selects the tab; the arrow, Home and End keys
   move to a tab and select it (data-mv-tabs-activation="manual" only moves
   focus, for a choice that loads data; Enter or Space then selects it). The
   page's own click listeners on a tab still run, so a page reacts to a
   selection the same way whether it came from the mouse or the keys. With
   data-mv-tabs-hash="sec-" the selected tab is written to the address
   (#sec-risks) without adding a Back step, and an address naming a tab
   opens it.
   Either way only the selected (or focused) tab is in the Tab order (a
   roving tabindex), so one Tab press leaves the bar. */
(function () {
  "use strict";
  if (window.mvTabs) { window.mvTabs.init(); return; }
  var KEYS = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };

  function tabsOf(list) {
    return Array.prototype.filter.call(list.querySelectorAll('[role="tab"]'), function (tab) {
      return tab.closest('[role="tablist"]') === list;
    });
  }
  function panels(list) { return list.getAttribute("data-mv-tabs") === "panels"; }
  function panelOf(tab) {
    var id = tab.getAttribute("aria-controls");
    return id ? document.getElementById(id) : null;
  }

  function focusTab(tabs, index) {
    tabs.forEach(function (tab, i) { tab.setAttribute("tabindex", i === index ? "0" : "-1"); });
    tabs[index].focus();
  }

  function remember(list, tab) {
    var prefix = list.getAttribute("data-mv-tabs-hash");
    if (prefix === null || !window.history || !window.history.replaceState) return;
    window.history.replaceState(window.history.state, "", "#" + prefix + tab.getAttribute("data-mv-tab"));
  }

  // Mark one tab selected and show its panel. Tabs that share one panel (a
  // filtered list) leave it shown and name the chosen tab as its label.
  function select(tab, opts) {
    var list = tab && tab.closest('[role="tablist"]');
    if (!list) return;
    var shown = panelOf(tab);
    tabsOf(list).forEach(function (other) {
      var chosen = other === tab;
      other.setAttribute("aria-selected", chosen ? "true" : "false");
      other.setAttribute("tabindex", chosen ? "0" : "-1");
      var panel = panelOf(other);
      if (panel && panel !== shown) panel.hidden = true;
    });
    if (shown) {
      shown.hidden = false;
      if (shown.getAttribute("role") === "tabpanel") shown.setAttribute("aria-labelledby", tab.id);
    }
    if (opts && opts.focus) tab.focus();
    if (opts && opts.remember) remember(list, tab);
  }

  function onKey(event) {
    var list = event.currentTarget;
    var tabs = tabsOf(list);
    var index = tabs.indexOf(event.target);
    if (index < 0 || event.altKey || event.ctrlKey || event.metaKey) return;
    var next = null;
    if (event.key in KEYS) next = (index + KEYS[event.key] + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else if (!panels(list) && (event.key === " " || event.key === "Spacebar")) {
      event.preventDefault();
      event.target.click();
      return;
    }
    if (next === null) return;
    event.preventDefault();
    focusTab(tabs, next);
    // Selecting goes through a click, so the page's own listeners run too.
    if (panels(list) && list.getAttribute("data-mv-tabs-activation") !== "manual") tabs[next].click();
  }

  function onClick(event) {
    var list = event.currentTarget;
    var tab = event.target.closest && event.target.closest('[role="tab"]');
    if (!tab || tab.closest('[role="tablist"]') !== list || tab.disabled) return;
    select(tab, { remember: true });
  }

  function fromAddress(list) {
    var prefix = list.getAttribute("data-mv-tabs-hash");
    if (prefix === null) return;
    var hash = window.location.hash || "";
    if (hash.indexOf("#" + prefix) !== 0) return;
    var key = hash.slice(prefix.length + 1);
    var tab = tabsOf(list).filter(function (t) { return t.getAttribute("data-mv-tab") === key; })[0];
    if (!tab) return;
    // An address naming another tab opens it as a click would, so a page
    // that loads data for the chosen tab (a board's time range) loads it.
    if (tab.getAttribute("aria-selected") !== "true") tab.click(); else select(tab);
    if (typeof list.scrollIntoView === "function") list.scrollIntoView({ block: "start" });
  }

  function init(root) {
    Array.prototype.forEach.call((root || document).querySelectorAll("[data-mv-tabs]"), function (list) {
      if (list.getAttribute("data-mv-tabs-ready") === "true") return;
      list.setAttribute("data-mv-tabs-ready", "true");
      list.addEventListener("keydown", onKey);
      if (!panels(list)) return;
      list.addEventListener("click", onClick);
      if (list.getAttribute("data-mv-tabs-hash") !== null) {
        fromAddress(list);
        window.addEventListener("hashchange", function () { fromAddress(list); });
      }
    });
  }

  window.mvTabs = { init: init, select: select };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { init(); });
  else init();
})();
