"use strict";
// The markup panel_tabs() and tab_panel() in templates/_tabs.html render,
// for page tests that run a page's script against its tab bar.
// tests/test_tab_bars.py checks that each page renders this same structure.
function panelTabs(label, items, selected, { id = "page-tabs", data = "", hash = null, manual = false,
  tabPrefix = null, panelPrefix = null, controls = "", cls = "" } = {}) {
  const tp = tabPrefix === null ? id + "-tab-" : tabPrefix, pp = panelPrefix === null ? id + "-panel-" : panelPrefix;
  const tabs = items.map(([key, text, value]) => `<button class="mv-tab" type="button" role="tab"` +
    (data ? ` data-${data}="${value === undefined ? key : value}"` : "") +
    ` aria-selected="${key === selected}" tabindex="${key === selected ? 0 : -1}" id="${tp}${key}" data-mv-tab="${key}"` +
    (controls === false ? "" : ` aria-controls="${controls || pp + key}"`) + `>${text}</button>`).join("");
  return `<div class="mv-tabs${cls ? " " + cls : ""}" role="tablist" aria-label="${label}" data-mv-tabs="panels"` +
    (hash === null ? "" : ` data-mv-tabs-hash="${hash}"`) + (manual ? ' data-mv-tabs-activation="manual"' : "") + `>${tabs}</div>`;
}
function tabPanel(key, selected, { id = "page-tabs", tabPrefix = null, panelPrefix = null } = {}) {
  const tp = tabPrefix === null ? id + "-tab-" : tabPrefix, pp = panelPrefix === null ? id + "-panel-" : panelPrefix;
  return `role="tabpanel" id="${pp}${key}" aria-labelledby="${tp}${key}"${key === selected ? "" : " hidden"}`;
}
// Fire a key on a tab the way a browser does: keydown bubbling from the tab.
function press(w, target, key) {
  const event = new w.KeyboardEvent("keydown", { key, bubbles: true, cancelable: true });
  target.dispatchEvent(event);
  return event;
}
module.exports = { panelTabs, tabPanel, press };
