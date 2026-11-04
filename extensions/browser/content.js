// Lightwork page-context capture (content script).
//
// Inert by design: it collects NOTHING on its own, makes no network calls,
// and only answers an explicit getPageContext request sent by the popup
// when the user clicks "Send this page". The reply is the page title, URL,
// the current text selection (capped), and a BOUNDED, OBSERVE-ONLY
// accessibility/DOM snapshot (interactive controls + landmarks/headings).
//
// Observe-only: the snapshot is read with getAttribute/textContent/getBounding
// ClientRect only. It never clicks, types, focuses, submits, or mutates the
// page, and runs only on the user's "Send this page" click — never on its own.

// --- caps: keep the payload small no matter how huge the page is ----------
const MAX_ELEMENTS = 60; // interactive controls returned, in DOM order
const MAX_LANDMARKS = 25; // landmark/heading entries returned
const MAX_NAME = 120; // chars per accessible name / heading text
const MAX_SELECTOR = 120; // chars per selector hint
const MAX_VALUE = 80; // chars of an input's visible value/placeholder
const MAX_SCAN = 4000; // DOM nodes scanned before we stop (perf guard)

// Roles we surface as "interactive". Tag-derived; we do not execute anything.
const INTERACTIVE = new Set(["a", "button", "input", "select", "textarea", "summary"]);
const LANDMARK_TAGS = new Set(["main", "nav", "header", "footer", "aside", "section", "form"]);
const HEADING_TAGS = new Set(["h1", "h2", "h3"]);

function clip(s, n) {
  // Collapse whitespace so multi-line labels don't blow the cap, then trim.
  return String(s == null ? "" : s).replace(/\s+/g, " ").trim().slice(0, n);
}

// CSS.escape may be missing in exotic engines; degrade to a literal-ish guard.
function cssEscape(s) {
  try {
    if (typeof CSS !== "undefined" && CSS && typeof CSS.escape === "function") {
      return CSS.escape(s);
    }
  } catch (_e) { /* fall through */ }
  return String(s).replace(/[^A-Za-z0-9_-]/g, "\\$&");
}

// A stable-ish selector HINT (not a guarantee): prefer #id, else a short
// tag + [name]/[type] descriptor, else nth-of-type within the parent. This is
// advisory context for the agent; the extension never acts on it.
function selectorHint(el) {
  try {
    const tag = (el.tagName || "").toLowerCase();
    if (el.id) return clip("#" + cssEscape(el.id), MAX_SELECTOR);
    let sel = tag;
    const name = el.getAttribute && el.getAttribute("name");
    if (name) sel += '[name="' + cssEscape(name) + '"]';
    else {
      const type = el.getAttribute && el.getAttribute("type");
      if (type) sel += '[type="' + cssEscape(type) + '"]';
    }
    const parent = el.parentElement;
    if (parent) {
      const sameTag = [];
      for (const child of parent.children) {
        if (child.tagName === el.tagName) sameTag.push(child);
      }
      if (sameTag.length > 1) {
        const idx = sameTag.indexOf(el) + 1;
        sel += ":nth-of-type(" + idx + ")";
      }
    }
    return clip(sel, MAX_SELECTOR);
  } catch (_e) {
    return clip((el.tagName || "node").toLowerCase(), MAX_SELECTOR);
  }
}

// Accessible name, approximated from the cheap, observe-only sources in
// rough precedence order. We deliberately do NOT walk aria-labelledby trees
// or compute the full ARIA name; this is a hint, kept bounded and read-only.
function accessibleName(el) {
  const attr = (n) => (el.getAttribute && el.getAttribute(n)) || "";
  const tag = (el.tagName || "").toLowerCase();
  let name = attr("aria-label");
  if (!name && attr("aria-labelledby")) {
    // Resolve referenced ids' text, but cap how many/how much we read.
    const ids = attr("aria-labelledby").split(/\s+/).slice(0, 3);
    const parts = [];
    for (const id of ids) {
      try {
        const ref = id && document.getElementById(id);
        if (ref) parts.push(ref.textContent || "");
      } catch (_e) { /* ignore */ }
    }
    name = parts.join(" ");
  }
  if (!name && tag === "input") {
    // <label for=id> or a wrapping <label>.
    try {
      if (el.labels && el.labels.length) name = el.labels[0].textContent || "";
    } catch (_e) { /* labels may throw on detached nodes */ }
  }
  if (!name) name = attr("title") || attr("placeholder") || attr("alt");
  if (!name && (tag === "button" || tag === "a" || tag === "summary")) {
    name = el.textContent || "";
  }
  if (!name && tag === "input") {
    const type = (attr("type") || "").toLowerCase();
    if (type === "submit" || type === "button" || type === "reset") name = el.value || "";
  }
  return clip(name, MAX_NAME);
}

// Is the element plausibly visible? Cheap, read-only check; skips hidden and
// zero-box nodes so the snapshot reflects what the user can actually see.
function isVisible(el) {
  try {
    if (el.hidden) return false;
    if (el.getAttribute && el.getAttribute("aria-hidden") === "true") return false;
    const rect = el.getBoundingClientRect();
    if (!rect || (rect.width === 0 && rect.height === 0)) return false;
    const style = (el.ownerDocument.defaultView || window).getComputedStyle(el);
    if (style && (style.visibility === "hidden" || style.display === "none")) return false;
    return true;
  } catch (_e) {
    return true; // never let a visibility probe drop an element on error
  }
}

function describeInteractive(el, includeValues = false) {
  const tag = (el.tagName || "").toLowerCase();
  const item = {
    role: clip((el.getAttribute && el.getAttribute("role")) || tag, 32),
    tag: tag,
    name: accessibleName(el),
    selector: selectorHint(el),
  };
  if (tag === "input" || tag === "select" || tag === "textarea") {
    const type = el.getAttribute && el.getAttribute("type");
    if (type) item.type = clip(type, 24);
    if (el.disabled) item.disabled = true;
    // Visible value/placeholder ONLY — never secrets. Password fields are
    // reported by type but their value is never read.
    if (includeValues && (tag !== "input" || (type || "text").toLowerCase() !== "password")) {
      const v = (el.value || (el.getAttribute && el.getAttribute("placeholder")) || "");
      const vc = clip(v, MAX_VALUE);
      if (vc) item.value = vc;
    }
  }
  return item;
}

// Walk the document once, OBSERVE-ONLY, collecting bounded structure. We stop
// after MAX_SCAN nodes / the per-bucket caps so a giant page can't bloat the
// payload or hang the page.
function snapshot(includeValues = false) {
  const elements = [];
  const landmarks = [];
  let scanned = 0;
  let walker;
  try {
    walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_ELEMENT);
  } catch (_e) {
    return { elements: [], landmarks: [], truncated: false };
  }
  let node = walker.currentNode;
  let truncated = false;
  while (node) {
    if (++scanned > MAX_SCAN) { truncated = true; break; }
    const tag = (node.tagName || "").toLowerCase();
    if (HEADING_TAGS.has(tag) || LANDMARK_TAGS.has(tag) ||
        (node.getAttribute && ["main", "navigation", "banner", "contentinfo", "search", "region", "complementary"].indexOf(node.getAttribute("role")) !== -1)) {
      if (landmarks.length < MAX_LANDMARKS && isVisible(node)) {
        const role = (node.getAttribute && node.getAttribute("role")) || tag;
        const text = HEADING_TAGS.has(tag) ? (node.textContent || "") : (node.getAttribute && (node.getAttribute("aria-label") || "")) || "";
        landmarks.push({ role: clip(role, 32), tag: tag, name: clip(text, MAX_NAME) });
      }
    }
    const role = node.getAttribute && node.getAttribute("role");
    const isInteractive =
      INTERACTIVE.has(tag) ||
      (role && ["button", "link", "checkbox", "radio", "tab", "menuitem", "switch", "option"].indexOf(role) !== -1);
    if (isInteractive && elements.length < MAX_ELEMENTS && isVisible(node)) {
      // Skip empty <a> anchors that are just layout (no name, no href).
      const hasHref = tag === "a" && node.getAttribute && node.getAttribute("href");
      const desc = describeInteractive(node, includeValues);
      if (desc.name || hasHref || desc.value) elements.push(desc);
    }
    if (elements.length >= MAX_ELEMENTS && landmarks.length >= MAX_LANDMARKS) {
      truncated = true;
      break;
    }
    node = walker.nextNode();
  }
  return { elements: elements, landmarks: landmarks, truncated: truncated };
}

function getPageContext(options = {}) {
  const ctx = {
    title: clip(document.title, 300),
    url: String(location.href || "").slice(0, 2000),
    selection: String(window.getSelection() || "").slice(0, 4000),
  };
  try {
    const snap = options.structure ? snapshot(options.formValues === true) : {elements: [], landmarks: [], truncated: false};
    ctx.structured = {
      lang: clip((document.documentElement && document.documentElement.lang) || "", 16),
      counts: { elements: snap.elements.length, landmarks: snap.landmarks.length },
      truncated: snap.truncated,
      landmarks: snap.landmarks,
      elements: snap.elements,
    };
  } catch (_e) {
    // The structured snapshot is best-effort; never let it break the basic
    // title/url/selection context the popup has always relied on.
    ctx.structured = null;
  }
  return ctx;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  // Defense in depth: only answer messages from THIS extension (popup /
  // background), never a page. The manifest declares no externally_connectable,
  // so a web page can't reach chrome.runtime today -- but pin it so a future
  // manifest change can't silently let an attacker page harvest page context.
  if (_sender && _sender.id !== chrome.runtime.id) {
    return;
  }
  if (msg && msg.type === "getPageContext") {
    sendResponse(getPageContext(msg.options || {}));
  }
  // Synchronous response; the channel is not kept open.
});
