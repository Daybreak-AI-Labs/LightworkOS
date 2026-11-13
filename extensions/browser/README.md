# Lightwork browser extension

A Manifest V3 WebExtension that puts a chat box to your **local** Lightwork
agent in the browser toolbar, plus a "Send this page" action that ships the
current page's title, URL, text selection, **and a bounded, observe-only
accessibility/DOM snapshot** to the agent as goal context.

Plain JavaScript, no build step, no remote code. It reuses the dashboard's
existing REST API — `POST /api/v1/goals` to start a goal (the same start
path the dashboard chat uses) and `GET /api/v1/goals/{id}/events` to stream
progress back into the popup.

## Install (load unpacked)

1. Start the dashboard locally: `maverick dashboard` (default
   `http://127.0.0.1:8765`).
2. Open **Settings → Access** in the local dashboard and search for
   **Allow the browser extension**. An administrator enables this setting and
   provides the required dashboard access token. If you cannot edit it, ask your
   workspace administrator. Settings shows deployment overrides; a locked
   effective value needs the installation administrator. Return to the popup
   after setup. No token means the extension cannot connect.
3. Chrome / Edge / Brave: open `chrome://extensions`, enable **Developer
   mode**, click **Load unpacked**, and pick this directory
   (`extensions/browser/`).
   Firefox: open `about:debugging#/runtime/this-firefox`, click **Load
   Temporary Add-on…**, and pick `manifest.json`.
4. Click the Lightwork toolbar icon and paste `MAVERICK_DASHBOARD_TOKEN` under
   **Settings** in the popup.

## Use

- **Chat**: type a goal, press **Send** (or Ctrl/Cmd-Enter). The popup polls
  the goal's event feed and renders progress + the final result.
- **Send this page** opens a preview first. Independently include or remove
  title/URL, selection, page structure and visible form values. Form values need
  administrator permission and a fresh choice on each page. Cancel sends no goal.
  Category preferences contain booleans only; private captured values stay in the
  open popup until the reviewed context is sent or discarded. The current policy
  is checked again before starting work. Existing task/tool governance still applies.

## Structured page context

Beyond title/URL/selection, "Send this page" includes a **bounded,
observe-only accessibility/DOM snapshot** of the active tab so the agent can
reason about the page's structure instead of guessing from the URL alone. It
is produced by `content.js` only in response to your click, and contains:

- **Interactive elements** — buttons, links, inputs, selects, textareas, and
  ARIA-role widgets (button/link/checkbox/radio/tab/menuitem/switch/option),
  each with its accessible **name/label**, its **role/tag**, a stable
  **selector hint** (`#id` / `tag[name=…]` / `:nth-of-type`), and — for form
  fields — the `type` and any **visible** value or placeholder.
- **Landmarks & headings** — `main`/`nav`/`header`/`footer`/`aside`/`section`/
  `form` and ARIA-landmark roles, plus `h1`–`h3`, giving the agent the page's
  outline.
- **Metadata** — document `lang`, element/landmark counts, and a `truncated`
  flag.

It is **bounded by design**: capped at 60 interactive elements, 25
landmarks/headings, ~4000 scanned nodes, and per-string length limits, so the
payload stays small on any page. **Password field values are never read**
(the field is reported by `type` only). The snapshot is read with
`getAttribute`/`textContent`/`getBoundingClientRect` only — it never clicks,
types, focuses, submits, or otherwise mutates the page.

## Security model

- **Local only.** `host_permissions` is `http://127.0.0.1/*` — the extension
  *cannot* talk to any other host, and the popup refuses non-loopback
  dashboard URLs. This describes extension transport only. The dashboard may send reviewed content to its configured AI provider and permitted tools under workspace policy; the popup shows the configured model before submission.
- **Opt-in CORS, fail-closed.** The dashboard answers extension origins
  (`chrome-extension://…`, `moz-extension://…`) only when the operator sets
  `[dashboard] allow_extension = true` (or
  `MAVERICK_DASHBOARD_ALLOW_EXTENSION=1`). Off by default: no CORS header is
  emitted and extension POSTs are rejected by the dashboard's cross-site
  gate. The allowance is scoped to extension origins — ordinary web origins
  (`https://…`) are never allowed. Extension CORS is only enabled when
  `MAVERICK_DASHBOARD_TOKEN` is also set, so no-token loopback mode stays
  same-origin only.
- **Token.** Every extension call must carry `Authorization: Bearer <token>`;
  the popup stores the token in `chrome.storage.local` (extension-private, on
  disk, this machine). Without a token the dashboard serves loopback callers
  only and does not grant extension CORS or CSRF bypasses.
- **Inert, observe-only content script.** `content.js` collects nothing on
  its own and makes no network calls; it only answers an explicit
  `getPageContext` message triggered by your click on "Send this page". The
  structured snapshot is strictly **observe-only** — it reads the DOM
  (`getAttribute`/`textContent`/`getBoundingClientRect`) but never clicks,
  types, focuses, submits, or mutates the page. The manifest auto-injects the
  inert script into HTTP(S) pages at `document_idle`. Its response is
  bounded (element/landmark/length caps) so nothing is exfiltrated or bloated.
  Password field values are never read.
- **No remote code.** All scripts are local files; the extension-page CSP is
  `script-src 'self'`. CI parses `manifest.json` and statically checks these
  invariants (`packages/maverick-dashboard/tests/test_extension_static.py`).

See the [client request and acknowledgement contract](../../docs/client-request-lifecycle.md) for replay, deadlines, access errors, and platform qualification limits.

Unconfirmed task starts retain their original title, description and request key
in extension-local storage. **Check start status** first reads the receipt; only a
`not_dispatched` draft is replayed, with the same inputs and key and a fresh page
sharing-policy check. Unknown outcomes remain held. Accepted starts remove the
saved payload. Older entries without the original payload require dashboard
review if the draft was never dispatched.
