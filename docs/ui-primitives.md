# Dashboard UI primitives

Shared, page-agnostic helpers are defined in
`packages/maverick-dashboard/maverick_dashboard/static/lightwork-ui.js`, with
styles in `static/lightwork.css`. `templates/base.html` loads them and supplies
the toast/confirmation regions, making them available to pages that
`{% extends "base.html" %}`. **Prefer these over
native `confirm()` / `alert()` or hand-rolled toasts** — they are accessible
(assertive vs. polite live regions; a focus-trapping, focus-returning modal),
themed (no hard-coded colors), and consistent across the dashboard.

## `window.mvToast(message, { error, quiet })`

Transient notification.

- `error: true` → an assertive (`role="alert"`) live region, prefixed `⚠ `.
- otherwise → a polite (`role="status"`) live region.
- `quiet: true` → shown but not read out (`aria-hidden`), for when the page
  already announces the same words, in its own status line or by moving focus.
- Auto-dismisses (errors linger longer). The two live regions are baked into the
  DOM at load, so announcements are reliable (a `role` injected into an existing
  polite region is not).

```js
mvToast('Schedule deleted');
mvToast('Could not delete schedule', { error: true });
```

## `window.mvConfirm(message, { okText }) -> Promise<boolean>`

Accessible confirmation on the native `<dialog>`: focus trap, `Esc` cancels,
focus returns to the opener on close. Falls back to `window.confirm` where
`<dialog>.showModal` is unavailable. **Not re-entrant** — a call while already
open resolves `false`.

```js
if (!(await mvConfirm('Delete this schedule? It will stop running.', { okText: 'Delete' }))) return;
```

Callers must be `async`. If the confirmed action removes the element that held
focus (e.g. a deleted list row), move focus to a stable landmark afterward — a
`tabindex="-1"` section heading — since the opener no longer exists.

## `window.mvForm(title, fields, { okText }) -> Promise<object|null>`

Collects a small set of typed fields in the native `<dialog>` (focus trap, `Esc`
cancels, focus returns to the opener) — the replacement for a chain of
`window.prompt` calls. Resolves to a `{ key: value }` object, or `null` if
cancelled. Required fields with no value block submit with an inline error.
Falls back to sequential `prompt`s where `<dialog>.showModal` is unavailable.
**Not re-entrant** (shared dialog). Each field is
`{ key, label, type, required, default, options, placeholder, help }` where
`type` is `text` | `number` | `date` | `bool` | `select` (`options` for `select`).

```js
const vals = await mvForm('Run this flow', [
  { key: 'amount', label: 'Amount', type: 'number', required: true },
  { key: 'urgent', label: 'Urgent?', type: 'bool', default: false },
], { okText: 'Run' });
if (vals === null) return;                 // cancelled
```

## `window.mvCopy(text)`

Copies `text` to the clipboard (Clipboard API, with a hidden-textarea fallback)
and toasts the outcome.

```js
copyBtn.addEventListener('click', function () { mvCopy(urlEl.textContent); });
```

## `--scrim`

The single overlay-backdrop token (`:root` in `static/lightwork.css`). Use it for any modal /
drawer / picker backdrop instead of a bespoke `rgba(...)`:

```css
.my-overlay::backdrop { background: var(--scrim); }
```

## `window.mvEl(tag, cls, text)` / `window.mvWhen(ts)`

`mvEl` is a one-line element builder (`createElement` + optional class + optional
`textContent`); `mvWhen(epoch_seconds)` formats a timestamp with the browser
locale. Both were reimplemented per page before; use the shared ones.

```js
var row = mvEl('li', 'mv-row');
row.appendChild(mvEl('div', 'mv-row__title', name));
row.appendChild(mvEl('div', 'mv-row__sub', 'last run ' + mvWhen(ts)));
```

## Empty states: `empty_state(...)` / `window.mvEmpty(title, body, action, opts)`

One component for every empty list, panel and page (`.mv-empty`). The wording
says what will appear and how to add the first one — "[What will appear
here]. [How to add the first one]." — plus at most one next step. Leave the
button out when the viewer can't use the destination page. The button is a
plain `.btn`, never a second primary: the page's main action is in the header.

```html
{% from "_empty_state.html" import empty_state %}
{{ empty_state('No results yet',
               'Finished tasks with a saved answer appear here. Start a task to get the first one.',
               action_label='Start a task', action_href='/chat') }}
```

`id`/`hidden` serve empties a script toggles; `compact=true` is the smaller,
left-aligned version for panels, tiles and charts. Script-rendered lists use
the same markup:

```js
list.replaceChildren(mvEmpty('No schedules yet',
  'Schedules you create appear here. Create one below to run a workflow on a timetable.',
  { label: 'Create a schedule', onClick: focusForm }));          // or { label, href }
```

## Page header: `hero(..., actions=..., compact=...)`

`templates/_hero.html` is the one page header. Its `actions` slot holds the
page's main action (the view's only `btn--primary`) and any secondary buttons
beside it; build it with `{% set hero_actions %}…{% endset %}` so the markup is
template-owned while every value inside stays escaped. `compact=true` is the
shorter header for working pages, with the actions beside the title. The
macro comment documents the arguments.

## Tabs and filter toggles: `.mv-tabs` / `.mv-tab`

One look for tab strips and list filters. The selected item shows a selected
state — `aria-selected="true"` (tabs, `role="tab"` in a `role="tablist"`),
`aria-pressed="true"` (filter toggles in a `role="group"`) or
`aria-current="page"` (links) — never `btn--primary`, which is kept for the
view's main action.

```html
<div class="mv-tabs" role="tablist" aria-label="Record types">
  <button class="mv-tab" role="tab" aria-selected="true" aria-controls="tab-a" id="tabbtn-a" type="button">Agreements</button>
  <button class="mv-tab" role="tab" aria-selected="false" aria-controls="tab-b" id="tabbtn-b" tabindex="-1" type="button">AI systems</button>
</div>
```

Tabs move with the arrow keys (see the Security and Privacy pages); script
only toggles the ARIA state, the stylesheet does the rest.

## `.card` / `.card-grid`

The shared card surface (border + token padding + hover) and a responsive
`auto-fill` grid of them. Used by the Templates catalog. Cards and `.mv-row`s
get a subtle `mv-rise` entrance, disabled under `prefers-reduced-motion`.

```html
<div class="card-grid">
  <div class="card">…</div>
</div>
```

## `.mv-row` / `.btn--icon`

The shared list-row component — an icon/title + a muted subline + trailing
actions — used by the Automations page, the builder's schedule/trigger lists,
and the Workflows index. `.btn--icon` is the compact square button for a row's
`✕` / icon action.

```html
<li class="mv-row">
  <div class="mv-row__main">
    <div class="mv-row__title">Title</div>
    <div class="mv-row__sub">subtitle</div>
  </div>
  <div class="mv-row__actions"><button class="btn btn--icon" aria-label="Delete">✕</button></div>
</li>
```

## Adoption

In use by: the Automations page, the workflow builder (schedules, triggers,
connector picker), the killswitch pill, fleets, learned-tools, the goal
cancel action, the assessments register (delete + add-evidence), connections
(delete), and the agent-factory tool picker. New destructive actions and
notifications should use these rather than native dialogs.
