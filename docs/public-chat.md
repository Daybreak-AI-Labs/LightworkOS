# Public website chat

A chat box for anonymous visitors on a customer's public website. One
published specialist answers the questions. It is off by default.

## Turn it on

Either answer yes to "Allow a chat box on your public website" in the setup
wizard (the default is no), or set this in the configuration file:

```toml
[public_chat]
enabled = true
```

Settings > All settings > Chat channels has the same switch. While it is off,
every public and admin chat route answers 404 and nothing is stored.

`allow_localhost_origins = true` lets a website at `http://localhost` use the
chat. It is for development only. Never turn it on for a public website.

## Add a website

Administrators with the admin permission manage websites on the Channels page,
under "Chat on your public website". The page adds a website, rotates its key,
stops it and shows its recent messages. It appears only while the chat is on.
The same actions are available through the API:

`POST /api/v1/public-chat/sites`

| Field | Rule |
|---|---|
| `display_name` | 1 to 80 characters, plain text |
| `origins` | 1 to 20 exact `https://` origins, for example `https://shop.example`. No path, query or user name. |
| `specialist` | A specialist published in this workspace |
| `greeting` | Up to 280 characters, shown when a visitor opens the chat |
| `daily_cap_dollars` | Required. Above 0, at most 1000. |
| `messages_per_session` | 1 to 30 (default 20) |
| `messages_per_minute` | 1 to 6 (default 6) |
| `messages_per_client_per_day` | 1 to 5000 (default 200). Messages per client address in any 24 hours, across all its sessions. |
| `retention_days` | 1 to 365 (default 30) |

The response includes `publishable_key` (`lwpk_...`). It is shown once. Only
its SHA-256 digest is stored, so copy it into the website at once.

- `POST /api/v1/public-chat/sites/{id}/rotate` issues a new key. The old key
  and every live visitor session stop at once.
- `POST /api/v1/public-chat/sites/{id}/revoke` stops the site. Its key,
  origins and sessions end at once, and its stored transcripts are deleted.
- `GET /api/v1/public-chat/sites/{id}/transcripts` shows the stored messages,
  read-only, oldest first. Each view is an audit event.

## Embed the chat

Add one tag to the host page. The key is a publishable value, not a secret,
but keep it to the sites you listed.

```html
<script src="https://YOUR-LIGHTWORK-HOST/public/chat/v1/widget.js"
        data-key="lwpk_..." async></script>
```

`widget.js` is static and contains no key. It draws a "Chat with us" button
and a panel in a closed shadow root. Every message is inserted as text, never
as markup. The tag may go in the head or the body; if the page body does not
exist yet, the panel appears once the page has loaded.

Scripts on the host page share the page's trust boundary. The closed shadow
root keeps them from reaching the panel through `host.shadowRoot`, but it is
not a security boundary: such a script can still read the chat.

## What a visitor can and cannot reach

A visitor can:

- open the chat, read the greeting and send up to the session and minute limits;
- receive one answer per message from the site's specialist.

A visitor cannot:

- use any tool, file, knowledge source, connector or agent loop;
- read workspace records, other visitors' sessions, transcripts or the dashboard;
- change the assistant's role. Visitor text is treated as untrusted, and the
  assistant answers only about the specialist's topic.

## Security model

- **Keys.** `lwpk_` plus 32 random bytes, URL-safe. Stored as SHA-256 digests
  only. A bad, unknown or revoked key gets the same generic `401`.
- **Origins.** A request must carry an `Origin` header that exactly matches
  one of the site's origins. A missing or other origin gets `403`. CORS is
  granted only to those exact origins. Any client can send any `Origin`
  value, so this stops browsers on other websites, not a client that sends a
  false origin on purpose. The key is public (it is in the page), so the daily
  cap is the spending limit that matters.
- **Visitor sessions.** `lwps_` tokens, valid for at most 30 minutes, stored
  as digests and bound to the origin they were issued for.
- **No cookies.** Neither the widget nor these routes set or read a cookie,
  so there is no ambient credential for a cross-site request to ride on.
- **Limits.** Message bodies are capped at 4 KiB. Starting sessions is rate
  limited per site and per client address. The client address is the
  forwarded visitor address only when the request comes from a proxy listed in
  `[auth.proxy] trusted_proxies`; otherwise it is the direct address. Messages
  are limited per session (at most 30) and per minute (at most 6 in any 60
  seconds). A new session starts with new message limits, so the per-client
  daily limit (`messages_per_client_per_day`) counts across a site's sessions:
  each message counts for 24 hours from when it was sent. Every message that
  passes the origin and size checks counts, including one that a session or
  minute limit then refuses. Visitors who share one address, such as people on
  the same company network, share that limit. The count is kept in memory for
  at most 10,000 addresses and restarts with the dashboard. When that table is
  full, the address whose latest counted message is oldest gives way, so a
  burst of new addresses never refuses a new visitor; that address starts a new
  count. The spending cap is kept on disk and bounds the cost.
- **Answers.** Each answer is one tool-free provider call
  (`LLM.complete` with `tools=None`, one physical attempt, no failover),
  through the budgeted path. Before each call, the answer's share (5 cents)
  of today's cap is held. The hold is then settled to what was billed,
  including a call that went above the hold. When the cap is used up, visitors
  get a "not available right now" answer. A call whose estimated cost is above
  the hold is refused before it is sent. A provider failure gets a `503` and
  keeps its hold.
- **Transcripts.** Sealed with the at-rest helper, bound to the tenant, site,
  conversation and row. Stored per tenant. Removed after the site's retention
  period. Revoking a site deletes its transcripts at once. Retention runs on
  the dashboard's background schedule, once when it starts and then at most
  once an hour, and also when a visit or an admin view happens. Each sweep
  covers every workspace. An installation that never used the chat creates no
  files for it.
- **Errors.** Refusal text is fixed and generic, but the status code is not the
  same for every refusal. A key that is unknown or revoked gets `401` whatever
  the origin. A live key used from an origin the site does not list gets `403`.
  So a caller who holds a key can tell whether it is still live, and, by trying
  origins, whether a given origin is listed for the site (`201` for a listed
  origin, `403` for an unlisted one). That reveals no secret: the key is public
  on the host page by design, and the server stores only its digest, so the key
  cannot be recovered from the server. An origin list is configuration, though,
  and it can name hosts that are not public, such as a staging site. Anyone who
  holds a live key can learn those names this way, so list only the origins
  that should use the chat.
- **Audit.** Creating, rotating and revoking a site, and viewing transcripts,
  are audit events without key material. A site is recorded once it exists; if
  the record cannot be written, the new site is revoked again and the request
  fails. Individual visitor requests are not audited.

## Known limits

- Each answer sees only the visitor's current message, not earlier turns.
- The visitor waits for the answer in the same request. There is no polling.
- Transcripts past retention are removed by the hourly background pass, so one
  can outlive its retention by up to an hour. A workspace whose sweep fails is
  logged and skipped for that pass; the other workspaces are still swept, and
  the failed one is tried again at the next pass, an hour later.
- The answer hold is a fixed 5 cents and is not configurable. A model whose
  estimated cost for one answer is above that is refused before the call.
- An answer may use at most 4,000 input tokens, system prompt included. A
  longer specialist prompt is billed and then refused on every visit, so keep
  the instructions short. The limit is not configurable.
- The widget's stylesheet is an inline `<style>` element inside its shadow
  root. A host page whose content security policy forbids inline styles may
  block it, so the panel would appear unstyled.
- The client address behind a proxy comes only from a pinned trusted proxy.
  Behavior behind a specific proxy deployment is not qualified.
- The widget's placement and text insertion are not qualified in a real
  browser.
