# Microsoft Teams channel

Lightwork can take work from Microsoft Teams and decide approvals there. The
adapter is `packages/maverick-channels/maverick_channels/teams.py`; it speaks
the Azure Bot Framework's Bot Connector REST API (v3) directly, with no
Microsoft SDK. Live Teams has **not** been exercised in this repository: the
behaviour below is verified against Microsoft's published contract with
recorded transports and locally signed tokens (`tests/test_teams.py`). Please
run the checklist at the end on a real tenant.

Sources used for the contract:

- Authentication with the Bot Connector API (issuer, audience, OpenID metadata,
  signing keys, token endpoints for single- and multi-tenant apps):
  https://learn.microsoft.com/azure/bot-service/rest-api/bot-framework-rest-connector-authentication
- Bot Connector API reference (reply to activity, send to conversation, update
  activity, create conversation):
  https://learn.microsoft.com/azure/bot-service/rest-api/bot-framework-rest-connector-api-reference
- Channel and group chat conversations (mentions and stripping the bot mention):
  https://learn.microsoft.com/microsoftteams/platform/bots/how-to/conversations/channel-and-group-conversations
- Universal Actions for Adaptive Cards (`Action.Execute`, the `adaptiveCard/action`
  invoke and its response schema):
  https://learn.microsoft.com/adaptive-cards/authoring-cards/universal-action-model
- Proactive messages (creating a personal conversation from an Entra object id):
  https://learn.microsoft.com/microsoftteams/platform/bots/how-to/conversations/send-proactive-messages

## What it does

- **Messages become work.** A message in a personal chat, a group chat or a
  channel (where the bot must be @mentioned) is admitted through the same
  durable intake as Slack (`delivery.py`), becomes a goal owned by
  `user:teams:<Entra object id>`, and the result is posted back in the same
  conversation as a reply to the asking message. The EU AI Act Art. 50
  first-turn disclosure and the sender allowlist apply exactly as for every
  other channel because the adapter uses the shared server handler.
- **Approvals in Teams.** When an approval is queued (any producer:
  `safety.consent`, outside agents, harness refinement), every linked person
  marked *Can approve* receives an Adaptive Card with the same content as the
  dashboard's Approvals page: what it changes, who asked, decide-by time,
  spending, what it will do, before/after, what happens next (and *Can't be
  undone*), open questions. The buttons are **Approve**, **Reject** and **Ask a
  question (send back)**. A high or critical risk approval shows a second
  confirmation card before it is approved: the person ticks *I have read what
  this action will do* and, for critical risk, types **APPROVE** — the same
  acknowledgement rule as the Approvals page (`[approval]
  require_acknowledgement`), recorded as an `approval_confirmation` audit event
  with `channel = teams`. After a decision the updated card offers **Undo** for
  the grace window (`[approval] undo_grace_seconds`, default 30 seconds; the
  agent waits that long before acting); an undo returns the request to pending
  and the next decision is a new signed audit round. The decision goes through
  `maverick_dashboard.approval_decisions` — the same functions the dashboard
  routes call — so quorum (N-of-M), segregation of duties, the current-card
  binding check and the signed audit chain are identical. The card is updated
  in place with the outcome and who decided; the audit record carries
  `channel = teams`. Expired or already-decided cards answer with a plain
  message. Protected-settings changes (`settings_quorum`) are never decided
  from chat.
- **Security.** Every request is a JWT signed by the Bot Connector, verified
  fail-closed: issuer `https://api.botframework.com`, audience = your app id,
  RS256 with keys from `https://login.botframework.com/v1/.well-known/openidconfiguration`
  (cached, refreshed on an unknown key at most once a minute and at least
  daily), 5-minute clock skew, and the `serviceurl` claim must match the
  activity. The token proves Microsoft relayed the message, not who wrote it,
  so the sender's Entra object id must be on `allowed_users` and the tenant on
  `allowed_tenants` (default: your `tenant_id`). Message ids are claimed before
  processing so a redelivery cannot run a goal twice. Outbound calls use the
  kernel's SSRF-safe pinned HTTPS client and only ever go to the `serviceUrl`
  named in the verified token.

## 1. Register the bot in Azure (administrator steps)

1. In the Azure portal create an **Azure Bot** resource
   (https://learn.microsoft.com/azure/bot-service/bot-service-quickstart-registration).
   Choose **Single Tenant** for *Type of App* unless you have a reason for
   multi-tenant (Microsoft no longer creates new multi-tenant bots). Let it
   create a new Microsoft App ID. Note the **Microsoft App ID** and, on the
   app registration in Microsoft Entra (**Certificates & secrets**), create a
   **client secret** and copy its *value*. Note your **Directory (tenant) ID**.
2. On the bot's **Configuration** page set the **Messaging endpoint** to
   `https://<your public address>/webhook/teams`. The address must be public
   HTTPS; forward it to the port in `[channels.teams] port` (default 8771,
   bound to 127.0.0.1) with your reverse proxy.
3. Under **Channels** add **Microsoft Teams** and accept the terms.
4. No Microsoft Graph permissions are required: the bot only uses the Bot
   Connector scope `https://api.botframework.com/.default`, which the Azure Bot
   registration grants. The bot receives the sender's Entra object id in each
   activity; it never reads the directory.

## 2. Teams app manifest

Create a Teams app in the Developer Portal (or a manifest zip) with the bot:

```json
{
  "$schema": "https://developer.microsoft.com/json-schemas/teams/v1.16/MicrosoftTeams.schema.json",
  "manifestVersion": "1.16",
  "id": "<Microsoft App ID>",
  "version": "1.0.0",
  "name": { "short": "Lightwork" },
  "description": { "short": "Give Lightwork work and decide approvals", "full": "Lightwork governed AI workforce" },
  "developer": { "name": "Your company", "websiteUrl": "https://example.com",
                 "privacyUrl": "https://example.com/privacy", "termsOfUseUrl": "https://example.com/terms" },
  "icons": { "color": "color.png", "outline": "outline.png" },
  "accentColor": "#FFFFFF",
  "bots": [{
    "botId": "<Microsoft App ID>",
    "scopes": ["personal", "team", "groupChat"],
    "supportsFiles": false,
    "isNotificationOnly": false
  }],
  "permissions": ["identity", "messageTeamMembers"],
  "validDomains": []
}
```

Upload it (sideload or publish through your organisation's app catalogue) and
install the app for each person who should use it. Approval cards are posted
to a person's **personal** chat, so the app must be installed in personal scope
for them.

## 3. Configure Lightwork

Dashboard: **Channels → Microsoft Teams** — turn on, paste the App ID, client
secret and tenant ID, save, then press **Test connection** (it asks
`login.microsoftonline.com` for a Bot Framework token and explains a refusal
in plain words). **All settings → Chat channels → Microsoft Teams** holds
*Who may use Microsoft Teams* (Entra object ids), *Decide approvals in
Microsoft Teams* and *Microsoft 365 tenants that may use Lightwork*.

Config file equivalent:

```toml
[channels.teams]
enabled = true
app_id = "00000000-0000-0000-0000-000000000000"
app_password = "${TEAMS_APP_PASSWORD}"   # or set TEAMS_APP_PASSWORD via the secret provider
tenant_id = "11111111-1111-1111-1111-111111111111"
allowed_users = ["12345678-abcd-abcd-abcd-1234567890ab"]
allowed_tenants = []                      # empty = only tenant_id
approvals_enabled = true
port = 8771
```

The installer (`maverick-installer`) offers Teams in the channel list and asks
for the tenant id, port, approvals switch and the allowed people.

Where to find a person's Entra object id: Microsoft Entra admin centre →
Users → the person → **Object ID**.

## 4. Link people to Lightwork users

Teams only tells Lightwork a person's Entra object id. On **Channels →
Microsoft Teams → People linked to Teams** an administrator either:

- links an object id (or sign-in address) to a Lightwork user and ticks *Can
  approve requests from Teams*, or
- creates a **one-time code** for a Lightwork user; the person sends
  `link <code>` to the bot in Teams. The code works once and expires after
  15 minutes.

Links are stored in `~/.maverick/teams-identities.json` and every change is
audited. A person who has chatted with the bot once can receive approval
cards immediately; a person linked by object id who has never chatted is
reached by creating a personal conversation (needs `tenant_id`). Linking by
sign-in address alone is enough for messages and decisions, but Teams cannot
open a proactive chat from an address, so ask that person to message the bot
once.

## 5. Check on a real tenant

- Send "hello" in a personal chat: expect the AI disclosure on the first reply.
- @mention the bot in a channel: the mention is stripped before the goal text.
- Queue an approval (for example a dashboard-mode consent) and confirm the card
  arrives, that **Approve** on a high-risk item shows the confirmation card,
  and that the Approvals page shows the same decision with the Teams user's
  Lightwork identity.
- Press a button on an old card: expect "already decided or has expired".
