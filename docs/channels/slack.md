# Slack

Lightwork's Slack app answers direct messages, answers when it is mentioned in
a channel or group, posts approval requests as cards with **Approve**,
**Reject** and **Ask a question** buttons, takes `/lightwork` slash commands,
and sends each person their daily summary as a direct message.

Two ways to connect:

* **Socket Mode** (default, no public web address needed) — `maverick serve`
  keeps a WebSocket open to Slack; buttons and slash commands arrive on it.
* **Over the web** — Slack posts buttons and slash commands to the dashboard
  at `https://<dashboard>/webhook/slack/interactions` and
  `https://<dashboard>/webhook/slack/commands`, signed with your app's signing
  secret. Use this when the dashboard is reachable from the internet and you
  are not running the Socket Mode bot.

## Create the app

1. Create an app at <https://api.slack.com/apps> (from scratch).
2. **OAuth & Permissions → Bot Token Scopes**: add

   | Scope | Why |
   |---|---|
   | `chat:write` | post replies, cards and summaries |
   | `commands` | the `/lightwork` slash command |
   | `im:history` | read direct messages |
   | `channels:history` | read messages in public channels it is in |
   | `groups:history` | read messages in private channels it is in |
   | `app_mentions:read` | be told when it is mentioned |
   | `users:read` | show who decided |
   | `im:write` | open the direct message for the daily summary |
   | `files:read` | (optional) files people share become goal attachments |

3. **Event Subscriptions → Subscribe to bot events**: `message.im`,
   `message.channels`, `message.groups`, `app_mention`.
4. **Slash Commands**: create `/lightwork`. Socket Mode needs no URL; over the
   web the Request URL is `https://<dashboard>/webhook/slack/commands`.
5. **Interactivity & Shortcuts**: turn on. Socket Mode needs no URL; over the
   web the Request URL is `https://<dashboard>/webhook/slack/interactions`.
6. **Socket Mode**: turn on and create an app-level token with
   `connections:write` (this is `SLACK_APP_TOKEN`).
7. Install the app to the workspace; the bot token (`xoxb-…`) is
   `SLACK_BOT_TOKEN`. The signing secret is on **Basic Information**.

## Configure Lightwork

Dashboard: **Channels → Slack** (tokens, signing secret, approvals channel) and
**Settings → All settings → Chat channels → Slack**. Or in
`~/.maverick/config.toml`:

```toml
[channels.slack]
enabled = true
app_token = "${SLACK_APP_TOKEN}"
bot_token = "${SLACK_BOT_TOKEN}"
allowed_user_ids = ["U01ABCDEF"]      # who may give Lightwork work
thread_replies = false                # DMs: answer in a thread
approvals_channel = "C0123456"        # where new approval cards are posted
signing_secret = "${SLACK_SIGNING_SECRET}"   # only for the web receivers
```

Environment variables `SLACK_APP_TOKEN`, `SLACK_BOT_TOKEN`,
`SLACK_SIGNING_SECRET`, `SLACK_APPROVALS_CHANNEL` and `SLACK_ALLOWED_USER_IDS`
win over saved values.

## Linking people

A decision from Slack must be attributable to a Lightwork person. Either an
administrator maps the Slack member id on **Users → Chat accounts**, or the
person opens **My work → Your chat accounts → Get a link code** and sends
`/lightwork link <code>` in Slack (the code works once, for 15 minutes). Every
link and unlink is written to the audit log.

## What people can do

* **DM the bot** — the message becomes a task, exactly as before.
* **Mention it** in a channel or group (`@Lightwork summarise this thread`) —
  it answers in the thread.
* **Approval cards** — new requests appear in the approvals channel with what
  it will do, the risk, the spending, whether it can be undone and the
  decide-by time. Approve/Reject record the same signed audit entry as the
  Approvals page, tagged `channel = slack`. A High request shows a
  confirmation dialog first; a Critical one also opens a window where the
  person types `APPROVE` (the same acknowledgement rule as the Approvals
  page, written to the audit log as `approval_confirmation`). The card is
  rewritten in place with the outcome and who decided, and offers **Undo**
  while the undo window (`[approval] undo_grace_seconds`, default 30 s) is
  open; an undo returns the request to pending and the next decision is a
  new audit round. An expired or already decided request is refused.
* **Slash commands**: `/lightwork status`, `/lightwork approve <n> [confirm]`,
  `/lightwork reject <n> [confirm]`, `/lightwork undo <n>`,
  `/lightwork ask <what you need>`, `/lightwork link <code>`,
  `/lightwork help`. High needs `confirm`; Critical needs `confirm APPROVE`.
  `/lightwork ask` runs through the Socket Mode bot; over the web it points
  the person at the bot.
* **Daily summary** — at the hour the person chose on My work (default 08:00
  in their time zone) they get a DM with the same content as the page:
  approvals, questions, recent results, access keys that stop working within
  7 days (when the API-keys feature is installed) and spending this month.
  Turned on with `[my_work] digest_enable = true` (Settings → Integrations →
  Daily summary).

## How requests are checked (web receivers)

Following Slack's request-signing guide: the signature header
`X-Slack-Signature` must equal `v0=` + HMAC-SHA256(signing secret,
`v0:<X-Slack-Request-Timestamp>:<raw body>`), the timestamp must be within
five minutes, and a signature seen before is refused (replay). Requests larger
than the webhook body limit are refused before they are read.
