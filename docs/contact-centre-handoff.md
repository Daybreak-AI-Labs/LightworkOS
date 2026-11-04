# Handing a conversation to a contact centre

When a person takes over a conversation in Lightwork (human help), the handoff
stays in Lightwork. You can also send it to a contact centre outside Lightwork:
a Zendesk support ticket, or a signed message to your own system.

It is **off by default**. With the provider off, nothing is sent and no outbox
is kept.

## Turn it on

Settings > Integrations > **Contact centre**, or the `[contact_centre]` table in
`config.toml`:

| Setting | What it is |
|---|---|
| Provider | `off` (default), `zendesk` or `webhook`. An unknown value is treated as `off`. |
| Zendesk subdomain | The part before `.zendesk.com`, such as `acme-support`. Letters, digits and hyphens only, up to 63 characters. |
| Zendesk agent email | The agent whose access token is used. Tickets are created as that agent. |
| Zendesk access token | Stored sealed and never shown again. Environment variable `MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN` overrides it. |
| Webhook address | A secure `https://` address. Plain `http://` and addresses with a username or password are refused. |
| Webhook signing secret | Stored sealed and never shown again. Environment variable `MAVERICK_CONTACT_CENTRE_WEBHOOK_SECRET` overrides it. Without it, nothing is sent to the webhook. |
| Lightwork web address | Used for the link back to the conversation. Leave it empty to send without a link. |
| Recent messages to include | 1 to 50, default 20. |

Secrets are never written to `config.toml`. The setup wizard asks only for the
provider and the non-secret addresses, and tells you where to enter the secret.

A handoff made while a secret or the Zendesk agent email is missing is kept as
**Waiting for Settings** with the reason. Lightwork checks it again before each send,
when it next starts, and when the contact-centre settings are saved in the dashboard,
so it is sent once Settings are complete, without a restart. A handoff made
while the Zendesk subdomain or the webhook address is missing is **Not sent** at once,
because the customer was shown that address. Lightwork never sends it to an address
that was set afterwards: if the provider or address is changed before a waiting
handoff is sent, it is recorded as **Not sent** and nothing leaves Lightwork.

## What is sent

- The conversation title, as the subject (or the webhook's `payload.subject`).
- Why the person was asked for, as the reason.
- The requester's name and email. When the account name is itself an email address,
  the name is left empty and the email is sent once.
- The most recent messages, oldest first, each shortened to 2,000 characters.
- A link back to the conversation, when a Lightwork web address is set.

The task brief and saved reply are **not** sent. Attachments are not sent.

Before the customer confirms a handoff, the review names the destination and lists
these fields. The destination shown is fixed when the review is made: if the
provider or address is changed before the request is confirmed, the request is
refused and must be reviewed again. A handoff that is already queued is also
checked against the reviewed provider and address before each send.

Free text (the reason, the title and each message) passes through the proven
redactor (`provable_redaction.redact_proven`) first. Personal data and secrets it
detects are removed, and text it cannot verify is replaced with a notice. The
requester's own name and email are not redacted, because the ticket needs them.

Please review this against your own data-protection obligations before you turn
it on.

## Zendesk

Each handoff creates one ticket:

- Request: `POST https://<subdomain>.zendesk.com/api/v2/tickets.json`
- Authentication: HTTP Basic with the username `<agent email>/token` and the API
  token as the password, sent as `Authorization: Basic <base64 of "email/token:token">`.
  This credential form is taken from Zendesk's authentication reference.
- Body: `{"ticket": {"subject", "comment": {"body"}, "tags": ["lightwork"],
  "external_id": "handoff:<id>", "requester": {"name", "email"}}}`. The
  requester is omitted when no email is known.

Not verified against Zendesk's documentation: the exact endpoint form
(`tickets.json` versus `tickets`), the success status code, and the rate-limit
wording for this endpoint. Test with one handoff to a sandbox Zendesk before
you rely on it.

## Signed webhook

Each handoff posts one JSON message with the event `contact_centre.handoff`.
Signing is the same as Lightwork's other outbound webhooks (see
[webhooks.md](webhooks.md)):

- `X-Lightwork-Signature: sha256=<HMAC-SHA256 of "<timestamp>.<body>">`
- `X-Lightwork-Timestamp`: the Unix time the signature was made. Check that it
  is recent before you trust the message.
- `X-Lightwork-Delivery`: the same value on every retry of one handoff, so your
  system can ignore a repeat.

Verify with the same rule as `maverick.webhooks.verify_signature`.

## Delivery states

| Shown as | Meaning |
|---|---|
| Waiting to send | Queued; the first attempt starts in the background. |
| Waiting for Settings | A secret or the Zendesk agent email is missing. It is sent once Settings are complete. |
| Sending | An attempt is in progress. |
| Retrying | The last attempt did not reach the receiver. The next attempt is scheduled. |
| Sent | Accepted. For Zendesk, the ticket number is shown when the reply includes it. |
| Not sent | Lightwork will not try again. The reason says what to fix. |
| Not confirmed | A request may have reached the receiver but no clear answer came back. **It is not sent again.** Check the destination before you send it by hand. |
| Not queued | The provider is set but no delivery was recorded for this handoff, for example because queueing failed. The in-app handoff is not affected. |
| Status unavailable | Lightwork could not read its delivery record just now. The in-app handoff is not affected, and the status returns when the record can be read. |

## Retries and no duplicates

- Up to five attempts over about an hour: immediately, then after roughly 1, 5,
  15 and 40 minutes, each ±20 %. The schedule is the webhook retry schedule.
- A retry happens only when nothing reached the receiver (for example, the
  connection failed) or on a `429` response. A `5xx` response from Zendesk or a
  webhook may mean the request was received, so it is shown as **Not confirmed**
  and is not sent again.
- Each handoff has one outbox entry keyed by its handoff id. Asking for the same
  handoff again never creates a second ticket.
- A send that may have arrived but was not confirmed is never repeated.
- If Lightwork stops during a send, it shows that send as **Not confirmed** when
  it starts again. Retries that were waiting continue after a restart, in the
  shared workspace and in every active workspace.

The in-app handoff is confirmed first. A failure here never undoes or blocks it.

## Limits and safety

- Requests use the same address guard as outbound webhooks. Addresses that point
  to private or local networks are refused.
- The enterprise egress lock applies: if it blocks the destination, nothing is sent.
- Each workspace has its own outbox, sealed with that workspace's key. It keeps
  the newest 2,000 handoffs. Finished entries are removed first when it is full.
- Each send and its outcome is recorded in the audit log without message text
  or credentials.
- The conversation link is `<Lightwork web address>/chat/goal/<id>`, the task page
  that shows the human handoff panel. Only the route is checked in the test suite;
  open one link after you set the address to confirm it on your server.
