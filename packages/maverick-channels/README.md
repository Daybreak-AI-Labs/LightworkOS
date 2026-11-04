# maverick-channels

Channel adapters for Lightwork. A channel normalizes incoming messages
from any platform into a shared `{user_id, text, attachments}` shape,
hands it to the orchestrator, and routes the response back.

This is how phone-companion mode works: Lightwork itself runs on your
Desktop or VPS (`maverick serve`), and any of these channels gives your
phone (or any other client) a frontend.

## Channels

Every adapter below is registered in `maverick.server._WIRES`, so
`maverick serve` hosts it once its `[channels.<table>]` section is enabled
(the installer offers each one). Each needs its provider's credentials and a
per-sender allowlist; unknown senders are denied. Readiness depends on the
provider account, so send a test message from the Channels page after setup.

| Channel | Config table | Install extra | Notes |
|---|---|---|---|
| Telegram | `telegram` | `[telegram]` | Bot API long-poll; no public endpoint needed |
| Discord | `discord` | `[discord]` | Gateway WebSocket bot |
| Slack | `slack` | `[slack]` | Socket Mode; no public webhook needed |
| Signal | `signal` | bundled; needs `signal-cli` on PATH | JSON-RPC daemon |
| Email | `email` | bundled | IMAP poll + SMTP send (stdlib) |
| Matrix | `matrix` | `[matrix]` | matrix-nio; federated, end-to-end encryptable |
| Mattermost | `mattermost` | `[mattermost]` | Bot account answering direct messages and @mentions |
| Microsoft Teams | `teams` | `[teams]` | Azure Bot Framework webhook; approvals as Adaptive Cards |
| Bluesky | `bluesky` | `[bluesky]` | AT Protocol |
| Mastodon | `mastodon` | `[mastodon]` | Mastodon API |
| Threads | `threads` | `[threads]` | Meta Threads API |
| RCS | `rcs` | `[rcs]` | Google RCS Business Messaging |
| WhatsApp (Twilio) | `whatsapp` | `[whatsapp]` | Twilio webhook; needs public HTTPS |
| WhatsApp (Cloud API) | `whatsapp_cloud` | `[whatsapp-cloud]` | Meta Cloud API webhook; needs public HTTPS |
| SMS | `sms` | `[sms]` | Twilio webhook; needs public HTTPS |
| iMessage | `imessage` | bundled | macOS only; needs Full Disk Access |
| IRC | `irc` | bundled | RFC 1459/2812 over asyncio |
| Voice | `voice` | `[voice]` | Voice provider functions (HTTP results never prove spoken delivery) |

`rich_render` is an opt-in helper layered on the base adapters, not a separate
channel.

Install one extra per channel, or everything at once:

```bash
python -m pip install -e ./packages/maverick-core -e './packages/maverick-channels[all]'
```

## The interface

Every channel implements:

```python
class Channel:
    async def start(self) -> None: ...
    async def send(self, user_id: str, text: str) -> None: ...
    async def stop(self) -> None: ...
```

And dispatches `IncomingMessage(user_id, text, attachments)` to a single
handler the wizard wires up.

## Wiring channels

In `~/.maverick/config.toml`:

```toml
[channels.telegram]
enabled = true
bot_token = "${TELEGRAM_BOT_TOKEN}"
allowed_user_ids = ["123456789"]
# optional alternative: allowed_chat_ids = ["-1001234567890"]

[channels.discord]
enabled = true
bot_token = "${DISCORD_BOT_TOKEN}"

[channels.slack]
enabled = false
app_token = "${SLACK_APP_TOKEN}"
bot_token = "${SLACK_BOT_TOKEN}"

[channels.signal]
enabled = false
phone_number = "+12345550199"

[channels.email]
enabled = false
imap_host = "imap.gmail.com"
imap_user = "${EMAIL_USER}"
imap_password = "${EMAIL_APP_PASSWORD}"
smtp_host = "smtp.gmail.com"
smtp_port = 465
smtp_user = "${EMAIL_USER}"
smtp_password = "${EMAIL_APP_PASSWORD}"
```

Then run:

```bash
maverick serve
```

Multiple channels can be enabled simultaneously — each runs in its own
async task.
