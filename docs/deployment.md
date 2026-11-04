# Deployment

Four deployment targets, all driven by the same `maverick init` wizard.

## Desktop

Install Lightwork from a clone of the repository with the
[source installation guide](source-install.md), run `lightwork dashboard`, and
complete setup in the dashboard. No prebuilt binary, PyPI package or container
image is currently published, so install from `main`; published releases will
be listed on the
[releases page](https://github.com/Daybreak-AI-Labs/LightworkOS/releases). The
eight-package cohort is not on PyPI, so do not install Lightwork distribution
names from a public package index.

Runs as your user. Application state defaults to `~/.maverick/`; task
files use the selected sandbox workspace. Guided setup proposes
`~/Documents/Maverick`, while advanced setup proposes `~/maverick-workspace`;
`MAVERICK_WORKDIR` supplies a deployment default and an explicit saved
`[sandbox] workdir` takes precedence. Local setup provisions the selected path
before reporting success. The dashboard and enabled server/channel adapters
listen on their configured ports when started.

Answer-sharing links use **Settings → Lightwork's address for others** (or the
deployment-owned `MAVERICK_PUBLIC_URL`) when configured. The address must already
reach this installation; saving it does not publish a local server. Without it,
links use the address the page was opened at, and Chat explains when that address
is limited to this computer or a private network.

Named-workspace sharing keeps an opaque token-hash locator in the private,
deployment-wide `MAVERICK_HOME/dashboard-share-routes` directory. The destination
world store still checks the token's expiry, revocation and current review gate.
Dashboard replicas must share this private control-plane state as well as their
world backend for the same share links to work on every replica; PostgreSQL alone
does not replicate these locators. Include the directory in application-state
backups. Expired locators are pruned in bounded batches when new links are made.

**Artifact status:** the release workflow is configured to attach three
single-file PyInstaller binaries, checksums, SBOMs, and Sigstore material to a
tagged release; none has been published yet. Before relying on a binary, check
that the release lists the exact operating-system file and its verification
material. The source-bootstrap packages and the Windows MSI installer candidate
are separate paths. The MSI candidate includes the frozen runtime and offline
WebView2 installer, but still requires publisher signing and clean-machine
acceptance before release. Engineering bootstrap packages are
not attached to product releases. See
[`docs/DISTRIBUTION.md`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/DISTRIBUTION.md) for
the full artifact list and verification steps.

## Docker

No container image is published yet. Build one from a clone of the
repository with `docker build -f deploy/docker/Dockerfile -t lightwork:local .`
and use that tag in place of `ghcr.io/daybreak-ai-labs/lightworkos:<version>`
in this example. Once release images are published, use the exact version tag
of a published release.

```bash
docker run -it --rm \
  -v ~/maverick-workspace:/workspace \
  -v ~/.maverick/config.toml:/home/maverick/.maverick/config.toml:ro \
  -e MAVERICK_WORKDIR=/workspace \
  -e ANTHROPIC_API_KEY=... \
  ghcr.io/daybreak-ai-labs/lightworkos:<version> \
  start "..."
```

For untrusted skills, **do not** mount `~/.maverick/` into the same
container that runs the agent tools. A local sandbox inside this
container can read mounted files and process environment variables.
Mount only the workspace and a read-only `config.toml`; keep API keys
scoped to this container run.

This one-shot example persists task files at `/workspace`; application state
outside those mounts is disposable. A saved `[sandbox] workdir` must also point
inside the workspace mount. The standard persistent-state image default is
`/home/maverick/.maverick/workspace`; Compose explicitly uses `/workspace`.
On upgrades, relocate files from an older workdir before replacing its container
and verify persistence after replacement. A saved path is not rewritten just
because the deployment default changed.

To run the dashboard from the same image as a token-gated browser demo,
locally, on a VPS or on a managed platform, follow `deploy/demo/README.md`.

## VPS

Always-on, accessible from anywhere via channel adapters.

The `vps` deployment target generates:

- A `systemd` unit at `/etc/systemd/system/maverick.service`
- A Caddy reverse proxy config (if you need HTTPS for WhatsApp/SMS webhooks)
- Config under `/etc/maverick/config.toml` (`MAVERICK_CONFIG` env)

The generated service uses the configured sandbox workdir and validates that
the service account can use it. It does not assume that every setup selected
`~/maverick-workspace`.

The VPS installer is `deploy/vps/install.sh`; its usage notes are at the top
of the script, and
[`deploy/vps/README.md`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/deploy/vps/README.md)
describes how it renders the service. Fetch the script and check out the
repository at the same full commit SHA, as the script's header shows. Confirm
the generated service and reverse proxy before exposing the dashboard to users.

### Security-sensitive world-schema upgrades

The v32 execution-principal and v33 HALT-generation migrations are additive
database changes, but they are not a mixed-binary security guarantee. Before an
upgrade that crosses either version, drain and stop every goal executor and
every process that can arm or clear the shared HALT, upgrade those processes as
one cohort, let one upgraded process migrate the world store, and only then
resume dispatch. A pre-v32 executor does not enforce the exact execution binding;
a pre-v33 HALT writer does not rotate or compare the clear generation.

Do not treat the SQL migration's online-safe classification as permission to
run old and new executors concurrently when relying on either property. The
database remains upgrade-compatible; the security semantics take effect after
all relevant writers are on the upgraded code.

## Legacy workspace records

On PostgreSQL, department boards use exact workspace ownership for their task
population and approvals even when legacy compatibility reads are enabled.
Older unassigned tasks and approvals are excluded from named-workspace boards
until an administrator migrates them, so board totals can differ from views
that still include legacy records.

Flow `regex()` expressions now allow at most one unescaped quantifier and no
counted repetitions. Unsupported patterns fail the flow step instead of
silently returning an empty value; revise existing expressions before upgrade.

## Behind a load balancer or reverse proxy

The dashboard preserves the actual network peer rather than allowing Uvicorn
to rewrite it from forwarding headers. Public phone and TV consent endpoints
have their own address resolution and use `FORWARDED_ALLOW_IPS` to identify
trusted forwarders. To count each device separately, list the balancer in the
environment the dashboard starts in:

```bash
# the balancer's address; current uvicorn also accepts a range such as 10.0.0.0/16
export FORWARDED_ALLOW_IPS="10.0.1.20"
```

- List only proxies you run, and make sure they add the address of the
  connection they received to `X-Forwarded-For` (most load balancers do). Do not
  use `*` when the dashboard can also be reached directly: any caller could then
  choose the address it is counted under.
- The dashboard's other address checks use `[auth.proxy] trusted_proxies`,
  rather than treating `FORWARDED_ALLOW_IPS` as permission to rewrite the peer.
  If running an external ASGI server instead of Lightwork's launcher, disable
  its proxy-header middleware (for Uvicorn, use `--no-proxy-headers`) so the
  true peer reaches the application.
- The per-app limit (Settings, "Requests per minute from each app") is
  separate and always applies to the whole app, whatever the address.
- To check, send requests from two devices and look at the dashboard's request
  log: it should show each device's own address instead of the balancer's.

### Sign-in attempts behind a proxy

Signing in with an email and passphrase allows 10 attempts a minute from each
address, for the owner and colleagues alike; the 11th gets "Too many sign-in
attempts. Wait a minute and try again." The address is the connection's, and
the `X-Forwarded-For` chain counts only when the connection comes from an
address listed in `[auth.proxy] trusted_proxies`. The public rights-request
form and the allowed-addresses list (`[auth.ip_allowlist]`) read the address
the same way. Behind a load balancer or reverse proxy that is not listed,
everyone signing in shares one allowance, so a few mistyped passphrases can
lock the whole office out for a minute. List your proxies:

```toml
[auth.proxy]
trusted_proxies = ["10.0.1.20"]   # your proxy's address, or a range such as "10.0.0.0/16"
```

- This works whether or not reverse-proxy sign-in (`[auth.proxy] enabled`) is
  on. With reverse-proxy sign-in off it only changes which address is counted;
  it does not let the proxy sign anyone in.
- The list is exact: only the addresses listed count, so include `127.0.0.1`
  if a proxy runs on the same computer.
- List only proxies you run. Lightwork walks the chain from the right and stops
  at the first address none of your proxies vouched for, so a caller cannot
  choose the address it is counted under.
- Settings shows the same setting as "Proxy addresses to trust".

## Phone (companion mode)

Lightwork itself runs on Desktop or VPS — your phone is a frontend that
talks to it through one of the channels below. This avoids the cost,
privacy, and capability tradeoffs of running an agent on the phone
itself, while keeping parity with the desktop experience.

Start the channel server on whichever machine Lightwork runs on:

```bash
maverick serve
```

### Channel matrix

| Channel  | Status   | Setup | Public webhook needed? |
|----------|----------|-------|------------------------|
| Telegram | ready    | Create a bot via @BotFather, paste token | no |
| Discord  | ready    | Create a Discord app + bot, enable Message Content Intent | no |
| Slack    | ready    | Create app, enable Socket Mode, paste both tokens | no |
| Signal   | ready    | Install signal-cli, register your number | no |
| Email    | ready    | IMAP + SMTP credentials (Gmail app password works) | no |
| Matrix   | ready    | Homeserver URL + user_id + access token | no |
| WhatsApp | ready    | Twilio Business API + public HTTPS endpoint | YES |
| SMS      | ready    | Twilio + public HTTPS endpoint | YES |
| iMessage | ready    | macOS only + Full Disk Access permission | no |

Multiple channels can be enabled at once; each runs in its own async task.

### Channel setup recipes

**Telegram (easiest):**

1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Run `/newbot`, follow prompts, copy the token
3. `maverick init` — enable telegram, paste token at the env-var prompt
4. `maverick serve`
5. Find your bot in Telegram and message it

**Discord:**

1. https://discord.com/developers/applications → New Application
2. Bot tab → Add Bot → enable Message Content Intent → copy token
3. OAuth2 → URL Generator → scopes: `bot`; permissions: Read Messages, Send Messages
4. Open the generated URL to invite the bot to your server
5. `maverick init`, enable discord, paste token

**Slack:**

1. https://api.slack.com/apps → Create New App → From scratch
2. Socket Mode → Enable; generate an App-Level Token with `connections:write` scope
3. OAuth & Permissions → add bot scopes: `chat:write`, `im:history`, `im:read`
4. Install to your workspace; copy Bot Token
5. Event Subscriptions → enable; subscribe to `message.im`
6. `maverick init`, enable slack, paste both tokens

**Signal:**

1. Install signal-cli: https://github.com/AsamK/signal-cli
2. Register: `signal-cli -u +12345550199 register`
3. Verify with the SMS code: `signal-cli -u +12345550199 verify 123-456`
4. `maverick init`, enable signal, enter your number

**Email:**

1. Use an app password (Gmail Settings → 2FA → App Passwords)
2. `maverick init`, enable email, paste IMAP/SMTP details + app password

**Matrix:**

1. Create account on matrix.org (or self-hosted homeserver)
2. Get access token (Element → Settings → Help & About → Access Token)
3. `maverick init`, enable matrix, paste homeserver, user_id, token

**WhatsApp / SMS (require public webhook):**

1. Sign up at twilio.com; verify a sender
2. Run Lightwork on a VPS (you need a public HTTPS endpoint)
3. Caddyfile in `deploy/vps/Caddyfile` shows the reverse-proxy pattern
4. `maverick init`, enable whatsapp/sms, paste Twilio creds + from number
5. In Twilio console, set the webhook URL to
   `https://yourdomain.com/webhook/whatsapp` (or `/sms`)

**iMessage (macOS only):**

1. System Settings → Privacy & Security → Full Disk Access
2. Add `/usr/bin/python3` (or your Python interpreter) to the list
3. `maverick init`, enable imessage
