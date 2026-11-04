# DSAR Concierge — a standalone data-subject-request agent

The whole DSAR lifecycle on one small surface, run on its own or alongside
the Lightwork platform (same records — the capability seam decides what's on;
see `/about` in the running app):

* **Intake** — a subject-facing form (`/request`) and a message webhook
  (`POST /webhook/message`) with a deterministic detector (kind + subject +
  matched phrases kept as provenance; nothing is silently opened).
* **Identity verification** — an emailed single-use token link. The
  statutory clock starts at submission and never waits for the inbox.
* **The clock** — `DSAR_SLA_DAYS` (default 30), SLA aging bands on the
  queue, overdue front and center.
* **Fulfillment** — access/portability packages assembled ONLY from the
  system extracts the operator provides (`package.json` download + cover
  note emailed to the subject). **Erasure is never destructive from
  here**: the agent prepares a structured per-system operator handoff and
  parks the request awaiting confirmation.
* **Counted value** — `/value.json` sums per-request value (env-overridable
  baselines) for a fleet console to roll up.

**With Lightwork** the same agent additionally mirrors every request into
the governed privacy workspace registers, lands every step on the signed
audit chain, and can use the platform's real subject-data export machinery.

## Run it

```bash
DSAR_OPERATOR_TOKEN=$(openssl rand -hex 24) bash run_standalone.sh
                                # http://127.0.0.1:8891  (operator queue;
                                # sign in as operator with DSAR_OPERATOR_TOKEN)
                                # /request  (subject-facing form)
                                # /about    (capability matrix)
```

Container installs: `Dockerfile.standalone` here; its header shows the build
and run commands, configured with the env names below. For remote access, place the
loopback-bound container behind an HTTPS proxy: HTTP Basic credentials need
TLS in transit. Set `DSAR_BASE_URL` to that proxy's public HTTPS URL.
Operator changes require an Origin or Referer matching the public scheme, host
and port in `DSAR_BASE_URL`. Configure that URL for the HTTPS proxy's external
address; API clients performing changes must send the same trusted origin.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `DSAR_STANDALONE` | unset | `1` forces standalone (also implied when the platform isn't installed) |
| `DSAR_HOST` / `DSAR_PORT` | `127.0.0.1` / `8891` | bind (set `DSAR_HOST=0.0.0.0` in containers) |
| `DSAR_DATA_DIR` | `.dsar-data` | the request store (mount `/data` in containers) |
| `DSAR_BASE_URL` | `http://127.0.0.1:8891` | public URL used in verification links |
| `DSAR_OPERATOR_USER` / `DSAR_OPERATOR_TOKEN` | `operator` / unset | HTTP Basic credentials required for the operator queue, case pages, package downloads, and workflow actions |
| `DSAR_EMAIL_ALLOWED_DOMAINS` | unset | Required in platform mode: comma-separated exact recipient domains permitted for public intake and verification email. Configure shared rate limiting at the reverse proxy and mail service; the in-process peer, recipient, and global limits are per worker and reset on restart. External ASGI servers must disable proxy-header rewriting so callers cannot spoof the peer. |
| `DSAR_SLA_DAYS` | `30` | the statutory clock |
| `EMAIL_USER` / `EMAIL_SMTP_PORT` | — | outbound mail identity (standalone captures locally) |
| `VALUE_HOURLY_RATE`, `VALUE_DSAR_*_HOURS` | `$60`, 2.5/2.5/3.0h | the operator's own value inputs |

Public intake limits are best-effort abuse reduction. Recipient aliases can map
multiple addresses to the same mailbox, and a failed delivery still consumes a
short-term reservation. Configure recipient-aware quotas at the mail service;
review failed deliveries through the operator's normal mail monitoring.
