# Security policy

Lightwork is an AI agent that executes shell commands, reads files, and
calls external APIs. Vulnerabilities here can affect any host running it.
This policy explains how to report a vulnerability and how reports are
handled.

## Reporting

**Do not file public GitHub issues for vulnerabilities.** Report privately:

1. **GitHub private vulnerability reporting** (preferred): open the
   repository's **Security** tab and choose **Report a vulnerability**, or go
   directly to
   https://github.com/Daybreak-AI-Labs/LightworkOS/security/advisories/new.
2. **Email**, if you cannot use GitHub: chris@daybreakailabs.com.

Include:

- Affected version (`lightwork version` output, or the commit you tested)
- Reproduction steps
- Impact assessment (what an attacker can achieve)
- Proposed fix, if you have one

## Coordinated disclosure

We follow a **90-day coordinated disclosure window** from initial report.
For unpatched critical issues we may extend by mutual agreement.

Public disclosure (advisory, and a CVE where one is assigned) happens after a
fix is available. We credit reporters in the advisory unless they prefer to
stay anonymous. Disclosed issues are also recorded in the
[disclosure log](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/DISCLOSURES.md).

## Supported versions

No release is currently published. The packages on `main` are at version
`0.1.7` (see `release-cohort.toml`), which is unreleased, and security fixes
are made on `main`.

Once releases are published, only the latest minor release receives
security fixes. Older releases are not patched. This table will list
each supported release when the first one is published.

| Version | Supported |
|---------|-----------|
| `main` (0.1.7, unreleased) | Yes: development line; fixes land here |

## Threat model

Out of scope (will not be treated as vulns):

- LLM hallucinations / prompt-injection effects the user explicitly
  authorized via tool calls (e.g. `maverick` runs `rm` because the
  user told it to).
- Anything that requires already-arbitrary code execution on the host.

In scope:

- Privilege escalation beyond the sandbox backend (local subprocess,
  Docker `--network=none`, SSH-as-user).
- Prompt-injection chains that bypass `maverick-shield` (e.g. tool
  output injection, image vision-block injection, cross-turn replay).
- Webhook spoofing / signature bypass on channel adapters (Telegram,
  Twilio).
- Secret exfiltration via skill bodies, MCP tool descriptions, or
  plugin entry_points.
- Path traversal in attachments, skills, or world.db paths.
- DoS on the local FastAPI dashboard.

## Severity and response targets

Maintainers rate each in-scope report against this rubric. The response and
fix times are targets the maintainers aim for, not contractual guarantees.

| Severity | Examples (from the threat model) | First response | Fix target |
|---|---|---|---|
| Critical | sandbox escape to host; secret exfiltration without user action; auth bypass on the dashboard/API | 24 h | 7 days |
| High | shield bypass chains achieving unauthorized tool effects; webhook signature bypass; cross-tenant data access | 48 h | 14 days |
| Medium | path traversal contained by a second control; DoS on local services; capability-check gaps | 5 days | 30 days |
| Low | hardening gaps, missing defense-in-depth, doc-level issues | 10 days | next minor |

**Recognition.** Every valid report receives credit in the advisory (unless
anonymity is requested) and an entry in the list below. The project does not
run a paid bug bounty. Duplicates are credited to the first reporter; the
maintainers judge severity against the rubric and explain their reasoning in
the advisory thread.

**Safe harbor.** Good-faith research within this scope — using your own
instance, no access to others' data, no service degradation of systems you
don't own, no social engineering — will not be met with legal action. Testing
against someone else's deployment is out of scope and out of safe harbor.

**Credited researchers.** Researchers credited in published advisories are
listed here. None yet.

## Hardening tips

- Set `MAVERICK_DASHBOARD_TOKEN` on any VPS deployment exposed beyond
  `127.0.0.1`.
- Set `MAVERICK_PLUGINS_ALLOW` explicitly; the default is empty so
  pip-installed plugins do NOT auto-execute, but if you want to enable
  any, list them by name.
- Use `sandbox.backend = "docker"` for goals that run user-provided
  shell. Docker isolation is much stronger than the local subprocess
  backend.
- Rotate `ANTHROPIC_API_KEY` etc. on a schedule. Lightwork reads from
  `~/.maverick/.env` (chmod 600).

## Execution posture

The most important thing to understand about Lightwork's security:

> **By default, the agent executes model-generated shell commands. With the
> default `local` sandbox backend, those commands run directly on the host,
> and the safety Shield is an optional dependency that fails *open* if not
> installed.** A successful prompt injection on that configuration is host
> code execution.

This is a deliberate design trade-off (fast local iteration, no hard
dependency on the shield), not an oversight — but it means **the operator
chooses the blast radius**. Defense in depth, from outermost to innermost:

1. **Sandbox backend** — the real containment boundary. `local` = your host;
   `docker`/`podman` run each command in a throwaway container
   (`--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
   `--pids-limit`); `kubernetes`/`ssh` isolate further.
   `firecracker` is an experimental scaffold, not a supported isolation backend. The
   setup wizard defaults real installs to a container when one is available,
   and the kernel logs a one-time warning when it runs on `local` (louder
   when the shield is absent). **For any untrusted goal, use a container
   backend.**
2. **Agent Shield** (`maverick-shield`) — screens prompts, tool calls, and
   output. Optional and fail-open by design, so it is a *floor*, not a
   guarantee. Treat it as one layer, never the only one.
3. **Tool ACL + budget + killswitch** — `[security] denied_tools`, the
   `Budget` cap, and `~/.maverick/HALT` bound what a run can do and spend.

The consumer wizard (`maverick init`, "consumer" mode) fails closed: when no
container is available it **denies** the host-mutating tools (`shell`,
`write_file`, `apply_patch`) and runs the strictest shield profile.

## Security-relevant configuration

| Setting (env / config)                    | Effect                                                                 |
|-------------------------------------------|------------------------------------------------------------------------|
| `[sandbox] backend`                       | Execution isolation. `docker`/`podman` strongly recommended for untrusted goals. |
| `[sandbox] pids_limit` (default 512)      | Fork-bomb cap for container backends.                                  |
| `MAVERICK_SUPPRESS_SANDBOX_WARNING=1`     | Silences the unsandboxed-host warning (only set if you accept host execution). |
| `MAVERICK_DASHBOARD_TOKEN`                | Required for any non-loopback / proxied dashboard access (fail-closed). |
| `MAVERICK_PLUGINS_ALLOW`                  | Allowlist for plugin entry points (default empty = none auto-load).    |
| `MAVERICK_FETCH_ALLOW_PRIVATE=1`          | Disables the SSRF guard's private/metadata-IP block (do not set in prod). |
| `MAVERICK_MCP_TOKEN` / `MAVERICK_MCP_MAX_BODY` | Bearer auth (fail-closed) + request-body cap for the MCP HTTP transport. |
| `MAVERICK_A2A_TOKEN`                      | Bearer auth for the A2A task endpoint (off unless A2A is enabled).     |
| `[webhooks] secret` / `MAVERICK_WEBHOOK_SECRET` | HMAC secret for inbound webhooks; with no secret the receivers fail closed (401). |
| `SMS_BIND_HOST` / `WHATSAPP_BIND_HOST`    | Channel webhook bind address (default `127.0.0.1`; front with a proxy). |
| `*_ALLOWED_USER_IDS` (per channel)        | Mandatory default-deny sender allowlist for chat channels.             |

When in doubt, prefer the more restrictive setting: a container backend, an
explicit dashboard token, an empty plugin allowlist, and per-channel sender
allowlists.
