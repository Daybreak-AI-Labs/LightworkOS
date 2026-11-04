# Agent threat hunting

Every safety-relevant thing an agent does — or has done to it — lands in the
[audit log](operations.md): the shield blocking a prompt injection, the egress
lock refusing a cloud call (an exfiltration attempt), a sub-agent denied for
trying to exceed its capability grant, a governance policy firing, the kill
switch. `maverick hunt` sweeps that trail and surfaces the attacks, risk-ranked.

```bash
maverick hunt                      # sweep the whole audit trail
maverick hunt --since 2026-06-01   # bound the window (UTC)
maverick hunt --strict             # exit non-zero if any signal is found (gate a monitor)
maverick hunt --format json        # for a SIEM / pipeline
```

```text
Agent threat hunt
Risk: HIGH  (4210 audit event(s) scanned, 3 signal type(s))

  [HIGH] Exfiltration attempt: an egress to a non-local provider was blocked
      6 event(s); agents: research-1, summarizer-2; last 2026-06-07 14:02 UTC
  [HIGH] Privilege escalation: an agent tried to exceed its capability grant
      2 event(s); agents: tool-runner-3; last 2026-06-07 13:55 UTC
  [LOW]  Secret detected and redacted before write
      41 event(s); agents: system; last 2026-06-07 14:10 UTC
```

## What it hunts

| Signal | Audit event | What it means |
|---|---|---|
| Prompt injection / jailbreak | `shield_block` | the shield blocked unsafe content |
| Exfiltration attempt | `egress_blocked` | the egress lock refused a non-local provider |
| Privilege escalation | `capability_denied` | an agent tried to exceed its grant |
| Governance denial | `governance_denied` | a governance policy denied an action |
| Kill switch | `halt` | `~/.maverick/HALT` aborted running goals |
| Secret leak (caught) | `secret_redacted` | a secret was detected and redacted |

The audit log is secret-redacted before write, and the hunt only summarises event
**metadata** (kind / agent / goal / provider / tool / reason) — never payload
content. The sweep is fail-soft: a missing or unreadable log yields a `clear`
report rather than an error.

## Conducted by the agent

`maverick hunt` is the engine. The **threat-hunter agent** builds on it: it runs
the sweep, then investigates each signal — correlating events, pulling the goal
that triggered it, and judging whether it's a real attack or a benign block — and
reports for a human to action. It surfaces; a human responds.

## Remediation (bounded auto-fix)

`maverick remediate` assesses the deployment's security posture — control gaps
(from `maverick compliance`) plus active breach signals (from the hunt) — and maps
each gap to the fix that closes it:

```bash
maverick remediate           # show the plan (gaps, breaches, what would be fixed)
maverick remediate --apply   # apply the auto-fixable fixes (only if enabled)
```

Fixes split two ways:

- **Auto-fixable** — reversible, in-boundary flips of *Lightwork's own* config
  (enable audit signing, set retention). Applied by `--apply` **only** under
  enterprise mode **plus** an explicit opt-in (`[security] auto_fix = true` /
  `MAVERICK_SECURITY_AUTOFIX=1`), both off by default. The write is
  least-destructive (it appends a config block only when that section is absent,
  never editing an existing one), every applied fix is a `config_remediated` audit
  event, and the command tells you how to undo it.
- **Gated** — anything behaviour-changing (enterprise mode, at-rest encryption,
  consent) or outward-facing is **proposed for a human**, never auto-applied.

So the security assessor fixes the safe, reversible gaps on its own and leaves the
consequential ones for a person — more throughput, bounded blast radius.
