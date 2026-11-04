# Incident response guide for Lightwork deployments

This guide is for operators who run Lightwork. It shows how to use Lightwork's
built-in controls to contain an incident, collect evidence and recover. It is
not a complete incident-response programme: roles, escalation, response
targets and notification duties belong to your organization's own incident
policy. The controls described here support SOC 2 CC7.3/CC7.4, ISO/IEC
27001:2022 A.5.24–A.5.28 and ISO/IEC 42001:2023 A.10 (AI incidents).

To report a vulnerability **in Lightwork itself**, do not open a public issue;
follow the [security policy](../../../SECURITY.md).

Code paths below are relative to `packages/maverick-core/`. Data paths assume
the default data directory `~/.maverick` (`MAVERICK_HOME` overrides it).

---

## 1. Scope

- **Security incidents** — confidentiality, integrity or availability events:
  data exposure or exfiltration, credential or key compromise, unauthorized
  access, malware, denial of service.
- **AI / agent incidents** (ISO 42001 A.10) — a model or agent behaving
  unsafely, exceeding its authorized scope, taking an unsafe autonomous action,
  prompt-injection compromise, a governance or guardrail bypass, a fairness
  alert, or runaway learning.

Routine bugs with no safety, security or data impact belong in normal
engineering triage. Outages of a model provider's own service are handled by
that provider; coordinate around them, but their response is an inherited
control.

---

## 2. Severity levels (example)

Adapt these levels and set response targets in your own incident policy.
Classify at triage, re-classify as facts change, and escalate when in doubt.

| Level | Definition | Examples |
| --- | --- | --- |
| **SEV1 — Critical** | Confirmed or highly likely breach, irreversible data loss, or an unsafe autonomous action with real-world impact. | Personal-data exfiltration; audit-signing key compromise; an agent executed a destructive or irreversible real-world action; prompt injection that bypassed the shield and reached a high-privilege tool. |
| **SEV2 — High** | Serious incident, contained or containable, with significant but bounded impact; or a near-miss that only governance or the killswitch stopped. | Killswitch fired on an agent attempting an out-of-scope action; single-tenant data exposure; repeated `shield_block` / `governance_denied` events indicating an active attack; a capability misconfiguration granting excess privilege. |
| **SEV3 — Medium** | Limited impact, no confirmed data exposure, system working within its guardrails. | A single fairness alert needing review; a circuit breaker repeatedly tripping on a non-critical dependency; an isolated `capability_denied` anomaly. |
| **SEV4 — Low** | Informational; a policy or hygiene issue with no operational impact. | A single anomalous audit event explained on review; a guardrail false positive. |

**Treat as SEV2 or higher until disproved:** any halt fired in production; any
audit-chain or anchor verification failure (possible tampering); any confirmed
access to data by an unauthorized party; any agent action outside its approved
capability set.

---

## 3. Roles (example)

| Role | Responsibilities |
| --- | --- |
| **Incident commander** | Owns the incident end to end: sets severity, assigns roles, authorizes containment (including a halt), keeps the timeline, declares resolution. |
| **Technical lead** | Investigates, collects and verifies audit evidence, runs the halt, circuit-breaker and revocation actions in §4, and drives root-cause analysis. |
| **Communications** | Internal status updates and any external notices, under your organization's approval process. |
| **Scribe** | Keeps the timeline in your incident record: every action, decision and time (UTC), with evidence references (audit day-files, event kinds, command output). |

In a small team one person may hold several roles; for the most serious
incidents keep the incident commander and the scribe separate.

---

## 4. Lifecycle checklist

### Detect

- [ ] Capture the trigger: alert, halt event, `shield_block` spike,
      `fairness_alert`, user report.
- [ ] Record the first-detected time (UTC) and source.
- [ ] Preserve evidence **before** changing anything (note the current audit
      day-file; snapshot relevant logs).
- [ ] Declare an incident and assign an incident commander.

### Triage

- [ ] Assign a provisional severity (§2).
- [ ] Decide the type: security, AI/agent, or both, and pick the §7 playbook.
- [ ] Scope it: which agents, tenants, principals, data subjects and systems.
- [ ] Decide whether to halt **now**. If an unsafe autonomous action or active
      exfiltration is plausible, halt first and investigate after.

### Contain (§5)

- [ ] Stop the harm: halt the deployment, revoke the offending principal,
      and/or leave a failing dependency's breaker open.
- [ ] Rotate exposed credentials and keys.
- [ ] Confirm containment held (re-check halt state; watch the audit log).
- [ ] Record every containment action with its time.

### Eradicate

- [ ] Remove the root cause (bad configuration, vulnerability, poisoned
      learned state, malicious input pattern).
- [ ] For AI incidents, roll learned state back to a known-good snapshot (§7)
      before re-enabling learning.
- [ ] Deploy the fix; add a guardrail or shield rule if the attack bypassed
      existing controls.
- [ ] Verify the audit log again (§6).

### Recover

- [ ] Restore service in a controlled way (one tenant or a canary first).
- [ ] Clear the halt only when the incident commander authorizes it (§5.1),
      and confirm no halt remains active.
- [ ] Restore revoked principals deliberately, one at a time.
- [ ] Watch for recurrence for a defined period, then declare resolution.

### Review

- [ ] Hold a post-incident review (§9).

---

## 5. Containment controls

### 5.1 Killswitch (halt)

Implementation: `maverick/killswitch.py`. Agents call `killswitch.check()` at
tool-call boundaries and at each turn; once a halt is active it raises
`Halted`, so agents stop at their next tool call. Ways to halt:

1. **Halt file** (fastest; works from any shell on the host):

   ```bash
   touch "${MAVERICK_HALT_FILE:-$HOME/.maverick/HALT}"
   ```

   The default path is `<data dir>/HALT`; `MAVERICK_HALT_FILE` overrides it.
   The file is checked at most about once a second, at tool boundaries. One
   halt file covers every tenant in the process.

2. **Dashboard emergency stop** (`POST /api/v1/halt`, with an optional
   `reason`). It arms the local halt and, when the deployment shares a Postgres
   world store, the shared halt that every host consults. In shared mode it
   requires a dashboard admin; in local mode, the `operate` permission. The
   action is recorded in the audit log.

3. **CLI**, through the Agent Control Plane (needs
   `[control_plane] enable = true` or `MAVERICK_CONTROL_PLANE=1`):

   ```bash
   maverick control-plane halt --reason "SEV1: unsafe action by agent X"
   maverick control-plane status      # shows the observed halt state
   ```

4. **In-process**, for code embedding Lightwork. It records a `halt` audit
   event with the reason:

   ```python
   from maverick import killswitch
   killswitch.halt("SEV1: unsafe autonomous action by agent X", source="manual")
   ```

**Verify the halt took effect** (in the process concerned, or via
`maverick control-plane status`):

```python
from maverick import killswitch
killswitch.is_active()   # True while any halt is live
killswitch.check()       # raises Halted(...) while halted
```

**Clearing (recovery only, authorized by the incident commander).** Use the
dashboard's **Resume** action (`DELETE /api/v1/halt`). It may ask for a recent
second-factor confirmation. Do **not** clear by hand by deleting the file and
calling `killswitch.clear()` or `world.disarm_halt()` in sequence: that leaves
a window in which one halt authority is clear while another is still armed.

The Resume action:

1. records the exact local file, in-process and shared halt generations;
2. takes a temporary process stop;
3. locks the observed shared row and deletes the local halt inside that
   database transaction;
4. rolls the shared clear back if the local deletion fails; and
5. releases its own process hold only after commit and verification.

A concurrent new halt changes the generation and wins; an unavailable authority
or an uncertain commit leaves the local halt in place and returns an error. For
a local-only deployment, `maverick control-plane clear-halt` applies the same
exact-generation clear to the halt file and the process.

### 5.2 Revoking a principal

Revoke the principal that misbehaved instead of halting everything when the
blast radius is one agent or one user's runs:

```bash
maverick capability revoke "user:<id>" --reason "SEV2: out-of-scope tool use"
maverick capability revocations          # list revoked principals
maverick capability unrevoke "user:<id>" # restore, during recovery
```

The revocation list (`maverick/revocation.py`) is re-read when it changes, so
a revoked principal's **next** tool call is denied even mid-run, including the
calls of agents it spawned. It is consulted only when capability enforcement is
on (`[capabilities] enforce = true`); without enforcement there is no principal
to revoke against, so halt instead.

The Agent Control Plane offers the same action for native runs and external
agents (an external agent's trust entry is revoked as well, so the gateway
refuses it too):

```bash
maverick control-plane list                                  # governed principals
maverick control-plane suspend "<principal>" --reason "..."  # revoke; reversible with resume
maverick control-plane contain "<principal>" --reason "..."  # revoke the subtree and record a security incident
maverick control-plane release "<principal>"                 # undo a containment
```

Confirm the revocation held by watching for `capability_denied` audit events on
the next attempt (§6).

### 5.3 Circuit breakers

Implementation: `maverick/circuit_breaker.py`, a three-state breaker
(closed → open → half-open) that fails fast on a misbehaving dependency.
Breakers live in memory in each process: the dashboard's live diagnostics show
the dashboard process's breakers, and the Python calls below act on the process
that runs them.

```python
from maverick import circuit_breaker
circuit_breaker.snapshot()       # every breaker with its state and counters
cb = circuit_breaker.get("<key from snapshot>")
cb.state                         # CircuitState.CLOSED / OPEN / HALF_OPEN
cb.reset()                       # force closed (recovery)
circuit_breaker.reset_all()      # drop every breaker (use with care)
```

To keep a failing dependency isolated during containment, leave its breaker
open until the dependency is confirmed healthy.

---

## 6. Evidence collection

The signed, hash-chained audit log is the record for forensics. Audit signing
is on by default; if it has been turned off, the log is append-only but not
tamper-evident.

- **Location:** `~/.maverick/audit/YYYY-MM-DD.ndjson` (one file per UTC day)
  plus the `anchors.ndjson` tip ledger. With tenant isolation on, each tenant
  has its own audit directory.
- **Verify the chain** (exits 1 on any break, so it can gate automation):

  ```bash
  maverick audit verify --all                    # every day-file plus the anchor ledger
  maverick audit verify --all --pubkey <hex>     # trust a specific Ed25519 key
  ```

  The same checks from Python (`maverick/audit/signing.py`):

  ```python
  from maverick.audit import reader, signing
  audit_dir = reader.resolve_audit_dir(None)
  for day in signing.day_files(audit_dir):
      breaks = signing.verify_chain(day)
      if breaks:
          print("CHAIN BREAK", day, breaks)       # possible tampering: escalate
  print("anchors:", signing.verify_anchors(audit_dir))
  ```

  Any break is itself an escalation trigger: preserve the files, snapshot the
  host and treat the incident as SEV2 or higher.

- **Find events:** `maverick audit grep <regex> --day YYYY-MM-DD` and
  `maverick audit tail -n 200`. `maverick audit export` writes JSON or CEF for a
  date range (`--since` / `--until` or `--all`), and `--verify` checks
  signatures first.

- **Event kinds to pull** (`maverick/audit/events.py`):

  | Event kind | Pull it for |
  | --- | --- |
  | `shield_block` | Input, tool call or output blocked by the shield (stage, reason, score): prompt injection, exfiltration attempts. |
  | `capability_denied` | An agent tried to use a capability it lacked (tool, principal, channel). |
  | `consent_result` | Human approval, denial or timeout on a gated action. |
  | `governance_denied` | A governance or policy guardrail blocked an action. |
  | `fairness_alert` | A fairness or bias threshold was breached. |
  | `halt` | The killswitch fired (source, reason). |

- **Preserve, don't alter.** Copy the relevant day-files to evidence storage and
  never edit them in place. Record the day-file names and event kinds you pulled
  in your incident record.

---

## 7. AI-incident playbook (ISO 42001 A.10)

The general pattern is **halt → snapshot → roll back → review → re-enable**.

| Symptom | Steps |
| --- | --- |
| **Agent behaving unsafely, out of scope, or taking an unsafe autonomous action** | 1. Halt (§5.1): the halt file first for speed; the dashboard emergency stop for a shared, multi-host deployment. 2. Pull `governance_denied`, `capability_denied`, `consent_result` and `halt` events (§6) to reconstruct what it attempted. 3. If one principal is responsible, revoke it (§5.2) and keep the rest running; otherwise stay halted. 4. Establish whether any action taken is reversible, and work with the owners of the affected systems to undo real-world effects. 5. Remove the root cause; re-enable only with the incident commander's approval. |
| **Prompt-injection compromise** | 1. Halt if a high-privilege tool was reached; otherwise revoke the affected principal. 2. Pull `shield_block` events (stage = input, tool or output) to see what the shield caught and what it missed. 3. Keep the malicious input as evidence and add a shield or guardrail rule for the pattern. 4. Check that no learned state was poisoned (next row). 5. Re-enable once the new rule is shown to work. |
| **Runaway or poisoned learning** | 1. Halt learning-driven agents. 2. Snapshot the current learned state for evidence: `from maverick import dreaming; dreaming.snapshot_learning_state()`. 3. Roll back to the last known-good snapshot: `maverick dream --list-snapshots`, then `maverick dream --rollback <snapshot>` (or `latest`). 4. Verify the audit log (§6) before re-enabling learning. |
| **Fairness alert** | 1. Set severity (usually SEV3 unless people are affected at scale). 2. Pull `fairness_alert` events for the metric, threshold and affected group. 3. If biased outputs are being produced at scale, halt or revoke; otherwise pause the affected workflow. 4. Find the root cause (data, prompt or learned drift), fix it and document it. 5. Assess under your own policy whether any disclosure is required. |

If an agent or model is permanently decommissioned as the resolution, record
the decision, its owner and the data disposition in your incident record.

---

## 8. Notifications

Lightwork does not send incident notifications. Duties to notify regulators,
affected individuals or contractual counterparties are your organization's,
under its own policy and the law that applies to it. For example, GDPR
Article 33 requires notifying the supervisory authority without undue delay,
and where feasible within 72 hours of becoming aware of a personal-data breach
that is likely to result in a risk to individuals; Article 34 requires telling
the individuals when that risk is high. The verified audit evidence (§6) and
your incident timeline are the inputs for those decisions. Record every
notification made (who, when, through which channel).

---

## 9. Post-incident review

- **When:** soon after resolution; for SEV1 and SEV2 always.
- **How:** blameless; focus on systems and process, not individuals.
- **Inputs:** the incident record and timeline, and the verified audit evidence.
- **Questions:**
  - [ ] Is the timeline from detection to resolution complete and accurate?
  - [ ] What were the root cause and contributing factors?
  - [ ] What detected it, what delayed detection or containment, and what went well?
  - [ ] Did the controls (halt, revocation, circuit breakers, shield and
        governance) work as intended? Any gaps?
  - [ ] Was the audit evidence complete and did it verify?
- **Outputs:** corrective actions with owners and dates in your tracking
  system, new or updated risks in your risk register, and any changes to this
  guide or to your configuration.
