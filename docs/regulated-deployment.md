# Regulated deployment

**Run Lightwork on private / sensitive data with fail-closed application
controls and deployment-level network containment.**

The kernel ships fail-open and cloud-capable — right for a personal agent, wrong the
moment it touches PHI, PII, financial, or otherwise regulated data. This page is the
single reference for standing Lightwork up in a *regulated* posture: one profile, the
guarantees it gives you, and one command to **prove** they hold.

## The guarantee

With the profile below, every load-bearing control is fail-closed at once:

| Guarantee | What it means | GDPR / EU AI Act |
|---|---|---|
| **Application egress lock** | Governed LLM calls are pinned to local / self-hosted models (`ollama` / `vllm` / `tgi`, or an allow-listed endpoint). A cloud-routed call raises `EgressBlocked` **before any prompt is sent**; supported Python HTTP clients are checked per request. | GDPR Art. 32 / AI Act Art. 15 |
| **Encryption at rest** | AES-256-GCM seals the memory store and the world-DB content (turns, facts, messages, questions). | GDPR Art. 32 |
| **Tamper-evident audit** | Every event is Ed25519 hash-chained, so a forged or deleted log line is detectable. | EU AI Act Art. 12 |
| **Human oversight** | Destructive-action consent defaults to `ask` instead of auto-approve: a task someone started in Lightwork's chat waits for a person on the Approvals page and is refused if nobody decides in time; other non-interactive runs are *denied*. | EU AI Act Art. 14 |
| **Storage limitation** | Retention windows expire audit, episode, and event data on a schedule. | GDPR Art. 5(1)(e) |
| **Isolated execution** | Agent-generated shell runs in a container (docker → podman), never `shell=True` on the host; if no container runtime exists it fails closed. Plugin tool calls can be isolation-proxied and plugin distributions can be content-hash-checked after a lockfile is generated, but plugin import/discovery code still runs in-process; install only trusted plugins. | EU AI Act Art. 15 (robustness / cybersecurity) |

Enterprise mode alone is not a hard network boundary: raw sockets, subprocess
clients, and network libraries outside the wrapped set require sandbox and
deployment controls. For a no-egress requirement, enforce container/sandbox
network isolation plus host/OS/VPC default-deny egress, and verify those
controls independently of `maverick enterprise verify`.

## The profile

Put this in `~/.maverick/config.toml`. Enterprise mode alone gives you the egress lock,
fail-closed consent, capability enforcement, at-rest encryption, **and** the
deployment-specific secure defaults (container-default sandbox, plugin tool-call isolation +
hash-lock checks); signing, retention, and anonymization are the extra knobs. Setting
`[profile] name = "enterprise"` (or `MAVERICK_PROFILE=enterprise`) selects enterprise
mode plus those defaults in a single knob.

```toml
[enterprise]
mode = true            # egress lock + fail-closed consent + capabilities + at-rest encryption

[audit]
sign = true            # Ed25519 tamper-evident audit chain

[privacy]
anonymous = true       # redact PII (email/SSN/phone) from audit events before write

[retention]
audit_days = 365       # storage limitation (GDPR Art. 5(1)(e)) -- tune to your policy
episodes_days = 90
events_days = 365
messages_days = 365
```

Anonymization is required, not optional: at-rest encryption protects *closed, sealed*
audit segments, but the current day-file stays plaintext until it is sealed, so only
anonymous mode actually redacts PII from the live log. Without it the
`PII redaction in logs` compliance control reports `action_needed`.

Retention and tamper-evidence are designed to coexist. `maverick retention enforce`
deletes expired day-files, but their entries stay in the append-only anchor ledger --
so the purge is recorded there as a signed `retention_purge` row naming each removed
day and the exact tip hash and row count it destroyed. `maverick audit verify` reads
that row and reports the deletion as policy rather than tampering, which is why a
retention-enabled deployment still verifies green.

The record is deliberately narrow, so it excuses a deletion without excusing an
attack. It is honoured only when the ledger's own signed chain is intact, only for
the days it names, and only when the tip and row count match that day's last anchor
-- so a file altered before deletion, or truncated before deletion, still fails
verification. Because the row commits to the tip, an archived copy of a purged day
(see [audit checkpoint operations](audit-checkpoints.md))
can be reconciled byte-for-byte against what
the purge claims it removed.

The env equivalents (for containers / CI, where a secrets manager injects the key):

```bash
export MAVERICK_ENTERPRISE=1
export MAVERICK_AUDIT_SIGN=1
export MAVERICK_ANON=1
export MAVERICK_ENCRYPTION_KEY=<32-byte key, hex or base64>   # else generated under ~/.maverick/keys
```

To seal data that already exists on disk from before encryption was enabled, run
`maverick encryption migrate` once (see [Encryption at rest](encryption.md)).

## Prove it

Two commands, two audiences:

```bash
maverick enterprise verify     # ops / CI: actively exercise the guarantees
maverick compliance --strict   # auditor / gate: map controls to articles, fail if any regress
```

`maverick enterprise verify` does **not** just read flags — it proves the egress lock
refuses a real cloud provider and that at-rest sealing round-trips on *this* box (so a
missing crypto backend or unreadable key fails here, not silently at write time). It
exits non-zero if any guarantee fails, so it drops straight into a deploy gate:

```text
Regulated-deployment guarantees
===============================

  [PASS]  Egress lock           enterprise mode on; cloud provider 'anthropic' refused, self-hosted 'ollama' allowed ...
  [PASS]  At-rest encryption    AES-256-GCM seal/unseal round-trips; plaintext absent from ciphertext
  [PASS]  Tamper-evident audit  Ed25519 hash-chain on; verify with 'maverick audit verify'
  [PASS]  Human oversight       consent mode = ask
  [PASS]  Retention policy      configured; enforce with 'maverick retention enforce'

5/5 guarantees hold
```

`maverick compliance --strict` is the broader GDPR + EU AI Act control map (it also
covers transparency disclosure, redaction, the kill switch, and the data-subject-rights
tooling); `--format json` feeds a SIEM or pipeline.

## Records of processing (Art. 30)

GDPR Art. 30 requires the controller to keep a record of processing activities.
`maverick ropa` generates a **scaffold** of it from the live deployment — pre-filling the
technical half (the personal-data categories it stores, recipients / international
transfers derived from the egress lock, retention, and the active Art. 32 security
measures) and marking the organizational fields (controller identity, DPO, lawful basis,
purposes) for your DPO to complete:

```bash
maverick ropa                       # readable scaffold
maverick ropa --format json -o ropa.json
```

It's a starting point for a DPO to finish, not a completed record.

## Impact assessment (Art. 35) and AI-Act classification

Two more scaffolds for the rest of the paperwork:

```bash
maverick dpia      # GDPR Art. 35 Data Protection Impact Assessment scaffold
maverick ai-act    # EU AI Act risk classification (self-assessment)
```

`maverick dpia` pre-fills the processing description (consistent with the ROPA) and a
**risk register** of the agent-on-personal-data risks — data egress to an LLM,
unsupervised automated action, audit tampering, indefinite retention — each mapped to the
Lightwork control that mitigates it and flagged `OPEN` if that control is currently off.
Necessity/proportionality and residual-risk sign-off are left to the controller.

`maverick ai-act` reports the live Art. 50 transparency posture and hands you a checklist
of the prohibited (Art. 5) and high-risk (Annex III) categories. A conversational agent
that discloses it is AI is **limited-risk by default** — but you must rule out those lists
for your use case. Both are self-assessment aids, not legal attestations.

## What this is *not*

This is **control coverage, not a legal compliance attestation.** Full GDPR / EU AI Act
compliance also needs organizational and legal measures the software cannot perform — a
DPA, a completed ROPA (`maverick ropa` scaffolds the Art. 30 record but a DPO must finish
it), a DPIA, AI-Act risk classification, and review by qualified counsel. The data-subject
rights (access, portability, erasure) are *available* on demand via `maverick dsar export`,
`maverick export-user`, and `maverick erase`, not automatic.

See also: [Encryption at rest](encryption.md) · [Safety & enterprise mode](safety.md#enterprise-mode-private-sensitive-data).
