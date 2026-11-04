# SOC 2 Controls Mapping

This document maps the SOC 2 **Trust Services Criteria (TSC)** to the concrete
Lightwork controls that satisfy each: a controls inventory an auditor can read
alongside the
machine-readable evidence collector in
[`packages/maverick-core/maverick/soc2.py`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/packages/maverick-core/maverick/soc2.py)
(`collect_soc2_evidence()`).

> **Note.** SOC 2 is an *organizational* attestation, not a code audit.
> Lightwork's engineering controls cover a large share of the **Security (Common
> Criteria)** plus the **Confidentiality / Availability / Processing Integrity /
> Privacy** categories — but a real SOC 2 Type II report also requires
> *process* controls (change management, vendor management, background checks,
> incident response, HR onboarding/offboarding) that are **not code**. Those are
> marked **Process-only** or **Gap** below and must be operated by the
> organization that deploys Lightwork.

## Status legend

| Status | Meaning |
| --- | --- |
| **Implemented** | A concrete, enforced technical control exists in the codebase. |
| **Implemented (on by default)** | Implemented and enabled in a default install; an operator can turn it off explicitly. |
| **Implemented (opt-in)** | Implemented but off by default; it must be enabled for a compliant deployment. |
| **Partial** | A control exists but is opt-in/off-by-default, scoped, or incomplete. |
| **Gap** | No control today; needs to be built or established. |
| **Process-only** | Satisfied (if at all) by an organizational process outside this repo, not by code. |

The "Evidence" column points at a module/file, or — where the
[`soc2.py`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/packages/maverick-core/maverick/soc2.py) collector reports it
live — the **evidence key** (the dotted path into `collect_soc2_evidence()`'s
output, e.g. `controls.capability_enforcement`).

## CC — Common Criteria (Security)

The CC series is mandatory for every SOC 2 report.

### CC1 — Control Environment (governance, ethics, org structure)

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC1.1 Integrity & ethical values | Anti-test-cheating verifier; test-driven `verify_final` keeps agents honest | Partial | `maverick/verifier.py`; `maverick/agent.py` (verify gate) |
| CC1.2–CC1.5 Board oversight, org structure, accountability | Operator governance, org chart, role definitions | Process-only | Not code — operator policy |

### CC2 — Communication & Information

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC2.1 Quality information for internal control | Append-only Ed25519 Merkle-chained audit log; OpenTelemetry traces/metrics | Implemented | `maverick/audit/`; `audit_log`, `audit_signing_key`; `maverick/observability.py` |
| CC2.2 Internal communication of responsibilities | EU AI Act Art. 50 user disclosure; user-facing docs | Partial | `maverick/compliance.py`; `docs/` |
| CC2.3 External communication | Public docs, support/incident channels | Process-only | `docs/`; operator policy |

### CC3 — Risk Assessment

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC3.1 Specifies objectives | Tool risk model + risk ceilings; capability `max_risk` | Implemented | `maverick/safety/tool_risk.py`; `maverick/capability.py` |
| CC3.2 Identifies & analyzes risk | Agent Shield (prompt-injection / exfil detection); preflight checks | Implemented | `maverick/safety/` (jailbreak/remote_scan); `maverick/preflight.py` |
| CC3.3 Fraud risk | Anti-test-cheating; secret/PII detectors | Partial | `maverick/safety/secret_detector.py`, `pii_detector.py` |
| CC3.4 Assesses change in risk | Eval-gated CI; chaos testing | Partial | `.github/workflows/`; `maverick/chaos.py` |

### CC4 — Monitoring Activities

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC4.1 Ongoing/separate evaluations | OpenTelemetry; health checks; circuit breakers; eval-gated CI | Implemented | `maverick/observability.py`, `health.py`, `circuit_breaker.py` |
| CC4.2 Evaluates & communicates deficiencies | Audit-chain and anchor-ledger verification (`verify_chain`, `verify_anchors`) surfaces tamper/breaks; issue reporting | Partial | `maverick/audit/signing.py`; `audit_log` evidence key; `maverick/issue_report.py` |

### CC5 — Control Activities

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC5.1 Selects control activities | Tool ACLs + risk ceilings; capability grants | Implemented | `maverick/safety/tool_acl.py`; `maverick/capability.py` |
| CC5.2 Technology general controls | Sandbox-mediated shell; capability chokepoint at the tool boundary | Implemented | `maverick/safety/`; sandbox `exec()` mediation (kernel rule 4, `CONTRIBUTING.md`; enforced by the `shell=True` gate in `.github/workflows/ci.yml`) |
| CC5.3 Deploys via policies & procedures | Config-driven policy (`~/.maverick/config.toml`); installer wizard | Partial | `maverick/config.py`; `apps/installer-cli/` |

### CC6 — Logical & Physical Access Controls

This is Lightwork's strongest area.

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC6.1 Logical access security (identity, least privilege) | Per-agent **capabilities**: signed, attenuating; tool + path + host scopes; enforced at the tool chokepoint. Least-privilege-on-spawn by construction. | Implemented (opt-in) | `maverick/capability.py`; `controls.capability_enforcement` |
| CC6.1 Authentication | **OIDC** ID-token verifier (asymmetric-only algs; alg-confusion-hardened; verified `exp`/`iat`/`aud`/`iss`/`sub`); a verified subject maps to the `user:{sub}` principal the capability/tenant model already uses | Implemented (opt-in) | `maverick/oidc.py`; `controls.oidc_auth` |
| CC6.2 Registration/authorization of users | Tool ACLs by channel/user; consent/HITL gating | Implemented | `maverick/safety/tool_acl.py`, `consent.py` |
| CC6.3 Role-based access / modification | Capability attenuation (child ≤ parent); risk ceilings | Implemented (opt-in) | `maverick/capability.py` (`attenuate`); `controls.capability_enforcement` |
| CC6.6 Boundary protection (external threats) | Agent Shield (prompt-injection/exfil); host-scope capability; network host allow-globs | Implemented | `maverick/safety/` (shield); `maverick/capability.py` (`allow_hosts`) |
| CC6.7 Restricts data transmission/movement | Secret/PII redaction; exfil detection; capability path scopes | Implemented | `maverick/safety/secret_detector.py`; `maverick/capability.py` (`allow_paths`) |
| CC6.7 Encryption at rest | AES-256-GCM authenticated encryption for sensitive local stores; **on by default** (secure-by-default), forced by compliance floors | Implemented (on by default) | `maverick/crypto_at_rest.py` (`at_rest_enabled`); `controls.encryption_at_rest` |
| CC6.8 Prevents/detects unauthorized software | Sandbox isolation backends; tool ACLs; plugin manifest | Partial | sandbox `exec()`; `maverick/plugin_manifest.py` |

### CC7 — System Operations

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC7.1 Detects config changes/vulnerabilities | Preflight checks; eval-gated CI; dependency markers | Partial | `maverick/preflight.py`; `.github/workflows/ci.yml` |
| CC7.2 Monitors anomalies | OpenTelemetry metrics; circuit breakers; `capability_denied` audit event | Implemented | `maverick/observability.py`; `maverick/audit/events.py` (`CAPABILITY_DENIED`) |
| CC7.3 Evaluates security events | Audit log + chain verification; shield_block / consent events | Implemented | `maverick/audit/`; `audit_log` evidence key |
| CC7.4 Responds to incidents | Killswitch (file + in-process halt); circuit breakers | Partial | `maverick/killswitch.py`; `maverick/circuit_breaker.py` |
| CC7.4 Incident response *program* | Documented IR runbook, on-call, escalation | Process-only | Not code — operator policy |
| CC7.5 Recovers from incidents | Durable checkpoint/resume; job queue | Implemented | `maverick/checkpoint.py`; `maverick/job_queue.py` |

### CC8 — Change Management

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC8.1 Authorizes/designs/tests/approves changes | Eval-gated CI; PR review; semantic-PR-title + lint gates; test-driven verifier | Partial | `.github/workflows/` (ci, lint-pr-title); test matrix (`.github/workflows/ci.yml`) |
| CC8.1 Change-management *policy* (approvals, segregation of duties) | Documented change-control policy, reviewer requirements, prod-deploy approvals | Process-only | Not code — operator policy |

### CC9 — Risk Mitigation

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| CC9.1 Mitigates business-disruption risk | Hard **Budget** caps; usage **quotas** + enforcement; killswitch | Implemented | `maverick/budget.py`; `maverick/quotas.py` (`controls.usage_quotas`); `maverick/killswitch.py` |
| CC9.2 Vendor & business-partner risk management | Sub-processor inventory, vendor security reviews, DPAs | Process-only / Gap | Not code — operator policy (LLM providers, infra vendors) |

## A — Availability

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| A1.1 Capacity management | Budget caps; per-principal usage quotas; net concurrency limits | Implemented | `maverick/budget.py`, `quotas.py`, `net_concurrency.py` |
| A1.2 Backup / recovery / resilience | Durable checkpoint/resume; job queue; circuit breakers | Implemented | `maverick/checkpoint.py`, `job_queue.py`, `circuit_breaker.py` |
| A1.2 Environmental protections / DR site | Hosting/DR (infra-level) | Process-only | Not code — deployment/infra |
| A1.3 Tests recovery | Chaos testing; checkpoint/resume tests | Partial | `maverick/chaos.py`; test suite |

## PI — Processing Integrity

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| PI1.1 Processing definitions / quality | Eval-gated CI; test-driven verifier + anti-test-cheating | Implemented | `maverick/verifier.py`; `.github/workflows/` |
| PI1.2 Inputs are complete & accurate | Shield input scanning; preflight; consent gates | Implemented | `maverick/safety/`; `maverick/preflight.py` |
| PI1.3 Processing is complete/accurate/timely/authorized | Capability enforcement; budget; durable checkpoint/resume; risk-proportional verify | Implemented (opt-in) | `maverick/capability.py`; `budget.py`; `checkpoint.py` |
| PI1.4 Outputs are complete & accurate (delivered to right parties) | Verifier accept gate; output-side shield/exfil + redaction | Implemented | `maverick/verifier.py`; `maverick/safety/` |
| PI1.5 Stores inputs/outputs completely & accurately | Append-only signed audit log (tamper-evident) | Implemented | `maverick/audit/`; `audit_log` evidence key |

## C — Confidentiality

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| C1.1 Identifies & protects confidential information | Multi-tenant isolation (per-tenant memory/audit/world.db); secret/PII redaction | Implemented (opt-in) | `maverick/paths.py` (`controls.tenant_isolation`); `maverick/safety/secret_detector.py` |
| C1.1 Access boundaries for confidential data | Capability path/host scopes; tool ACLs | Implemented (opt-in) | `maverick/capability.py` (`allow_paths`/`allow_hosts`) |
| C1.1 Encryption at rest | AES-256-GCM authenticated encryption of sensitive local stores (also CC6.7); **on by default** (secure-by-default), forced by compliance floors | Implemented (on by default) | `maverick/crypto_at_rest.py` (`at_rest_enabled`); `controls.encryption_at_rest` |
| C1.2 Disposes of confidential information | **GDPR erase** (scrub/delete user + re-sign chain); audit retention | Implemented | `maverick/audit/erase.py`, `retention.py` |

## P — Privacy

The Privacy category mirrors the AICPA Privacy Management Framework; most of it
is policy + notice, with a few technical anchors.

| TSC | Lightwork control | Status | Evidence |
| --- | --- | --- | --- |
| P1 Notice | EU AI Act Art. 50 first-turn AI disclosure | Partial | `maverick/compliance.py` (`first_turn_disclosure`) |
| P2 Choice & consent | Consent/HITL gating for destructive actions | Implemented | `maverick/safety/consent.py` |
| P3 Collection | Anonymous mode (strip identifying fields from logs/audit) | Partial | `maverick/privacy.py` (`anon_enabled`) |
| P4 Use, retention & disposal | Audit retention policy; GDPR erase | Implemented | `maverick/audit/retention.py`, `erase.py` |
| P5 Access (subject access) | GDPR erase (right to erasure) **and** DSAR export — Art. 15/20 access/portability bundle of all data held for a subject (world + audit) | Implemented | `maverick/dsar.py` (`export_subject_data`; `controls.data_subject_export`); `maverick/audit/erase.py` (erasure) |
| P6 Disclosure to third parties | Secret redaction; sub-processor disclosure | Partial / Process-only | `maverick/safety/secret_detector.py`; operator's sub-processor list |
| P7 Quality | Tenant isolation prevents cross-subject contamination | Partial | `maverick/paths.py` |
| P8 Monitoring & enforcement | Audit log; privacy complaint handling | Partial / Process-only | `maverick/audit/`; operator policy |

## Process-only / Gap summary (NOT code)

A SOC 2 Type II report cannot pass on engineering controls alone. The following
are **out of scope for this repository** and must be operated as processes by
the deploying organization (or built where marked Gap):

- **Change management policy** (CC8): documented approvals, segregation of
  duties, prod-deploy sign-off. (Code controls: CI gates + PR review.)
- **Vendor / sub-processor management** (CC9.2): security reviews, DPAs,
  sub-processor inventory for LLM providers and infra.
- **Incident response program** (CC7.4): runbooks, on-call, escalation, customer
  notification SLAs. (Code controls: killswitch + circuit breakers.)
- **HR controls** (CC1): background checks, onboarding/offboarding, security
  training, acceptable-use & confidentiality agreements.
- **Physical & environmental security** (CC6/A1): data-center/hosting controls —
  inherited from the cloud provider; document via their SOC 2.
- **Risk assessment program** (CC3): periodic, documented enterprise risk
  assessment with management review.
- **Vulnerability management / pen testing cadence** (CC7.1): scheduled scans
  and third-party penetration tests with remediation tracking.

### Opt-in controls to enable

- **Several controls are opt-in / off-by-default** (capabilities, tenant
  isolation, quotas, OIDC); encryption at rest and audit signing are on by
  default unless disabled. For a SOC 2 deployment all of them must be **on** and
  shown enabled (`audit_log` = `ok`, not `unsigned`) in the evidence snapshot —
  see "Verifying posture" below. The opt-in default is intentional (single-tenant
  local use is unchanged), but a compliant deployment must turn them on.

## The evidence collector

[`maverick/soc2.py`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/packages/maverick-core/maverick/soc2.py) exposes:

```python
from maverick.soc2 import collect_soc2_evidence
snapshot = collect_soc2_evidence()
```

It returns a JSON-serializable posture snapshot. Top-level keys:

| Key | Meaning |
| --- | --- |
| `version` | maverick package version |
| `collected_at` | UTC epoch seconds of collection |
| `controls.capability_enforcement` | capability enforcement on/off (CC6.1/CC6.3) |
| `controls.tenant_isolation` | per-user tenant isolation on/off (C1.1) |
| `controls.usage_quotas` | per-principal usage quotas on/off (CC9.1/A1.1) |
| `controls.oidc_auth` | OIDC ID-token verifier on/off (CC6.1) |
| `controls.encryption_at_rest` | AES-256-GCM at-rest encryption on/off (CC6.7/C1.1) |
| `controls.data_subject_export` | DSAR access/portability export present (P5; presence probe → `enabled`/`absent`) |
| `audit_log` | audit-chain plus anchor-ledger verification: `ok` / `broken` (tamper) / `unsigned` (signing off) / `empty` / `no_crypto` / `unknown` (CC2.1/PI1.5) |
| `audit_signing_key` | audit signing-key presence (tamper-evidence trust anchor) |

Each `controls.*` probe carries a `status` of `enabled` / `disabled` / `absent`
/ `unknown`. The collector is **fail-soft**: a missing optional module is
`absent`, a probe that raises is `unknown`, and the call never throws.
(`controls.data_subject_export` is a *presence* probe — it reports `enabled`
when the capability is shipped or `absent` when it is not, and never `disabled`
or `unknown`, since it checks only that the code exists rather than calling it.)

### Verifying posture

```bash
python -c "import json; from maverick.soc2 import collect_soc2_evidence; \
print(json.dumps(collect_soc2_evidence(), indent=2))"
```

A SOC 2-ready deployment should show `capability_enforcement`,
`tenant_isolation`, `usage_quotas`, and `oidc_auth` as `enabled`,
`encryption_at_rest` as `enabled`, and `audit_log` as `ok` with
`audit_signing_key` present.

At-rest encryption and audit signing **default ON** (secure-by-default —
`maverick.security_defaults.secure_by_default`), unless explicitly disabled
(`MAVERICK_SECURE_DEFAULT=0`, or the per-control knobs `[encryption] at_rest` /
`[audit] sign`). So on a fresh install `encryption_at_rest` reports `enabled`, and
once the audit log has rows they are signed and the per-day chains plus cross-file
anchor ledger verify `ok` (the log reads `empty` only until the first write, and
`audit_signing_key` becomes present once the first signed row is written). With
signing explicitly off the log is reported `unsigned` — append-only, but not
cryptographically tamper-evident.

The deployment-specific controls that would break the zero-config happy path stay
opt-in and must be turned on for a full SOC 2 posture: `capability_enforcement`,
`tenant_isolation`, `usage_quotas`, and `oidc_auth` (OIDC would otherwise lock out
the local single-user dashboard).

> The `maverick soc2` command prints this snapshot as JSON (`--json` for
> single-line output) and exits non-zero unless the required controls are
> ready. See [`soc2/README.md`](soc2/README.md).
