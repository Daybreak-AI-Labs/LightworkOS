# SOC 2 Readiness & Control Turn-On Guide

This guide is for organizations that run Lightwork inside a SOC 2-scoped
system. The detailed control mapping lives in
[`../soc2-controls.md`](../soc2-controls.md); this document covers **readiness
posture**, the **Type I → Type II path**, and the **control turn-on guide** that
a compliant deployment must follow.

> SOC 1 is out of scope — Lightwork is not a system of record for financial
> reporting (no ICFR relevance). See the [compliance documentation index](../README.md).

## 1. Type I vs Type II

| Report | What it attests | Effort |
| --- | --- | --- |
| **SOC 2 Type I** | Controls are suitably *designed* at a point in time | ~4–8 weeks once policies + process docs exist |
| **SOC 2 Type II** | Controls *operated effectively* over a window (typically 3–6+ months of evidence) | Type I + the observation window |

Most organizations that ask for a SOC 2 report require **Type II**. The
practical sequence is: approve policies → put the Process controls in place →
enable opt-in controls → **Type I** → run the observation window collecting
evidence → **Type II**.

## 2. Trust Services Categories in scope

- **Security (Common Criteria, CC)** — mandatory; Lightwork's strongest area.
- **Availability (A)** — budget/quota caps, checkpoint/resume, circuit breakers.
- **Processing Integrity (PI)** — verifier gates, signed audit, output shield.
- **Confidentiality (C)** — tenant isolation, encryption at rest, redaction.
- **Privacy (P)** — DSAR, erasure, retention, Art.50 disclosure.

The deploying organization decides which optional categories (A/PI/C/P) to include in the
report scope; all five are substantially supported.

## 3. Control turn-on guide (REQUIRED for a compliant deployment)

Capability enforcement, tenant isolation, usage quotas and OIDC ship
**off-by-default** so single-tenant local use is unchanged; encryption at rest
and audit signing are on by default unless disabled. For a SOC 2 (and ISO 27001)
deployment all of them must be **enabled and shown enabled** in the evidence
snapshot. This is configuration, not new code.

| Control | Enable via | Evidence key (`collect_soc2_evidence()`) | Target |
| --- | --- | --- | --- |
| Capability enforcement | `[capabilities] enforce = true` / `MAVERICK_ENFORCE_CAPABILITIES=1` | `controls.capability_enforcement` | `enabled` |
| Tenant isolation | `[tenancy] by_user = true` / `MAVERICK_TENANT_BY_USER=1` | `controls.tenant_isolation` | `enabled` |
| Usage quotas | `[quotas] enforce = true` / `MAVERICK_QUOTA_ENFORCE=1` | `controls.usage_quotas` | `enabled` |
| OIDC authentication | `[auth.oidc] enabled = true` / `MAVERICK_OIDC_ENABLED=1` | `controls.oidc_auth` | `enabled` |
| Encryption at rest (on by default) | `[encryption] at_rest = true` / `MAVERICK_ENCRYPT_AT_REST=1` | `controls.encryption_at_rest` | `enabled` |
| Audit signing (on by default) | `[audit] sign = true` / `MAVERICK_AUDIT_SIGN=1` | `audit_log` | `ok` (not `unsigned`) |

[`../deployment/compliant-config.toml`](../deployment/compliant-config.toml) sets
all of these in one reference configuration.

The hardened-but-functional defaults live in `maverick/security_defaults.py`;
the enterprise deployment profile turns these on as a group. See
[`../../security-hardening.md`](../../security-hardening.md) and
[`../../enterprise/security-overview.md`](../../enterprise/security-overview.md).

## 4. Verifying posture (evidence collection)

Lightwork ships a machine-readable evidence collector:

```bash
python -c "import json; from maverick.soc2 import collect_soc2_evidence; \
print(json.dumps(collect_soc2_evidence(), indent=2))"
```

A SOC 2-ready snapshot shows `capability_enforcement`, `tenant_isolation`, and
`usage_quotas` as `enabled`, `oidc_auth` and `encryption_at_rest` as `enabled`,
`audit_log` as `ok`, and `audit_signing_key` present.

The **`maverick soc2`** CLI command does exactly this — it prints the evidence
snapshot as JSON and **exits non-zero unless every required control is in a
ready posture** (the `_soc2_posture_ready` gate: required controls `enabled`,
`audit_log` `ok`, signing key present). Wire it into CI or a deploy gate the
same way as `maverick compliance --strict`:

```bash
maverick soc2            # pretty JSON; exit 1 if not SOC 2-ready
maverick soc2 --json     # compact single-line JSON for log capture
```

Capture this snapshot periodically during the Type II window as design +
operating evidence.

### Standing posture gate (CI)

The [`Compliance Posture`](../../../.github/workflows/compliance-posture.yml)
GitHub Actions workflow runs the gate automatically: it applies
[`compliant-config.toml`](../deployment/compliant-config.toml) and fails unless
`maverick soc2` is compliant-ready. It runs weekly, on demand
(`workflow_dispatch`), and on any change to the controls/config that affect
posture — a **regression gate** so a code change can't silently break the
ability to pass. It also
uploads each run's `soc2-evidence.json` as an artifact. This workflow is
`pull_request`-triggered and executes code from the checked-out tree, so keep it
on GitHub-hosted runners only; do **not** retarget it to a production or other
privileged self-hosted runner. To gate a *live* deployment, run
[`verify-posture.sh`](../deployment/verify-posture.sh) on the deployment host
from a trusted, protected ref or another trusted deployment automation path.

## 5. Process controls to operate (NOT code)

A Type II report cannot pass on engineering controls alone. The organization
that deploys Lightwork owns and operates these processes and produces their
evidence over the observation window:

- Change-management process (CC8)
- Vendor / sub-processor management (CC9.2)
- Incident-response program (CC7.4); the [incident-response guide](../procedures/incident-response-runbook.md)
  covers Lightwork's containment and forensics controls
- HR controls (CC1.4)
- Risk-assessment program (CC3)
- Vulnerability management / pen-test cadence (CC7.1)
- Physical/environmental security (CC6/A1) → cloud provider's own SOC 2/ISO report

## 6. Readiness checklist

- [ ] Security and AI policies approved by management with effective dates
- [ ] Risk register reviewed and accepted
- [ ] Opt-in controls enabled; evidence snapshot shows all targets met
- [ ] Process controls (§5) operating, each with an owner
- [ ] Cloud provider attestations collected (inherited physical/env controls)
- [ ] Auditor (CPA firm) engaged for Type I
- [ ] Observation window started for Type II evidence collection
