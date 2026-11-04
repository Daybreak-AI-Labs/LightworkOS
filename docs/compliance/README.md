# Compliance documentation

These documents are for organizations that run Lightwork inside a system they
want audited. They show how Lightwork's technical controls map to three
frameworks, how to turn those controls on, and how to verify and evidence the
result:

- **SOC 2** (AICPA Trust Services Criteria).
- **ISO/IEC 27001:2022** (information security management).
- **ISO/IEC 42001:2023** (AI management).

Lightwork is software, not a certified service, and using it does not make an
organization compliant. Every framework also requires *organizational*
controls, such as governance, risk assessment, change management, vendor
management, HR security and an incident-response programme. These documents
mark those controls **Process**: the organization deploying Lightwork operates
them and owns their evidence. Lightwork itself is not audited or certified
against any of these frameworks.

SOC 1 is out of scope: Lightwork is not a system of record for financial
reporting (no ICFR relevance) unless a deployment places it in a
financial-reporting chain.

## Document map

| Document | Purpose |
| --- | --- |
| [`control-crosswalk.md`](control-crosswalk.md) | Maps SOC 2 criteria, ISO 27001 Annex A and ISO 42001 Annex A themes to the Lightwork controls that address them and to the code that implements them. Start here. |
| [`soc2-controls.md`](soc2-controls.md) | SOC 2 Trust Services Criteria mapped to controls, and the evidence collector (`maverick soc2`). |
| [`soc2/README.md`](soc2/README.md) | Running Lightwork in a SOC 2-scoped deployment: the Type I and Type II path, the control turn-on guide and the posture gate. |
| [`deployment/hardening-checklist.md`](deployment/hardening-checklist.md) | Step-by-step checklist for enabling and verifying the controls before go-live. |
| [`deployment/compliant-config.toml`](deployment/compliant-config.toml) | Reference `config.toml` that turns on every control a compliant deployment must show enabled. |
| [`deployment/verify-posture.sh`](deployment/verify-posture.sh) | Runs the posture checks (`maverick soc2`, `maverick enterprise verify --require`, `maverick compliance --strict`, `maverick doctor`) on a deployment host. |
| [`procedures/incident-response-runbook.md`](procedures/incident-response-runbook.md) | Incident response with Lightwork's controls: halt, revocation, circuit breakers, audit-log forensics and the AI-incident playbook. |

## How to use them

1. **Map your scope.** Read the [control crosswalk](control-crosswalk.md) to see
   which requirements Lightwork's controls address, which are opt-in, and which
   your organization must meet with its own processes.
2. **Turn the controls on.** Encryption at rest and audit signing are on by
   default. Capability enforcement, tenant isolation, usage quotas and OIDC are
   off by default so a single-user local install works without setup; a
   compliant deployment must enable them. Apply
   [`compliant-config.toml`](deployment/compliant-config.toml) and work through
   the [hardening checklist](deployment/hardening-checklist.md).
3. **Verify and keep evidence.** `maverick soc2` prints the posture snapshot and
   exits non-zero unless every required control is ready; run it, or
   [`verify-posture.sh`](deployment/verify-posture.sh), as a deploy gate and keep
   dated snapshots for your auditor.
4. **Operate your processes.** Run your own change-management, vendor,
   HR-security, risk and incident-response processes alongside the technical
   controls; the [incident-response guide](procedures/incident-response-runbook.md)
   covers the Lightwork side of an incident.

## Related

- [Security hardening](../security-hardening.md): the secure-by-default posture
  and how to tighten it further.
- The [Compliance Posture workflow](../../.github/workflows/compliance-posture.yml)
  applies `compliant-config.toml` in CI and fails unless `maverick soc2` reports a
  ready posture, so a code change cannot silently break a compliant
  configuration.
